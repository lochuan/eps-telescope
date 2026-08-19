import binascii

import pytest

from eps_probe import protocol


def frame(ftype, seq=0, word1=0):
    word0 = ftype | (protocol.PROTO_VERSION << 8) | (seq << 16)
    return (word0 & 0xFFFFFFFF).to_bytes(4, "little") + (word1 & 0xFFFFFFFF).to_bytes(4, "little")


def build_stream():
    """Complete stream: 3 registers + 2 regions (8 bytes each) + 1 egg + STATUS + END.

    Returns (frames, expected) where expected holds the hand-precomputed values the
    collector must reproduce.
    """
    names = ["DCRA1COUT", "PRDNAME1", "PRDNAME2"]
    reg_values = [0x12345678, 0x35384852, 0x54534554]  # PRDNAME words spell b"RH85TEST"

    r1_addr = 0x00018000
    r2_addr = 0x00010000
    r1_data = bytes.fromhex("4433221188776655")
    r2_data = bytes.fromhex("ddccbbaa33221100")

    frames = [
        frame(protocol.FRAME_BEGIN0),
        frame(protocol.FRAME_BEGIN1, word1=18),
    ]
    data_bytes = b""
    for slot, value in enumerate(reg_values):
        frames.append(frame(protocol.FRAME_REGISTER_DATA, seq=slot, word1=value))
        data_bytes += value.to_bytes(4, "little")

    for addr, rdata in ((r1_addr, r1_data), (r2_addr, r2_data)):
        words = [int.from_bytes(rdata[i:i + 4], "little") for i in range(0, len(rdata), 4)]
        frames.append(frame(protocol.FRAME_REGION_BEGIN, word1=addr))
        frames.append(frame(protocol.FRAME_REGION_LENGTH, word1=len(rdata)))
        for idx, w in enumerate(words):
            frames.append(frame(protocol.FRAME_REGION_DATA, seq=idx, word1=w))
            data_bytes += w.to_bytes(4, "little")
        # The wire carries the STANDARD CRC (binascii.crc32 semantics), exactly
        # what deep_probe.c transmits as `raw_crc ^ 0xFFFFFFFF`.
        frames.append(frame(protocol.FRAME_REGION_END, word1=binascii.crc32(rdata)))

    frames.append(frame(protocol.FRAME_EGG_FOUND, word1=0x0008E6C7))
    frames.append(frame(protocol.FRAME_STATUS, word1=0))
    combined = binascii.crc32(data_bytes)
    frames.append(frame(protocol.FRAME_END, word1=combined))

    expected = {
        "names": names,
        "reg_values": reg_values,
        "registers": dict(zip(names, reg_values)),
        "dcra": {"DCRA1COUT": 0x12345678},
        "prdname": "RH85TEST",
        "regions": {r1_addr: r1_data, r2_addr: r2_data},
        "egg_candidates": [0x0008E6C7],
        "combined_crc": combined,
    }
    return frames, expected


def consume_all(collector, frames):
    for can_id, data in enumerate(frames):
        collector.consume(can_id, data)


def test_complete_stream_reassembles():
    frames, exp = build_stream()
    col = protocol.StreamCollector(register_names=exp["names"])
    consume_all(col, frames)
    res = col.finish()

    assert res.registers == exp["registers"]
    assert res.dcra == exp["dcra"]
    assert res.prdname == exp["prdname"]
    assert res.regions == exp["regions"]
    assert res.egg_candidates == exp["egg_candidates"]
    assert res.combined_crc == exp["combined_crc"]
    assert res.valid is True
    assert res.error is None


def test_tampered_region_data_frame_invalidates():
    frames, exp = build_stream()
    # Flip one byte inside the first REGION_DATA frame's word1; the precomputed
    # region/combined CRCs in the stream now mismatch the accumulated data.
    tampered = frames[:]
    for i, data in enumerate(tampered):
        if data[0] == protocol.FRAME_REGION_DATA:
            word0 = int.from_bytes(data[0:4], "little")
            word1 = int.from_bytes(data[4:8], "little") ^ 0x00000001
            tampered[i] = frame(word0 & 0xFF, seq=(word0 >> 16) & 0xFFFF, word1=word1)
            break

    col = protocol.StreamCollector(register_names=exp["names"])
    consume_all(col, tampered)
    res = col.finish()
    assert res.valid is False
    assert res.region_bad == {0x00018000}


def test_region_end_crc_mismatch_records_only_that_region():
    frames, exp = build_stream()
    # Corrupt the CRC on the FIRST region's REGION_END only; the second region
    # stays intact so only 0x00018000 is flagged.
    tampered = frames[:]
    seen_region = False
    for i, data in enumerate(tampered):
        if data[0] == protocol.FRAME_REGION_BEGIN:
            seen_region = True
        if seen_region and data[0] == protocol.FRAME_REGION_END:
            word0 = int.from_bytes(data[0:4], "little")
            word1 = int.from_bytes(data[4:8], "little") ^ 0xFFFFFFFF
            tampered[i] = frame(word0 & 0xFF, seq=(word0 >> 16) & 0xFFFF, word1=word1)
            break

    col = protocol.StreamCollector(register_names=exp["names"])
    consume_all(col, tampered)
    res = col.finish()
    assert res.valid is False
    assert res.region_bad == {0x00018000}
    assert 0x00010000 not in res.region_bad


def test_missing_end_raises_protocol_error():
    frames, exp = build_stream()
    col = protocol.StreamCollector(register_names=exp["names"])
    consume_all(col, frames[:-1])
    with pytest.raises(protocol.ProtocolError):
        col.finish()


def test_unknown_frame_type_raises_protocol_error():
    col = protocol.StreamCollector()
    col.consume(0, frame(protocol.FRAME_BEGIN0))
    with pytest.raises(protocol.ProtocolError):
        col.consume(0, frame(0x99))


def test_version_mismatch_raises_protocol_error():
    col = protocol.StreamCollector(expected_version=protocol.PROTO_VERSION)
    word0 = protocol.FRAME_BEGIN0 | ((protocol.PROTO_VERSION + 1) << 8)
    data = word0.to_bytes(4, "little") + b"\x00\x00\x00\x00"
    with pytest.raises(protocol.ProtocolError):
        col.consume(0, data)


def test_build_region_request_layout():
    req = protocol.build_region_request(flags=1, regions=[(0x00018000, 8), (0x00010000, 8)])
    assert len(req) == 6 + 2 * 10
    assert req[0:4] == b"PROB"
    assert req[4] == 1          # flags
    assert req[5] == 2          # num_regions
    assert req[6:10] == (0x00018000).to_bytes(4, "big")
    assert req[10:12] == (8).to_bytes(2, "big")
    assert req[12:16] == b"\x00" * 4
    assert req[16:20] == (0x00010000).to_bytes(4, "big")
    assert req[20:22] == (8).to_bytes(2, "big")
    assert req[22:26] == b"\x00" * 4


def test_crc32_helpers_match_zlib():
    payload = b"RH850 EPS probe crc vector 123456789"
    assert protocol.crc32_stream([payload]) == binascii.crc32(payload)
    crc = 0xFFFFFFFF
    for b in payload:
        crc = protocol.crc32_update(crc, b)
    assert (crc ^ 0xFFFFFFFF) == binascii.crc32(payload)
