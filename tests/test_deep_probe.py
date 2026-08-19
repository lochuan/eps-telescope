"""Layer 3 deep-probe orchestration: fingerprint + boot-integrity verification.

Tests drive ``run_deep_probe`` with a recording mock transport and feed the
``verify_*`` helpers hand-constructed ``regions``/``egg_candidates`` built from
the verified fingerprints constants. No real hardware involved.
"""

import binascii

from eps_probe import deep_probe
from eps_probe.fingerprints import ADJUST_WORD, PATCH_FINGERPRINT, PATCH_POINT
from eps_probe.payload import REQUEST_OFFSET, decrypt_envelope
from eps_probe.protocol import StreamResult

_FP_BYTES = bytes.fromhex(PATCH_FINGERPRINT["bytes"])

_FULL_RANGE_START = 0x18000
_FULL_RANGE_END = 0xFFDF0


def _fingerprint_region():
    """Region keyed 0x8E6A0 with the real 64-byte window placed at 0x8E6A7."""
    data = bytearray(b"\xAA" * 0x100)
    off = PATCH_FINGERPRINT["window_base"] - 0x8E6A0
    data[off:off + 64] = _FP_BYTES
    return {0x8E6A0: bytes(data)}


def _adjust_region(word):
    """Region keyed 0xFFDE0 carrying ``word`` at 0xFFDEC (little-endian)."""
    data = bytearray(0x40)
    data[0xFFDEC - 0xFFDE0:0xFFDEC - 0xFFDE0 + 4] = word.to_bytes(4, "little")
    return {0xFFDE0: bytes(data)}


def _full_range_region():
    """Region keyed 0x18000 covering [0x18000, 0xFFDF0) with CRC == 0xFFFFFFFF."""
    length = _FULL_RANGE_END - _FULL_RANGE_START
    prefix = bytes((i * 7 + 1) & 0xFF for i in range(length - 4))
    tail = (binascii.crc32(prefix) ^ 0xFFFFFFFF).to_bytes(4, "little")
    return {_FULL_RANGE_START: prefix + tail}


class MockTransport:
    def __init__(self, result):
        self.result = result
        self.uploads = []

    def upload_and_trigger(self, envelope, new_uds, expected_sha256=None):
        self.uploads.append((envelope, new_uds, expected_sha256))
        return True

    def collect_stream(self, timeout=60.0):
        return self.result


# --- verify_patch_fingerprint -------------------------------------------------

def test_verify_patch_fingerprint_match():
    out = deep_probe.verify_patch_fingerprint(_fingerprint_region(), [])
    assert out["status"] == "MATCH"


def test_window_status_patched():
    # The real already-patched vehicle's window: identical to the verified
    # fingerprint except byte 32 (the patch byte) is 0x01 instead of 0xD1.
    patched = bytearray(_FP_BYTES)
    patched[PATCH_FINGERPRINT["patch_offset"]] = PATCH_POINT["patched"]
    assert deep_probe._window_status(bytes(patched)) == "PATCHED"
    assert deep_probe._window_status(_FP_BYTES) == "MATCH"
    assert deep_probe._window_status(b"\x00" * 64) == "MISMATCH"
    assert deep_probe._window_status(None) == "NO_DATA"


def test_verify_patch_fingerprint_patched():
    regions = _fingerprint_region()
    data = bytearray(regions[0x8E6A0])
    off = PATCH_FINGERPRINT["window_base"] - 0x8E6A0
    data[off + PATCH_FINGERPRINT["patch_offset"]] = PATCH_POINT["patched"]
    out = deep_probe.verify_patch_fingerprint({0x8E6A0: bytes(data)}, [])
    assert out["status"] == "PATCHED"


def test_verify_patch_fingerprint_mismatch():
    regions = _fingerprint_region()
    data = bytearray(regions[0x8E6A0])
    data[PATCH_FINGERPRINT["window_base"] - 0x8E6A0] ^= 0xFF
    out = deep_probe.verify_patch_fingerprint({0x8E6A0: bytes(data)}, [])
    assert out["status"] == "MISMATCH"


def test_verify_patch_fingerprint_no_data():
    out = deep_probe.verify_patch_fingerprint({}, [])
    assert out["status"] == "NO_DATA"


def test_verify_patch_fingerprint_bad_region_is_no_data():
    out = deep_probe.verify_patch_fingerprint(
        _fingerprint_region(), [], region_bad={0x8E6A0}
    )
    assert out["status"] == "NO_DATA"
    assert "CRC" in out["note"]


def test_verify_patch_fingerprint_unrelated_bad_region_ignored():
    out = deep_probe.verify_patch_fingerprint(
        _fingerprint_region(), [], region_bad={0xFFDE0}
    )
    assert out["status"] == "MATCH"
    assert "note" not in out


def test_verify_patch_fingerprint_candidate_context_match():
    regions = _fingerprint_region()
    candidate = PATCH_FINGERPRINT["window_base"] + 31  # egg start 0x8E6C6
    out = deep_probe.verify_patch_fingerprint(regions, [candidate])
    assert out["status"] == "MATCH"
    assert out["candidates"] == [{"addr": candidate, "status": "MATCH"}]


def test_verify_patch_fingerprint_candidate_context_no_data():
    out = deep_probe.verify_patch_fingerprint(
        _fingerprint_region(), [0x5A000]
    )
    assert out["candidates"] == [{"addr": 0x5A000, "status": "NO_DATA"}]


def test_verify_patch_fingerprint_candidate_context_mismatch():
    regions = {0x18000: bytes(range(64))}
    out = deep_probe.verify_patch_fingerprint(regions, [0x1801F])
    assert out["candidates"] == [{"addr": 0x1801F, "status": "MISMATCH"}]


# --- verify_boot_integrity ----------------------------------------------------

def test_verify_boot_integrity_original():
    out = deep_probe.verify_boot_integrity(
        _adjust_region(ADJUST_WORD["original"])
    )
    assert out["adjust_word"] == ADJUST_WORD["original"]
    assert out["state"] == "original"
    assert "residue_ok" not in out


def test_verify_boot_integrity_patched():
    out = deep_probe.verify_boot_integrity(
        _adjust_region(ADJUST_WORD["patched"])
    )
    assert out["adjust_word"] == ADJUST_WORD["patched"]
    assert out["state"] == "patched"


def test_verify_boot_integrity_other_word_is_unknown():
    out = deep_probe.verify_boot_integrity(_adjust_region(0x1234ABCD))
    assert out["adjust_word"] == 0x1234ABCD
    assert out["state"] == "unknown"


def test_verify_boot_integrity_missing_adjust_region():
    out = deep_probe.verify_boot_integrity({})
    assert out["state"] == "unknown"
    assert out["adjust_word"] is None


def test_verify_boot_integrity_bad_adjust_region_stays_unknown():
    out = deep_probe.verify_boot_integrity(
        _adjust_region(ADJUST_WORD["original"]), region_bad={0xFFDE0}
    )
    assert out["state"] == "unknown"
    assert out["adjust_word"] == ADJUST_WORD["original"]
    assert "CRC" in out["note"]


def test_verify_boot_integrity_bad_full_range_residue_false():
    out = deep_probe.verify_boot_integrity(
        _full_range_region(), region_bad={_FULL_RANGE_START}
    )
    assert out["state"] == "unknown"
    assert out["residue_ok"] is False
    assert "CRC" in out["note"]


def test_verify_boot_integrity_full_range_residue_ok():
    out = deep_probe.verify_boot_integrity(_full_range_region())
    assert out["residue_ok"] is True
    assert out["state"] == "unknown"


def test_verify_boot_integrity_full_range_residue_bad():
    regions = {_FULL_RANGE_START: bytes(0xFFDF0 - 0x18000)}
    out = deep_probe.verify_boot_integrity(regions)
    assert out["state"] == "unknown"
    assert out["residue_ok"] is False


# --- classify_target ----------------------------------------------------------

def test_classify_target_sa_blocked():
    fp = deep_probe.verify_patch_fingerprint(_fingerprint_region(), [])
    bi = deep_probe.verify_boot_integrity(_adjust_region(ADJUST_WORD["original"]))
    out = deep_probe.classify_target(fp, bi, sa_ok=False, envelope_ok=True)
    assert out["classification"] == "sa_blocked"


def test_classify_target_envelope_blocked():
    fp = deep_probe.verify_patch_fingerprint(_fingerprint_region(), [])
    bi = deep_probe.verify_boot_integrity(_adjust_region(ADJUST_WORD["original"]))
    out = deep_probe.classify_target(fp, bi, sa_ok=True, envelope_ok=False)
    assert out["classification"] == "envelope_blocked"


def test_classify_target_verified_variant():
    fp = deep_probe.verify_patch_fingerprint(_fingerprint_region(), [])
    bi = deep_probe.verify_boot_integrity(_adjust_region(ADJUST_WORD["original"]))
    out = deep_probe.classify_target(fp, bi, sa_ok=True, envelope_ok=True)
    assert out["classification"] == "verified_variant"
    assert out["boot_integrity"] == "original"


def test_classify_target_already_patched():
    fp = deep_probe.verify_patch_fingerprint(_fingerprint_region(), [])
    bi = deep_probe.verify_boot_integrity(_adjust_region(ADJUST_WORD["patched"]))
    out = deep_probe.classify_target(fp, bi, sa_ok=True, envelope_ok=True)
    assert out["classification"] == "already_patched"


def test_classify_target_patched_fingerprint_is_already_patched():
    # An already-patched vehicle: window differs only at the patch byte
    # (0x01), egg scan finds nothing, adjust word = patched value.
    regions = _fingerprint_region()
    data = bytearray(regions[0x8E6A0])
    off = PATCH_FINGERPRINT["window_base"] - 0x8E6A0
    data[off + PATCH_FINGERPRINT["patch_offset"]] = PATCH_POINT["patched"]
    fp = deep_probe.verify_patch_fingerprint({0x8E6A0: bytes(data)}, [])
    assert fp["status"] == "PATCHED"
    bi = deep_probe.verify_boot_integrity(_adjust_region(ADJUST_WORD["patched"]))
    out = deep_probe.classify_target(fp, bi, sa_ok=True, envelope_ok=True)
    assert out["classification"] == "already_patched"


def test_classify_target_match_with_unknown_boot_state_is_incomplete():
    fp = deep_probe.verify_patch_fingerprint(_fingerprint_region(), [])
    bi = deep_probe.verify_boot_integrity(_adjust_region(0x1234ABCD))
    out = deep_probe.classify_target(fp, bi, sa_ok=True, envelope_ok=True)
    assert out["classification"] == "probe_incomplete"


def test_classify_target_residue_false_forces_incomplete():
    fp = deep_probe.verify_patch_fingerprint(_fingerprint_region(), [])
    bi = deep_probe.verify_boot_integrity({0x18000: bytes(0xFFDF0 - 0x18000)})
    assert bi["residue_ok"] is False
    out = deep_probe.classify_target(fp, bi, sa_ok=True, envelope_ok=True)
    assert out["classification"] == "probe_incomplete"


def test_classify_target_bad_stream_is_incomplete():
    fp = deep_probe.verify_patch_fingerprint(_fingerprint_region(), [])
    bi = deep_probe.verify_boot_integrity(_adjust_region(ADJUST_WORD["original"]))
    out = deep_probe.classify_target(
        fp, bi, sa_ok=True, envelope_ok=True, stream_ok=False
    )
    assert out["classification"] == "probe_incomplete"


def test_classify_target_mismatch_without_egg_scan_is_incomplete():
    regions = {0x8E6A0: bytes(0x100)}
    fp = deep_probe.verify_patch_fingerprint(regions, [])
    bi = deep_probe.verify_boot_integrity(_adjust_region(0x1234ABCD))
    out = deep_probe.classify_target(
        fp, bi, sa_ok=True, envelope_ok=True, scan_egg=False
    )
    assert out["classification"] == "probe_incomplete"


def test_classify_target_egg_variant():
    regions = {0x8E6A0: bytes(0x100)}
    fp = deep_probe.verify_patch_fingerprint(regions, [0x8E6C6])
    bi = deep_probe.verify_boot_integrity(_adjust_region(0x1234ABCD))
    out = deep_probe.classify_target(fp, bi, sa_ok=True, envelope_ok=True)
    assert out["classification"] == "egg_variant"
    assert out["egg_hits"] == 1


def test_classify_target_no_egg():
    regions = {0x8E6A0: bytes(0x100)}
    fp = deep_probe.verify_patch_fingerprint(regions, [])
    bi = deep_probe.verify_boot_integrity(_adjust_region(0x1234ABCD))
    out = deep_probe.classify_target(fp, bi, sa_ok=True, envelope_ok=True)
    assert out["classification"] == "no_egg"


def test_classify_target_probe_incomplete():
    fp = deep_probe.verify_patch_fingerprint({}, [])
    bi = deep_probe.verify_boot_integrity(_adjust_region(ADJUST_WORD["original"]))
    out = deep_probe.classify_target(fp, bi, sa_ok=True, envelope_ok=True)
    assert out["classification"] == "probe_incomplete"


# --- run_deep_probe -----------------------------------------------------------

def test_run_deep_probe_flags_and_call_chain():
    result = StreamResult(
        registers={"2": 0x41, "17": 0xDEADBEEF},
        regions={0x8E6A0: bytes(0x100)},
        egg_candidates=[0x8E6C6],
        valid=True,
    )
    transport = MockTransport(result)
    out = deep_probe.run_deep_probe(transport, shellcode=b"\x00\x01")

    assert len(transport.uploads) == 1
    envelope, new_uds, expected_sha256 = transport.uploads[0]
    assert new_uds is False
    assert expected_sha256 is None
    assert len(envelope) == 0x1000

    plain = decrypt_envelope(envelope)
    block = plain[REQUEST_OFFSET:]
    assert block[:4] == b"PROB"
    assert block[4] == 0x03  # bit0 registers + bit1 egg scan
    assert block[5] == len(deep_probe.DEFAULT_REGIONS)

    assert out["registers"] == {"FAREASELC": 0x41, "FHVE3": 0xDEADBEEF}
    assert len(out["registers"]) == 2
    assert out["regions"] == {0x8E6A0: bytes(0x100)}
    assert out["egg_candidates"] == [0x8E6C6]
    assert out["stream_valid"] is True
    assert out["region_bad"] == []
    assert out["envelope_ok"] is True
    assert out["scan_egg"] is True
    assert out["error"] is None


def test_run_deep_probe_threads_external_envelope_pin():
    result = StreamResult(registers={}, regions={}, valid=True)
    transport = MockTransport(result)
    deep_probe.run_deep_probe(
        transport, shellcode=b"\x00\x01",
        expected_envelope_sha256="0" * 64,
    )
    _envelope, _new_uds, expected_sha256 = transport.uploads[0]
    assert expected_sha256 == "0" * 64


def test_run_deep_probe_no_egg_scan_flag():
    result = StreamResult(registers={}, regions={}, valid=False)
    transport = MockTransport(result)
    out = deep_probe.run_deep_probe(
        transport, shellcode=b"\x00\x01", scan_egg=False
    )
    envelope, _new_uds, _pin = transport.uploads[0]
    block = decrypt_envelope(envelope)[REQUEST_OFFSET:]
    assert block[4] == 0x01  # registers only
    assert out["scan_egg"] is False


def test_run_deep_probe_parses_stream_error():
    result = StreamResult(
        registers={}, regions={}, valid=False, error=(3, 0xEE)
    )
    transport = MockTransport(result)
    out = deep_probe.run_deep_probe(transport, shellcode=b"\x00\x01")
    assert out["stream_valid"] is False
    assert out["error"] == (3, 0xEE)


# --- constants ----------------------------------------------------------------

def test_default_regions_exact():
    assert deep_probe.DEFAULT_REGIONS == [
        (0x8E6A0, 0x100),
        (0xFFDE0, 0x40),
        (0x17D80, 0x40),
        (0xFEBF2CF8, 0x100),
    ]
