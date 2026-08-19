import hashlib
import struct
from types import SimpleNamespace

import pytest
from Crypto.Cipher import AES

from eps_probe import transport
from eps_probe.protocol import crc32_update

ADDR = 0x7A1
RESP_ADDR = ADDR + 8
BUS = 0

ENVELOPE = b"\xAA" * 0x1000
PIN = "0" * 64


class FakePanda:
    def __init__(self, serial=None, frames=()):
        self.serial = serial
        self.frames = list(frames)
        self.safety_mode = None
        self.closed = False

    def set_safety_mode(self, mode):
        self.safety_mode = mode

    def can_recv(self):
        while self.frames:
            yield self.frames.pop(0)

    def close(self):
        self.closed = True


class FakeUdsClient:
    def __init__(self, panda, req_id, resp_id, bus, timeout=None,
                 response_pending_timeout=None):
        self.req_id = req_id
        self.resp_id = resp_id
        self.bus = bus
        self.timeout = timeout
        self.response_pending_timeout = response_pending_timeout
        self.calls = []
        self.seed = b"\x11" * 16
        self.security_access_error = None
        self.read_responses = []

    def _record(self, method, *args, **kwargs):
        self.calls.append((method, args, kwargs))

    def diagnostic_session_control(self, session):
        self._record("diagnostic_session_control", session)
        return b"\x50"

    def read_data_by_identifier(self, did):
        self._record("read_data_by_identifier", did)
        if self.read_responses:
            return self.read_responses.pop(0)
        return b""

    def security_access(self, access, data_record=None, security_key=None):
        self._record("security_access", access,
                     data_record=data_record, security_key=security_key)
        if self.security_access_error:
            raise self.security_access_error
        if data_record is not None:
            return self.seed
        return b"\x67" + (security_key or b"")

    def write_data_by_identifier(self, did, data):
        self._record("write_data_by_identifier", did, data)
        return b"\x6f" + struct.pack(">H", did) + b"\x00"

    def _uds_request(self, service, data=b""):
        self._record("_uds_request", service, data)
        return b"\x34\x02\x01\x00"

    def transfer_data(self, block, chunk):
        self._record("transfer_data", block, chunk)
        return b"\x36\x01"

    def request_transfer_exit(self):
        self._record("request_transfer_exit")
        return b"\x37"

    def routine_control(self, start, rid, option):
        self._record("routine_control", start, rid, option)
        return b"\x71\x10\xf0"


def make_bindings(panda, uds_factory, isotp_send):
    return SimpleNamespace(
        Panda=lambda serial=None: panda,
        UdsClient=uds_factory,
        elm327=0x20000,
        session_default=0x01,
        session_extended=0x03,
        session_programming=0x02,
        access_request_seed=0x01,
        access_send_key=0x02,
        service_request_download=0x34,
        routine_start=0x01,
        isotp_send=isotp_send,
    )


@pytest.fixture
def harness():
    panda = FakePanda()
    sleeps = []
    isotp_calls = []
    created = {"uds": None}

    def uds_factory(*args, **kwargs):
        created["uds"] = FakeUdsClient(*args, **kwargs)
        return created["uds"]

    bindings = make_bindings(
        panda, uds_factory, lambda *a, **k: isotp_calls.append((a, k))
    )
    tr = transport.EcuTransport(
        serial=None, addr=ADDR, bus=BUS, bindings=bindings,
        sleeper=sleeps.append,
    )
    with tr:
        yield SimpleNamespace(
            transport=tr, panda=panda, uds=created["uds"], sleeps=sleeps,
            isotp_calls=isotp_calls,
        )


def test_seed_key_secret_constant():
    assert transport.SEED_KEY_SECRET == bytes.fromhex(
        "f05f36b7d78c03e24ab4faef2a57d044"
    )


def test_derive_security_key_matches_aes_reference():
    seed = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    zeros = bytes(16)
    intermediate = AES.new(transport.SEED_KEY_SECRET, AES.MODE_ECB).decrypt(zeros)
    expected = AES.new(intermediate, AES.MODE_ECB).encrypt(seed)
    assert transport.derive_security_key(seed, transport.SEED_KEY_SECRET) == expected
    assert len(expected) == 16


def test_uds_client_uses_response_pending_timeout(harness):
    assert harness.uds.response_pending_timeout == 10.0


def test_session_ladder_order_and_settle(harness):
    harness.transport.session_ladder()
    sessions = [
        c[1][0] for c in harness.uds.calls
        if c[0] == "diagnostic_session_control"
    ]
    assert sessions == [0x01, 0x03, 0x02]
    assert harness.sleeps == [0.5, 0.7, 1.0]


def test_security_access_sends_derived_key(harness):
    harness.uds.seed = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert harness.transport.security_access() is True
    sa_calls = [c for c in harness.uds.calls if c[0] == "security_access"]
    assert [c[1][0] for c in sa_calls] == [0x01, 0x02]
    assert sa_calls[0][2] == {
        "data_record": bytes(16), "security_key": None,
    }
    expected_key = transport.derive_security_key(
        harness.uds.seed, transport.SEED_KEY_SECRET
    )
    assert sa_calls[1][2]["security_key"] == expected_key


def test_security_access_returns_false_on_negative_response(harness):
    harness.uds.security_access_error = RuntimeError("security access denied")
    assert harness.transport.security_access() is False


def test_security_access_rejects_wrong_seed_length(harness):
    harness.uds.seed = b"\x00" * 4
    with pytest.raises(transport.TransportError):
        harness.transport.security_access()


def test_prepare_and_upload_sequence_old_uds(harness):
    harness.transport.prepare_and_upload(
        ENVELOPE, hashlib.sha256(ENVELOPE).hexdigest(), new_uds=False
    )
    calls = harness.uds.calls
    assert [c[0] for c in calls] == [
        "write_data_by_identifier",
        "write_data_by_identifier",
        "write_data_by_identifier",
        "_uds_request",
        "transfer_data",
        "transfer_data",
        "transfer_data",
        "transfer_data",
        "request_transfer_exit",
        "routine_control",
    ]
    writes = [c for c in calls if c[0] == "write_data_by_identifier"]
    assert [c[1][0] for c in writes] == [0x203, 0x201, 0x202]
    assert writes[0][1][1] == b"\x00" * 5
    assert writes[1][1][1] == bytes(16)
    assert writes[2][1][1] == bytes(16)

    rd = [c for c in calls if c[0] == "_uds_request"][0]
    assert rd[1][0] == 0x34
    assert rd[1][1] == b"\x01\x46\x01\x00" + struct.pack("!II", 0xFEBF0000, 0x1000)

    transfers = [c for c in calls if c[0] == "transfer_data"]
    assert len(transfers) == 4
    for i, call in enumerate(transfers):
        assert call[1][0] == i + 1
        assert call[1][1] == ENVELOPE[i * 0x400:(i + 1) * 0x400]

    rc = [c for c in calls if c[0] == "routine_control"][0]
    assert rc[1][0] == 0x01
    assert rc[1][1] == 0x10F0
    assert rc[1][2] == b"\x45\x00" + struct.pack("!II", 0xFEBF0000, 0x1000)


def test_prepare_and_upload_new_uds_routine_magic(harness):
    harness.transport.prepare_and_upload(
        ENVELOPE, hashlib.sha256(ENVELOPE).hexdigest(), new_uds=True
    )
    rc = [c for c in harness.uds.calls if c[0] == "routine_control"][0]
    assert rc[1][2][:2] == b"\x45\x01"
    assert rc[1][2][2:] == struct.pack("!II", 0xFEBF0000, 0x1000)


def test_upload_and_trigger_sends_raw_trigger_frame(harness):
    harness.transport.upload_and_trigger(ENVELOPE, new_uds=False)
    assert len(harness.isotp_calls) == 1
    args, kwargs = harness.isotp_calls[0]
    assert args[1] == b"\x31\x01\xff\x00\x45\x00" + struct.pack("!II", 0xE0000, 0x8000)
    assert args[2] == ADDR
    assert kwargs == {"bus": BUS}


def test_upload_and_trigger_new_uds_magic(harness):
    harness.transport.upload_and_trigger(ENVELOPE, new_uds=True)
    args, _kwargs = harness.isotp_calls[0]
    assert args[1] == b"\x31\x01\xff\x00\x45\x01" + struct.pack("!II", 0xE0000, 0x8000)


def test_prepare_and_upload_rejects_sha256_mismatch(harness):
    with pytest.raises(transport.TransportError, match="SHA-256"):
        harness.transport.prepare_and_upload(ENVELOPE, PIN, new_uds=False)
    assert harness.uds.calls == []


def test_prepare_and_upload_rejects_wrong_length(harness):
    with pytest.raises(transport.TransportError, match="0x1000"):
        harness.transport.prepare_and_upload(b"\xAA" * 0x800, PIN, new_uds=False)


def test_read_identity_reads_app_then_boot_after_ladder(harness):
    harness.uds.read_responses = [b"APP-APP", b"BOOT-BOOT"]
    app, boot = harness.transport.read_identity()
    assert app == b"APP-APP"
    assert boot == b"BOOT-BOOT"
    dids = [
        c[1][0] for c in harness.uds.calls
        if c[0] == "read_data_by_identifier"
    ]
    assert dids == [0xF181, 0xF181]
    sessions = [
        c[1][0] for c in harness.uds.calls
        if c[0] == "diagnostic_session_control"
    ]
    assert sessions == [0x01, 0x03, 0x02]


def _end_word_for(data_words):
    # Wire carries the STANDARD CRC (binascii.crc32 semantics = raw accumulator
    # XOR 0xFFFFFFFF), matching what deep_probe.c sends on the END frame.
    acc = 0xFFFFFFFF
    for word in data_words:
        for byte in struct.pack("<I", word):
            acc = crc32_update(acc, byte)
    return acc ^ 0xFFFFFFFF


def test_collect_stream_skips_pending_and_returns_result(harness):
    data_word = 0x11223344
    harness.panda.frames.extend([
        (RESP_ADDR, b"\x03\x7f\x31\x78\x00\x00\x00\x00", BUS),
        (RESP_ADDR, b"\xb0\x01\x00\x00" + b"\x00" * 4, BUS),
        (RESP_ADDR, b"\xb2\x01\x00\x00" + struct.pack("<I", data_word), BUS),
        (RESP_ADDR, b"\xe0\x01\x00\x00" + struct.pack("<I", _end_word_for([data_word])), BUS),
    ])
    result = harness.transport.collect_stream(timeout=5.0)
    assert result.valid is True
    assert result.registers == {"0": data_word}


def test_collect_stream_raises_on_negative_response(harness):
    harness.panda.frames.append((RESP_ADDR, b"\x03\x7f\x31\x31\x00\x00\x00\x00", BUS))
    with pytest.raises(transport.TransportError, match="NRC 0x31"):
        harness.transport.collect_stream(timeout=5.0)


def test_collect_stream_times_out(harness):
    with pytest.raises(transport.TransportError, match="timed out"):
        harness.transport.collect_stream(timeout=0.01)


def test_close_closes_panda(harness):
    assert harness.panda.closed is False
    harness.transport.close()
    assert harness.panda.closed is True
    assert harness.transport.panda is None
