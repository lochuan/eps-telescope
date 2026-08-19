"""Layer 1 UDS enumeration probes: SID support, DID ranges, RIDs, download acceptance.

Tests drive a recording fake UdsClient (duck-typed to opendbc's shapes); no
real hardware, panda, or opendbc import is involved.
"""

from types import SimpleNamespace

import pytest

from eps_probe import uds_probe


class NegativeResponse(Exception):
    """Duck-typed shape of opendbc ``NegativeResponseError``."""

    def __init__(self, error_code, service_id=0):
        super().__init__("negative response")
        self.error_code = error_code
        self.service_id = service_id


class MessageTimeoutError(Exception):
    """Duck-typed shape of opendbc ``MessageTimeoutError``."""


class FakeUdsClient:
    def __init__(self):
        self.timeout = 1.0
        self.calls = []
        self.sid_responses = {}
        self.did_responses = {}
        self.rid_responses = {}
        self.download_responses = {}
        self.session_error = None
        self.tester_present_error = None

    def _record(self, method, *args):
        self.calls.append((method, args, self.timeout))

    def _pop(self, table, key, default):
        entry = table.get(key, default)
        if isinstance(entry, list):
            return entry.pop(0) if entry else default
        return entry

    def diagnostic_session_control(self, session):
        self._record("diagnostic_session_control", session)
        if self.session_error:
            raise self.session_error
        return b"\x50" + session.to_bytes(1, "big")

    def tester_present(self):
        self._record("tester_present")
        if self.tester_present_error:
            raise self.tester_present_error
        return b"\x7e\x00"

    def _uds_request(self, sid, subfunction=None, data=None):
        self._record("_uds_request", sid)
        resp = self._pop(self.sid_responses, sid, NegativeResponse(0x11))
        if isinstance(resp, Exception):
            raise resp
        return resp

    def read_data_by_identifier(self, did):
        self._record("read_data_by_identifier", did)
        resp = self._pop(self.did_responses, did, NegativeResponse(0x11))
        if isinstance(resp, Exception):
            raise resp
        return resp

    def routine_control(self, rc_type, rid, option):
        self._record("routine_control", rc_type, rid, option)
        resp = self._pop(self.rid_responses, rid, NegativeResponse(0x31))
        if isinstance(resp, Exception):
            raise resp
        return resp

    def request_download(self, address, size, **kwargs):
        self._record("request_download", address, size)
        ram_addr = uds_probe.DOWNLOAD_TARGETS["ram"][0]
        key = "ram" if address == ram_addr else "flash"
        resp = self._pop(self.download_responses, key, NegativeResponse(0x70))
        if isinstance(resp, Exception):
            raise resp
        return resp


@pytest.fixture
def client():
    return FakeUdsClient()


@pytest.fixture
def transport(client):
    return SimpleNamespace(uds=client)


# --- Constants ---------------------------------------------------------------

def test_sid_all_is_unique_and_covers_at_least_20():
    assert len(uds_probe.SID_ALL) >= 20
    assert len(uds_probe.SID_ALL) == len(set(uds_probe.SID_ALL))
    assert all(isinstance(s, int) for s in uds_probe.SID_ALL)


def test_sid_all_covers_opendbc_service_type_and_stub_set():
    for sid in (0x10, 0x11, 0x22, 0x27, 0x2E, 0x31, 0x34, 0x3E):
        assert sid in uds_probe.SID_ALL
    assert set(uds_probe.SID_STUBS) <= set(uds_probe.SID_ALL)


def test_nrc_names_is_exact_egg_hunter_subset():
    expected = {0x10, 0x11, 0x12, 0x13, 0x22, 0x24, 0x25, 0x26, 0x31, 0x33,
                0x35, 0x36, 0x37, 0x70, 0x71, 0x72, 0x73, 0x78, 0x7E, 0x7F}
    assert set(uds_probe.NRC_NAMES) == expected
    assert len(uds_probe.NRC_NAMES) == 20


def test_did_ranges_default():
    assert uds_probe.DID_RANGES == [
        (0xF180, 0xF19F), (0x200, 0x2FF), (0x0000, 0x00FF),
    ]


# --- probe_sessions ----------------------------------------------------------

def test_probe_sessions_records_ok_nrc_timeout(client, transport):
    client.sid_responses = {
        0x22: b"\x62\xf1\x81\xaa",
        0x3E: NegativeResponse(0x7E),
        0x31: MessageTimeoutError("timeout"),
    }
    results = uds_probe.probe_sessions(transport, [0x01])
    assert len(results) == 1
    record = results[0]
    assert set(record) == {"session", "services"}
    assert record["session"] == 0x01
    services = {s["sid"]: s for s in record["services"]}
    assert services[0x22]["status"] == "ok"
    assert services[0x22]["nrc"] is None
    assert services[0x3E]["status"] == "nrc"
    assert services[0x3E]["nrc"] == 0x7E
    assert services[0x31]["status"] == "timeout"
    assert services[0x31]["nrc"] is None
    assert services[0x10]["status"] == "nrc"
    assert services[0x10]["nrc"] == 0x11
    for s in record["services"]:
        assert set(s) == {"sid", "status", "nrc"}


def test_probe_sessions_uses_default_session_ladder(client, transport):
    results = uds_probe.probe_sessions(transport)
    assert [r["session"] for r in results] == [0x01, 0x03, 0x02]
    dsc = [c for c in client.calls if c[0] == "diagnostic_session_control"]
    assert [c[1][0] for c in dsc] == [0x01, 0x03, 0x02]
    tp = [c for c in client.calls if c[0] == "tester_present"]
    assert len(tp) == 3


def test_probe_sessions_retries_once_on_nrc_0x78(client, transport):
    client.sid_responses[0x22] = [NegativeResponse(0x78), b"\x62\x00\xaa"]
    results = uds_probe.probe_sessions(transport, [0x01])
    by_sid = {s["sid"]: s for s in results[0]["services"]}
    assert by_sid[0x22]["status"] == "ok"
    assert by_sid[0x22]["nrc"] is None
    calls = [c for c in client.calls
             if c[0] == "_uds_request" and c[1][0] == 0x22]
    assert len(calls) == 2


def test_probe_sessions_0x78_then_0x78_on_retry_records_nrc(client, transport):
    client.sid_responses[0x22] = [NegativeResponse(0x78), NegativeResponse(0x78)]
    results = uds_probe.probe_sessions(transport, [0x01])
    by_sid = {s["sid"]: s for s in results[0]["services"]}
    assert by_sid[0x22]["status"] == "nrc"
    assert by_sid[0x22]["nrc"] == 0x78
    calls = [c for c in client.calls
             if c[0] == "_uds_request" and c[1][0] == 0x22]
    assert len(calls) == 2


def test_probe_sessions_0x78_then_timeout_on_retry_records_timeout(client, transport):
    client.sid_responses[0x22] = [
        NegativeResponse(0x78), MessageTimeoutError("timeout"),
    ]
    results = uds_probe.probe_sessions(transport, [0x01])
    by_sid = {s["sid"]: s for s in results[0]["services"]}
    assert by_sid[0x22]["status"] == "timeout"
    assert by_sid[0x22]["nrc"] is None
    calls = [c for c in client.calls
             if c[0] == "_uds_request" and c[1][0] == 0x22]
    assert len(calls) == 2


def test_probe_sessions_skips_dead_session(client, transport):
    client.tester_present_error = MessageTimeoutError("timeout")
    results = uds_probe.probe_sessions(transport, [0x01])
    assert results == [{"session": 0x01, "services": []}]
    assert not [c for c in client.calls if c[0] == "_uds_request"]


def test_probe_sessions_skips_unreachable_session(client, transport):
    client.session_error = NegativeResponse(0x7F)
    results = uds_probe.probe_sessions(transport, [0x01])
    assert results == [{"session": 0x01, "services": []}]


def test_probe_sessions_applies_per_request_timeout(client, transport):
    client.sid_responses[0x22] = b"\x62\x00\xaa"
    uds_probe.probe_sessions(transport, [0x01], timeout=0.5)
    assert client.timeout == 1.0
    probes = [c for c in client.calls if c[0] == "_uds_request"]
    assert probes and all(c[2] == 0.5 for c in probes)


# --- probe_dids --------------------------------------------------------------

def test_probe_dids_walks_blocks_and_respects_timeout(client, transport):
    client.did_responses = {
        0xF180: b"\xaa\xbb",
        0xF181: NegativeResponse(0x31),
        0xF182: MessageTimeoutError("timeout"),
    }
    results = uds_probe.probe_dids(transport, [(0xF180, 0xF182)])
    assert [r["did"] for r in results] == [0xF180, 0xF181, 0xF182]
    assert results[0] == {"did": 0xF180, "status": "ok",
                          "nrc": None, "data": b"\xaa\xbb"}
    assert results[1] == {"did": 0xF181, "status": "nrc",
                          "nrc": 0x31, "data": None}
    assert results[2] == {"did": 0xF182, "status": "timeout",
                          "nrc": None, "data": None}


def test_probe_dids_default_ranges_walk_end_inclusive(client, transport):
    results = uds_probe.probe_dids(transport)
    expected = sum(end - start + 1 for start, end in uds_probe.DID_RANGES)
    assert expected == 0x20 + 0x100 + 0x100
    assert len(results) == expected
    assert results[0]["did"] == 0xF180
    assert results[-1]["did"] == 0x00FF
    dids = [c[1][0] for c in client.calls
            if c[0] == "read_data_by_identifier"]
    assert dids[0] == 0xF180
    assert dids[-1] == 0x00FF


# --- probe_routines ----------------------------------------------------------

def test_probe_routines_records_nrc_without_trigger(client, transport):
    client.rid_responses = {
        0x10F0: NegativeResponse(0x31),
        0x10F3: b"\x71\x10\xf3\x00",
        0xFF00: NegativeResponse(0x7E),
    }
    results = uds_probe.probe_routines(transport, [0x10F0, 0x10F3, 0xFF00])
    by_rid = {r["rid"]: r for r in results}
    assert by_rid[0x10F0] == {"rid": 0x10F0, "status": "nrc", "nrc": 0x31}
    assert by_rid[0x10F3] == {"rid": 0x10F3, "status": "ok", "nrc": None}
    assert by_rid[0xFF00] == {"rid": 0xFF00, "status": "nrc", "nrc": 0x7E}
    rc = [c for c in client.calls if c[0] == "routine_control"]
    assert len(rc) == 3
    assert rc[0][1] == (0x01, 0x10F0, b"")
    assert rc[1][1] == (0x03, 0x10F3, b"")
    assert rc[2][1] == (0x01, 0xFF00, b"")


def test_probe_routines_known_rids_default(client, transport):
    results = uds_probe.probe_routines(transport)
    assert [r["rid"] for r in results] == uds_probe.RIDS_KNOWN
    rc = [c for c in client.calls if c[0] == "routine_control"]
    assert all(c[1][2] == b"" for c in rc)


# --- probe_download_acceptance ------------------------------------------------

def test_probe_download_acceptance_records_ram_ok_flash_nrc(client, transport):
    client.download_responses = {
        "ram": 0x400,
        "flash": NegativeResponse(0x70),
    }
    out = uds_probe.probe_download_acceptance(transport)
    assert set(out) == {"ram", "flash"}
    assert out["ram"] == {
        "address": 0xFEBF0000,
        "size": 0x1000,
        "status": "ok",
        "max_block_length": 0x400,
        "nrc": None,
    }
    assert out["flash"]["status"] == "nrc"
    assert out["flash"]["nrc"] == 0x70
    assert out["flash"]["max_block_length"] is None
    assert [c[0] for c in client.calls] == [
        "request_download", "request_download",
    ]


def test_probe_download_acceptance_records_timeout(client, transport):
    client.download_responses = {"flash": MessageTimeoutError("timeout")}
    out = uds_probe.probe_download_acceptance(transport)
    assert out["flash"]["status"] == "timeout"
    assert out["flash"]["nrc"] is None
    assert out["flash"]["max_block_length"] is None
