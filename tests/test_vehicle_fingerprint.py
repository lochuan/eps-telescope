"""Vehicle fingerprint module: main-ECU full sweep + other-ECU important DIDs.

Tests inject a duck-typed UdsClient (same shape as test_uds_probe.py); no real
hardware or opendbc import.
"""

import pytest

from eps_probe import vehicle_fingerprint as vf


class NegativeResponse(Exception):
    def __init__(self, error_code, service_id=0):
        super().__init__("negative response")
        self.error_code = error_code
        self.service_id = service_id


class MessageTimeoutError(Exception):
    pass


class FakeUdsClient:
    def __init__(self):
        self.timeout = 1.0
        self.did_responses = {}
        self.session_error = None
        self.calls = []

    def _pop(self, table, key, default):
        entry = table.get(key, default)
        if isinstance(entry, list):
            return entry.pop(0) if entry else default
        return entry

    def diagnostic_session_control(self, session):
        self.calls.append(("dsc", session))
        if self.session_error:
            raise self.session_error
        return b"\x50" + session.to_bytes(1, "big")

    def read_data_by_identifier(self, did):
        self.calls.append(("rdbi", did))
        resp = self._pop(self.did_responses, did, NegativeResponse(0x11))
        if isinstance(resp, Exception):
            raise resp
        return resp


def test_main_ecu_dids_flattens_ranges():
    dids = vf.main_ecu_dids()
    assert len(dids) == 0x200 + 0x100 + 0x02  # 770
    assert dids[0] == 0xF000
    assert dids[-1] == 0xFF01
    assert 0xF181 in dids and 0xF190 in dids and 0xFF00 in dids


def test_scan_main_ecu_records_name_and_status():
    client = FakeUdsClient()
    client.did_responses = {
        0xF190: b"JTXXXXXXXXXXXXXXXX",
        0xF181: NegativeResponse(0x31),
        0xF120: MessageTimeoutError("timeout"),
    }
    results = vf.scan_main_ecu(client, timeout=0.2)
    assert len(results) == 770
    by_did = {r["did"]: r for r in results}
    assert by_did[0xF190]["status"] == "ok"
    assert by_did[0xF190]["name"] == "VIN(0xF190)"
    assert by_did[0xF190]["data"] == b"JTXXXXXXXXXXXXXXXX"
    assert by_did[0xF181]["status"] == "nrc"
    assert by_did[0xF181]["nrc"] == 0x31
    assert by_did[0xF120]["status"] == "timeout"
    assert by_did[0xF120]["name"] == "VehicleManufacturerIdentification(0xF120)"
    assert client.timeout == 1.0  # restored after the 0.2s override


def test_scan_other_ecus_per_addr_and_closes():
    created, closed = [], []

    def factory(addr):
        client = FakeUdsClient()
        client.did_responses = {0xF188: b"\x01SW\x00", 0xF190: b"VINX"}
        client.close = lambda: closed.append(addr)
        created.append(addr)
        return client

    results = vf.scan_other_ecus(
        factory, addrs=[0x7D2, 0x7B0], dids=[0xF188, 0xF190], timeout=0.3
    )
    assert sorted(results) == [0x7B0, 0x7D2]
    assert results[0x7D2][0]["did"] == 0xF188
    assert results[0x7D2][0]["status"] == "ok"
    assert closed == created  # every client closed after its scan


def test_extract_vin():
    main = [
        {"did": 0xF181, "status": "nrc", "data": None},
        {"did": 0xF190, "status": "ok", "data": b"JT1ABCDE123456789\x00\x00"},
    ]
    assert vf.extract_vin(main) == "JT1ABCDE123456789"


def test_extract_vin_none_when_absent():
    assert vf.extract_vin([{"did": 0xF190, "status": "nrc", "data": None}]) is None
    assert vf.extract_vin([]) is None


def test_fingerprint_orchestrates():
    main = FakeUdsClient()
    main.did_responses = {0xF190: b"JT000000000000000"}

    def factory(addr):
        client = FakeUdsClient()
        client.did_responses = {0xF188: b"\x01abc"}
        client.close = lambda: None
        return client

    result = vf.fingerprint(main, factory, addrs=[0x7D2])
    assert result["vin"] == "JT000000000000000"
    assert len(result["main_ecu"]) == 770
    assert sorted(result["ecus"]) == [0x7D2]


def test_fingerprint_ignores_extended_session_rejection():
    main = FakeUdsClient()
    main.session_error = NegativeResponse(0x7F)
    main.did_responses = {0xF181: b"x"}

    def factory(addr):
        client = FakeUdsClient()
        client.close = lambda: None
        return client

    result = vf.fingerprint(main, factory, addrs=[0x7D2])
    assert len(result["main_ecu"]) == 770
