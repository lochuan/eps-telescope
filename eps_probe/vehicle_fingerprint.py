"""Vehicle fingerprint: identify the vehicle/platform by probing other ECUs.

Read-only. Probes the engine ECU (``0x7E0``) with a full identification-block
DID sweep (``0xF000-0xF1FF`` + ``0xF200-0xF2FF`` + ``0xFF00-0xFF01``, 770
DIDs) and a set of ~10 other Toyota ECUs with a small important-DID set —
mirroring openpilot's fw-query approach (tester present, default/extended
sessions only, never programming, no writes anywhere).

Depends on opendbc's ``UdsClient`` on comma; tests inject a duck-typed client
(the same shape as ``tests/test_uds_probe.py``).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Callable

from . import uds_probe

MAIN_ECU_ADDR = 0x7E0

# Main-ECU full sweep ranges (ISO-14229 identification + periodic + UDS version).
MAIN_ECU_DID_RANGES = [(0xF000, 0xF1FF), (0xF200, 0xF2FF), (0xFF00, 0xFF01)]

# openpilot Toyota ECU addresses on bus 0 (UDS-capable on 0xF1xx).
OTHER_ECU_ADDRS = [
    0x7D2,  # hybrid
    0x7B0,  # abs
    0x7D1,  # fwdRadar
    0x7D0,  # fwdCamera
    0x780,  # srs
    0x7E1,  # transmission
    0x7C4,  # hvac
    0x7C0,  # combination meter
    0x713,  # hv battery
    0x716,  # motor generator
]

# Important DIDs probed on the other ECUs (application ID / SW number /
# version / VIN / UDS version).
OTHER_ECU_DIDS = [0xF181, 0xF188, 0xF189, 0xF190, 0xFF00]

FINGERPRINT_TIMEOUT = 0.5


def main_ecu_dids() -> list[int]:
    """Flatten the main-ECU sweep ranges to a list of DIDs."""
    return [d for start, end in MAIN_ECU_DID_RANGES for d in range(start, end + 1)]


def _scan(uds: Any, dids: list[int], timeout: float) -> list[dict]:
    return uds_probe.probe_dids(SimpleNamespace(uds=uds), dids, timeout=timeout)


def scan_main_ecu(uds: Any, timeout: float = FINGERPRINT_TIMEOUT) -> list[dict]:
    """Full identification-block DID sweep on the engine ECU (read-only)."""
    return _scan(uds, main_ecu_dids(), timeout)


def scan_other_ecus(
    uds_factory: Callable[[int], Any],
    addrs: list[int] | None = None,
    dids: list[int] | None = None,
    timeout: float = FINGERPRINT_TIMEOUT,
) -> dict[int, list[dict]]:
    """Scan the important DID set on each other ECU address.

    ``uds_factory(addr)`` must return a client with ``read_data_by_identifier``
    and an optional ``close``; each client is closed after its scan.
    """
    addrs = OTHER_ECU_ADDRS if addrs is None else addrs
    dids = OTHER_ECU_DIDS if dids is None else dids
    results: dict[int, list[dict]] = {}
    for addr in addrs:
        uds = uds_factory(addr)
        try:
            results[addr] = _scan(uds, dids, timeout)
        finally:
            close = getattr(uds, "close", None)
            if close is not None:
                close()
    return results


def extract_vin(main_ecu: list[dict]) -> str | None:
    """Pull the VIN string from the main-ECU 0xF190 read, if present."""
    for record in main_ecu:
        if record["did"] == 0xF190 and record["status"] == "ok" and record["data"]:
            raw = bytes(record["data"])
            return raw.decode("latin-1", errors="replace").rstrip("\x00")
    return None


def fingerprint(
    main_uds: Any,
    other_uds_factory: Callable[[int], Any],
    *,
    addrs: list[int] | None = None,
) -> dict:
    """Run the whole vehicle fingerprint.

    Returns ``{"main_ecu": [...], "ecus": {addr: [...]}, "vin": str|None}``.
    The main-ECU scan first switches to the extended session (non-destructive,
    openpilot style); if that is rejected the sweep still runs in the current
    session. Other ECUs are read one address at a time.
    """
    try:
        main_uds.diagnostic_session_control(uds_probe.SESSION_EXTENDED)
    except Exception:
        pass  # some ECUs reject extended; read in the current session
    main = scan_main_ecu(main_uds)
    others = scan_other_ecus(other_uds_factory, addrs=addrs)
    return {"main_ecu": main, "ecus": others, "vin": extract_vin(main)}
