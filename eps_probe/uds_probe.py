"""Layer 1 read-only UDS enumeration for the RH850 EPS probe.

Drives a UdsClient (through ``EcuTransport``) to map what the ECU exposes in
each diagnostic session: which standard SIDs answer (recording the positive
response or NRC), which DIDs in the interesting ranges read, whether the known
routines reject or answer, and whether RequestDownload (0x34) is accepted for
the RAM staging address and flash — without transferring any data.

Everything is read-only. SID probing sends the bare SID byte: any real action
needs a request body, so the worst an ECU can do is answer an NRC. Routine
probing uses an empty option record so nothing triggers (0x10F3 is a
REQUEST_RESULTS status query, the others START with no option). Download
acceptance stops after the 0x34 request. Per-request timeout defaults to 1s and
a 0x78 response-pending is re-collected once.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

# --- UDS constants -----------------------------------------------------------

# Negative response codes (egg-hunter subset), for the report's NRC name lookup.
NRC_NAMES: dict[int, str] = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x25: "noResponseFromSubnetComponent",
    0x26: "failurePreventsExecutionOfRequestedAction",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceedNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted",
    0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure",
    0x73: "wrongBlockSequenceCounter",
    0x78: "requestCorrectlyReceivedResponsePending",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}

# Diagnostic sessions (opendbc SESSION_TYPE values).
SESSION_DEFAULT = 0x01
SESSION_EXTENDED = 0x03
SESSION_PROGRAMMING = 0x02

# Every opendbc SERVICE_TYPE, plus the stub SIDs that have no high-level
# UdsClient method and therefore need a raw request.
SID_OPENDBC = {
    0x10, 0x11, 0x14, 0x19, 0x22, 0x23, 0x24, 0x27, 0x28, 0x2A,
    0x2C, 0x2E, 0x2F, 0x31, 0x34, 0x35, 0x36, 0x37, 0x3D, 0x3E,
    0x83, 0x84, 0x85, 0x86, 0x87,
}
SID_STUBS = {0x14, 0x19, 0x2C, 0x2F, 0x35, 0x3D, 0x83, 0x84, 0x86, 0x87}
SID_ALL = sorted(SID_OPENDBC | SID_STUBS)

# EPS targeted DIDs. Only the DIDs whose meaning/semantics are known from
# firmware RE are probed — no full-range sweep on the EPS (its UDS surface is
# minimal and already fingerprinted by the shellcode deep probe):
#   - 0xF181  application software identification (readable, primary variant signal)
#   - 0x201/0x202/0x203  write-only flash-routine DIDs (KDF key / IV / state
#     machine prereq) known from RE; 0x22 read returns NRC, but presence in the
#     table confirms the variant.
#   - 0xF188/0xF190/0xFF00  known-absent confirmations: the validated variant
#     returns NRC 0x31 for these; a response would reveal a different variant.
EPS_TARGET_DIDS = [0xF181, 0x201, 0x202, 0x203, 0xF188, 0xF190, 0xFF00]

# Exact DID names for the ISO-14229 identification block (opendbc
# DATA_IDENTIFIER_TYPE), the UDS version DIDs, and the RE-known write DIDs.
DID_NAMES: dict[int, str] = {
    0x201: "Write.SAKdfKey",
    0x202: "Write.SAIv",
    0x203: "Write.StatePrereq",
    0xF180: "BootSoftwareIdentification",
    0xF181: "ApplicationSoftwareIdentification",
    0xF182: "ApplicationDataIdentification",
    0xF183: "BootSoftwareFingerprint",
    0xF184: "ApplicationSoftwareFingerprint",
    0xF185: "ApplicationDataFingerprint",
    0xF186: "ActiveDiagnosticSession",
    0xF187: "VehicleManufacturerSparePartNumber",
    0xF188: "VehicleManufacturerEcuSoftwareNumber",
    0xF189: "VehicleManufacturerEcuSoftwareVersionNumber",
    0xF18A: "SystemSupplierIdentifier",
    0xF18B: "EcuManufacturingDate",
    0xF18C: "EcuSerialNumber",
    0xF18D: "SupportedFunctionalUnits",
    0xF18E: "VehicleManufacturerKitAssemblyPartNumber",
    0xF18F: "RegulationXSoftwareIdentificationNumbers",
    0xF190: "VIN",
    0xF191: "VehicleManufacturerEcuHardwareNumber",
    0xF192: "SystemSupplierEcuHardwareNumber",
    0xF193: "SystemSupplierEcuHardwareVersionNumber",
    0xF194: "SystemSupplierEcuSoftwareNumber",
    0xF195: "SystemSupplierEcuSoftwareVersionNumber",
    0xF196: "ExhaustRegulationOrTypeApprovalNumber",
    0xF197: "SystemNameOrEngineType",
    0xF198: "RepairShopCodeOrTesterSerialNumber",
    0xF199: "ProgrammingDate",
    0xF19A: "CalibrationRepairShopCodeOrEquipmentSerialNumber",
    0xF19B: "CalibrationDate",
    0xF19C: "CalibrationEquipmentSoftwareNumber",
    0xF19D: "EcuInstallationDate",
    0xF19E: "OdxFile",
    0xF19F: "Entity",
    0xFF00: "UdsVersion",
    0xFF01: "ReservedForIso15765_5",
}

# Range-category labels (ISO-14229) for DIDs without a single-name meaning.
_DID_RANGE_LABELS: list[tuple[int, int, str]] = [
    (0x0000, 0x00FF, "ISOSAEReserved"),
    (0x0100, 0xA5FF, "VehicleManufacturerSpecific"),
    (0xA600, 0xA7FF, "ReservedForLegislativeUse"),
    (0xA800, 0xACFF, "VehicleManufacturerSpecific"),
    (0xB000, 0xB1FF, "VehicleManufacturerSpecific"),
    (0xC000, 0xC2FF, "VehicleManufacturerSpecific"),
    (0xCF00, 0xEFFF, "VehicleManufacturerSpecific"),
    (0xF000, 0xF00F, "TrailerNetworkConfiguration"),
    (0xF010, 0xF0FF, "VehicleManufacturerSpecific"),
    (0xF100, 0xF17F, "VehicleManufacturerIdentification"),
    (0xF1A0, 0xF1EF, "VehicleManufacturerIdentification"),
    (0xF1F0, 0xF1FF, "SystemSupplierIdentification"),
    (0xF200, 0xF2FF, "PeriodicDataIdentifier"),
    (0xF300, 0xF3FF, "DynamicallyDefinedDataIdentifier"),
    (0xF400, 0xF7FF, "OBDDataIdentifier"),
    (0xF800, 0xF8FF, "OBDInfoTypeDataIdentifier"),
    (0xFA00, 0xFA0F, "AirbagDeploymentDataIdentifier"),
    (0xFA19, 0xFAFF, "SafetySystemDataIdentifier"),
    (0xFD00, 0xFEFF, "SystemSupplierSpecific"),
]


def did_label(did: int) -> str:
    """Return a display label ``Name(0xXXXX)`` for a DID.

    Known DIDs get their exact ISO/RE name; unknown DIDs get the ISO-14229
    range-category label for the block they fall in, e.g.
    ``ApplicationSoftwareIdentification(0xF181)`` or
    ``VehicleManufacturerSpecific(0xF120)``.
    """
    name = DID_NAMES.get(did)
    if name is None:
        name = "Unknown"
        for start, end, label in _DID_RANGE_LABELS:
            if start <= did <= end:
                name = label
                break
    return f"{name}(0x{did:04X})"

# RoutineControl subfunctions.
ROUTINE_START = 0x01
ROUTINE_REQUEST_RESULTS = 0x03

# Known routine identifiers. 0x10F3 is a status query (REQUEST_RESULTS with an
# empty option); the rest are probed with START + empty option so they cannot
# actually trigger.
RID_STATUS = 0x10F3
RIDS_KNOWN = [0x10F0, 0x10F1, 0x10F2, 0x10F3, 0xFF00, 0xFF01, 0xFF02]

# RequestDownload acceptance probe targets: (address, size) per slot.
DOWNLOAD_TARGETS = {
    "ram": (0xFEBF0000, 0x1000),
    "flash": (0x18000, 0x1000),
}


# --- Helpers -----------------------------------------------------------------

def _classify_error(exc: BaseException) -> tuple[str, int | None]:
    """Map a UDS client exception to (status, nrc); re-raise anything else.

    Duck-types opendbc's shapes so the probes work against any client that
    exposes an integer ``error_code`` for negative responses and raises
    ``MessageTimeoutError`` (or a ``TimeoutError``) on timeout.
    """
    nrc = getattr(exc, "error_code", None)
    if isinstance(nrc, int):
        return "nrc", nrc
    if isinstance(exc, TimeoutError) or type(exc).__name__ == "MessageTimeoutError":
        return "timeout", None
    raise exc


@contextmanager
def _uds_timeout(uds: Any, timeout: float):
    """Run one request under ``timeout`` seconds, restoring the client's own."""
    previous = getattr(uds, "timeout", None)
    if previous is not None:
        uds.timeout = timeout
    try:
        yield
    finally:
        if previous is not None:
            uds.timeout = previous


def _collect(uds: Any, timeout: float, fn) -> tuple[str, int | None, Any]:
    """Run one UDS request via ``fn``; retry once on NRC 0x78.

    Returns ``(status, nrc, data)`` where ``data`` is the request result on
    ``"ok"`` and ``None`` otherwise.
    """
    def attempt() -> Any:
        with _uds_timeout(uds, timeout):
            return fn()

    try:
        return "ok", None, attempt()
    except Exception as exc:
        status, nrc = _classify_error(exc)
        if status == "nrc" and nrc == 0x78:
            try:
                return "ok", None, attempt()
            except Exception as retry_exc:
                status, nrc = _classify_error(retry_exc)
                return status, nrc, None
        return status, nrc, None


# --- Layer 1 probes ----------------------------------------------------------

def probe_sessions(
    t, sessions: list[int] | None = None, timeout: float = 1.0
) -> list[dict]:
    """Per-session SID support enumeration (DEFAULT -> EXTENDED -> PROGRAMMING).

    After each session switch a TesterPresent (0x3E) confirms the session is
    alive; a dead session is recorded with an empty ``services`` list. Each SID
    in ``SID_ALL`` is probed with the bare SID byte and recorded as
    ``{"sid", "status": "ok|nrc|timeout", "nrc"}``.
    """
    uds = t.uds
    if sessions is None:
        sessions = [SESSION_DEFAULT, SESSION_EXTENDED, SESSION_PROGRAMMING]
    out: list[dict] = []
    for session in sessions:
        try:
            with _uds_timeout(uds, timeout):
                uds.diagnostic_session_control(session)
                uds.tester_present()
        except Exception as exc:
            _classify_error(exc)  # protocol anomalies re-raise; session dead
            out.append({"session": session, "services": []})
            continue
        services = []
        for sid in SID_ALL:
            status, nrc, _data = _collect(uds, timeout, lambda s=sid: uds._uds_request(s))
            services.append({"sid": sid, "status": status, "nrc": nrc})
        out.append({"session": session, "services": services})
    return out


def probe_dids(
    t, dids: list[int] | None = None, timeout: float = 1.0
) -> list[dict]:
    """Read each targeted DID via 0x22, recording status, NRC, data and a label.

    ``dids`` is a flat list of Data Identifiers (default ``EPS_TARGET_DIDS``).
    Records ``{"did", "name", "status", "nrc", "data"}`` where ``name`` is
    ``did_label(did)`` (e.g. ``"ApplicationSoftwareIdentification(0xF181)"``).
    """
    uds = t.uds
    if dids is None:
        dids = EPS_TARGET_DIDS
    out: list[dict] = []
    for did in dids:
        status, nrc, data = _collect(
            uds, timeout, lambda d=did: bytes(uds.read_data_by_identifier(d))
        )
        out.append({
            "did": did,
            "name": did_label(did),
            "status": status,
            "nrc": nrc,
            "data": data,
        })
    return out


def probe_routines(
    t, rids: list[int] | None = None, timeout: float = 1.0
) -> list[dict]:
    """Probe known routine identifiers conservatively.

    0x10F3 is a REQUEST_RESULTS status query (empty option). All other RIDs are
    probed with START and an empty option record, which cannot trigger the
    routine; the ECU's rejection NRC is recorded as proof of existence.
    Records ``{"rid", "status": "ok|nrc|timeout", "nrc"}``.
    """
    uds = t.uds
    if rids is None:
        rids = RIDS_KNOWN
    out: list[dict] = []
    for rid in rids:
        rc_type = ROUTINE_REQUEST_RESULTS if rid == RID_STATUS else ROUTINE_START
        status, nrc, _data = _collect(
            uds, timeout, lambda r=rid, c=rc_type: uds.routine_control(c, r, b"")
        )
        out.append({"rid": rid, "status": status, "nrc": nrc})
    return out


def probe_download_acceptance(t, timeout: float = 1.0) -> dict:
    """Probe whether RequestDownload (0x34) is accepted for RAM and flash.

    Sends the 0x34 request without transferring any data, recording the
    negotiated ``max_block_length`` or the NRC per target. Returns
    ``{"ram": {...}, "flash": {...}}``.
    """
    uds = t.uds
    out: dict = {}
    for name, (address, size) in DOWNLOAD_TARGETS.items():
        status, nrc, data = _collect(
            uds, timeout, lambda a=address, s=size: uds.request_download(a, s)
        )
        out[name] = {
            "address": address,
            "size": size,
            "status": status,
            "max_block_length": data if status == "ok" else None,
            "nrc": nrc,
        }
    return out
