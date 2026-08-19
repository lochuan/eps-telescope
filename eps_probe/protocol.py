"""Tagged + CRC streaming protocol for the RH850 EPS probe, and its host-side collector.

The probe firmware (Task 6, ``deep_probe.c``) emits a stream of 8-byte CAN frames.
Each frame is two little-endian u32 words:

* ``word0`` low 8 bits = frame type, bits 8..15 = protocol version, bits 16..31 =
  slot / sequence index (register slot, region data word index, error stage).
* ``word1`` = the frame payload.

All data bytes (the 4 bytes of ``word1`` of every REGISTER_DATA and REGION_DATA
frame, in stream order) accumulate into a raw CRC-32 accumulator (poly
0xEDB88320, init 0xFFFFFFFF, no final xor). The wire carries the STANDARD CRC
(``binascii.crc32`` semantics, i.e. raw accumulator XOR 0xFFFFFFFF): the END
frame's ``word1`` is ``combined_crc_raw ^ 0xFFFFFFFF`` and REGION_END's
``word1`` likewise (this is exactly what ``deep_probe.c`` transmits). The
collector recomputes the standard CRC from its own raw accumulators
(``raw ^ 0xFFFFFFFF``) and compares against the wire value.

``StreamCollector`` reassembles register values by slot index and region bytes by
``addr + idx*4``. It does NOT know the register names: the caller (deep_probe,
Task 7) supplies ``register_names`` (taken from ``fingerprints.REGISTER_READS``)
so that ``StreamResult.registers`` / ``dcra`` / ``prdname`` can be named. This
module never imports ``fingerprints``.
"""

from dataclasses import dataclass, field

# --- Protocol constants -----------------------------------------------------

PROTO_VERSION = 1

FRAME_BEGIN0 = 0xB0          # stream start; word1 = 0
FRAME_BEGIN1 = 0xB1          # word1 = expected total frame count (informational)
FRAME_REGISTER_DATA = 0xB2   # word1 = register value; seq = REGISTER_READS slot
FRAME_REGION_BEGIN = 0xB3    # word1 = region start address
FRAME_REGION_LENGTH = 0xB4   # word1 = region byte count
FRAME_REGION_DATA = 0xD0     # word1 = 4 data bytes; seq = word index within region
FRAME_REGION_END = 0xB5      # word1 = region CRC (standard, binascii.crc32)
FRAME_EGG_FOUND = 0xC1       # word1 = candidate address
FRAME_EGG_SCAN_END = 0xC2    # word1 = candidate count (informational)
FRAME_STATUS = 0xC0          # word1 = status code (informational)
FRAME_ERROR = 0xEE           # word1 = code; seq = stage
FRAME_END = 0xE0             # word1 = combined CRC (standard, binascii.crc32)

_CRC_POLY = 0xEDB88320


class ProtocolError(Exception):
    """The stream violated the tagged-frame protocol (bad frame, version, ordering)."""


@dataclass
class StreamResult:
    """Reassembled probe stream.

    ``valid`` is True only when the END CRC matches the accumulated data bytes,
    no region CRC mismatch was seen, and no ERROR frame was received.
    ``region_bad`` holds the start address of every region whose REGION_END CRC
    failed, so consumers can refuse to trust that region's bytes without
    discarding the whole stream.
    """

    registers: dict[str, int] = field(default_factory=dict)
    regions: dict[int, bytes] = field(default_factory=dict)
    egg_candidates: list[int] = field(default_factory=list)
    dcra: dict[str, int] = field(default_factory=dict)
    prdname: str = ""
    combined_crc: int = 0
    valid: bool = False
    error: tuple[int, int] | None = None
    region_bad: set[int] = field(default_factory=set)


# --- CRC helpers -------------------------------------------------------------

def crc32_update(crc: int, byte: int) -> int:
    """Advance a raw CRC-32 accumulator by one byte (poly 0xEDB88320).

    Seed with ``0xFFFFFFFF``. The accumulated value is the *raw* accumulator
    without the final xor; the wire frames carry ``raw ^ 0xFFFFFFFF`` (the
    standard ``binascii.crc32`` value).
    """
    crc = (crc ^ byte) & 0xFFFFFFFF
    for _ in range(8):
        if crc & 1:
            crc = ((crc >> 1) ^ _CRC_POLY) & 0xFFFFFFFF
        else:
            crc >>= 1
    return crc


def crc32_stream(bytes_iterable) -> int:
    """CRC-32 over an iterable of bytes objects, zlib/binascii convention.

    Equivalent to ``binascii.crc32(b"".join(bytes_iterable))``.
    """
    crc = 0xFFFFFFFF
    for data in bytes_iterable:
        for byte in data:
            crc = crc32_update(crc, byte)
    return crc ^ 0xFFFFFFFF


# --- Request block ------------------------------------------------------------

def build_region_request(flags: int, regions: list[tuple[int, int]]) -> bytes:
    """Build the region-read request block.

    Layout: ``b"PROB"`` magic (u32 BE 0x50524F42) + flags u8 + num_regions u8 +
    per region ``{addr u32 BE, len u16 BE}`` + 4 padding bytes (10 bytes each).
    """
    out = bytearray(b"PROB")
    out.append(flags & 0xFF)
    out.append(len(regions) & 0xFF)
    for addr, length in regions:
        out += addr.to_bytes(4, "big")
        out += length.to_bytes(2, "big")
        out += b"\x00" * 4
    return bytes(out)


# --- Stream collector ----------------------------------------------------------

class StreamCollector:
    """Reassembles a tagged-CRC probe stream from raw CAN frames.

    ``register_names`` is the consumer-supplied register table (names only, by
    slot index), used to name ``registers``, auto-pick ``DCRA1*`` into ``dcra``
    and assemble ``PRDNAME*`` words into ``prdname``. ``protocol`` itself never
    resolves register names.
    """

    def __init__(
        self,
        expected_version: int = 1,
        *,
        register_names: list[str] | None = None,
    ):
        self.expected_version = expected_version
        self.register_names = register_names
        self.timed_out = False

        self._started = False
        self._end_seen = False
        self._end_ok = True
        self._region_bad: set[int] = set()
        self._error: tuple[int, int] | None = None

        self._reg_values: dict[int, int] = {}
        self._egg_candidates: list[int] = []
        self._combined_crc: int = 0xFFFFFFFF

        self._region_addr: int | None = None
        self._region_buf: bytearray | None = None
        self._region_crc: int = 0xFFFFFFFF
        self._regions: dict[int, bytearray] = {}

    def consume(self, can_id: int, data: bytes) -> None:
        """Feed one 8-byte CAN frame into the collector.

        ``can_id`` is reserved for the caller's CAN-ID filtering; the frame
        payload is parsed unconditionally.
        """
        if len(data) != 8:
            raise ProtocolError(f"frame must be 8 bytes, got {len(data)}")
        word0 = int.from_bytes(data[0:4], "little")
        word1 = int.from_bytes(data[4:8], "little")
        ftype = word0 & 0xFF
        version = (word0 >> 8) & 0xFF
        seq = (word0 >> 16) & 0xFFFF

        if ftype == FRAME_BEGIN0:
            if version != self.expected_version:
                raise ProtocolError(
                    f"version {version} != expected {self.expected_version}"
                )
            self._reset()
            self._started = True
            return

        if not self._started:
            raise ProtocolError("frame before BEGIN0")
        if self._end_seen:
            raise ProtocolError("frame after END")

        if ftype == FRAME_BEGIN1:
            return  # informational: expected total frame count
        if ftype == FRAME_REGISTER_DATA:
            self._reg_values[seq] = word1
            self._accumulate(word1)
            return
        if ftype == FRAME_REGION_BEGIN:
            if self._region_buf is not None:
                raise ProtocolError("REGION_BEGIN with open region")
            self._region_addr = word1
            return
        if ftype == FRAME_REGION_LENGTH:
            if self._region_addr is None or self._region_buf is not None:
                raise ProtocolError("REGION_LENGTH without REGION_BEGIN")
            self._region_buf = bytearray(word1)
            return
        if ftype == FRAME_REGION_DATA:
            if self._region_addr is None or self._region_buf is None:
                raise ProtocolError("REGION_DATA outside a region")
            off = seq * 4
            if off + 4 > len(self._region_buf):
                raise ProtocolError(
                    f"REGION_DATA word {seq} beyond region length {len(self._region_buf)}"
                )
            raw = word1.to_bytes(4, "little")
            self._region_buf[off:off + 4] = raw
            for byte in raw:
                self._region_crc = crc32_update(self._region_crc, byte)
            self._accumulate(word1)
            return
        if ftype == FRAME_REGION_END:
            if self._region_addr is None or self._region_buf is None:
                raise ProtocolError("REGION_END without an open region")
            if (self._region_crc ^ 0xFFFFFFFF) != word1:
                self._region_bad.add(self._region_addr)
            self._regions[self._region_addr] = self._region_buf
            self._region_addr = None
            self._region_buf = None
            self._region_crc = 0xFFFFFFFF
            return
        if ftype == FRAME_EGG_FOUND:
            self._egg_candidates.append(word1)
            return
        if ftype == FRAME_EGG_SCAN_END:
            return  # informational: candidate count
        if ftype == FRAME_STATUS:
            return  # informational
        if ftype == FRAME_ERROR:
            self._error = (seq, word1)
            return
        if ftype == FRAME_END:
            self._end_ok = (self._combined_crc ^ 0xFFFFFFFF) == word1
            self._end_seen = True
            return

        raise ProtocolError(f"unknown frame type 0x{ftype:02X}")

    def finish(self) -> StreamResult:
        """Return the reassembled stream, raising if it never reached END.

        A stream aborted by an explicit ERROR frame returns a result with
        ``error`` set and ``valid=False`` instead of raising.
        """
        if not self._started:
            raise ProtocolError("finish() without BEGIN0")
        if not self._end_seen:
            if self._error is not None:
                return self._build_result()
            if self.timed_out:
                raise ProtocolError("stream timed out before END frame")
            raise ProtocolError("stream ended without END frame")
        return self._build_result()

    def _accumulate(self, word: int) -> None:
        """Fold a data word's 4 bytes (LE) into the combined CRC."""
        for byte in word.to_bytes(4, "little"):
            self._combined_crc = crc32_update(self._combined_crc, byte)

    def _reset(self) -> None:
        self._end_seen = False
        self._end_ok = True
        self._region_bad = set()
        self._error = None
        self._reg_values = {}
        self._egg_candidates = []
        self._combined_crc = 0xFFFFFFFF
        self._region_addr = None
        self._region_buf = None
        self._region_crc = 0xFFFFFFFF
        self._regions = {}

    def _build_result(self) -> StreamResult:
        registers = self._named_registers()
        return StreamResult(
            registers=registers,
            regions={addr: bytes(buf) for addr, buf in self._regions.items()},
            egg_candidates=list(self._egg_candidates),
            dcra={name: value for name, value in registers.items()
                  if name.startswith("DCRA1")},
            prdname=self._assemble_prdname(),
            combined_crc=self._combined_crc ^ 0xFFFFFFFF,
            valid=self._end_ok and not self._region_bad and self._error is None,
            error=self._error,
            region_bad=set(self._region_bad),
        )

    def _named_registers(self) -> dict[str, int]:
        if self.register_names is None:
            return {str(slot): value
                    for slot, value in sorted(self._reg_values.items())}
        out: dict[str, int] = {}
        for slot, value in self._reg_values.items():
            if slot < len(self.register_names):
                out[self.register_names[slot]] = value
            else:
                out[str(slot)] = value
        return out

    def _assemble_prdname(self) -> str:
        if self.register_names is None:
            return ""
        entries = []
        for slot, name in enumerate(self.register_names):
            if name.startswith("PRDNAME"):
                value = self._reg_values.get(slot)
                if value is not None:
                    suffix = name[len("PRDNAME"):]
                    entries.append((int(suffix) if suffix.isdigit() else 0, value))
        raw = b"".join(value.to_bytes(4, "little")
                       for _, value in sorted(entries, key=lambda e: e[0]))
        return raw.decode("ascii", errors="replace").rstrip("\x00 \t\r\n")
