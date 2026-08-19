"""Layer 3 deep-probe orchestration: fingerprint + boot-integrity verification.

``run_deep_probe`` drives an ``EcuTransport`` through the full probe flow:
build the region-read request block (flags bit0 = register snapshot, bit1 = egg
scan), wrap it in the secoc-style envelope, upload + trigger, and parse the
reassembled ``StreamResult`` into a plain dict.

``verify_patch_fingerprint`` / ``verify_boot_integrity`` then answer the two
Layer-3 questions from the returned regions:

* Is the patch-point fingerprint intact?  The 64-byte window ``0x8E6A7..0x8E6E7``
  (region key ``0x8E6A0``, offset 7) is compared byte-for-byte against
  ``PATCH_FINGERPRINT["bytes"]``.  Every egg candidate gets the same comparison
  against its own window (egg start is offset 31 inside the fingerprint window,
  so a candidate's window starts at ``candidate - 31``).
* Is boot integrity consistent?  The CRC adjust word at ``0xFFDEC`` is read from
  the ``0xFFDE0`` region and classified ``original``/``patched``/``unknown``
  against ``ADJUST_WORD``.  When a full-range region covering ``[0x18000,
  0xFFDF0)`` is present (not in ``DEFAULT_REGIONS`` — a deliberate cost trade),
  the host also recomputes the DCRA1 software CRC over the range and reports
  ``residue_ok``.

``classify_target`` folds fingerprint + boot-integrity + Layer-2 gates into one
raw guidance conclusion; report.py (Task 8) maps the ``classification`` enum to
guidance text.
"""

from __future__ import annotations

from .fingerprints import (
    ADJUST_WORD,
    DCRA_MECHANISM,
    EGG_SIGNATURE,
    PATCH_FINGERPRINT,
    REGISTER_READS,
)
from .payload import build_envelope
from .protocol import StreamResult, build_region_request, crc32_stream

# Patch-point fingerprint region (covers window 0x8E6A7..0x8E6E7 and the
# 0x40B boundary); CRC adjust-word tail; identity string; KDF runtime region.
DEFAULT_REGIONS: list[tuple[int, int]] = [
    (0x8E6A0, 0x100),      # patch fingerprint window
    (0xFFDE0, 0x40),       # CRC adjust word (0xFFDEC) + sector tail
    (0x17D80, 0x40),       # identity string region
    (0xFEBF2CF8, 0x100),   # KDF runtime region (RAM dump evidence)
]

# Request-block flag bits (mirrors deep_probe.c): bit0 = register snapshot,
# bit1 = egg signature scan.
_FLAG_REGISTERS = 0x01
_FLAG_EGG_SCAN = 0x02

_FP_BYTES = bytes.fromhex(PATCH_FINGERPRINT["bytes"])
# The egg signature sits at byte offset 31 of the 64-byte fingerprint window
# (window_base 0x8E6A7 + 31 == egg 0x8E6C6), so a candidate's window starts at
# candidate - 31.
_EGG_OFFSET_IN_WINDOW = _FP_BYTES.index(EGG_SIGNATURE)

# classify_target conclusions (small enum; Task 8 maps them to guidance text).
CLASSIFICATION_VERIFIED = "verified_variant"
CLASSIFICATION_ALREADY_PATCHED = "already_patched"
CLASSIFICATION_EGG_VARIANT = "egg_variant"
CLASSIFICATION_NO_EGG = "no_egg"
CLASSIFICATION_SA_BLOCKED = "sa_blocked"
CLASSIFICATION_ENVELOPE_BLOCKED = "envelope_blocked"
CLASSIFICATION_INCOMPLETE = "probe_incomplete"


# --- Helpers ------------------------------------------------------------------

def _read_range(regions: dict, base: int, length: int) -> bytes | None:
    """Return ``regions[base : base+length]`` from whichever region covers it.

    Regions are keyed by their start address; a range is served by the first
    region whose span fully contains ``[base, base+length)``.  Returns ``None``
    when no uploaded region covers the whole range (the caller's NO_DATA path).
    """
    for start, data in regions.items():
        if start <= base and base + length <= start + len(data):
            return data[base - start:base - start + length]
    return None


def _name_registers(registers: dict[str, int]) -> dict[str, int]:
    """Map slot-index register keys to the manual register names.

    ``EcuTransport.collect_stream`` assembles registers without a name table
    (protocol.py leaves naming to the consumer), so slots arrive keyed by their
    index as strings.  ``REGISTER_READS`` order is the slot order.
    """
    by_slot = {str(slot): name for slot, (name, _addr, _width) in
               enumerate(REGISTER_READS)}
    named: dict[str, int] = {}
    for key, value in registers.items():
        named[by_slot.get(key, key)] = value
    return named


# --- Orchestration --------------------------------------------------------------

def run_deep_probe(
    transport,
    *,
    shellcode: bytes,
    regions: list[tuple[int, int]] | None = None,
    scan_egg: bool = True,
) -> dict:
    """Upload + trigger the deep probe and return its parsed stream.

    Builds the region-read request block with flags bit0 (register snapshot)
    and, when ``scan_egg``, bit1 (egg scan); wraps it in an envelope (DIDs all
    zeros); uploads and triggers with ``new_uds=False``; collects and parses the
    stream into ``{"registers", "regions", "egg_candidates", "stream_valid",
    "error"}``.  Register slots are renamed to the manual names; regions stay
    keyed by their start address.
    """
    if regions is None:
        regions = DEFAULT_REGIONS
    flags = _FLAG_REGISTERS | (_FLAG_EGG_SCAN if scan_egg else 0)
    request_block = build_region_request(flags, regions)
    envelope = build_envelope(
        shellcode, request_block, b"\x00" * 16, b"\x00" * 16
    )
    transport.upload_and_trigger(envelope, new_uds=False)
    result: StreamResult = transport.collect_stream()
    return {
        "registers": _name_registers(dict(result.registers)),
        "regions": {addr: bytes(data) for addr, data in result.regions.items()},
        "egg_candidates": list(result.egg_candidates),
        "stream_valid": bool(result.valid),
        "error": result.error,
    }


# --- Verification ---------------------------------------------------------------

def verify_patch_fingerprint(regions: dict, egg_candidates: list[int]) -> dict:
    """Compare the patch-point fingerprint window against the known bytes.

    The 64-byte window is read from whichever region covers ``0x8E6A7..0x8E6E7``
    (the ``0x8E6A0`` region in ``DEFAULT_REGIONS``) and compared byte-for-byte
    against ``PATCH_FINGERPRINT["bytes"]``.

    Returns ``{"status": "MATCH|MISMATCH|NO_DATA", "candidates": [...]}``.  Each
    egg candidate carries its own window comparison (window starts at
    ``candidate - 31``) recorded as ``{"addr", "status"}`` — ``NO_DATA`` when no
    uploaded region covers that window (e.g. a hit elsewhere in flash).
    """
    window = _read_range(regions, PATCH_FINGERPRINT["window_base"], 64)
    if window is None:
        status = "NO_DATA"
    elif window == _FP_BYTES:
        status = "MATCH"
    else:
        status = "MISMATCH"

    candidates = []
    for candidate in egg_candidates:
        c_window = _read_range(
            regions, candidate - _EGG_OFFSET_IN_WINDOW, 64
        )
        if c_window is None:
            c_status = "NO_DATA"
        elif c_window == _FP_BYTES:
            c_status = "MATCH"
        else:
            c_status = "MISMATCH"
        candidates.append({"addr": candidate, "status": c_status})

    return {"status": status, "candidates": candidates}


def verify_boot_integrity(regions: dict) -> dict:
    """Classify the boot-integrity evidence available in ``regions``.

    Always classifies the CRC adjust word at ``0xFFDEC`` (region key ``0xFFDE0``,
    offset 12, little-endian): ``"original"`` == ``ADJUST_WORD["original"]``,
    ``"patched"`` == ``ADJUST_WORD["patched"]``, anything else (or missing
    region) ``"unknown"``.

    When a single region covers the full DCRA1 range ``[0x18000, 0xFFDF0)``,
    additionally recomputes the software CRC over that range and adds
    ``residue_ok`` (True when it equals ``DCRA_MECHANISM["residue"]``).
    """
    raw = _read_range(regions, ADJUST_WORD["addr"], 4)
    if raw is None:
        adjust_word: int | None = None
        state = "unknown"
    else:
        adjust_word = int.from_bytes(raw, "little")
        state = (
            "original" if adjust_word == ADJUST_WORD["original"]
            else "patched" if adjust_word == ADJUST_WORD["patched"]
            else "unknown"
        )

    out = {"adjust_word": adjust_word, "state": state}

    start = DCRA_MECHANISM["range_start"]
    end = DCRA_MECHANISM["range_end"]
    full = _read_range(regions, start, end - start)
    if full is not None:
        out["residue_ok"] = crc32_stream([full]) == DCRA_MECHANISM["residue"]
    return out


# --- Classification ---------------------------------------------------------------

def classify_target(
    fingerprint: dict, boot_integrity: dict, sa_ok: bool, envelope_ok: bool
) -> dict:
    """Fold Layer-2 gates + Layer-3 evidence into one raw guidance conclusion.

    Returns a dict with a ``classification`` key from the small enum above plus
    the supporting evidence Task 8 uses to render guidance text.  Layer-2 gates
    take precedence (they abort the deep probe), then fingerprint MATCH /
    MISMATCH / NO_DATA drives the boot-integrity and egg branches.
    """
    f_status = fingerprint.get("status")
    egg_hits = len(fingerprint.get("candidates", []))
    b_state = boot_integrity.get("state", "unknown")

    if not sa_ok:
        classification = CLASSIFICATION_SA_BLOCKED
    elif not envelope_ok:
        classification = CLASSIFICATION_ENVELOPE_BLOCKED
    elif f_status == "MATCH":
        classification = (
            CLASSIFICATION_ALREADY_PATCHED if b_state == "patched"
            else CLASSIFICATION_VERIFIED
        )
    elif f_status == "MISMATCH":
        classification = (
            CLASSIFICATION_EGG_VARIANT if egg_hits
            else CLASSIFICATION_NO_EGG
        )
    else:
        classification = CLASSIFICATION_INCOMPLETE

    return {
        "classification": classification,
        "fingerprint": f_status,
        "boot_integrity": b_state,
        "egg_hits": egg_hits,
        "sa_ok": bool(sa_ok),
        "envelope_ok": bool(envelope_ok),
    }
