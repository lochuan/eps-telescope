"""Verified constants for the Toyota RH850 EPS read-only probe.

Data provenance:
- ``PATCH_FINGERPRINT`` / ``EGG_SIGNATURE`` / ``PATCH_POINT``: decoded from the
  Ghidra project over the OEM firmware ``code_v2.bin`` (SecOC RX state machine
  at ``FUN_0008e67a``), cross-validated against vehicle artifacts.
- ``ADJUST_WORD``: from a real vehicle faci-pe-cycle report and sector read-back.
- ``DCRA_MECHANISM`` / ``REGISTER_READS`` / ``MCU_PRDNAME``: register names and
  addresses taken verbatim from the RH850/P1M-E hardware manual register table.
  Names use the manual names only; the legacy payload aliases are intentionally
  absent (see ``tests/test_fingerprints.py``).

All values are hardcoded verified constants for one firmware variant. Nothing in
this module performs I/O; it is consumed by protocol/payload/deep_probe/report.
"""

# --- Patch-point fingerprint (Ghidra code_v2.bin, cross-checked vs artifacts) ---

PATCH_FINGERPRINT: dict = {
    "window_base": 0x8E6A7,
    "window_len": 64,
    "patch_offset": 32,
    "sha256": "50d793a2942716dcf0582238edfe6c2d72378eea8bd4e1bf575a8539cd497350",
    "bytes": "d3bfffcef86152fa05bb0f0900610aba05003aa5051a381d30bfff86ff1d30e0d19a0d1a38bfff78fb1d301a38bfffe6fbd505203e0002bfffa4fc0ad8b50520",
}

# Egg signature unique to the current firmware; the patch byte sits at egg+1.
EGG_SIGNATURE: bytes = bytes.fromhex("e0d19a0d1a38bfff")

# Egg start address in the FW-PATCH firmware (0x8E6C6). The patch byte is the
# next byte, egg+1 == PATCH_POINT["addr"] (0x8E6C7). A candidate found at this
# address means the patch point sits where FW-PATCH expects it.
EGG_ADDRESS: int = 0x8E6C6

# Scan range for the egg signature over the code flash.
EGG_SCAN_START: int = 0x18000
EGG_SCAN_END: int = 0xFFE00

# Patch byte inside the 64-byte window (0x8E6C7, instruction `cmp r0,r26`).
PATCH_POINT: dict = {"addr": 0x8E6C7, "original": 0xD1, "patched": 0x01}

# --- Boot integrity (DCRA1 CRC mechanism) ---

# CRC covers [range_start, range_end) over code flash; a correct boot checksum
# leaves residue 0xFFFFFFFF in DCRA1COUT.
DCRA_MECHANISM: dict = {
    "range_start": 0x18000,
    "range_end": 0xFFDF0,
    "residue": 0xFFFFFFFF,
    "cin": 0xFFD51000,
    "cout": 0xFFD51004,
    "ctl": 0xFFD51020,
}

# The adjust word at range_end-4 is the CRC function value of the whole covered
# range, not a firmware constant. 0x0962887F = unpatched firmware,
# 0x41C90FF2 = observed on an already-patched vehicle.
ADJUST_WORD: dict = {"addr": 0xFFDEC, "original": 0x0962887F, "patched": 0x41C90FF2}

# --- Register reads (RH850/P1M-E hardware manual names) ---
#
# (name, address, width_in_bytes). Names/addresses per the manual register
# table; comments quote the manual register name only.

REGISTER_READS: list[tuple[str, int, int]] = [
    # FACI/FCU state (base 0xFFA1xxxx)
    ("FPMON", 0xFFA10000, 1),       # FPMON
    ("FASTAT", 0xFFA10010, 1),      # FASTAT
    ("FAREASELC", 0xFFA10020, 2),   # FAREASELC
    ("FSADDR", 0xFFA10030, 4),      # FSADDR
    ("FEADDR", 0xFFA10034, 4),      # FEADDR
    ("FSTATR", 0xFFA10080, 4),      # FSTATR
    ("FENTRYR", 0xFFA10084, 2),     # FENTRYR
    ("FPROTR", 0xFFA10088, 2),      # FPROTR
    ("FSUINITR", 0xFFA10090, 1),    # FSUINITR
    ("FLKSTAT", 0xFFA10098, 1),     # FLKSTAT
    ("FPCKAR", 0xFFA100E4, 2),      # FPCKAR
    # SELFID (ID code compare)
    ("SELFID0", 0xFFA08000, 4),     # SELFID0
    ("SELFID1", 0xFFA08004, 4),     # SELFID1
    ("SELFID2", 0xFFA08008, 4),     # SELFID2
    ("SELFID3", 0xFFA0800C, 4),     # SELFID3
    ("SELFIDST", 0xFFA08010, 4),    # SELFIDST
    # Software protection / high-voltage enable
    ("FHVE15", 0xFFF8A430, 4),      # FHVE15
    ("FHVE3", 0xFFF82410, 4),       # FHVE3
    # Boot integrity (DCRA1)
    ("DCRA1CIN", 0xFFD51000, 4),    # DCRA1CIN
    ("DCRA1COUT", 0xFFD51004, 4),   # DCRA1COUT
    ("DCRA1CTL", 0xFFD51020, 4),    # DCRA1CTL
    # MCU identity (product name, 16-byte ASCII, reverse-ordered)
    ("PRDNAME1", 0xFFCD00D0, 4),    # PRDNAME1
    ("PRDNAME2", 0xFFCD00D4, 4),    # PRDNAME2
    ("PRDNAME3", 0xFFCD00D8, 4),    # PRDNAME3
    ("PRDNAME4", 0xFFCD00DC, 4),    # PRDNAME4
]

# MCU product name registers, read as a contiguous 16-byte string.
MCU_PRDNAME: list[int] = [0xFFCD00D0, 0xFFCD00D4, 0xFFCD00D8, 0xFFCD00DC]
