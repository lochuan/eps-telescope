"""End-to-end offline verification against real vehicle patch artifacts.

Reads the sector images and the faci-pe-cycle report straight from the
artifacts zip (in-memory via ``zipfile``, never extracted to disk) and asserts
that the verified constants in ``eps_probe.fingerprints`` reproduce from real
evidence:

* the 64-byte patch fingerprint window inside the unpatched 0x88000 target
  sector matches ``PATCH_FINGERPRINT["bytes"]`` / ``sha256``;
* the DCRA1 adjust word at 0xFFDEC reads ``ADJUST_WORD["original"]`` from the
  unpatched CRC sector and ``ADJUST_WORD["patched"]`` from the post-patch
  read-back;
* the faci-pe-cycle report's old/new adjust words and DCRA1 range match
  ``ADJUST_WORD`` / ``DCRA_MECHANISM``;
* a full protocol frame stream for the fingerprint-window region reassembles
  through ``StreamCollector`` and ``verify_patch_fingerprint`` reports MATCH.

The zip path is fixed (a local machine artifact). When it is absent the whole
module skips so the suite stays green on machines without the vehicle data.
"""

import binascii
import hashlib
import json
import zipfile

import pytest

from eps_probe import deep_probe
from eps_probe.fingerprints import (
    ADJUST_WORD,
    DCRA_MECHANISM,
    PATCH_FINGERPRINT,
)
from eps_probe.protocol import (
    PROTO_VERSION,
    FRAME_BEGIN0,
    FRAME_BEGIN1,
    FRAME_REGION_BEGIN,
    FRAME_REGION_LENGTH,
    FRAME_REGION_DATA,
    FRAME_REGION_END,
    FRAME_END,
    StreamCollector,
)

ARTIFACTS_ZIP = "/Users/kevin/Documents/VehicleWorkspace/eps-patch/artifacts.zip"

_TARGET_SECTOR = "artifacts/probe/original-sector-0x88000.bin"
_CRC_SECTOR = "artifacts/probe/original-sector-0xf8000.bin"
_FINAL_READBACK = "artifacts/patch/20251125T181744Z/final-readback-crc.bin"
_CYCLE_REPORT = "artifacts/probe/faci-pe-cycle-report.json"

# File offsets inside the 32 KiB sector images.
_WINDOW_OFF = PATCH_FINGERPRINT["window_base"] - 0x88000          # 0x66A7
_ADJUST_OFF = ADJUST_WORD["addr"] - 0xF8000                       # 0x7DEC
_REGION_KEY = 0x8E6A0                                             # DEFAULT_REGIONS key
_REGION_OFF = _REGION_KEY - 0x88000                               # 0x66A0 in sector


def _open_zip():
    try:
        return zipfile.ZipFile(ARTIFACTS_ZIP)
    except (FileNotFoundError, zipfile.BadZipFile):
        pytest.skip(f"artifacts zip missing at {ARTIFACTS_ZIP}")


def _frame(ftype, seq=0, word1=0):
    word0 = ftype | (PROTO_VERSION << 8) | (seq << 16)
    return (
        (word0 & 0xFFFFFFFF).to_bytes(4, "little")
        + (word1 & 0xFFFFFFFF).to_bytes(4, "little")
    )


def _region_stream(addr, data):
    """Complete BEGIN..REGION_END..END frame stream carrying one region."""
    words = [
        int.from_bytes(data[i:i + 4], "little")
        for i in range(0, len(data) - 3, 4)
    ]
    frames = [
        _frame(FRAME_BEGIN0),
        _frame(FRAME_BEGIN1, word1=1),
        _frame(FRAME_REGION_BEGIN, word1=addr),
        _frame(FRAME_REGION_LENGTH, word1=len(data)),
    ]
    for seq, word in enumerate(words):
        frames.append(_frame(FRAME_REGION_DATA, seq=seq, word1=word))
    frames.append(_frame(FRAME_REGION_END, word1=binascii.crc32(data)))
    frames.append(_frame(FRAME_END, word1=binascii.crc32(data)))
    return frames


def test_fingerprint_window_bytes_and_sha256():
    with _open_zip() as zf:
        sector = zf.read(_TARGET_SECTOR)
    assert len(sector) == 0x8000
    window = sector[_WINDOW_OFF:_WINDOW_OFF + PATCH_FINGERPRINT["window_len"]]
    assert window == bytes.fromhex(PATCH_FINGERPRINT["bytes"])
    assert hashlib.sha256(window).hexdigest() == PATCH_FINGERPRINT["sha256"]


def test_original_sector_adjust_word_matches_original():
    with _open_zip() as zf:
        sector = zf.read(_CRC_SECTOR)
    assert len(sector) == 0x8000
    raw = sector[_ADJUST_OFF:_ADJUST_OFF + 4]
    assert int.from_bytes(raw, "little") == ADJUST_WORD["original"]


def test_final_readback_adjust_word_matches_patched():
    with _open_zip() as zf:
        sector = zf.read(_FINAL_READBACK)
    assert len(sector) == 0x8000
    raw = sector[_ADJUST_OFF:_ADJUST_OFF + 4]
    assert int.from_bytes(raw, "little") == ADJUST_WORD["patched"]


def test_cycle_report_matches_fingerprint_constants():
    with _open_zip() as zf:
        report = json.loads(zf.read(_CYCLE_REPORT))
    dcra = report["dcra"]
    assert dcra["old_adjust_word"] == ADJUST_WORD["original"]
    assert dcra["new_adjust_word"] == ADJUST_WORD["patched"]
    assert dcra["range_start"] == DCRA_MECHANISM["range_start"]
    assert dcra["range_end"] == DCRA_MECHANISM["range_end"]


def test_replay_fingerprint_region_through_verify():
    with _open_zip() as zf:
        sector = zf.read(_TARGET_SECTOR)
    region = sector[_REGION_OFF:_REGION_OFF + 0x100]
    regions = {_REGION_KEY: region}
    out = deep_probe.verify_patch_fingerprint(regions, egg_candidates=[])
    assert out == {"status": "MATCH", "candidates": [], "egg_found": False, "egg_at_expected": False}


def test_replay_window_stream_reassembles_and_matches():
    with _open_zip() as zf:
        sector = zf.read(_TARGET_SECTOR)
    data = sector[_REGION_OFF:_REGION_OFF + 0x100]
    collector = StreamCollector()
    for can_id, frame_bytes in enumerate(_region_stream(_REGION_KEY, data)):
        collector.consume(can_id, frame_bytes)
    result = collector.finish()

    assert result.valid is True
    assert result.regions == {_REGION_KEY: data}
    out = deep_probe.verify_patch_fingerprint(result.regions, result.egg_candidates)
    assert out["status"] == "MATCH"
