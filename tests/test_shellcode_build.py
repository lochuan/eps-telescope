"""Build-artifact tests for the read-only deep-probe shellcode.

``deep_probe.bin`` / ``deep_probe.dis`` / ``manifest.json`` are produced on the
homelab v850 toolchain (no local v850 toolchain exists) and synced back into
``shellcode/build/``. ``deep_probe.dis`` is the ``v850-elf-objdump -d`` listing
the tests parse to statically verify the shellcode never writes the
flash/FCU/DCRA registers.
"""

import hashlib
import json
import pathlib
import re

from eps_probe import fingerprints as fp

ROOT = pathlib.Path(__file__).resolve().parent.parent
BUILD = ROOT / "shellcode" / "build"

SHELLCODE_LIMIT = 0xFD0

# Address prefixes that must never be a *store* target. Reads are the whole
# point of the probe; stores to these ranges (FACI/FCU state, FHVE enables,
# DCRA1) would corrupt flash protection or the boot-integrity engine.
FORBIDDEN_PREFIXES = ("ffa1", "fff8", "ffa2", "ffd51")


def test_bin_exists_and_size():
    binary = BUILD / "deep_probe.bin"
    assert binary.exists(), "run the homelab build first (shellcode/build.sh)"
    assert 0 < binary.stat().st_size < SHELLCODE_LIMIT


def test_manifest_sha256_matches_bin():
    binary = BUILD / "deep_probe.bin"
    manifest = json.loads((BUILD / "manifest.json").read_text())
    payload = manifest["payload"]["deep_probe"]
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    assert payload["sha256"] == digest
    assert payload["size"] == binary.stat().st_size


# --- disassembly parsing -----------------------------------------------------

_BYTE = re.compile(r"^[0-9a-fA-F]{2}$")
_INSN = re.compile(r"^\s*[0-9a-fA-F]+:\s+(.+)$")
_HEX = re.compile(r"0x([0-9a-fA-F]+)")
_DEST = re.compile(r"^(?P<disp>-?(?:0x[0-9a-fA-F]+|\d+))?\[(?P<reg>r\d+|[a-z]+)\]$")


def _instructions(dis_text):
    """Yield (mnemonic, operands) for every instruction in an objdump listing."""
    for line in dis_text.splitlines():
        m = _INSN.match(line)
        if not m:
            continue  # section/label headers
        tokens = m.group(1).split()
        mnemonic = None
        for i, tok in enumerate(tokens):
            if _BYTE.match(tok):
                continue  # raw encoding bytes precede the mnemonic
            mnemonic = tok
            operands = [t.rstrip(",") for t in tokens[i + 1:]]
            break
        if mnemonic is not None:
            yield mnemonic, operands


def _imm(value):
    return int(value, 0)


def _sign16(value):
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def forbidden_store_targets(dis_text):
    """Return the set of full addresses written by ``st.*`` instructions whose
    address can be reconstructed from the immediate-address construction
    (movhi/movea/addi) preceding them, limited to forbidden prefixes."""
    regs = {}
    targets = []
    for mnemonic, operands in _instructions(dis_text):
        if mnemonic == "movhi" and len(operands) >= 3:
            regs[operands[2]] = (_imm(operands[0]) << 16) & 0xFFFFFFFF
        elif mnemonic in ("movea", "addi") and len(operands) >= 3:
            base = regs.get(operands[1])
            if base is not None:
                regs[operands[2]] = (base + _sign16(_imm(operands[0]))) & 0xFFFFFFFF
        elif mnemonic.startswith("st") and operands:
            dest = operands[-1]
            full = None
            dm = _DEST.match(dest)
            if dm:
                disp = _sign16(_imm(dm.group("disp"))) if dm.group("disp") else 0
                base = regs.get(dm.group("reg"))
                if base is not None:
                    full = (base + disp) & 0xFFFFFFFF
            else:
                hm = _HEX.search(dest)
                if hm:
                    full = int(hm.group(1), 16)
            if full is not None and _is_forbidden(full):
                targets.append(full)
    return targets


def _is_forbidden(addr):
    if f"{addr:08x}".startswith(FORBIDDEN_PREFIXES):
        return True
    return addr in {addr for _, addr, _ in fp.REGISTER_READS}


def test_no_write_to_flash_registers():
    dis = (BUILD / "deep_probe.dis").read_text()
    assert forbidden_store_targets(dis) == []


def test_detector_catches_forbidden_store():
    """The analyzer above must flag a store into a forbidden range."""
    synthetic = "\n".join([
        "   0:\t00 00 00 00 \tmovhi\t-0x5f, r0, r5",
        "   4:\t00 00 00 00 \tmovea\t0x80, r5, r5",
        "   8:\t00 00 00 00 \tst.w\tr6, 0[r5]",
    ])
    assert forbidden_store_targets(synthetic) == [0xFFA10080]
