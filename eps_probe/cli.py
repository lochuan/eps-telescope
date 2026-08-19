"""CLI composition for the RH850 EPS probe: layered gating and artifacts.

``build_parser`` declares the probe flags; ``run`` composes the layered probe
(read identity + Layer 1 UDS enumeration, optional Security Access, optional
Layer 3 deep probe) and writes a timestamped artifacts directory. Everything
hardware-adjacent is injected — ``transport_factory`` supplies the transport
and ``payload_bytes`` the shellcode — so ``run`` is fully testable offline.

Gating ladder (per the task brief):

* ``--depth uds``        Layer 1 only; SecurityAccess is never attempted.
* ``--depth sa``         Layer 1 + SecurityAccess; a failed SA degrades to a
                         uds-level report (layer2 present with ``sa_ok`` False,
                         layer3 ``None``).
* ``--depth shellcode``  Layer 3 runs only when SA succeeded AND ``payload_bytes``
                         is not ``None`` (the shellcode binary exists); a missing
                         binary skips Layer 3 with a stderr note.

Fatal conditions raise ``CliError``; ``probe.main`` prints ``ERROR: ...`` to
stderr and exits 2 (mirroring the FW-PATCH ``main()`` pattern).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import deep_probe, report, uds_probe
from .transport import EcuTransport

# Task-6 build output, relative to the repo root.
DEFAULT_SHELLCODE = Path("shellcode/build/deep_probe.bin")

# Layer-1 sessions probed per depth, cumulative up the session ladder.
_DEPTH_SESSIONS = {
    "uds": [uds_probe.SESSION_DEFAULT],
    "sa": [uds_probe.SESSION_DEFAULT, uds_probe.SESSION_EXTENDED],
    "shellcode": [
        uds_probe.SESSION_DEFAULT,
        uds_probe.SESSION_EXTENDED,
        uds_probe.SESSION_PROGRAMMING,
    ],
}


class CliError(RuntimeError):
    """Fatal CLI condition (e.g. boardd/pandad running) that must abort."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="probe",
        description="RH850 EPS 只读探测: Layer 1 UDS 枚举 / Security Access / 深探指纹",
    )
    parser.add_argument(
        "--addr",
        type=lambda value: int(value, 0),
        default=0x7A1,
        help="ECU 诊断地址 (hex 或 decimal; default 0x7A1)",
    )
    parser.add_argument(
        "--serial", default=None, help="panda serial (省略则自动查找)"
    )
    parser.add_argument(
        "--depth",
        choices=["uds", "sa", "shellcode"],
        default="shellcode",
        help="探测深度: uds | sa | shellcode (default shellcode)",
    )
    parser.add_argument(
        "--no-egg-scan",
        action="store_true",
        help="深探时跳过 egg 签名扫描 (请求块清 bit1)",
    )
    parser.add_argument(
        "--artifacts-dir",
        default="./artifacts",
        help="artifacts 根目录 (default ./artifacts)",
    )
    return parser


def run(args, *, transport_factory, payload_bytes) -> Path:
    """Compose the layered probe, write artifacts, and return the artifacts dir."""
    if _boardd_running():
        raise CliError("selfdrive pandad/boardd 正在运行 — 为避免占用总线已中止探测")

    transport = transport_factory()
    with transport:
        app_f181, boot_f181 = transport.read_identity()
        layer1 = _probe_layer1(transport, args.depth)
        layer2 = {"sa_ok": False, "nrc": None, "envelope_ok": None}
        layer3 = None
        if args.depth in ("sa", "shellcode"):
            layer2["sa_ok"] = bool(transport.security_access())
            if (
                args.depth == "shellcode"
                and layer2["sa_ok"]
                and payload_bytes is not None
            ):
                layer3 = _probe_layer3(transport, args, payload_bytes)
                layer2["envelope_ok"] = layer3["stream_valid"]

    meta = _build_meta(args, app_f181, boot_f181)
    report_data = report.build_report(meta, layer1, layer2, layer3)
    artifacts_dir = _write_artifacts(args.artifacts_dir, report_data)
    sys.stdout.write(report_data["markdown"])
    return artifacts_dir


def load_shellcode(path=DEFAULT_SHELLCODE) -> bytes | None:
    """Read the shellcode binary; None + stderr note when it is missing."""
    source = Path(path)
    if not source.is_file():
        print(f"note: {source} 不存在 — Layer 3 深探跳过", file=sys.stderr)
        return None
    return source.read_bytes()


# --- helpers ------------------------------------------------------------------

def _boardd_running() -> bool:
    """True when a selfdrive boardd/pandad process is live on this host."""
    for argv in (
        ["pgrep", "-f", r"selfdrive\.pandad\.pandad"],
        ["pidof", "pandad"],
    ):
        try:
            proc = subprocess.run(argv, capture_output=True)
        except FileNotFoundError:
            continue
        if proc.returncode == 0 and proc.stdout.strip():
            return True
    return False


def _probe_layer1(transport, depth: str) -> dict:
    return {
        "sessions": uds_probe.probe_sessions(transport, _DEPTH_SESSIONS[depth]),
        "dids": uds_probe.probe_dids(transport),
        "routines": uds_probe.probe_routines(transport),
        "download": uds_probe.probe_download_acceptance(transport),
    }


def _probe_layer3(transport, args, payload_bytes: bytes) -> dict:
    deep = deep_probe.run_deep_probe(
        transport, shellcode=payload_bytes, scan_egg=not args.no_egg_scan
    )
    deep["fingerprint"] = deep_probe.verify_patch_fingerprint(
        deep["regions"], deep["egg_candidates"]
    )
    deep["boot_integrity"] = deep_probe.verify_boot_integrity(deep["regions"])
    deep["classification"] = deep_probe.classify_target(
        deep["fingerprint"],
        deep["boot_integrity"],
        sa_ok=True,
        envelope_ok=bool(deep["stream_valid"]),
    )
    return deep


def _build_meta(args, app_f181: bytes, boot_f181: bytes) -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "addr": f"0x{args.addr:X}",
        "serial": args.serial,
        "depth": args.depth,
        "app_f181": app_f181.hex(),
        "boot_f181": boot_f181.hex(),
    }


def _write_artifacts(base_dir: str, report_data: dict) -> Path:
    root = Path(base_dir)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = root / stamp
    out_dir.mkdir(parents=True, exist_ok=True)
    _atomic_write(
        out_dir / "probe.json",
        json.dumps(report_data["json"], default=_json_default, indent=2).encode("utf-8"),
    )
    _atomic_write(out_dir / "probe.md", report_data["markdown"].encode("utf-8"))
    return out_dir


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def _json_default(obj):
    if isinstance(obj, bytes):
        return obj.hex()
    raise TypeError(f"not JSON serializable: {type(obj).__name__}")
