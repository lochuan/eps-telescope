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
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import deep_probe, report, uds_probe
from .transport import EcuTransport, EnvelopeAuthError

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
        "--no-fingerprint",
        action="store_true",
        help="跳过车辆指纹探测 (主 ECU 全扫 + 其他 ECU 重要 DID)",
    )
    parser.add_argument(
        "--artifacts-dir",
        default="./artifacts",
        help="artifacts 根目录 (default ./artifacts)",
    )
    return parser


def run(
    args, *, transport_factory, payload_bytes, fingerprint_runner=None
) -> Path:
    """Compose the layered probe, write artifacts, and return the artifacts dir."""
    if _boardd_running():
        raise CliError("selfdrive pandad/boardd 正在运行 — 为避免占用总线已中止探测")

    transport = transport_factory()
    with transport:
        try:
            app_f181, boot_f181 = transport.read_identity()
            identity_error = None
        except Exception as exc:
            app_f181, boot_f181 = None, None
            identity_error = str(exc)
        try:
            layer1 = _probe_layer1(transport, args.depth)
        except Exception as exc:
            layer1 = {"error": str(exc)}
        layer2 = {
            "sa_ok": False,
            "nrc": None,
            "envelope_ok": None,
            "envelope_nrc": None,
        }
        layer3 = None
        if args.depth in ("sa", "shellcode"):
            sa_ok, sa_nrc = transport.security_access()
            layer2["sa_ok"] = sa_ok
            layer2["nrc"] = sa_nrc
            if (
                args.depth == "shellcode"
                and layer2["sa_ok"]
                and payload_bytes is not None
            ):
                try:
                    layer3 = _probe_layer3(transport, args, payload_bytes)
                except EnvelopeAuthError as exc:
                    layer2["envelope_ok"] = False
                    layer2["envelope_nrc"] = exc.nrc
                    layer3 = _envelope_blocked_layer3(exc.nrc)
                except Exception as exc:
                    layer2["envelope_ok"] = False
                    layer3 = {"error": str(exc)}
                else:
                    layer2["envelope_ok"] = layer3["envelope_ok"]

        # Vehicle fingerprint: identify the platform from the engine ECU and
        # other ECUs (read-only). Failures degrade to a recorded error.
        if not args.no_fingerprint:
            runner = fingerprint_runner or _probe_vehicle_fingerprint
            try:
                layer1["vehicle"] = runner(transport)
            except Exception as exc:
                layer1["vehicle"] = {"error": str(exc)}

    meta = _build_meta(args, app_f181, boot_f181, identity_error)
    report_data = report.build_report(meta, layer1, layer2, layer3)
    artifacts_dir = _write_artifacts(args.artifacts_dir, report_data)
    sys.stdout.write(report_data["markdown"])
    return artifacts_dir


def load_shellcode(path=DEFAULT_SHELLCODE) -> bytes | None:
    """Read the shellcode binary; None + stderr note when it is missing.

    When present, the binary's SHA-256 is verified against the ``manifest.json``
    recorded next to it (external trusted pin); a mismatch raises ``CliError``
    so the run exits 2 instead of uploading a tampered payload.
    """
    source = Path(path)
    if not source.is_file():
        print(f"note: {source} 不存在 — Layer 3 深探跳过", file=sys.stderr)
        return None
    data = source.read_bytes()
    manifest_path = source.parent / "manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text())
        expected = manifest["payload"]["deep_probe"]["sha256"]
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise CliError(
                f"shellcode SHA-256 mismatch: manifest {expected}, got {actual}"
            )
    return data


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
        deep["regions"], deep["egg_candidates"], region_bad=deep["region_bad"]
    )
    deep["boot_integrity"] = deep_probe.verify_boot_integrity(
        deep["regions"], region_bad=deep["region_bad"]
    )
    deep["classification"] = deep_probe.classify_target(
        deep["fingerprint"],
        deep["boot_integrity"],
        sa_ok=True,
        envelope_ok=deep["envelope_ok"],
        stream_ok=deep["stream_valid"],
        scan_egg=not args.no_egg_scan,
    )
    return deep


def _envelope_blocked_layer3(nrc: int | None) -> dict:
    """Layer-3 result for a 0x10F0 rejection: envelope_blocked guidance only."""
    classification = deep_probe.classify_target(
        {"status": "NO_DATA", "candidates": []},
        {"adjust_word": None, "state": "unknown"},
        sa_ok=True,
        envelope_ok=False,
    )
    detail = "unknown NRC" if nrc is None else f"NRC 0x{nrc:02X}"
    return {
        "envelope_ok": False,
        "error": f"envelope 0x10F0 authentication rejected ({detail})",
        "classification": classification,
    }


def _probe_vehicle_fingerprint(transport) -> dict:
    """Identify the vehicle by probing the engine ECU and other ECUs (read-only).

    Opens additional opendbc UdsClients on the same panda, sweeps the main ECU
    identification block and reads the important DIDs on other ECUs. Never uses
    the programming session. Returns the ``vehicle_fingerprint.fingerprint``
    result dict.
    """
    from eps_probe import vehicle_fingerprint as vf
    from eps_probe.transport import load_openpilot_bindings

    bindings = load_openpilot_bindings()
    panda = transport.panda
    bus = 0

    def uds_factory(addr):
        return bindings.UdsClient(
            panda, addr, addr + 8, bus, timeout=vf.FINGERPRINT_TIMEOUT
        )

    main_uds = bindings.UdsClient(
        panda, vf.MAIN_ECU_ADDR, vf.MAIN_ECU_ADDR + 8, bus,
        timeout=vf.FINGERPRINT_TIMEOUT,
    )
    try:
        return vf.fingerprint(main_uds, uds_factory)
    finally:
        main_uds.close()


def _build_meta(args, app_f181: bytes | None, boot_f181: bytes | None,
                identity_error: str | None = None) -> dict:
    meta = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "addr": f"0x{args.addr:X}",
        "serial": args.serial,
        "depth": args.depth,
        "app_f181": None if app_f181 is None else app_f181.hex(),
        "boot_f181": None if boot_f181 is None else boot_f181.hex(),
    }
    if identity_error is not None:
        meta["identity_error"] = identity_error
    return meta


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
