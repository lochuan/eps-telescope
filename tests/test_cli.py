"""CLI composition: parser defaults/flags, layered gating, atomic artifacts.

Tests drive ``cli.run`` with a recording mock transport and monkeypatched
Layer-1/Layer-3 probe functions, and exercise ``probe.main`` for the wiring and
exit-code contract. No real hardware involved.
"""

import json
import re

import pytest

from eps_probe import cli
from eps_probe.transport import EcuTransport
from eps_probe.uds_probe import (
    SESSION_DEFAULT,
    SESSION_EXTENDED,
    SESSION_PROGRAMMING,
)

import probe


class MockTransport:
    """Recording transport: identity + SecurityAccess, no UDS client hardware."""

    def __init__(self, app=b"\xAA\x01", boot=b"\xBB\x02", sa_ok=True):
        self.app = app
        self.boot = boot
        self.sa_ok = sa_ok
        self.calls = []

    def __enter__(self):
        self.calls.append("open")
        return self

    def __exit__(self, *exc):
        self.calls.append("close")

    def read_identity(self):
        self.calls.append("identity")
        return self.app, self.boot

    def security_access(self):
        self.calls.append("sa")
        return self.sa_ok


@pytest.fixture
def patch_probes(monkeypatch):
    """Neutralize hardware: boardd check, Layer-1 and Layer-3 probe functions."""
    recorded = {"sessions": None, "deep": None, "classify": None}

    def _probe_sessions(t, sessions=None, timeout=1.0):
        recorded["sessions"] = sessions
        return []

    def _probe_dids(t, did_ranges=None, timeout=1.0):
        return []

    def _probe_routines(t, rids=None, timeout=1.0):
        return []

    def _probe_download(t, timeout=1.0):
        return {}

    def _run_deep_probe(transport, *, shellcode, regions=None, scan_egg=True):
        recorded["deep"] = {
            "registers": {},
            "regions": {0x8E6A0: b"\x00" * 0x100},
            "egg_candidates": [],
            "stream_valid": True,
            "error": None,
            "shellcode": shellcode,
            "scan_egg": scan_egg,
        }
        return dict(recorded["deep"])

    def _verify_fingerprint(regions, egg_candidates):
        return {"status": "MATCH", "candidates": []}

    def _verify_boot(regions):
        return {"adjust_word": 0x01, "state": "original"}

    def _classify(fingerprint, boot_integrity, sa_ok, envelope_ok):
        recorded["classify"] = (sa_ok, envelope_ok)
        return {
            "classification": "verified_variant",
            "fingerprint": "MATCH",
            "boot_integrity": "original",
            "egg_hits": 0,
            "sa_ok": sa_ok,
            "envelope_ok": envelope_ok,
        }

    monkeypatch.setattr(cli, "_boardd_running", lambda: False)
    monkeypatch.setattr(cli.uds_probe, "probe_sessions", _probe_sessions)
    monkeypatch.setattr(cli.uds_probe, "probe_dids", _probe_dids)
    monkeypatch.setattr(cli.uds_probe, "probe_routines", _probe_routines)
    monkeypatch.setattr(cli.uds_probe, "probe_download_acceptance", _probe_download)
    monkeypatch.setattr(cli.deep_probe, "run_deep_probe", _run_deep_probe)
    monkeypatch.setattr(cli.deep_probe, "verify_patch_fingerprint", _verify_fingerprint)
    monkeypatch.setattr(cli.deep_probe, "verify_boot_integrity", _verify_boot)
    monkeypatch.setattr(cli.deep_probe, "classify_target", _classify)
    return recorded


# --- parser -------------------------------------------------------------------

def test_build_parser_defaults():
    args = cli.build_parser().parse_args([])
    assert args.addr == 0x7A1
    assert args.serial is None
    assert args.depth == "shellcode"
    assert args.no_egg_scan is False
    assert args.artifacts_dir == "./artifacts"


def test_build_parser_flags():
    args = cli.build_parser().parse_args([
        "--addr", "0x7A3",
        "--serial", "UNIT123",
        "--depth", "sa",
        "--no-egg-scan",
        "--artifacts-dir", "out/run1",
    ])
    assert args.addr == 0x7A3
    assert args.serial == "UNIT123"
    assert args.depth == "sa"
    assert args.no_egg_scan is True
    assert args.artifacts_dir == "out/run1"


def test_build_parser_addr_accepts_decimal():
    args = cli.build_parser().parse_args(["--addr", "2001"])
    assert args.addr == 2001


@pytest.mark.parametrize("depth", ["uds", "sa", "shellcode"])
def test_build_parser_accepts_each_depth(depth):
    assert cli.build_parser().parse_args(["--depth", depth]).depth == depth


def test_build_parser_rejects_unknown_depth():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["--depth", "full"])


# --- run: depth gating --------------------------------------------------------

def test_run_depth_uds_never_calls_security_access(patch_probes, tmp_path):
    transport = MockTransport()
    args = cli.build_parser().parse_args(
        ["--depth", "uds", "--artifacts-dir", str(tmp_path)]
    )
    out = cli.run(args, transport_factory=lambda: transport, payload_bytes=b"x")

    assert "sa" not in transport.calls
    assert transport.calls[:2] == ["open", "identity"]
    assert patch_probes["sessions"] == [SESSION_DEFAULT]
    payload = json.loads((out / "probe.json").read_bytes())
    assert payload["layer2"] == {"sa_ok": False, "nrc": None, "envelope_ok": None}
    assert payload["layer3"] is None


def test_run_depth_sa_calls_security_access_but_no_deep(patch_probes, tmp_path):
    transport = MockTransport(sa_ok=True)
    args = cli.build_parser().parse_args(
        ["--depth", "sa", "--artifacts-dir", str(tmp_path)]
    )
    out = cli.run(args, transport_factory=lambda: transport, payload_bytes=b"x")

    assert "sa" in transport.calls
    assert patch_probes["sessions"] == [SESSION_DEFAULT, SESSION_EXTENDED]
    payload = json.loads((out / "probe.json").read_bytes())
    assert payload["layer2"]["sa_ok"] is True
    assert payload["layer3"] is None
    assert patch_probes["deep"] is None


def test_run_depth_shellcode_probes_all_sessions(patch_probes, tmp_path):
    args = cli.build_parser().parse_args(["--artifacts-dir", str(tmp_path)])
    cli.run(args, transport_factory=lambda: MockTransport(), payload_bytes=b"x")
    assert patch_probes["sessions"] == [
        SESSION_DEFAULT, SESSION_EXTENDED, SESSION_PROGRAMMING,
    ]


def test_run_sa_failure_degrades_to_uds_report(patch_probes, tmp_path):
    transport = MockTransport(sa_ok=False)
    args = cli.build_parser().parse_args(
        ["--depth", "sa", "--artifacts-dir", str(tmp_path)]
    )
    out = cli.run(args, transport_factory=lambda: transport, payload_bytes=b"x")

    payload = json.loads((out / "probe.json").read_bytes())
    assert payload["layer2"]["sa_ok"] is False
    assert payload["layer3"] is None
    assert patch_probes["deep"] is None
    md = (out / "probe.md").read_text()
    assert "SecurityAccess: 失败" in md
    assert "## Layer 3 深探" not in md


def test_run_sa_failure_blocks_deep_probe(patch_probes, tmp_path):
    transport = MockTransport(sa_ok=False)
    args = cli.build_parser().parse_args(["--artifacts-dir", str(tmp_path)])
    out = cli.run(args, transport_factory=lambda: transport, payload_bytes=b"x")
    payload = json.loads((out / "probe.json").read_bytes())
    assert payload["layer3"] is None


# --- run: layer 3 -------------------------------------------------------------

def test_run_shellcode_runs_deep_probe_and_classifies(patch_probes, tmp_path):
    args = cli.build_parser().parse_args(["--artifacts-dir", str(tmp_path)])
    out = cli.run(args, transport_factory=lambda: MockTransport(), payload_bytes=b"\x00\x01")

    assert patch_probes["deep"] is not None
    assert patch_probes["deep"]["shellcode"] == b"\x00\x01"
    assert patch_probes["deep"]["scan_egg"] is True
    assert patch_probes["classify"] == (True, True)
    payload = json.loads((out / "probe.json").read_bytes())
    assert payload["layer3"]["classification"]["classification"] == "verified_variant"
    assert payload["layer2"]["envelope_ok"] is True
    assert payload["classification"]["classification"] == "verified_variant"
    assert "固件与已验证变体" in payload["guidance"][0]


def test_run_no_egg_scan_clears_scan_flag(patch_probes, tmp_path):
    args = cli.build_parser().parse_args(
        ["--no-egg-scan", "--artifacts-dir", str(tmp_path)]
    )
    cli.run(args, transport_factory=lambda: MockTransport(), payload_bytes=b"\x00\x01")
    assert patch_probes["deep"]["scan_egg"] is False


def test_run_missing_shellcode_skips_layer3(patch_probes, tmp_path):
    args = cli.build_parser().parse_args(["--artifacts-dir", str(tmp_path)])
    out = cli.run(args, transport_factory=lambda: MockTransport(), payload_bytes=None)
    payload = json.loads((out / "probe.json").read_bytes())
    assert payload["layer3"] is None
    assert patch_probes["deep"] is None
    assert "## Layer 3 深探" not in (out / "probe.md").read_text()


# --- artifacts ----------------------------------------------------------------

def test_run_writes_artifacts_atomically(patch_probes, tmp_path, capsys, monkeypatch):
    replace_calls = []
    real_replace = cli.os.replace

    def record_replace(src, dst):
        replace_calls.append((str(src), str(dst)))
        real_replace(src, dst)

    monkeypatch.setattr(cli.os, "replace", record_replace)
    args = cli.build_parser().parse_args(["--artifacts-dir", str(tmp_path)])
    out = cli.run(args, transport_factory=lambda: MockTransport(), payload_bytes=b"\x00\x01")

    assert out.parent == tmp_path
    assert re.fullmatch(r"\d{8}T\d{6}Z", out.name)
    assert not list(out.glob("*.tmp"))
    assert len(replace_calls) == 2
    assert all(src.endswith(".tmp") for src, _ in replace_calls)
    assert sorted(dst.rsplit("/", 1)[-1] for _, dst in replace_calls) == [
        "probe.json", "probe.md",
    ]

    payload = json.loads((out / "probe.json").read_bytes())
    assert payload["meta"]["addr"] == "0x7A1"
    assert payload["meta"]["depth"] == "shellcode"
    assert payload["layer1"] == {"sessions": [], "dids": [], "routines": [], "download": {}}
    assert "## 下一步" in (out / "probe.md").read_text()

    stdout = capsys.readouterr().out
    assert "# RH850 EPS 探测报告" in stdout


# --- boardd / pandad guard ----------------------------------------------------

def test_run_aborts_when_boardd_running(monkeypatch):
    monkeypatch.setattr(cli, "_boardd_running", lambda: True)
    calls = []

    def factory():
        calls.append("factory")
        return MockTransport()

    args = cli.build_parser().parse_args(["--depth", "uds"])
    with pytest.raises(cli.CliError):
        cli.run(args, transport_factory=factory, payload_bytes=None)
    assert calls == []


def test_probe_main_exit_2_when_boardd_running(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "_boardd_running", lambda: True)
    rc = probe.main(["--depth", "uds", "--artifacts-dir", str(tmp_path)])
    assert rc == 2


# --- probe.py wiring ----------------------------------------------------------

def test_probe_main_wires_transport_and_payload(monkeypatch, tmp_path):
    captured = {}

    def _run(args, *, transport_factory, payload_bytes):
        captured["args"] = args
        captured["payload_bytes"] = payload_bytes
        captured["transport"] = transport_factory()
        return tmp_path

    monkeypatch.setattr(cli, "run", _run)
    shell = tmp_path / "deep_probe.bin"
    shell.write_bytes(b"\xDE\xAD\xBE\xEF")
    monkeypatch.setattr(probe, "SHELLCODE_PATH", shell)

    rc = probe.main(["--addr", "0x7A3", "--serial", "UNIT9", "--depth", "sa"])

    assert rc == 0
    assert captured["args"].addr == 0x7A3
    assert captured["args"].serial == "UNIT9"
    assert captured["payload_bytes"] == b"\xDE\xAD\xBE\xEF"
    assert isinstance(captured["transport"], EcuTransport)
    assert captured["transport"].addr == 0x7A3
    assert captured["transport"]._serial == "UNIT9"


def test_probe_main_exit_2_on_run_error(monkeypatch, tmp_path, capsys):
    def _run(args, *, transport_factory, payload_bytes):
        raise RuntimeError("boom")

    monkeypatch.setattr(cli, "run", _run)
    rc = probe.main(["--depth", "uds", "--artifacts-dir", str(tmp_path)])
    assert rc == 2
    assert "ERROR: boom" in capsys.readouterr().err


def test_probe_main_exit_2_on_shellcode_read_error(monkeypatch, tmp_path, capsys):
    def _boom(_path):
        raise PermissionError("shellcode unreadable")

    monkeypatch.setattr(cli, "load_shellcode", _boom)
    rc = probe.main(["--depth", "uds", "--artifacts-dir", str(tmp_path)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "ERROR: shellcode unreadable" in err
    assert "Traceback" not in err


# --- shellcode loading --------------------------------------------------------

def test_load_shellcode_returns_bytes_for_existing_file(tmp_path):
    source = tmp_path / "deep_probe.bin"
    source.write_bytes(b"\x01\x02\x03")
    assert cli.load_shellcode(source) == b"\x01\x02\x03"


def test_load_shellcode_none_with_note_for_missing_file(tmp_path, capsys):
    assert cli.load_shellcode(tmp_path / "nope.bin") is None
    assert "nope.bin" in capsys.readouterr().err
