"""Report generator: JSON payload, markdown summary, guidance decision tree."""

import pytest

from eps_probe import report
from eps_probe.deep_probe import classify_target
from eps_probe.fingerprints import REGISTER_READS

# Exact decision-tree guidance text per classification (Spec §8 / task brief).
_GUIDANCE = {
    "verified_variant": "固件与已验证变体在 patch 点逐字节一致，可按 0x88000/0xF8000 规划 patch",
    "already_patched": "该车疑似已 patch，注意勿重复操作",
    "egg_variant": "存在 egg 但上下文不匹配，可能为变体或 patch 点重定位，需离线对照新指纹",
    "no_egg": "未发现 egg 签名，patch 点位不同，需完整 dump + RE 重新定位",
    "sa_blocked": "SecurityAccess 失败(NRC 0x..)，0x27 算法或状态不同，需采集 seed/key 对逆向",
    "envelope_blocked": "信封 0x10F0 鉴权失败，需提取该变体 PayloadBuildSecret",
    "probe_incomplete": "深探数据不完整，需重试或降级为 UDS 级探测",
}


def _classification(name):
    """Minimal classify_target-shaped dict for a given classification."""
    return {
        "classification": name,
        "fingerprint": "MATCH" if name in ("verified_variant", "already_patched") else "MISMATCH",
        "boot_integrity": "original",
        "egg_hits": 0,
        "sa_ok": True,
        "envelope_ok": True,
    }


_META = {"timestamp": "2026-08-19T00:00:00Z", "addr": "0x7A1", "serial": "unit-test"}

_LAYER1 = {
    "sessions": [
        {
            "session": 0x01,
            "services": [
                {"sid": 0x10, "status": "ok", "nrc": None},
                {"sid": 0x11, "status": "nrc", "nrc": 0x11},
            ],
        },
        {
            "session": 0x03,
            "services": [
                {"sid": 0x10, "status": "ok", "nrc": None},
                {"sid": 0x11, "status": "ok", "nrc": None},
                {"sid": 0x22, "status": "timeout", "nrc": None},
            ],
        },
    ],
    "dids": [
        {"did": 0xF181, "status": "ok", "nrc": None, "data": b"\x01\x02"},
        {"did": 0xF182, "status": "nrc", "nrc": 0x31, "data": None},
    ],
    "routines": [
        {"rid": 0x10F0, "status": "nrc", "nrc": 0x31},
        {"rid": 0x10F3, "status": "ok", "nrc": None},
    ],
    "download": {
        "ram": {"status": "ok", "max_block_length": 0x400, "nrc": None},
        "flash": {"status": "nrc", "nrc": 0x31},
    },
}

_LAYER2 = {"sa_ok": True, "nrc": None, "envelope_ok": True}

_REGISTERS = {
    "FPMON": 0x00,
    "FASTAT": 0x00,
    "FAREASELC": 0x0000,
    "FSTATR": 0x00000000,
    "FENTRYR": 0x0000,
    "FPROTR": 0x0000,
    "FSUINITR": 0x00,
    "FLKSTAT": 0x01,
    "FPCKAR": 0x0000,
    "SELFID0": 0x00000000,
    "FHVE15": 0x00000000,
    "FHVE3": 0x00000000,
    "DCRA1CIN": 0xFFD51000,
    "DCRA1COUT": 0xFFFFFFFF,
    "PRDNAME1": 0x54524F50,
}


def _layer3(classification=None):
    out = {
        "registers": dict(_REGISTERS),
        "regions": {0x8E6A0: b"\x00" * 0x100},
        "egg_candidates": [],
        "stream_valid": True,
        "error": None,
        "fingerprint": {"status": "MATCH", "candidates": []},
        "boot_integrity": {"adjust_word": 0x0962887F, "state": "original"},
    }
    if classification is not None:
        out["classification"] = _classification(classification)
    return out


# --- guidance_from_classification ---------------------------------------------

@pytest.mark.parametrize("classification,expected", _GUIDANCE.items())
def test_guidance_exact_text_per_classification(classification, expected):
    assert report.guidance_from_classification(_classification(classification)) == [expected]
    assert report.guidance_from_classification(classification) == [expected]


def test_guidance_unknown_classification_yields_nothing():
    assert report.guidance_from_classification("nonsense") == []
    assert report.guidance_from_classification({}) == []
    assert report.guidance_from_classification(None) == []


def test_classify_target_output_flows_to_guidance():
    fp = {"status": "MATCH", "candidates": []}
    bi = {"adjust_word": 0x0962887F, "state": "original"}
    cls = classify_target(fp, bi, sa_ok=True, envelope_ok=True)
    assert cls["classification"] == "verified_variant"
    assert report.guidance_from_classification(cls) == [
        _GUIDANCE["verified_variant"]
    ]


# --- markdown_registers -------------------------------------------------------

def test_markdown_registers_uses_manual_names_only():
    regs = dict(_REGISTERS)
    regs["FLWL"] = 0x1111      # legacy alias for FHVE15
    regs["FLWE"] = 0x2222      # legacy alias for FHVE3
    regs["FAESTAT"] = 0x33     # legacy alias for FASTAT
    regs["FREQR"] = 0x44       # legacy alias for FAREASELC
    md = report.markdown_registers(regs)

    assert "| 寄存器名 | 地址 | 宽度 | 值 |" in md
    for name in ("FSTATR", "FENTRYR", "FHVE15", "FPMON", "FAREASELC"):
        assert name in md
    for alias in ("FLWL", "FLWE", "FAESTAT", "FREQR"):
        assert alias not in md


def test_markdown_registers_ordered_by_register_reads():
    md = report.markdown_registers(dict(_REGISTERS))
    rows = [line for line in md.splitlines() if line.startswith("| ") and not line.startswith("| 寄存器名") and not line.startswith("|--")]
    present = [name for name, _addr, _width in REGISTER_READS if name in _REGISTERS]
    assert [row.split("|")[1].strip() for row in rows] == present


def test_markdown_registers_skips_unknown_keys():
    md = report.markdown_registers({"FSTATR": 0, "unknown_reg": 0x123})
    assert "FSTATR" in md
    assert "unknown_reg" not in md


# --- build_report -------------------------------------------------------------

def test_build_report_json_nests_meta_and_layers():
    out = report.build_report(_META, _LAYER1, _LAYER2, _layer3("verified_variant"))
    payload = out["json"]
    assert payload["meta"] == _META
    assert payload["layer1"] == _LAYER1
    assert payload["layer2"] == _LAYER2
    assert payload["layer3"] == _layer3("verified_variant")
    assert payload["classification"]["classification"] == "verified_variant"
    assert payload["guidance"] == [_GUIDANCE["verified_variant"]]
    assert out["guidance"] == payload["guidance"]


@pytest.mark.parametrize("classification,expected", _GUIDANCE.items())
def test_build_report_guidance_and_markdown_next_steps(classification, expected):
    out = report.build_report(_META, _LAYER1, _LAYER2, _layer3(classification))
    assert out["guidance"] == [expected]
    assert out["json"]["guidance"] == [expected]
    assert "## 下一步" in out["markdown"]
    assert f"- {expected}" in out["markdown"]


def test_build_report_markdown_sections_and_summary():
    out = report.build_report(_META, _LAYER1, _LAYER2, _layer3("verified_variant"))
    md = out["markdown"]
    for header in (
        "## 元信息",
        "## Layer 1 UDS 枚举",
        "## Layer 2 SecurityAccess",
        "## Layer 3 深探",
        "## 下一步",
    ):
        assert header in md
    assert "unit-test" in md
    assert "0x7A1" in md
    assert "1/2 SID 响应" in md
    assert "DID: 1/2 读取成功" in md
    assert "SecurityAccess: 通过" in md
    assert "FSTATR" in md
    assert "FENTRYR" in md
    assert "FHVE15" in md
    assert "指纹状态: MATCH" in md
    assert "0x0962887F" in md
    assert "original" in md


def test_build_report_without_layer3():
    out = report.build_report(_META, _LAYER1, _LAYER2)
    payload = out["json"]
    assert payload["layer3"] is None
    assert "classification" not in payload
    assert payload["guidance"] == []
    assert out["guidance"] == []
    assert "## 下一步" in out["markdown"]
    assert "## Layer 3 深探" not in out["markdown"]


def test_build_report_layer3_without_classification():
    out = report.build_report(_META, _LAYER1, _LAYER2, _layer3())
    assert "classification" not in out["json"]
    assert out["guidance"] == []


def test_markdown_layer3_surfaces_stream_valid_and_region_bad():
    layer3 = _layer3("verified_variant")
    layer3["stream_valid"] = False
    layer3["region_bad"] = [0x8E6A0, 0xFFDE0]
    layer3["fingerprint"] = {
        "status": "NO_DATA",
        "note": "指纹窗口区域 0x8E6A0 CRC 校验失败，数据不可信",
        "candidates": [],
    }
    layer3["boot_integrity"] = {
        "adjust_word": 0x0962887F, "state": "unknown",
        "note": "调整字区域 0xFFDE0 CRC 校验失败，数据不可信",
    }
    md = report.build_report(_META, _LAYER1, _LAYER2, layer3)["markdown"]
    assert "流 CRC 校验: 失败" in md
    assert "区域 CRC 失败: 0x8E6A0, 0xFFDE0" in md
    assert "指纹窗口区域 0x8E6A0 CRC" in md
    assert "调整字区域 0xFFDE0 CRC" in md


def test_markdown_layer3_records_egg_scan_skip():
    layer3 = _layer3()
    layer3["scan_egg"] = False
    md = report.build_report(_META, _LAYER1, _LAYER2, layer3)["markdown"]
    assert "egg 签名扫描: 跳过 (--no-egg-scan)" in md


def test_markdown_layer2_surfaces_envelope_nrc():
    layer2 = dict(_LAYER2)
    layer2["envelope_ok"] = False
    layer2["envelope_nrc"] = 0x31
    md = report.build_report(_META, _LAYER1, layer2, None)["markdown"]
    assert "信封 0x10F0 鉴权: 失败" in md
    assert "信封 NRC: 0x31" in md


def test_markdown_layer3_error_only():
    md = report.build_report(_META, _LAYER1, _LAYER2, {"error": "stream timeout"})["markdown"]
    assert "错误: stream timeout" in md
    assert "指纹状态: 未知" in md
