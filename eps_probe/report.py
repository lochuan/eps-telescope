"""Report generation: JSON payload, markdown summary, and next-step guidance.

``build_report`` folds the Layer 1/2/3 result dicts (plus run metadata) into a
serializable JSON payload, a human-readable markdown summary, and the list of
next-step guidance strings. ``markdown_registers`` renders the register
snapshot as a table ordered by ``fingerprints.REGISTER_READS`` using only the
manual register names. ``guidance_from_classification`` maps the
``classify_target`` conclusion enum (Task 7) to the decision-tree guidance text
(Spec §8).

Layer result contracts consumed here (composed by the CLI):
- ``layer1``: ``{"sessions": [...], "dids": [...], "routines": [...],
  "download": {...}}`` from ``uds_probe.probe_*`` (or ``{"error": str}`` when
  the layer failed as a whole).
- ``layer2``: ``{"sa_ok": bool, "nrc": int|None, "envelope_ok": bool|None,
  "envelope_nrc": int|None}``.
- ``layer3``: ``run_deep_probe`` output (``stream_valid`` / ``region_bad`` /
  ``envelope_ok`` / ``scan_egg`` surfaced in the markdown) plus ``fingerprint``
  (``verify_patch_fingerprint``), ``boot_integrity``
  (``verify_boot_integrity``) and, when the CLI ran it, ``classification``
  (``classify_target``). The ``classification`` dict is promoted to its own
  JSON section and drives the markdown ``## 下一步`` guidance.
"""

from __future__ import annotations

from .fingerprints import ADJUST_WORD, REGISTER_READS

# Decision-tree guidance (Spec §8). Exactly one string per classification; the
# enum strings come from ``deep_probe.classify_target``.
_GUIDANCE: dict[str, str] = {
    "verified_variant": "固件与已验证变体在 patch 点逐字节一致，可按 0x88000/0xF8000 规划 patch",
    "already_patched": "该车疑似已 patch，注意勿重复操作",
    "egg_variant": "存在 egg 但上下文不匹配，可能为变体或 patch 点重定位，需离线对照新指纹",
    "no_egg": "未发现 egg 签名，patch 点位不同，需完整 dump + RE 重新定位",
    "sa_blocked": "SecurityAccess 失败(NRC 0x..)，0x27 算法或状态不同，需采集 seed/key 对逆向",
    "envelope_blocked": "信封 0x10F0 鉴权失败，需提取该变体 PayloadBuildSecret",
    "probe_incomplete": "深探数据不完整，需重试或降级为 UDS 级探测",
}


def guidance_from_classification(classification: dict | str) -> list[str]:
    """Map a ``classify_target`` conclusion to its next-step guidance text(s).

    Accepts either the full classification dict (Task 7 shape, key
    ``classification``) or the bare enum string.  Unknown classifications yield
    no guidance (``[]``) so ``build_report`` degrades gracefully.
    """
    if isinstance(classification, dict):
        classification = classification.get("classification")
    text = _GUIDANCE.get(classification)
    return [] if text is None else [text]


def markdown_registers(registers: dict) -> str:
    """Render the register snapshot as a markdown table in REGISTER_READS order.

    Rows use the manual register names only (never the legacy payload aliases);
    a key present in ``registers`` but absent from ``REGISTER_READS`` is
    skipped.  Columns: 寄存器名 | 地址 | 宽度 | 值.
    """
    lines = ["| 寄存器名 | 地址 | 宽度 | 值 |", "|---|---|---|---|"]
    for name, addr, width in REGISTER_READS:
        if name not in registers:
            continue
        value = registers[name]
        lines.append(
            f"| {name} | 0x{addr:08X} | {width} | 0x{value:0{width * 2}X} |"
        )
    return "\n".join(lines)


def build_report(
    meta: dict, layer1: dict, layer2: dict, layer3: dict | None = None
) -> dict:
    """Fold the layered probe results into JSON + markdown + guidance.

    Returns ``{"json": {...}, "markdown": str, "guidance": [str, ...]}``.  The
    JSON payload nests ``meta`` + ``layer1``/``layer2``/``layer3`` plus, when
    ``layer3`` carries a ``classification`` key (``classify_target`` output,
    Task 7), a ``classification`` section and the ``guidance`` strings.
    """
    classification = None
    if layer3 is not None:
        classification = layer3.get("classification")
    guidance = guidance_from_classification(classification)

    json_payload = {
        "meta": meta,
        "layer1": layer1,
        "layer2": layer2,
        "layer3": layer3,
        "guidance": guidance,
    }
    if classification is not None:
        json_payload["classification"] = classification

    markdown = _markdown_summary(meta, layer1, layer2, layer3, guidance)
    return {"json": json_payload, "markdown": markdown, "guidance": guidance}


# --- Markdown helpers ---------------------------------------------------------

def _markdown_summary(
    meta: dict, layer1: dict, layer2: dict, layer3: dict | None, guidance: list[str]
) -> str:
    parts = ["# RH850 EPS 探测报告", "", "## 元信息"]
    parts.extend(f"- {key}: {value}" for key, value in meta.items())
    parts += ["", "## Layer 1 UDS 枚举"]
    parts.extend(_markdown_layer1(layer1))
    parts += ["", "## Layer 2 SecurityAccess"]
    parts.extend(_markdown_layer2(layer2))
    if layer3 is not None:
        parts += ["", "## Layer 3 深探"]
        parts.extend(_markdown_layer3(layer3))
    parts += ["", "## 下一步"]
    if guidance:
        parts.extend(f"- {item}" for item in guidance)
    else:
        parts.append("- 无")
    return "\n".join(parts) + "\n"


def _markdown_layer1(layer1: dict) -> list[str]:
    out = []
    for entry in layer1.get("sessions") or []:
        services = entry.get("services") or []
        ok = sum(1 for s in services if s.get("status") == "ok")
        out.append(
            f"- 会话 0x{entry.get('session', 0):02X}: {ok}/{len(services)} SID 响应"
        )
    dids = layer1.get("dids") or []
    if dids:
        ok = sum(1 for d in dids if d.get("status") == "ok")
        out.append(f"- DID: {ok}/{len(dids)} 读取成功")
    routines = layer1.get("routines") or []
    if routines:
        ok = sum(1 for r in routines if r.get("status") == "ok")
        out.append(f"- 例程: {ok}/{len(routines)} 响应")
    download = layer1.get("download") or {}
    present = [(name, download[name]) for name in ("ram", "flash") if download.get(name)]
    if present:
        out.append(
            "- RequestDownload: "
            + ", ".join(f"{name}: {entry.get('status', '?')}" for name, entry in present)
        )
    return out


def _markdown_layer2(layer2: dict) -> list[str]:
    out = []
    sa_ok = layer2.get("sa_ok")
    status = "通过" if sa_ok else "失败" if sa_ok is False else "未知"
    out.append(f"- SecurityAccess: {status}")
    if layer2.get("nrc") is not None:
        out.append(f"- NRC: 0x{layer2['nrc']:02X}")
    if layer2.get("envelope_ok") is not None:
        out.append(f"- 信封 0x10F0 鉴权: {'通过' if layer2['envelope_ok'] else '失败'}")
    if layer2.get("envelope_nrc") is not None:
        out.append(f"- 信封 NRC: 0x{layer2['envelope_nrc']:02X}")
    return out


def _markdown_layer3(layer3: dict) -> list[str]:
    out = []
    if layer3.get("error") is not None:
        out.append(f"- 错误: {layer3['error']}")
    if layer3.get("envelope_ok") is not None:
        out.append(
            f"- 信封 0x10F0 鉴权: {'通过' if layer3['envelope_ok'] else '失败'}"
        )
    if "stream_valid" in layer3:
        out.append(f"- 流 CRC 校验: {'通过' if layer3['stream_valid'] else '失败'}")
    region_bad = layer3.get("region_bad") or []
    if region_bad:
        out.append(
            "- 区域 CRC 失败: "
            + ", ".join(f"0x{addr:X}" for addr in sorted(region_bad))
        )
    if layer3.get("scan_egg") is not None:
        out.append(
            "- egg 签名扫描: " + ("启用" if layer3["scan_egg"] else "跳过 (--no-egg-scan)")
        )
    registers = layer3.get("registers") or {}
    if registers:
        out += ["### 寄存器快照", markdown_registers(registers)]
    fingerprint = layer3.get("fingerprint") or {}
    status_line = f"- 指纹状态: {fingerprint.get('status', '未知')}"
    if fingerprint.get("note"):
        status_line += f" ({fingerprint['note']})"
    out.append(status_line)
    candidates = fingerprint.get("candidates") or []
    if candidates:
        out.append(
            "- egg 候选: "
            + ", ".join(f"0x{c.get('addr', 0):X}({c.get('status')})" for c in candidates)
        )
    boot = layer3.get("boot_integrity") or {}
    adjust = boot.get("adjust_word")
    state = boot.get("state", "unknown")
    addr = ADJUST_WORD["addr"]
    if adjust is not None:
        out.append(f"- 调整字 0x{addr:X}: 0x{adjust:08X} ({state})")
    else:
        out.append(f"- 调整字 0x{addr:X}: 未读取 ({state})")
    if boot.get("note"):
        out.append(f"- {boot['note']}")
    if "residue_ok" in boot:
        out.append(f"- DCRA1 残差验证: {'通过' if boot['residue_ok'] else '失败'}")
    return out
