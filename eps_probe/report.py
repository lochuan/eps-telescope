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

from .fingerprints import ADJUST_WORD, EGG_ADDRESS, REGISTER_READS

# Decision-tree guidance (Spec §8). Exactly one string per classification; the
# enum strings come from ``deep_probe.classify_target``. Bilingual: 中文 (English).
_GUIDANCE: dict[str, str] = {
    "verified_variant": (
        "固件与已验证变体在 patch 点逐字节一致，可按 0x88000/0xF8000 规划 patch "
        "(Firmware matches the verified variant at the patch point; plan the "
        "patch against 0x88000/0xF8000)"
    ),
    "already_patched": (
        "该车疑似已 patch，注意勿重复操作 "
        "(This vehicle appears already patched; do not patch again)"
    ),
    "egg_variant": (
        "egg 位于 FW-PATCH 位置 (0x8E6C6) 但上下文不匹配，可能是同位置变体 "
        "(Egg at the FW-PATCH location but context differs; likely a variant at "
        "the same patch point)"
    ),
    "egg_variant_relocated": (
        "存在 egg 但地址与 FW-PATCH (0x8E6C6) 不同，patch 点可能重定位，需离线对照新指纹 "
        "(Egg present but not at the FW-PATCH address; the patch point may be "
        "relocated — compare against a new fingerprint offline)"
    ),
    "no_egg": (
        "未发现 egg 签名，patch 点位不同，需完整 dump + RE 重新定位 "
        "(No egg signature found; the patch point differs — a full dump + RE "
        "relocation is required)"
    ),
    "sa_blocked": (
        "SecurityAccess 失败，0x27 算法或状态不同，需采集 seed/key 对逆向 "
        "(SecurityAccess failed; the 0x27 algorithm/state differs — collect "
        "seed/key pairs to reverse-engineer)"
    ),
    "envelope_blocked": (
        "信封 0x10F0 鉴权失败，需提取该变体 PayloadBuildSecret "
        "(Envelope 0x10F0 authentication failed; extract this variant's "
        "PayloadBuildSecret)"
    ),
    "probe_incomplete": (
        "深探数据不完整，需重试或降级为 UDS 级探测 "
        "(Deep-probe data incomplete; retry or fall back to UDS-level probing)"
    ),
}


def guidance_from_classification(classification: dict | str) -> list[str]:
    """Map a ``classify_target`` conclusion to its next-step guidance text(s).

    Accepts either the full classification dict (Task 7 shape, key
    ``classification``) or the bare enum string.  ``egg_variant`` splits on
    ``egg_at_expected``: the egg at FW-PATCH's ``EGG_ADDRESS`` points to a
    same-location variant, an egg elsewhere points to a relocated patch point.
    Unknown classifications yield no guidance (``[]``) so ``build_report``
    degrades gracefully.
    """
    egg_at_expected = None
    if isinstance(classification, dict):
        egg_at_expected = classification.get("egg_at_expected")
        classification = classification.get("classification")
    if classification == "egg_variant" and egg_at_expected is False:
        text = _GUIDANCE["egg_variant_relocated"]
    else:
        text = _GUIDANCE.get(classification)
    return [] if text is None else [text]


def markdown_registers(registers: dict) -> str:
    """Render the register snapshot as a markdown table in REGISTER_READS order.

    Rows use the manual register names only (never the legacy payload aliases);
    a key present in ``registers`` but absent from ``REGISTER_READS`` is
    skipped.  Columns: 寄存器名 | 地址 | 宽度 | 值.
    """
    lines = ["| 寄存器名 (Register) | 地址 (Addr) | 宽度 (Width) | 值 (Value) |", "|---|---|---|---|"]
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
    parts = ["# RH850 EPS 探测报告 (RH850 EPS Probe Report)", "", "## 元信息 (Metadata)"]
    parts.extend(f"- {key}: {value}" for key, value in meta.items())
    parts += ["", "## Layer 1 UDS 枚举 (UDS Enumeration)"]
    parts.extend(_markdown_layer1(layer1))
    vehicle = layer1.get("vehicle")
    if vehicle:
        parts += ["", "## 车辆指纹 (Vehicle Fingerprint)"]
        parts.extend(_markdown_vehicle(vehicle))
    parts += ["", "## Layer 2 SecurityAccess"]
    parts.extend(_markdown_layer2(layer2))
    if layer3 is not None:
        parts += ["", "## Layer 3 深探 (Deep Probe)"]
        parts.extend(_markdown_layer3(layer3))
    parts += ["", "## 下一步 (Next Steps)"]
    if guidance:
        parts.extend(f"- {item}" for item in guidance)
    else:
        parts.append("- 无 (none)")
    return "\n".join(parts) + "\n"


def _markdown_layer1(layer1: dict) -> list[str]:
    out = []
    for entry in layer1.get("sessions") or []:
        services = entry.get("services") or []
        ok = sum(1 for s in services if s.get("status") == "ok")
        out.append(
            f"- 会话 0x{entry.get('session', 0):02X}: {ok}/{len(services)} SID 响应 (responded)"
        )
    dids = layer1.get("dids") or []
    if dids:
        ok = sum(1 for d in dids if d.get("status") == "ok")
        out.append(f"- DID: {ok}/{len(dids)} 读取成功 (read OK)")
    routines = layer1.get("routines") or []
    if routines:
        ok = sum(1 for r in routines if r.get("status") == "ok")
        out.append(f"- 例程: {ok}/{len(routines)} 响应 (responded)")
    download = layer1.get("download") or {}
    present = [(name, download[name]) for name in ("ram", "flash") if download.get(name)]
    if present:
        out.append(
            "- RequestDownload: "
            + ", ".join(f"{name}: {entry.get('status', '?')}" for name, entry in present)
        )
    return out


_ECU_NAME = {
    0x7E0: "Engine",
    0x7D2: "Hybrid",
    0x7B0: "ABS",
    0x7D1: "ForwardRadar",
    0x7D0: "ForwardCamera",
    0x780: "SRS",
    0x7E1: "Transmission",
    0x7C4: "HVAC",
    0x7C0: "CombinationMeter",
    0x713: "HVBattery",
    0x716: "MotorGenerator",
}


def _fmt_did_data(data) -> str:
    """Render DID read data: ASCII when printable, else hex.

    Toyota software identifiers commonly carry a 0x01/0x02 prefix byte; it is
    stripped before the printable-ASCII check so e.g. ``01 8965B4512000`` is
    shown as ``8965B4512000`` rather than a hex blob.
    """
    if not data:
        return "-"
    raw = bytes(data)
    body = raw[1:] if raw and raw[0] in (0x01, 0x02) else raw
    if all(32 <= b < 127 or b == 0 for b in body):
        text = body.decode("latin-1").rstrip("\x00")
        if text:
            return text
    return raw.hex()


def _markdown_vehicle(vehicle: dict) -> list[str]:
    """Render the vehicle-fingerprint section (main-ECU sweep + other ECUs)."""
    out = []
    if "error" in vehicle:
        out.append(f"- 指纹探测失败 (fingerprint failed): {vehicle['error']}")
        return out
    vin = vehicle.get("vin")
    if vin:
        out.append(f"- VIN: {vin}")
    main = vehicle.get("main_ecu") or []
    main_ok = [r for r in main if r.get("status") == "ok"]
    out.append(f"- 主 ECU (0x7E0): {len(main_ok)}/{len(main)} DID 读取成功 (read OK)")
    for record in main_ok:
        out.append(f"  - {record.get('name', '?')}: {_fmt_did_data(record.get('data'))}")
    ecus = vehicle.get("ecus") or {}
    for addr in sorted(ecus):
        records = ecus[addr] or []
        ok = [r for r in records if r.get("status") == "ok"]
        label = _ECU_NAME.get(addr, f"0x{addr:03X}")
        if not ok:
            out.append(f"- {label} (0x{addr:03X}): 无响应 (no response)")
            continue
        out.append(f"- {label} (0x{addr:03X}):")
        for record in ok:
            out.append(f"  - {record.get('name', '?')}: {_fmt_did_data(record.get('data'))}")
    return out


def _markdown_layer2(layer2: dict) -> list[str]:
    out = []
    sa_ok = layer2.get("sa_ok")
    status = "通过 (OK)" if sa_ok else "失败 (FAIL)" if sa_ok is False else "未知 (unknown)"
    out.append(f"- SecurityAccess: {status}")
    if layer2.get("nrc") is not None:
        out.append(f"- NRC: 0x{layer2['nrc']:02X}")
    if layer2.get("envelope_ok") is not None:
        ok = "通过 (OK)" if layer2["envelope_ok"] else "失败 (FAIL)"
        out.append(f"- 信封 0x10F0 鉴权 (envelope auth): {ok}")
    if layer2.get("envelope_nrc") is not None:
        out.append(f"- 信封 NRC: 0x{layer2['envelope_nrc']:02X}")
    return out


def _markdown_layer3(layer3: dict) -> list[str]:
    out = []
    if layer3.get("error") is not None:
        out.append(f"- 错误 (error): {layer3['error']}")
    if layer3.get("envelope_ok") is not None:
        ok = "通过 (OK)" if layer3["envelope_ok"] else "失败 (FAIL)"
        out.append(f"- 信封 0x10F0 鉴权 (envelope auth): {ok}")
    if "stream_valid" in layer3:
        ok = "通过 (OK)" if layer3["stream_valid"] else "失败 (FAIL)"
        out.append(f"- 流 CRC 校验 (stream CRC): {ok}")
    region_bad = layer3.get("region_bad") or []
    if region_bad:
        out.append(
            "- 区域 CRC 失败 (region CRC failed): "
            + ", ".join(f"0x{addr:X}" for addr in sorted(region_bad))
        )
    if layer3.get("scan_egg") is not None:
        if layer3["scan_egg"]:
            out.append("- egg 签名扫描 (egg scan): 启用 (enabled)")
        else:
            out.append("- egg 签名扫描 (egg scan): 跳过 (skipped) (--no-egg-scan)")
    registers = layer3.get("registers") or {}
    if registers:
        out += ["### 寄存器快照 (Register Snapshot)", markdown_registers(registers)]
    fingerprint = layer3.get("fingerprint") or {}
    status_line = f"- 指纹状态 (fingerprint): {fingerprint.get('status', '未知 (unknown)')}"
    if fingerprint.get("note"):
        status_line += f" ({fingerprint['note']})"
    out.append(status_line)
    candidates = fingerprint.get("candidates") or []
    egg_found = bool(fingerprint.get("egg_found"))
    egg_at_expected = bool(fingerprint.get("egg_at_expected"))
    if egg_found:
        if egg_at_expected:
            out.append(
                f"- egg 签名 (egg signature): 存在@0x{EGG_ADDRESS:X} "
                "(present, matches FW-PATCH)"
            )
        else:
            out.append(
                "- egg 签名 (egg signature): 存在-地址不同 "
                "(present, relocated from FW-PATCH)"
            )
    else:
        out.append("- egg 签名 (egg signature): 未发现 (not found)")
    if candidates:
        rendered = []
        for c in candidates:
            marker = "与FW-PATCH一致" if c.get("at_expected") else "重定位"
            rendered.append(f"0x{c.get('addr', 0):X}({c.get('status')},{marker})")
        out.append("- egg 候选 (egg candidates): " + ", ".join(rendered))
    boot = layer3.get("boot_integrity") or {}
    adjust = boot.get("adjust_word")
    state = boot.get("state", "unknown")
    addr = ADJUST_WORD["addr"]
    if adjust is not None:
        out.append(f"- 调整字 0x{addr:X} (adjust word): 0x{adjust:08X} ({state})")
    else:
        out.append(f"- 调整字 0x{addr:X} (adjust word): 未读取 (not read) ({state})")
    if boot.get("note"):
        out.append(f"- {boot['note']}")
    if "residue_ok" in boot:
        ok = "通过 (OK)" if boot["residue_ok"] else "失败 (FAIL)"
        out.append(f"- DCRA1 残差验证 (residue): {ok}")
    return out
