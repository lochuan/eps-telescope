# RH850 EPS Probe — 设计文档

日期: 2026-08-19
状态: 已批准（用户已确认并选择 subagent 逐任务执行）

## 1. 目标

构建一个**严格只读**的 Toyota RH850（RH850/P1M-E 系）EPS 探测工具。它不对 EPS 做任何刷写操作，目的是采集目标车辆尽可能丰富的信息（MCU 身份、固件变体、UDS 能力、SA 可用性、flash 状态、boot integrity 机制、patch 点指纹），并为下一步制定 patch 方案提供指引。

参考来源：
- `egg-hunter-patch` — 简单通用探测流程（会话梯子 → SA → shellcode dump）
- `8965B4512000-FW-PATCH` — 安全流式协议、runtime watchdog guard、证据绑定思路
- `secoc` — 加密信封上传方法（AES-CBC + CMAC，DID 201/202，0x10F0 鉴权，0xFF00 触发）
- 知识库固件 UDS 逆向（分发表/会话门/DID/例程/区域表，SA 两步 AES，KDF/CMAC/CBC）
- openpilot/opendbc UDS 客户端与 ISO-TP
- RH850/P1M-E 硬件手册（寄存器正确名、FACI 命令、DCRA、RS-CANFD）

## 2. 运行环境与依赖

- 运行于 openpilot 设备（comma），Panda 经 ELM327 安全模式透传 CAN
- Python 3.12.x（低于 3.13）
- 依赖：`panda`、`opendbc`（UdsClient、isotp、CarParams）、`pycryptodome`（AES/CMAC）、`tqdm`
- 目标 UDS 地址默认 `0x7A1`，响应 `0x7A9`（rx_offset 0x8），bus 0
- 交叉编译：v850-elf-gcc（Docker 镜像，复用 secoc shellcode 构建思路）

## 3. 分层门控流程

```
CLI (--addr 0x7a1, --serial, --depth {uds,sa,shellcode})
  ├─ Layer 1 UDS 枚举（任何固件均可执行，只读）
  │    ├─ 会话梯子 DEFAULT→EXTENDED→PROGRAMMING（settle 0.5/0.7/1.0s）
  │    ├─ DID F181（app + boot，记录完整原始值，不硬编码格式）
  │    ├─ 各会话枚举标准 SID 支持性（记录响应/NRC 名）
  │    ├─ 关键 DID 范围探测（0xF180-0xF19F, 0x200-0x2FF, 0x0000-0x00FF）
  │    ├─ RID 探测（保守：0x10F3 状态查询 + 已知 RID 空 option，记录 NRC）
  │    └─ RequestDownload 接受性探测（0x34→RAM 0xFEBF0000 / flash 0x18000，只发请求不传输）
  ├─ Layer 2 SecurityAccess
  │    ├─ 请求种子（16B 0 record）→ 已知 SEED_KEY_SECRET 推导 key → 发送
  │    └─ 记录 seed 值 / 接受与否 / NRC（0x35 算法不符、0x36 超次数、0x33 拒绝）
  ├─ Layer 3 shellcode 深探（SA 通过且信封路径可用）
  │    ├─ 参数化信封（请求块嵌入，复用 secoc 构建逻辑）
  │    ├─ 上传 RAM 0xFEBF0000 → routine 0x10F0 鉴权（old/new variant）→ 0xFF00 触发
  │    └─ 只读 shellcode 采集：寄存器快照 + 定向区域 + patch 指纹 + boot integrity
  └─ 报告：时间戳 JSON + markdown 摘要 + 下一步 patch 指引
```

每层失败均记录并继续可用信息，绝不写入 flash。`--depth` 控制最大深入层级；SA 失败自动降级。

## 4. 严格只读约束

- 不发任何 FACI 命令、不进入 P/E 模式、不写 lock bit、不写 option byte、不擦除/编程任何 flash
- 只允许 UDS 0x34 RequestDownload 到 **RAM** `0xFEBF0000`（易失，进程内销毁）
- shellcode 只做 MMIO 读 + CAN TX 流式回传；通过 runtime watchdog stub（0xFEBF1188）维持运行，结束走 bootloader reset（`0x0000157e`）

## 5. 正确寄存器映射（来自 RH850/P1M-E 硬件手册）

> 两个既有 payload（egg-hunter / FW-PATCH）的寄存器名大量用错，本工程一律使用手册正确名。

### FACI/FCU 状态（base 0xFFA1xxxx）

| 地址 | 正确名 | 宽度 | 含义 | payload 曾用错名 |
|---|---|---|---|---|
| 0xFFA10000 | FPMON | 8 | FLMD0 引脚 / FWE | ✓ |
| 0xFFA10010 | FASTAT | 8 | access error / command lock | "FAESTAT" ✗ |
| 0xFFA10020 | FAREASELC | 16 | code flash 区域选择 | "FREQR" ✗ |
| 0xFFA10030 | FSADDR | 32 | 命令起始地址 | ✓ |
| 0xFFA10034 | FEADDR | 32 | 命令结束地址 | — |
| 0xFFA10080 | FSTATR | 32 | FRDY/ILGLERR/ERSERR/PRGERR/FLWEERR… | "FASTAT" ✗ |
| 0xFFA10084 | FENTRYR | 16 | P/E 进入（FENTRYRC/…D） | "FPCKAR" ✗ |
| 0xFFA10088 | FPROTR | 16 | lock-bit 保护 | "FENTRYR" ✗ |
| 0xFFA10090 | FSUINITR | 8 | | — |
| 0xFFA10098 | FLKSTAT | 8 | lock bit 读结果 | — |
| 0xFFA100E4 | FPCKAR | 16 | 处理时钟通知 | （payload 误放 0x84） |
| 0xFFA08000-0C | SELFID0-3 | 32 | ID code 比较 | — |
| 0xFFA08010 | SELFIDST | 32 | IDST（0=已认证） | — |

### 软件保护 / 高电压使能

| 地址 | 正确名 | 宽度 | 含义 | payload 曾用错名 |
|---|---|---|---|---|
| 0xFFF82410 | FHVE3 | 32 | FHVE3CNT=1 使能 P/E/blank-check | "FLWE" ✗ |
| 0xFFF8A430 | FHVE15 | 32 | FHVE15CNT=1 使能 P/E/blank-check | "FLWL" ✗ |

### Boot integrity（DCRA1）

| 地址 | 正确名 | 说明 |
|---|---|---|
| 0xFFD51000 | DCRA1CIN | CRC 输入 |
| 0xFFD51004 | DCRA1COUT | CRC 结果 |
| 0xFFD51020 | DCRA1CTL | 控制 |

覆盖范围 `[0x18000, 0xFFDF0)`，残差目标 `0xFFFFFFFF`。

### MCU 身份

| 地址 | 正确名 | 说明 |
|---|---|---|
| 0xFFCD00D0 | PRDNAME1 | 产品名（16 字节 ASCII，倒序存储） |
| 0xFFCD00D4 | PRDNAME2 | |
| 0xFFCD00D8 | PRDNAME3 | |
| 0xFFCD00DC | PRDNAME4 | |

### CAN TX（RS-CANFD0，base 0xFFD20000，buffer p=0x10）

RSCFD0CFDTMCp / RSCFD0CFDTMSTSp / RSCFD0CFDTMIDp / RSCFD0CFDTMPTRp / RSCFD0CFDTMFDCTRp / RSCFD0CFDTMDFb_p。这些名字在手册 §17 中正确（payload 的 CAN 寄存器名无误）。

## 6. Patch 点指纹（来自 Ghidra code_v2.bin + 车辆 artifacts 交叉验证）

- **Patch 字节**：`0x8E6C7`，`0xD1 → 0x01`，所在指令 `1D 30 E0 D1`（`0x8E6C4 mov r29,r6` + `0x8E6C6 cmp r0,r26`）
- **egg 签名**：`E0 D1 9A 0D 1A 38 BF FF` @ `0x8E6C6`（patch 字节在 egg+1），当前固件唯一
- **64B 指纹窗口**：`0x8E6A7..0x8E6E7`，patch 字节 offset 32，SHA-256 `50d793a2942716dcf0582238edfe6c2d72378eea8bd4e1bf575a8539cd497350`，hex `d3bfffcef86152fa05bb0f0900610aba05003aa5051a381d30bfff86ff1d30e0d19a0d1a38bfff78fb1d301a38bfffe6fbd505203e0002bfffa4fc0ad8b50520`
- **语义**：`FUN_0008e67a` 是 SecOC RX 状态机分支，patch 强制落入验证兼容路径（`FUN_0008e2ba`，含 `FUN_0008d9a4` 验证）

## 7. Boot integrity 机制（与 CRC 调整字）

- 调整字在 `range_end - 4 = 0xFFDEC`，是**整个覆盖范围内容的 CRC 函数值，不是固件常量**
- 未 patch 值 `0x0962887F`，已 patch 值 `0x41C90FF2`（来自真实车辆 faci-pe-cycle 报告与回读扇区）
- 探测验证方式：读 DCRA1 CTL/COUT（idle 观察）+ 流式回传 CRC 扇区 → 主机对 `[0x18000, 0xFFDF0)` 软件 CRC32 → 检查残差 `0xFFFFFFFF`；读取调整字并分类（orig / patched / other）

## 8. 输出与指引

每次运行生成时间戳 artifacts：
- `probe.json` — 全部原始数据（分层结果、寄存器快照、指纹比对、DID/SID/NRC）
- `probe.md` — 人读摘要，全部字段使用正确寄存器名
- 原始 CAN 流 `.bin`（Layer 3 有数据时）

指引决策树：
1. 指纹 MATCH + boot integrity 残差验证通过 → "固件与已验证变体一致，可按 0x88000/0xF8000 规划 patch"
2. 指纹 MATCH + 调整字 = patched → "该车疑似已 patch，注意勿重复操作"
3. egg 命中但指纹不符 → "变体或 patch 点重定位，需离线对照新指纹"
4. 无 egg → "patch 点位不同，需完整 dump + RE 重新定位"
5. SA 失败（0x35/0x36/0x33）→ "0x27 算法不同/被拒，需采集 seed/key 对逆向"
6. 信封鉴权失败（0x10F0 拒绝）→ "需提取该变体 PayloadBuildSecret"

## 9. 项目结构

```
telescope/
├── probe.py                    # CLI 入口
├── pyproject.toml
├── eps_probe/
│   ├── __init__.py
│   ├── transport.py            # Panda/UDS 会话梯子/SA/上传/触发（old/new variant）
│   ├── uds_probe.py            # Layer 1：SID/DID/RID/download 探测
│   ├── payload.py              # 信封构建 + 请求块嵌入（secoc 逻辑）
│   ├── protocol.py             # tagged+CRC 流协议 + StreamCollector
│   ├── deep_probe.py           # Layer 3 编排 + 指纹/boot integrity 验证
│   ├── fingerprints.py         # 变体指纹表（5-7 节数据）
│   ├── report.py               # JSON + markdown + 指引
│   └── cli.py                  # 参数解析 + 门控 + artifacts
├── shellcode/
│   ├── deep_probe.c            # 参数化请求块只读 shellcode
│   ├── linker.ld
│   ├── build.sh
│   └── Dockerfile
├── docs/superpowers/specs/     # 本设计文档
├── docs/superpowers/plans/     # 实现计划
└── tests/
```

## 10. 关键接口摘要

- `fingerprints.PATCH_FINGERPRINT / EGG_SIGNATURE / DCRA_MECHANISM / ADJUST_WORD / REGISTER_READS / MCU_PRDNAME`
- `protocol.build_region_request(flags, regions) -> bytes`；`protocol.StreamCollector.consume()/finish() -> StreamResult`
- `payload.build_envelope(shellcode, request_block, did_201, did_202) -> bytes`；`payload.build_request_block(...)`
- `transport.EcuTransport(serial, addr, bus, bindings)`：`read_identity()`、`session_ladder()`、`security_access(secret)`、`upload_and_trigger(envelope, new_uds)`、`collect_stream(op, timeout)`
- `uds_probe.probe_sessions / probe_dids / probe_routines / probe_download_acceptance`
- `deep_probe.run_deep_probe(transport, variants)`、`verify_patch_fingerprint(...)`、`verify_boot_integrity(...)`
- `report.build_report(layer1, layer2, layer3)`
- CLI：`--addr`（默认 0x7A1）、`--serial`、`--depth {uds,sa,shellcode}`、`--no-egg-scan`
