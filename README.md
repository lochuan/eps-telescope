# RH850 EPS Probe

[English](#english) · [中文](#中文)

# English

A read-only probe for Toyota EPS ECUs built on the RH850/P1M-E. It maps what the steering ECU exposes over UDS, checks Security Access, reads a deep firmware fingerprint, and identifies the vehicle. It never writes flash.

## What it collects

The probe runs in three layers. Each layer runs if the one before it succeeds, and a failure degrades to the layers that already ran.

1. **UDS surface.** For each diagnostic session, it lists which UDS services respond, which data identifiers exist, and whether RequestDownload accepts the RAM or flash ranges.
2. **Security Access.** It requests a seed, derives the key with the known algorithm, and reports the NRC if the ECU rejects it.
3. **Deep firmware fingerprint.** It uploads a small read-only shellcode to RAM, then reads MCU registers, the patch-point context, the boot-integrity CRC word, and scans for the patch signature (the "egg"). It also probes the engine ECU and other ECUs to identify the platform and read the VIN.

The probe answers two questions for a vehicle you have not seen before:

- Does the patch point exist where FW-PATCH expects it? The egg scan finds the signature `E0 D1 9A 0D 1A 38 BF FF`. If a hit sits at `0x8E6C6`, the patch byte at `0x8E6C7` matches FW-PATCH's location. If the hit is elsewhere, the patch point is relocated.
- Is this firmware the verified variant? The 64-byte window around the patch point is compared byte-for-byte against the verified firmware. `MATCH` means identical, `PATCHED` means the vehicle is already patched, `MISMATCH` means a different variant.

## What it does not do

- No flash writes, no FACI erase/program commands, no P/E mode entry.
- No SecOC key extraction.
- Nothing that changes the ECU. The shellcode reads memory and streams it back over CAN.

## Requirements

- A comma device (openpilot) or any machine with `panda`, `opendbc`, `pycryptodome`, and `tqdm` installed for Python 3.12.
- A Panda connected to the vehicle's CAN bus.
- The built shellcode at `shellcode/build/deep_probe.bin`. The repo ships it; rebuild only with the v850 toolchain (see below).
- Openpilot stopped. The probe aborts if `boardd` or `pandad` is running, because it needs exclusive access to the Panda.

## Setup

On comma, install the Python deps:

```bash
python3.12 -c 'import panda; import opendbc.car.uds; from Crypto.Cipher import AES'
```

Stop openpilot:

```bash
tmux kill-session -t comma
pidof pandad      # must print nothing
```

Sync the repository to comma, then run it there. The probe needs the `shellcode/build/deep_probe.bin` file, so keep the `shellcode/` directory with the code.

## Usage

```bash
python3.12 probe.py                          # full probe at 0x7A1
python3.12 probe.py --addr 0x7A1             # target another diagnostic address
python3.12 probe.py --serial <panda-serial>  # pick a Panda when several exist
python3.12 probe.py --depth uds              # UDS surface only
python3.12 probe.py --depth sa               # UDS surface + Security Access
python3.12 probe.py --no-egg-scan            # skip the flash-wide egg scan
python3.12 probe.py --no-fingerprint         # skip the other-ECU platform probe
python3.12 probe.py --artifacts-dir /data/probe   # change the output root
```

The default `--depth shellcode` runs all three layers. `--depth uds` never touches Security Access. If Security Access fails, the probe writes a UDS-level report and stops. If the shellcode file is missing, Layer 3 is skipped with a note.

## Output

The probe prints a markdown report to the terminal and writes it under `artifacts/<timestamp>/`:

```text
artifacts/
└── 20260819T215500Z/
    ├── probe.json   # all raw data, machine-readable
    └── probe.md     # the same report the terminal shows
```

The report has five sections:

- **Metadata.** Target address, Panda serial, application and boot firmware IDs.
- **Layer 1 UDS enumeration.** Sessions probed, DIDs read, routines, RequestDownload acceptance.
- **Vehicle fingerprint.** The engine ECU's identification-block sweep, each other ECU's software number, and the VIN.
- **Layer 2 Security Access.** Whether the handshake passed and the NRC if it failed.
- **Layer 3 deep probe.** MCU registers, fingerprint status, the CRC adjust word, and the egg results. It says explicitly whether the egg exists and whether its address matches FW-PATCH.
- **Next steps.** One guidance line per classification.

### Classifications

| Classification | Meaning |
|---|---|
| `verified_variant` | Patch-point window matches the verified firmware byte-for-byte. Plan the patch against FW-PATCH's addresses. |
| `already_patched` | Window matches except the patch byte, which is its patched value. The vehicle is already patched; do not patch again. |
| `egg_variant` | Egg at `0x8E6C6` but the context differs, or the egg sits elsewhere. Compare the new window offline. |
| `no_egg` | No egg signature in the scan range. The patch point differs; a full dump and RE are needed to relocate it. |
| `sa_blocked` | Security Access failed. Collect seed/key pairs to reverse-engineer the 0x27 algorithm. |
| `envelope_blocked` | The 0x10F0 envelope authentication failed. Extract this variant's PayloadBuildSecret. |
| `probe_incomplete` | Deep-probe data was incomplete. Retry or fall back to `--depth uds`. |

Read `probe.json` for the details behind the classification. The fingerprint window bytes, the egg candidate addresses with their `at_expected` flags, the DCRA range, and the adjust-word state are all there.

## Safety notes

- The probe is read-only by design. It does not enter flash P/E mode, does not issue FACI commands, and never writes to `0xFFA2xxxx` or the flash-write-enable registers.
- The UDS session ladder switches the ECU to programming session during Layer 1. That is non-destructive, but the probe leaves the ECU in that session; power-cycle the vehicle when you finish.
- Stop openpilot before running. The probe fails closed if `boardd` or `pandad` is alive.

## Rebuilding the shellcode

The probe ships a built `shellcode/build/deep_probe.bin`. Rebuild only when you change `shellcode/deep_probe.c`:

```bash
docker run --rm \
  -v "$PWD/shellcode:/src" -w /src \
  gcc-v850-elf-master:latest sh build.sh
```

`build.sh` enforces the 4048-byte shellcode limit and writes `deep_probe.bin` and `manifest.json`. The `--no-fingerprint` and `--no-egg-scan` flags let you shorten a run, but they narrow the report.

# 中文

## 这是什么

针对丰田 EPS（RH850/P1M-E）的只读探测工具。它摸清转向 ECU 的 UDS 暴露面、检查 Security Access、读取深度固件指纹，并识别整车平台。它从不写 flash。

## 采集什么

探测分三层。每一层在前一层成功后运行，失败则降级到已完成的层。

1. **UDS 暴露面**。在每个诊断会话里，列出哪些 UDS 服务有响应、哪些 DID 可读、RequestDownload 是否接受 RAM 或 flash 范围。
2. **Security Access**。请求种子，用已知算法推导密钥，若 ECU 拒绝则记录 NRC。
3. **深度固件指纹**。向 RAM 上传一个小的只读 shellcode，读取 MCU 寄存器、patch 点上下文、boot-integrity CRC 字，并全 flash 扫描 patch 签名（"egg"）。同时探测引擎 ECU 和其他 ECU，识别平台并读取 VIN。

对一辆没见过的车，它回答两个问题：

- **patch 点是否在 FW-PATCH 期望的位置？** egg 扫描找签名 `E0 D1 9A 0D 1A 38 BF FF`。命中在 `0x8E6C6`，则 `0x8E6C7` 的 patch 字节与 FW-PATCH 位置一致；命中在别处，patch 点已重定位。
- **固件是否与已验证变体一致？** patch 点周围 64 字节窗口与已验证固件逐字节比对。`MATCH` 表示一致，`PATCHED` 表示已 patch，`MISMATCH` 表示不同变体。

## 不做什么

- 不写 flash，不发 FACI 擦除/编程命令，不进入 P/E 模式。
- 不提取 SecOC 密钥。
- 不改 ECU 状态。shellcode 只读内存并经 CAN 回传。

## 要求

- comma 设备（openpilot），或任何装了 `panda`、`opendbc`、`pycryptodome`、`tqdm` 且 Python 3.12 的机器。
- 接到车辆 CAN 总线的 Panda。
- 构建好的 shellcode `shellcode/build/deep_probe.bin`。仓库自带；只有改 `shellcode/deep_probe.c` 才需要重建。
- openpilot 已停止。探测脚本检测到 `boardd` 或 `pandad` 运行会中止，因为需要独占 Panda。

## 部署

在 comma 上装依赖：

```bash
python3.12 -c 'import panda; import opendbc.car.uds; from Crypto.Cipher import AES'
```

停止 openpilot：

```bash
tmux kill-session -t comma
pidof pandad      # 必须无输出
```

把仓库同步到 comma 后运行。探测需要 `shellcode/build/deep_probe.bin`，所以 `shellcode/` 目录要一起带过去。

## 用法

```bash
python3.12 probe.py                          # 默认 0x7A1 全深度
python3.12 probe.py --addr 0x7A1             # 指定诊断地址
python3.12 probe.py --serial <panda-serial>  # 多 Panda 时指定
python3.12 probe.py --depth uds              # 只做 UDS 暴露面
python3.12 probe.py --depth sa               # UDS + Security Access
python3.12 probe.py --no-egg-scan            # 跳过全 flash egg 扫描
python3.12 probe.py --no-fingerprint         # 跳过其他 ECU 平台探测
python3.12 probe.py --artifacts-dir /data/probe   # 换输出目录
```

默认 `--depth shellcode` 跑全部三层。`--depth uds` 不碰 Security Access。Security Access 失败时写 UDS 级报告并停止。shellcode 文件缺失时跳过 Layer 3 并提示。

## 输出

终端打印 markdown 报告，同时写入 `artifacts/<时间戳>/`：

```text
artifacts/
└── 20260819T215500Z/
    ├── probe.json   # 全部原始数据，机器可读
    └── probe.md     # 与终端相同的报告
```

报告分五节：

- **元信息**。目标地址、Panda serial、app 与 boot 固件 ID。
- **Layer 1 UDS 枚举**。探测的会话、可读 DID、例程、RequestDownload 接受性。
- **车辆指纹**。引擎 ECU 识别块扫描、各 ECU 软件号、VIN。
- **Layer 2 Security Access**。握手是否通过，失败时的 NRC。
- **Layer 3 深探**。MCU 寄存器、指纹状态、CRC 调整字、egg 结果。明确写出 egg 是否存在、地址是否与 FW-PATCH 一致。
- **下一步**。每个分类对应一条指引。

### 分类

| 分类 | 含义 |
|---|---|
| `verified_variant` | patch 点窗口与已验证固件逐字节一致，可按 FW-PATCH 地址规划 patch。 |
| `already_patched` | 窗口除 patch 字节外一致，且该字节是 patch 后的值。车已 patch，勿重复操作。 |
| `egg_variant` | egg 在 `0x8E6C6` 但上下文不同，或 egg 在别处。需离线对照新窗口。 |
| `no_egg` | 扫描范围内无 egg 签名。patch 点不同，需要完整 dump + RE 重定位。 |
| `sa_blocked` | Security Access 失败。采集 seed/key 对逆向 0x27 算法。 |
| `envelope_blocked` | 信封 0x10F0 鉴权失败。需提取该变体 PayloadBuildSecret。 |
| `probe_incomplete` | 深探数据不完整。重试或退回 `--depth uds`。 |

分类背后的细节都在 `probe.json`：指纹窗口字节、egg 候选地址及其 `at_expected` 标志、DCRA 范围、调整字状态。

## 安全说明

- 探测按设计只读。不进入 flash P/E 模式，不发 FACI 命令，不写 `0xFFA2xxxx` 或 flash 写使能寄存器。
- Layer 1 的会话梯子会把 ECU 切到 programming 会话。这不破坏数据，但探测后 ECU 停留在此会话，结束后请给车辆断电。
- 运行前停止 openpilot。`boardd` 或 `pandad` 存活时脚本 fail closed。

## 重建 shellcode

仓库自带 `shellcode/build/deep_probe.bin`。只有改 `shellcode/deep_probe.c` 才重建：

```bash
docker run --rm \
  -v "$PWD/shellcode:/src" -w /src \
  gcc-v850-elf-master:latest sh build.sh
```

`build.sh` 强制 4048 字节上限，写 `deep_probe.bin` 和 `manifest.json`。`--no-fingerprint` 和 `--no-egg-scan` 可以缩短运行，但会缩小报告内容。
