#!/bin/sh
set -eu

tool_prefix=${TOOL_PREFIX:-v850-elf-}
build_dir=build
shellcode_limit=4048
mkdir -p "$build_dir"

"${tool_prefix}gcc" -Os -fPIC -ffreestanding -fno-builtin -fno-stack-protector \
  -fno-tree-loop-distribute-patterns -mno-prolog-function \
  -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
  -c deep_probe.c -o "$build_dir/deep_probe.o"
"${tool_prefix}ld" -T linker.ld "$build_dir/deep_probe.o" -o "$build_dir/deep_probe.elf"
"${tool_prefix}objcopy" -O binary -j .text.entry -j .text -j .rodata \
  "$build_dir/deep_probe.elf" "$build_dir/deep_probe.bin"
"${tool_prefix}objdump" -d "$build_dir/deep_probe.elf" > "$build_dir/deep_probe.dis"

size=$(wc -c < "$build_dir/deep_probe.bin" | tr -d ' ')
if [ "$size" -ge "$shellcode_limit" ]; then
  echo "deep_probe payload is $size bytes; limit is $shellcode_limit" >&2
  rm -f "$build_dir/deep_probe.bin"
  exit 1
fi

gcc_version=$("${tool_prefix}gcc" -dumpfullversion)
binutils_version=$("${tool_prefix}objcopy" --version | sed -n '1s/.* //p')
sha256_file() { sha256sum "$1" | cut -d ' ' -f 1; }

printf '{\n  "toolchain": {"gcc": "%s", "binutils": "%s"},\n  "payload": {\n' \
  "$gcc_version" "$binutils_version" > "$build_dir/manifest.json"
printf '    "deep_probe": {"size": %s, "sha256": "%s"}\n' \
  "$size" "$(sha256_file "$build_dir/deep_probe.bin")" >> "$build_dir/manifest.json"
printf '  }\n}\n' >> "$build_dir/manifest.json"
