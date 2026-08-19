"""RH850 EPS probe composition entry point.

Thin wrapper over ``eps_probe.cli``: parses the CLI flags, wires a real
``EcuTransport`` factory, loads the Task-6 shellcode binary and hands control
to ``cli.run``. Exit code 0 on success, 2 on any error (``ERROR: ...`` on
stderr, mirroring the FW-PATCH ``main()`` pattern).
"""

import sys
from pathlib import Path

from eps_probe import cli
from eps_probe.transport import EcuTransport

SHELLCODE_PATH = Path("shellcode/build/deep_probe.bin")


def main(argv=None) -> int:
    args = cli.build_parser().parse_args(argv)
    try:
        payload = cli.load_shellcode(SHELLCODE_PATH)
        cli.run(
            args,
            transport_factory=lambda: EcuTransport(serial=args.serial, addr=args.addr),
            payload_bytes=payload,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
