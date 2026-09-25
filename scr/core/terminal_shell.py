"""Run one Neo-Recon worker, then hand its terminal back to an interactive shell."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys


def run_session(argv: list[str]) -> int:
    if not argv:
        return 64
    try:
        os.environ["NEO_RECON_COLLECT_NATIVE"] = "1"
        os.environ["NEO_RECON_STREAM_INPUT"] = "1"
        result = subprocess.run(argv, check=False)
        code = result.returncode
    except KeyboardInterrupt:
        code = 130
    shell = os.environ.get("SHELL") or shutil.which("bash") or "/bin/sh"
    os.execvpe(shell, [shell, "-i"], os.environ.copy())
    return code


def main() -> int:
    argv = sys.argv[1:]
    if argv[:1] == ["--"]:
        argv = argv[1:]
    return run_session(argv)


if __name__ == "__main__":
    raise SystemExit(main())
