"""Ensure a native executable is present before a service runner starts it."""

from __future__ import annotations

import sys

from config import load_settings
from scr.dependencies.manager import DependencyManager


def main(argv: list[str] | None = None) -> int:
    executables = list(argv if argv is not None else sys.argv[1:])
    if not executables:
        print("usage: python3 -m scr.dependencies.bootstrap EXECUTABLE [...]", file=sys.stderr)
        return 64
    settings = load_settings()
    result = DependencyManager(
        install_missing=settings.install_missing_dependencies
    ).ensure(tuple(executables))
    if result.missing:
        print("Missing required executable(s): " + ", ".join(result.missing), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
