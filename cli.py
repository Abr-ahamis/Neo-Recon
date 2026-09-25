"""CLI argument parsing and one-time target input."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from scr.core.context import TargetContext, validate_target
from scr.core.evidence import EvidenceStore
from config import load_settings


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="ctfrecon", description="Authorized CTF/lab reconnaissance")
    parser.add_argument("target", nargs="?", help="one authorized hostname or IP address")
    parser.add_argument("--ports", help="optional RustScan TCP port list, useful for scoped lab checks")
    parser.add_argument("--output-root", type=Path,
                        help="directory for this scan's evidence (defaults to configured scan root)")
    return parser.parse_args(argv)


def get_context(argv: list[str] | None = None) -> TargetContext:
    args = parse_args(argv)
    target = args.target
    if target is None:
        if not sys.stdin.isatty():
            raise ValueError("target is required when stdin is not interactive")
        target = input("Target: ").strip()
    target = validate_target(target)
    settings = load_settings()
    output_root = (args.output_root or settings.scan_root).expanduser().resolve()
    temporary_root = Path("/tmp").resolve()
    if not output_root.is_relative_to(temporary_root):
        raise ValueError("scan output must be stored under /tmp")
    evidence = EvidenceStore.create(output_root, target)
    return TargetContext(target=target, scan_dir=evidence.root,
                         facts={"port_spec": args.ports} if args.ports else {})
