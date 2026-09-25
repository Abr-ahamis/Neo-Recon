"""Neo-Recon application entry point."""

from __future__ import annotations

import sys

# Avoid leaving root-owned __pycache__ files in the checkout when invoked with sudo.
sys.dont_write_bytecode = True

from cli import get_context
from scr.core.evidence import write_json
from scr.core.orchestrator import run_services
from scr.discovery.pipeline import discover


def main() -> int:
    try:
        context = get_context()
    except (ValueError, EOFError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    try:
        discover(context, port_spec=context.facts.get("port_spec"))
        service_states = run_services(context)
    except KeyboardInterrupt:
        write_json(context.scan_dir / "metadata/scan.json",
                   {"target": context.target, "state": "CANCELLED"})
        return 130
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        write_json(context.scan_dir / "metadata/scan.json",
                   {"target": context.target, "state": "FAILED", "error": str(exc)})
        return 1
    failed = any(state.value != "SUCCESS" for state in service_states.values())
    write_json(context.scan_dir / "metadata/scan.json",
               {"target": context.target, "state": "PARTIAL" if failed else "SUCCESS"})
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
