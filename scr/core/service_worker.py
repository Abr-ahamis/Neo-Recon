"""Execute one complete service module inside its dedicated terminal worker."""

from __future__ import annotations

import json
import os
import signal
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from scr.core.context import TargetContext
from scr.core.evidence import write_json
from scr.core.orchestrator import _module_for
from scr.core.resources import TraversalLimits
from scr.core.suggestions import service_suggestions


def _cancel(signum: int, frame: object) -> None:
    raise KeyboardInterrupt


def _json_value(value: Any) -> Any:
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def run(path: Path) -> int:
    data = json.loads(path.read_text(encoding="utf-8"))
    context = TargetContext(
        target=data["target"], scan_dir=Path(data["scan_dir"]),
        hostnames=set(data.get("hostnames", [])), domains=set(data.get("domains", [])),
        services=data.get("services", []), tcp_ports=data.get("tcp_ports", []),
        udp_ports=data.get("udp_ports", []), credentials=data.get("credentials", []),
        facts=data.get("facts", {}),
    )
    limits = TraversalLimits(**data["limits"])
    os.environ["NEO_RECON_SERVICE_WORKER"] = "1"
    module = _module_for(data["service"], context, int(data["port"]),
                         data.get("transport", "tcp"), limits)
    if module is None:
        return 64
    signal.signal(signal.SIGINT, _cancel)
    signal.signal(signal.SIGTERM, _cancel)
    state, result = "SUCCESS", None
    try:
        result = module.run()
    except KeyboardInterrupt:
        state = "CANCELLED"
    except Exception as exc:
        state = "FAILED"
        result = {"error": str(exc)}
    suggestions = service_suggestions(data["service"], context, int(data["port"]))
    if suggestions:
        os.write(1, b"\nSuggested commands (copy and run):\n")
        for command in suggestions:
            os.write(1, f"  {command}\n".encode("utf-8", errors="replace"))
    write_json(Path(data["result_path"]), {
        "state": state, "service": data["service"], "port": data["port"],
        "result": _json_value(result), "hostnames": sorted(context.hostnames),
        "domains": sorted(context.domains), "facts": _json_value(context.facts),
        "resources": _json_value(context.resources),
    })
    return 130 if state == "CANCELLED" else 1 if state == "FAILED" else 0


if __name__ == "__main__":
    raise SystemExit(run(Path(sys.argv[1])))
