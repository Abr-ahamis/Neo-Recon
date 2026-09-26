"""Internal entry point launched inside an isolated worker terminal."""

from __future__ import annotations

import json
import os
import re
import signal
import sys
from pathlib import Path

from scr.core.process import CommandRunner
from scr.core.tasks import Task


def _cancel(signum: int, frame: object) -> None:
    raise KeyboardInterrupt


_NO_RESULT = re.compile(
    rb"(?:connection refused|no route to host|connection timed out|"
    rb"authentication required|successful bind must be completed|insufficient access rights|"
    rb"permission denied|access denied|nt_status_access_denied|"
    rb"nt_status_resource_name_not_found|"
    rb"not accessible|not found|no such file|no shares available|no entries|"
    rb"0 hosts? up|no open ports|0 open ports|no ports found|"
    rb"failed to connect|could not connect|service unavailable)", re.I
)
_POSITIVE_RESULT = re.compile(
    rb"(?:\bOpen\s+[0-9a-fA-F:.]+:\d{1,5}\b|\b\d{1,5}/(?:tcp|udp)\s+open\b|"
    rb"discovered open port|anonymous login successful|HTTP/\d(?:\.\d)?\s+2\d\d|"
    rb"\b230\s|NT_STATUS_SUCCESS)", re.I
)


def _useful_output(path: Path, service: str | None = None) -> bool:
    try:
        with path.open("rb") as stream:
            output = stream.read(1_048_576)
    except OSError:
        return False
    meaningful = [line.strip() for line in output.splitlines() if line.strip()]
    if not meaningful:
        return False
    if service == "rustscan" and not _POSITIVE_RESULT.search(output):
        return False
    if _NO_RESULT.search(output) and not _POSITIVE_RESULT.search(output):
        return False
    # Close terminals whose complete result is an expected empty/access failure.
    if len(meaningful) <= 4 and all(_NO_RESULT.search(line) for line in meaningful):
        return False
    return True


def run(manifest_path: Path) -> int:
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    metadata_path = Path(data["metadata_path"])
    pidfile = metadata_path.with_suffix(".pid")
    signal.signal(signal.SIGTERM, _cancel)
    signal.signal(signal.SIGINT, _cancel)
    task = Task(data["id"], data["target"], data["service"], data["argv"],
                Path(data["output_path"]), metadata_path, data["timeout"],
                data.get("dependencies", []), data.get("parent_task"), data.get("reason", ""),
                display_argv=data.get("display_argv"))
    task.collector_socket = data.get("collector_socket")
    task.show_command = data.get("show_command", True)
    task.new_terminal = data.get("new_terminal", False)
    pidfile.write_text(str(os.getpid()), encoding="ascii")
    result_code = 1
    try:
        result = CommandRunner().run(task)
        result_code = result.exit_code
    except KeyboardInterrupt:
        result_code = 130
    finally:
        pidfile.unlink(missing_ok=True)
    suggestions = data.get("suggested_commands", [])
    if suggestions:
        os.write(1, b"\nSuggested commands (copy and run):\n")
        for command in suggestions:
            os.write(1, f"  {command}\n".encode("utf-8", errors="replace"))
    return result_code


if __name__ == "__main__":
    raise SystemExit(run(Path(sys.argv[1])))
