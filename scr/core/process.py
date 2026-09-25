"""Command lifecycle, metadata, timeout and exit-state handling."""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scr.core.evidence import write_json
from scr.core.suggestions import next_commands
from scr.core.pty import run_pty
from scr.core.tasks import Task, TaskState


PROCESS_CANCEL_EVENT = threading.Event()
_SUGGESTION_LOCK = threading.Lock()


def reset_process_cancellation() -> None:
    PROCESS_CANCEL_EVENT.clear()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass(frozen=True)
class ProcessResult:
    exit_code: int
    state: TaskState
    output_path: Path
    metadata_path: Path


class CommandRunner:
    def __init__(self, *, stream_fd: int | None = 1, cwd: Path | None = None) -> None:
        self.stream_fd = stream_fd
        self.cwd = cwd
        self.cancel_event = PROCESS_CANCEL_EVENT

    def run(self, task: Task) -> ProcessResult:
        started = now()
        task.state = TaskState.RUNNING
        task.attempts += 1
        if self.stream_fd is not None and task.show_command:
            command = f"COMMAND: {shlex.join(task.display_argv or task.argv)}\n".encode()
            view = memoryview(command)
            while view:
                view = view[os.write(self.stream_fd, view):]
        error: str | None = None
        try:
            env = None
            if task.collector_socket:
                env = os.environ.copy()
                env["NEO_RECON_COLLECT_SOCKET"] = task.collector_socket
            input_fd = (0 if os.environ.get("NEO_RECON_STREAM_INPUT") == "1"
                        and os.isatty(0) else None)
            exit_code, state = run_pty(task.argv, task.output_path, task.timeout,
                                       cwd=self.cwd, env=env, stream_fd=self.stream_fd,
                                       cancel_event=self.cancel_event, input_fd=input_fd)
            task.state = TaskState(state)
        except KeyboardInterrupt:
            task.state = TaskState.CANCELLED
            exit_code = 130
            error = "interrupted"
            self._metadata(task, started, now(), exit_code, error)
            raise
        except OSError as exc:
            task.state = TaskState.FAILED
            exit_code = 127 if exc.errno == 2 else 1
            error = str(exc)
        ended = now()
        self._metadata(task, started, ended, exit_code, error)
        if self.stream_fd is not None:
            try:
                suggestions = next_commands(task.service, task.target,
                                            task.display_argv or task.argv,
                                            task.output_path.read_bytes()[:1_048_576])
                with _SUGGESTION_LOCK:
                    os.write(self.stream_fd,
                             b"\n----------------------------------------\nNext 5 Commands\n"
                             b"----------------------------------------\n")
                    for index, command in enumerate(suggestions[:5], 1):
                        os.write(self.stream_fd, f"{index}. {command}\n".encode())
                    os.write(self.stream_fd, b"----------------------------------------\n")
            except OSError:
                pass
        return ProcessResult(exit_code, task.state, task.output_path, task.metadata_path)

    def cancel_all(self) -> None:
        self.cancel_event.set()

    @staticmethod
    def _metadata(task: Task, started: str, ended: str, exit_code: int,
                  error: str | None) -> None:
        values: dict[str, Any] = {
            "task_id": task.id, "target": task.target, "service": task.service,
            "argv": task.display_argv or task.argv, "execution_argv": task.argv,
            "command": shlex.join(task.display_argv or task.argv),
            "start_time": started, "end_time": ended, "exit_code": exit_code,
            "state": task.state.value, "output_path": str(task.output_path),
        }
        if error:
            values["error"] = error
        write_json(task.metadata_path, values)
