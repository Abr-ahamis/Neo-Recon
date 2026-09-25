"""GUI terminal selection with tmux/current-terminal fallback."""

from __future__ import annotations

import os
import signal
import shlex
import json
import shutil
import subprocess
import sys
import time
import threading
from pathlib import Path
from typing import Any

from scr.core.evidence import write_json
from scr.core.desktop import desktop_session_env
from scr.core.process import CommandRunner
from scr.core.tasks import Task, TaskState
from scr.core.workspace import WorkspaceManager
from config import load_settings


class TerminalManager:
    _launch_lock = threading.RLock()
    _inline_lock = threading.RLock()
    _active_lock = threading.Lock()
    _active: dict[str, tuple[threading.Event, Task | None, TaskState | None]] = {}

    def __init__(self, *, workspace_manager: WorkspaceManager | None = None) -> None:
        self.desktop_env = desktop_session_env()
        self.gui = bool(self.desktop_env.get("DISPLAY") or self.desktop_env.get("WAYLAND_DISPLAY"))
        self.inline_service = os.environ.get("NEO_RECON_SERVICE_WORKER") == "1"
        self.last_external = False
        self.workspaces = workspace_manager or WorkspaceManager(
            limit=load_settings().workspace_window_limit, env=self.desktop_env)

    def command(self, title: str, argv: list[str]) -> list[str] | None:
        title = title if title.startswith("Neo-Recon:") else f"Neo-Recon:{title}"
        worker_command = [sys.executable, "-m", "scr.core.terminal_shell", "--", *argv]
        if self.gui:
            adapters = (
                ("foot", ["foot", "--title", title]),
                ("gnome-terminal", ["gnome-terminal", "--wait", f"--title={title}", "--"]),
                ("kitty", ["kitty", "--title", title, "--"]),
                ("alacritty", ["alacritty", "--title", title, "-e"]),
                ("wezterm", ["wezterm", "start", "--always-new-process", "--title", title, "--"]),
                ("konsole", ["konsole", "--separate", "--title", title, "-e"]),
                ("xfce4-terminal", ["xfce4-terminal", "--disable-server", "--title", title, "--execute"]),
            )
            for executable, prefix in adapters:
                if shutil.which(executable):
                    return prefix + worker_command
        if os.environ.get("TMUX") and shutil.which("tmux"):
            return ["tmux", "new-window", "-d", "-n", title, "-c",
                    str(Path(__file__).resolve().parents[2]), shlex.join(worker_command)]
        if shutil.which("tmux"):
            session = f"neo-recon-{title.lower()}-{os.getpid()}-{time.time_ns()}"
            return ["tmux", "new-session", "-d", "-s", session, "-c",
                    str(Path(__file__).resolve().parents[2]), shlex.join(worker_command)]
        return None

    def launch(self, title: str, argv: list[str],
               env: dict[str, str] | None = None) -> subprocess.Popen[bytes] | None:
        title = title if title.startswith("Neo-Recon:") else f"Neo-Recon:{title}"
        with self._launch_lock, self.workspaces._placement_lock:
            original = None
            workspace = None
            if self.workspaces.enabled:
                try:
                    original = self.workspaces.active_workspace()
                except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
                    original = None
                workspace = self.workspaces.reserve()
                if workspace is not None and not self.workspaces.has_capacity(workspace):
                    self.workspaces.release(workspace)
                    workspace = self.workspaces.reserve()
                    if workspace is not None and not self.workspaces.has_capacity(workspace):
                        self.workspaces.release(workspace)
                        workspace = None
                if workspace is not None and workspace != original and not self.workspaces.switch_to(workspace):
                    self.workspaces.release(workspace)
                    workspace = None
            command = self.command(title, argv)
            if command is None:
                self.workspaces.release(workspace)
                if original is not None and workspace != original:
                    self.workspaces.switch_to(original)
                return None
            try:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           start_new_session=True,
                                           env={**self.desktop_env, **(env or {})},
                                           cwd=Path(__file__).resolve().parents[2])
            except BaseException:
                self.workspaces.release(workspace)
                if original is not None and workspace != original:
                    self.workspaces.switch_to(original)
                raise
            placed = self.workspaces.place_when_visible(title, workspace)
            if placed and self.workspaces.enabled:
                self.workspaces.repair_overflow(title)
            if self.workspaces.enabled and not placed:
                self.workspaces.release(workspace)
            if original is not None and workspace != original:
                self.workspaces.switch_to(original)
            return process

    def execute(self, task: Task, runner: CommandRunner | None = None) -> TaskState:
        key = task.deduplication_key
        with self._active_lock:
            current = self._active.get(key)
            if current is None:
                event = threading.Event()
                self._active[key] = (event, task, None)
                owner = True
            else:
                event, _, _ = current
                owner = False
        if not owner:
            event.wait(task.timeout + 30)
            with self._active_lock:
                _, original, state = self._active.get(key, (event, None, None))
            if original is not None and original.output_path.exists():
                task.output_path.parent.mkdir(parents=True, exist_ok=True)
                if task.output_path != original.output_path:
                    shutil.copyfile(original.output_path, task.output_path)
                task.state = state or original.state
                write_json(task.metadata_path, {
                    "task_id": task.id, "state": task.state.value,
                    "duplicate_of": original.id, "output_path": str(task.output_path),
                    "command": task.display_argv or task.argv,
                })
                return task.state
            return TaskState.SKIPPED
        try:
            if self.inline_service:
                task.terminal_external = os.environ.get("NEO_RECON_COLLECT_NATIVE") == "1"
                with self._inline_lock:
                    return (runner or CommandRunner()).run(task).state
            return self._execute_once(task, runner)
        finally:
            with self._active_lock:
                event, _, _ = self._active.get(key, (threading.Event(), None, None))
                self._active[key] = (event, task, task.state)
                event.set()

    def _execute_once(self, task: Task, runner: CommandRunner | None = None) -> TaskState:
        runner = runner or CommandRunner()
        manifest = task.metadata_path.with_suffix(".task.json")
        pidfile = task.metadata_path.with_suffix(".pid")
        write_json(manifest, {
            "id": task.id, "target": task.target, "service": task.service,
            "argv": task.argv, "display_argv": task.display_argv,
            "output_path": str(task.output_path.resolve()),
            "metadata_path": str(task.metadata_path.resolve()), "timeout": task.timeout,
            "dependencies": task.dependencies, "parent_task": task.parent_task,
            "reason": task.reason,
            "suggested_commands": task.suggested_commands,
            "collector_socket": task.collector_socket,
            "show_command": task.show_command,
        })
        worker = [sys.executable, "-m", "scr.core.worker", str(manifest.resolve())]
        worker_env = os.environ.copy()
        if task.collector_socket:
            worker_env["NEO_RECON_COLLECT_SOCKET"] = task.collector_socket
        try:
            launcher = self.launch(f"{task.service.upper()}-{task.id}", worker, worker_env)
        except OSError:
            launcher = None
        if launcher is None:
            self.last_external = False
            task.terminal_external = False
            result = runner.run(task)
            return result.state
        self.last_external = True
        task.terminal_external = True

        startup_deadline = time.monotonic() + 15
        try:
            while not task.metadata_path.exists():
                if not pidfile.exists() and launcher.poll() not in {None, 0}:
                    self.last_external = False
                    task.terminal_external = False
                    return runner.run(task).state
                if not pidfile.exists() and time.monotonic() >= startup_deadline:
                    if launcher.poll() is None:
                        launcher.terminate()
                    self.last_external = False
                    task.terminal_external = False
                    return runner.run(task).state
                time.sleep(.05)
        except KeyboardInterrupt:
            if pidfile.exists():
                try:
                    os.kill(int(pidfile.read_text()), signal.SIGTERM)
                except (OSError, ValueError):
                    pass
                deadline = time.monotonic() + 3
                while pidfile.exists() and time.monotonic() < deadline:
                    time.sleep(.05)
            if launcher.poll() is None:
                launcher.terminate()
            raise
        metadata: dict[str, Any] = json.loads(task.metadata_path.read_text())
        task.state = TaskState(metadata.get("state", TaskState.FAILED.value))
        return task.state
