"""SSH host-key discovery and explicitly authorized identity enumeration."""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from scr.core.context import TargetContext
from scr.core.evidence import write_json
from scr.core.output import collect
from scr.core.process import CommandRunner
from scr.core.tasks import Task, TaskState
from scr.core.terminal import TerminalManager
from scr.modules.ssh import commands, parser, rules


class SSHModule:
    service = "ssh"

    def __init__(self, context: TargetContext, *, port: int = 22,
                 runner: CommandRunner | None = None,
                 terminals: TerminalManager | None = None,
                 execute: Callable[[Task], TaskState] | None = None) -> None:
        self.context, self.port = context, port
        self.runner = runner or CommandRunner()
        self.terminals = terminals or TerminalManager()
        self.execute_task = execute

    def _run(self, label: str, native: tuple[list[str], list[str]]) -> tuple[TaskState, bytes]:
        actual, display = native
        key = hashlib.sha256((label + str(self.port)).encode()).hexdigest()[:12]
        task = Task(f"ssh-{label}-{key}", self.context.target, "ssh", actual,
                    self.context.scan_dir / "services/ssh" / f"{label}-{key}.raw",
                    self.context.scan_dir / "metadata" / f"ssh-{label}-{key}.json",
                    timeout=30, reason=f"SSH {label}", display_argv=display)
        state = self.execute_task(task) if self.execute_task else self.terminals.execute(task, self.runner)
        if not self.execute_task and task.terminal_external and task.output_path.exists():
            collect("SSH", display, task.output_path)
        raw = task.output_path.read_bytes() if task.output_path.exists() else b""
        return state, raw

    def run(self) -> dict:
        scan_state, key_output = self._run("hostkeys", commands.keyscan(self.context.target, self.port))
        result: dict = {"port": self.port, "host_keys": parser.host_keys(key_output),
                        "authentication_methods": [], "authenticated": False,
                        "identity": None, "state": scan_state.value}
        auth_result, auth_output = self._run("auth-methods", commands.auth_methods(
            self.context.target, self.port))
        methods = parser.auth_state(auth_output, 0 if auth_result == TaskState.SUCCESS else 1)
        result["authentication_methods"] = methods["authentication_methods"]
        result["authentication_state"] = methods["permission_state"]
        credential = next((c for c in self.context.credentials
                           if rules.authorized_key(c, self.context.target)), None)
        if credential:
            state, raw = self._run("identity", commands.authorized_session(
                self.context.target, self.port, credential["username"], credential["private_key"]))
            result.update(parser.auth_state(raw, 0 if state == TaskState.SUCCESS else 1))
            result["state"] = state.value
            if result.get("authenticated"):
                self.context.facts.setdefault("identities", {})["ssh"] = result["identity"]
        self.context.facts.setdefault("ssh", {})[str(self.port)] = result
        write_json(self.context.scan_dir / "metadata/ssh.json", result)
        return result
