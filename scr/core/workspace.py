"""Place worker terminals in configured workspaces under Hyprland or Sway."""

from __future__ import annotations

import json
import pwd
import re
import shutil
import subprocess
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Callable

from scr.core.desktop import desktop_session_env


class WorkspaceManager:
    _reservation_lock = threading.Lock()
    _placement_lock = threading.RLock()
    _global_reservations: dict[int, int] = defaultdict(int)

    def __init__(self, *, limit: int = 4, preferred_workspaces: tuple[int, ...] = (),
                 run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
                 executable: str = "hyprctl", enabled: bool | None = None,
                 env: dict[str, str] | None = None) -> None:
        self.limit = limit
        self.run = run
        self.env = desktop_session_env() if env is None else env
        self.executable = executable
        self.preferred_workspaces = tuple(dict.fromkeys(int(x) for x in preferred_workspaces if int(x) > 0))
        sway = bool(self.env.get("SWAYSOCK") and shutil.which("swaymsg"))
        self.backend = "sway" if sway else "hyprland"
        self.executable = "swaymsg" if sway else executable
        self.enabled = (sway or shutil.which(executable) is not None) if enabled is None else enabled
        self.sway_workspace_names = self._read_sway_workspace_names() if sway else {}

    def _read_sway_workspace_names(self) -> dict[int, str]:
        config_path = self.env.get("SWAY_CONFIG")
        if config_path:
            candidates = [Path(config_path).expanduser()]
        else:
            home = Path.home()
            if self.env.get("SUDO_UID"):
                try:
                    home = Path(pwd.getpwuid(int(self.env["SUDO_UID"])).pw_dir)
                except (KeyError, ValueError):
                    pass
            config_home = Path(self.env.get("XDG_CONFIG_HOME", home / ".config"))
            candidates = [config_home / "sway/config", home / ".config/sway/config"]
        for path in candidates:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            names = {}
            for match in re.finditer(r'^\s*set\s+\$ws(\d+)\s+["\']([^"\']+)["\']',
                                     text, re.MULTILINE):
                names[int(match.group(1))] = match.group(2)
            if names:
                return names
        return {}

    def _sway_tree(self) -> object:
        result = self.run([self.executable, "-t", "get_tree", "-r"], capture_output=True,
                          text=True, check=False, timeout=3, env=self.env)
        if result.returncode:
            raise RuntimeError(result.stderr or "swaymsg get_tree failed")
        return json.loads(result.stdout)

    @staticmethod
    def _sway_clients(tree: object) -> list[dict]:
        clients: list[dict] = []

        def visit(node: object, workspace: int = 0) -> None:
            if not isinstance(node, dict):
                return
            if node.get("type") == "workspace":
                try:
                    workspace = int(node.get("num") or str(node.get("name", "")).split(":", 1)[0])
                except (TypeError, ValueError):
                    workspace = 0
            if node.get("type") == "con" and not node.get("nodes") and not node.get("floating_nodes"):
                props = node.get("window_properties") or {}
                clients.append({"title": node.get("name") or props.get("title") or "",
                                "workspace": {"id": workspace}, "address": node.get("id"),
                                "con_id": node.get("id"), "mapped": not node.get("scratchpad_state")})
            for key in ("nodes", "floating_nodes"):
                children = node.get(key, [])
                if isinstance(children, list):
                    for child in children:
                        visit(child, workspace)

        visit(tree)
        return clients

    def _json(self, command: str) -> object:
        if self.backend == "sway":
            if command == "clients":
                return self._sway_clients(self._sway_tree())
            if command == "activeworkspace":
                result = self.run([self.executable, "-t", "get_workspaces", "-r"],
                                  capture_output=True, text=True, check=False, timeout=3,
                                  env=self.env)
                if result.returncode:
                    raise RuntimeError(result.stderr or "swaymsg get_workspaces failed")
                active = next((item for item in json.loads(result.stdout)
                               if isinstance(item, dict) and item.get("focused")), None)
                if active is None:
                    raise RuntimeError("Sway focused workspace was not found")
                return {"id": active.get("num") or active.get("name")}
        result = self.run([self.executable, "-j", command], capture_output=True,
                          text=True, check=False, timeout=2, env=self.env)
        if result.returncode:
            raise RuntimeError(result.stderr or f"hyprctl {command} failed")
        return json.loads(result.stdout)

    def active_workspace(self) -> int:
        active = self._json("activeworkspace")
        if not isinstance(active, dict) or "id" not in active:
            raise RuntimeError("Hyprland active workspace response is invalid")
        return int(active["id"])

    def window_counts(self) -> dict[int, int]:
        clients = self._json("clients")
        counts: dict[int, int] = defaultdict(int)
        if not isinstance(clients, list):
            return counts
        for client in clients:
            if not isinstance(client, dict):
                continue
            if client.get("mapped") is False or client.get("hidden") is True:
                continue
            workspace = client.get("workspace")
            if isinstance(workspace, dict) and "id" in workspace and int(workspace["id"]) > 0:
                counts[int(workspace["id"])] += 1
        return counts

    def worker_counts(self) -> dict[int, int]:
        """Compatibility alias; capacity now includes every visible app window."""
        return self.window_counts()

    def reserve(self) -> int | None:
        if not self.enabled:
            return None
        with self._reservation_lock:
            try:
                active = self.active_workspace()
                counts = self.window_counts()
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError,
                    subprocess.SubprocessError):
                return None
            if self.preferred_workspaces:
                available = [item for item in self.preferred_workspaces
                             if counts.get(item, 0) + self._global_reservations[item] < self.limit]
                choices = available or list(self.preferred_workspaces)
                candidate = min(choices,
                               key=lambda item: (counts.get(item, 0) + self._global_reservations[item],
                                                 self.preferred_workspaces.index(item)))
            else:
                candidate = active
                while counts.get(candidate, 0) + self._global_reservations[candidate] >= self.limit:
                    candidate += 1
            self._global_reservations[candidate] += 1
            return candidate

    def switch_to(self, workspace: int) -> bool:
        if not self.enabled:
            return False
        try:
            name = self.sway_workspace_names.get(workspace)
            command = ([self.executable, f'workspace "{name}"'] if name else
                       [self.executable, f"workspace number {workspace}"]
                       if self.backend == "sway" else
                       [self.executable, "dispatch", "workspace", str(workspace)])
            result = self.run(command,
                              capture_output=True, text=True, check=False, timeout=2,
                              env=self.env)
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def has_capacity(self, workspace: int) -> bool:
        try:
            return self.window_counts().get(workspace, 0) < self.limit
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError,
                subprocess.SubprocessError):
            return False

    def repair_overflow(self, title: str) -> bool:
        """Move the new worker if an unrelated app opened during launch."""
        try:
            clients = self._json("clients")
            if not isinstance(clients, list):
                return False
            counts = self.window_counts()
            target = next((item for item in clients if isinstance(item, dict)
                           and item.get("title") == title and item.get("address")), None)
            if target is None:
                return False
            workspace_data = target.get("workspace", {})
            workspace = int(workspace_data.get("id", 0))
            if counts.get(workspace, 0) <= self.limit:
                return True
            if self.preferred_workspaces:
                candidate = min(self.preferred_workspaces,
                                key=lambda item: (counts.get(item, 0),
                                                  self.preferred_workspaces.index(item)))
            else:
                candidate = workspace + 1
            with self._reservation_lock:
                if not self.preferred_workspaces:
                    while counts.get(candidate, 0) + self._global_reservations[candidate] >= self.limit:
                        candidate += 1
                self._global_reservations[candidate] += 1
            try:
                return self.place(title, str(target["address"]), candidate)
            finally:
                self.release(candidate)
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError,
                subprocess.SubprocessError):
            return False

    def release(self, workspace: int | None) -> None:
        if workspace is None:
            return
        with self._reservation_lock:
            if self._global_reservations.get(workspace, 0) > 0:
                self._global_reservations[workspace] -= 1

    def place(self, title: str, address: str, workspace: int | None) -> bool:
        if workspace is None or not self.enabled:
            return False
        try:
            if self.backend == "sway":
                name = self.sway_workspace_names.get(workspace)
                destination = f'"{name}"' if name else f"number {workspace}"
                command = [self.executable,
                           f"[con_id={address}] move container to workspace {destination}"]
            else:
                command = [self.executable, "dispatch", "movetoworkspace",
                           f"{workspace},address:{address}"]
            result = self.run(command, capture_output=True,
                              text=True, check=False, timeout=2, env=self.env)
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def place_when_visible(self, title: str, workspace: int | None,
                           *, timeout: float = 3.0) -> bool:
        if workspace is None or not self.enabled:
            return False
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                clients = self._json("clients")
                if isinstance(clients, list):
                    for client in clients:
                        if (isinstance(client, dict) and
                                (str(client.get("title", "")) == title or
                                 str(client.get("name", "")) == title)
                                and (client.get("address") or client.get("con_id"))):
                            address = client.get("address") or client.get("con_id")
                            return self.place(title, str(address), workspace)
                time.sleep(.05)
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError,
                subprocess.SubprocessError):
            return False
        return False
