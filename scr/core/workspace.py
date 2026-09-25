"""Hyprland placement for visible Neo-Recon worker terminals."""

from __future__ import annotations

import json
import shutil
import subprocess
import threading
import time
from collections import defaultdict
from typing import Callable

from scr.core.desktop import desktop_session_env


class WorkspaceManager:
    _reservation_lock = threading.Lock()
    _placement_lock = threading.RLock()
    _global_reservations: dict[int, int] = defaultdict(int)

    def __init__(self, *, limit: int = 5,
                 run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
                 executable: str = "hyprctl", enabled: bool | None = None,
                 env: dict[str, str] | None = None) -> None:
        self.limit = limit
        self.run = run
        self.env = desktop_session_env() if env is None else env
        self.executable = executable
        self.enabled = shutil.which(executable) is not None if enabled is None else enabled

    def _json(self, command: str) -> object:
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
            candidate = active
            while counts.get(candidate, 0) + self._global_reservations[candidate] >= self.limit:
                candidate += 1
            self._global_reservations[candidate] += 1
            return candidate

    def switch_to(self, workspace: int) -> bool:
        if not self.enabled:
            return False
        try:
            result = self.run([self.executable, "dispatch", "workspace", str(workspace)],
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
            candidate = workspace + 1
            with self._reservation_lock:
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
            result = self.run([self.executable, "dispatch", "movetoworkspace",
                               f"{workspace},address:{address}"], capture_output=True,
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
                                str(client.get("title", "")) == title and client.get("address")):
                            return self.place(title, str(client["address"]), workspace)
                time.sleep(.05)
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError,
                subprocess.SubprocessError):
            return False
        return False
