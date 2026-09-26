"""Recover the invoking desktop session environment for elevated runs."""

from __future__ import annotations

import os
import pwd
from pathlib import Path


def desktop_session_env(base: dict[str, str] | None = None,
                        runtime_root: Path = Path("/run/user")) -> dict[str, str]:
    env = dict(os.environ if base is None else base)
    if os.geteuid() != 0 or not env.get("SUDO_UID"):
        return env
    try:
        user_id = int(env["SUDO_UID"])
        runtime = runtime_root / str(user_id)
        account = pwd.getpwuid(user_id)
    except (ValueError, KeyError, OSError):
        return env
    if not runtime.is_dir():
        return env
    env.setdefault("XDG_RUNTIME_DIR", str(runtime))
    env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={runtime}/bus")
    if not env.get("XAUTHORITY") and (Path(account.pw_dir) / ".Xauthority").is_file():
        env["XAUTHORITY"] = str(Path(account.pw_dir) / ".Xauthority")
    if not env.get("WAYLAND_DISPLAY"):
        socket = next(iter(sorted(runtime.glob("wayland-*"))), None)
        if socket:
            env["WAYLAND_DISPLAY"] = socket.name
    hyprland = runtime / "hypr"
    if not env.get("HYPRLAND_INSTANCE_SIGNATURE") and hyprland.is_dir():
        sessions = [path for path in hyprland.iterdir()
                    if path.is_dir() and (path / ".socket.sock").exists()]
        if sessions:
            sessions.sort(key=lambda path: path.stat().st_mtime, reverse=True)
            env["HYPRLAND_INSTANCE_SIGNATURE"] = sessions[0].name
    if not env.get("SWAYSOCK"):
        sway_sockets = sorted(runtime.glob("sway-ipc.*.sock"),
                              key=lambda path: path.stat().st_mtime, reverse=True)
        if sway_sockets:
            env["SWAYSOCK"] = str(sway_sockets[0])
    return env
