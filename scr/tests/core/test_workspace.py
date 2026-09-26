from __future__ import annotations

import json
import subprocess
import unittest

from scr.core.workspace import WorkspaceManager
from scr.core.desktop import desktop_session_env
from pathlib import Path
import tempfile
from unittest.mock import patch


class WorkspaceManagerTests(unittest.TestCase):
    def test_preferred_workspaces_are_limited_to_configured_ids(self) -> None:
        clients: list[dict] = []

        def fake_run(argv, **kwargs):
            output = json.dumps({"id": 1} if argv[2] == "activeworkspace" else clients)
            return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")

        manager = WorkspaceManager(run=fake_run, enabled=True,
                                   preferred_workspaces=(7, 8, 9), env={})
        chosen = []
        for index in range(6):
            workspace = manager.reserve()
            chosen.append(workspace)
            clients.append({"title": f"terminal-{index}", "workspace": {"id": workspace}})
            manager.release(workspace)
        self.assertEqual(chosen, [7, 8, 9, 7, 8, 9])

    def test_sway_tree_normalizes_visible_terminal_nodes(self) -> None:
        tree = {"type": "root", "nodes": [{"type": "workspace", "num": 8,
                "nodes": [{"type": "con", "id": 321, "name": "Neo-Recon:ffuf",
                           "nodes": [], "floating_nodes": []}]}]}
        clients = WorkspaceManager._sway_clients(tree)
        self.assertEqual(clients[0]["title"], "Neo-Recon:ffuf")
        self.assertEqual(clients[0]["workspace"]["id"], 8)
        self.assertEqual(clients[0]["con_id"], 321)

    def test_sway_backend_uses_swaymsg_ipc(self) -> None:
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            if argv[1:3] == ["-t", "get_workspaces"]:
                output = json.dumps([{"num": 8, "focused": True}])
            else:
                output = "{}"
            return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")

        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "sway.conf"
            config.write_text('set $ws7 "7: "\nset $ws8 "8: "\nset $ws9 "9: "\n')
            with patch("scr.core.workspace.shutil.which", return_value="/usr/bin/swaymsg"):
                manager = WorkspaceManager(run=fake_run, enabled=True,
                                           preferred_workspaces=(7, 8, 9),
                                           env={"SWAYSOCK": "/tmp/sway-ipc.sock",
                                                "SWAY_CONFIG": str(config)})
            self.assertEqual(manager.active_workspace(), 8)
            self.assertTrue(manager.switch_to(9))
            self.assertTrue(manager.place("terminal", "321", 9))
        self.assertEqual(calls[0][0], "swaymsg")
        self.assertEqual(calls[1], ["swaymsg", 'workspace "9: "'])
        self.assertEqual(calls[2], ["swaymsg", '[con_id=321] move container to workspace "9: "'])

    def test_terminal_adapter_prefers_foot(self) -> None:
        with patch("scr.core.terminal.desktop_session_env",
                   return_value={"DISPLAY": ":1"}), \
             patch("scr.core.terminal.shutil.which",
                   side_effect=lambda name: "/usr/bin/" + name
                   if name in {"foot", "gnome-terminal"} else None):
            from scr.core.terminal import TerminalManager
            manager = TerminalManager(workspace_manager=WorkspaceManager(enabled=False, env={}))
            command = manager.command("test", ["true"])
        self.assertIsNotNone(command)
        self.assertEqual(command[0], "foot")

    def test_elevated_process_recovers_callers_hyprland_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime_root = Path(directory)
            runtime = runtime_root / "1000"
            session = runtime / "hypr" / "test-signature"
            session.mkdir(parents=True)
            (session / ".socket.sock").touch()
            (runtime / "wayland-2").touch()
            with patch("scr.core.desktop.os.geteuid", return_value=0):
                env = desktop_session_env({"SUDO_UID": "1000"}, runtime_root)
            self.assertEqual(env["XDG_RUNTIME_DIR"], str(runtime))
            self.assertEqual(env["WAYLAND_DISPLAY"], "wayland-2")
            self.assertEqual(env["HYPRLAND_INSTANCE_SIGNATURE"], "test-signature")

    def test_worker_windows_distribute_in_groups_of_four(self) -> None:
        current = 1
        clients: list[dict] = []

        def fake_run(argv, **kwargs):
            if argv[2] == "activeworkspace":
                output = json.dumps({"id": current})
            else:
                output = json.dumps(clients)
            return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")

        manager = WorkspaceManager(run=fake_run, enabled=True, env={})
        placed: list[int] = []
        for index in range(15):
            workspace = manager.reserve()
            placed.append(workspace)
            clients.append({"title": f"Neo-Recon:worker-{index}", "workspace": {"id": workspace}})
            manager.release(workspace)
        self.assertEqual(placed[:4], [1] * 4)
        self.assertEqual(placed[4:8], [2] * 4)
        self.assertEqual(placed[8:12], [3] * 4)
        self.assertEqual(placed[12:], [4] * 3)

    def test_independent_service_managers_share_pending_reservations(self) -> None:
        current = 1
        clients: list[dict] = []

        def fake_run(argv, **kwargs):
            output = json.dumps({"id": current} if argv[2] == "activeworkspace" else clients)
            return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")

        selected = []
        for index in range(6):
            manager = WorkspaceManager(run=fake_run, enabled=True, env={})
            workspace = manager.reserve()
            selected.append(workspace)
            clients.append({"title": f"Neo-Recon:parallel-{index}",
                            "workspace": {"id": workspace}})
            manager.release(workspace)
        self.assertEqual(selected, [1, 1, 1, 1, 2, 2])

    def test_all_existing_app_windows_consume_the_five_window_limit(self) -> None:
        clients = [{"title": f"Browser {i}", "workspace": {"id": 1}}
                   for i in range(4)]

        def fake_run(argv, **kwargs):
            output = json.dumps({"id": 1} if argv[2] == "activeworkspace" else clients)
            return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")

        manager = WorkspaceManager(run=fake_run, enabled=True, env={})
        workspaces = []
        for index in range(3):
            workspace = manager.reserve()
            workspaces.append(workspace)
            clients.append({"title": f"Neo-Recon:worker-{index}",
                            "workspace": {"id": workspace}, "mapped": True})
            manager.release(workspace)
        self.assertEqual(workspaces, [2, 2, 2])

    def test_unmapped_and_hidden_windows_do_not_consume_visible_slots(self) -> None:
        clients = ([{"title": "hidden", "workspace": {"id": 1}, "hidden": True}]
                   + [{"title": "unmapped", "workspace": {"id": 1}, "mapped": False}]
                   + [{"title": f"Visible {i}", "workspace": {"id": 1}, "mapped": True}
                      for i in range(4)])

        def fake_run(argv, **kwargs):
            output = json.dumps({"id": 1} if argv[2] == "activeworkspace" else clients)
            return subprocess.CompletedProcess(argv, 0, stdout=output, stderr="")

        manager = WorkspaceManager(run=fake_run, enabled=True, env={})
        workspace = manager.reserve()
        self.assertEqual(workspace, 2)
        manager.release(workspace)


if __name__ == "__main__":
    unittest.main()
