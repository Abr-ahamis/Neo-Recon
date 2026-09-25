from __future__ import annotations

import os
import json
import pty
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from scr.core.output import collect
from scr.core.collector import CollectorServer
from scr.core.worker import _useful_output
from scr.core.terminal_shell import run_session
from scr.core.terminal import TerminalManager
import threading


class OutputTests(unittest.TestCase):
    def test_web_report_uses_two_hundred_line_limit(self) -> None:
        raw = b"web line\n" * 201
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "web.raw"
            output.write_bytes(raw)
            read_fd, write_fd = os.pipe()
            try:
                collect("HTTP", ["curl", "http://example.test"], output, write_fd)
                os.close(write_fd)
                write_fd = -1
                rendered = os.read(read_fd, 4096)
            finally:
                os.close(read_fd)
                if write_fd >= 0:
                    os.close(write_fd)
            self.assertIn(b"Output exceeded 200 lines", rendered)
            self.assertIn(str(output.resolve()).encode(), rendered)
            self.assertNotIn(b"web line", rendered)
            self.assertEqual(output.read_bytes(), raw)

    def test_large_raw_output_is_saved_but_omitted_from_main_report(self) -> None:
        raw = (b"native line\n" * 251) + b"tail"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "native.raw"
            output.write_bytes(raw)
            read_fd, write_fd = os.pipe()
            try:
                collect("curl", ["curl", "http://example.test"], output, write_fd)
                os.close(write_fd)
                write_fd = -1
                rendered = os.read(read_fd, 4096)
            finally:
                os.close(read_fd)
                if write_fd >= 0:
                    os.close(write_fd)
            self.assertIn(b"Output exceeded 250 lines", rendered)
            self.assertIn(str(output.resolve()).encode(), rendered)
            self.assertNotIn(b"native line", rendered)
            self.assertEqual(output.read_bytes(), raw)

    def test_output_at_main_report_limit_is_displayed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "native.raw"
            raw = b"line\n" * 250
            output.write_bytes(raw)
            read_fd, write_fd = os.pipe()
            try:
                collect("curl", ["curl", "http://example.test"], output, write_fd)
                os.close(write_fd)
                write_fd = -1
                rendered = bytearray()
                while chunk := os.read(read_fd, 4096):
                    rendered.extend(chunk)
            finally:
                os.close(read_fd)
                if write_fd >= 0:
                    os.close(write_fd)
            self.assertTrue(rendered.endswith(raw))

    def test_gui_terminal_prefers_foot_then_gnome_terminal(self) -> None:
        manager = TerminalManager()
        manager.gui = True
        with patch("scr.core.terminal.shutil.which",
                   side_effect=lambda name: f"/usr/bin/{name}" if name in {"foot", "gnome-terminal"} else None):
            self.assertEqual(manager.command("HTTP", ["worker"])[0], "foot")
        with patch("scr.core.terminal.shutil.which",
                   side_effect=lambda name: f"/usr/bin/{name}" if name == "gnome-terminal" else None):
            self.assertEqual(manager.command("HTTP", ["worker"])[0], "gnome-terminal")

    def test_workspace_query_failure_does_not_disable_gui_terminal_launch(self) -> None:
        class UnavailableWorkspace:
            enabled = True
            _placement_lock = threading.RLock()

            def active_workspace(self):
                raise RuntimeError("no Hyprland socket in current environment")

            def reserve(self):
                return None

            def release(self, _workspace):
                pass

            def place_when_visible(self, _title, _workspace):
                return False

        manager = TerminalManager(workspace_manager=UnavailableWorkspace())
        with patch.object(manager, "command", return_value=["fake-terminal"]), \
             patch("scr.core.terminal.subprocess.Popen") as popen:
            manager.launch("HTTP", ["worker"])
        popen.assert_called_once()

    def test_collector_colors_only_generated_header(self) -> None:
        raw = b"\x1b[32mNative warning\x1b[0m\r\nexact bytes\x00"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "native.raw"
            output.write_bytes(raw)
            read_fd, write_fd = os.pipe()
            try:
                collect("nmap", ["nmap", "-p80", "target"], output, write_fd)
                os.close(write_fd)
                write_fd = -1
                rendered = bytearray()
                while chunk := os.read(read_fd, 4096):
                    rendered.extend(chunk)
            finally:
                os.close(read_fd)
                if write_fd >= 0:
                    os.close(write_fd)
            self.assertIn(b"\x1b[34m", rendered)
            self.assertTrue(rendered.endswith(raw))

    def test_service_output_is_sent_to_main_collector_without_local_headers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / "native.raw"
            raw.write_bytes(b"native tool result\n")
            received = []
            with CollectorServer() as server, \
                 patch.dict(os.environ, {"NEO_RECON_COLLECT_SOCKET": str(server.path)}), \
                 patch("scr.core.collector.collect",
                       side_effect=lambda service, argv, path, force_local=False:
                       received.append((service, argv, Path(path).read_bytes(), force_local))):
                collect("SMB", ["smbclient", "//target/share"], raw)
                deadline = time.monotonic() + 2
                while not received and time.monotonic() < deadline:
                    time.sleep(.01)
            self.assertEqual(received, [("SMB", ["smbclient", "//target/share"],
                                         b"native tool result\n", True)])

    def test_useful_terminal_lifecycle_classification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result"
            output.write_bytes(b"")
            self.assertFalse(_useful_output(output))
            output.write_bytes(b"Connection refused\r\n")
            self.assertFalse(_useful_output(output))
            output.write_bytes(b"Warning: native banner\r\nConnection refused\r\n")
            self.assertFalse(_useful_output(output))
            output.write_bytes(b"RustScan banner\r\nOpen 10.0.0.1:445\r\nConnection refused\r\n")
            self.assertTrue(_useful_output(output))
            output.write_bytes(b"RustScan banner\r\nNmap done: 1 IP address scanned\r\n")
            self.assertFalse(_useful_output(output, "rustscan"))
            output.write_bytes(b"Operations error: a successful bind must be completed on the connection\n")
            self.assertFalse(_useful_output(output, "ldap"))

    def test_worker_exits_after_log_and_metadata_complete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = root / "metadata.json"
            raw = root / "native.raw"
            manifest = root / "task.json"
            manifest.write_text(json.dumps({
                "id": "worker-test", "target": "127.0.0.1", "service": "test",
                "argv": [sys.executable, "-u", "-c", "print('native result')"],
                "display_argv": [sys.executable, "-u", "-c", "print('native result')"],
                "output_path": str(raw), "metadata_path": str(metadata),
                "timeout": 5, "keep_terminal": True,
            }))
            worker = subprocess.Popen([sys.executable, "-m", "scr.core.worker", str(manifest)],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pidfile = metadata.with_suffix(".pid")
            deadline = time.monotonic() + 3
            while not metadata.exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(metadata.exists())
            self.assertEqual(json.loads(metadata.read_text())["state"], "SUCCESS")
            self.assertEqual(raw.read_bytes(), b"native result\n")
            self.assertFalse(pidfile.exists())
            self.assertEqual(worker.wait(timeout=2), 0)

    def test_worker_exits_for_an_empty_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata, raw, manifest = root / "metadata.json", root / "native.raw", root / "task.json"
            manifest.write_text(json.dumps({
                "id": "empty-test", "target": "127.0.0.1", "service": "test",
                "argv": [sys.executable, "-c", "pass"],
                "output_path": str(raw), "metadata_path": str(metadata),
                "timeout": 5, "keep_terminal": True,
            }))
            result = subprocess.run([sys.executable, "-m", "scr.core.worker", str(manifest)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     timeout=3, check=False)
            self.assertEqual(result.returncode, 0)
            self.assertTrue(metadata.exists())
            self.assertEqual(raw.read_bytes(), b"")

    def test_terminal_hands_successful_worker_back_to_interactive_shell(self) -> None:
        with patch.dict(os.environ, {"SHELL": "/bin/bash"}), \
             patch("scr.core.terminal_shell.subprocess.run", return_value=subprocess.CompletedProcess([], 0)), \
             patch("scr.core.terminal_shell.os.execvpe", side_effect=SystemExit(0)) as execute_shell:
            with self.assertRaises(SystemExit):
                run_session(["worker"])
        self.assertEqual(execute_shell.call_args.args[1], ["/bin/bash", "-i"])

    def test_ctrl_c_also_returns_terminal_to_interactive_shell(self) -> None:
        with patch.dict(os.environ, {"SHELL": "/bin/bash"}), \
             patch("scr.core.terminal_shell.subprocess.run", side_effect=KeyboardInterrupt), \
             patch("scr.core.terminal_shell.os.execvpe", side_effect=SystemExit(0)) as execute_shell:
            with self.assertRaises(SystemExit):
                run_session(["worker"])
        self.assertEqual(execute_shell.call_args.args[1], ["/bin/bash", "-i"])

    @unittest.skipUnless(Path("/bin/sh").exists(), "requires a local POSIX shell")
    def test_terminal_accepts_commands_after_worker_finishes(self) -> None:
        master, slave = pty.openpty()
        env = os.environ.copy()
        env["SHELL"] = "/bin/sh"
        process = subprocess.Popen(
            [sys.executable, "-m", "scr.core.terminal_shell", "--",
             sys.executable, "-c", "print('worker-finished')"],
            stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True,
            cwd=Path(__file__).resolve().parents[3])
        os.close(slave)
        captured = bytearray()
        sent = False
        deadline = time.monotonic() + 5
        try:
            while time.monotonic() < deadline and process.poll() is None:
                if select.select([master], [], [], .1)[0]:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:
                        break
                    captured.extend(chunk)
                    if b"worker-finished" in captured and not sent:
                        time.sleep(.1)
                        os.write(master, b"printf 'interactive-ready\\n'\nexit\n")
                        sent = True
            process.wait(timeout=1)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=2)
            os.close(master)
        self.assertTrue(sent, captured.decode(errors="replace"))
        self.assertIn(b"interactive-ready", captured)


if __name__ == "__main__":
    unittest.main()
