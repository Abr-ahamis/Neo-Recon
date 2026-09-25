from __future__ import annotations

import json
import os
import signal
import select
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scr.core.context import TargetContext, target_authority, validate_target
from scr.core.evidence import EvidenceStore
from scr.core.process import CommandRunner
from scr.core.pty import run_pty
from scr.core.tasks import Task, TaskState
from scr.core.terminal import TerminalManager


class ContextTests(unittest.TestCase):
    def test_target_validation(self) -> None:
        self.assertEqual(validate_target("127.0.0.1"), "127.0.0.1")
        self.assertEqual(validate_target("ctf.example.local"), "ctf.example.local")
        for invalid in ("", "-nmap", "foo/bar", "host\nother"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_target(invalid)
        self.assertEqual(target_authority("2001:db8::1", 443), "[2001:db8::1]:443")

    def test_context_keeps_discovered_hostnames_out_of_scope(self) -> None:
        context = TargetContext("ctf.local", Path("scan"))
        context.add_hostname("web.ctf.local")
        self.assertIn("web.ctf.local", context.hostnames)
        self.assertNotIn("web.ctf.local", context.facts.get("in_scope_hostnames", set()))


class ExecutionTests(unittest.TestCase):
    def test_live_pty_bytes_equal_saved_bytes_and_arrive_incrementally(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "native.log"
            read_fd, write_fd = os.pipe()
            result: list[tuple[int, str]] = []
            command = [sys.executable, "-u", "-c",
                       "import time; print('line-1'); time.sleep(.35); print('line-2'); time.sleep(.35); print('line-3')"]
            thread = threading.Thread(target=lambda: result.append(
                run_pty(command, raw, 5, stream_fd=write_fd)))
            started = time.monotonic()
            thread.start()
            captured = bytearray()
            self.assertTrue(select.select([read_fd], [], [], 1)[0])
            captured.extend(os.read(read_fd, 1024))
            self.assertIn(b"line-1", captured)
            self.assertTrue(thread.is_alive())
            while thread.is_alive() or select.select([read_fd], [], [], 0)[0]:
                if select.select([read_fd], [], [], .1)[0]:
                    data = os.read(read_fd, 1024)
                    if not data:
                        break
                    captured.extend(data)
                elif not thread.is_alive():
                    break
            thread.join(2)
            os.close(read_fd)
            os.close(write_fd)
            self.assertFalse(thread.is_alive())
            self.assertEqual(result, [(0, "SUCCESS")])
            self.assertEqual(bytes(captured), raw.read_bytes())
            self.assertLess(time.monotonic() - started, 1.2)
            self.assertIn(b"line-3", captured)

    def test_pty_forwards_terminal_input_to_interactive_worker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            read_fd, write_fd = os.pipe()
            threading.Timer(.1, lambda: (os.write(write_fd, b"continue\n"), os.close(write_fd))).start()
            output = Path(directory) / "interactive.raw"
            result = run_pty([sys.executable, "-u", "-c",
                              "import sys; print('ready', flush=True); print('got:' + sys.stdin.readline().strip())"],
                             output, 3, stream_fd=None, input_fd=read_fd)
            os.close(read_fd)
            self.assertEqual(result, (0, "SUCCESS"))
            self.assertIn(b"got:continue", output.read_bytes())

    def test_timeout_and_cancel_preserve_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "timeout.log"
            code = "import time; print('before-timeout', flush=True); time.sleep(5)"
            code_result = run_pty([sys.executable, "-u", "-c", code], raw, .15, stream_fd=None)
            self.assertEqual(code_result[1], "TIMEOUT")
            self.assertIn(b"before-timeout", raw.read_bytes())

            cancel = threading.Event()
            threading.Timer(.15, cancel.set).start()
            cancel_result = run_pty([sys.executable, "-u", "-c", code],
                                    root / "cancel.log", 5, stream_fd=None,
                                    cancel_event=cancel)
            self.assertEqual(cancel_result, (130, "CANCELLED"))
            self.assertIn(b"before-timeout", (root / "cancel.log").read_bytes())

    @unittest.skipUnless(Path("/proc").exists(), "process-tree assertion requires Linux /proc")
    def test_keyboard_interrupt_cleans_child_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child_pid_file = root / "child.pid"
            code = ("import subprocess,sys,time; "
                    f"p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
                    f"open({str(child_pid_file)!r},'w').write(str(p.pid)); "
                    "print('child-started',flush=True); time.sleep(30)")
            timer = threading.Timer(.4, lambda: os.kill(os.getpid(), signal.SIGINT))
            timer.start()
            try:
                with self.assertRaises(KeyboardInterrupt):
                    run_pty([sys.executable, "-u", "-c", code], root / "interrupt.log", 10,
                            stream_fd=None)
            finally:
                timer.cancel()
            self.assertIn(b"child-started", (root / "interrupt.log").read_bytes())
            child_pid = int(child_pid_file.read_text())
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                stat = Path(f"/proc/{child_pid}/stat")
                if not stat.exists() or stat.read_text().split()[2] == "Z":
                    break
                time.sleep(.05)
            else:
                self.fail(f"child process {child_pid} remained running after Ctrl-C")

    def test_metadata_records_command_exit_state_and_raw_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = Task("bad", "127.0.0.1", "test", [sys.executable, "-c", "print('x'); raise SystemExit(7)"],
                        root / "x.log", root / "x.json", timeout=3)
            result = CommandRunner(stream_fd=None).run(task)
            metadata = json.loads(result.metadata_path.read_text())
            self.assertEqual(result.exit_code, 7)
            self.assertEqual(task.state, TaskState.FAILED)
            self.assertEqual(metadata["exit_code"], 7)
            self.assertIn(b"x", result.output_path.read_bytes())

    def test_evidence_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = EvidenceStore.create(Path(directory), "ctf.example")
            for subdirectory in ("discovery", "nmap", "services", "commands", "findings", "metadata"):
                self.assertTrue((store.root / subdirectory).is_dir())

    def test_duplicate_active_command_runs_once_and_reuses_raw_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"NEO_RECON_SERVICE_WORKER": "1"}):
            root = Path(directory)
            manager = TerminalManager()
            started = threading.Event()
            calls = []

            class Runner:
                def run(self, task):
                    calls.append(task.id)
                    started.set()
                    time.sleep(.15)
                    task.output_path.parent.mkdir(parents=True, exist_ok=True)
                    task.output_path.write_bytes(b"native result\n")
                    task.state = TaskState.SUCCESS
                    return SimpleNamespace(state=TaskState.SUCCESS)

            first = Task("first", "127.0.0.1", "http", ["curl", "http://127.0.0.1/"],
                         root / "first.raw", root / "first.json", resource_id="http://127.0.0.1/",
                         display_argv=["curl", "http://127.0.0.1/"])
            second = Task("second", "127.0.0.1", "http", ["curl", "http://127.0.0.1/"],
                          root / "second.raw", root / "second.json", resource_id="http://127.0.0.1/",
                          display_argv=["curl", "http://127.0.0.1/"])
            first_result = []
            thread = threading.Thread(target=lambda: first_result.append(manager.execute(first, Runner())))
            thread.start()
            self.assertTrue(started.wait(1))
            second_result = manager.execute(second, Runner())
            thread.join(1)
            self.assertFalse(thread.is_alive())
            self.assertEqual(calls, ["first"])
            self.assertEqual(first_result, [TaskState.SUCCESS])
            self.assertEqual(second_result, TaskState.SUCCESS)
            self.assertEqual(second.output_path.read_bytes(), b"native result\n")


if __name__ == "__main__":
    unittest.main()
