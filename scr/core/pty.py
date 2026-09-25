"""PTY allocation and byte-for-byte live stream capture."""

from __future__ import annotations

import errno
import os
import pty
import select
import signal
import subprocess
import threading
import termios
import time
from pathlib import Path
from typing import BinaryIO, Callable


def _drain(master: int, sink: BinaryIO, stream_fd: int | None,
           on_chunk: Callable[[bytes], None] | None) -> bool:
    try:
        data = os.read(master, 65536)
    except OSError as exc:
        if exc.errno == errno.EIO:
            return False
        raise
    if not data:
        return False
    sink.write(data)
    if stream_fd is not None:
        view = memoryview(data)
        while view:
            view = view[os.write(stream_fd, view):]
    if on_chunk:
        on_chunk(data)
    return True


def run_pty(argv: list[str], output_path: Path, timeout: float,
            *, cwd: Path | None = None, env: dict[str, str] | None = None,
            stream_fd: int | None = 1, on_chunk: Callable[[bytes], None] | None = None,
            cancel_event: threading.Event | None = None,
            input_fd: int | None = None) -> tuple[int, str]:
    """Run argv on a PTY, forwarding and saving identical master-stream bytes."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    master, slave = pty.openpty()
    # A PTY normally maps each native LF to CRLF. Disable output processing so
    # the bytes captured from the PTY remain the bytes written by the process.
    attributes = termios.tcgetattr(slave)
    attributes[1] &= ~termios.OPOST
    if input_fd is not None:
        attributes[3] &= ~termios.ECHO
    termios.tcsetattr(slave, termios.TCSANOW, attributes)
    proc: subprocess.Popen[bytes] | None = None
    status = "SUCCESS"
    deadline = time.monotonic() + timeout
    kill_at: float | None = None
    killed = False
    with output_path.open("wb", buffering=0) as sink:
        try:
            proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave,
                                    cwd=cwd, env=env, close_fds=True, start_new_session=True)
            os.close(slave)
            slave = -1
            eof = False
            input_open = input_fd is not None
            while not eof or proc.poll() is None:
                now = time.monotonic()
                if status == "SUCCESS" and now >= deadline and (proc.poll() is None or not eof):
                    status = "TIMEOUT"
                    kill_at = now + 0.5
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                if cancel_event and cancel_event.is_set() and status == "SUCCESS":
                    status = "CANCELLED"
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    kill_at = now + 0.5
                if status == "TIMEOUT" and not killed and kill_at is not None and now >= kill_at:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    killed = True
                if status == "CANCELLED" and not killed and kill_at is not None and now >= kill_at:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    killed = True
                readers = [master] + ([input_fd] if input_open and input_fd is not None else [])
                ready = select.select(readers, [], [], 0.1)[0]
                if input_fd is not None and input_fd in ready:
                    incoming = os.read(input_fd, 4096)
                    if incoming:
                        os.write(master, incoming)
                    else:
                        input_open = False
                if master in ready:
                    try:
                        eof = not _drain(master, sink, stream_fd, on_chunk)
                    except OSError as exc:
                        if exc.errno == errno.EIO:
                            eof = True
                        else:
                            raise
                elif proc.poll() is not None:
                    # A PTY can close just after the child exits; select once more to drain it.
                    continue
            exit_code = proc.wait()
            if status == "SUCCESS" and exit_code != 0:
                status = "FAILED"
            if status == "CANCELLED":
                exit_code = 130
            return exit_code, status
        except KeyboardInterrupt:
            status = "CANCELLED"
            if proc is not None and proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.wait(timeout=0.5)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait()
            # Preserve bytes already pending in the PTY after cancellation.
            while select.select([master], [], [], 0.05)[0]:
                try:
                    if not _drain(master, sink, stream_fd, on_chunk):
                        break
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
            raise
        except BaseException:
            if proc is not None and proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
            raise
        finally:
            if slave >= 0:
                os.close(slave)
            os.close(master)
