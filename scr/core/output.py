"""Minimal completed-output collector; raw bytes are passed through unchanged."""

from __future__ import annotations

import os
import shlex
import json
import socket
import threading
from pathlib import Path

_COLLECT_LOCK = threading.Lock()
_NEEDS_SEPARATOR_NEWLINE = False
MAX_MAIN_REPORT_LINES = 300


def _write_all(stream_fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(stream_fd, view)
        if written <= 0:
            raise OSError("terminal stream closed while collecting output")
        view = view[written:]


def _within_main_report_limit(path: Path) -> bool:
    lines = 0
    has_data = False
    last_byte = b""
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            has_data = True
            lines += chunk.count(b"\n")
            last_byte = chunk[-1:]
            if lines > MAX_MAIN_REPORT_LINES:
                return False
    if has_data and last_byte != b"\n":
        lines += 1
    return lines <= MAX_MAIN_REPORT_LINES


def collect(service: str, argv: list[str], output_path: Path, stream_fd: int = 1,
            *, force_local: bool = False) -> None:
    global _NEEDS_SEPARATOR_NEWLINE
    collector_socket = os.environ.get("NEO_RECON_COLLECT_SOCKET")
    if collector_socket and not force_local:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            client.sendto(json.dumps({"service": service, "argv": argv,
                                     "output_path": str(output_path)}).encode(),
                         collector_socket)
            return
        except OSError:
            return
        finally:
            client.close()
    if not _within_main_report_limit(output_path):
        return
    header = ("\033[34m" + "-" * 79 + f"\n{service.upper()}\nCOMMAND: {shlex.join(argv)}\n" +
              "-" * 79 + "\033[0m\n").encode()
    with _COLLECT_LOCK:
        if _NEEDS_SEPARATOR_NEWLINE:
            _write_all(stream_fd, b"\n")
        _write_all(stream_fd, header)
        with output_path.open("rb") as stream:
            while chunk := stream.read(65536):
                view = memoryview(chunk)
                while view:
                    written = os.write(stream_fd, view)
                    if written <= 0:
                        raise OSError("terminal stream closed while collecting output")
                    view = view[written:]
        size = output_path.stat().st_size
        if size:
            with output_path.open("rb") as stream:
                stream.seek(size - 1)
                _NEEDS_SEPARATOR_NEWLINE = stream.read(1) != b"\n"
        else:
            _NEEDS_SEPARATOR_NEWLINE = False
