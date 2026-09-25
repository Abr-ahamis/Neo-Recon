"""Receive completed worker-command evidence for the main terminal collector."""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
from pathlib import Path

from scr.core.output import collect


class CollectorServer:
    def __init__(self) -> None:
        self.path = Path(tempfile.gettempdir()) / f"neorecon-{os.getpid()}-{id(self):x}.sock"
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.socket.bind(str(self.path))
        os.chmod(self.path, 0o600)
        self.socket.settimeout(.2)
        self.thread = threading.Thread(target=self._serve, name="output-collector", daemon=True)
        self.running = True
        self.thread.start()

    def _serve(self) -> None:
        while self.running:
            try:
                raw = self.socket.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                item = json.loads(raw)
                if item.get("stop"):
                    return
                collect(item["service"], item["argv"], Path(item["output_path"]), force_local=True)
            except (KeyError, TypeError, ValueError, OSError):
                continue

    def close(self) -> None:
        if not self.running:
            return
        stop = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            stop.sendto(b'{"stop":true}', str(self.path))
        except OSError:
            pass
        finally:
            stop.close()
        self.running = False
        self.thread.join(timeout=2)
        self.socket.close()
        self.path.unlink(missing_ok=True)

    def __enter__(self) -> "CollectorServer":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
