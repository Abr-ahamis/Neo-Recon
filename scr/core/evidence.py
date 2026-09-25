"""Evidence directory and atomic command-metadata storage."""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")[:100] or "target"


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@dataclass(frozen=True)
class EvidenceStore:
    root: Path

    @classmethod
    def create(cls, base: Path, target: str) -> "EvidenceStore":
        root = base / safe_name(target) / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        for name in ("discovery", "nmap", "services", "commands", "findings", "metadata"):
            (root / name).mkdir(parents=True, exist_ok=True)
        write_json(root / "metadata/scan.json", {"target": target, "state": "RUNNING"})
        return cls(root)
