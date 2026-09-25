"""Application settings loaded from the project's TOML configuration."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Settings:
    scan_root: Path = Path("scr/scans")
    max_workers: int = 8
    command_timeout: float = 900.0
    retries: int = 0
    max_depth: int = 12
    max_tasks: int = 5000
    max_files: int = 10000
    max_directories: int = 2000
    max_download_size: int = 10 * 1024 * 1024
    install_missing_dependencies: bool = False


def load_settings(path: Path | None = None) -> Settings:
    path = path or Path(__file__).parent / "scr/config/default.toml"
    if not path.exists():
        return Settings()
    with path.open("rb") as stream:
        raw: dict[str, Any] = tomllib.load(stream)
    scan = raw.get("scan", {})
    limits = raw.get("limits", {})
    dependencies = raw.get("dependencies", {})
    return Settings(
        scan_root=Path(scan.get("root", "scr/scans")),
        max_workers=int(scan.get("max_workers", 8)),
        command_timeout=float(scan.get("command_timeout", 900)),
        retries=int(scan.get("retries", 0)),
        max_depth=int(limits.get("max_depth", 12)),
        max_tasks=int(limits.get("max_tasks", 5000)),
        max_files=int(limits.get("max_files", 10000)),
        max_directories=int(limits.get("max_directories", 2000)),
        max_download_size=int(limits.get("max_download_size", 10485760)),
        install_missing_dependencies=bool(dependencies.get("install_missing", False)),
    )
