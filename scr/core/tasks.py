"""Task model and lifecycle state."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import json
from pathlib import Path


class TaskState(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    SKIPPED = "SKIPPED"
    CANCELLED = "CANCELLED"


@dataclass
class Task:
    id: str
    target: str
    service: str
    argv: list[str]
    output_path: Path
    metadata_path: Path
    timeout: float = 900
    dependencies: list[str] = field(default_factory=list)
    parent_task: str | None = None
    reason: str = ""
    resource_id: str | None = None
    parent_resource_id: str | None = None
    depth: int = 0
    display_argv: list[str] | None = None
    terminal_external: bool = False
    max_retries: int = 0
    state: TaskState = TaskState.QUEUED
    attempts: int = 0
    suggested_commands: list[str] = field(default_factory=list)
    collector_socket: str | None = None
    show_command: bool = True

    def __post_init__(self) -> None:
        if not self.id or not self.argv or not self.argv[0]:
            raise ValueError("task id and executable argv are required")
        if self.timeout <= 0 or self.max_retries < 0:
            raise ValueError("timeout must be positive and retries non-negative")

    @property
    def deduplication_key(self) -> str:
        identity = json.dumps([self.target, self.service.lower(), self.resource_id,
                               self.display_argv or self.argv], ensure_ascii=False,
                              separators=(",", ":"))
        return hashlib.sha256(identity.encode()).hexdigest()
