"""Protocol-neutral resource and access model for adaptive enumeration."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Access(StrEnum):
    UNKNOWN = "UNKNOWN"
    YES = "YES"
    NO = "NO"


class ResourceStatus(StrEnum):
    DISCOVERED = "DISCOVERED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    INACCESSIBLE = "INACCESSIBLE"
    SKIPPED = "SKIPPED"


@dataclass
class Resource:
    service: str
    target: str
    port: int | None
    protocol: str
    resource_type: str
    name: str
    path: str = ""
    parent: str | None = None
    depth: int = 0
    list_access: Access = Access.UNKNOWN
    read_access: Access = Access.UNKNOWN
    write_access: Access = Access.UNKNOWN
    authentication_required: bool | None = None
    authenticated_identity: str | None = None
    status: ResourceStatus = ResourceStatus.DISCOVERED
    metadata: dict[str, Any] = field(default_factory=dict)
    resource_id: str = ""

    def __post_init__(self) -> None:
        if not self.service or not self.target or not self.resource_type:
            raise ValueError("resource service, target, and type are required")
        if not self.resource_id:
            parts = (self.target, self.service.lower(), str(self.port or ""),
                     self.protocol.lower(), self.resource_type.lower(), self.path or self.name)
            self.resource_id = json.dumps(parts, ensure_ascii=False, separators=(",", ":"))

    @property
    def can_list(self) -> bool:
        return self.list_access == Access.YES

    @property
    def can_read(self) -> bool:
        return self.read_access == Access.YES

    @property
    def can_write(self) -> bool:
        return self.write_access == Access.YES

    @property
    def probe_blocked(self) -> bool:
        return (self.authentication_required is True and not self.authenticated_identity) or (
            self.list_access == Access.NO and self.read_access == Access.NO
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id, "service": self.service, "target": self.target,
            "port": self.port, "protocol": self.protocol, "parent": self.parent,
            "depth": self.depth, "name": self.name, "path": self.path,
            "resource_type": self.resource_type, "list_access": self.list_access.value,
            "read_access": self.read_access.value, "write_access": self.write_access.value,
            "authentication_required": self.authentication_required,
            "authenticated_identity": self.authenticated_identity,
            "status": self.status.value, "metadata": self.metadata,
        }


@dataclass(frozen=True)
class TraversalLimits:
    max_depth: int = 12
    max_tasks: int = 5000
    max_files: int = 10000
    max_directories: int = 2000
    max_download_size: int = 10 * 1024 * 1024
    max_workers: int = 8

    def __post_init__(self) -> None:
        if min(self.max_depth, self.max_tasks, self.max_files,
               self.max_directories, self.max_download_size, self.max_workers) < 1:
            raise ValueError("resource limits must be positive")
