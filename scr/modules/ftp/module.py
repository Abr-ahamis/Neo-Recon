"""Anonymous FTP namespace traversal and bounded file probes."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from urllib.parse import quote

from scr.core.context import TargetContext, target_authority
from scr.core.evidence import write_json
from scr.core.output import collect
from scr.core.process import CommandRunner
from scr.core.resources import Access, Resource, ResourceStatus, TraversalLimits
from scr.core.tasks import Task, TaskState
from scr.core.terminal import TerminalManager
from scr.engine.traversal import ResourceTraversal
from scr.modules.ftp import commands, parser, rules


class FTPModule:
    service = "ftp"

    def __init__(self, context: TargetContext, *, port: int = 21,
                 limits: TraversalLimits | None = None,
                 runner: CommandRunner | None = None,
                 terminals: TerminalManager | None = None,
                 execute: Callable[[Task], TaskState] | None = None) -> None:
        self.context, self.port = context, port
        self.base = f"ftp://{target_authority(context.target, port)}/"
        self.limits = limits or TraversalLimits()
        self.runner = runner or CommandRunner()
        self.terminals = terminals or TerminalManager()
        self.execute_task = execute
        self.traversal = ResourceTraversal(self.limits)

    def _task(self, path: str, probe_file: bool = False) -> Task:
        url = self.base + quote(path.strip("/"), safe="/!$&'()*+,;=:@-._~%")
        if not probe_file and not path:
            url = self.base
        if not probe_file:
            url = url.rstrip("/") + "/"
            native = commands.list_path(url)
        else:
            native = commands.file_probe(url, self.limits.max_download_size)
        key = hashlib.sha256((("file:" if probe_file else "list:") + path).encode()).hexdigest()[:16]
        task = Task(f"ftp-{key}", self.context.target, "ftp", native[0],
                    self.context.scan_dir / "services/ftp" / f"{key}.raw",
                    self.context.scan_dir / "metadata" / f"ftp-{key}.json",
                    timeout=30, reason="FTP resource enumeration", display_argv=native[1],
                    resource_id=path)
        return task

    def _execute(self, task: Task) -> tuple[TaskState, bytes]:
        state = self.execute_task(task) if self.execute_task else self.terminals.execute(task, self.runner)
        if not self.execute_task and task.terminal_external and task.output_path.exists():
            collect("FTP", task.display_argv or task.argv, task.output_path)
        raw = task.output_path.read_bytes() if task.output_path.exists() else b""
        return state, raw

    def _enumerate(self, resource: Resource) -> list[Resource]:
        if resource.resource_type == "file":
            size = resource.metadata.get("size")
            if size is None or size > self.limits.max_download_size:
                resource.metadata["inspection"] = "metadata-only"
                resource.status = ResourceStatus.SUCCESS
                return []
            task = self._task(resource.path, probe_file=True)
            state, raw = self._execute(task)
            result = parser.access(raw, 0 if state == TaskState.SUCCESS else 1)
            resource.read_access = Access.YES if state == TaskState.SUCCESS else result["read_access"]
            resource.authentication_required = result["authentication_required"]
            resource.metadata["permission_state"] = "READ" if state == TaskState.SUCCESS else result["permission_state"]
            resource.status = ResourceStatus.SUCCESS if state == TaskState.SUCCESS else ResourceStatus.INACCESSIBLE
            return []
        task = self._task(resource.path)
        state, raw = self._execute(task)
        result = parser.access(raw, 0 if state == TaskState.SUCCESS else 1)
        resource.list_access = result["list_access"]
        resource.read_access = result["read_access"]
        resource.authentication_required = result["authentication_required"]
        resource.authenticated_identity = "anonymous"
        resource.metadata["permission_state"] = result["permission_state"]
        if state != TaskState.SUCCESS:
            resource.status = ResourceStatus.INACCESSIBLE
            # Unknown extensionless entries can still be files. Avoid fetching
            # them; a failed child listing remains a bounded probe result.
            return []
        return rules.resources_from_listing(resource, parser.listing(raw))

    def run(self) -> list[dict]:
        root = Resource("ftp", self.context.target, self.port, "tcp", "directory",
                        "/", path="", authenticated_identity="anonymous",
                        metadata={"authentication_method": "anonymous"})
        self.traversal.traverse([root], self._enumerate)
        values = [item.to_dict() for item in self.traversal.resources.values()]
        self.context.resources.update({item["resource_id"]: item for item in values})
        write_json(self.context.scan_dir / "metadata/ftp-resources.json", values)
        return values
