"""Adaptive SMB share and directory enumeration."""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
import re
from collections.abc import Callable
from typing import Any

from scr.core.context import TargetContext
from scr.core.evidence import write_json
from scr.core.output import collect
from scr.core.process import CommandRunner
from scr.core.resources import Access, Resource, ResourceStatus, TraversalLimits
from scr.core.tasks import Task, TaskState
from scr.core.terminal import TerminalManager
from scr.engine.traversal import ResourceTraversal
from scr.modules.smb import commands, parser, rules


class SMBModule:
    service = "smb"

    def __init__(self, context: TargetContext, *, limits: TraversalLimits | None = None,
                 port: int = 445, runner: CommandRunner | None = None,
                 terminals: TerminalManager | None = None,
                 execute: Callable[[Task], TaskState] | None = None) -> None:
        self.context = context
        self.port = port
        self.limits = limits or TraversalLimits()
        self.runner = runner or CommandRunner()
        self.terminals = terminals or TerminalManager()
        self.execute_task = execute or self._execute
        self.auth_file: Path | None = None
        self.identity: str | None = None
        self.traversal = ResourceTraversal(self.limits)

    def _credential_file(self) -> Path | None:
        credential = next((item for item in self.context.credentials
                           if item.get("target", self.context.target) == self.context.target
                           and item.get("username") and item.get("password") is not None), None)
        if not credential:
            self.identity = "anonymous/guest"
            return None
        if any(any(ch in str(credential.get(key, "")) for ch in "\r\n\0")
               for key in ("username", "password", "domain")):
            raise ValueError("SMB credentials may not contain line breaks or NUL bytes")
        directory = self.context.scan_dir / "services/smb/.private"
        directory.mkdir(parents=True, exist_ok=True)
        fd, filename = tempfile.mkstemp(prefix="smb-auth-", dir=directory)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(f"username = {credential['username']}\n")
            stream.write(f"password = {credential['password']}\n")
            if credential.get("domain"):
                stream.write(f"domain = {credential['domain']}\n")
        self.identity = credential["username"]
        self.auth_file = Path(filename)
        return self.auth_file

    def _make_task(self, task_id: str, native: tuple[list[str], list[str]],
                   suffix: str, resource: Resource | None = None) -> Task:
        actual, display = native
        key = hashlib.sha256((resource.resource_id if resource else task_id).encode()).hexdigest()[:16]
        output = self.context.scan_dir / "services/smb" / f"{suffix}-{key}.log"
        metadata = self.context.scan_dir / "metadata" / f"smb-{suffix}-{key}.json"
        task = Task(task_id, self.context.target, "smb", actual, output, metadata,
                    timeout=300, parent_task=resource.parent if resource else None,
                    reason=f"SMB {suffix} enumeration",
                    resource_id=resource.resource_id if resource else None,
                    parent_resource_id=resource.parent if resource else None,
                    depth=resource.depth if resource else 0, display_argv=display)
        return task

    def _execute(self, task: Task) -> TaskState:
        state = self.terminals.execute(task, self.runner)
        if task.terminal_external and task.output_path.exists():
            collect(task.service, task.display_argv or task.argv, task.output_path)
        return state

    @staticmethod
    def _raw(task: Task) -> bytes:
        return task.output_path.read_bytes() if task.output_path.exists() else b""

    def _record_identity(self, resource: Resource) -> None:
        resource.authenticated_identity = self.identity

    def _enumerate_resource(self, resource: Resource) -> list[Resource]:
        if resource.resource_type == "file":
            return self._inspect_file(resource)
        share = str(resource.metadata.get("share", resource.name))
        relative = "" if resource.resource_type == "share" else resource.path
        native = commands.list_directory(self.context.target, self.port, share, relative, self.auth_file)
        task = self._make_task("smb-list-" + hashlib.sha256(resource.resource_id.encode()).hexdigest()[:12],
                               native, "list", resource)
        state = self.execute_task(task)
        output = self._raw(task)
        result = parser.access_result(output, 0 if state == TaskState.SUCCESS else 1)
        resource.list_access = result["list_access"]
        resource.read_access = result["read_access"]
        resource.authentication_required = result["authentication_required"]
        resource.metadata["permission_state"] = result["permission_state"]
        self._record_identity(resource)
        if state != TaskState.SUCCESS:
            resource.status = ResourceStatus.INACCESSIBLE if resource.authentication_required else ResourceStatus.FAILED
            return []
        entries = parser.parse_listing(output, share, relative)
        return rules.resources_from_listing(resource, entries)

    def _inspect_file(self, resource: Resource) -> list[Resource]:
        if not rules.read_required(resource, self.limits.max_download_size):
            resource.metadata["inspection"] = "metadata-only"
            resource.status = ResourceStatus.SUCCESS
            return []
        share = str(resource.metadata["share"])
        parent_path, _, filename = resource.path.rpartition("/")
        artifact_dir = self.context.scan_dir / "services/smb/files"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        suffix = Path(filename).suffix
        if not re.fullmatch(r"\.[A-Za-z0-9]{1,10}", suffix):
            suffix = ".bin"
        destination = artifact_dir / (hashlib.sha256(resource.resource_id.encode()).hexdigest() + suffix)
        native = commands.download_file(self.context.target, self.port, share, parent_path,
                                        filename, destination, self.auth_file)
        task = self._make_task("smb-read-" + hashlib.sha256(resource.resource_id.encode()).hexdigest()[:12],
                               native, "inspect", resource)
        state = self.execute_task(task)
        result = parser.access_result(self._raw(task), 0 if state == TaskState.SUCCESS else 1)
        downloaded = state == TaskState.SUCCESS and destination.is_file()
        resource.read_access = Access.YES if downloaded else result["read_access"]
        resource.authentication_required = result["authentication_required"]
        resource.metadata["permission_state"] = "READ" if state == TaskState.SUCCESS else result["permission_state"]
        if downloaded:
            resource.metadata["artifact"] = str(destination.relative_to(self.context.scan_dir))
            resource.metadata["actual_size"] = destination.stat().st_size
            with destination.open("rb") as stream:
                magic = stream.read(4096)
            resource.metadata["content_classification"] = parser.classify_file(
                filename, destination.stat().st_size, resource.path, magic
            )["category"]
        self._record_identity(resource)
        return []

    def run(self) -> list[dict[str, Any]]:
        auth_file = self._credential_file()
        try:
            task = self._make_task("smb-shares", commands.list_shares(
                self.context.target, self.port, auth_file), "shares")
            state = self.execute_task(task)
            if state != TaskState.SUCCESS:
                return []
            share_output = self._raw(task)
            facts = parser.parse_context(share_output)
            if facts.get("domain"):
                self.context.add_domain(facts["domain"])
            if facts.get("server"):
                self.context.add_hostname(facts["server"])
            self.context.facts.setdefault("smb", {}).update(facts)
            shares = parser.parse_shares(share_output)
            roots = [Resource("smb", self.context.target, self.port, "tcp", "share",
                              item["name"], path=item["name"], list_access=Access.UNKNOWN,
                              authentication_required=None, authenticated_identity=self.identity,
                              metadata={**item, "share": item["name"]}) for item in shares]
            self.traversal.traverse(roots, self._enumerate_resource)
            results = [resource.to_dict() for resource in self.traversal.resources.values()]
            self.context.resources.update({item["resource_id"]: item for item in results})
            write_json(self.context.scan_dir / "metadata/smb-resources.json", results)
            return results
        finally:
            if auth_file:
                auth_file.unlink(missing_ok=True)
                try:
                    auth_file.parent.rmdir()
                except OSError:
                    pass
