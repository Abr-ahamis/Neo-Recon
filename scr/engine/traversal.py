"""Bounded, deduplicated adaptive traversal of service-discovered resources."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
import threading

from scr.core.resources import Resource, ResourceStatus, TraversalLimits


DIRECTORY_TYPES = {"directory", "folder", "collection", "container", "namespace",
                   "organizational_unit", "ldap_container", "ldap_context", "schema", "database"}
FILE_TYPES = {"file", "regular_file", "document", "archive", "database_file", "source_file"}


class ResourceTraversal:
    def __init__(self, limits: TraversalLimits | None = None) -> None:
        self.limits = limits or TraversalLimits()
        self._lock = threading.Lock()
        self._visited: set[str] = set()
        self._accepted: dict[str, Resource] = {}
        self._file_count = 0
        self._directory_count = 0

    @property
    def resources(self) -> dict[str, Resource]:
        with self._lock:
            return dict(self._accepted)

    def offer(self, resource: Resource, parent: Resource | None = None) -> bool:
        with self._lock:
            if parent is not None:
                resource.parent = parent.resource_id
                resource.depth = parent.depth + 1
            if resource.depth > self.limits.max_depth or resource.probe_blocked:
                resource.status = ResourceStatus.SKIPPED
                return False
            if resource.resource_id in self._visited or len(self._accepted) >= self.limits.max_tasks:
                resource.status = ResourceStatus.SKIPPED
                return False
            kind = resource.resource_type.lower()
            if kind in FILE_TYPES or kind.endswith("_file"):
                if self._file_count >= self.limits.max_files:
                    resource.status = ResourceStatus.SKIPPED
                    return False
                self._file_count += 1
            if kind in DIRECTORY_TYPES or kind.endswith("_directory"):
                if self._directory_count >= self.limits.max_directories:
                    resource.status = ResourceStatus.SKIPPED
                    return False
                self._directory_count += 1
            self._visited.add(resource.resource_id)
            self._accepted[resource.resource_id] = resource
            resource.status = ResourceStatus.QUEUED
            return True

    def traverse(self, roots: Iterable[Resource],
                 enumerate_resource: Callable[[Resource], Iterable[Resource]]) -> dict[str, Resource]:
        queue: deque[Resource] = deque()
        for root in roots:
            if self.offer(root):
                queue.append(root)
        futures: dict[Future[Iterable[Resource]], Resource] = {}
        with ThreadPoolExecutor(max_workers=self.limits.max_workers,
                                thread_name_prefix="resource") as pool:
            while queue or futures:
                while queue and len(futures) < self.limits.max_workers:
                    resource = queue.popleft()
                    resource.status = ResourceStatus.RUNNING
                    futures[pool.submit(enumerate_resource, resource)] = resource
                done, _ = wait(futures, return_when=FIRST_COMPLETED)
                for future in done:
                    parent = futures.pop(future)
                    try:
                        children = future.result()
                    except Exception:
                        parent.status = ResourceStatus.FAILED
                        continue
                    if parent.status == ResourceStatus.RUNNING:
                        parent.status = ResourceStatus.SUCCESS
                    for child in children:
                        if self.offer(child, parent):
                            queue.append(child)
        return self.resources
