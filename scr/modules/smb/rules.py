"""SMB result-to-resource rules."""

from __future__ import annotations

from typing import Any

from scr.core.resources import Access, Resource


def resources_from_listing(parent: Resource, entries: list[dict[str, Any]]) -> list[Resource]:
    children = []
    for entry in entries:
        kind = entry["resource_type"]
        children.append(Resource(
            service=parent.service, target=parent.target, port=parent.port,
            protocol=parent.protocol, resource_type=kind, name=entry["name"],
            path=entry["path"], parent=parent.resource_id, depth=parent.depth + 1,
            list_access=Access.UNKNOWN if kind == "directory" else Access.NO,
            read_access=Access.UNKNOWN, write_access=Access.UNKNOWN,
            authentication_required=parent.authentication_required,
            authenticated_identity=parent.authenticated_identity,
            metadata={**entry, "permission_state": "UNKNOWN"},
        ))
    return children


def read_required(file_resource: Resource, max_download_size: int) -> bool:
    return bool(file_resource.metadata.get("interesting") and
                file_resource.metadata.get("size", max_download_size + 1) <= max_download_size)
