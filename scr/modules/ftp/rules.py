"""Convert FTP listings into generic traversable resources."""

from scr.core.resources import Access, Resource


def resources_from_listing(parent: Resource, entries: list[dict]) -> list[Resource]:
    base = parent.path.rstrip("/")
    resources = []
    for entry in entries:
        path = "/".join(filter(None, (base, entry["name"])))
        resources.append(Resource(parent.service, parent.target, parent.port, parent.protocol,
            entry["resource_type"], entry["name"], path=path, parent=parent.resource_id,
            depth=parent.depth + 1, list_access=Access.UNKNOWN,
            read_access=Access.UNKNOWN, authentication_required=parent.authentication_required,
            authenticated_identity=parent.authenticated_identity, metadata=dict(entry)))
    return resources
