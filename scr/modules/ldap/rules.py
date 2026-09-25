"""LDAP directory-object traversal rules."""

from scr.core.resources import Access, Resource
from scr.modules.ldap.parser import entries, object_kind


def children_from_output(parent: Resource, output: bytes | str) -> list[Resource]:
    resources = []
    for entry in entries(output):
        dn = (entry.get("dn") or [""])[0]
        kind = object_kind(entry)
        if not dn or dn == parent.path:
            continue
        resources.append(Resource("ldap", parent.target, parent.port, parent.protocol, kind,
            dn, path=dn, parent=parent.resource_id, depth=parent.depth + 1,
            list_access=Access.YES, read_access=Access.YES,
            authentication_required=False, metadata={"attributes": entry}))
    return resources
