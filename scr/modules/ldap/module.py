"""Anonymous LDAP RootDSE and bounded container traversal."""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from scr.core.context import TargetContext
from scr.core.evidence import write_json
from scr.core.output import collect
from scr.core.process import CommandRunner
from scr.core.resources import Access, Resource, ResourceStatus, TraversalLimits
from scr.core.tasks import Task, TaskState
from scr.core.terminal import TerminalManager
from scr.engine.traversal import ResourceTraversal
from scr.modules.ldap import commands, parser, rules


class LDAPModule:
    service = "ldap"

    def __init__(self, context: TargetContext, *, port: int = 389, tls: bool = False,
                 limits: TraversalLimits | None = None, runner: CommandRunner | None = None,
                 terminals: TerminalManager | None = None,
                 execute: Callable[[Task], TaskState] | None = None) -> None:
        self.context, self.port, self.tls = context, port, tls
        self.limits = limits or TraversalLimits()
        self.runner = runner or CommandRunner()
        self.terminals = terminals or TerminalManager()
        self.execute_task = execute
        self.traversal = ResourceTraversal(self.limits)

    def _run(self, label: str, native: tuple[list[str], list[str]], resource_id: str = "") -> tuple[TaskState, bytes]:
        actual, display = native
        key = hashlib.sha256((label + resource_id + str(self.port)).encode()).hexdigest()[:14]
        task = Task(f"ldap-{label}-{key}", self.context.target, "ldap", actual,
                    self.context.scan_dir / "services/ldap" / f"{label}-{key}.raw",
                    self.context.scan_dir / "metadata" / f"ldap-{label}-{key}.json",
                    timeout=20, reason=f"LDAP {label}", display_argv=display,
                    resource_id=resource_id or None)
        state = self.execute_task(task) if self.execute_task else self.terminals.execute(task, self.runner)
        if not self.execute_task and task.terminal_external and task.output_path.exists():
            collect("LDAP", display, task.output_path)
        return state, task.output_path.read_bytes() if task.output_path.exists() else b""

    def _enumerate(self, resource: Resource) -> list[Resource]:
        if resource.resource_type not in {"ldap_context", "organizational_unit", "ldap_container"}:
            resource.status = ResourceStatus.SUCCESS
            return []
        state, raw = self._run("children", commands.children(self.context.target, self.port,
                                                              resource.path, self.tls), resource.resource_id)
        text = raw.decode("utf-8", errors="replace")
        if parser.authentication_required(raw):
            resource.authentication_required = True
            resource.list_access = resource.read_access = Access.NO
            resource.metadata["permission_state"] = "AUTH_REQUIRED"
            resource.status = ResourceStatus.INACCESSIBLE
            return []
        if state != TaskState.SUCCESS:
            resource.status = ResourceStatus.FAILED
            return []
        resource.authentication_required = False
        resource.list_access = resource.read_access = Access.YES
        children = rules.children_from_output(resource, raw)
        facts = self.context.facts.setdefault("ldap_objects", [])
        for child in children:
            attrs = child.metadata.get("attributes", {})
            facts.append({"dn": child.path, "type": child.resource_type,
                          "cn": attrs.get("cn", []),
                          "sAMAccountName": attrs.get("samaccountname", []),
                          "userPrincipalName": attrs.get("userprincipalname", []),
                          "dNSHostName": attrs.get("dnshostname", []),
                          "servicePrincipalName": attrs.get("serviceprincipalname", [])})
            for hostname in attrs.get("dnshostname", []):
                self.context.add_hostname(hostname)
        return children

    def run(self) -> list[dict]:
        state, raw = self._run("rootdse", commands.root_dse(self.context.target, self.port, self.tls))
        if state != TaskState.SUCCESS:
            result = {"anonymous_bind": False, "naming_contexts": []}
            write_json(self.context.scan_dir / "metadata/ldap-rootdse.json", result)
            return []
        contexts = parser.naming_contexts(raw)
        entries = parser.entries(raw)
        facts: dict[str, object] = {"anonymous_bind": True, "naming_contexts": contexts}
        facts["anonymous_rootdse"] = True
        primary = next((dn for entry in entries
                        for dn in entry.get("defaultnamingcontext", [])), None)
        if primary is None:
            primary = next((dn for dn in contexts
                            if not dn.lower().startswith(("cn=configuration,", "cn=schema,"))
                            and not dn.lower().startswith(("dc=domaindnszones,", "dc=forestdnszones,"))), None)
        roots = []
        primary_domain = parser.domain_from_dn(primary) if primary else None
        if primary_domain:
            self.context.add_domain(primary_domain)
            self.context.facts.setdefault("domain", primary_domain)
            facts["domain"] = primary_domain
        for entry in entries:
            for hostname in entry.get("dnshostname", []):
                self.context.add_hostname(hostname)
                facts["hostname"] = hostname
        # RootDSE can expose several AD partitions. Enumerate the primary
        # domain tree first; configuration and DNS partitions are metadata,
        # not equivalent user/container trees for this anonymous traversal.
        for dn in ([primary] if primary else []):
            domain = parser.domain_from_dn(dn)
            roots.append(Resource("ldap", self.context.target, self.port,
                                  "tls" if self.tls else "tcp", "ldap_context", dn,
                                  path=dn, read_access=Access.UNKNOWN,
                                  authentication_required=False,
                                  metadata={"domain": domain, "anonymous": True}))
        self.traversal.traverse(roots, self._enumerate)
        values = [item.to_dict() for item in self.traversal.resources.values()]
        auth_required = any(item.authentication_required is True
                            for item in self.traversal.resources.values())
        facts["anonymous_directory_read"] = False if auth_required else any(
            item.read_access == Access.YES for item in self.traversal.resources.values())
        write_json(self.context.scan_dir / "metadata/ldap-rootdse.json", facts)
        self.context.resources.update({item["resource_id"]: item for item in values})
        write_json(self.context.scan_dir / "metadata/ldap-resources.json", values)
        return values
