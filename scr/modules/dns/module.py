"""Target-scoped DNS query sequence that pivots from discovered zone data."""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from scr.core.context import TargetContext
from scr.core.evidence import write_json
from scr.core.output import collect
from scr.core.process import CommandRunner
from scr.core.tasks import Task, TaskState
from scr.core.terminal import TerminalManager
from scr.modules.dns import commands, parser, rules


class DNSModule:
    service = "dns"

    def __init__(self, context: TargetContext, *, port: int = 53,
                 runner: CommandRunner | None = None, terminals: TerminalManager | None = None,
                 execute: Callable[[Task], TaskState] | None = None) -> None:
        self.context, self.port = context, port
        self.runner = runner or CommandRunner()
        self.terminals = terminals or TerminalManager()
        self.execute_task = execute
        self.records: list[dict[str, str]] = []
        self.queries: set[tuple[str, str, bool]] = set()

    def _query(self, name: str, kind: str, tcp: bool) -> list[dict[str, str]]:
        key = (name, kind, tcp)
        if key in self.queries:
            return []
        self.queries.add(key)
        native = commands.query(name, kind, tcp=tcp, server=self.context.target, port=self.port)
        actual, display = native
        identity = f"{name}|{kind}|{int(tcp)}"
        digest = hashlib.sha256(identity.encode()).hexdigest()[:14]
        task = Task(f"dns-{digest}", self.context.target, "dns", actual,
                    self.context.scan_dir / "services/dns" / f"{digest}.raw",
                    self.context.scan_dir / "metadata" / f"dns-{digest}.json",
                    timeout=15, reason=f"DNS {kind} query", display_argv=display,
                    resource_id=identity)
        state = self.execute_task(task) if self.execute_task else self.terminals.execute(task, self.runner)
        if not self.execute_task and task.terminal_external and task.output_path.exists():
            collect("DNS", display, task.output_path)
        raw = task.output_path.read_bytes() if task.output_path.exists() else b""
        parsed = parser.answers(raw)
        self.records.extend(parsed)
        if state == TaskState.SUCCESS:
            for record in parsed:
                if record["type"] in {"A", "AAAA", "CNAME", "NS"}:
                    self.context.add_hostname(record["name"])
                if record["type"] in {"CNAME", "NS"}:
                    self.context.add_hostname(record["value"])
                if record["type"] == "PTR":
                    self.context.add_hostname(record["value"])
                if record["type"] == "SOA":
                    domain = record["name"]
                    self.context.add_domain(domain)
        return parsed

    def run(self) -> list[dict[str, str]]:
        domain = parser.domain_from_target(self.context.target)
        known_domain = self.context.facts.get("domain")
        if not isinstance(known_domain, str):
            known_domain = next(iter(sorted(self.context.domains)), None)
        if domain:
            found = self._query(self.context.target, "SOA", tcp=False)
            self._query(self.context.target, "SOA", tcp=True)
        else:
            found = self._query(self.context.target, "PTR", tcp=False)
            self._query(self.context.target, "PTR", tcp=True)
            domain = known_domain
        if not domain:
            ptr = next((r["value"] for r in found if r["type"] == "PTR"), None)
            domain = parser.domain_from_target(ptr) if ptr else None
            if ptr:
                self.context.add_hostname(ptr)
        if domain:
            self.context.add_domain(domain)
            for kind in ("SOA", "NS", "A", "AAAA", "MX", "TXT", "SRV"):
                found.extend(self._query(domain, kind, tcp=False))
                self._query(domain, kind, tcp=True)
        pending = rules.followup_queries(found)
        while pending and len(self.queries) < 200:
            name, kind = pending.pop(0)
            discovered = self._query(name, kind, tcp=False)
            self._query(name, kind, tcp=True)
            pending.extend(item for item in rules.followup_queries(discovered)
                           if not any(item[0] == qname and item[1] == qtype
                                      for qname, qtype, _ in self.queries))
        write_json(self.context.scan_dir / "metadata/dns-records.json", self.records)
        return self.records
