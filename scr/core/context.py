"""Single-target scan context and validation."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def validate_target(value: str) -> str:
    target = value.strip()
    if not target or target.startswith("-") or any(c in target for c in "\r\n\0"):
        raise ValueError("enter a valid hostname or IP address")
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        hostname = target[:-1] if target.endswith(".") else target
        if len(hostname) > 253 or not hostname:
            raise ValueError("enter a valid hostname or IP address")
        labels = hostname.split(".")
        if any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", x)
               for x in labels):
            raise ValueError("enter a valid hostname or IP address")
        return target


def target_authority(target: str, port: int | None = None) -> str:
    """Format a validated hostname/IP for URL and URI authorities."""
    try:
        address = ipaddress.ip_address(target)
        host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    except ValueError:
        host = target
    return f"{host}:{port}" if port is not None else host


@dataclass
class TargetContext:
    target: str
    scan_dir: Path
    hostnames: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    services: list[dict[str, Any]] = field(default_factory=list)
    tcp_ports: list[int] = field(default_factory=list)
    udp_ports: list[int] = field(default_factory=list)
    resources: dict[str, Any] = field(default_factory=dict)
    credentials: list[dict[str, str]] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)

    def add_hostname(self, hostname: str, *, in_scope: bool = False) -> None:
        if hostname:
            self.hostnames.add(hostname.rstrip("."))
        if in_scope:
            self.facts.setdefault("in_scope_hostnames", set()).add(hostname.rstrip("."))

    def add_domain(self, domain: str) -> None:
        if domain:
            self.domains.add(domain.rstrip("."))
