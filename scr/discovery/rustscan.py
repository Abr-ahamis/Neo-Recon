"""RustScan command construction and native output port extraction."""

from __future__ import annotations

import re
from pathlib import Path

from scr.core.context import TargetContext
from scr.core.tasks import Task


_PORT_LIST = re.compile(rb"\[((?:\d{1,5}\s*,\s*)*\d{1,5})\]")
_OPEN_LINE = re.compile(rb"\b(?:Open|open)\s+(?:[0-9a-fA-F:.]+:)?(\d{1,5})/(tcp|udp)\b")
_RUSTSCAN_OPEN = re.compile(rb"\bOpen\s+[0-9a-fA-F:.]+:(\d{1,5})\b")
_NMAP_OPEN_LINE = re.compile(rb"^\s*(\d{1,5})/(tcp|udp)\s+open\b", re.MULTILINE | re.IGNORECASE)
_GREPPABLE = re.compile(rb"Ports:\s*((?:\d+/(?:open|closed)/(?:tcp|udp)(?:,\s*)?)+)")


def command(target: str, *, port_spec: str | None = None,
            output_file: str | Path | None = None) -> list[str]:
    argv = ["rustscan", "-a", target]
    if port_spec:
        argv.extend(("-p", port_spec))
    if output_file is not None:
        argv.extend(("--", "-oN", str(output_file)))
    return argv


def make_task(context: TargetContext, port_spec: str | None = None) -> Task:
    nmap_output = context.scan_dir / "discovery/rustscan-port"
    argv = command(context.target, port_spec=port_spec, output_file=nmap_output)
    return Task("rustscan", context.target, "rustscan", argv,
                context.scan_dir / "discovery/rustscan.log",
                context.scan_dir / "metadata/rustscan.json", timeout=1800,
                reason="Initial TCP port discovery", display_argv=argv)


def extract_ports(data: bytes) -> dict[str, list[int]]:
    ports: dict[str, set[int]] = {"tcp": set(), "udp": set()}
    for match in _PORT_LIST.finditer(data):
        for token in match.group(1).split(b","):
            port = int(token.strip())
            if 1 <= port <= 65535:
                ports["tcp"].add(port)
    for port, proto in _OPEN_LINE.findall(data):
        value = int(port)
        if 1 <= value <= 65535:
            ports[proto.decode("ascii")].add(value)
    for port in _RUSTSCAN_OPEN.findall(data):
        value = int(port)
        if 1 <= value <= 65535:
            ports["tcp"].add(value)
    for port, proto in _NMAP_OPEN_LINE.findall(data):
        value = int(port)
        if 1 <= value <= 65535:
            ports[proto.decode("ascii").lower()].add(value)
    for line in _GREPPABLE.findall(data):
        for item in line.split(b","):
            port, state, proto = item.strip().split(b"/")
            value = int(port)
            if state == b"open" and 1 <= value <= 65535:
                ports[proto.decode("ascii")].add(value)
    return {proto: sorted(values) for proto, values in ports.items()}
