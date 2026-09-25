"""Nmap service/version command construction and normal-output parsing."""

from __future__ import annotations

import re
import ipaddress
from pathlib import Path
from typing import Any

from scr.core.context import TargetContext
from scr.core.tasks import Task


_PORT_LINE = re.compile(r"^\s*(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$")
_REPORT = re.compile(r"^Nmap scan report for\s+(.+?)\s*$", re.MULTILINE | re.IGNORECASE)
_DOMAIN = re.compile(r"\bDomain(?:\s+name)?\s*:\s*([A-Za-z0-9.-]+)", re.IGNORECASE)
_FQDN = re.compile(r"\bFQDN\s*:\s*([A-Za-z0-9.-]+)", re.IGNORECASE)
_NETBIOS = re.compile(r"\b(?:NetBIOS\s+computer\s+name|Hostname)\s*:\s*([A-Za-z0-9.-]+)", re.IGNORECASE)
_PAREN_IP = re.compile(r"\(([^()]+)\)\s*$")
_HTTP_SCRIPT_EVIDENCE = re.compile(
    r"(?:http-title|http-server-header|http-methods|http-robots\.txt|"
    r"HTTP/1\.[01]\s+[1-5]\d\d)", re.IGNORECASE)


def command(target: str, tcp_ports: list[int], udp_ports: list[int] | None = None) -> list[str]:
    specs = []
    if tcp_ports:
        specs.append("T:" + ",".join(map(str, sorted(set(tcp_ports)))))
    if udp_ports:
        specs.append("U:" + ",".join(map(str, sorted(set(udp_ports)))))
    if not specs:
        raise ValueError("Nmap requires at least one discovered port")
    argv = ["nmap", "-Pn", "-sC", "-sV", "-O", "-T4"]
    try:
        if ipaddress.ip_address(target).version == 6:
            argv.append("-6")
    except ValueError:
        pass
    if udp_ports:
        argv.append("-sU")
    return argv + ["-p", ",".join(specs), "-oN", "-", target]


def port_discovery_command(target: str, port_spec: str | None = None) -> list[str]:
    """Use Nmap as the read-only port-discovery fallback when RustScan is unavailable."""
    argv = ["nmap", "-Pn", "-n", "--open", "-sT", "-T4"]
    argv.extend(("-p", port_spec) if port_spec else ("-p-",))
    argv.extend(("-oN", "-"))
    try:
        if ipaddress.ip_address(target).version == 6:
            argv.insert(1, "-6")
    except ValueError:
        pass
    return argv + [target]


def make_task(context: TargetContext) -> Task:
    return Task("nmap", context.target, "nmap",
                command(context.target, context.tcp_ports, context.udp_ports),
                context.scan_dir / "nmap/nmap.log",
                context.scan_dir / "metadata/nmap.json", timeout=1800,
                dependencies=["rustscan"], parent_task="rustscan",
                reason="Service and version detection for discovered ports")


def parse_services(output: bytes | str) -> list[dict[str, Any]]:
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output
    lines = text.splitlines()
    matches = [(index, _PORT_LINE.match(line)) for index, line in enumerate(lines)]
    rows = [(index, match) for index, match in matches if match]
    results = []
    for row_index, (line_index, match) in enumerate(rows):
        port, transport, service, detail = match.groups()
        end = rows[row_index + 1][0] if row_index + 1 < len(rows) else len(lines)
        service_block = "\n".join(lines[line_index + 1:end])
        fingerprint_ports = {(int(found_port), found_transport.lower())
                             for found_port, found_transport in re.findall(
                                 r"SF-Port(\d+)-(TCP|UDP)", service_block, re.IGNORECASE)}
        has_http_signal = bool(_HTTP_SCRIPT_EVIDENCE.search(service_block))
        script_http = has_http_signal and (not fingerprint_ports or
                                           (int(port), transport.lower()) in fingerprint_ports)
        if service.lower().rstrip("?") in {"rtsp", "unknown", "tcpwrapped"} and script_http:
            service = "http"
            detail = " ".join(part for part in (detail, "HTTP detected by Nmap script/fingerprint") if part)
        results.append({"port": int(port), "transport": transport, "service": service,
                        "details": detail or "", "nmap_http_evidence": script_http})
    return results


def extract_host_identity(output: bytes | str, target: str) -> dict[str, str | None]:
    """Return only hostname/domain values explicitly present in Nmap evidence."""
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output
    hostname: str | None = None
    fqdn: str | None = None
    target_ip: str | None = None
    for report in _REPORT.finditer(text):
        value = report.group(1).strip()
        address_match = _PAREN_IP.search(value)
        if address_match:
            try:
                target_ip = str(ipaddress.ip_address(address_match.group(1)))
                value = value[:address_match.start()].strip()
            except ValueError:
                pass
        try:
            target_ip = str(ipaddress.ip_address(value))
            continue
        except ValueError:
            if value:
                hostname = value.rstrip(".")
                if "." in hostname:
                    fqdn = hostname
    try:
        target_ip = target_ip or str(ipaddress.ip_address(target))
    except ValueError:
        pass
    domains = [match.group(1).rstrip(".") for match in _DOMAIN.finditer(text)]
    fqdn_matches = [match.group(1).rstrip(".") for match in _FQDN.finditer(text)]
    netbios_matches = [match.group(1).rstrip(".") for match in _NETBIOS.finditer(text)]
    if fqdn_matches:
        fqdn = fqdn_matches[0]
        hostname = fqdn.split(".", 1)[0]
    elif fqdn:
        hostname = fqdn.split(".", 1)[0]
    if not hostname and netbios_matches:
        hostname = netbios_matches[0]
    domain = domains[0] if domains else None
    if not domain and fqdn and "." in fqdn:
        domain = fqdn.split(".", 1)[1]
    return {"target_ip": target_ip, "hostname": hostname, "fqdn": fqdn, "domain": domain}
