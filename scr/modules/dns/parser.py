"""Parse dig answer records separately from retained native output."""

from __future__ import annotations

import ipaddress
import re

_ANSWER = re.compile(r"^([^\s]+)\s+\d+\s+IN\s+(\S+)\s+(.+)$", re.I)
_HOST_ANSWER = re.compile(
    r"^([^\s]+)\s+(?:has\s+address|has\s+IPv6\s+address|name\s+server|"
    r"mail\s+is\s+handled\s+by|domain\s+name\s+pointer|has\s+SOA\s+record|"
    r"descriptive\s+text)\s+(.+)$", re.I)


def answers(output: bytes | str) -> list[dict[str, str]]:
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output
    result = []
    for line in text.splitlines():
        match = _ANSWER.match(line.strip())
        if match:
            name, record_type, value = match.groups()
            if record_type.upper() == "PTR":
                value = value.split()[0]
            result.append({"name": name.rstrip("."), "type": record_type.upper(), "value": value.rstrip(".")})
            continue
        host_match = _HOST_ANSWER.match(line.strip())
        if host_match:
            name, rest = host_match.groups()
            lowered = line.lower()
            record_type = ("AAAA" if "ipv6 address" in lowered else
                           "A" if "has address" in lowered else
                           "NS" if "name server" in lowered else
                           "MX" if "mail is handled by" in lowered else
                           "PTR" if "domain name pointer" in lowered else
                           "SOA" if "has soa record" in lowered else "TXT")
            value = rest.split()[0] if record_type in {"A", "AAAA", "NS", "PTR"} else rest
            result.append({"name": name.rstrip("."), "type": record_type,
                           "value": value.rstrip(".")})
    return result


def domain_from_target(target: str) -> str | None:
    try:
        ipaddress.ip_address(target)
        return None
    except ValueError:
        return target.rstrip(".")
