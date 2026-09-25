"""LDIF parsing for RootDSE and directory objects."""

from __future__ import annotations

import base64
import re


def entries(output: bytes | str) -> list[dict[str, list[str]]]:
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output
    unfolded = re.sub(r"\r?\n[ \t]", "", text)
    result: list[dict[str, list[str]]] = []
    current: dict[str, list[str]] = {}
    for line in unfolded.splitlines() + [""]:
        if not line:
            if current:
                result.append(current)
                current = {}
            continue
        if line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        if value.startswith(":"):
            try:
                value = base64.b64decode(value[1:].strip()).decode("utf-8", errors="replace")
            except ValueError:
                value = ""
        else:
            value = value.lstrip()
        current.setdefault(key.lower(), []).append(value)
    return result


def naming_contexts(output: bytes | str) -> list[str]:
    values = []
    for item in entries(output):
        values.extend(item.get("defaultnamingcontext", []))
        values.extend(item.get("namingcontexts", []))
    return list(dict.fromkeys(values))


def authentication_required(output: bytes | str) -> bool:
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output
    lowered = text.lower()
    return any(marker in lowered for marker in (
        "successful bind must be completed on the connection",
        "stronger authentication required",
        "invalid credentials",
        "ldap insufficient_access",
        "insufficient access rights",
    ))


def domain_from_dn(value: str) -> str | None:
    labels = re.findall(r"(?:^|,)\s*DC=([^,]+)", value, re.I)
    while labels and labels[0].lower() in {"domaindnszones", "forestdnszones"}:
        labels.pop(0)
    return ".".join(labels) if labels else None


def object_kind(entry: dict[str, list[str]]) -> str:
    classes = {value.lower() for value in entry.get("objectclass", [])}
    if "organizationalunit" in classes:
        return "organizational_unit"
    if "container" in classes:
        return "ldap_container"
    if "group" in classes:
        return "ldap_group"
    if "computer" in classes:
        return "ldap_computer"
    if "user" in classes:
        return "ldap_user"
    return "ldap_object"
