"""Internal SSH banner/key and authentication-state parsing."""

from __future__ import annotations

import re

_KEY = re.compile(rb"^([^\s]+)\s+(ssh-[^\s]+|ecdsa-[^\s]+)\s+([^\s]+)", re.M)


def host_keys(output: bytes) -> list[dict[str, str]]:
    return [{"host": host.decode("ascii", "replace"),
             "algorithm": algorithm.decode("ascii", "replace"),
             "key": key.decode("ascii", "replace")}
            for host, algorithm, key in _KEY.findall(output)]


def auth_state(output: bytes, exit_code: int) -> dict[str, object]:
    text = output.decode("utf-8", errors="replace")
    match = re.search(r"Authentications that can continue:\s*([^\r\n]+)", text, re.I)
    identity = re.search(r"uid=\d+\(([^)]+)\)", text)
    return {"authentication_methods": match.group(1).strip().split(",") if match else [],
            "authenticated": exit_code == 0 and bool(identity),
            "identity": identity.group(1) if identity else None,
            "permission_state": "AUTHENTICATED" if exit_code == 0 and identity else
                                "AUTH_REQUIRED" if match or "permission denied" in text.lower() else "UNKNOWN"}
