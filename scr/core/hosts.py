"""Evidence-based, atomic host mapping updates."""

from __future__ import annotations

import ipaddress
import os
import re
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_LOCK = threading.Lock()


def _valid_alias(value: str) -> bool:
    alias = value.rstrip(".")
    if not alias or len(alias) > 253 or not _HOST_LABEL.fullmatch(alias):
        return False
    try:
        ipaddress.ip_address(alias)
        return False
    except ValueError:
        return all(label and len(label) <= 63 for label in alias.split("."))


class HostsManager:
    def __init__(self, path: Path = Path("/etc/hosts")) -> None:
        self.path = Path(path)

    def apply(self, address: str, aliases: list[str] | set[str]) -> dict[str, Any]:
        try:
            ip = str(ipaddress.ip_address(address))
        except ValueError:
            return {"status": "skipped", "reason": "no validated target IP"}
        by_casefold = {alias.rstrip(".").casefold(): alias.rstrip(".")
                       for alias in aliases if _valid_alias(alias)}
        desired = sorted(by_casefold.values(), key=str.casefold)
        if not desired:
            return {"status": "skipped", "reason": "no validated hostnames"}
        with _LOCK:
            try:
                hosts_path = self.path.resolve(strict=True)
                original = hosts_path.read_bytes()
                text = original.decode("utf-8")
                lines = text.splitlines(keepends=True)
                mapped: dict[str, set[str]] = {}
                for line in lines:
                    active = line.split("#", 1)[0].split()
                    if len(active) >= 2:
                        for alias in active[1:]:
                            mapped.setdefault(alias.casefold(), set()).add(active[0])
                if all(mapped.get(alias.casefold(), set()) == {ip} for alias in desired):
                    return {"status": "unchanged", "address": ip, "aliases": desired}

                conflicts = {
                    alias.casefold() for alias in desired
                    if any(existing != ip for existing in mapped.get(alias.casefold(), set()))
                }
                updated: list[str] = []
                for line in lines:
                    active = line.split("#", 1)[0].split()
                    if len(active) >= 2 and conflicts.intersection(a.casefold() for a in active[1:]):
                        original_line = line.rstrip("\r\n")
                        updated.append(f"# Neo-Recon: replaced mapping for {' '.join(active[1:])}\n")
                        updated.append(f"# {original_line}\n")
                    else:
                        updated.append(line)
                already_correct = {
                    alias.casefold() for alias in desired
                    if ip in mapped.get(alias.casefold(), set())
                }
                additions = [alias for alias in desired if alias.casefold() not in already_correct]
                if not updated or (updated[-1] and not updated[-1].endswith(("\n", "\r"))):
                    updated.append("\n")
                updated.append(f"{ip}\t{' '.join(additions)}\n")
                replacement = "".join(updated).encode("utf-8")
                backup = hosts_path.with_name(
                    f"{hosts_path.name}.neo-recon.{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}.bak"
                )
                self._atomic_backup(original, backup)
                self._atomic_replace(replacement, hosts_path)
                return {"status": "updated", "address": ip, "aliases": additions,
                        "backup": str(backup), "conflicts_commented": sorted(conflicts)}
            except (OSError, UnicodeError) as exc:
                return {"status": "failed", "reason": str(exc),
                        "path": str(self.path)}

    @staticmethod
    def _atomic_backup(content: bytes, backup: Path) -> None:
        fd, name = tempfile.mkstemp(prefix=f".{backup.name}.", dir=backup.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, backup)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _atomic_replace(content: bytes, destination: Path) -> None:
        details = destination.stat()
        fd, name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
        temporary = Path(name)
        try:
            os.fchmod(fd, details.st_mode & 0o7777)
            if hasattr(os, "fchown"):
                os.fchown(fd, details.st_uid, details.st_gid)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
            directory_fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)
