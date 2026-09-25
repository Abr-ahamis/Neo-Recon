"""Locate installed discovery lists and make bounded per-scan copies."""

from __future__ import annotations

import os
from pathlib import Path


WEB_CANDIDATES = (
    "Discovery/Web-Content/common.txt",
    "Discovery/Web-Content/raft-small-words.txt",
    "dirb/wordlists/common.txt",
    "dirbuster/wordlists/directory-list-2.3-small.txt",
)
VHOST_CANDIDATES = (
    "Discovery/DNS/subdomains-top1million-5000.txt",
    "Discovery/DNS/subdomains-top1million-20000.txt",
)
SEARCH_ROOTS = (Path("/usr/share/seclists"), Path("/usr/share/wordlists"),
                Path("/usr/share/dirb"), Path("/usr/share/dirbuster"),
                Path("/opt"), Path("/usr/local/share"))


def find_wordlist(kind: str, fallback: Path) -> Path:
    """Prefer SecLists, then common system lists, and always return a usable path."""
    relative_candidates = WEB_CANDIDATES if kind == "web" else VHOST_CANDIDATES
    roots = []
    configured = os.environ.get("SECLISTS_DIR")
    if configured:
        roots.append(Path(configured).expanduser())
    roots.extend(SEARCH_ROOTS)
    for root in roots:
        for relative in relative_candidates:
            candidate = root / relative
            if candidate.is_file() and os.access(candidate, os.R_OK):
                return candidate
    # Support nonstandard SecLists installs while limiting the filesystem walk
    # to conventional shared wordlist locations.
    expected = {Path(value).name.lower() for value in relative_candidates}
    for root in roots:
        if not root.is_dir():
            continue
        try:
            for base, directories, files in os.walk(root):
                directories[:] = [name for name in directories
                                  if name not in {".git", "node_modules", "proc", "sys"}]
                match = next((name for name in files if name.lower() in expected), None)
                if match:
                    candidate = Path(base) / match
                    if os.access(candidate, os.R_OK):
                        return candidate
        except OSError:
            continue
    return fallback


def bounded_copy(source: Path, destination: Path, *, limit: int = 250) -> int:
    """Copy unique nonempty candidates without modifying an installed wordlist."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    seen: set[str] = set()
    with source.open(encoding="utf-8", errors="replace") as src, destination.open("w", encoding="utf-8") as dst:
        for raw in src:
            value = raw.strip()
            if not value or value.startswith("#") or value in seen:
                continue
            seen.add(value)
            dst.write(value + "\n")
            count += 1
            if count >= limit:
                break
    return count
