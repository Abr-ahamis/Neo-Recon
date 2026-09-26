"""Find suitable installed wordlists, preferring SecLists over local lists."""

from __future__ import annotations

import os
from pathlib import Path

SEARCH_ROOTS = (Path("/usr/share/seclists"), Path("/usr/share/SecLists"),
                Path("/usr/share/wordlists"), Path("/usr/share/dirb"),
                Path("/usr/share/dirbuster"), Path("/usr/local/share"),
                Path("/usr/share"), Path("/opt"))
PREFERRED = {
    "web": ("Discovery/Web-Content/raft-medium-directories.txt",
            "Discovery/Web-Content/common.txt", "Discovery/Web-Content/directory-list-2.3-small.txt"),
    "web-files": ("Discovery/Web-Content/raft-medium-files.txt",
                  "Discovery/Web-Content/raft-medium-words.txt"),
    "vhost": ("Discovery/DNS/subdomains-top1million-5000.txt",
              "Discovery/DNS/fierce-hostlist.txt", "Discovery/DNS/namelist.txt"),
    "usernames": ("Usernames/top-usernames-shortlist.txt",
                  "Usernames/xato-net-10-million-usernames.txt"),
}
LOCAL_NAMES = {
    "web": ("common.txt", "raft-medium-directories.txt", "directory-list-2.3-small.txt"),
    "web-files": ("raft-medium-files.txt", "common.txt"),
    "vhost": ("vhosts.txt", "subdomains-top1million-5000.txt", "common.txt"),
    "usernames": ("users.txt", "usernames.txt", "common.txt"),
}


def find_wordlist(kind: str, fallback: Path | None = None) -> Path | None:
    """Return SecLists first, then a matching file in known wordlist folders."""
    configured = os.environ.get("SECLISTS_DIR")
    roots = ([Path(configured).expanduser()] if configured else []) + list(SEARCH_ROOTS)
    for root in roots:
        for rel in PREFERRED.get(kind, ()):
            candidate = root / rel
            if candidate.is_file() and os.access(candidate, os.R_OK):
                return candidate
    names = {name.lower() for name in LOCAL_NAMES.get(kind, ())}
    for root in roots:
        if not root.is_dir():
            continue
        try:
            for base, dirs, files in os.walk(root):
                dirs[:] = [d for d in dirs if d not in {".git", "node_modules"}]
                for name in files:
                    candidate = Path(base) / name
                    if name.lower() in names and os.access(candidate, os.R_OK):
                        return candidate
        except OSError:
            continue
    return fallback if fallback and fallback.is_file() else None


def bounded_copy(source: Path, destination: Path, *, limit: int | None = None) -> int:
    """Copy unique, non-comment entries. None preserves the source list size."""
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
            if limit is not None and count >= limit:
                break
    return count
