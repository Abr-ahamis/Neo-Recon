"""FTP listing, access and file metadata parsing."""

import re
from pathlib import PurePosixPath
from typing import Any

from scr.core.resources import Access

_DENIED = re.compile(r"530|not logged in|permission denied|login incorrect", re.I)
_INTERESTING = {"conf", "cfg", "config", "ini", "env", "json", "xml", "yml", "yaml", "txt",
                "log", "bak", "old", "zip", "tar", "gz", "7z", "rar", "sql", "db", "sqlite",
                "py", "sh", "ps1", "php", "pem", "key", "crt", "csv"}
_UNIX = re.compile(r"^([bcdlps-][rwxStTs-]{9})\s+\d+\s+\S+\s+\S+\s+(\d+)\s+\S+\s+\S+\s+\S+\s+(.+)$")
_DOS = re.compile(r"^\d{2}-\d{2}-\d{2,4}\s+\d{1,2}:\d{2}[AP]M\s+(<DIR>|\d+)\s+(.+)$", re.I)


def listing(output: bytes | str) -> list[dict[str, Any]]:
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output
    found = []
    for line in text.splitlines():
        line = line.strip()
        match, dos = _UNIX.match(line), _DOS.match(line)
        if match:
            permissions, size_text, name = match.groups()
            is_dir, size = permissions[0] == "d", int(size_text)
        elif dos:
            size_text, name = dos.groups()
            is_dir, size = size_text.upper() == "<DIR>", (0 if size_text.upper() == "<DIR>" else int(size_text))
        else:
            name, is_dir, size = line, False, None
        name = name.strip()
        if not name or name in {".", ".."} or any(c in name for c in "/\\\0\r\n"):
            continue
        suffix = PurePosixPath(name.lower()).suffix.lstrip(".")
        is_file = not is_dir and suffix in _INTERESTING
        category = ("credential_like" if any(w in name.lower() for w in
                    ("credential", "password", "secret", "token")) else
                    "configuration" if suffix in {"conf", "cfg", "config", "ini", "env", "json", "xml"} else
                    "backup" if suffix in {"bak", "old", "zip", "tar", "gz", "7z", "rar"} else
                    "database" if suffix in {"sql", "db", "sqlite"} else "file")
        found.append({"name": name, "path": name,
                      "resource_type": "file" if is_file else "directory",
                      "size": size, "extension": suffix, "interesting": is_file, "category": category})
    return found


def access(output: bytes | str, exit_code: int) -> dict[str, Any]:
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output
    if _DENIED.search(text):
        return {"list_access": Access.NO, "read_access": Access.NO,
                "authentication_required": True, "permission_state": "AUTH_REQUIRED"}
    if exit_code == 0:
        return {"list_access": Access.YES, "read_access": Access.UNKNOWN,
                "authentication_required": False, "permission_state": "LIST"}
    return {"list_access": Access.NO, "read_access": Access.UNKNOWN,
            "authentication_required": None, "permission_state": "NO_ACCESS"}
