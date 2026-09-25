"""SMB share/listing parsing and local file classification."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from scr.core.resources import Access


_SHARE = re.compile(r"^\s*(\S.*?)\s{2,}(Disk|IPC|Printer|Device)\s*(.*?)\s*$", re.I)
_ENTRY = re.compile(r"^\s*(.+?)\s+([A-Z]+)\s+(\d+)\s{2,}(.+?)\s*$")
_ACCESS_DENIED = re.compile(r"ACCESS_DENIED|LOGON_FAILURE|NT_STATUS_ACCESS_DENIED|NT_STATUS_LOGON_FAILURE", re.I)
_MISSING = re.compile(r"BAD_NETWORK_NAME|OBJECT_PATH_NOT_FOUND|NO_SUCH_FILE", re.I)
_CONTEXT = re.compile(r"\b(Workgroup|Domain|OS|Server)=\[([^\]]*)\]", re.I)


def parse_shares(output: bytes | str) -> list[dict[str, str]]:
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output
    shares = []
    for line in text.splitlines():
        match = _SHARE.match(line)
        if match:
            name, kind, comment = match.groups()
            if name not in {"Sharename", "---------"} and not any(c in name for c in "/\\\0"):
                shares.append({"name": name.strip(), "kind": kind.lower(), "comment": comment.strip()})
    return shares


def parse_context(output: bytes | str) -> dict[str, str]:
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output
    return {key.lower(): value for key, value in _CONTEXT.findall(text)}


def access_result(output: bytes | str, exit_code: int) -> dict[str, Any]:
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output
    if _ACCESS_DENIED.search(text):
        return {"list_access": Access.NO, "read_access": Access.NO,
                "authentication_required": True, "permission_state": "AUTH_REQUIRED"}
    if _MISSING.search(text):
        return {"list_access": Access.NO, "read_access": Access.NO,
                "authentication_required": False, "permission_state": "NO_ACCESS"}
    if exit_code == 0:
        return {"list_access": Access.YES, "read_access": Access.UNKNOWN,
                "authentication_required": False, "permission_state": "LIST"}
    return {"list_access": Access.UNKNOWN, "read_access": Access.UNKNOWN,
            "authentication_required": None, "permission_state": "UNKNOWN"}


def classify_file(name: str, size: int, path: str = "", magic: bytes = b"") -> dict[str, Any]:
    lower = (name + " " + path).lower()
    suffix = PurePosixPath(name.lower()).suffix.lstrip(".")
    category = "binary"
    if b"-----BEGIN " in magic and b"PRIVATE KEY-----" in magic or suffix in {"key", "p12", "pfx"}:
        category = "private_key" if "key" in lower or b"PRIVATE KEY" in magic else "certificate"
    elif suffix in {"pem", "crt", "cer", "der"}:
        category = "certificate"
    elif any(x in lower for x in ("password", "credential", "secret", "token", "id_rsa")):
        category = "credential_like"
    elif suffix in {"conf", "cfg", "config", "ini", "env", "json", "xml", "yml", "yaml", "toml"}:
        category = "configuration"
    elif suffix in {"sql", "db", "sqlite", "sqlite3", "mdb", "bak"}:
        category = "database" if suffix in {"db", "sqlite", "sqlite3", "mdb", "sql"} else "backup"
    elif suffix in {"zip", "tar", "gz", "7z", "rar", "bz2", "xz"}:
        category = "archive"
    elif suffix in {"bak", "old", "backup", "dump", "orig", "save"}:
        category = "backup"
    elif suffix in {"py", "js", "ts", "java", "c", "cpp", "go", "rb", "php", "cs"}:
        category = "source_code"
    elif suffix in {"ps1", "sh", "bat", "cmd", "vbs", "pl"}:
        category = "script"
    elif suffix in {"log", "out"}:
        category = "log"
    elif suffix in {"txt", "md", "rtf", "doc", "docx", "pdf"}:
        category = "document"
    elif magic.startswith(b"PK\x03\x04"):
        category = "archive"
    elif magic.startswith(b"SQLite format 3"):
        category = "database"
    elif magic.startswith(b"%PDF"):
        category = "document"
    interesting = category in {"configuration", "credential_like", "backup", "database",
                               "archive", "source_code", "script", "log", "certificate", "private_key"}
    return {"filename": name, "path": path, "size": size, "extension": suffix,
            "category": category, "interesting": interesting,
            "download_eligible": interesting and 0 <= size}


def parse_listing(output: bytes | str, share: str, parent_path: str = "") -> list[dict[str, Any]]:
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output
    entries = []
    for line in text.splitlines():
        match = _ENTRY.match(line)
        if not match:
            continue
        name, attributes, size, _mtime = match.groups()
        name = name.strip()
        if (name in {".", ".."} or not name or
                any(c in name for c in "/\\\r\n\0")):
            continue
        path = "/".join(part for part in (parent_path.strip("/"), name) if part)
        if "D" in attributes:
            entries.append({"name": name, "path": path, "share": share,
                            "resource_type": "directory", "attributes": attributes})
        else:
            entries.append({**classify_file(name, int(size), path), "name": name,
                            "share": share, "resource_type": "file", "attributes": attributes})
    return entries
