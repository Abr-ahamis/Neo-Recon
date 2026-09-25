"""Read-only smbclient command builders."""

from __future__ import annotations

from pathlib import Path


RUNNER = Path(__file__).with_name("run.sh")


def _wrap(native: list[str]) -> tuple[list[str], list[str]]:
    return [str(RUNNER), *native], native


def list_shares(target: str, port: int, auth_file: Path | None = None) -> tuple[list[str], list[str]]:
    auth = ["-A", str(auth_file)] if auth_file else ["-N"]
    return _wrap(["smbclient", "-p", str(port), *auth, "-L", f"//{target}"])


def list_directory(target: str, port: int, share: str, path: str = "",
                   auth_file: Path | None = None) -> tuple[list[str], list[str]]:
    auth = ["-A", str(auth_file)] if auth_file else ["-N"]
    native = ["smbclient", "-p", str(port), *auth, f"//{target}/{share}"]
    if path:
        native.extend(("-D", path))
    native.extend(("-c", "ls"))
    return _wrap(native)


def download_file(target: str, port: int, share: str, path: str, filename: str,
                  destination: Path, auth_file: Path | None = None) -> tuple[list[str], list[str]]:
    if any(ch in filename for ch in "\r\n\0"):
        raise ValueError("invalid remote filename")
    quoted_name = filename.replace("\\", "\\\\").replace('"', '\\"')
    quoted_dest = str(destination).replace("\\", "\\\\").replace('"', '\\"')
    auth = ["-A", str(auth_file)] if auth_file else ["-N"]
    native = ["smbclient", "-p", str(port), *auth, f"//{target}/{share}"]
    if path:
        native.extend(("-D", path))
    native.extend(("-c", f'get "{quoted_name}" "{quoted_dest}"'))
    return _wrap(native)
