"""Native curl command definitions for FTP."""

from pathlib import Path
from urllib.parse import quote
from scr.dependencies.tools import select_tool


def list_path(url: str, timeout: int = 20) -> tuple[list[str], list[str]]:
    tool = select_tool("curl")
    display = (["curl", "--silent", "--show-error", "--user", "anonymous:",
                "--max-time", str(timeout), url] if tool == "curl" else
               ["wget", "--output-document=-", "--timeout", str(timeout), url])
    return ["bash", str(Path(__file__).with_name("run.sh")), *display], display


def file_probe(url: str, max_size: int, timeout: int = 20) -> tuple[list[str], list[str]]:
    tool = select_tool("curl")
    display = (["curl", "--silent", "--show-error", "--include", "--max-filesize", str(max_size),
                "--user", "anonymous:", "--max-time", str(timeout), url] if tool == "curl" else
               ["wget", "--server-response", "--content-on-error", "--output-document=-",
                "--timeout", str(timeout), "--quota", str(max_size), url])
    return ["bash", str(Path(__file__).with_name("run.sh")), *display], display


def file_metadata(url: str, max_size: int, timeout: int = 20) -> tuple[list[str], list[str]]:
    tool = select_tool("curl")
    display = (["curl", "--silent", "--show-error", "--head", "--user", "anonymous:",
                "--max-filesize", str(max_size), "--max-time", str(timeout), url] if tool == "curl" else
               ["wget", "--server-response", "--spider", "--timeout", str(timeout), url])
    return ["bash", str(Path(__file__).with_name("run.sh")), *display], display


def child_url(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + quote(path.strip("/"), safe="/!$&'()*+,;=:@-._~%")
