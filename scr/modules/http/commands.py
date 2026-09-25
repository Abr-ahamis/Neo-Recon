"""Native HTTP request command definitions."""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from urllib.parse import urlsplit
from scr.dependencies.tools import select_tool


def request(url: str, timeout: int = 15, max_size: int = 10 * 1024 * 1024,
            headers: tuple[str, ...] = (), method: str | None = None) -> tuple[list[str], list[str]]:
    script = str(Path(__file__).with_name("run.sh"))
    tool = select_tool("curl")
    if tool == "curl":
        display = ["curl", "--silent", "--show-error", "--include", "--max-filesize", str(max_size),
                   "--max-time", str(timeout), "--path-as-is"]
        if urlsplit(url).scheme == "https":
            display.append("--verbose")
        if method:
            display.extend(("--request", method))
        for header in headers:
            display.extend(("--header", header))
        display.append(url)
    else:
        display = ["wget", "--server-response", "--content-on-error", "--output-document=-",
                   "--timeout", str(timeout), "--quota", str(max_size), "--max-redirect=0"]
        if method:
            display.append(f"--method={method}")
        for header in headers:
            display.append(f"--header={header}")
        display.append(url)
    argv = ["bash", script, *display]
    return argv, display


def command_string(argv: list[str]) -> str:
    return shlex.join(argv)


def fuzz(url_template: str, wordlist: Path, json_output: Path, *,
         timeout: int = 45, threads: int = 20,
         headers: tuple[str, ...] = ()) -> tuple[list[str], list[str]]:
    display = ["ffuf", "-v", "-noninteractive", "-u", url_template,
               "-w", str(wordlist), "-maxtime", str(timeout),
               "-t", str(threads), "-of", "json", "-o", str(json_output)]
    for header in headers:
        display.extend(("-H", header))
    return ["bash", str(Path(__file__).with_name("run.sh")), *display], display


def parse_fuzz_results(path: Path) -> list[dict[str, object]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    results = document.get("results", []) if isinstance(document, dict) else []
    return [item for item in results if isinstance(item, dict)] if isinstance(results, list) else []
