"""Deterministic HTTP result-to-resource rules."""

from __future__ import annotations

from urllib.parse import urlsplit
from pathlib import PurePosixPath
from pathlib import Path

from scr.core.resources import Access, Resource
from scr.modules.http.parser import Response, discover_links, is_soft_404, resource_kind

SEEDS = ("robots.txt", "sitemap.xml", "admin/", "login", ".env", "config.php",
         "backup.zip", "database.sql", "api/")
WORDLIST = Path(__file__).resolve().parents[2] / "wordlists/web/quick.txt"


def initial_paths() -> tuple[str, ...]:
    try:
        values = WORDLIST.read_text(encoding="utf-8").splitlines()
    except OSError:
        values = []
    return tuple(dict.fromkeys((*SEEDS, *(value.strip() for value in values if value.strip()))))


def candidate_type(path: str) -> str:
    parsed = urlsplit(path)
    name = PurePosixPath(parsed.path).name
    if parsed.path.endswith("/"):
        return "directory"
    if PurePosixPath(name).suffix or name.startswith("."):
        return "file"
    return "endpoint"


def child_resources(parent: Resource, response: Response, base_url: str,
                    baseline: Response) -> list[Resource]:
    children = []
    for url in discover_links(response, response.url or base_url):
        if url == parent.path:
            continue
        resource_type = candidate_type(url)
        children.append(Resource(
            "http", parent.target, parent.port, parent.protocol, resource_type, url,
            path=url, parent=parent.resource_id, depth=parent.depth + 1,
            list_access=Access.UNKNOWN, read_access=Access.UNKNOWN,
            authentication_required=None, metadata={"url": url, "source": "link"},
        ))
    return children


def accepted(response: Response, baseline: Response) -> bool:
    return response.status is not None and not is_soft_404(response, baseline)


def path_type(url: str, response: Response) -> str:
    return resource_kind(url, response)


def path_depth(url: str) -> int:
    return len([part for part in urlsplit(url).path.split("/") if part])
