"""HTTP response parsing; source output bytes remain stored unchanged."""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit


@dataclass(frozen=True)
class Response:
    status: int | None
    headers: dict[str, str]
    body: bytes
    url: str = ""

    @property
    def signature(self) -> tuple[int | None, int, int, int, str, str]:
        text = self.body.decode("utf-8", errors="replace")
        return (self.status, len(self.body), len(text.split()), len(text.splitlines()),
                self.headers.get("location", ""), self.headers.get("content-type", "").split(";", 1)[0])


def parse_response(raw: bytes, url: str = "") -> Response:
    # curl --include can contain interim/proxy response blocks; use the final header block.
    blocks = raw.replace(b"\r\n", b"\n").split(b"\n\n")
    status = None
    headers: dict[str, str] = {}
    body = raw
    for index, block in enumerate(blocks):
        values = block.splitlines()
        if not values:
            continue
        first, *lines = values
        if first.startswith(b"HTTP/"):
            try:
                status = int(first.split(None, 2)[1])
            except (ValueError, IndexError):
                status = None
            headers = {}
            for line in lines:
                if b":" in line:
                    key, value = line.split(b":", 1)
                    headers[key.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()
            body = b"\n\n".join(blocks[index + 1:])
    return Response(status, headers, body, url)


def similar(left: bytes, right: bytes) -> float:
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, left[:65536], right[:65536], autojunk=False).ratio()


def is_soft_404(response: Response, baseline: Response, threshold: float = 0.92) -> bool:
    if response.status in {404, 410}:
        return True
    if response.signature == baseline.signature:
        return True
    return similar(response.body, baseline.body) >= threshold


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.values: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = dict(attrs)
        for key in ("href", "src", "action"):
            value = attrs_map.get(key)
            if value:
                self.values.append(value)


class _Title(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.inside = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.inside = self.inside or tag.lower() == "title"

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.inside = False

    def handle_data(self, data: str) -> None:
        if self.inside:
            self.parts.append(data)


def page_title(body: bytes) -> str | None:
    parser = _Title()
    try:
        parser.feed(body.decode("utf-8", errors="replace"))
    except Exception:
        return None
    value = " ".join(" ".join(parser.parts).split())
    return value or None


def discover_links(response: Response, base_url: str) -> list[str]:
    parser = _Links()
    try:
        parser.feed(response.body.decode("utf-8", errors="replace"))
    except Exception:
        return []
    base = urlsplit(base_url)
    found: set[str] = set()
    values = list(parser.values)
    if response.headers.get("location"):
        values.append(response.headers["location"])
    for value in values:
        candidate = urlsplit(urljoin(base_url, value))
        if candidate.scheme not in {"http", "https"} or candidate.netloc.lower() != base.netloc.lower():
            continue
        path = candidate.path or "/"
        if not path.startswith("/"):
            continue
        found.add(urlunsplit((base.scheme, base.netloc, path, candidate.query, "")))
    return sorted(found)


def resource_kind(url: str, response: Response) -> str:
    path = urlsplit(url).path
    if path.endswith("/"):
        return "directory"
    if response.headers.get("content-type", "").startswith("text/html"):
        return "endpoint"
    return "file"
