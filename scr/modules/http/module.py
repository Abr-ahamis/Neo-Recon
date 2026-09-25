"""Baseline-aware HTTP probing and bounded native ffuf enumeration."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit

from scr.core.context import TargetContext, target_authority
from scr.core.evidence import write_json
from scr.core.output import collect
from scr.core.process import CommandRunner
from scr.core.resources import Access, Resource, ResourceStatus, TraversalLimits
from scr.core.tasks import Task, TaskState
from scr.core.terminal import TerminalManager
from scr.dependencies.manager import DependencyManager
from scr.engine.traversal import ResourceTraversal
from scr.modules.http import commands, parser, rules
from scr.modules.http.wordlists import bounded_copy, find_wordlist
from config import load_settings


class HTTPModule:
    service = "http"

    def __init__(self, context: TargetContext, *, port: int, tls: bool = False,
                 limits: TraversalLimits | None = None,
                 runner: CommandRunner | None = None,
                 terminals: TerminalManager | None = None,
                 execute: Callable[[Task], TaskState] | None = None) -> None:
        self.context = context
        self.port = port
        self.scheme = "https" if tls else "http"
        self.authority = target_authority(context.target, port)
        self.base_url = f"{self.scheme}://{self.authority}/"
        self.limits = limits or TraversalLimits()
        self.runner = runner or CommandRunner()
        self.terminals = terminals or TerminalManager()
        self.execute_task = execute
        self.traversal = ResourceTraversal(self.limits)
        self.baseline: parser.Response | None = None
        self._fuzzed: set[str] = set()

    @staticmethod
    def _ensure_ffuf() -> bool:
        if not shutil.which("ffuf"):
            DependencyManager(
                install_missing=load_settings().install_missing_dependencies
            ).ensure(("ffuf",))
        return shutil.which("ffuf") is not None

    def _task(self, url: str, label: str, headers: tuple[str, ...] = (),
              method: str | None = None) -> Task:
        key = hashlib.sha256((url + "|" + "|".join(headers) + "|" + (method or "GET")).encode()).hexdigest()[:16]
        output = self.context.scan_dir / "services/http" / f"{label}-{key}.raw"
        metadata = self.context.scan_dir / "metadata" / f"http-{label}-{key}.json"
        actual, display = commands.request(url, max_size=self.limits.max_download_size,
                                           headers=headers, method=method)
        return Task(f"http-{label}-{key}", self.context.target, "http", actual,
                    output, metadata, timeout=25, reason=f"HTTP {label}",
                    display_argv=display, resource_id=url)

    def _request(self, url: str, label: str,
                 headers: tuple[str, ...] = (),
                 method: str | None = None) -> tuple[TaskState, parser.Response]:
        task = self._task(url, label, headers, method)
        state = (self.execute_task(task) if self.execute_task else
                 self.terminals.execute(task, self.runner))
        if not self.execute_task and task.terminal_external and task.output_path.exists():
            collect("HTTP", task.display_argv or task.argv, task.output_path)
        raw = task.output_path.read_bytes() if task.output_path.exists() else b""
        response = parser.parse_response(raw, url)
        return state, response

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int | None]:
        parts = urlsplit(url)
        return parts.scheme, parts.hostname or "", parts.port

    def _enumerate(self, resource: Resource) -> list[Resource]:
        _, response = self._request(resource.path, "resource")
        if response.status is None:
            resource.status = ResourceStatus.FAILED
            return []
        if response.status in {401, 403, 407}:
            resource.metadata.update({"status_code": response.status,
                                      "content_type": response.headers.get("content-type"),
                                      "content_length": len(response.body),
                                      "permission_state": "AUTH_REQUIRED" if response.status in {401, 407} else "NO_ACCESS"})
            resource.authentication_required = response.status in {401, 407}
            resource.list_access = resource.read_access = Access.NO
            resource.status = ResourceStatus.INACCESSIBLE
            return []
        baseline = self.baseline
        if baseline is None or not rules.accepted(response, baseline):
            resource.status = ResourceStatus.INACCESSIBLE
            resource.list_access = Access.NO
            resource.read_access = Access.NO
            if (resource.path == self.base_url and response.status is not None
                    and self.execute_task is None):
                return self._fuzz_directory(resource)
            return []
        resource.metadata.update({"status_code": response.status,
                                  "content_type": response.headers.get("content-type"),
                                  "content_length": len(response.body),
                                  "redirect": response.headers.get("location"),
                                  "server": response.headers.get("server"),
                                  "title": parser.page_title(response.body),
                                  "allow": response.headers.get("allow"),
                                  "dav": response.headers.get("dav"),
                                  "resource_type": rules.path_type(resource.path, response)})
        resource.authentication_required = response.status in {401, 407}
        resource.list_access = Access.YES if resource.metadata["resource_type"] == "directory" else Access.UNKNOWN
        resource.read_access = Access.YES if 200 <= response.status < 400 else Access.NO
        self._record_links(response)
        children = rules.child_resources(resource, response, self.base_url, baseline)
        if self.execute_task is None and self._is_directory(resource) and resource.depth < min(self.limits.max_depth, 3):
            children.extend(self._fuzz_directory(resource))
        return children

    @staticmethod
    def _is_directory(resource: Resource) -> bool:
        return resource.resource_type == "directory" or urlsplit(resource.path).path.endswith("/")

    def _fuzz_directory(self, resource: Resource) -> list[Resource]:
        if (not self._ensure_ffuf() or resource.resource_id in self._fuzzed
                or len(self._fuzzed) >= 8):
            return []
        self._fuzzed.add(resource.resource_id)
        source = find_wordlist("web", rules.WORDLIST)
        if not source.is_file():
            return []
        key = hashlib.sha256(resource.path.encode()).hexdigest()[:12]
        scan = self.context.scan_dir
        wordlist = scan / "metadata" / "http-wordlists" / f"web-{key}.txt"
        json_output = scan / "metadata" / f"http-ffuf-{key}.json"
        if bounded_copy(source, wordlist, limit=250) == 0:
            return []
        url = resource.path if resource.path.endswith("/") else resource.path + "/"
        argv, display = commands.fuzz(url.rstrip("/") + "/FUZZ", wordlist, json_output)
        output = scan / "services/http" / f"ffuf-{key}.raw"
        metadata = scan / "metadata" / f"http-ffuf-{key}-command.json"
        task = Task(f"http-ffuf-{key}", self.context.target, "http", argv, output,
                    metadata, timeout=60, reason=f"HTTP wordlist discovery under {url}",
                    display_argv=display, resource_id=url)
        state = self.terminals.execute(task, self.runner)
        if task.terminal_external and output.exists():
            collect("HTTP", display, output)
        if state not in {TaskState.SUCCESS, TaskState.FAILED}:
            return []
        children = []
        for result in commands.parse_fuzz_results(json_output):
            candidate = result.get("input", {})
            word = candidate.get("FUZZ") if isinstance(candidate, dict) else None
            status = result.get("status")
            if not isinstance(status, int) or status in {404, 410}:
                continue
            found_url = result.get("url")
            if isinstance(found_url, str):
                if self._origin(found_url) != self._origin(self.base_url):
                    continue
                path = found_url
                word = urlsplit(found_url).path.rsplit("/", 1)[-1]
            else:
                if not isinstance(word, str) or not word or word.startswith(("/", "http://", "https://")):
                    continue
                path = urlunsplit((self.scheme, self.authority,
                                   urlsplit(url).path + word.lstrip("/"), "", ""))
            resource_type = rules.candidate_type(word)
            children.append(Resource("http", self.context.target, self.port, "tcp",
                                     resource_type, path, path=path,
                                     parent=resource.resource_id, depth=resource.depth + 1,
                                     metadata={"source": "ffuf", "status_code": status,
                                               "words": result.get("words"),
                                               "lines": result.get("lines"),
                                               "content_length": result.get("length")}))
        return children

    def _record_links(self, response: parser.Response) -> None:
        for url in parser.discover_links(response, response.url or self.base_url):
            host = urlsplit(url).hostname
            if host:
                self.context.add_hostname(host)

    def run(self) -> list[dict[str, object]]:
        # One base-page request provides the HTTP context. Discovery uses ffuf,
        # so the report is not filled with one curl transcript per candidate.
        _, self.baseline = self._request(self.base_url, "base")
        if self.baseline.status is None:
            return []
        root = Resource("http", self.context.target, self.port, "tcp", "endpoint",
                        self.base_url, path=self.base_url,
                        metadata={"url": self.base_url, "source": "root"})
        response = self.baseline
        root.metadata.update({"status_code": response.status,
                              "content_type": response.headers.get("content-type"),
                              "content_length": len(response.body),
                              "redirect": response.headers.get("location"),
                              "server": response.headers.get("server"),
                              "title": parser.page_title(response.body),
                              "allow": response.headers.get("allow"),
                              "dav": response.headers.get("dav")})
        root.authentication_required = response.status in {401, 407}
        root.read_access = Access.YES if response.status and 200 <= response.status < 400 else Access.NO
        if response.status in {401, 403, 407}:
            root.list_access = Access.NO
            root.metadata["permission_state"] = "AUTH_REQUIRED" if response.status in {401, 407} else "NO_ACCESS"
        self._record_links(response)
        resources = [root]
        if response.status not in {401, 403, 407} and self.execute_task is None:
            resources.extend(self._fuzz_directory(root))
        values = [item.to_dict() for item in resources]
        self.context.resources.update({item["resource_id"]: item for item in values})
        write_json(self.context.scan_dir / "metadata/http-resources.json", values)
        domain = self.context.facts.get("domain") or next(iter(sorted(self.context.domains)), None)
        if domain and self.execute_task is None:
            self._enumerate_vhosts(str(domain))
        return values

    def _enumerate_vhosts(self, domain: str) -> None:
        fallback = Path(__file__).resolve().parents[2] / "wordlists/common.txt"
        source = find_wordlist("vhost", fallback)
        wordlist = self.context.scan_dir / "metadata/http-vhosts-active.txt"
        try:
            bounded_copy(source, wordlist, limit=30)
            candidates = [line.strip() for line in wordlist.read_text(encoding="utf-8").splitlines()
                          if line.strip()]
        except OSError:
            return
        findings = []
        if self._ensure_ffuf():
            key = hashlib.sha256((self.base_url + domain).encode()).hexdigest()[:12]
            json_output = self.context.scan_dir / "metadata" / f"http-vhosts-{key}.json"
            argv, display = commands.fuzz(self.base_url, wordlist, json_output,
                                           headers=(f"Host: FUZZ.{domain}",))
            output = self.context.scan_dir / "services/http" / f"ffuf-vhosts-{key}.raw"
            metadata = self.context.scan_dir / "metadata" / f"http-vhosts-{key}-command.json"
            task = Task(f"http-vhosts-{key}", self.context.target, "http", argv,
                        output, metadata, timeout=60,
                        reason=f"HTTP virtual-host discovery for {domain}",
                        display_argv=display, resource_id=self.base_url)
            state = self.terminals.execute(task, self.runner)
            if task.terminal_external and output.exists():
                collect("HTTP", display, output)
            if state == TaskState.SUCCESS:
                candidates = [item.get("input", {}).get("FUZZ")
                              for item in commands.parse_fuzz_results(json_output)
                              if isinstance(item.get("input"), dict)]
        else:
            candidates = []
        for candidate in candidates:
            if not isinstance(candidate, str) or not candidate or "/" in candidate or " " in candidate:
                continue
            hostname = f"{candidate}.{domain}"
            self.context.add_hostname(hostname)
            findings.append({"hostname": hostname, "source": "ffuf"})
        write_json(self.context.scan_dir / "metadata/http-vhosts.json", findings)
