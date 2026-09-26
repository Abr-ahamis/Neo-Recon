"""Baseline-aware HTTP probing and bounded native ffuf enumeration."""

from __future__ import annotations

import hashlib
import shlex
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
            result = DependencyManager(
                install_missing=load_settings().install_missing_dependencies
            ).ensure(("ffuf",))
            if result.missing:
                print("[HTTP] ffuf is missing. Install with: sudo apt-get install -y ffuf "
                      "(or: sudo pacman -S --needed ffuf)")
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
        source = find_wordlist("web", Path(__file__).resolve().parents[2] / "wordlists/common.txt")
        if source is None or not source.is_file():
            print("[HTTP] No web wordlist found. Install SecLists or place a list under "
                  "scr/wordlists, then run: ffuf -u <BASE_URL>/FUZZ -w <WORDLIST> -mc all")
            return []
        key = hashlib.sha256(resource.path.encode()).hexdigest()[:12]
        scan = self.context.scan_dir
        wordlist = scan / "metadata" / "http-wordlists" / f"web-{key}.txt"
        json_output = scan / "metadata" / f"http-ffuf-{key}.json"
        if bounded_copy(source, wordlist) == 0:
            return []
        url = resource.path if resource.path.endswith("/") else resource.path + "/"
        baseline_size = len(self.baseline.body) if self.baseline else None
        argv, display = commands.fuzz(url.rstrip("/") + "/FUZZ", wordlist, json_output,
                                      filter_size=baseline_size)
        output = scan / "services/http" / f"ffuf-{key}.raw"
        metadata = scan / "metadata" / f"http-ffuf-{key}-command.json"
        task = Task(f"http-ffuf-{key}", self.context.target, "http", argv, output,
                    metadata, timeout=60, reason=f"HTTP wordlist discovery under {url}",
                    display_argv=display, resource_id=url, new_terminal=True)
        state = self.terminals.execute(task, self.runner)
        if task.terminal_external and output.exists():
            collect("HTTP", display, output)
        if state not in {TaskState.SUCCESS, TaskState.FAILED}:
            return []
        result_sets = [commands.parse_fuzz_results(json_output)]
        file_source = find_wordlist("web-files", None)
        if file_source:
            file_wordlist = scan / "metadata" / "http-wordlists" / f"files-{key}.txt"
            if bounded_copy(file_source, file_wordlist):
                file_json = scan / "metadata" / f"http-ffuf-files-{key}.json"
                file_argv, file_display = commands.fuzz(
                    url.rstrip("/") + "/FUZZ", file_wordlist, file_json,
                    filter_size=baseline_size,
                    extensions=(".asp", ".aspx", ".html", ".txt", ".bak", ".zip", ".config", ".old"))
                file_output = scan / "services/http" / f"ffuf-files-{key}.raw"
                file_task = Task(f"http-ffuf-files-{key}", self.context.target, "http",
                                 file_argv, file_output,
                                 scan / "metadata" / f"http-ffuf-files-{key}-command.json",
                                 timeout=120, reason=f"HTTP file discovery under {url}",
                                 display_argv=file_display, resource_id=url, new_terminal=True)
                file_state = self.terminals.execute(file_task, self.runner)
                if file_task.terminal_external and file_output.exists():
                    collect("HTTP", file_display, file_output)
                if file_state in {TaskState.SUCCESS, TaskState.FAILED}:
                    result_sets.append(commands.parse_fuzz_results(file_json))
        else:
            print("[HTTP] No file wordlist found; directory fuzzing still ran. "
                  "Use SecLists Discovery/Web-Content/raft-medium-files.txt when available.")
        children = []
        for result in (item for group in result_sets for item in group):
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
        if self.execute_task is None:
            self._print_manual_commands(str(domain) if domain else None)
        return values

    def _enumerate_vhosts(self, domain: str) -> None:
        fallback = Path(__file__).resolve().parents[2] / "wordlists/web/vhosts.txt"
        source = find_wordlist("vhost", fallback)
        if source is None:
            command = (f"ffuf -u {self.base_url} -H 'Host: FUZZ.{domain}' "
                       "-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc all")
            print(f"[HTTP] No vhost wordlist found. Run manually: {command}")
            return
        wordlist = self.context.scan_dir / "metadata/http-vhosts-active.txt"
        try:
            bounded_copy(source, wordlist)
            candidates = [line.strip() for line in wordlist.read_text(encoding="utf-8").splitlines()
                          if line.strip()]
        except OSError:
            return
        findings = []
        if self._ensure_ffuf():
            key = hashlib.sha256((self.base_url + domain).encode()).hexdigest()[:12]
            json_output = self.context.scan_dir / "metadata" / f"http-vhosts-{key}.json"
            argv, display = commands.fuzz(self.base_url, wordlist, json_output,
                                           headers=(f"Host: FUZZ.{domain}",),
                                           filter_size=len(self.baseline.body) if self.baseline else None)
            output = self.context.scan_dir / "services/http" / f"ffuf-vhosts-{key}.raw"
            metadata = self.context.scan_dir / "metadata" / f"http-vhosts-{key}-command.json"
            task = Task(f"http-vhosts-{key}", self.context.target, "http", argv,
                        output, metadata, timeout=60,
                        reason=f"HTTP virtual-host discovery for {domain}",
                        display_argv=display, resource_id=self.base_url, new_terminal=True)
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

    def _print_manual_commands(self, domain: str | None) -> None:
        """Print five useful, copy-ready follow-up commands after automated fuzzing."""
        root = Path(__file__).resolve().parents[2]
        directories = find_wordlist("web", root / "wordlists/common.txt")
        files = find_wordlist("web-files", root / "wordlists/common.txt")
        vhosts = find_wordlist("vhost", root / "wordlists/web/vhosts.txt")
        directory_list = shlex.quote(str(directories)) if directories else "<DIRECTORY_WORDLIST>"
        file_list = shlex.quote(str(files)) if files else "<FILE_WORDLIST>"
        vhost_list = shlex.quote(str(vhosts)) if vhosts else "<VHOST_WORDLIST>"
        base = self.base_url.rstrip("/")
        baseline_filter = f" -fs {len(self.baseline.body)}" if self.baseline else ""
        commands_to_run = [
            f"ffuf -u {base}/FUZZ -w {directory_list}{baseline_filter} -ac -t 40 -of json -o ffuf-directories.json",
            f"ffuf -u {base}/FUZZ -w {file_list} -e .asp,.aspx,.html,.txt,.bak,.zip,.config,.old{baseline_filter} -ac -t 40 -of json -o ffuf-files.json",
            (f"ffuf -u {base}/ -H 'Host: FUZZ.{domain or '<DOMAIN>'}' -w {vhost_list} "
             f"{baseline_filter.strip()} -ac -t 40 -of json -o ffuf-vhosts.json"),
            f"gobuster dir -u {base}/ -w {directory_list} -x asp,aspx,html,txt,bak,zip,config,old -s 200,204,301,302,307,401,403 -t 40 -o gobuster-directories.txt",
            f"feroxbuster --url {base}/ --wordlist {directory_list} --extensions asp,aspx,html,txt,bak,zip,config,old --status-codes 200 204 301 302 307 401 403 --threads 20 --output feroxbuster-results.txt",
        ]
        print("\n[HTTP] Automated vhost, directory, and file enumeration finished.")
        print("Suggested commands (copy and run):")
        for index, command in enumerate(commands_to_run, start=1):
            print(f"{index}. {command}")
