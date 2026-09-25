from __future__ import annotations

import tempfile
import shutil
import unittest
import json
import os
import subprocess
import sys
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from unittest.mock import patch

from scr.core.context import TargetContext
from scr.core.resources import TraversalLimits
from scr.core.tasks import TaskState
from scr.core.process import CommandRunner
from scr.core.terminal import TerminalManager
from scr.modules.http.module import HTTPModule
from scr.modules.http.parser import discover_links, is_soft_404, parse_response
from scr.modules.http.commands import fuzz, parse_fuzz_results, request
from scr.modules.http.rules import initial_paths
from scr.modules.http.wordlists import bounded_copy, find_wordlist
from scr.core.suggestions import service_suggestions


class HTTPParserTests(unittest.TestCase):
    def test_wordlist_search_prefers_seclists_and_bounds_scan_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seclists = root / "Discovery/Web-Content"
            seclists.mkdir(parents=True)
            source = seclists / "common.txt"
            source.write_text("admin\\n#comment\\nlogin\\nadmin\\n".replace("\\n", "\n"))
            with patch("scr.modules.http.wordlists.SEARCH_ROOTS", (root,)):
                self.assertEqual(find_wordlist("web", Path("fallback.txt")), source)
                self.assertEqual(find_wordlist("vhost", Path("fallback.txt")), source)
            copied = root / "scan/wordlist.txt"
            self.assertEqual(bounded_copy(source, copied, limit=2), 2)
            self.assertEqual(copied.read_text(), "admin\nlogin\n")

    def test_wordlist_search_finds_common_txt_anywhere_under_wordlists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "nested" / "Discovery" / "Web-Content" / "common.txt"
            source.parent.mkdir(parents=True)
            source.write_text("admin\n")
            with patch("scr.modules.http.wordlists.SEARCH_ROOTS", (root,)):
                self.assertEqual(find_wordlist("web", Path("fallback.txt")), source)
                self.assertEqual(find_wordlist("vhost", Path("fallback.txt")), source)

    def test_ffuf_command_and_result_parser(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wordlist, result_file = root / "words.txt", root / "result.json"
            argv, display = fuzz("http://example.test/FUZZ", wordlist, result_file)
            self.assertEqual(display[0], "ffuf")
            self.assertIn(str(wordlist), display)
            self.assertNotIn("-ac", display)
            self.assertIn("-of", display)
            result_file.write_text('{"results":[{"input":{"FUZZ":"admin/"},"status":200}]}')
            self.assertEqual(parse_fuzz_results(result_file)[0]["status"], 200)

    def test_response_baseline_links_and_soft_404(self) -> None:
        baseline = parse_response(b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\nmissing")
        soft = parse_response(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nmissing")
        real = parse_response(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<a href='/admin/'>Admin</a>",
                              "http://127.0.0.1:8080/")
        self.assertTrue(is_soft_404(soft, baseline))
        self.assertFalse(is_soft_404(real, baseline))
        self.assertEqual(discover_links(real, real.url), ["http://127.0.0.1:8080/admin/"])
        from scr.modules.http.parser import page_title
        self.assertEqual(page_title(b"<html><title> Lab  Portal </title></html>"), "Lab Portal")

    def test_quick_wordlist_is_bounded_and_http_headers_are_configurable(self) -> None:
        paths = initial_paths()
        self.assertLessEqual(len(paths), 50)
        self.assertIn(".env", paths)
        self.assertIn("backup.zip", paths)
        self.assertIn("config.json", paths)
        _, display = request("http://127.0.0.1/", headers=("Host: dev.lab.example",))
        self.assertIn("--header", display)
        self.assertIn("Host: dev.lab.example", display)

    def test_registered_wget_fallback_is_selected_when_curl_is_missing(self) -> None:
        with patch("scr.dependencies.tools.shutil.which",
                   side_effect=lambda name: "/usr/bin/wget" if name == "wget" else None):
            _, display = request("http://192.0.2.10/", headers=("Host: dev.lab.example",))
        self.assertEqual(display[0], "wget")
        self.assertTrue(any("Host: dev.lab.example" in item for item in display))
        self.assertTrue(any("--quota" in item for item in display))

    def test_http_suggestions_use_discovered_host_and_small_wordlists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = TargetContext("192.0.2.10", Path(directory), domains={"lab.example"},
                                    facts={"domain": "lab.example"}, resources={
                "one": {"service": "http", "path": "http://192.0.2.10:8080/admin/",
                        "read_access": "YES"}
            })
            commands = service_suggestions("http", context, 8080)
            self.assertLessEqual(len(commands), 5)
            self.assertTrue(any("curl -i" in command and "/admin/" in command for command in commands))
            if shutil.which("ffuf"):
                self.assertEqual(len(commands), 5)
                self.assertTrue(any("FUZZ.lab.example" in command and "http-vhosts-suggestions.txt" in command
                                    for command in commands))
                fuzz_command = next(command for command in commands if "FUZZ" in command and "-H" not in command)
                self.assertIn("http-web-suggestions.txt", fuzz_command)
                wordlist = Path(directory) / "metadata/http-web-suggestions.txt"
                self.assertTrue(wordlist.is_file())
                self.assertLessEqual(len(wordlist.read_text().splitlines()), 250)


class HTTPAdaptiveTests(unittest.TestCase):
    def test_one_base_request_collects_context_without_repeated_curls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = TargetContext("127.0.0.1", Path(directory))
            seen: list[str] = []

            def execute(task):
                url = task.resource_id
                seen.append(url)
                path = "/" + url.split("://", 1)[1].split("/", 1)[1]
                status, body = (200, b"<title>Lab</title><a href='/admin/'>admin</a><a href='/backup.zip'>backup</a>")
                task.output_path.parent.mkdir(parents=True, exist_ok=True)
                task.output_path.write_bytes(
                    f"HTTP/1.1 {status} Test\r\nContent-Type: text/html\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body
                )
                task.state = TaskState.SUCCESS
                return TaskState.SUCCESS

            module = HTTPModule(context, port=8080, execute=execute,
                                limits=TraversalLimits(max_workers=3, max_depth=5))
            resources = module.run()
            self.assertEqual(seen, ["http://127.0.0.1:8080/"])
            self.assertEqual(len(resources), 1)
            self.assertEqual(resources[0]["metadata"]["title"], "Lab")
            self.assertIn("127.0.0.1", context.hostnames)

    def test_auth_required_and_forbidden_results_are_not_readable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = TargetContext("127.0.0.1", Path(directory))

            def execute(task):
                url = task.resource_id
                status = 404 if "not-found" in url else 401 if url.endswith("/") else 403
                body = b"missing" if status == 404 else b"restricted"
                task.output_path.parent.mkdir(parents=True, exist_ok=True)
                task.output_path.write_bytes(f"HTTP/1.1 {status} Result\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
                return TaskState.SUCCESS

            values = HTTPModule(context, port=8080, execute=execute).run()
            root = next(item for item in values if item["path"].endswith(":8080/"))
            self.assertEqual(root["authentication_required"], True)
            self.assertEqual(root["read_access"], "NO")
            self.assertEqual(root["metadata"]["permission_state"], "AUTH_REQUIRED")

    @unittest.skipUnless(shutil.which("curl"), "curl is required for the service worker integration")
    def test_complete_http_worker_runs_in_one_inline_service_process(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"<title>local test</title>" if self.path == "/" else b"missing"
                self.send_response(200 if self.path == "/" else 404)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_OPTIONS(self):
                self.send_response(204)
                self.send_header("Allow", "GET, HEAD, OPTIONS")
                self.end_headers()

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                scan_dir = root / "scan"
                for name in ("services", "metadata"):
                    (scan_dir / name).mkdir(parents=True)
                result_path = scan_dir / "metadata/service-result.json"
                manifest = root / "service.json"
                manifest.write_text(json.dumps({
                    "service": "http", "target": "127.0.0.1",
                    "port": server.server_address[1], "transport": "tcp",
                    "scan_dir": str(scan_dir), "result_path": str(result_path),
                    "hostnames": [], "domains": [], "services": [],
                    "tcp_ports": [], "udp_ports": [], "credentials": [], "facts": {},
                    "limits": {"max_depth": 2, "max_tasks": 8, "max_files": 20,
                               "max_directories": 20, "max_download_size": 1024 * 1024,
                               "max_workers": 3},
                }))
                env = os.environ.copy()
                env.pop("NEO_RECON_SERVICE_WORKER", None)
                result = subprocess.run([sys.executable, "-m", "scr.core.service_worker",
                                          str(manifest)], cwd=Path(__file__).resolve().parents[3],
                                         env=env, capture_output=True, timeout=15, check=False)
                self.assertEqual(result.returncode, 0,
                                 result.stderr.decode(errors="replace") + result.stdout.decode(errors="replace")
                                 + (result_path.read_text() if result_path.exists() else "no worker result"))
                state = json.loads(result_path.read_text())
                self.assertEqual(state["state"], "SUCCESS")
                raw = list((scan_dir / "services/http").glob("*.raw"))
                self.assertGreaterEqual(len(raw), 1)
                self.assertTrue(any(b"local test" in item.read_bytes() for item in raw))
                self.assertFalse(any(b"OPTIONS" in item.read_bytes() for item in raw))
                self.assertIn(b"Suggested commands (copy and run)", result.stdout)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    @unittest.skipUnless(shutil.which("curl") and shutil.which("ffuf"),
                         "curl and ffuf are required for local HTTP fuzz integration")
    def test_native_curl_worker_against_localhost(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                values = {"/": (200, b"<a href='/admin/'>admin</a>"),
                          "/admin/": (200, b"<a href='config.php'>config</a>"),
                          "/admin/config.php": (200, b"configuration"),
                          "/fuzz-only/": (200, b"found only by ffuf"),
                          "/robots.txt": (404, b"missing")}
                status, body = values.get(self.path, (404, b"missing"))
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        class InlineTerminal(TerminalManager):
            def launch(self, title, argv, env=None):
                return None

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                context = TargetContext("127.0.0.1", Path(directory))
                wordlist_root = Path(directory) / "seclists"
                custom_list = wordlist_root / "Discovery/Web-Content/common.txt"
                custom_list.parent.mkdir(parents=True)
                custom_list.write_text("admin/\nadmin/config.php\nfuzz-only/\n")
                module = HTTPModule(context, port=server.server_address[1], runner=CommandRunner(stream_fd=None),
                                    terminals=InlineTerminal(),
                                    limits=TraversalLimits(max_depth=4, max_workers=3))
                prior_wordlists = os.environ.get("SECLISTS_DIR")
                os.environ["SECLISTS_DIR"] = str(wordlist_root)
                try:
                    resources = module.run()
                finally:
                    if prior_wordlists is None:
                        os.environ.pop("SECLISTS_DIR", None)
                    else:
                        os.environ["SECLISTS_DIR"] = prior_wordlists
                paths = {item["path"] for item in resources}
                self.assertTrue(any(path.endswith("/admin/config.php") for path in paths), paths)
                self.assertTrue(any(path.endswith("/fuzz-only/") for path in paths), paths)
                raw_logs = list((Path(directory) / "services/http").glob("*.raw"))
                self.assertGreaterEqual(len(raw_logs), 2)
                self.assertTrue(any(b"HTTP/1.0 200" in log.read_bytes() for log in raw_logs))
                fuzz_logs = list((Path(directory) / "services/http").glob("ffuf-*.raw"))
                self.assertTrue(fuzz_logs, "HTTP module did not launch ffuf")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
