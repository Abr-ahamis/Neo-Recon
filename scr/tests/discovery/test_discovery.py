from __future__ import annotations

import unittest
import os
import select
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

from scr.core.context import TargetContext
from scr.core.pty import run_pty
from scr.core.process import CommandRunner
from scr.core.terminal import TerminalManager
from scr.discovery.classifier import classify_all
from scr.discovery.nmap import command as nmap_command, parse_services
from scr.discovery.rustscan import command as rustscan_command, extract_ports, make_task as rustscan_task


class DiscoveryTests(unittest.TestCase):
    def test_rustscan_nmap_http_fingerprint_reaches_http_service_stage(self) -> None:
        class InlineTerminal(TerminalManager):
            def launch(self, title, argv, env=None):
                return None

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary_dir = root / "bin"
            binary_dir.mkdir()
            rustscan = binary_dir / "rustscan"
            rustscan.write_text("#!/usr/bin/env python3\nprint('Open 127.0.0.1:8080', flush=True)\n")
            rustscan.chmod(0o755)
            nmap = binary_dir / "nmap"
            nmap.write_text("#!/usr/bin/env python3\n"
                            "print('PORT     STATE SERVICE VERSION')\n"
                            "print('8080/tcp open  rtsp')\n"
                            "print('| fingerprint-strings:')\n"
                            "print('|   GetRequest:')\n"
                            "print('|     HTTP/1.0 200 OK')\n"
                            "print('|_http-title: Local fixture')\n")
            nmap.chmod(0o755)
            context = TargetContext("127.0.0.1", root / "scan")
            with patch.dict(os.environ, {"PATH": str(binary_dir) + os.pathsep + os.environ["PATH"]}):
                from scr.discovery.pipeline import discover
                services = discover(context, terminals=InlineTerminal(),
                                    runner=CommandRunner(stream_fd=None))
            self.assertEqual(context.tcp_ports, [8080])
            self.assertEqual(services[0]["module"], "http")

    def test_rustscan_commands_and_native_port_formats(self) -> None:
        self.assertEqual(rustscan_command("127.0.0.1"),
                         ["rustscan", "-a", "127.0.0.1"])
        self.assertEqual(rustscan_command("lab.local", port_spec="8080,8443",
                                          output_file="scan/rustscan-port"),
                         ["rustscan", "-a", "lab.local", "-p",
                          "8080,8443", "--", "-oN",
                          "scan/rustscan-port"])
        self.assertNotIn("-g", rustscan_command("lab.local", output_file="scan/out"))
        self.assertEqual(extract_ports(b"127.0.0.1 -> [22, 80, 443]\r\n"),
                         {"tcp": [22, 80, 443], "udp": []})
        data = (b"Host: lab.local ()\tPorts: 53/open/udp, 8080/open/tcp\n"
                b"Open 123/udp\nOpen 10.10.10.8:445\n")
        self.assertEqual(extract_ports(data), {"tcp": [445, 8080], "udp": [53, 123]})
        self.assertEqual(extract_ports(b"PORT STATE SERVICE\n53/udp open domain\n445/tcp open microsoft-ds\n"),
                         {"tcp": [445], "udp": [53]})

    def test_nmap_constructs_scoped_protocol_port_list(self) -> None:
        argv = nmap_command("lab.local", [443, 8080, 443], [53])
        self.assertEqual(argv[argv.index("-p") + 1], "T:443,8080,U:53")
        self.assertIn("-sU", argv)
        self.assertIn("-sV", argv)
        self.assertIn("-sC", argv)
        self.assertIn("-O", argv)
        self.assertEqual(nmap_command("lab.local", [8443]),
                         ["nmap", "-Pn", "-sC", "-sV", "-O", "-T4", "-p",
                          "T:8443", "-oN", "-", "lab.local"])
        self.assertNotIn("-n", nmap_command("lab.local", [8443]))
        self.assertIn("-6", nmap_command("2001:db8::1", [443]))

    def test_nmap_parser_and_fingerprint_classifier_ignore_port_number(self) -> None:
        output = ("PORT     STATE SERVICE VERSION\n"
                  "8080/tcp open  http    Apache httpd 2.4.58\n"
                  "8443/tcp open  ssl/http nginx 1.24\n"
                  "9999/tcp open  http    Docker Engine API\n"
                  "31337/tcp open  mystery custom protocol\n"
                  "53/udp   open  domain  dnsmasq 2.89\n")
        parsed = parse_services(output)
        classified = classify_all(parsed)
        self.assertEqual([x["module"] for x in classified],
                         ["http", "https", "unimplemented", "unknown", "dns"])
        self.assertEqual(classified[2]["service_family"], "docker")
        self.assertEqual(classified[2]["implementation"], "not-implemented")
        self.assertEqual(classified[3]["classification"], "unknown")
        self.assertEqual(classified[2]["classification_evidence"], "product-fingerprint")
        self.assertEqual(classify_all([{"port": 31337, "transport": "tcp", "service": "telnet",
                                        "details": ""}])[0]["module"], "unimplemented")
        live = classify_all([
            {"port": 445, "transport": "tcp", "service": "microsoft-ds?", "details": ""},
            {"port": 464, "transport": "tcp", "service": "kpasswd5?", "details": ""},
            {"port": 5985, "transport": "tcp", "service": "http",
             "details": "Microsoft HTTPAPI httpd 2.0"},
            {"port": 9389, "transport": "tcp", "service": "mc-nmf",
             "details": ".NET Message Framing"},
        ])
        self.assertEqual([item["service_family"] for item in live],
                         ["smb", "kerberos", "winrm", "adws"])
        self.assertEqual(live[2]["classification_evidence"], "product-port-fingerprint")

    def test_http_script_fingerprint_overrides_nmap_rtsp_soft_match(self) -> None:
        output = ("PORT     STATE SERVICE VERSION\n"
                  "80/tcp   open  rtsp\n"
                  "| fingerprint-strings:\n"
                  "|   GetRequest:\n"
                  "|     HTTP/1.0 200 OK\n"
                  "|_http-title: Mobile router\n"
                  "5555/tcp open  adb Android Debug Bridge device\n"
                  "SF-Port80-TCP:V=7.99%r(GetRequest,HTTP/1.0 200 OK)\n")
        parsed = parse_services(output)
        classified = classify_all(parsed)
        self.assertEqual(classified[0]["module"], "http")
        self.assertEqual(classified[1]["module"], "unknown")

    def test_nmap_host_identity_uses_only_explicit_evidence(self) -> None:
        from scr.discovery.nmap import extract_host_identity

        output = ("Nmap scan report for dc.support.htb (10.129.230.181)\n"
                  "| ldap-rootdse: Domain: support.htb\n"
                  "| smb-os-discovery: FQDN: dc.support.htb\n")
        self.assertEqual(extract_host_identity(output, "10.129.230.181"), {
            "target_ip": "10.129.230.181", "hostname": "dc",
            "fqdn": "dc.support.htb", "domain": "support.htb",
        })
        self.assertEqual(extract_host_identity("Nmap scan report for 10.0.0.2", "lab.local"), {
            "target_ip": "10.0.0.2", "hostname": None, "fqdn": None, "domain": None,
        })

    def test_rustscan_open_line_is_live_and_saved_before_process_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary_dir = root / "bin"
            binary_dir.mkdir()
            fake = binary_dir / "rustscan"
            fake.write_text("#!/usr/bin/env python3\n"
                            "import time\n"
                            "print('Open 127.0.0.1:9123', flush=True)\n"
                            "time.sleep(.6)\n"
                            "print('Scan complete', flush=True)\n")
            fake.chmod(0o755)
            context = TargetContext("127.0.0.1", root / "scan")
            task = rustscan_task(context, port_spec="9123")
            self.assertEqual(task.argv[:4],
                             ["rustscan", "-a", "127.0.0.1", "-p"])
            self.assertNotIn("-g", task.argv)
            self.assertEqual(task.argv[4:7], ["9123", "--", "-oN"])
            self.assertEqual(Path(task.argv[-1]), context.scan_dir / "discovery/rustscan-port")
            read_fd, write_fd = os.pipe()
            result: list[tuple[int, str]] = []
            env = os.environ.copy()
            env["PATH"] = str(binary_dir) + os.pathsep + env.get("PATH", "")
            thread = threading.Thread(target=lambda: result.append(run_pty(
                task.argv, task.output_path, 5, env=env, stream_fd=write_fd)))
            thread.start()
            self.assertTrue(select.select([read_fd], [], [], 1)[0])
            first = os.read(read_fd, 4096)
            self.assertIn(b"Open 127.0.0.1:9123", first)
            self.assertIn(b"Open 127.0.0.1:9123", task.output_path.read_bytes())
            self.assertTrue(thread.is_alive())
            captured = bytearray(first)
            while thread.is_alive() or select.select([read_fd], [], [], 0)[0]:
                if select.select([read_fd], [], [], .1)[0]:
                    chunk = os.read(read_fd, 4096)
                    if not chunk:
                        break
                    captured.extend(chunk)
                elif not thread.is_alive():
                    break
            thread.join(timeout=2)
            os.close(read_fd)
            os.close(write_fd)
            self.assertEqual(result, [(0, "SUCCESS")])
            self.assertEqual(bytes(captured), task.output_path.read_bytes())
            self.assertEqual(extract_ports(task.output_path.read_bytes()),
                             {"tcp": [9123], "udp": []})


if __name__ == "__main__":
    unittest.main()
