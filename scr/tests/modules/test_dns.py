from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scr.core.context import TargetContext
from scr.core.tasks import TaskState
from scr.modules.dns.module import DNSModule
from scr.modules.dns.parser import answers
from scr.modules.dns.commands import query
from unittest.mock import patch


class DNSTests(unittest.TestCase):
    def test_answers_parser(self) -> None:
        parsed = answers("""lab.example. 3600 IN SOA ns.lab.example. hostmaster.lab.example. 1 2 3 4 5
lab.example. 3600 IN NS ns.lab.example.
ns.lab.example. 3600 IN A 192.0.2.5
""")
        self.assertEqual([item["type"] for item in parsed], ["SOA", "NS", "A"])
        self.assertEqual(parsed[0]["name"], "lab.example")

    def test_registered_host_fallback_parses_common_answers(self) -> None:
        with patch("scr.dependencies.tools.shutil.which",
                   side_effect=lambda name: "/usr/bin/host" if name == "host" else None):
            _, display = query("lab.example", "A", server="192.0.2.10", port=5353)
        self.assertEqual(display[0], "host")
        self.assertIn("5353", display)
        parsed = answers("lab.example has address 192.0.2.44\n")
        self.assertEqual(parsed, [{"name": "lab.example", "type": "A", "value": "192.0.2.44"}])

    def test_soa_drives_tcp_udp_followups_and_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = TargetContext("lab.example", Path(directory))
            calls = []

            def execute(task):
                args = task.display_argv
                calls.append(args)
                record = args[-1]
                name = args[-2]
                if record == "SOA":
                    raw = b"lab.example. 3600 IN SOA ns.lab.example. hostmaster.lab.example. 1 2 3 4 5\n"
                elif record == "NS":
                    raw = b"lab.example. 3600 IN NS ns.lab.example.\n"
                elif record == "A" and name == "lab.example":
                    raw = b"lab.example. 3600 IN A 192.0.2.9\n"
                else:
                    raw = b""
                task.output_path.parent.mkdir(parents=True, exist_ok=True)
                task.output_path.write_bytes(raw)
                return TaskState.SUCCESS

            records = DNSModule(context, execute=execute).run()
            self.assertIn("lab.example", context.domains)
            self.assertIn("lab.example", context.hostnames)
            self.assertTrue(any("+tcp" in args for args in calls))
            self.assertTrue(any("NS" in args for args in calls))
            self.assertTrue(any(r["type"] == "SOA" for r in records))

    def test_uses_domain_discovered_by_another_service(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = TargetContext("192.0.2.10", Path(directory), domains={"lab.example"})
            calls = []

            def execute(task):
                args = task.display_argv
                calls.append(args)
                task.output_path.parent.mkdir(parents=True, exist_ok=True)
                record, name = args[-1], args[-2]
                raw = (b"lab.example. 3600 IN SOA ns.lab.example. hostmaster.lab.example. 1 2 3 4 5\n"
                       if record == "SOA" else b"")
                task.output_path.write_bytes(raw)
                return TaskState.SUCCESS

            DNSModule(context, execute=execute).run()
            self.assertTrue(any(args[-2:] == ["lab.example", "SOA"] for args in calls))


if __name__ == "__main__":
    unittest.main()
