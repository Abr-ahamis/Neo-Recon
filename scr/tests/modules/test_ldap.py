from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scr.core.context import TargetContext
from scr.core.resources import TraversalLimits
from scr.core.tasks import TaskState
from scr.modules.ldap.module import LDAPModule
from scr.modules.ldap.commands import children
from scr.modules.ldap.parser import authentication_required, domain_from_dn, entries, naming_contexts


class LDAPTests(unittest.TestCase):
    def test_anonymous_directory_search_has_server_and_client_time_bounds(self) -> None:
        _, command = children("192.0.2.10", 389, "DC=lab,DC=example")
        self.assertIn("nettimeout=5", command)
        self.assertEqual(command[command.index("-l") + 1], "10")
        self.assertEqual(command[command.index("-z") + 1], "500")

    def test_ldif_root_and_continuation_parsing(self) -> None:
        raw = b"defaultNamingContext: DC=lab,DC=example\n\ndn: CN=Alice,DC=lab,DC=example\ncn: Ali\n ce\nobjectClass: user\n"
        self.assertEqual(naming_contexts(raw), ["DC=lab,DC=example"])
        self.assertEqual(domain_from_dn("DC=lab,DC=example"), "lab.example")
        self.assertEqual(entries(raw)[1]["cn"], ["Alice"])
        self.assertTrue(authentication_required(
            b"Operations error: a successful bind must be completed on the connection"))
        self.assertFalse(authentication_required(b"dn: OU=Users,DC=lab,DC=example\n"))
        self.assertEqual(domain_from_dn("DC=DomainDnsZones,DC=lab,DC=example"), "lab.example")
        self.assertEqual(domain_from_dn("DC=ForestDnsZones,DC=lab,DC=example"), "lab.example")

    def test_rootdse_queries_only_primary_domain_partition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = TargetContext("192.0.2.10", Path(directory))
            queried: list[str] = []

            def execute(task):
                task.output_path.parent.mkdir(parents=True, exist_ok=True)
                if task.id.startswith("ldap-rootdse"):
                    task.output_path.write_bytes(
                        b"defaultNamingContext: DC=lab,DC=example\n"
                        b"namingContexts: DC=lab,DC=example\n"
                        b"namingContexts: CN=Configuration,DC=lab,DC=example\n"
                        b"namingContexts: DC=DomainDnsZones,DC=lab,DC=example\n"
                        b"namingContexts: DC=ForestDnsZones,DC=lab,DC=example\n"
                    )
                else:
                    queried.append(task.display_argv[task.display_argv.index("-b") + 1])
                    task.output_path.write_bytes(b"insufficient access rights")
                return TaskState.SUCCESS

            resources = LDAPModule(context, execute=execute).run()
            self.assertEqual(len(queried), 1)
            self.assertEqual(queried[0], "DC=lab,DC=example")
            self.assertEqual(context.domains, {"lab.example"})
            self.assertEqual(len(resources), 1)

    def test_rootdse_access_does_not_claim_anonymous_directory_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = TargetContext("127.0.0.1", Path(directory))

            def execute(task):
                task.output_path.parent.mkdir(parents=True, exist_ok=True)
                if task.id.startswith("ldap-rootdse"):
                    task.output_path.write_bytes(b"defaultNamingContext: DC=lab,DC=example\n")
                    return TaskState.SUCCESS
                task.output_path.write_bytes(
                    b"Operations error (1)\nAdditional information: a successful bind must be completed on the connection.\n"
                )
                return TaskState.FAILED

            results = LDAPModule(context, execute=execute).run()
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["status"], "INACCESSIBLE")
            self.assertTrue(results[0]["authentication_required"])
            root = Path(directory) / "metadata/ldap-rootdse.json"
            import json
            facts = json.loads(root.read_text())
            self.assertTrue(facts["anonymous_rootdse"])
            self.assertFalse(facts["anonymous_directory_read"])

    def test_rootdse_to_ou_recursive_pivot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = TargetContext("127.0.0.1", Path(directory))
            queried: list[str] = []

            def execute(task):
                args = task.display_argv
                task.output_path.parent.mkdir(parents=True, exist_ok=True)
                if "-s" in args and args[args.index("-s") + 1] == "base":
                    raw = b"defaultNamingContext: DC=lab,DC=example\n"
                else:
                    base = args[args.index("-b") + 1]
                    queried.append(base)
                    if base == "DC=lab,DC=example":
                        raw = (b"dn: OU=Users,DC=lab,DC=example\nobjectClass: organizationalUnit\n"
                               b"ou: Users\n\n")
                    else:
                        raw = (b"dn: CN=alice,OU=Users,DC=lab,DC=example\nobjectClass: user\n"
                               b"sAMAccountName: alice\n\n")
                task.output_path.write_bytes(raw)
                return TaskState.SUCCESS

            resources = LDAPModule(context, execute=execute,
                limits=TraversalLimits(max_depth=5)).run()
            self.assertIn("lab.example", context.domains)
            self.assertEqual(len(queried), 2)
            self.assertTrue(any(r["resource_type"] == "organizational_unit" for r in resources))
            self.assertTrue(any(r["resource_type"] == "ldap_user" for r in resources))


if __name__ == "__main__":
    unittest.main()
