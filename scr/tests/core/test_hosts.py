from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scr.core.hosts import HostsManager


class HostsManagerTests(unittest.TestCase):
    def test_conflicting_alias_is_backed_up_commented_and_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hosts"
            original = ("127.0.0.1 localhost\n"
                        "10.10.10.10 dc.support.htb\n"
                        "192.0.2.8 unrelated.example\n")
            path.write_text(original)
            result = HostsManager(path).apply("10.129.230.181",
                                               {"dc.support.htb", "support.htb", "dc"})
            updated = path.read_text()
            self.assertEqual(result["status"], "updated")
            self.assertIn("# Neo-Recon: replaced mapping for dc.support.htb", updated)
            self.assertIn("# 10.10.10.10 dc.support.htb", updated)
            self.assertIn("10.129.230.181\tdc dc.support.htb support.htb", updated)
            self.assertIn("192.0.2.8 unrelated.example", updated)
            self.assertEqual(Path(result["backup"]).read_text(), original)

    def test_correct_mapping_is_not_rewritten_or_backed_up(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hosts"
            original = "127.0.0.1 localhost\n10.0.0.2 dc.lab.local lab.local\n"
            path.write_text(original)
            result = HostsManager(path).apply("10.0.0.2", {"dc.lab.local", "lab.local"})
            self.assertEqual(result["status"], "unchanged")
            self.assertEqual(path.read_text(), original)
            self.assertEqual(list(path.parent.glob("*.bak")), [])

    def test_conflicting_duplicate_is_commented_even_if_correct_mapping_exists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hosts"
            path.write_text("10.0.0.2 dc.lab.local\n10.0.0.3 dc.lab.local\n")
            result = HostsManager(path).apply("10.0.0.2", {"dc.lab.local"})
            updated = path.read_text()
            self.assertEqual(result["status"], "updated")
            self.assertIn("10.0.0.2 dc.lab.local", updated)
            self.assertIn("# 10.0.0.3 dc.lab.local", updated)

    def test_invalid_aliases_and_non_ip_target_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hosts"
            path.write_text("127.0.0.1 localhost\n")
            self.assertEqual(HostsManager(path).apply("lab.local", {"dc.lab.local"})["status"],
                             "skipped")
            self.assertEqual(HostsManager(path).apply("10.0.0.2", {"-bad", "../x"})["status"],
                             "skipped")


if __name__ == "__main__":
    unittest.main()
