from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scr.core.context import TargetContext
from scr.core.resources import TraversalLimits
from scr.core.tasks import TaskState
from scr.modules.ftp.module import FTPModule
from scr.modules.ftp.parser import access, listing


class FTPTests(unittest.TestCase):
    def test_listing_access_and_adaptive_nested_enumeration(self) -> None:
        rows = listing("""drwxr-xr-x 2 ftp ftp 4096 Jan 01 12:00 public
-rw-r--r-- 1 ftp ftp 24 Jan 01 12:00 credentials.txt
""")
        self.assertEqual([(r["name"], r["resource_type"]) for r in rows],
                         [("public", "directory"), ("credentials.txt", "file")])
        self.assertEqual(rows[1]["size"], 24)
        self.assertTrue(rows[1]["interesting"])
        self.assertTrue(access(b"230 Login successful", 0)["authentication_required"] is False)
        self.assertTrue(access(b"530 Login incorrect", 1)["authentication_required"])

    def test_anonymous_listing_recurses_and_probes_bounded_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = TargetContext("127.0.0.1", Path(directory))
            called: list[str] = []

            def execute(task):
                url = task.display_argv[-1]
                called.append(url)
                if url.endswith("/public/"):
                    raw = b"-rw-r--r-- 1 ftp ftp 12 Jan 01 12:00 credentials.txt\n"
                elif url.endswith("/credentials.txt"):
                    raw = b"200 Opening data connection\r\nfixture credentials\r\n"
                else:
                    raw = b"drwxr-xr-x 2 ftp ftp 4096 Jan 01 12:00 public\n"
                task.output_path.parent.mkdir(parents=True, exist_ok=True)
                task.output_path.write_bytes(raw)
                return TaskState.SUCCESS

            module = FTPModule(context, execute=execute,
                               limits=TraversalLimits(max_depth=4, max_download_size=100))
            resources = module.run()
            paths = {item["path"] for item in resources}
            self.assertIn("public", paths)
            self.assertIn("public/credentials.txt", paths)
            self.assertTrue(any(url.endswith("/credentials.txt") for url in called))
            file = next(item for item in resources if item["resource_type"] == "file")
            self.assertEqual(file["read_access"], "YES")


if __name__ == "__main__":
    unittest.main()
