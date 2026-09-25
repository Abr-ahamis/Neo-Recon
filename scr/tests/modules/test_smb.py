from __future__ import annotations

import shlex
import tempfile
import unittest
from pathlib import Path

from scr.core.context import TargetContext
from scr.core.resources import Access, TraversalLimits
from scr.core.tasks import TaskState
from scr.modules.smb.module import SMBModule
from scr.modules.smb.parser import access_result, classify_file, parse_listing, parse_shares


class SMBParserTests(unittest.TestCase):
    def test_share_and_directory_fixtures(self) -> None:
        shares = parse_shares("""Sharename       Type      Comment
---------       ----      -------
public          Disk      Public share
IPC$            IPC       IPC Service
""")
        self.assertEqual([x["name"] for x in shares], ["public", "IPC$"])
        listing = parse_listing("""  .                                   D        0  Mon Jan 01 00:00:00 2024
  ..                                  D        0  Mon Jan 01 00:00:00 2024
  documents                           D        0  Mon Jan 01 00:00:00 2024
  credentials.txt                     A       40  Mon Jan 01 00:00:00 2024
  huge.iso                            A 99999999  Mon Jan 01 00:00:00 2024
  ../escape.txt                       A       10  Mon Jan 01 00:00:00 2024
""", "public")
        self.assertEqual([(x["name"], x["resource_type"]) for x in listing],
                         [("documents", "directory"), ("credentials.txt", "file"), ("huge.iso", "file")])
        self.assertEqual(listing[1]["category"], "credential_like")
        self.assertTrue(listing[1]["interesting"])
        self.assertGreater(listing[2]["size"], 10_000)

    def test_access_modes_and_file_classification(self) -> None:
        self.assertEqual(access_result(b"", 0)["permission_state"], "LIST")
        self.assertEqual(access_result(b"NT_STATUS_ACCESS_DENIED", 1)["permission_state"], "AUTH_REQUIRED")
        self.assertEqual(access_result(b"NT_STATUS_BAD_NETWORK_NAME", 1)["permission_state"], "NO_ACCESS")
        self.assertEqual(classify_file("db.bin", 3, magic=b"SQLite format 3")["category"], "database")
        self.assertEqual(classify_file("server.key", 10)["category"], "private_key")


class SMBAdaptiveTests(unittest.TestCase):
    def test_anonymous_share_recursively_lists_and_inspects_bounded_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = TargetContext("127.0.0.1", root)
            executed: list[tuple[str, ...]] = []

            def fake_execute(task):
                argv = task.display_argv
                executed.append(tuple(argv))
                task.output_path.parent.mkdir(parents=True, exist_ok=True)
                output = b""
                if "-L" in argv:
                    output = (b"Workgroup=[LAB] Server=[files01]\r\n"
                              b"Sharename       Type      Comment\r\n"
                              b"---------       ----      -------\r\n"
                              b"public          Disk      Public share\r\n")
                elif "-c" in argv and argv[-1] == "ls":
                    path = argv[argv.index("-D") + 1] if "-D" in argv else ""
                    fixtures = {
                        "": ("documents", "D", 0, "config.xml", "A", 40, "huge.iso", "A", 99999999),
                        "documents": ("archive", "D", 0, "credentials.txt", "A", 50),
                        "documents/archive": ("backup.sql", "A", 60),
                    }
                    values = fixtures.get(path, ())
                    lines=[]
                    index=0
                    while index < len(values):
                        name, attrs, size = values[index:index+3]
                        lines.append(f"  {name:<35} {attrs} {size:8d}  Mon Jan 01 00:00:00 2024")
                        index += 3
                    output = ("\r\n".join(lines) + "\r\n").encode()
                elif "-c" in argv and "get " in argv[-1]:
                    args = shlex.split(argv[-1])
                    destination = Path(args[-1])
                    destination.write_bytes(b"credentials=fixture\n")
                    output = b"getting file\r\n"
                task.output_path.write_bytes(output)
                task.state = TaskState.SUCCESS
                return TaskState.SUCCESS

            module = SMBModule(context, limits=TraversalLimits(max_depth=6, max_files=20,
                                    max_directories=20, max_tasks=100, max_download_size=1024),
                               execute=fake_execute)
            resources = module.run()
            paths = {item["path"] for item in resources}
            self.assertTrue({"public", "documents", "documents/archive",
                             "config.xml", "documents/credentials.txt",
                             "documents/archive/backup.sql", "huge.iso"}.issubset(paths))
            self.assertTrue(any("-D" in argv and argv[argv.index("-D") + 1] == "documents/archive"
                                for argv in executed))
            self.assertFalse(any("huge.iso" in argv[-1] for argv in executed if "-c" in argv))
            downloaded = [x for x in resources if x["resource_type"] == "file" and x["read_access"] == "YES"]
            self.assertGreaterEqual(len(downloaded), 3)
            self.assertEqual(context.facts["smb"]["workgroup"], "LAB")
            self.assertIn("files01", context.hostnames)
            self.assertTrue(all(x["write_access"] == "UNKNOWN" for x in resources))


if __name__ == "__main__":
    unittest.main()
