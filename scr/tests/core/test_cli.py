from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cli import get_context, parse_args


class CLITests(unittest.TestCase):
    def test_output_root_can_route_scan_evidence_outside_default_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            args = parse_args(["--output-root", str(root), "10.129.22.26"])
            self.assertEqual(args.output_root, root)
            with patch("cli.load_settings") as load:
                from config import Settings
                load.return_value = Settings()
                context = get_context(["--output-root", str(root), "10.129.22.26"])
            self.assertTrue(context.scan_dir.is_relative_to(root))
            self.assertTrue((context.scan_dir / "metadata/scan.json").is_file())


if __name__ == "__main__":
    unittest.main()
