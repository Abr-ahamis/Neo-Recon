from __future__ import annotations

import unittest
from unittest.mock import patch

from scr.dependencies.manager import DependencyManager


class DependencyTests(unittest.TestCase):
    def test_missing_tools_are_reported_without_installing_by_default(self) -> None:
        with patch("scr.dependencies.manager.shutil.which", side_effect=lambda name: "/usr/bin/curl" if name == "curl" else None), \
             patch("scr.dependencies.manager.subprocess.run") as install:
            result = DependencyManager(install_missing=False, package_manager="apt").ensure(("curl", "dig"))
        self.assertEqual(result.available, ("curl",))
        self.assertEqual(result.missing, ("dig",))
        install.assert_not_called()

    def test_package_manager_detection_is_limited_to_supported_managers(self) -> None:
        with patch("scr.dependencies.manager.shutil.which", side_effect=lambda name: "/usr/bin/pacman" if name == "pacman" else None):
            self.assertEqual(DependencyManager.detect_package_manager(), "pacman")

    def test_service_fallback_is_selected_when_primary_is_missing(self) -> None:
        with patch("scr.dependencies.manager.shutil.which",
                   side_effect=lambda name: "/usr/bin/wget" if name == "wget" else None):
            result = DependencyManager(install_missing=False, package_manager="apt").ensure_service(
                (), {"curl": ("wget",)})
        self.assertEqual(result.missing, ())
        self.assertEqual(result.selected, (("curl", "wget"),))


if __name__ == "__main__":
    unittest.main()
