from __future__ import annotations

import unittest
from unittest.mock import patch

from config import load_settings
from scr.dependencies.manager import DependencyManager
from scr.dependencies.registry import EXECUTABLE_PACKAGES


class DependencyTests(unittest.TestCase):
    def test_project_config_enables_install_and_configures_official_rustscan_release(self) -> None:
        settings = load_settings()
        self.assertTrue(settings.install_missing_dependencies)
        self.assertEqual(
            DependencyManager._configured_rustscan_url(),
            "https://github.com/bee-san/RustScan/releases/download/2.4.1/rustscan.deb.zip",
        )

    def test_rustscan_release_fallback_is_attempted_before_apt(self) -> None:
        manager = DependencyManager(install_missing=True, package_manager="apt",
                                    rustscan_download_url="https://example.invalid/rustscan.zip")
        with patch("scr.dependencies.manager.shutil.which", return_value=None), \
             patch("scr.dependencies.manager.os.geteuid", return_value=0), \
             patch("scr.dependencies.manager.DependencyManager._install_rustscan_release",
                   return_value=False) as release, \
             patch("scr.dependencies.manager.subprocess.run") as package_install:
            result = manager.ensure(("rustscan",))
        release.assert_called_once_with("https://example.invalid/rustscan.zip")
        package_install.assert_called_once_with(
            ["apt-get", "install", "-y", "rustscan"], check=False)
        self.assertEqual(result.missing, ("rustscan",))

    def test_apt_package_names_exist_in_project_registry_for_installed_workflow_tools(self) -> None:
        for executable in ("rustscan", "nmap", "curl", "wget", "smbclient", "smbmap",
                           "rpcclient", "nxc", "ffuf", "ldapsearch", "dig", "ssh"):
            with self.subTest(executable=executable):
                self.assertIn("apt", EXECUTABLE_PACKAGES[executable])

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
