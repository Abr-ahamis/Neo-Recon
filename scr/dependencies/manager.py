"""Central executable checks and explicitly configured package installation."""

from __future__ import annotations

import shutil
import subprocess
import json
import os
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

from scr.dependencies.packages import PACKAGE_MANAGER_COMMANDS
from scr.dependencies.registry import EXECUTABLE_PACKAGES


@dataclass(frozen=True)
class DependencyResult:
    available: tuple[str, ...]
    missing: tuple[str, ...]
    installed: tuple[str, ...] = ()
    selected: tuple[tuple[str, str], ...] = ()


class DependencyManager:
    def __init__(self, *, install_missing: bool = False, package_manager: str | None = None,
                 rustscan_download_url: str | None = None) -> None:
        self.install_missing = install_missing
        self.package_manager = package_manager or self.detect_package_manager()
        self.rustscan_download_url = rustscan_download_url or self._configured_rustscan_url()

    @staticmethod
    def _configured_rustscan_url() -> str:
        path = Path(__file__).resolve().parents[2] / "config.json"
        try:
            with path.open(encoding="utf-8") as stream:
                config = json.load(stream)
            return str(config.get("dependencies", {}).get("rustscan_download_url", ""))
        except (OSError, ValueError, TypeError):
            return ""

    @staticmethod
    def detect_package_manager() -> str | None:
        if shutil.which("apt-get"):
            return "apt"
        if shutil.which("pacman"):
            return "pacman"
        return None

    def check(self, executables: tuple[str, ...] | list[str]) -> DependencyResult:
        available = tuple(item for item in executables if shutil.which(item))
        missing = tuple(item for item in executables if item not in available)
        return DependencyResult(available, missing)

    def ensure(self, executables: tuple[str, ...] | list[str]) -> DependencyResult:
        result = self.check(executables)
        if not result.missing or not self.install_missing:
            return result
        release_attempted = False
        missing = list(result.missing)
        if "rustscan" in missing and self.rustscan_download_url:
            release_attempted = True
            self._install_rustscan_release(self.rustscan_download_url)
            missing = list(self.check(executables).missing)
        manager = self.package_manager
        packages = sorted({EXECUTABLE_PACKAGES[item][manager]
                           for item in missing if manager
                           and item in EXECUTABLE_PACKAGES
                           and manager in EXECUTABLE_PACKAGES[item]})
        if packages:
            command = [*PACKAGE_MANAGER_COMMANDS[manager], *packages]
            if os.geteuid() != 0 and shutil.which("sudo"):
                command.insert(0, "sudo")
            try:
                subprocess.run(command, check=False)
            except OSError:
                pass
        verified = self.check(executables)
        if ("rustscan" in verified.missing and not release_attempted
                and self.rustscan_download_url):
            self._install_rustscan_release(self.rustscan_download_url)
            verified = self.check(executables)
        installed = tuple(item for item in result.missing if item not in verified.missing)
        return DependencyResult(verified.available, verified.missing, installed)

    @staticmethod
    def _install_rustscan_release(url: str) -> bool:
        """Install the configured official .deb zip without storing credentials."""
        try:
            print(f"RustScan package install failed; trying configured release: {url}")
            request = urllib.request.Request(url, headers={"User-Agent": "Neo-Recon dependency installer"})
            with urllib.request.urlopen(request, timeout=60) as response:
                archive = response.read(100 * 1024 * 1024 + 1)
            if len(archive) > 100 * 1024 * 1024:
                raise ValueError("RustScan release archive exceeds 100 MiB")
            with tempfile.TemporaryDirectory(prefix="neo-recon-rustscan-") as directory:
                zip_path = Path(directory) / "rustscan.zip"
                zip_path.write_bytes(archive)
                with zipfile.ZipFile(zip_path) as package_zip:
                    deb_names = [name for name in package_zip.namelist()
                                 if name.lower().endswith(".deb") and not name.startswith(("/", ".."))]
                    if len(deb_names) != 1:
                        raise ValueError("release archive must contain exactly one .deb package")
                    deb = Path(directory) / Path(deb_names[0]).name
                    deb.write_bytes(package_zip.read(deb_names[0]))
                command = ["dpkg", "-i", str(deb)]
                if os.geteuid() != 0:
                    if not shutil.which("sudo"):
                        return False
                    command.insert(0, "sudo")
                installed = subprocess.run(command, check=False).returncode == 0
                if not installed and shutil.which("apt-get"):
                    repair = ["apt-get", "install", "-f", "-y"]
                    if os.geteuid() != 0 and shutil.which("sudo"):
                        repair.insert(0, "sudo")
                    subprocess.run(repair, check=False)
                    installed = shutil.which("rustscan") is not None
                return installed or shutil.which("rustscan") is not None
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            print(f"RustScan release installation failed: {exc}")
            return False

    def ensure_service(self, required: tuple[str, ...] | list[str],
                       fallbacks: dict[str, tuple[str, ...] | list[str]]) -> DependencyResult:
        base = self.ensure(required)
        installed = list(base.installed)
        available = set(base.available)
        missing = list(base.missing)
        selected: list[tuple[str, str]] = []
        for primary, alternatives in fallbacks.items():
            checked = self.ensure((primary,))
            available.update(checked.available)
            installed.extend(checked.installed)
            if primary in checked.available:
                selected.append((primary, primary))
                continue
            fallback = next((tool for tool in alternatives if shutil.which(tool)), None)
            if fallback:
                available.add(fallback)
                selected.append((primary, fallback))
            else:
                missing.append(primary)
        return DependencyResult(tuple(sorted(available)), tuple(dict.fromkeys(missing)),
                                tuple(dict.fromkeys(installed)), tuple(selected))
