"""Central executable checks and explicitly configured package installation."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

from scr.dependencies.packages import PACKAGE_MANAGER_COMMANDS
from scr.dependencies.registry import EXECUTABLE_PACKAGES


@dataclass(frozen=True)
class DependencyResult:
    available: tuple[str, ...]
    missing: tuple[str, ...]
    installed: tuple[str, ...] = ()
    selected: tuple[tuple[str, str], ...] = ()


class DependencyManager:
    def __init__(self, *, install_missing: bool = False, package_manager: str | None = None) -> None:
        self.install_missing = install_missing
        self.package_manager = package_manager or self.detect_package_manager()

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
        if not result.missing or not self.install_missing or not self.package_manager:
            return result
        manager = self.package_manager
        packages = sorted({EXECUTABLE_PACKAGES[item][manager]
                           for item in result.missing if item in EXECUTABLE_PACKAGES
                           and manager in EXECUTABLE_PACKAGES[item]})
        if packages:
            subprocess.run([*PACKAGE_MANAGER_COMMANDS[manager], *packages], check=False)
        verified = self.check(executables)
        installed = tuple(item for item in result.missing if item not in verified.missing)
        return DependencyResult(verified.available, verified.missing, installed)

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
