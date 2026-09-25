"""Select a declared primary or fallback executable already on PATH."""

from __future__ import annotations

import shutil

from scr.dependencies.registry import EXECUTABLE_FALLBACKS


def select_tool(primary: str) -> str:
    candidates = (primary, *EXECUTABLE_FALLBACKS.get(primary, ()))
    selected = next((tool for tool in candidates if shutil.which(tool)), None)
    if selected is None:
        raise FileNotFoundError(f"none of the registered tools are available: {', '.join(candidates)}")
    return selected
