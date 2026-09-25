"""Small thread-safe event dispatcher for task lifecycle events."""

from __future__ import annotations

import threading
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Event:
    name: str
    task_id: str | None = None
    data: dict[str, Any] | None = None


class EventBus:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: dict[str, list[Callable[[Event], None]]] = defaultdict(list)

    def subscribe(self, name: str, callback: Callable[[Event], None]) -> None:
        with self._lock:
            self._subscribers[name].append(callback)

    def publish(self, event: Event) -> None:
        with self._lock:
            callbacks = tuple(self._subscribers[event.name]) + tuple(self._subscribers["*"])
        for callback in callbacks:
            callback(event)
