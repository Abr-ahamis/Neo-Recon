from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from scr.core.scheduler import Scheduler, SchedulerError
from scr.core.tasks import Task, TaskState


def task(name: str, dependencies: list[str] | None = None, retries: int = 0) -> Task:
    root = Path(tempfile.gettempdir()) / "neo-recon-tests"
    return Task(name, "127.0.0.1", "test", ["unused"], root / f"{name}.log", root / f"{name}.json",
                dependencies=dependencies or [], max_retries=retries)


class SchedulerTests(unittest.TestCase):
    def test_independent_tasks_overlap_and_failure_is_isolated(self) -> None:
        tasks = [task("a"), task("b"), task("c")]
        lock = threading.Lock()
        active = 0
        peak = 0

        def execute(item: Task) -> TaskState:
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(.3)
            with lock:
                active -= 1
            return TaskState.FAILED if item.id == "b" else TaskState.SUCCESS

        started = time.monotonic()
        states = Scheduler(max_workers=3).run(tasks, execute)
        elapsed = time.monotonic() - started
        self.assertEqual(peak, 3)
        self.assertLess(elapsed, .8)
        self.assertEqual(states, {"a": TaskState.SUCCESS, "b": TaskState.FAILED,
                                  "c": TaskState.SUCCESS})

    def test_dependencies_and_failed_dependency_skip(self) -> None:
        tasks = [task("discover"), task("service", ["discover"]),
                 task("blocked", ["service"])]
        order: list[str] = []

        def execute(item: Task) -> TaskState:
            order.append(item.id)
            return TaskState.FAILED if item.id == "service" else TaskState.SUCCESS

        states = Scheduler(2).run(tasks, execute)
        self.assertEqual(order, ["discover", "service"])
        self.assertEqual(states["blocked"], TaskState.SKIPPED)

    def test_retry_and_duplicate_or_cyclic_graph_handling(self) -> None:
        item = task("retry", retries=1)
        attempts = 0

        def execute(_: Task) -> TaskState:
            nonlocal attempts
            attempts += 1
            return TaskState.FAILED if attempts == 1 else TaskState.SUCCESS

        self.assertEqual(Scheduler(1).run([item], execute)["retry"], TaskState.SUCCESS)
        self.assertEqual(attempts, 2)
        with self.assertRaises(SchedulerError):
            Scheduler(1).run([task("dup"), task("dup")], execute)
        with self.assertRaises(SchedulerError):
            Scheduler(1).run([task("left", ["right"]), task("right", ["left"])], execute)


if __name__ == "__main__":
    unittest.main()
