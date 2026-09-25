"""Dependency-aware concurrent scheduler with retry and failure isolation."""

from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from collections.abc import Callable, Iterable

from scr.core.events import Event, EventBus
from scr.core.tasks import Task, TaskState


class SchedulerError(ValueError):
    pass


class Scheduler:
    def __init__(self, max_workers: int = 8, events: EventBus | None = None,
                 cancel_callback: Callable[[], None] | None = None) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be at least one")
        self.max_workers = max_workers
        self.events = events or EventBus()
        self.cancel_callback = cancel_callback

    def run(self, tasks: Iterable[Task], execute: Callable[[Task], object]) -> dict[str, TaskState]:
        items = list(tasks)
        by_id = {task.id: task for task in items}
        if len(by_id) != len(items):
            raise SchedulerError("duplicate task id")
        for task in items:
            missing = set(task.dependencies) - by_id.keys()
            if missing:
                raise SchedulerError(f"{task.id} has missing dependencies: {sorted(missing)}")
        pending = set(by_id)
        futures: dict[Future[object], Task] = {}
        retries: dict[str, int] = {task.id: 0 for task in items}
        with ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="recon") as pool:
            try:
                while pending or futures:
                    for task_id in tuple(pending):
                        task = by_id[task_id]
                        states = [by_id[dep].state for dep in task.dependencies]
                        if any(state in {TaskState.FAILED, TaskState.TIMEOUT,
                                         TaskState.SKIPPED, TaskState.CANCELLED} for state in states):
                            task.state = TaskState.SKIPPED
                            pending.remove(task_id)
                            self.events.publish(Event("task.skipped", task_id))
                        elif all(state == TaskState.SUCCESS for state in states) and len(futures) < self.max_workers:
                            task.state = TaskState.RUNNING
                            self.events.publish(Event("task.started", task_id))
                            pending.remove(task_id)
                            futures[pool.submit(execute, task)] = task
                    if not futures:
                        if pending:
                            waiting = {tid: by_id[tid].dependencies for tid in pending}
                            raise SchedulerError(f"dependency cycle or blocked graph: {waiting}")
                        continue
                    done, _ = wait(futures, return_when=FIRST_COMPLETED)
                    for future in done:
                        task = futures.pop(future)
                        try:
                            result = future.result()
                            if isinstance(result, TaskState):
                                task.state = result
                            elif task.state == TaskState.RUNNING:
                                task.state = TaskState.SUCCESS
                        except Exception:
                            task.state = TaskState.FAILED
                        if task.state in {TaskState.FAILED, TaskState.TIMEOUT} and retries[task.id] < task.max_retries:
                            retries[task.id] += 1
                            task.state = TaskState.QUEUED
                            pending.add(task.id)
                            continue
                        self.events.publish(Event("task.finished", task.id,
                                                  {"state": task.state.value, "attempt": retries[task.id] + 1}))
            except KeyboardInterrupt:
                if self.cancel_callback:
                    self.cancel_callback()
                for future in futures:
                    future.cancel()
                cancel = getattr(execute, "__self__", None)
                if cancel is not None and hasattr(cancel, "cancel_all"):
                    cancel.cancel_all()
                raise
        return {task.id: task.state for task in items}
