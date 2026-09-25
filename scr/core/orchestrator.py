"""Dispatch independently classified service modules through the scheduler."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import sys
from dataclasses import asdict
from collections.abc import Callable
from importlib import import_module
from typing import Any

from config import load_settings
from scr.core.context import TargetContext
from scr.core.collector import CollectorServer
from scr.core.evidence import write_json
from scr.core.resources import TraversalLimits
from scr.core.scheduler import Scheduler
from scr.core.tasks import Task, TaskState
from scr.core.process import PROCESS_CANCEL_EVENT, reset_process_cancellation
from scr.core.terminal import TerminalManager
from scr.dependencies.manager import DependencyManager


def _module_for(name: str, context: TargetContext, port: int, transport: str,
                limits: TraversalLimits) -> Any | None:
    if name == "smb":
        from scr.modules.smb.module import SMBModule
        return SMBModule(context, port=port, limits=limits)
    if name in {"http", "https"}:
        from scr.modules.http.module import HTTPModule
        return HTTPModule(context, port=port, tls=name == "https", limits=limits)
    if name == "ftp":
        from scr.modules.ftp.module import FTPModule
        return FTPModule(context, port=port, limits=limits)
    if name == "ssh":
        from scr.modules.ssh.module import SSHModule
        return SSHModule(context, port=port)
    if name == "ldap":
        from scr.modules.ldap.module import LDAPModule
        return LDAPModule(context, port=port, tls=transport == "tcp_tls", limits=limits)
    if name == "dns":
        from scr.modules.dns.module import DNSModule
        return DNSModule(context, port=port)
    return None


def run_services(context: TargetContext, *, max_workers: int | None = None,
                 factory: Callable[[str, TargetContext, int, str, TraversalLimits], Any | None] = _module_for,
                 dependency_manager: DependencyManager | None = None
                 ) -> dict[str, TaskState]:
    settings = load_settings()
    reset_process_cancellation()
    dependency_manager = dependency_manager or DependencyManager(
        install_missing=settings.install_missing_dependencies)
    terminal_manager = TerminalManager()
    limits = TraversalLimits(settings.max_depth, settings.max_tasks, settings.max_files,
                             settings.max_directories, settings.max_download_size,
                             settings.max_workers)
    specs = []
    seen: set[tuple[str, int, str]] = set()
    for detected in context.services:
        name = str(detected.get("module", "unknown"))
        port = int(detected["port"])
        transport = str(detected.get("transport", "tcp"))
        if str(detected.get("service", "")).lower() in {"ldaps", "ssl/ldap"}:
            transport = "tcp_tls"
        key = (name, port, transport)
        if name == "unknown" or key in seen:
            continue
        seen.add(key)
        module = factory(name, context, port, transport, limits)
        if module is not None:
            specs.append((name, port, transport, module))
    tasks = []
    by_id = {}
    collector = CollectorServer()
    for name, port, transport, module in specs:
        stable = hashlib.sha256(f"{name}|{port}|{transport}".encode()).hexdigest()[:12]
        result_path = context.scan_dir / "metadata" / f"service-result-{stable}.json"
        manifest_path = context.scan_dir / "metadata" / f"service-manifest-{stable}.json"
        write_json(manifest_path, {
            "service": name, "target": context.target, "port": port,
            "transport": transport, "scan_dir": str(context.scan_dir),
            "limits": asdict(limits), "result_path": str(result_path),
            "hostnames": sorted(context.hostnames), "domains": sorted(context.domains),
            "services": context.services, "tcp_ports": context.tcp_ports,
            "udp_ports": context.udp_ports, "credentials": context.credentials,
            "facts": _json_context(context.facts),
        })
        argv = ([sys.executable, "-m", "scr.core.service_worker", str(manifest_path)]
                if factory is _module_for else ["<injected-service-worker>"])
        task = Task(f"service-{name}-{stable}", context.target, name, argv,
                    context.scan_dir / "services" / name / f"worker-{stable}.log",
                    context.scan_dir / "metadata" / f"service-{name}-{stable}.json",
                    timeout=settings.command_timeout, reason="Classified service enumeration")
        task.collector_socket = str(collector.path)
        task.show_command = False
        tasks.append(task)
        by_id[task.id] = (module, result_path, factory is _module_for)

    def execute(task: Task) -> TaskState:
        try:
            module, result_path, external_worker = by_id[task.id]
            dependency_name = getattr(module, "service", task.service)
            dependency_spec = import_module(f"scr.modules.{dependency_name}.dependencies")
            if hasattr(dependency_manager, "ensure_service"):
                dependency_result = dependency_manager.ensure_service(
                    getattr(dependency_spec, "REQUIRED_EXECUTABLES", ()),
                    getattr(dependency_spec, "FALLBACKS", {}))
            else:
                dependency_result = dependency_manager.ensure(
                    getattr(dependency_spec, "REQUIRED_EXECUTABLES", ()))
            if dependency_result.missing:
                write_json(task.metadata_path, {"task_id": task.id, "state": "SKIPPED",
                    "reason": "missing dependencies", "missing": dependency_result.missing})
                return TaskState.SKIPPED
            optional_tools = tuple(getattr(dependency_spec, "OPTIONAL_EXECUTABLES", ()))
            optional_result = dependency_manager.ensure(optional_tools) if optional_tools else None
            write_json(context.scan_dir / "metadata" / f"service-tools-{task.id}.json",
                       {"task_id": task.id, "selected": dict(getattr(dependency_result, "selected", ())),
                        "installed": getattr(dependency_result, "installed", ()),
                        "optional_available": getattr(optional_result, "available", ()),
                        "optional_missing": getattr(optional_result, "missing", ())})
            if external_worker:
                state = terminal_manager.execute(task)
            else:
                result = module.run()
                state = result if isinstance(result, TaskState) else TaskState.SUCCESS
                write_json(result_path, {"state": state.value, "result": _json_context(result)})
            if state != TaskState.SUCCESS:
                return state
            result_data = json.loads(result_path.read_text(encoding="utf-8")) if result_path.exists() else {}
            context.hostnames.update(result_data.get("hostnames", []))
            context.domains.update(result_data.get("domains", []))
            context.facts.update(result_data.get("facts", {}))
            context.resources.update(result_data.get("resources", {}))
            write_json(task.metadata_path, {"task_id": task.id, "state": "SUCCESS",
                       "service": task.service, "target": task.target,
                       "result_count": len(result_data.get("result", []))
                           if hasattr(result_data.get("result"), "__len__") else None})
            return TaskState.SUCCESS
        except KeyboardInterrupt:
            write_json(task.metadata_path, {"task_id": task.id, "state": "CANCELLED"})
            raise
        except Exception as exc:
            write_json(task.metadata_path, {"task_id": task.id, "state": "FAILED",
                       "service": task.service, "error": str(exc)})
            return TaskState.FAILED

    def cancel_workers() -> None:
        PROCESS_CANCEL_EVENT.set()
        for pidfile in context.scan_dir.rglob("*.pid"):
            try:
                os.kill(int(pidfile.read_text()), signal.SIGTERM)
            except (OSError, ValueError):
                pass

    scheduler = Scheduler(max_workers or settings.max_workers, cancel_callback=cancel_workers)
    try:
        states = scheduler.run(tasks, execute)
    finally:
        collector.close()
    write_json(context.scan_dir / "metadata/service-tasks.json",
               {task_id: state.value for task_id, state in states.items()})
    return states


def _json_context(value: Any) -> Any:
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, dict):
        return {str(key): _json_context(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_context(item) for item in value]
    return value
