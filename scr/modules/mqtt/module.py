"""Read-only MQTT topic subscriptions for exposed broker data."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from config import load_settings
from scr.core.context import TargetContext
from scr.core.evidence import write_json
from scr.core.output import collect
from scr.core.process import CommandRunner
from scr.core.tasks import Task
from scr.core.terminal import TerminalManager
from scr.dependencies.manager import DependencyManager


class MQTTModule:
    service = "mqtt"

    def __init__(self, context: TargetContext, *, port: int = 1883) -> None:
        self.context, self.port = context, port
        self.runner, self.terminals = CommandRunner(), TerminalManager()

    def run(self) -> list[dict[str, str]]:
        manager = DependencyManager(install_missing=load_settings().install_missing_dependencies)
        manager.ensure(("mosquitto_sub",))
        if not shutil.which("mosquitto_sub"):
            command = (f"timeout --signal=INT --kill-after=2s 12s mosquitto_sub "
                       f"-h {self.context.target} -p {self.port} -t '#' -T '$SYS/#' -v -C 10")
            print("[MQTT] mosquitto_sub is unavailable. Install: sudo apt-get install -y "
                  f"mosquitto-clients; then run: {command}")
            write_json(self.context.scan_dir / "metadata/mqtt.json", {"available": False, "command": command})
            return []
        results = []
        for label, topic, count in (("application-topics", "#", "10"),):
            argv = ["bash", str(Path(__file__).with_name("run.sh")),
                    "timeout", "--signal=INT", "--kill-after=2s", "12s",
                    "mosquitto_sub", "-h", self.context.target, "-p", str(self.port),
                    "-t", topic, "-T", "$SYS/#", "-v", "-C", count]
            digest = hashlib.sha256(label.encode()).hexdigest()[:12]
            task = Task(f"mqtt-{digest}", self.context.target, "mqtt", argv,
                        self.context.scan_dir / "services/mqtt" / f"{label}.raw",
                        self.context.scan_dir / "metadata" / f"mqtt-{label}.json",
                        timeout=16, reason=f"MQTT {label}", display_argv=argv[2:])
            self.terminals.execute(task, self.runner)
            if task.terminal_external and task.output_path.exists():
                collect("MQTT", task.display_argv or task.argv, task.output_path)
            raw = task.output_path.read_text(encoding="utf-8", errors="replace") if task.output_path.exists() else ""
            results.append({"subscription": topic, "output": raw})
        write_json(self.context.scan_dir / "metadata/mqtt.json", results)
        return results
