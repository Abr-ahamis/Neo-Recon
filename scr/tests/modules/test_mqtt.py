from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scr.core.context import TargetContext
from scr.core.tasks import TaskState
from scr.modules.mqtt.module import MQTTModule


class MQTTTimeoutTests(unittest.TestCase):
    def test_subscription_is_filtered_and_hard_limited(self) -> None:
        class RecordingTerminal:
            def __init__(self):
                self.tasks = []

            def execute(self, task, runner=None):
                self.tasks.append(task)
                task.output_path.parent.mkdir(parents=True, exist_ok=True)
                task.output_path.write_text("topic payload\n")
                return TaskState.SUCCESS

        with tempfile.TemporaryDirectory() as directory:
            module = MQTTModule(TargetContext("192.0.2.20", Path(directory)))
            terminal = RecordingTerminal()
            module.terminals = terminal
            with patch("scr.modules.mqtt.module.DependencyManager") as manager, \
                    patch("scr.modules.mqtt.module.shutil.which", return_value="/usr/bin/mosquitto_sub"):
                manager.return_value.ensure.return_value = None
                module.run()
            self.assertEqual(len(terminal.tasks), 1)
            task = terminal.tasks[0]
            self.assertEqual(task.timeout, 16)
            self.assertIn("12s", task.argv)
            self.assertIn("-T", task.argv)
            self.assertIn("$SYS/#", task.argv)
            self.assertEqual(task.argv[task.argv.index("-C") + 1], "10")
            self.assertNotIn("200", task.argv)


if __name__ == "__main__":
    unittest.main()
