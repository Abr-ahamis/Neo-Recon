from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from scr.core.context import TargetContext
from scr.core.orchestrator import run_services
from scr.core.tasks import TaskState


class OrchestratorTests(unittest.TestCase):
    def test_classified_service_modules_run_concurrently_and_fail_independently(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = TargetContext("127.0.0.1", Path(directory), services=[
                {"module": "http", "service": "http", "port": 8080, "transport": "tcp"},
                {"module": "ftp", "service": "ftp", "port": 21, "transport": "tcp"},
                {"module": "smb", "service": "microsoft-ds", "port": 445, "transport": "tcp"},
                {"module": "unknown", "service": "mystery", "port": 9999, "transport": "tcp"},
            ])

            class Dependencies:
                def ensure(self, names):
                    return SimpleNamespace(missing=())

            class FakeModule:
                def __init__(self, name, fail=False):
                    self.service, self.fail = name, fail

                def run(self):
                    time.sleep(.2)
                    if self.fail:
                        raise RuntimeError("fixture failure")
                    return []

            def factory(name, context, port, transport, limits):
                return FakeModule(name, fail=name == "ftp")

            started = time.monotonic()
            states = run_services(context, max_workers=3, factory=factory,
                                  dependency_manager=Dependencies())
            elapsed = time.monotonic() - started
            self.assertEqual(sorted(state.value for state in states.values()), ["FAILED", "SUCCESS", "SUCCESS"])
            self.assertLess(elapsed, .5)


if __name__ == "__main__":
    unittest.main()
