from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scr.core.context import TargetContext
from scr.core.tasks import TaskState
from scr.modules.ssh.module import SSHModule
from scr.modules.ssh.parser import auth_state, host_keys


class SSHTests(unittest.TestCase):
    def test_key_and_authentication_parsers(self) -> None:
        keys = host_keys(b"host ssh-ed25519 AQID\nhost ecdsa-sha2-nistp256 BAUG\n")
        self.assertEqual([key["algorithm"] for key in keys], ["ssh-ed25519", "ecdsa-sha2-nistp256"])
        auth = auth_state(b"Authentications that can continue: publickey\nuid=1000(alice) gid=1000(alice)", 0)
        self.assertTrue(auth["authenticated"])
        self.assertEqual(auth["identity"], "alice")

    def test_no_credentials_means_no_auth_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = TargetContext("127.0.0.1", Path(directory))
            calls = []

            def execute(task):
                calls.append(task.display_argv[0])
                task.output_path.parent.mkdir(parents=True, exist_ok=True)
                output = (b"host ssh-ed25519 AQID\n" if task.display_argv[0] == "ssh-keyscan" else
                          b"Authentications that can continue: publickey\n")
                task.output_path.write_bytes(output)
                return TaskState.SUCCESS

            result = SSHModule(context, execute=execute).run()
            self.assertEqual(calls, ["ssh-keyscan", "ssh"])
            self.assertEqual(len(result["host_keys"]), 1)
            self.assertEqual(result["authentication_methods"], ["publickey"])
            self.assertFalse(result["authenticated"])


if __name__ == "__main__":
    unittest.main()
