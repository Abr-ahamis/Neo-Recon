"""Read-only OpenSSH command definitions."""

from pathlib import Path

RUNNER = Path(__file__).with_name("run.sh")


def keyscan(target: str, port: int) -> tuple[list[str], list[str]]:
    display = ["ssh-keyscan", "-T", "5", "-p", str(port), target]
    return [str(RUNNER), *display], display


def auth_methods(target: str, port: int) -> tuple[list[str], list[str]]:
    display = ["ssh", "-vv", "-o", "BatchMode=yes", "-o", "PubkeyAuthentication=no",
               "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
               "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
               "-o", "ConnectTimeout=8", "-p", str(port), target]
    return [str(RUNNER), *display], display


def authorized_session(target: str, port: int, username: str, key_path: str) -> tuple[list[str], list[str]]:
    options = ["-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
               "-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=no",
               "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=8",
               "-p", str(port), "-i", key_path]
    remote = "whoami; id; hostname; uname -a"
    display = ["ssh", *options, f"{username}@{target}", remote]
    return [str(RUNNER), *display], display
