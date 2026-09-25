"""SSH rules: enumerate remotely only through already authorized key context."""


def authorized_key(credential: dict, target: str) -> bool:
    return (credential.get("target", target) == target and
            bool(credential.get("username")) and bool(credential.get("private_key")))
