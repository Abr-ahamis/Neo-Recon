"""Read-only Active Directory command builders."""

from pathlib import Path

RUNNER = Path(__file__).with_name("run.sh")


def wrap(args: list[str]) -> tuple[list[str], list[str]]:
    return ["bash", str(RUNNER), *args], args


def userenum(target: str, domain: str, users: Path) -> tuple[list[str], list[str]]:
    return wrap(["kerbrute", "userenum", "--dc", target, "-d", domain, str(users)])


def asrep(domain: str, target: str, users: Path) -> tuple[list[str], list[str]]:
    return wrap(["impacket-GetNPUsers", f"{domain}/", "-dc-ip", target,
                 "-usersfile", str(users), "-no-pass"])


def rpc_null(target: str) -> tuple[list[str], list[str]]:
    return wrap(["rpcclient", "-U", "", "-N", target, "-c",
                 "srvinfo;enumdomains;querydominfo;netshareenumall;enumdomusers;enumdomgroups"])


def smb_enum(target: str, mode: str, limit: int | None = None) -> tuple[list[str], list[str]]:
    args = ["nxc", "smb", target, "-u", "", "-p", ""]
    args.extend(["--rid-brute", str(limit)] if mode == "rid" else [f"--{mode}"])
    return wrap(args)
