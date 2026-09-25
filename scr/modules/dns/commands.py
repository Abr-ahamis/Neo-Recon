"""Native dig command definitions."""

from pathlib import Path
import ipaddress
from scr.dependencies.tools import select_tool

RUNNER = Path(__file__).with_name("run.sh")


def query(name: str, record_type: str, *, tcp: bool = False, server: str | None = None,
          port: int = 53) -> tuple[list[str], list[str]]:
    tool = select_tool("dig")
    if tool == "dig":
        display = ["dig", "+time=3", "+tries=1", "+noall", "+answer", "-p", str(port)]
        if tcp:
            display.append("+tcp")
        if server:
            display.append("@" + server)
    elif tool == "host":
        display = ["host", "-p", str(port)]
        if tcp:
            display.append("-T")
        display.extend(("-t", record_type, name))
        if server:
            display.append(server)
    else:
        display = ["nslookup", f"-port={port}", f"-type={record_type}"]
        if tcp:
            display.append("-vc")
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        address = None
    if tool == "nslookup":
        display.extend((name, server or "127.0.0.1"))
    elif tool == "dig":
        if record_type.upper() == "PTR" and address:
            display.extend(("-x", name))
        else:
            display.extend((name, record_type))
    return [str(RUNNER), *display], display
