"""Low impact AD discovery over Kerberos, SMB null sessions and RPC."""

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
from scr.modules.http.wordlists import bounded_copy, find_wordlist
from scr.modules.kerberos import commands


class KerberosModule:
    service = "kerberos"

    def __init__(self, context: TargetContext, *, port: int = 88) -> None:
        self.context, self.port = context, port
        self.runner, self.terminals = CommandRunner(), TerminalManager()
        self.dependencies = DependencyManager(install_missing=load_settings().install_missing_dependencies)

    def _run(self, label: str, native: tuple[list[str], list[str]], *, timeout: int = 180) -> None:
        argv, display = native
        digest = hashlib.sha256((label + str(self.port)).encode()).hexdigest()[:12]
        task = Task(f"ad-{label}-{digest}", self.context.target, "kerberos", argv,
                    self.context.scan_dir / "services/kerberos" / f"{label}.raw",
                    self.context.scan_dir / "metadata" / f"ad-{label}.json", timeout=timeout,
                    reason=f"AD {label}", display_argv=display)
        state = self.terminals.execute(task, self.runner)
        if task.terminal_external and task.output_path.exists():
            collect("AD", display, task.output_path)

    def run(self) -> list[dict[str, str]]:
        domain = (self.context.facts.get("domain") or next(iter(sorted(self.context.domains)), ""))
        if not domain:
            print("[AD] Domain unavailable from Nmap. Provide the domain with --domain or derive it from DNS.")
            return []
        root = Path(__file__).resolve().parents[2]
        users = find_wordlist("usernames", root / "wordlists/common.txt")
        if users:
            scan_users = self.context.scan_dir / "metadata" / "ad-usernames.txt"
            bounded_copy(users, scan_users)
        else:
            scan_users = None
        # Install available packages, then report actionable commands for tools
        # that have no package in the detected distribution.
        self.dependencies.ensure(("rpcclient", "nxc", "impacket-GetNPUsers"))
        target_ip = str(self.context.facts.get("target_ip", self.context.target))
        if shutil.which("nxc"):
            for mode in ("shares", "users", "groups"):
                self._run(f"smb-{mode}", commands.smb_enum(target_ip, mode))
            self._run("smb-rid-brute", commands.smb_enum(target_ip, "rid", 3000), timeout=300)
        else:
            print("[AD] nxc unavailable. Install: sudo apt-get install -y netexec; "
                  f"then run: nxc smb {target_ip} -u '' -p '' --shares --users --groups")
        if shutil.which("rpcclient"):
            self._run("rpc-null", commands.rpc_null(target_ip))
        else:
            print("[AD] rpcclient unavailable. Install: sudo apt-get install -y samba-common-bin; "
                  f"then run: rpcclient -U '' -N {target_ip} -c 'srvinfo;enumdomains;querydominfo;netshareenumall;enumdomusers;enumdomgroups'")
        if scan_users and shutil.which("kerbrute"):
            self._run("kerberos-userenum", commands.userenum(target_ip, domain, scan_users), timeout=900)
        else:
            users_arg = str(scan_users) if scan_users else "<USERS_FILE>"
            print("[AD] Kerbrute or username list unavailable. Install kerbrute from "
                  "https://github.com/ropnop/kerbrute/releases and SecLists, then run: "
                  f"kerbrute userenum --dc {target_ip} -d {domain} {users_arg}")
        if scan_users and shutil.which("impacket-GetNPUsers"):
            self._run("asrep-check", commands.asrep(domain, target_ip, scan_users), timeout=300)
        elif scan_users:
            print("[AD] GetNPUsers unavailable. Install with: sudo apt-get install -y impacket-scripts; "
                  f"then run: impacket-GetNPUsers {domain}/ -dc-ip {target_ip} -usersfile {scan_users} -no-pass")
        if not users:
            print("[AD] No username wordlist found. SecLists is preferred; local scr/wordlists is second choice.")
        write_json(self.context.scan_dir / "metadata/ad-enumeration.json", {
            "domain": domain, "dc": target_ip, "username_wordlist": str(users) if users else None,
            "username_count_file": str(scan_users) if scan_users else None,
        })
        return []
