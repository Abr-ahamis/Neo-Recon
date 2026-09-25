"""Build copyable commands from resources actually discovered by a worker."""

from __future__ import annotations

import shlex
import shutil
import re
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any

from scr.core.context import TargetContext, target_authority
from scr.modules.http.wordlists import bounded_copy, find_wordlist


ROOT = Path(__file__).resolve().parents[2]


def next_commands(service: str, target: str, argv: list[str], output: bytes) -> list[str]:
    """Return five copyable follow-ups for one completed command."""
    service = service.lower()
    if service in {"http", "https"} or any(item in {"curl", "wget", "ffuf", "gobuster", "feroxbuster"}
                                               for item in argv):
        url = next((item for item in argv if item.startswith(("http://", "https://"))),
                   f"http://{target}/")
        parts = urlsplit(url)
        root = f"{parts.scheme or 'http'}://{parts.netloc or target}/"
        wordlist = ROOT / "scr/wordlists/web/quick.txt"
        return [
            shlex.join(["curl", "-I", "--max-time", "10", root]),
            shlex.join(["curl", "-X", "OPTIONS", "-i", "--max-time", "10", root]),
            shlex.join(["nmap", "-Pn", "-p", str(parts.port or (443 if parts.scheme == "https" else 80)), "--script",
                        "http-title,http-headers,http-methods", target]),
            shlex.join(["gobuster", "dir", "-u", root, "-w", str(wordlist), "-t", "10"]),
            shlex.join(["ffuf", "-u", root + "FUZZ", "-w", str(wordlist), "-ac", "-fc", "404"]),
        ]
    if service == "smb" or any(item in {"smbclient", "smbmap", "rpcclient", "nxc"} for item in argv):
        port_match = re.search(r"(?:-p|-P)\s*(\d+)", " ".join(argv))
        port = port_match.group(1) if port_match else "445"
        share_match = re.search(rf"//{re.escape(target)}/([^\s]+)", " ".join(argv))
        share = share_match.group(1).strip("'\"") if share_match else ""
        commands = [shlex.join(["smbmap", "-H", target, "-P", port,
                                "--no-write-check", "-r", "--depth", "1", "-q"])]
        if share:
            commands.append(shlex.join(["smbclient", "-p", port, "-N",
                                        f"//{target}/{share}", "-c", "ls"]))
        commands.extend([
            shlex.join(["rpcclient", "-U", "", "-N", "-p", port, target, "-c", "srvinfo"]),
            shlex.join(["nxc", "smb", target, "-u", "", "-p", "", "--shares"]),
            shlex.join(["nmap", "-Pn", "-p", port, "--script",
                        "smb-protocols,smb-security-mode,smb-enum-shares", target]),
        ])
        return commands[:5]
    if service in {"rustscan", "nmap", "network"}:
        ports = sorted(set(re.findall(rb"(?m)^\s*(\d{1,5})/tcp\s+open\b", output)))
        port_spec = ",".join(value.decode() for value in ports) or "22,53,80,139,445"
        return [
            shlex.join(["nmap", "-Pn", "-sV", "-sC", "-p", port_spec, target]),
            shlex.join(["nmap", "-Pn", "-p", "445", "--script", "smb-protocols,smb-security-mode", target]),
            shlex.join(["nmap", "-Pn", "-p", "53", "--script", "dns-recursion,dns-nsid", target]),
            shlex.join(["nmap", "-Pn", "-p", "22", "--script", "ssh2-enum-algos,ssh-hostkey", target]),
            shlex.join(["nc", "-nv", "-w", "3", target, "445"]),
        ]
    if service == "dns":
        return [
            shlex.join(["dig", f"@{target}", "-x", target]),
            shlex.join(["dig", f"@{target}", "NS"]),
            shlex.join(["dig", f"@{target}", "TXT"]),
            shlex.join(["dig", f"@{target}", "SOA"]),
            shlex.join(["nmap", "-Pn", "-p", "53", "--script", "dns-nsid,dns-recursion", target]),
        ]
    if service == "ssh":
        return [
            shlex.join(["ssh-keyscan", "-T", "5", target]),
            shlex.join(["nmap", "-Pn", "-p", "22", "--script", "ssh-hostkey", target]),
            shlex.join(["nmap", "-Pn", "-p", "22", "--script", "ssh2-enum-algos", target]),
            shlex.join(["ssh", "-vv", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", target]),
            shlex.join(["nmap", "-Pn", "-p", "22", "--script", "ssh-auth-methods", target]),
        ]
    if service == "ftp":
        return [
            shlex.join(["curl", "--user", "anonymous:", f"ftp://{target}/"]),
            shlex.join(["nmap", "-Pn", "-p", "21", "--script", "ftp-syst,ftp-anon", target]),
            shlex.join(["nc", "-nv", "-w", "3", target, "21"]),
            shlex.join(["curl", "--user", "anonymous:", f"ftp://{target}/README"]),
            shlex.join(["nmap", "-Pn", "-p", "21", "-sV", target]),
        ]
    if service == "ldap":
        return [
            shlex.join(["ldapsearch", "-x", "-H", f"ldap://{target}", "-s", "base"]),
            shlex.join(["nmap", "-Pn", "-p", "389", "--script", "ldap-rootdse", target]),
            shlex.join(["nmap", "-Pn", "-p", "636", "--script", "ldap-rootdse", target]),
            shlex.join(["openssl", "s_client", "-connect", f"{target}:636", "-brief"]),
            shlex.join(["nc", "-nv", "-w", "3", target, "389"]),
        ]
    return [
        shlex.join(["nmap", "-Pn", "-sV", "-sC", target]),
        shlex.join(["nmap", "-Pn", "-p", "22,53,80,139,445", "-sV", target]),
        shlex.join(["nc", "-nv", "-w", "3", target, "80"]),
        shlex.join(["curl", "-I", "--max-time", "5", f"http://{target}/"]),
        shlex.join(["smbmap", "-H", target, "--no-write-check", "-r", "--depth", "1", "-q"]),
    ]


def service_suggestions(service: str, context: TargetContext, port: int) -> list[str]:
    resources = list(context.resources.values())
    if service in {"http", "https"}:
        scheme = "https" if service == "https" else "http"
        authority = target_authority(context.target, port)
        root = f"{scheme}://{authority}/"
        paths = [str(item.get("path", "")) for item in resources
                 if item.get("service") == "http"
                 and item.get("read_access") == "YES"
                 and item.get("path")]
        domain = context.facts.get("domain") or next(iter(sorted(context.domains)), None)
        if shutil.which("ffuf"):
            web_source = find_wordlist("web", ROOT / "scr/wordlists/common.txt")
            wordlist = context.scan_dir / "metadata/http-web-suggestions.txt"
            bounded_copy(web_source, wordlist, limit=250)
            ext = ".php,.asp,.aspx,.jsp,.html,.txt,.log,.conf,.json,.xml,.yaml,.bak,.zip,.sql,.db,.env"
            commands = [shlex.join(["curl", "-i", "--max-time", "15", root])]
            commands.extend(shlex.join(["curl", "-i", "--max-time", "15", path])
                            for path in dict.fromkeys(paths)
                            if path.startswith(root) and path != root)
            commands = commands[:2]
            commands.extend([
                shlex.join(["ffuf", "-u", f"{root}FUZZ", "-w", str(wordlist),
                            "-ac", "-fc", "404"]),
                shlex.join(["ffuf", "-u", f"{root}FUZZ", "-w", str(wordlist), "-e", ext,
                            "-ac", "-fc", "404"]),
            ])
            if isinstance(domain, str) and domain:
                vhost_source = find_wordlist("vhost", ROOT / "scr/wordlists/common.txt")
                vhost_list = context.scan_dir / "metadata/http-vhosts-suggestions.txt"
                bounded_copy(vhost_source, vhost_list, limit=100)
                commands.append(shlex.join(["ffuf", "-u", root,
                                            "-H", f"Host: FUZZ.{domain}", "-w",
                                            str(vhost_list), "-ac", "-fc", "404"]))
            else:
                commands.append(shlex.join(["curl", "-i", "--max-time", "15", root + "robots.txt"]))
            commands.append(shlex.join(["nmap", "-Pn", "-p", str(port), "--script",
                                        "http-title,http-headers,http-methods", context.target]))
        else:
            urls = list(dict.fromkeys([root, *paths[:2], root + "robots.txt",
                                       root + "sitemap.xml", root + ".env"]))
            commands = [shlex.join(["curl", "-i", "--max-time", "15", path])
                        for path in urls[:4]]
            commands.append(shlex.join(["nmap", "-Pn", "-p", str(port), "--script",
                                        "http-title,http-headers,http-methods", context.target]))
        return commands[:5]
    if service == "smb":
        return [shlex.join(["smbclient", f"//{context.target}/{item.get('name')}",
                            "-N", "-p", str(port), "-c", "ls"])
                for item in resources[:4] if item.get("service") == "smb"
                and item.get("resource_type") == "share"
                and item.get("list_access") == "YES"]
    if service == "ftp":
        return [shlex.join(["curl", "--user", "anonymous:",
                            f"ftp://{target_authority(context.target, port)}/{item.get('path', '').lstrip('/')}"])
                for item in resources[:3] if item.get("service") == "ftp"
                and item.get("list_access") == "YES"]
    if service == "ldap":
        domain = context.facts.get("domain") or next(iter(sorted(context.domains)), None)
        if isinstance(domain, str) and domain:
            base = ",".join(f"DC={label}" for label in domain.split("."))
            return [shlex.join(["ldapsearch", "-x", "-H",
                                f"ldap://{target_authority(context.target, port)}",
                                "-b", base, "(objectClass=*)", "dn"])]
    if service == "dns":
        domain = context.facts.get("domain") or next(iter(sorted(context.domains)), None)
        if isinstance(domain, str) and domain:
            return [shlex.join(["dig", f"@{context.target}", "-p", str(port), domain, "ANY"])]
    if service == "ssh":
        return [shlex.join(["ssh", "-v", "-p", str(port), context.target])]
    return []
