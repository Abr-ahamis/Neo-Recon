"""Build copyable commands from resources actually discovered by a worker."""

from __future__ import annotations

import shlex
import shutil
from pathlib import Path
from typing import Any

from scr.core.context import TargetContext, target_authority
from scr.modules.http.wordlists import bounded_copy, find_wordlist


ROOT = Path(__file__).resolve().parents[2]


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
            web_source = find_wordlist("web", ROOT / "wordlists/web/quick.txt")
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
                vhost_source = find_wordlist("vhost", ROOT / "wordlists/web/vhosts.txt")
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
