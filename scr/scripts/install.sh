#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
cd "$ROOT"
exec python3 -m scr.dependencies.bootstrap \
    rustscan nmap curl wget ffuf smbclient smbmap rpcclient nxc \
    ldapsearch dig host nslookup ssh ssh-keyscan
