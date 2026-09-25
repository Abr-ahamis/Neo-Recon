# Neo-Recon

Neo-Recon is a terminal-based reconnaissance orchestrator for authorized CTF and lab targets. The Python controller runs RustScan, passes discovered ports to Nmap, classifies service fingerprints, then schedules implemented service workers concurrently.

Run from the repository root:

```bash
python3 main.py 10.10.10.10
```

With no positional target, the CLI prompts once when attached to a terminal. `--ports` can constrain RustScan for a lab check. Missing declared tools are installed when the configured package manager is available. This requires package-management privileges; run `sudo python3 main.py TARGET` when needed. The root `config.json` controls this behavior and the RustScan release URL. RustScan first uses that URL when absent, then falls back to the configured distribution package. Change `dependencies.install_missing` or `dependencies.rustscan_download_url` there to adjust installation.

The explicit installer script checks and installs the supported workflow tools:

```bash
sudo ./scr/scripts/install.sh
```

## Current implementation

The execution core includes target validation, task states, dependency-aware concurrency, process-group timeout/cancellation, PTY streaming, raw evidence capture, metadata, worker terminal selection, and bounded resource traversal. Discovery is RustScan → Nmap → protocol/fingerprint classification. Adaptive workers currently exist for SMB, HTTP/HTTPS, anonymous FTP, SSH host keys/explicit key authentication, anonymous LDAP/LDAPS, and DNS.

These workers are an initial implementation, not complete coverage of every protocol or authentication path. Other service directories remain placeholders. See [agent/SERVICES.md](agent/SERVICES.md) and [agent/TASK.md](agent/TASK.md) for status and remaining work.

## Evidence and output

Each scan and its native command output are stored under `/tmp/neo-recon/scans/<target>/<timestamp>/`. `--output-root` can select another directory under `/tmp`. Native command streams are saved separately from metadata. Parsers operate on a separate copy; PTY output processing is disabled to preserve line endings. The main collector adds only service/command separators. Default enumeration is read-only and target-scoped; no credential guessing or automatic expansion to discovered hosts occurs.

RustScan uses its normal command form, `rustscan -a TARGET -- -oN PATH`, without greppable `-g` output. Its live terminal stream is captured separately in `discovery/rustscan.log`; Nmap-style open-port lines are parsed for the next discovery stage. Worker output is forwarded as it arrives and saved byte-for-byte. Completed native output is appended to the main terminal with blue framework separators; tool output colors and bytes are left untouched. On Hyprland, the workspace manager counts every visible application window and places each new worker only where the total remains at or below four. It reserves placement before opening each terminal and rechecks after launch. `foot` is the preferred terminal emulator. Nmap hostnames/domains are added to shared scan context; `/etc/hosts` updates are backed up and atomic, and a permissions failure is recorded without stopping the scan.

Each active service runs as one worker in its own terminal. When enumeration ends or is interrupted with Ctrl-C, the worker returns control to an interactive shell; saved evidence and command metadata remain available. HTTP makes one base-page request, then uses a bounded copy of `common.txt` for hidden path discovery and known-domain vhost discovery. The list finder checks `/usr/share/wordlists/` and SecLists locations, then uses the bundled `scr/wordlists/common.txt`. Finished workers print copyable follow-up commands only when they are supported by discoveries and installed tools. Missing tools are checked by the central dependency manager; installation follows the configured dependency setting. Real Hyprland placement depends on `hyprctl`; without it, the configured terminal emulator or tmux fallback is used.
