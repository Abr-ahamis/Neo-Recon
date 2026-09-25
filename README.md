# Neo-Recon

Neo-Recon is a terminal-based reconnaissance orchestrator for authorized CTF and lab targets. The Python controller runs RustScan, passes discovered ports to Nmap, classifies service fingerprints, then schedules implemented service workers concurrently.

Run from the repository root:

```bash
python3 main.py 10.10.10.10
```

With no positional target, the CLI prompts once when attached to a terminal. `--ports` can constrain RustScan for a lab check. RustScan and Nmap must already be installed; service tools are checked centrally. Dependency installation is disabled by default and can be enabled in `scr/config/default.toml`.

## Current implementation

The execution core includes target validation, task states, dependency-aware concurrency, process-group timeout/cancellation, PTY streaming, raw evidence capture, metadata, worker terminal selection, and bounded resource traversal. Discovery is RustScan → Nmap → protocol/fingerprint classification. Adaptive workers currently exist for SMB, HTTP/HTTPS, anonymous FTP, SSH host keys/explicit key authentication, anonymous LDAP/LDAPS, and DNS.

These workers are an initial implementation, not complete coverage of every protocol or authentication path. Other service directories remain placeholders. See [agent/SERVICES.md](agent/SERVICES.md) and [agent/TASK.md](agent/TASK.md) for status and remaining work.

## Evidence and output

Each scan is stored under `scr/scans/<target>/<timestamp>/`. Native command streams are saved separately from metadata. Parsers operate on a separate copy; PTY output processing is disabled to preserve line endings. The main collector adds only service/command separators. Default enumeration is read-only and target-scoped; no credential guessing or automatic expansion to discovered hosts occurs.

RustScan uses its normal command form, `rustscan -a TARGET -- -oN PATH`, without greppable `-g` output. Its live terminal stream is captured separately in `discovery/rustscan.log`; Nmap-style open-port lines are parsed for the next discovery stage. Worker output is forwarded as it arrives and saved byte-for-byte. Completed native output is appended to the main terminal with blue framework separators; tool output colors and bytes are left untouched. On Hyprland, the workspace manager counts every visible application window and places each new worker only where the total remains at or below five. It reserves placement before opening each terminal and rechecks after launch. Nmap hostnames/domains are added to shared scan context; `/etc/hosts` updates are backed up and atomic, and a permissions failure is recorded without stopping the scan. `--output-root` directs a scan's complete evidence tree to a chosen path such as `/tmp`.

Each active service runs as one worker in its own terminal. When enumeration ends or is interrupted with Ctrl-C, the worker returns control to an interactive shell; saved evidence and command metadata remain available. HTTP runs native ffuf against a bounded copy of installed SecLists `common.txt` when available, with the bundled quick list and curl probes as fallback. Matches are checked against a random-path baseline, and bounded virtual-host checks are available when a domain is known. Finished workers print copyable follow-up commands only when they are supported by discoveries and installed tools. Fallback selection currently covers selected HTTP/FTP and DNS tools; other service fallbacks remain incomplete. Real Hyprland placement depends on `hyprctl`; without it, the configured terminal emulator or tmux fallback is used.
