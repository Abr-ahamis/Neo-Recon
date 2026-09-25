# Architecture

Implemented initial flow:

```text
main.py -> cli/config -> RustScan -> Nmap -> classifier -> concurrent scheduler
                                                 -> service module -> run.sh -> native tool
                                                 -> parser/rules -> resource traversal
```

Python owns shared target context, task scheduling, process and PTY control, terminal management, evidence metadata, parsing, and deterministic decisions. Implemented service packages declare commands, parser/rules, dependencies, and a Bash `run.sh` entry point. The runner executes the native argv it receives; unimplemented service folders remain placeholders.

Evidence is organized under `scr/scans/<target>/<timestamp>/`, with raw command output separate from metadata. Parsers may interpret output for decisions; they never alter raw evidence. Independent service tasks run concurrently when dependencies permit. Ctrl-C cancels worker process trees, and one failed worker does not stop unrelated tasks.

## Output and dependencies

Raw output is authoritative. The main collector may add only a minimal command/service header and separators. Service dependencies are declared centrally and mapped to package names by the dependency manager. Never store sudo passwords or silently add repositories.

The generic resource model tracks service, target, port, protocol, parent, depth, path, access, authentication, and status. Traversal deduplicates resource IDs and enforces depth, task, file, directory, and download limits. Implemented adaptive workers are SMB, HTTP, FTP, LDAP, and DNS; SSH has an authentication-context-dependent identity path rather than recursive resource traversal.

Independent classified service modules use the dependency-aware scheduler. Missing tools are centrally detected; optional apt/pacman installation is disabled in the default config. No sudo password is stored, and no repository is added automatically.
