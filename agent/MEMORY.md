# Project memory

- Terminal-first, single-target CTF/lab reconnaissance orchestrator.
- RustScan precedes Nmap; classification uses detected protocol/fingerprint, not only ports.
- Python owns framework orchestration; service `run.sh` scripts invoke native tools.
- Worker terminals show real commands and live native output; raw evidence is preserved unchanged.
- The main terminal collects completed output with minimal separators/headers.
- Independent service tasks run concurrently; dependencies define ordering.
- Parsers, shared state, and deterministic rules drive adaptive read-only enumeration.
- A central dependency manager handles declared tool/package requirements.
- Current code implements initial execution/discovery and adaptive SMB, HTTP, FTP, SSH, LDAP, and DNS workers; many module folders remain placeholders.
- Tests use deterministic fixtures for service parsers/traversal; localhost live discovery was checked, but live service modules have not been verified.
- Dependency installs are centrally managed and disabled by default. No brute force, destructive writes, or automatic scope expansion.
