# Services

Every service package contains `module.py`, `commands.py`, `parser.py`, `rules.py`, `dependencies.py`, and an executable `run.sh`. The Bash runner is a thin native-command `exec` entry point; Python files describe and integrate the module.

Implemented initial workers:

- **SMB:** anonymous share listing and target-scoped auth-file support; share/directory traversal, access parsing, file classification, and bounded inspection of interesting files. No write tests.
- **HTTP/HTTPS:** curl requests, random-path baseline, status/body soft-404 filtering, bounded seed paths, same-origin link recursion, response metadata, and native ffuf using a bounded copy of installed SecLists `common.txt` when available. Without ffuf, it falls back to bounded curl probes from the bundled quick list. Virtual-host candidates use a bounded installed DNS wordlist or bundled list.
- **FTP:** anonymous LIST traversal and bounded interesting-file probes when size is known. No credential guessing.
- **SSH:** host-key collection; safe identity commands run only with an explicitly supplied target-scoped private key.
- **LDAP/LDAPS:** anonymous RootDSE and naming-context/OU/container traversal, with users/groups/computers and selected attributes added to shared context.
- **DNS:** target/domain SOA/NS/record follow-ups over UDP and TCP; names are recorded in context without scanning their addresses.

Kerberos, WinRM, RDP, databases, NFS, SNMP, Redis, Docker, Kubernetes, email, messaging, CI/CD, monitoring, and uncommon protocols remain placeholders or classifier-only.

Current tests use fixtures; they do not establish live service compatibility. The only recorded live integration is a bounded localhost RustScan→Nmap discovery check. Classify from protocol/service evidence rather than port alone. Defaults are enumeration-focused. Do not brute-force credentials, perform write probes, or download unbounded resources. Dependencies are declared per module and resolved centrally.
