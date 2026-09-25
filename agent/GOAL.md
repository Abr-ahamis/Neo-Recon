# Goal

Build a terminal-based reconnaissance orchestrator for authorized CTF/lab environments. The user enters one target once. The planned flow is RustScan, Nmap service/version detection, protocol-based classification, parallel service workers, adaptive read-only enumeration, and persistent raw evidence.

The repository now has a working initial execution/discovery foundation and adaptive SMB, HTTP, FTP, SSH, LDAP, and DNS workers. This is a partial implementation: many planned service families, credential paths, and live protocol integrations remain incomplete. Continue from the actual code and tests; do not infer completion from the directory structure.
