# Tasks

## Structure

- [x] Create the requested root, `agent/`, and `scr/` package layout.
- [x] Add inert service and script placeholders.
- [x] Mark all shell placeholders executable.
- [x] Add package markers, documentation placeholders, and empty wordlist/evidence directories.

## Implemented

- [x] CLI and target context.
- [x] Task model, scheduler, process/PTY runner, terminal manager, and cancellation.
- [x] Raw evidence storage and command metadata.
- [x] RustScan, Nmap, port extraction, and protocol classifier.
- [x] Central dependency manager with opt-in install behavior.
- [x] Initial adaptive SMB, HTTP, FTP, SSH, LDAP, DNS workers and shared context.
- [x] Fixture tests for implemented components.
- [x] Normal RustScan command/output path and native `Open host:port` parsing; live fake-tool stream verified.
- [x] Blue collector headers with raw output bytes unchanged.
- [x] Worker terminals hand control back to an interactive shell after success or Ctrl-C.
- [x] Hyprland placement counts every visible application window, reserves capacity before launch, and rechecks the five-window total after launch.
- [x] One terminal worker per service task; active native commands are deduplicated.
- [x] Bounded HTTP path/vhost wordlists and discovery-based copyable follow-up commands for implemented workers.
- [x] Registered executable fallback selection for selected HTTP/FTP and DNS operations.
- [x] Evidence-based hostname/domain context and atomic `/etc/hosts` updates with backups.

## Remaining

- [ ] Multi-terminal Hyprland placement, interactive Ctrl-C, and all active service live-terminal integration tests on the target desktop.
- [ ] Broaden verified executable fallbacks beyond selected HTTP/FTP and DNS operations.
- [ ] Improve authorized credentials and service-specific permission modeling.
- [ ] Implement Kerberos, WinRM, RDP, database, NFS, SNMP, Docker, Kubernetes, and other planned workers.
- [ ] Expand classifier safely for uncommon/custom services.
- [ ] Complete end-to-end integration and robustness coverage.
