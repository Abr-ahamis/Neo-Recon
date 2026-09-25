# Plan

1. [x] CLI, target context, evidence layout, task model, PTY/process handling, terminal adapter, cancellation, metadata, and scheduler.
2. [x] RustScan discovery, port extraction, Nmap detection, and service classification.
3. [x] Initial adaptive SMB, HTTP/HTTPS, FTP, SSH, LDAP/LDAPS, and DNS workers.
4. [~] Generic resource traversal, deterministic parsers/rules, and bounded pivots exist; more service/auth edge cases require implementation and testing.
5. [ ] Add Windows/AD, database, and infrastructure service modules.
6. [ ] Harden live terminal/process cleanup and complete local integration coverage.
7. [ ] Consider an optional local AI advisor only after deterministic behavior is stable.

The next priority is live localhost integration for implemented modules, followed by remaining Windows/AD and database workers. Run the test suite after each change and keep unsupported services explicitly partial.
