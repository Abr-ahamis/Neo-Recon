# Design rules

1. Never rewrite native tool output or raw evidence.
2. Worker terminals show the real command and live tool output.
3. The main terminal adds only minimal separators and command/service headers.
4. Enter the target once and share it through context.
5. Classify by protocol/fingerprint; port is a hint.
6. Run independent tasks concurrently and deduplicate follow-up tasks.
7. Keep defaults read-only, non-destructive, and scope-limited.
8. Bash service runners invoke native tools; Python owns orchestration and state.
9. Keep service modules small and failure-isolated.
10. Do not add fake placeholder implementations or decorative framework output.
