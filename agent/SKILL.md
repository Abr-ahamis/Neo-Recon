# Development rules

Keep modules compact and responsibility-focused. Use Python for orchestration, concurrency, state, PTY/process handling, terminal management, and parsing. Use each service's Bash `run.sh` for invoking native reconnaissance tools. Use argv-safe process calls and explicit scope.

Parsers and deterministic rules operate separately from immutable raw evidence. Service runners show the command and stream native stdout/stderr live while preserving the same output in the evidence store. Avoid framework narration and custom dashboards.

Do not turn placeholders into fake implementations. Add tests when implementing behavior, using saved native-output fixtures where appropriate.
