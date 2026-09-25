# Agent instructions

Read `GOAL.md`, `ARCHITECTURE.md`, `SERVICES.md`, `PLAN.md`, `TASK.md`, `SKILL.md`, `MEMORY.md`, and `DESIGN_RULES.md` before changing project structure or architecture.

Native tool output is evidence. Never rewrite, normalize, summarize, or prettify it. Worker terminals show the actual command and live native stdout/stderr, and the same stream is saved. The main terminal adds only minimal command/service headers and separators around completed output.

Python owns the CLI, orchestration, tasks, scheduling, PTY/process control, terminals, evidence, parsing, and rules. Implemented service `run.sh` files are thin native-command exec wrappers; service packages that are not implemented remain explicit placeholders. Service Python files provide metadata, command definitions, parsing, rules, and dependency declarations. Do not make placeholders pretend to scan.

Keep defaults read-only and scope-limited. Do not add brute force, spraying, persistence, destructive writes, or automatic expansion to unrelated hosts. Do not store sudo passwords or silently add repositories.
