# Target discovery

## 2026-10-15 — Exclude personal targets before discovery reads

Add a default-true home inclusion argument to the existing discovery function and guard its
personal history/dotfile loops. Under no-home, the same synthetic probe's personal metadata
accesses fall from 26 to zero while project CI, scripts and environment targets remain.
Detectors, target size/depth limits, file reading and report generation are unchanged.
**Commit**: this entry's commit (see `git log --follow`). **Author**: Codex.
**Touches**: [CLI](cli.md), [CLI scenarios](../tests/cli.md), [README](../docs/readme.md).
