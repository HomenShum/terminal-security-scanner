# Target discovery

## 2026-10-15 — Fail the scan when a discovered file cannot be read

Propagate a descriptive read error instead of treating failure as an empty file. The existing
CLI then stops before publishing a clean report; opened large-read descriptors close in finally.
Legitimate empty reads and the existing size policy remain unchanged.
**Commit**: this entry's commit (see `git log --follow`). **Author**: Codex.
**Touches**: [CLI scenarios](../tests/cli.md), [README](../docs/readme.md).

## 2026-10-15 — Exclude personal targets before discovery reads

Add a default-true home inclusion argument to the existing discovery function and guard its
personal history/dotfile loops. Under no-home, the same synthetic probe's personal metadata
accesses fall from 26 to zero while project CI, scripts and environment targets remain.
Detectors, target size/depth limits, file reading and report generation are unchanged.
**Commit**: this entry's commit (see `git log --follow`). **Author**: Codex.
**Touches**: [CLI](cli.md), [CLI scenarios](../tests/cli.md), [README](../docs/readme.md).
