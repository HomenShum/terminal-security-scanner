# CLI scanning

## 2026-10-15 — Preserve explicitly selected projects with no-home

Pass the personal-target decision into discovery instead of rejecting every path beginning
with HOME. A synthetic project inside HOME or a near-prefix sibling previously returned zero
files and exit 0; the same built-CLI probe now retains all four project files and three HIGH
findings with exit 1. Default home scanning remains unchanged.
**Commit**: this entry's commit (see `git log --follow`). **Author**: Codex.
**Touches**: [discovery](targets.md), [CLI scenarios](../tests/cli.md), [README](../docs/readme.md).
