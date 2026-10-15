# First-run documentation

## 2026-10-15 — Document locked setup and private scan boundaries

Start newcomers with checkout, npm ci, build and local help before scanning. Explain personal
home inclusion, the corrected project behavior, report locations, exit codes and potentially
sensitive snippets so users can choose a scan scope and share results carefully. Record the
actual Node 22/Windows verification limit; no release or broader security certification is claimed.
**Commit**: this entry's commit (see `git log --follow`). **Author**: Codex.
**Touches**: [CLI](../scripts/cli.md), [discovery](../scripts/targets.md), [CLI scenarios](../tests/cli.md).

The historical example now links to the canonical HomenShum/NodeBenchAI repository; its numbers were not reproduced or recertified in this change.
