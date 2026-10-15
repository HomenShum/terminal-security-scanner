# CLI regression scenarios

## 2026-10-15 — Reject clean output after a discovered file disappears

Run one guarded synthetic CLI scenario that removes an owned file after discovery and before
reading. Require unsuccessful exit, the original read error, no clean JSON and unchanged prior
report bytes; preserve the original default/no-home, burst and repeated-scan scenarios.
**Commit**: this entry's commit (see `git log --follow`). **Author**: Codex.
**Touches**: [File reading](../scripts/targets.md), [README](../docs/readme.md).

## 2026-10-15 — Delegate runtime loading to the installed tsx CLI

Resolve the existing `tsx/cli` export and forward `--require` to the scanner child so the
tests do not directly require Node's newer `--import` flag. The child still verifies synthetic
HOME before scanning, and default home inclusion must record personal accesses to prove that
the real scanner's trace is observed. This preserves the declared engine range without
claiming that older Node releases or other platforms were executed.
**Commit**: this entry's commit (see `git log --follow`). **Author**: Codex.
**Touches**: [CLI](../scripts/cli.md), [discovery](../scripts/targets.md), [README](../docs/readme.md).

## 2026-10-15 — Exercise project scope through the actual CLI

Run the existing tsx CLI against verified synthetic HOME and USERPROFILE values. Cover projects
inside, outside and sharing a home prefix; two concurrent bursts; default personal inclusion;
clean and missing-optional-file cases; and six repeated scans with exact saved-report checks.
The original runtime fails three of four new scenarios; the corrected runtime passes all four
alongside the unchanged 21 detector cases. An external post-discovery-filter control still
detects project threats but makes personal metadata reads, proving that filter is insufficient.
**Commit**: this entry's commit (see `git log --follow`). **Author**: Codex.
**Touches**: [CLI](../scripts/cli.md), [discovery](../scripts/targets.md), [README](../docs/readme.md).
