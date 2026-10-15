# Change entry format

Keep one lane per surface. Add new entries at the top; preserve prior entries.
Use `git log --follow` to find the entry's commit and cross-link other affected lanes.

```md
## YYYY-MM-DD — Short imperative title
Explain the change and its user-visible reason in one to three sentences.
**Commit**: this entry's commit (see `git log --follow`). **Author**: Name.
**Touches**: other affected lanes.
```
