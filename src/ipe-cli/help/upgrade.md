Self-update ipe to the latest release (re-runs the installer).

```
ipe upgrade
```

## Options

- `[--check]` — report whether an upgrade is available, never install
- `[--check --exit-code]` — exit 10 = available, 0 = up-to-date, 2 = feed unreachable
- `[--yes|-y]` — skip the confirmation prompt (implied by non-TTY stdout)
- `[--dry-run]` — print the installer command without running it
- `[--agents]` — `ipe upgrade --agents` upgrades this project's AGENTS.md to this ipe's guide and never ipe itself; for a hand-edited file it asks on a terminal before backing the file up to `.ipe-backup/` and replacing it, and refuses without a terminal; combines only with `[--plain]` / `[--json]`, which never ask
- `[--plain]` — print one terse status line, flush-left (never prompts)
- `[--json]` — print the status as JSON (never prompts)
