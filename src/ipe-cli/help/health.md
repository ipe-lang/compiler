Diagnose the build environment and offer consent-gated setup.

```
ipe health
```

## Options

- `[--yes|-y]` — apply every suggested fix without prompting (for CI / provisioning)
- `[--plain]` — print one status record per line, flush-left (never mutates)
- `[--json]` — print the report as JSON for jq (never mutates)

## Output

A report on stdout; in a project it also rates the AGENTS.md guide current, stale or missing and never edits it (`ipe upgrade --agents` refreshes it).
