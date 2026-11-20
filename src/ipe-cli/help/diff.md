Compare two package versions' public APIs and report the required semver bump.

```
ipe diff <old> <new>  |  check <old> <new> <old-version> <new-version>
```

## Arguments

- `<old>` — the old package path to compare
- `<new>` — the new package path to compare

## Subcommands

- `check` — compares the same `<old> <new>` paths and two more positionals, `<old-version>` and `<new-version>`, also rejecting a new version that does not clear the required bump (`--check <old-version> <new-version>` is a deprecated alias)

## Options

- `[--plain]` — print flush-left change / bump records for grep/awk
- `[--json]` — print the report as a stable JSON object for jq
