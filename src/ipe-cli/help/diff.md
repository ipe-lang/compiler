Compare two package versions' public APIs and report the required semver bump.

```
ipe diff <old> <new>  |  check <old> <new> <old-version> <new-version>
```

## Arguments

The two package paths to compare — the old version first, then the new. `check`: also reject a new version that does not clear the required bump (`--check <old-version> <new-version>` is a deprecated alias).

## Options

- `[--plain]` — print flush-left change / bump records for grep/awk
- `[--json]` — print the report as a stable JSON object for jq
