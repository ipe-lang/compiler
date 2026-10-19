Run extensible static analysis over Ipê source (idiom, consistency, safety-by-convention).

```
ipe lint [<path>]
```

## Arguments

A module file under `src/` or `tests/` of the current directory's project, whose findings alone are reported and fixed, or a project directory. Defaults to the current directory's project, every module.

## Options

- `[--fix]` — apply every machine-applicable (semantics-preserving) fix instead of only reporting
- `[--json]` — emit findings as a JSON array ({"schema":"ipe.cli.lint/1","findings":[…]}); exit non-zero when the gate trips
- `[--plain]` — print one finding per line flush-left (rule:file:line:col: message), no decoration
