Run extensible static analysis over Ipê source (idiom, consistency, safety-by-convention).

```
ipe lint [<path>]
```

## Arguments

A source file or a project directory to lint. Defaults to the current project.

## Options

- `[--fix]` — apply every machine-applicable (semantics-preserving) fix instead of only reporting
- `[--json]` — emit findings as a JSON array ({"schema":"ipe.cli.lint/1","findings":[…]}); exit non-zero when the gate trips
- `[--plain]` — print one finding per line flush-left (rule:file:line:col: message), no decoration
