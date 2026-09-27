Report the security capabilities a program exercises, inferred from its code.

```
ipe capabilities [<path>]
```

## Arguments

A source file, a project directory, or a package.ipe. Defaults to the current project.

## Options

- `[--plain]` — print the bare capability names, one per line, flush-left
- `[--json]` — print the capability set as a stable JSON envelope for jq
