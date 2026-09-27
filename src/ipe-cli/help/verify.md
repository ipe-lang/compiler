Run the whole project gate: format, type-check, build, then test.

```
ipe verify [<path>]
```

## Arguments

A source file, a project directory, or a package.ipe. Defaults to the current project.

## Options

- `[--json]` — emit a compact gate verdict on stdout ({"result":…}; non-zero exit at the first failing stage)
