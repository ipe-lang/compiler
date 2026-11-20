Run the whole project gate: format, type-check, build, then test.

```
ipe verify [<path>]
```

## Arguments

- `[<path>]` — a project directory, its package.ipe, or a module file under `src/` or `tests/` of the current directory's project (default: the current directory's project)

## Options

- `[--json]` — emit a compact gate verdict on stdout ({"result":…}; non-zero exit at the first failing stage)
