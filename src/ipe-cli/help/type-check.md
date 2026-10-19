Type-check a program without building or running it.

```
ipe type-check [<path>]
```

## Arguments

A module file under `src/` or `tests/` of the current directory's project, a project directory, or a package.ipe. Defaults to the current directory's project, every entry.

## Options

- `[--json]` — emit each diagnostic as a stable JSON object (one per line) on stderr; success is the shared JSON envelope on stdout
