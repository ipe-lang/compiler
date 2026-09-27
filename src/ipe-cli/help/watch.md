Rebuild and re-run a program on every source change.

```
ipe watch [<path>]
```

## Arguments

A source file, a project directory, or a package.ipe. Defaults to the current project.

## Options

- @--out
- @--runtime
- `[--port <n>]` — serve on port <n> (default: 8000)
- `[--debugger]` — compile the in-app time-travelling debugger overlay into the served app
- `[--reset-state]` — force every returning session to a fresh init instead of preserving prior state
- @--quiet
