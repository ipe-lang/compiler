Build and run the project's tests/Main.ipe, reporting pass/fail.

```
ipe test [<path>]
```

## Arguments

- `[<path>]` — a project directory, its package.ipe, or a module file under `src/` or `tests/` of the current directory's project, which selects that project (default: the current directory's project)

## Notes

- The tests always run from the project's tests/Main.ipe and build with its package.ipe settings, its database driver included.

## Options

- `[--json]` — emit a compact {"result":…} verdict on stdout (non-zero exit on a failing case)
