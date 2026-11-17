Remove the project's ipe-owned build output (out/, .ipe/).

```
ipe clean
```

## Options

- `[--json]` — emit the result as JSON ({"schema":"ipe.cli.clean/1","removed":[…]})
- `[--plain]` — print one removed path per line, flush-left

## Output

The removed paths. Development builds keep their compiled dependencies in one shared per-user cache directory per compiler version (`<cache>/ipe/t/dev-<key>`), which `ipe clean` keeps and which is removed once unused for 30 days; with `CARGO_TARGET_DIR` or another target-dir pin set, a release builds in `<pin>/release-ipe/`.
