Format Ipê source files.

```
ipe fmt [<path>]
```

## Arguments

A file or directory to format (`.` for the current directory).

## Options

- `[--check]` — report unformatted files without rewriting them
- `[--check --json|--plain]` — with --check, emit the unformatted file list as JSON ({"unformatted":[…]}) or one path per line
- `[--stdin]` — format stdin to stdout (for editors and pipes); excludes <path>
