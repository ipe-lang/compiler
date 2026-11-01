Format Ipê source files.

```
ipe fmt [<path>...]
```

## Arguments

Files and directories to format; a directory formats every `.ipe` under it (`.` when none is given). A file reached twice is formatted once. Every file is formatted before any is written, so one refused file leaves them all unchanged.

## Options

- `[--check]` — report every unformatted file without rewriting any
- `[--check --json|--plain]` — with --check, emit the unformatted file list as JSON ({"unformatted":[…]}) or one path per line
- `[--stdin]` — format stdin to stdout (for editors and pipes); excludes every <path>
