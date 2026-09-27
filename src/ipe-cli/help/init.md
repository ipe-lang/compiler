Scaffold a new Ipê project.

```
ipe init [<directory>] [<shape>] [<runtime>]
```

## Arguments

directory: where to scaffold (`.` or omitted → the current directory). shape: script | tui | cli | server | web (default web) — picks the template. runtime (web only): served (default) | solo — seeds the default delivery. Host and target are delivery choices, chosen later at build/release. On a TTY an omitted positional is prompted; a re-run reconciles (creates only missing files) and refuses a shape that conflicts with the existing `main`.

## Options

- `[--shape <shape>]` — select the shape without a positional (script|tui|cli|server|web)
- `[--force]` — overwrite a non-empty target directory
- `[--lib]` — scaffold a library package (exposedModules) instead of an application
