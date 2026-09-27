Manage Rust crates as foreign-function dependencies.

```
ipe rust <add|remove|install> [<args>...]
```

## Arguments

The action to run (add / remove / install) and its arguments.

## Options

- `[--features <a,b>]` — add: enable the listed crate features
- `[--yes]` — add/install: skip the trust-summary confirmation prompt
- `[--allow-build-scripts]` — add/install: permit the crates' build scripts to run
- `[--verbose]` — add/install: show the full raw inspector log on failure
