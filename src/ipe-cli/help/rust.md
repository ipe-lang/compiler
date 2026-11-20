Manage Rust crates as foreign-function dependencies.

```
ipe rust <add|remove|install> [<args>...]
```

## Arguments

- `[<args>...]` — the chosen action's own arguments: a crate name, optionally `@version`, for add/remove; none for install

## Subcommands

- `add` — add a Rust crate dependency
- `remove` — remove a Rust crate dependency
- `install` — install the project's declared Rust crate dependencies

## Options

- `[--features <a,b>]` — add: enable the listed crate features
- `[--yes]` — add/install: skip the trust-summary confirmation prompt
- `[--allow-build-scripts]` — add/install: permit the crates' build scripts to run
- `[--verbose]` — add/install: show the full raw inspector log on failure
