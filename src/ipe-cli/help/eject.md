Emit a self-contained Rust project with a tree-shaken runtime.

```
ipe eject [<path>]
```

## Arguments

A source file, a project directory, or a package.ipe. Defaults to the current project.

## Options

- `--out <dir>` — write the standalone project to <dir>, which must be absent or empty and outside out/, .ipe/ and any other ipe-owned tree (required)
- `[--runtime <dir>]` — vendor the Ipê runtime source from <dir>
