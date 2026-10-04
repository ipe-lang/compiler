Build the production artifact (cached), then run exactly that artifact, jailed to its capabilities.

```
ipe release run [<path>]
```

## Arguments

A source file, a project directory, or a package.ipe (default: the current project). Every run builds from source and runs exactly what it built, confined: the default single binary jails itself, and a pure-native binary runs jailed to its consented capabilities. A prebuilt release directory (one holding `ipe-wrapper`, `ipe-app` or `ipe.profile` and no project manifest) is refused, because its capability grant is attested only by its own files: run a deployed bundle through its own `./ipe-wrapper`. A `--target wasm` or `web solo|desktop|ios|android` build has no run form and is refused: build it with `ipe release build`.

## Options

- `[--out <dir>]` — put the artifact under <dir>/release/ (default: out/ in the project)
- @--target
- `[--runtime <dir>]` — vendor the Ipê runtime source from <dir>
- `[-- <args>...]` — forward <args> to the artifact
