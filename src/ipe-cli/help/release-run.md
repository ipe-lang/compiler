Build the production artifact (cached), then run exactly that artifact, jailed to its capabilities.

```
ipe release run [<dir>|<artifact-dir>]
```

## Arguments

A project directory (default: the current directory), or a built artifact directory holding `ipe-wrapper`. Every run is confined: the default single binary jails itself, a bundle is verified against the floor embedded in its app and then jailed, and a pure-native binary runs jailed to its consented capabilities. An artifact directory runs as built, so it takes no build options. A `web client` build (with or without `desktop`/`ios`/`android`) or a served `web desktop` bundle has no run form and is refused: build it with `ipe release build`.

## Options

- `[--out <dir>]` — put the artifact under <dir>/release/ (default: out/ in the project)
- `[--target <triple>]` — a musl-static native <triple> (default: x86_64-unknown-linux-musl). The browser bundle is `web client`, never a target; a `web client` or app-bundle delivery takes no target.
- `[--runtime <dir>]` — vendor the Ipê runtime source from <dir>
- `[-- <args>...]` — forward <args> to the artifact
