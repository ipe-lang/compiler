Build the production artifact — optimised, Debug.* gated. Native-bearing apps get a jailed bundle; pure-native apps get a plain optimised binary; `web desktop|ios|android` produces a production app bundle; `--target wasm` produces a production browser bundle.

```
ipe release build [<path>] [<shape>] [<runtime>] [<host>]
```

## Arguments

A source file, a project directory, or a package.ipe (default: the current project). shape/runtime/host are the delivery grammar shared with `dev build`: a `desktop`/`ios`/`android` host lays out the production app bundle for that host (a self-contained desktop bundle, or a native mobile system-webview shell). An `android` host produces an unsigned Gradle project: a store build needs your own keystore configured in Gradle. With no delivery args, `release build` builds every delivery declared in package.ipe (`dev build` builds only the default one).

## Options

- `[--out <dir>]` — put the artifact under <dir>/release/ (default: out/ in the project)
- @--target
- @--static
- @--emit-permissions
- `[--runtime <dir>]` — vendor the Ipê runtime source from <dir>
- `[--bundle]` — native-bearing only: multi-file opt-out — wrapper + app + profile as siblings (app binary can be run directly, bypassing the sandbox)
- `[--embed]` — native-bearing only: default single self-jailing binary (app + profile fused into wrapper)
- `[--plain|--json]` — the layout of a refusal: the terse flush-left record or one stable JSON object
