Build the production artifact, optimised and with Debug.* gated. Native-bearing apps get a jailed bundle; pure-native apps get a plain optimised binary; `web desktop` and `web client desktop|ios|android` produce a production app bundle; `web client` produces a production browser bundle.

```
ipe release build [<dir>] [<shape>] [<runtime>] [<host>]
```

## Arguments

A project directory (default: the current directory). shape/runtime/host are the delivery grammar shared with `dev build`: a `desktop`/`ios`/`android` host lays out the production app bundle for that host (a self-contained desktop bundle, or a native mobile system-webview shell). An `android` host produces an unsigned Gradle project: a store build needs your own keystore configured in Gradle. With no delivery args, `release build` builds every delivery declared in package.ipe (`dev build` builds only the default one).

## Options

- `[--out <dir>]` — put the artifact under <dir>/release/ (default: out/ in the project)
- `[--target <triple>]` — a musl-static native <triple> (default: x86_64-unknown-linux-musl). The browser bundle is `web client`, never a target; a `web client` or app-bundle delivery takes no target.
- @--static
- @--emit-permissions
- `[--runtime <dir>]` — vendor the Ipê runtime source from <dir>
- `[--bundle]` — native-bearing only: multi-file opt-out — wrapper + app + profile as siblings (app binary can be run directly, bypassing the sandbox)
- `[--embed]` — native-bearing only: default single self-jailing binary (app + profile fused into wrapper)
- `[--plain|--json]` — the layout of a refusal: the terse flush-left record or one stable JSON object
