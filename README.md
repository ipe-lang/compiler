<div align="center">
    <img width="180" height="180" alt="Yellow Ipê (Handroanthus serratifolius)" src="https://github.com/user-attachments/assets/870f8739-69ab-4b05-af6a-b56c3e615e1c" />
</div>

<br />

[![Install](https://github.com/ipe-lang/compiler/actions/workflows/install-smoke.yml/badge.svg?branch=main)](https://github.com/ipe-lang/compiler/actions/workflows/install-smoke.yml)
[![Build & test](https://github.com/ipe-lang/compiler/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ipe-lang/compiler/actions/workflows/ci.yml)
[![Sandbox](https://github.com/ipe-lang/compiler/actions/workflows/admission-sandbox.yml/badge.svg?branch=main)](https://github.com/ipe-lang/compiler/actions/workflows/admission-sandbox.yml)
[![Supply-chain security](https://github.com/ipe-lang/compiler/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/ipe-lang/compiler/actions/workflows/security.yml)
[![Static binaries](https://github.com/ipe-lang/compiler/actions/workflows/static.yml/badge.svg?branch=main)](https://github.com/ipe-lang/compiler/actions/workflows/static.yml)
[![Docs deploy](https://github.com/ipe-lang/compiler/actions/workflows/docs-pages.yml/badge.svg?branch=main)](https://github.com/ipe-lang/compiler/actions/workflows/docs-pages.yml)

# Ipê language

> [!CAUTION]
> Although most features work, the code is under a thorough review that may last
> 3–4 months. Please consider [supporting the project](#support) so it is ready sooner :)

**Ipê** (pronounced [/ip'e/](https://ipa-reader.com/?text=%09ip%E2%80%B2e&voice=Vitoria)) is a
pure-functional language that compiles to Rust. It extends [Elm](https://elm-lang.org/)'s 
syntax and partially implements [Sky lang](https://sky-lang.org/) standard library. 

It aims to be a community-centered programming language — check out our [principles](PRINCIPLES.md)
to learn more about it.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/ipe-lang/compiler/main/install.sh | sh
```

## Quickstart

```sh
ipe init counter        # scaffolds a served web app — the default shape
cd counter
ipe dev run             # serves at http://localhost:8000 (server-rendered HTML + live SSE)
```

On a TTY `ipe init` asks the shape (`web` / `tui` / `cli` / `worker` / `server` / `script`) and, for the web shape, 
asks which runtime — `served` (a co-located SSR + SSE server) or `solo` (a wasm client).


Name the positionals to skip the wizard — `ipe init <dir> [shape] [runtime]` (host is a build-time choice, not an `init` arg): 
```sh
ipe init myapp web solo     # <dir>=myapp  <shape>=web  <runtime>=solo
```

See [Shapes](#shapes) below and the [getting started](docs/guide/getting-started.md) guide.

The first build of a new project on a fresh machine also compiles the Rust
dependencies of the runtime, so it takes minutes rather than seconds (longer for a
`solo` wasm client). That cost is paid once; later builds reuse the compiled
dependencies — see [Performance](#performance-dev-loop).

## Discover the language

The documentation site — guides, topics, and the full stdlib reference — is at
**<https://ipe-lang.github.io/compiler/>**.

The same documentation ships inside the `ipe` binary, so it works offline and
always matches the version you run. `ipe doc <key>` looks up any entity by key:

```sh
ipe doc Ipe.List        # a module's types and values with their signatures
ipe doc List.map        # one function: its signature and doc-comment
ipe doc case            # a language construct
ipe doc shapes          # a topic
ipe doc IPE-N0004       # a diagnostic code, with its explanation and fix
ipe doc version         # a CLI command
ipe doc list            # every stdlib module (and your project's)
```

A key that names no entry exactly prints the closest matches, each as the
exact `ipe doc …` command that opens it.

`ipe doc serve` builds the whole reference — the stdlib plus your project's own
modules and doc-comments — as an HTML site and serves it read-only on loopback
(`--port <n>` pins the port). Plain `ipe doc` writes it to disk instead —
`docs.json`, Markdown, and HTML under `doc/` (`--out <dir>` to change it).
`ipe doc check` fails when an exposed binding of your project lacks a
doc-comment.

## Shapes

One language; the **head of `main` pins the shape**, never a config field. **Web
(served SSR + SSE) is the default**; the same `Ipe.Ui` view also renders on the
terminal. → **[full shapes guide](docs/topics/shapes.md)**

| Shape | Entry | For |
|---|---|---|
| **Web** *(default)* | `Web.tea` | Browser DOM — served SSR+SSE, or a `solo` wasm client (browser / desktop / iOS / Android hosts) |
| **Tui** | `Tui.tea` | Full-screen terminal UIs |
| **Cli** | `Cli.tea` | Line-oriented CLIs and REPLs |
| **Worker** | `Worker.tea` | A view-less TEA loop (background jobs, timers) |
| **Script** | bare `main : Task Error ()` | Scripts, one-shot tools, `Server.listen`, any `Task` directly |

Web / Tui / Cli / Worker follow [The Elm Architecture](https://guide.elm-lang.org/architecture/).
A `Server` can host many endpoints and mount a full `Web` app on one port:

```elm
main =
    Server.listen 8080
        [ Server.get "/api/health" health
        , Server.mountApp "/app"
            (Web.embed
                -- the same fields as `Web.tea`, written inline
                { init = init, update = update, view = view
                , subscriptions = subscriptions, routes = [], notFound = Home
                }
            )
        ]
```

## Performance (dev loop)

Wall-clock, measured by [`tools/scripts/perf/bench.sh`](tools/scripts/perf/bench.sh) on the `web`
served counter with the released binary, once the runtime's dependencies are compiled:

- **App recompilation:** ≈ 10 seconds — needed only for a **type** change (a `Model` field, a function type signature).
- **Dev watch hot reload:** ≈ 500 **milliseconds** — every other edit (text, `init`, `update`, subscriptions, styles) hot-swaps into the running app, no `cargo`.
- Clean app build (after `ipe clean`) ≈ 18 s · release binary 7.0 MB · peak RAM 7.8 MB. → [faster builds](docs/guide/faster-builds.md)

## Features

- **Elm syntax** — Hindley–Milner inference, exhaustive `case`, immutable data; no `null`, no runtime exceptions.
- **Comprehensive stdlib** — web (SSR + SSE), typed HTTP and SQL, auth, email, cache, pub/sub, WebSockets — all behind one `Task Error a` boundary with a typed `Error`.
- **Compiles to readable Rust**, incrementally (salsa); `ipe dev watch` hot-swaps most edits and recompiles only on a type change.
- **No authored abrupt failure** — the compiler and runtime carry no `panic!` / `unwrap` / `expect` / index panic; every failure is a typed `Result` or diagnostic.
- **Accessible by default** — real `<button>`s, semantic landmarks, a contrast-safe focus ring, and reduced-motion honored out of the box.
- **Rust FFI** — `ipe rust add <crate>` binds a crate as a generated `Rust.<Crate>` interface (sandbox-inspected; discloses the `native-ffi` capability). → [dependencies](docs/guide/getting-started.md)
- **Delivery grammar** — `ipe dev build web desktop|ios|android` for a fast dev bundle, `ipe release build web desktop|ios|android` for a production distributable (desktop-webview or mobile system-webview shell).
- **Eject to plain Rust** — `ipe release eject` vendors and tree-shakes the runtime into a standalone Cargo project you build with no `ipe` toolchain.
- **Static binary** — `ipe dev build --static` produces a fully-static musl single binary — copy and run anywhere.

## Capabilities

Capabilities are inferred, not declared: `ipe release capabilities <entry>` reports exactly what a program may do (network, fs, env, ffi, …).

- `ipe dev` is for fast iteration on code you trust: it does not promise a capability check, a consent prompt, or a jail.
- `ipe release` is for production and for running external packages: it infers capabilities, asks your consent, gates Debug.*, and runs jailed.

Run external packages only through `ipe release`. → [capabilities](docs/reference/capabilities.md)

## Tooling

- `ipe lint` / `ipe lint --fix` — advisory static analysis, configured by a `lint.ipe`. → [lint guide](docs/guide/lint.md)
- `ipe lsp` — completion, go-to-definition, find-references, rename, code actions, semantic tokens over stdio. → [editor setup](docs/topics/editor-integration.md)
- `ipe dev run --record` records a cli/worker app's TEA session (each `(msg, model)` step, bounded ring) to `out/session.ipelog` as plain text, plus a typed `out/session.ipemsgs` when the app's `Msg` is encodable. `ipe dev run --replay [<log>]` rebuilds the app and re-folds `update` over that log from `init` (or from the recorded base, if the ring overflowed) with no `Cmd` fired — no I/O, network or DB effect runs again — printing each step, control bytes stripped, and the final model. The same program and log give byte-identical output, so a hand-typed bug reproduction becomes a shareable regression. A log from a changed program, or a truncated or oversized one, is refused whole. A `Msg` carrying a `Secret` is recorded as a trace only; `--replay` then shows that trace (the default when no typed log exists, or any `.ipelog` you name) — labelled as a trace, nothing re-run, capped, and with every control character stripped, so a handed-over or planted log cannot drive your terminal. Read logs with `--replay`, not `cat`.

  ```sh
  printf 'add 2\nadd 5\n' | ipe dev run --record  # runs the app, writes out/session.ipelog + out/session.ipemsgs
  ipe dev run --replay                               # start + one "<msg> => <model>" line per step + final model
  ipe dev run --replay bug.ipemsgs                   # replay a log someone sent you
  ipe dev run --replay bug.ipelog                    # show a trace someone sent you, sanitised
  ```
- `ipe add <pkg>[@<req>]` / `ipe remove <pkg>` — add or remove an Ipê package dependency. `add` resolves the requirement through the index (fetch, hash-verify), records the exact pin in `ipe.lock`, and writes the requirement into `package.ipe`'s `dependencies` block so a fresh clone re-resolves the same dependency; `remove` drops it from both. Author-written `depGit`/`depPath` escapes are left untouched — `add` never overwrites one.

  ```sh
  ipe add http-extras@^1.2   # → dependencies = [ dep "http-extras" "^1.2" ] in package.ipe + ipe.lock pin
  ipe remove http-extras     # drops it from both files
  ```
- `ipe fmt` · `ipe test` · `ipe verify` · `ipe package audit` — format, test, whole-project gate, and the publish quality gate.
- `ipe package publish` — run the quality gate, compute the package's index entry, and open the index pull request. One-time setup: run `ipe login` (a GitHub device-code flow), so publish can author the index-PR commit under your account's verified GitHub identity, and set `IPE_PUBLISH_SIGNING_KEY` to the path of an SSH signing key (its `.pub` registered as a *signing* key on your GitHub account) so the commit is signed. The curated index requires signed, verified commits; absent either precondition publish fails closed with a typed refusal rather than push a commit that could never merge. `--dry-run` prints the computed entry and intended PR without touching the network.

## Static compilation

`ipe dev build --static` produces a fully-static musl binary (zero runtime dependencies), after running
`rustup target add x86_64-unknown-linux-musl`.

## Support

Contributions are **very** welcome, in order of current need:

- **Donations** — [support Ipê's development](https://ko-fi.com/arthur_maciel??g=1). Thank you! ❤️
- **Pull requests** — most valuable are security / correctness / soundness fixes (a mis-compilation, a panic on valid input, an unsound emit). Every PR must be human-reviewed before submission — unfortunately there is not enough time to review unsupervised AI code.
- **Bug reports** — [report any bug you find](https://github.com/ipe-lang/compiler/issues).
