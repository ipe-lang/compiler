# Ipê examples

This directory contains the Ipê-native first-party examples. Each is a
self-contained Ipê project (a `package.ipe` manifest plus source under `src/`)
that builds with `ipe dev build` and targets the Rust backend.

## First-party examples

| Directory | Shape | What it demonstrates |
|-----------|-------|----------------------|
| `wasm/counter` | wasm/live | Basic TEA counter compiled to WebAssembly via `--target wasm`. The canonical "hello WASM" starting point. |
| `wasm/effects` | wasm/live | `Sub.every` timer and `Cmd.perform` side-effects exercised end-to-end in a browser via the Cmd/Sub bridge (gloo-timers). |
| `wasm/websocket` | wasm/live | `Ipe.WebSocket` client substitute: connect / onOpen / send / onMessage / close / onClose against a real WebSocket server in-browser. |
| `wasm/env-public` | wasm/live | `Ipe.Env.public` build-time config embedding: an allowlisted `API_BASE_URL` variable injected at compile time and readable in WASM at run time. |
| `wasm/spa` | wasm | SPA target: a pure-client single-page application with full TEA loop running in the browser. Uses `Web.tea` which emits `wasm_app` under `--target wasm`. |
| `wasm/hydration` | wasm | SSR hydration: server-side initial render (paint) followed by WASM client takeover. |
| `wasm/language-playground` | n/a (`ipe-wasm`) | The Ipê compiler frontend (parse → typecheck → lower → emit) compiled to WebAssembly: an ACE editor whose contents are compiled to Rust in the browser as you type, showing the emitted Rust or the diagnostics. A companion `Ipe.Http.Server` app (`server/`) plus a bwrap-jailed `jail-runner` workspace member add a sandboxed `POST /run` that builds and executes the emitted Rust. Built via the Ipê build program under `build/` (`cd build && ipe dev run`). See its `README.md`. |

## Shape demos

The per-shape demos linked from [`docs/shapes/`](../docs/shapes/) live under
`shapes/<shape>/`:

| Shape | Directory | What it demonstrates |
|-------|-----------|----------------------|
| terminal | `shapes/terminal/file-browser` | A keyboard-driven directory browser over `Tui.tea`: `File.readDir` lists the working directory, arrow keys navigate, and the selected file's first bytes render as a raw `Ui.cells` hexdump island inside the `Ipe.Ui` view. |
| terminal | `shapes/terminal/http-shell` | An HTTP query shell over `Cli.tea`: each stdin line like `get <url>` performs a real `Http.get` and prints the response status + body. |
| web | `shapes/web/task-publish` | The top-level, Task-shaped `Ipe.PubSub.publish` (`String -> any -> Task Error Int`) fired from a `Ipe.Tea.Web` app's `update` via `Cmd.perform`, with the subscriber count routed back into the model. Shows the Task form composing where a broadcast bus runs. |
| web | `shapes/web/server-mount` | A plain-`main` `Task` `Ipe.Server.Http` server that answers a JSON `/health` route AND mounts a full `Ipe.Tea.Web` (TEA) app at `/` behind the same `Server.listen`. `Web.embed` yields a mountable `WebApp` and `Server.mountApp` serves it beside ordinary `Server.get` handlers — one binary, an API and an interactive UI. |
| script | `shapes/script/release-preflight` | A plain-`main` batch program (no TEA loop): a release-preflight check run to completion. The worked example for the `Ipe.Task` guide and the `do`-notation idiom. |
| script | `shapes/script/word-frequency` | A plain-`main` batch program: a paragraph reduced to its three most common words via one `List` pipeline (tokenize, tally, rank, take). The worked example for the `Ipe.List` and `Ipe.String` guides and the pipe idiom. |
| script | `shapes/script/parse-port` | A plain-`main` batch program demonstrating parse-don't-validate: a `String -> Maybe Port` boundary parser so no downstream code re-checks the range. The worked example for the parse-don't-validate idiom. |

## FFI examples

Shim-free auto-FFI bindings against real crates.io crates, grouped under
`ffi/`. These bind native GUI/ECS crates and are not part of the headless
example sweep.

| Directory | Binds | What it demonstrates |
|-----------|-------|----------------------|
| `ffi/bevy-game` | `bevy_ecs` | A headless ECS world tick over the shim-free auto-FFI: creates a `World`, threads it through real ECS maintenance operations, and reads the final entity count as observable state — every `World.*` call is a generated binding, zero hand-written Rust shims. |
| `ffi/iced-counter` | `iced` | A binding spike mapping Iced's Elm architecture onto Ipê's TEA over the real `iced` crate: the `Model`/`Message` struct + enum bindings are emitted and forwarded; the `update`/`view` closure-to-run wiring is in progress. |

## Running an example

Each example is a self-contained Ipê project. Build it with
`ipe dev build package.ipe` (requires a built `ipe` binary from
`cargo build --release -p ipe`), then run the emitted crate with
`cargo run --manifest-path out/rust/Cargo.toml`.

For a WASM example, pass `--target wasm` to `ipe dev build` and serve
`out/rust/www/` with any HTTP server.
