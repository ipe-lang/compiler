# Ipê language playground (in-browser Ipê → Rust, sandboxed run)

A split-pane playground: you type Ipê on the left; the parse → resolve →
typecheck → lower → emit pipeline runs **in your browser** as a WebAssembly
module (the `ipe-wasm` crate) and the right pane shows the emitted Rust or the
compiler diagnostics, near-instantly. **Run** ships the emitted Rust to a local
Ipê server, which builds and executes it inside a bubblewrap jail and streams
the real program output back.

## Layout

| Path | What it is |
|---|---|
| `index.html` | the three-pane UI (Ipê source \| emitted Rust \| program output) |
| `pkg/` | git-ignored wasm-bindgen output the page loads |
| `setup/` | one-command setup: wasm bundle + jail-runner + offline cache warm |
| `build/` | Ipê program that rebuilds only the wasm bundle (`pkg/`) |
| `server/` | an `Ipe.Http.Server` app (static files + `POST /run`) |
| `jail-runner/` | a Rust workspace member: the sandboxed build+run harness |

## Prerequisites

- The `ipe` compiler binary (build from this repo: `cargo build -p ipe`).
- For `POST /run`: `bwrap`, `timeout`, `prlimit` (the jail primitives).
- The `wasm32-unknown-unknown` rustup target and a matching `wasm-bindgen` CLI
  (the setup program probes for these and prints install hints if missing).

## Setup (one command)

```sh
cd examples/wasm/language-playground/setup
ipe dev run
```

`setup/src/Main.ipe` runs the full setup in one step:
probes prerequisites (`git`/`cargo`/`rustup`/`wasm-bindgen`),
builds `ipe-wasm` for `wasm32-unknown-unknown` (release),
runs `wasm-bindgen` into `../pkg/`, builds `playground-jail-runner`,
and pre-warms the offline dependency cache.
Styled install hints and a non-zero exit on any missing tool.

## Run

```sh
cd examples/wasm/language-playground/server
ipe dev run
```

This starts the Ipê server (`Ipe.Http.Server`, port 8000), which serves the
playground root and `/pkg` statically and answers `POST /run`. Open
http://localhost:8000.

## Rebuild the bundle only

If you change `ipe-wasm` and only need to regenerate `pkg/` (skipping the
jail-runner rebuild and prewarm):

```sh
cd examples/wasm/language-playground/build
ipe dev run
```

## Manual steps (reference)

The one-command setup above runs these steps in sequence:

```sh
# 1. Build the wasm bundle
cd examples/wasm/language-playground/build && ipe dev run

# 2. Build the jail-runner and warm the offline cache
cargo build -p playground-jail-runner
# warm cache defaults to $IPE_PLAYGROUND_WARM_DIR or ~/.cache/ipe/playground-warm
$(cargo metadata --format-version 1 --no-deps | jq -r '.target_directory')/debug/jail-runner prewarm
```

(`prewarm` builds the fixed crate-template dependency closure with network on;
every jailed build after that is fully offline.)

## How `POST /run` works

1. The in-browser compiler emits a Rust project (each file under a
   `// ==== path ====` banner, then the emitted `Cargo.toml`).
2. `server/src/Runner.ipe` stages the split files under
   `~/.cache/ipe/playground-runs/<token>/` and execs
   `jail-runner run <project-dir> --wall 300 --warm <warm>` — a direct argv
   vector, no shell.
3. `jail-runner` builds the crate (`cargo build --offline`) **and** runs the
   resulting app binary inside a bubblewrap jail: network denied
   (`--unshare-net`), host filesystem read-only, `prlimit` caps, wall-clock
   kill, and — for the run phase — a seccomp filter that denies subprocess
   creation. The jail is the `ipe_sandbox` crate the compiler SEAL uses.
4. The server streams a `── Build ──` / `── Run ──` / `── Error ──`
   transcript back to the page.

The security model and the load-bearing tests live in
[docs/topics/playground.md](../../../docs/topics/playground.md) and
`jail-runner/tests/sandbox_security.rs`.
