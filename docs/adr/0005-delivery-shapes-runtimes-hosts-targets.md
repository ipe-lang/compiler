Status: Living (consolidated)
Date: 2026-09-18
Archive: misc/docs/archive/ADR/

# 0005. Delivery: shapes, runtimes, hosts, targets

How an Ipê program declares what it is and how it is delivered. One source
program is classified by its `main` into a *shape*, chosen among a *runtime* and
a *host* at delivery time, and lowered onto a concrete cargo *target*. Two
orthogonal axes (what `view` renders to; where effects execute) plus a
fail-closed `(engine, delivery, triple)` matrix govern every build; a *package*
composes these programs with an optional library surface.

## Decisions

### Shape is inferred from `main`, never declared

A program's shape is fixed by the head of its `main` binding — the single source
of truth. It is never written in `package.ipe` and never taken from a CLI flag as
a second source. Adding a shape adds nothing to any gate keyed on the shape list,
because no gate enumerates that list; the classifier maps one `main` head to one
shape. This keeps configuration from contradicting code: there is no
representable state where the manifest claims one shape and `main` is another.

### The two orthogonal axes: rendering class and effect locality

Every program answers two independent questions:

| axis | question | outcome |
|---|---|---|
| **rendering class** | what does `view` produce? | DOM / cells / lines / http / none → **shape** |
| **effect locality** | does the loop run at native effects? | co-located vs sandboxed → **runtime** |

The rendering class is the shape (fixed by `main`). The effect locality is the
runtime, chosen at delivery time and constrained by the program's effect surface.
Keeping the axes orthogonal is what lets one `Web.tea` source ship either
served-live or as a sandboxed client without a source change or a second entry
point.

### The shape set

> **IMPLEMENTED** — the shape set is four TEA shapes (`web`/`tui`/`cli`/`worker`) plus one direct bucket (`script`). `worker` is a first-class shape; `server` is folded into `script` (a `Direct` `Task Error ()` running `Server.listen`). The account below is current.

There are **four TEA shapes** — `web`, `tui`, `cli`, `worker` — that share the
Elm `init` / `update` / `subscriptions` loop and differ only by their **view
sink**:

| TEA shape | entry | view sink |
|---|---|---|
| `web` | `Web.tea` | DOM |
| `tui` | `Tui.tea` | terminal cells |
| `cli` | `Cli.tea` | terminal lines |
| `worker` | `Worker.tea` | ∅ (no view) |

`worker` is the no-view corner of the same loop: its control model discloses as
TEA, matching its managed loop, not as a run-to-completion program.

A program that uses **no TEA shape** is a plain `main : Task Error ()` — a
**direct** (non-TEA) program, spelled `script`. This is the direct bucket: a
batch tool or an HTTP server alike. A server is a direct program that runs
`Server.listen`; "opening a port" is an *effect* disclosed on the capability
axis (a network-listen capability), not a distinct shape or control model.

### Control models: {Tea, Direct}

> **IMPLEMENTED** — the control-model set is two: {`Tea`, `Direct`}. The retired `Server` model no longer parses; a server's `script` shape projects to `Direct`.

A shape projects to exactly one control model:

- `web` / `tui` / `cli` / `worker` → **Tea** — the managed loop.
- the direct bucket (`script`) → **Direct** — a `Task` the runtime runs to
  completion, however long it takes; a one-shot script or a listening server
  alike.

Server-ness lives on the capability axis, where an effect belongs: a program that
holds a network-listen capability and calls the `Server.*` kernels *is* a server,
disclosed through that capability rather than through a bespoke control model.
The security disclosure ("this opens the network") is preserved — the network
capability is classified and gated independently of the control model — so
folding `Server` into `Direct` drops only an architectural label, never a
security signal.

### Runtime vocabulary: `served` ↔ `solo`

> **IMPLEMENTED** — the runtime vocabulary is `served` (unnamed default; typing it is a `DeliveryError`) and `solo` (the one explicit runtime word). The retired words `live` and `spa` are accepted for one release as deprecated aliases and then removed.

The `web` shape — the only shape with a runtime choice — is delivered under one
of two runtimes:

| runtime | what it means | typed on the CLI? |
|---|---|---|
| **`served`** | a co-located server renders the view and streams live updates (SSR + SSE in the browser, a local IPC bridge on `desktop`); native effects available | **no** — the unnamed default; typing it is a pedagogical error |
| **`solo`** | the app runs self-contained: a WebAssembly client with no co-located server; effects only via Web-API capabilities and HTTP | yes — the one explicit runtime word |

The pair is a mental model: **served** (a server serves it) ↔ **solo** (it flies
solo). `solo` carries no client/server-split baggage and reads correctly on every
host. `served` collapses the internal delivery/canon double-naming onto one word
and is publicised as *"server-rendered, live-updated (SSR + SSE)"* rather than as
a bare label. Naming the default would create two ways to say one thing, so the
default stays nameless: you type `web` or `web solo`, never `web served`.

### Hosts are web-only, because all Ipê GUI is DOM

The host axis (`desktop` / `ios` / `android`, plus the implicit default host) is
**exclusive to the `web` shape**. There is no native widget toolkit; a "mobile
app" or "desktop app" is the `web` shape's DOM inside a native webview shell.
A non-web program (`script`, `tui`, `cli`, `worker`) has no mobile or desktop
host — it targets native, or (for a direct `script`) the co-located portable
floor. An app wanting a mobile UI *and* local-file access is a `web` app reaching
files through the capability layer, delivered `web solo ios`; file access goes
through the sandbox, as fail-closed security requires.

The desktop-webview program is the `web` shape under the `served` runtime on the
`desktop` host — the same TEA loop and diff/patch pipeline over a local IPC bridge
instead of SSE. There is no separate webview shape or entry point: webview is a
delivery vehicle for the `web` shape's output, captured by the host axis.

### The `(engine, delivery, triple)` validity matrix

Delivery lowers to a concrete cargo build over three coupled facts — the
compile **engine**, the resolved **delivery** (shape × runtime × host), and the
target **triple** — validated by one fail-closed matrix (`admit_triple`,
`src/ipe-cli/src/delivery.rs`). The engines and their triples:

| engine | triple | delivers |
|---|---|---|
| native | host triple | native binaries; `served` web; terminal and direct shapes |
| wasm-client | `wasm32-unknown-unknown` | the sandboxed browser `solo` client |
| wasm-wasi | `wasm32-wasip1` | the co-located portable floor for a direct program |

The matrix is defence in depth: the WASI triple is admissible **only** on the
wasm-wasi engine (the native engine has no wasip1 form, so a mis-routed triple is
refused independently of the engine gate), and the wasm-wasi engine refuses a
`solo` delivery (the browser sandbox is the opposite of a co-located WASI floor).
`solo` names the *delivery runtime*, never "wasm" as such: the browser client is
`wasm32-unknown-unknown` and the portable floor is `wasm32-wasip1`, kept apart by
this matrix so neither is confused for the other.

### Library admissibility is one SSOT gate

A single `allowed_in(module, shape, runtime)` table drives resolve, the LSP, and
diagnostics. A module disallowed for a given shape/runtime is a compile error
before any runtime boundary can be violated — a native effect (`Ipe.Db`,
`Ipe.File`, the HTTP *server*, `Ipe.Auth`) imported into a `solo` client is
turned away at `ipe` time, because a client bundle is public and a server-only
effect reaching it is a credential leak, not a lint. This is the language-level
layer of the client-bundle security gate below.

### The WASM client target reuses the one backend

The browser client is Ipê → Rust → `wasm32-unknown-unknown`, reusing the Rust
backend verbatim — a cargo target of the one backend, never a second code
generator. A runtime sink applies the same `Vec<Patch>` the existing `diff`
produces to the real DOM via typed `web-sys`, one update+diff+patch per animation
frame; `Cmd`/`Sub` map to a browser bridge. There is one backend, one runtime,
one no-panic contract, and one security gate to audit.

The client-bundle security boundary is enforced at three independent layers, so a
server-only effect is *unrepresentable* — not merely diagnosed — in a client
module:

1. **Target-keyed kernel registry** — under the client target, server effects
   have no denotation at canonicalisation; the effect cannot be named.
2. **Module partition + reachability closure** — only the reachable client
   surface is admitted; a server module cannot be dragged in transitively.
3. **Emitted `Cargo.toml` dependency floor** — the generated crate cannot pull a
   server-only dependency.

The app runs under `script-src 'self' 'wasm-unsafe-eval'` with no JS
`'unsafe-eval'` — tighter than a hand-written JS client. No-panic gives no-trap
for guarded kernels; the one honest residual (stack exhaustion on the smaller
WASM stack) is caught and reported as a classified diagnostic before the instance
dies, never a silent white screen.

### One `Web.tea` surface, branched at emit

The web entry is one open row-polymorphic record config — the required fields
(`init`, `update`, `view`, `subscriptions`, `routes`, `notFound`) plus a row
variable that absorbs any further field. There is no separate routed kernel: the
emitter branches on a single recovered fact — does the `Model` record carry a
`page` field? — emitting the routed form (routes vector, `notFound`, generated
page setter) when it does and the single-page form when it does not. A future cfg
field is absorbed by the row variable; a closed cfg record or a second web entry
kernel must not be reintroduced.

Route `:param` payloads are converted by the variant's payload field type at emit
(`String`/`Int`/`Float`/`Bool`), and any other payload type is a compile-time
diagnostic — a `:param` segment is inherently a URL string, so a payload the
runtime cannot derive from a string is rejected where the type is known, never as
an opaque downstream cargo error. This is the parse-don't-validate boundary for
routing.

### TEA is a state engine; `init` is prescriptive per shape

TEA is a **state engine**: a single `Model` evolved by pure `update` over typed
`Msg`, with every effect reified as data (`Cmd`/`Sub`). `view` is an *optional
projection* of the `Model`, not part of TEA's core — which is exactly why a
`worker` (TEA minus `view`) is a clean subtraction rather than a different kind of
program.

For a reactive shape `init` is mandatory and its argument is **prescriptive, not
inferred**: `init : WebReq -> (Model, Cmd Msg)` for `web` (the per-session request
context), `init : () -> (Model, Cmd Msg)` where there is no per-invocation
context. The effects-authority rule fixes what `init`'s argument may carry: only
context specific to this invocation *and* not reachable through the ambient
`System`/effects stdlib; all ambient input (env, args, cwd) is reached via
`System.*` from anywhere. A free type variable for `init`'s argument is rejected —
being prescriptive is both more Elm-faithful and make-invalid-states-
unrepresentable.

### A package is a container of disjoint targets

A **package** is one shared identity (one manifest, one registry entry, one
published namespace) holding:

- **at most one library surface** — its exposed modules; the empty list means
  "no public API";
- **zero or more programs** — each a `{ name, shape, entry }`; the empty list
  means "ships no executable".

`Program` and `Library` are **disjoint target kinds** — a library is just its
exposed modules (no shape, no entry, no build config); a program has a shape and
an entry. Emptiness carries "none", so no `Maybe` is needed: `exposedModules = []`
is a pure program, `programs = []` is a pure library, both non-empty is a library
plus thin programs over it. Cardinality is fixed at **one library surface, N
programs**: one package is one published namespace and therefore one public API;
several independent libraries are a **workspace** of packages, not one package.

Build configuration — dependency resolution, toolchain profile, database driver,
and the static/target/allocator settings below — is **package-wide**: one profile
produces all of a package's programs. Shape-specific options ride with each
program's `shape` variant, so an option irrelevant to a shape is unrepresentable
there.

### Static compilation and allocator selection

`ipe build --static [--allocator dlmalloc|mimalloc|talc]` produces a
fully-static, self-contained binary (musl target, `+crt-static`, an LTO +
`codegen-units=1` release profile) so an Ipê app runs on any Linux host with no
glibc dependency. The musl built-in malloc is single-threaded and tokio needs a
thread-safe allocator, so `dlmalloc` (pure-Rust, thread-safe, no C) is the
default; `mimalloc` is an opt-in for throughput at the cost of a host C toolchain.
`talc` parses (the enum stays closed) but resolves to a **typed refusal** — its
arena requires emitted `unsafe` and a hard heap cap, both of which the
generated-code soundness posture forbids — with a message naming `dlmalloc` as
the alternative. Static linking freezes every dependency into the artifact, so
the CI `cargo audit` over the emitted lockfile is load-bearing.

Superseded in part: the self-contained runtime word is `client`; `solo`, `spa` and `live` are refused.
