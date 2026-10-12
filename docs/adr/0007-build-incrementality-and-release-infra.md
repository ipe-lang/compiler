Status: Living (consolidated)
Date: 2026-09-18
Archive: misc/docs/archive/ADR/

# 0007. Build, incrementality & release infra

How the compiler is laid out, how it recompiles incrementally and serves the same
answers to the editor, how it emits and formats Rust, how it keeps the dev loop
fast without distributing object code, and how packages, CI, and releases are
coordinated. The throughline: one source of truth per fact, verified from source,
with under-invalidation and supply-chain trust ranked above raw speed.

## Decisions

### Repository layout follows the acyclic pipeline

Compiler crates live under `src/compiler/<name>` (as `ipe_<name>`); the driver CLI
under `src/ipe-cli/`; the runtime under `src/runtime/rust/`; the LSP crates under
`src/lsp/`; the stdlib source under `src/stdlib/`; the backend under
`src/compiler/backend/`. The acyclic stage pipeline is a directory listing —
`annotate → backend → canon → db → diagnostics → ffi → intern → ir → kernels →
lint → lower → parse → path-core → sandbox → syntax → types → watch` — so a
developer locates any stage by `ls src/compiler/`. The runtime is separate from the compiler and consumed by the
backend, which copies it into each emitted project as `src/ipe_runtime/`. Root
`tools/` holds standalone binaries.

### Incremental compilation is a salsa query graph; the editor is a second consumer, never a second analyzer

The front end is a memoised salsa query graph in `ipe_db` (`src/compiler/db/`) —
`parse_module`, `extract_imports`, per-module canonicalisation, `module_interface`,
`typecheck`, `lower` — keyed on `SourceFile`/`SourceRoot` inputs, with a durable
cut-point at the whole-program IR. A body-only edit re-runs only the stages
downstream of the edited module. `SourceFile`/`SourceRoot` are the only inputs an
editor or watcher writes; a `VerifiedEdit` gate blocks raw-string injection
without crossing the parse boundary. **Under-invalidation — a stale build that
looks correct — is a correctness violation and outranks every efficiency gain**;
known cross-module dependency edges are regression-tested. The emit→cargo boundary
sits *outside* salsa (cargo owns Rust incrementality) with write-if-different +
delete-orphans reconciliation so unchanged emitted files cause no spurious cargo
rebuild.

`ipe lsp` and `ipe watch` are **second consumers of that one database**, never a
divergent second analyzer: every editor feature is a pure function from
`(db, request)` to a response, sourced from the same queries the build runs, so
the server can never disagree with the build about parsing, name resolution, or
types. The transport (`ipe_lsp_server`, on `lsp-server`) is the only place that
touches stdio/JSON; positions cross the UTF-16 ↔ byte boundary through one
encoding-aware converter; a `rename` edit is built only from resolved query spans;
a non-type-checking program still yields kind-only completion rather than an
invented type. Feature `match`es carry no wildcard, so a new language variant is a
compile error in the server until every handler covers it.

Type checking has two tiers over the one database. `infer_module_scoped`
solves a single module against its dependencies' `typed_interface` schemes, so a
scheme-preserving edit to a dependency does not re-solve its dependents; the
editor features read it through `typecheck_module`. A module is served
per-module only when every solved fact it carries is independent of its
importers. An importer-pinnable scheme (an unannotated numeric export) marks
its interface open, and it and its importers fall back to the joint `typecheck`
projection, as do import cycles and red dependencies. An exported
UI-message-defaulting slot (whose default reads every use site, importers'
included) leaves the exported scheme closed (the annotation, or the scheme
reified before defaulting), so its importers still solve per-module against
the interface while the module's own types come from the joint projection. The build commands (`build`, `run`, `watch`, `check`, `test`,
`pkg`) lower from the joint `typecheck` solve: the lowerer also consumes
whole-program solver facts (warnings, the polymorphic-variable map keyed by
solver ids, untyped type parameters, signature wildcards, message-defaulted
variables) that the per-module result does not yet carry or gate, so routing
lowering through the scoped tier requires those facts per module and a
lowered-IR differential proving the assembled program identical to the joint
one. The `expected_type_at` type-directed completion
(`src/lsp/features/src/expected_type.rs`) reads the same per-module tier.

### Stdlib modules with internal structure are compiled from source

A stdlib module is shipped one of two ways: kernel-only stubs (a qualified call
resolves to a `KernelFn`, no source), or real embedded `.ipe` source compiled
exactly like a user module. A module with rich internal structure (helper
functions, ADTs, recursive combinators) uses the source path —
`inject_compiled_std_closure` injects its embedded source when the import graph
transitively reaches it. Such a module is fully annotated (every top-level binding
carries a type) so inference cannot fail deep in the stdlib, and it may be hybrid
(pure Ipê bodies plus `Ffi.kernel` aliases to existing kernels). The rule: if a
module needs more than a signature and a runtime dispatch slot, write it in Ipê.
The load-bearing invariant is that a compiled-source module either resolves to
exactly the user-module pipeline result or produces a clean `IPE-N…`/`IPE-T…`
diagnostic — never exit-0-then-cargo-fail.

### The Rust backend emits a document algebra and formats it itself

Each per-node emitter returns a `Doc` (a frozen Wadler/Leijen-style document) built
during the owned-IR walk; one deterministic renderer lays it out to width-canonical
bytes. There is no `rustfmt` subprocess. Every token — including every parenthesis
— is a `Text` leaf, so the SEAL is a structural property: the whitespace-normalised
concatenation of a document's leaves equals the token-level emitter's string, and a
dropped or reordered token fails at build time, not as a downstream cargo error. A
binary-operator chain earns a dedicated `Chain` variant (a generic
all-flat-or-all-break group provably cannot render the glued-then-broken layout).
The binding gate is byte-equality against the checked-in golden corpus over every
emitted `.rs` file; goldens are never re-blessed to match the renderer — the
renderer is fixed to match them, and a width change is a deliberate config edit plus
golden regeneration.

### The dev loop is fast from source — never by distributing object code

The compile-cost budget (a common program in milliseconds-to-seconds, a complex app
in seconds-to-tens-of-seconds) is reached by gating every optional dependency out of
the floor and compiling everything from source. Optional roots (serde/json, regex,
chrono, the crypto floor, url, uuid, …) sit behind runtime-crate cargo features
selected by a typed function-level reachability predicate, so a bare program
approaches std-only (measured: 105 crates → 3). The runtime is emitted as a real
version-matched dependency crate (not vendored inline) so an edit recompiles only
the user's crate; a build-once shared cargo target keyed by
`(compiler version, toolchain, feature set)` compiles the closure once per machine.
Prebuilt binary artifacts, a prelinked dylib, and a C-ABI runtime boundary are all
rejected on Security/Soundness precedence — users must build what they run, and the
Rust-native runtime boundary must not be erased to a hand-audited `unsafe` one. The
manifest, runtime module set, and feature set must agree and include exactly what
the reachable code needs; mis-dropping a crate is a compile-time SEAL drift error
(`crate_specs_match_manifests`), fail-closed (an unknown consumer keeps the crate).

> **NEEDS UPDATE AFTER IMPLEMENTATION** — the true-milliseconds dev loop is
> designed to route an FFI-free `ipe run` through an IR interpreter that removes
> `rustc` from the edit→run loop; no such interpreter exists yet (`ipe run` uses
> the AOT/cargo path; no `interpret`/`eval_ir` entry in `ipe_ir`), untracked. Once
> landed, state the interpreter path as current; until then the AOT path's residual
> cost is `rustc` over the user's own crate plus the link.

### Packages are coordinated by pinned, hashed, capability-gated entries

Dependencies are coordinated through four parse-don't-validate pieces plus an
enforced-semver rule and a merge gate. The manifest (`ipe.toml`) has three typed
sections — `[dependencies]` (Ipê packages), `[rust.dependencies]` (native crates),
`[capabilities] declared` — and the capability vocabulary is the *same type*
re-exported from the compiler's kernel registry, never a second string list. An
index entry pins `source`, `rev`, `sha256`, and `capabilities` per version; the
resolver verifies the fetched tree's hash *at the fetch point* before trusting it,
and writes a deterministic sorted lockfile (`ipe.lock`). Enforced semver (`ipe
diff`) projects the public interface to a canonical form and derives the required
bump fail-closed (unproven ⇒ breaking); pre-1.0, major is reserved, so a breaking
delta bumps minor. The package gate (`ipe package audit`) runs security-first
(provenance scan, capability consistency over the Ipê-inferable set, enforced
semver, supply-chain) as a typed rejection; the index CI's run is authoritative.
Pure-Ipê capabilities are *proven*; native capabilities are *declared and contained*
at runtime — that tiering is stated honestly, not blurred. The index repository
itself is external (`arthurmaciel/ipe-registry`).

### CI on GitHub Actions; releases via release-please

CI runs on GitHub-hosted ephemeral runners exclusively (no self-hosted), keeping
`main` green by construction: a PR runs only the fast required gate (`fmt`,
`clippy -D warnings`, `nextest`, `cargo-deny`, seal-smoke) and merges when green;
the slow jobs (`e2e`/`IPE_E2E=1`, parity, `miri`, feature-combos, examples-sweep,
static) run on push-to-main and nightly, off the PR path. Each job with a distinct
failure mode is its own `.yml`. Releases use **release-please**: Conventional
Commits drive the bump and changelog; there is exactly one workspace version (the
virtual-workspace `[workspace.package].version`, rewritten by a `simple`
release-type extra-file, inherited by every crate); release-please owns the tag,
release object, and changelog body, and the binary-build workflow only *uploads*
assets to the release-published event — one release object per tag, no create/upload
race. Pre-1.0, `1.0.0` is never reached automatically; cutting it is a deliberate
stability promise.
