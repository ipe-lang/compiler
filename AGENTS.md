# AGENTS.md — working on the Ipê compiler

@PRINCIPLES.md

**Ipê** is an Elm-family pure-functional language that compiles to Rust. This
repo is the compiler, runtime, and stdlib (a Rust workspace). This file is an
orienting map — it links down rather than restating; read the linked source for
depth.

## Mindset
- Weigh every decision by `PRINCIPLES.md`. Correctness and security come first —
  this is production infrastructure real users and downstream code depend on.
- Verify against the code before affirming — don't assume.
- When something looks wrong, suspect your own change/reasoning/orchestration
  first — before the tools, CI, or environment.

## Start here
- **On the compiler (Rust)?** → the pipeline map below.
- **Writing Ipê** (`.ipe` stdlib, examples, fixtures) or asking what the compiler
  accepts? → `ipe doc <Module>`; `src/ipe-cli/templates/AGENTS.md.in` (what
  `ipe init` ships).
- **Rules & enforcement:** `PRINCIPLES.md` is the SSOT. `docs/adr/` holds
  history/rationale (the only place archaeology belongs).

## Compiler pipeline — where a change lands
Acyclic chain of crates; most changes touch one stage.

| Stage | Crate | Look here when… |
|-------|-------|-----------------|
| Parse | `src/compiler/syntax`, `src/compiler/parse` | surface syntax, AST, syntactic `TypeAnnotation` |
| Resolve | `src/compiler/canon` | name resolution, module wiring, canonical `Type` |
| Infer | `src/compiler/types` (`constrain.rs`) | HM inference, `Ty`, kernel type schemes |
| Lower | `src/compiler/lower` | `Ty` → `IrType`, arity tables |
| IR | `src/compiler/ir` | lowered `IrType`, pretty-printing |
| Emit | `src/compiler/backend/rust` | emitted Rust, `naming.rs` (runtime symbols) |

- **Cross-cutting:** `src/compiler/kernels` (`KernelDef` registry — a build-time
  tripwire fails if a kernel's mirrored sites drift); `src/compiler/diagnostics`
  (IPE codes + `explain/*.md`); `src/compiler/{db,intern}` (salsa);
  `src/compiler/{sandbox,ffi,watch}`; `src/lsp/*`.
- `src/stdlib` = `.ipe` stdlib · `src/runtime/rust` = what the backend emits into
  · `src/ipe-cli` = the `ipe` binary.
- **CLI output:** human screens render through `ipe::screen` (one frame:
  header, gutter, semantic `Tone`, bug footer on errors); machine output
  (`--json`/`--plain`) through `screen::emit_machine`, never framed. Help and
  usage text lives in `src/ipe-cli/help/*.md` (`help_page`) — edit the `.md`,
  never a Rust string. `tests/raw_print_ratchet.rs` pins raw prints.
- **Four type reps, in order:** `TypeAnnotation` → `Type` → `Ty` → `IrType`.
  Confusing one for another is the classic early mistake.

## Fast gate (a PR must pass — minutes)
```bash
tools/scripts/gate quick      # fmt, clippy on changed crates, static guards, doc drift
tools/scripts/gate affected   # + tests over changed crates and their reverse deps
tools/scripts/gate full       # the whole CI mirror (`IPE_E2E=1` included)
```
- The pre-PR gate is `gate affected`. CI's PR run and its merge-queue re-run on
  the combined tree are the full check, so `gate full` is not a pre-PR step.
  A branch touching jail/sandbox, the browser runtime, or the registry also runs
  the one full-tier job trusted-author PRs skip: `audit_native`
  (`linux-x64-tier2`), `browser-e2e`, or `registry-admission`.
- An infra-flake CI red is re-run with `gh run rerun <id> --failed`.
- The commands are the `local:` blocks of `.github/ci/check-manifest.yml`, each
  verified against the CI step it mirrors; `--plan` prints them without running.
- Opt-in pre-push hook: `tools/scripts/install-pre-push-hook.sh` (runs `gate quick`).
- `--profile ci` for slow emit tests (default 120s false-times-out; ci gives 600s).
- `IPE_E2E=1` makes emit tests build+run the emitted project — THE SEAL:
  `ipe`-accepts ⇒ `cargo`-builds.
- Goldens are byte-exact emitted Rust — regenerate with `cargo run -p regen-goldens`,
  never hand-edit.

## Tooling — use first
- `tools/scripts/ipe-index locate|wakeup|deps|rdeps|links|neighbors` — pre-built
  structural index; use before `rg` for "where is X / who calls Y / kernel gaps".
- Backlog = GitHub issues via `tools/scripts/github/issue-ticket.sh add|list|close`.

## PR workflow
- Feature branch off `main` → fast gate → PR `--base main` →
  `gh pr merge <N> --auto --squash` (merges when green + current).
- `main` stays green by construction (fast gate + required CI). One PR per unit;
  check `gh pr list` first.
- Versions + `CHANGELOG.md` are release-please automated from Conventional
  Commits — never bump by hand.

## Documentation & comments
- **No archaeology.** State what the rule/design IS now — no dates, task numbers,
  phase/milestone labels, "was X now Y", or incident stories (ADRs are the one
  history home). Rationale, when needed, is structural, not narrative.
- **Comments say WHAT, not HOW — and only when non-obvious.** A comment restating
  the code, or a name that needs a comment, is a smell.

## Mechanical enforcement — comply by construction
When a lint or gate fires, fix the code — never the lint level, never the gate.
- **Clippy deny-set:** root `Cargo.toml` `[workspace.lints.clippy]` is the SSOT
  (broad groups + a cherry-picked `restriction` slice). Change policy there, never
  in a command — every `cargo clippy` is just `-- -D warnings`. `pedantic`'s
  `doc_markdown`: backtick code identifiers in `///`/`//!`/`//` comments
  (`` `Vec<T>` ``, `` `--all-targets` ``), `tests/*.rs` included.
- `runtime/src/lib.rs` adds `#![cfg_attr(not(test), deny(clippy::indexing_slicing,
  panic, unreachable, todo, unimplemented, panic_in_result_fn))]`.
- **Escape hatch:** per-site `#[allow(lint)] // one-line why` only — never
  crate/gate-wide. Ledgered production allows carry `IPE-RUST-AUDIT:ACCEPTED`;
  `tools/panic-scan` is the inventory SSOT.
- **`unsafe` is forbidden** — a build error: `unsafe_code = "deny"` in root
  `Cargo.toml` `[workspace.lints.rust]` (mirrored in each crate that keeps its own
  `[lints]`). Syscalls go through safe typed wrappers (`rustix`, `std` `OwnedFd`);
  tests seed the environment through the runtime env overlay, a typed option, or
  spawn-time `Command::env`, never `std::env::set_var`. Exactly two sanctioned
  sites, each a scoped `#[allow(unsafe_code)]` carrying `IPE-RUST-AUDIT:ACCEPTED`:
  the `pre_exec` hook in the private `system::harden_child_parent_death` (the
  runtime's single parent-death floor and descriptor floor — the sweep marks
  every descriptor `>= 3` the live listing names close-on-exec through
  `BorrowedFd::borrow_raw`, so a child inherits only stdio and its `NamedFds` —
  reached only through `system::spawn_hardened{,_tokio,_naming}` on the
  process-lifetime spawner thread and `system::exec_naming`; every
  child-spawner, `console_proxy` and `ipe dev watch` alike, routes through it), and the per-function allows in the Win32 module
  `run_jail::windows::windows_jail`, only on the functions calling a Win32 entry
  point no vetted safe crate wraps (the Job Object lifecycle goes through
  `win32job`); that module denies `unsafe` everywhere else. Every other module is
  `unsafe`-free.
- **Edition 2024** — workspace crates and every emitted project.

## No `dyn Any` — concrete over generic
- The backend NEVER emits `dyn Any` / `.downcast` / type-erasure. Wildcard `any`
  has ONE concrete lowering per position (an opaque carrier, e.g. `Dict String
  String` in pub/sub payload position), emitted at EVERY position (enum field,
  pattern binder, fn/decoder param, Db row arg, eta lambda param, return).
- Only genuine named type variables (`a`, `msg`) become Rust generics
  (monomorphized by rustc). Emit concrete whenever concrete is possible — a
  needless generic passes the gate but can ship a silent runtime bug (e.g. a
  `TypeId`-keyed broker needs publisher + subscriber on the same concrete `T`).
- Sanctioned runtime-internal *container* exceptions (payload never erased/
  downcast): `runtime/src/ipe_runtime/cache.rs`, `runtime/src/ipe_runtime/live/pubsub.rs`.
