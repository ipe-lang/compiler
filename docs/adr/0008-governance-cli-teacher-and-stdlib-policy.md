Status: Living (consolidated)
Date: 2026-09-18
Archive: misc/docs/archive/ADR/

# 0008. Governance, CLI-as-teacher & stdlib policy

How the project teaches its language and organises its own governance: the `ipe`
CLI is the self-teaching source (human-first, machine-readable on request), the
governance docs partition by audience with no fact stated twice, and the stdlib
is placed by what a function *is* — capability, defense, perf primitive, or cold
computation — with Security taking precedence.

## Decisions

### Human-first CLI output; machine forms behind a flag

Every command's default output is human-friendly: a two-space left gutter on prose
and colour only to a terminal (stripped when piped, redirected, or under
`NO_COLOR`), with the gutter and palette defined once in the `style` module so
every command and the installer apply them identically. The data-emitting commands
(`capabilities`, `diff`, `version`, `explain`'s code list) accept two mutually
exclusive flags — `--plain` (unstyled, flush-left, one record per line) and
`--json` (a stable, documented schema) — defaulting to the human form; `--plain
--json` together is a usage error. `ipe run` passes the compiled program's stdout
through untouched and sends its own messages to stderr, so program output pipes
cleanly. Any misuse prints that command's full `--help` to stderr and exits
non-zero; `--help` requested goes to stdout and exits zero. A `--json` schema is
stable — a field is added, never silently renamed or removed.

### The compiler is the language's teacher

Everything needed to learn Ipê and write idiomatic Ipê is queryable from the `ipe`
CLI, the same content served human-first by default and machine-readable on
request. `ipe explain` is that teacher across three kinds of thing — diagnostic
codes, constructs/syntax, and topics/idioms — resolving by concept (fuzzy/keyword
search, not only by exact code), with progressive disclosure (a short overview by
default; an `explain list` subcommand to browse a category) and one content
rendered twice (friendly prose or `--json`). Every example in every explain/doc
page is compiled in CI (a doctest-style gate): this is load-bearing — it is what
makes "idiomatic first-try" true, since a reader can copy any example and it
compiles. Compile diagnostics carry idiom-nudging hints linking `ipe explain
<topic>`, and `build`/`run`/`check` expose a stable JSON diagnostics mode, so the
loop — ask, write, get taught by the error, fix — closes inside the CLI.

> **NEEDS UPDATE AFTER IMPLEMENTATION** — today `ipe explain` covers diagnostic
> codes only (`run_explain` + `did_you_mean_codes`, `src/ipe-cli/src/driver/commands.rs`);
> the construct/syntax and topic/idiom pages, concept-level fuzzy resolution beyond
> codes, and the `explain list` subcommand are the staged content not yet built
> (untracked). Once landed, drop this banner; until then, the "teacher covers
> constructs and topics" claim above is the target, not the current surface.

### Governance-doc topology — four documents, one purpose each

Each governance fact lives in exactly one document:

1. **Root `AGENTS.md`** — contributor/agent onboarding for the compiler repo: the
   crate map + pipeline, build/test/gate commands, kernel anti-drift discipline,
   and one-way links down. Short.
2. **`src/ipe-cli/templates/AGENTS.md.in`** — the language authoring reference
   shipped by `ipe init`: a lean bootstrap over syntax, the tier model for
   ambient vs. imported names, the shape/entry-point map, and the mandatory
   idioms a signature can't express, pointing every lookup (module contents,
   signatures, diagnostics) at the live `ipe doc` — never compiler internals,
   never a transcribed or embedded stdlib index.
3. **`PRINCIPLES.md`** — values, principles, and rules only; the operational
   *mechanics* are kept out of it, leaving each rule plus a link to its procedure.
4. **Deep operational procedure** — the intended home is
   `docs/internals/dev-ops.md`, which `PRINCIPLES.md` points to.

The entrenched values and principles themselves are unchanged eternity clauses;
only mis-filed procedure and stale references were moved out. A reviewer who sees
procedure creeping back into `PRINCIPLES.md`, or a signature table growing into
either `AGENTS.md`, rejects it and points the content at its one home.

> **NEEDS UPDATE AFTER IMPLEMENTATION** — `PRINCIPLES.md` references
> `docs/internals/dev-ops.md` as the operational-procedure home, but no such file
> exists in the tree (the deep procedure was condensed into root `AGENTS.md`
> instead), untracked. Reconcile by either creating `docs/internals/dev-ops.md` or
> repointing `PRINCIPLES.md` to root `AGENTS.md`, then drop this banner.

### `AGENTS.md` is a bootstrap-and-interrogation reference, not a stdlib mirror

The shipped authoring reference teaches only what an agent cannot introspect —
surface syntax as a dense example cheat-sheet, the interrogation loop framed as
"the compiler is your ground truth," the architecture/shape map, the ambient
tier model (what needs no import vs. what does), and the handful of idioms a
signature cannot express — and delegates the rest to the live compiler: module
contents and full signatures to `ipe doc <Module>`, diagnostics to `ipe doc
<CODE>`, the capability model to `ipe capabilities`. It carries no stdlib
index at all, generated or hand-maintained — a `ipe doc list`/`ipe doc
<Module>` pointer cannot drift the way an embedded index can, which is a
stronger form of the same no-drift invariant the original design reached for
with a generated index. The invariant: the reference must not transcribe any
per-function signature or diagnostic text the compiler can emit. A unit test
(`doc::agents_template_truth` in `src/ipe-cli/src/doc.rs`) checks the names and
commands the file does claim — the Tier A function list and the `ipe`
commands block — against the live compiler, so those few claims cannot drift
either.

### Stdlib placement — capability, security-defense, perf, or computation

Every stdlib function is classified into one of four destinations, and is **native
if any** of three tests holds; otherwise it is a pure-Ipê package. (1) *Core
intrinsic* — what the compiler/runtime itself depends on (`Basics`, the TEA
reactor). (2) *Native*, if it is **a capability** (touches the outside world or
needs a vetted crate — the surface the trust model gates), **a security defense**
(its correctness *is* a security property — escapers, injection/traversal
validators, crypto — kept native, small, auditable, fuzzable, and non-overridable,
the sole constructor of an opaque safe type), or **a measured performance
primitive** (a hot throughput core or a happy-path combinator, kept native until a
benchmark says otherwise). (3) *Ipê package* — everything else: pure, cold
computation and data (value builders, data tables, cold formatting). The
security-defense test **overrides** the "computation → package" pull: a validator
is pure computation, but its failure mode is a vulnerability, so Security (the
first principle) keeps it native — e.g. `Html` constructors are a package while its
`render`/escaper is the native XSS barrier.

> **NEEDS UPDATE AFTER IMPLEMENTATION** — this is the decided *classification
> policy*; the migrations it prescribes are largely not executed — the cold data
> tables (`Money` currencies, `Locale`, `Palette`) and the `Ui`/`Html` builders
> are not yet `.ipe` packages (no such files under `src/stdlib`), and each move is
> gated on free-for-unused DCE so it does not cost emitted-binary size. Once DCE is
> free-for-unused and the moves land, record which surfaces became packages and
> drop this banner. (`CssSafety` is correctly native — `css_value_safety.rs` — per
> the security-defense test.)
