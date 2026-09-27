# PRINCIPLES.md

Every enforced rule of the Rust-backend project must live here, stated once. The
other governance docs — the root `AGENTS.md` (contributor onboarding),
`src/ipe-cli/templates/AGENTS.md.in` (Ipê language authoring reference), and
`docs/internals/dev-ops.md` (operational procedure) — should reference this file
rather than restate it.

These are goals we hold ourselves to, not claims that we have already reached
them. Where the code falls short of a principle, the gap is a defect to close,
never a reason to relax the principle.

## The main values

Ipê is meant to be:

1. **Explicitly principled:** the values, principles, rules, and declarations in
   this document must stand as entrenched eternity clauses. They and their
   priority order must not be changed, even by a majority of the community. To
   change them (e.g. favor exclusivity over community-openness, or efficiency
   over security or correctness), fork the project and start a new one with
   different principles.

2. **Community-centered:** diversity must be the foundation of the Ipê project.
   Respecting it in all its forms (age, gender, sexual orientation, ethnicity,
   race, culture, physical and cognitive ability, experience, socio-economic
   level, etc.) is MANDATORY. While respecting the values, principles, and rules,
   the community should have full autonomy to modify and extend the language,
   always seeking consensus. If no consensus is reached after 3 rounds of
   discussion and votes, a fourth round elects the majority's decision.

   The core language and standard library must stay deliberately small and
   principled. Breadth — new capabilities, platform and device integrations,
   domain libraries — should grow as community packages built on these
   principles, so developers and users extend the language together rather than
   waiting on the core to cover every need.

## The six technical principles (strict order)

Ipê must embrace all the principles and rules below throughout development and
use.

1. **Security** — generated code and runtime must give an attacker no foothold:
   no injection (SQL, shell, path, header, log), no secret leakage into logs or
   errors, no auth/CSRF bypass, no timing oracle on a secret comparison, no
   unbounded resource a remote party can exhaust. On untrusted input the safe
   outcome must be the only reachable one — we must fail closed: absent proof the
   input is safe, take the conservative, secure branch, never the permissive one.
2. **Correctness** — the same well-typed Ipê program with the same input must
   yield the same deterministic output, every run. Behaviour must be defined by
   the language's own semantics, not any external oracle; a deliberate divergence
   must be documented, never silent.
3. **Soundness** — a well-typed Ipê program must never be able to trigger a
   runtime failure in the generated Rust: no panic, no `.unwrap()`/`.expect()`
   blowup, no out-of-bounds index, no integer-overflow abort, no unchecked
   downcast, no UB. Correctness is "the result is right"; soundness is the
   stronger structural guarantee that no input can make the program fall over.
   **Bounded by construction:** the compiler and the emitted runtime alike must
   refuse work whose size an input dictates without a ceiling — every loop,
   recursion, and growable buffer must have a declared limit. Source nested tens
   of thousands deep, or a decode of an absurd length, must be turned back with a
   typed limit error before it can exhaust the stack or the heap; a process that
   instead dies on such input has broken soundness (and, when the input arrives
   over the network, principle 1's exhaustion clause too).
4. **Efficiency** — within the bounds of 1–3 we aim for no needless allocation
   or cloning, no hot-path recomputation, no O(n²) where O(n) is trivial, and a
   small binary and memory footprint. Efficiency must never be bought by trading
   a higher principle.
5. **Ease of use** — the language should stay out of the developer's way: a
   small, predictable surface, sensible defaults, little ceremony, and
   diagnostics that explain both the problem and the fix rather than only naming
   it. A feature present but hard to use correctly is not yet finished.
6. **Readability** — codegen and generated Rust should be clear, well-named,
   maintainable. All else equal, the clearer form should win.

**The ordering is a strict tie-breaker, not a weighting:** at any conflicting
decision the higher-numbered principle must yield — a faster path that opens a
soundness hole must be rejected, a more readable form that breaks correctness
must be rejected. A lower principle must never justify compromising a higher one.

## The fundamental technical rules

Beneath the ranked principles, every design and code pass must obey:

- **Parse, don't validate.** Convert untrusted/untyped input into a precise typed
  value ONCE at the boundary, so downstream code never re-encounters the
  unvalidated form. Foreign/JSON/config values must enter through a typed decode
  point; error channels must be typed (`Diagnostic`/`Error`), never `String`.
- **Make invalid states unrepresentable.** Encode invariants in types: a sum type
  over a bool-pair admitting impossible combinations; an exhaustive `match` (no
  wildcard that silently swallows a new variant); a smart constructor over an open
  field. A kernel the resolver recognises but the type-scheme table does not cover
  MUST be a compile-time error — never a silent flexible type variable that defers
  failure to the downstream Rust build. We must fail closed by construction: with
  no proof the state is valid, the representable outcome must be rejection, not a
  deferred blowup. A value's *role* must live in its type, never in a bare
  primitive another value of the same shape could stand in for: a message and a
  key should be separate types so neither is passable for the other (the model
  the runtime's crypto roles follow), and a position, a length, and a byte count
  should be kept apart rather than shared as one integer. The swap that would
  otherwise compile — a secret where a plaintext belongs, a length used as an
  index — should have no representation to begin with.
- **Fix the structure, not the symptom.** Repair the generative cause — the
  missing invariant, the drifting table, the untyped boundary, the special-case
  that should be a general rule — so the whole defect class cannot recur. Before
  writing a fix, ask "what structural property, if it held, would make this class
  of failure impossible?" and establish it. An ad-hoc patch that silences the
  visible symptom tends to resurface one shape over (the next `match` arm, the
  next kernel, another call site). Example: coercing only inline-lambda sibling
  branches to the `Arc` carrier is ad-hoc — the identical `E0308` returns when the
  sibling is a top-level function reference; the structural fix eta-expands every
  function-typed leaf over the group's arrow type, closing the class.
- **Single source of truth.** Every fact — a colour, a version, a capability name,
  a kernel signature, a user-facing phrase — must be defined in exactly one place.
  Where it must appear in a second form that cannot import the first (a shell
  script mirroring a Rust palette), generate one from the other or assert their
  equality in a test; never hand-sync. SSOT serves the precedence order: a
  one-line duplication caught by a test beats a leaky shared abstraction that hurts
  Correctness or Readability.
- **Defend in depth.** A security- or soundness-critical invariant must be
  enforced at more than one independent boundary, so no single missed or bypassed
  check opens the hole. The safe surface must never rest its guarantee on one
  gate: an identifier should be validated where it is built AND again where it
  reaches SQL; the SEAL should be re-checked at scheme, lowering, and emit; a row
  policy should filter in the query AND in the database. Enforcing a critical
  invariant twice is not redundant waste — it is the margin that survives a
  single mistake.

The ordering says what should win in a conflict; these rules say how to build
code that doesn't create the conflict.

### The mandatory technical SEAL — no ipe-exit-0-then-cargo-fail

**If `ipe` accepts a program (exit 0), the emitted Rust MUST `cargo build`. We
must never emit codegen that type-checks in ipe but fails cargo.** This is
make-invalid-states-unrepresentable applied to the pipeline itself: an
unschemed-but-resolved kernel, an arity table drifted from its callee table, a
generic where a concrete was required — each is a representable-but-illegal
pipeline state whose symptom is exit-0-then-cargo-fail. Every new acceptance path
(kernel, scheme, lowering arm, emitter case) must fail closed at ipe time, never
open at cargo time.

Where two constants or two parallel tables must agree — an arity table with its
callee table, a diagnostic's code family with its prefix letter — assert that
agreement at build time (a `const` check, a type-level relation) so the instant
they drift the *build* breaks, not a test that can be skipped nor a cargo error
two steps downstream. A test guarding the agreement can be deleted; a build that
refuses to compile cannot.

### No shortcuts — root cause or honest blocker

Removing or skipping the file, example, test, fixture, golden, or line that
*triggers* a bug is NOT a fix — it hides it. We must NEVER edit a reference
example, fixture, or golden to dodge a compiler gap; never weaken a gate; never
`#[allow]` a real violation; never fake a seal. Exactly two acceptable outcomes
for any defect: **root-cause it**, or **report it honestly as a tracked
blocker**. A green obtained by deleting the red is a FAILURE.

- **Root causes only.** We must never suppress a type error or warning; a
  defensive cover-up that hides a contract violation IS a violation.
- **Outcome ladder** (must govern every change): clean → proceed; a principle is
  hurt → rethink and reimplement within the boundary; no adequate in-boundary fix
  exists → revert, log why, signal the user. We must never ship a silent
  workaround.
- **No deferral.** "Pre-existing" / "known edge case" must never be a shipping
  excuse: any bug surfacing during dev/sweep/CI/testing — introduced or
  pre-existing — must enter the task pipeline on the spot. Only an explicit user
  override ("ship without fixing X") permits shipping a known unfixed issue.
- Every task should be a means to the larger goal — making Ipê a better language
  for its developers and users. "Make the sweep green" means make the programs
  actually compile and run correctly, not make red rows disappear. When a
  shortcut would satisfy the literal ask but betray that goal, we must do the
  harder correct thing or surface the tradeoff — never take the shortcut
  silently.

### Prove the refusals

A suite that exercises only the happy path certifies half a feature. We must pin
every path that must be *rejected* — the malformed input turned away, the
fail-closed branch taken, the value one step past the last legal one — because
those are the paths a regression or an attacker walks in on. A rejection that no
test drives is a rejection one edit away from vanishing unnoticed; the standing
check on it is what keeps it real.
