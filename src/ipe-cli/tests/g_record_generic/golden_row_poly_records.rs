//! Gate — row-poly subset/superset record resolution (A7 watch).
//!
//! `docs/adr/0001-language-semantics-and-types.md` records the
//! verdict: **no defect found**. Every
//! row-polymorphic subset/superset record shape reachable through Ipê's
//! surface today either resolves end-to-end in parity with the reference
//! compiler, or is rejected with the same verdict the reference gives
//! (fail-loud parity). This file wires the spec's 5-fixture proof matrix
//! into the sweep so a future change — most plausibly the class-1
//! "Boundary Scheme Promotion" generalization work — cannot silently widen
//! the A7 exact-sorted-field-set struct registry's reachable-shape
//! invariant without a test noticing.
//!
//! No compiler code change accompanies this file: it is verification +
//! hardening, matching the spec's proof-matrix rows P1 through P7 by direct
//! `ipe build` / `cargo build` observation, not by assumption.
//!
//! | Fixture | Proof-matrix row(s) | Gate | Asserts |
//! |---|---|---|---|
//! | `row_poly_subset_access` | P2 | accept | unannotated getter, subset field access over a superset arg; emits a concrete (non-generic) getter against the superset struct; `IPE_E2E=1` prints `Ada` |
//! | `row_poly_subset_pattern` | P5, P7 | accept | subset `case` pattern AND subset lambda pattern (through `List.map`) over a superset scrutinee; emitted pattern completes to the superset struct (`RecAgeName { age: _, name, .. }`); `IPE_E2E=1` prints `Iri: Ada, Bo` |
//! | `row_poly_closed_superset_neg` | P4 | reject | CLOSED record annotation called with a superset arg → IPE-T0001 |
//! | `row_poly_two_supersets_neg` | P6 (class-1 tripwire) | reject | unannotated let-bound getter called with two DIFFERENT superset shapes → IPE-T0001 |
//! | `row_poly_annotation_gap` | P1 | accept | single-field arg-position row `{ r \| name : String }` erases to a witness-bounded rustc generic (`R1: IpeHasName<Name = String>`); the field read routes through `ipe_name()` |
//! | `row_poly_greet` | P1 | accept | one row-poly fn called at TWO shapes (`{name,age}`, `{name,id}`); both concrete structs + a witness impl each; `IPE_E2E=1` prints `Ada, Bo` |
//! | `row_poly_multi` | P1 (multi-field) | accept | a TWO-field arg row `{ r \| name : String, id : Int }` at two shapes erases to ONE generic bounded by `IpeHasName<Name = String> + IpeHasId<Id = i64>`, one witness impl per field per struct; `IPE_E2E=1` prints `Ada#1 Bo#2` |
//! | `row_poly_task_seq_row_read` | row containment (emit-time) | accept | a row field read inside a discarded-Task effect AND its continuation, sequenced at two shapes; the effect's `rec.name` survives the emit-time capture-clone as a `Var` receiver (getter-routed, not a whole-row `CloneVar`), and `R1` carries `Send + 'static` for the boxed continuation; `IPE_E2E=1` prints `Ada`×2 then `Bo`×2 |
//! | `row_poly_accessor` | P8 | accept | first-class accessor `.name` (desugars to `\r -> r.name`) through `List.map` over a superset list; emits a concrete getter closure over the superset struct; `IPE_E2E=1` prints `Ada, Bo` |
//! | `row_poly_accessor_two_shapes` | P8 | accept | `.name` through `List.map` over two DIFFERENT record shapes; each occurrence a concrete getter; `IPE_E2E=1` prints `Ada, Bo | Cy, Di` |
//! | `row_poly_let_rebind_neg` | row containment | reject | a row-typed param re-bound (`let n = rec in n.name`) escapes the direct-access form → IPE-L0131 (else the emitted `n.name` is E0609) |
//! | `row_poly_subset_pattern_param_neg` | row containment | reject | a row param bound with a subset pattern (`getName {name} = name`) → IPE-L0131 (else the destructure of `R1` is E0308) |
//! | `row_poly_non_first_arg_neg` | row containment | reject | a single-field row in a non-first arg reached via a body lambda → clean IPE-L0131 (else the IPE-I0001 ICE backstop) |
//! | `row_poly_captured_clone_neg` | row containment | reject | a row field read captured into an inner lambda (`\_ -> rec.name`) becomes a `CloneVar` receiver the emitter cannot route → IPE-L0131 (else the emitted `rec.name` on the bare `R1` generic is E0609) |
//!
//! Run the E2E accept-path bodies (real `cargo build` + run) with:
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_row_poly_records
//! ```
//! The two reject fixtures (`row_poly_closed_superset_neg`,
//! `row_poly_two_supersets_neg`) run unconditionally (compile-time only, no
//! `cargo`, so no gate needed) — they are the pinned-records ADR tripwires and
//! must keep rejecting.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(name: &str) -> PathBuf {
    repo_root().join("tests").join("golden").join(name)
}

fn diag_code(err: &ipe::CliError) -> Option<ipe_diagnostics::Code> {
    match err {
        ipe::CliError::Pipeline { diag, .. } => Some(diag.code()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// row_poly_subset_access — P2: unannotated getter, subset access over a
// superset argument. Accept end-to-end.
// ---------------------------------------------------------------------------

/// ipe-0: the compiler must accept the unannotated `getName rec = rec.name`
/// called with a `{ name, age }` record and emit a CONCRETE getter whose
/// parameter is the resolved superset struct (`RecAgeName`) — proving the
/// A7 exact-sorted-field-set lookup resolves this subset-access shape
/// without a miss. Checked unconditionally (cheap, no `cargo`).
#[test]
fn subset_access_ipec_accepts_and_resolves_superset_struct() {
    let entry = golden_dir("row_poly_subset_access").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("row_poly_subset_access_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP row_poly_subset_access: runtime not available");
        return;
    };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must accept row_poly_subset_access (P2, subset field \
         access over a superset record): {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");
    assert!(
        emitted.contains("struct RecAgeName"),
        "the superset struct RecAgeName must be resolved and emitted; got \
         main.rs:\n{emitted}"
    );
    assert!(
        emitted.contains("pub fn main_get_name(rec: RecAgeName) -> String"),
        "getName must lower to a concrete getter over the superset struct \
         (the A7 exact-key resolution path), not a generic; got \
         main.rs:\n{emitted}"
    );
}

/// cargo-0 ∧ run-0: the emitted project actually compiles and prints the
/// field it read. Gated on `IPE_E2E=1` — matches the reference compiler's
/// own output for the identical shape (proof-matrix row P2: "accept; prints
/// `Ada`"), hand-verified against `the prior compiler`.
#[test]
fn subset_access_cargo_builds_and_prints_ada() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let entry = golden_dir("row_poly_subset_access").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_row_poly_subset_access_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for row_poly_subset_access: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("row_poly_subset_access", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "row_poly_subset_access binary must exit 0; got {:?}",
        outcome.exit_code
    );
    assert_eq!(
        outcome.stdout, "Ada\n",
        "must print the `name` field read through the subset access, \
         matching the reference oracle"
    );
}

// ---------------------------------------------------------------------------
// row_poly_subset_pattern — P5 + P7: subset case/lambda record patterns
// over a superset scrutinee. Accept end-to-end.
// ---------------------------------------------------------------------------

/// ipe-0: the compiler must accept both a subset `case` pattern (P5) and a
/// subset lambda pattern through a HOF (P7) over a `{ name, age }`
/// scrutinee, and the lowerer must complete each pattern to the superset
/// struct with a `..` rest before the emitter resolves it — the exact
/// `RecAgeName { age: _, name, .. }` shape the design doc predicts.
/// Checked unconditionally (cheap, no `cargo`).
#[test]
fn subset_pattern_ipec_accepts_and_completes_superset_pattern() {
    let entry = golden_dir("row_poly_subset_pattern").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("row_poly_subset_pattern_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP row_poly_subset_pattern: runtime not available");
        return;
    };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must accept row_poly_subset_pattern (P5 case pattern + \
         P7 lambda-through-HOF pattern, both subset over a superset \
         scrutinee): {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");
    let completed_pattern_count = emitted.matches("RecAgeName { age: _, name, .. }").count();
    assert!(
        completed_pattern_count >= 2,
        "both the case pattern (P5) and the lambda pattern (P7) must \
         complete to the superset struct pattern `RecAgeName {{ age: _, \
         name, .. }}` — the A7 exact-set resolution path for record \
         PATTERNS, not just record access; found {completed_pattern_count} \
         occurrence(s) in main.rs:\n{emitted}"
    );
}

/// cargo-0 ∧ run-0: the emitted project actually compiles and prints the
/// values read through both subset patterns. Gated on `IPE_E2E=1` — matches
/// the reference compiler's own output for the identical shapes
/// (proof-matrix rows P5 "prints (same)" and P7 "prints `Ada, Bo`"),
/// hand-verified against `the prior compiler` for this combined fixture
/// (`Iri: Ada, Bo`).
#[test]
fn subset_pattern_cargo_builds_and_prints_iri_ada_bo() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let entry = golden_dir("row_poly_subset_pattern").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_row_poly_subset_pattern_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for row_poly_subset_pattern: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("row_poly_subset_pattern", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "row_poly_subset_pattern binary must exit 0; got {:?}",
        outcome.exit_code
    );
    assert_eq!(
        outcome.stdout, "Iri: Ada, Bo\n",
        "must print the leader's name (case pattern) followed by the \
         mapped names (lambda pattern through List.map), matching the \
         reference oracle"
    );
}

// ---------------------------------------------------------------------------
// row_poly_closed_superset_neg — P4: closed annotation vs superset arg.
// Reject, IPE-T0001. Compile-time only, no gate.
// ---------------------------------------------------------------------------

/// A CLOSED record annotation (`{ name : String }`, no row var) cannot
/// absorb a superset argument's extra `age` field — mechanism 1
/// (`unifyRecords`) rejects it as IPE-T0001, in parity with the reference's
/// E2001 for the identical shape.
#[test]
fn closed_superset_is_ipe_t0001() {
    let name = "row_poly_closed_superset_neg";
    let entry = golden_dir(name).join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_out"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP {name}: runtime not available");
        return;
    };
    let res = ipe::build(&entry, &out, &runtime);
    assert!(res.is_err(), "{name} must fail to compile");
    let Err(err) = res else { return };
    assert_eq!(
        diag_code(&err),
        Some(ipe_diagnostics::IPE_T0001),
        "closed record annotation vs superset arg must be IPE-T0001; \
         err = {err}"
    );
    assert!(
        !out.join("src").join("main.rs").exists(),
        "{name}: no Rust must be emitted on a rejection"
    );
}

// ---------------------------------------------------------------------------
// row_poly_two_supersets_neg — P6. Reject, IPE-T0001. Compile-time only, no
// gate.
// ---------------------------------------------------------------------------

/// An unannotated LET-BOUND getter called with two DIFFERENT superset
/// shapes (`{ name, age }` then `{ name, id }`) is rejected as IPE-T0001 —
/// neither compiler let-generalizes over record rows. This rejection comes
/// from `unify.rs`'s ordinary closed-record-mismatch rule, via the
/// `Expr_::Let` no-let-polymorphism path (`constrain.rs`) — it does NOT
/// exercise `promote_untyped_boundaries`/Boundary Scheme Promotion, which
/// only generalizes MODULE-level bindings, not local `let`s. Do not read
/// this fixture as a regression gate for the class-1 cross-module
/// generalization mechanism (no cross-module two-superset fixture exists in
/// this repo; a real class-1 coupling tripwire would need one). It DOES still
/// pin the correct
/// no-let-poly-over-rows invariant described above: flipping this fixture
/// to accept without adding per-record-shape callee monomorphisation to the
/// backend would reintroduce the A7 exact-key miss as an ICE (best case) or
/// a seal-violating emitted-code type error. See
/// docs/adr/0001-language-semantics-and-types.md "Coupling
/// tripwire" for the ORIGINAL (broader) framing of that risk — the fixture
/// here covers only the local-let-binding instance of it.
#[test]
fn two_different_supersets_is_ipe_t0001() {
    let name = "row_poly_two_supersets_neg";
    let entry = golden_dir(name).join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_out"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP {name}: runtime not available");
        return;
    };
    let res = ipe::build(&entry, &out, &runtime);
    assert!(res.is_err(), "{name} must fail to compile");
    let Err(err) = res else { return };
    assert_eq!(
        diag_code(&err),
        Some(ipe_diagnostics::IPE_T0001),
        "an unannotated getter used at two different superset shapes must \
         be IPE-T0001 (no let-generalization over rows); err = {err}"
    );
    assert!(
        !out.join("src").join("main.rs").exists(),
        "{name}: no Rust must be emitted on a rejection"
    );
}

// ---------------------------------------------------------------------------
// row_poly_annotation_gap — P1. A single-field argument-position row-polymorphic
// annotation lowers to per-field witness traits + rustc generics and builds.
// Its emission shape is asserted below.
// ---------------------------------------------------------------------------

/// The row-var record annotation `{ r | name : String }` parses, type-checks,
/// lowers, and emits: `greet` erases its open row to a rustc generic `R1`
/// bounded by the synthesised `IpeHasName<Name = String>` witness trait, and
/// the body field read routes through the `ipe_name()` getter. rustc
/// monomorphises the call to the concrete argument struct — no dynamic field
/// lookup, no `dyn Any`. This is the per-record-shape monomorphisation the
/// pinned-records ADR (docs/adr/0018) reserves for the supported
/// (single-field argument-position) row form.
#[test]
fn row_var_annotation_lowers_to_witness_generic() {
    let name = "row_poly_annotation_gap";
    let entry = golden_dir(name).join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_out"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP {name}: runtime not available");
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{name} must now BUILD: a single-field argument-position row annotation \
         lowers to a witness-bounded generic (ADR-0001 canary); err = {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");
    assert!(
        emitted.contains("pub trait IpeHasName"),
        "the per-field witness trait must be synthesised; got main.rs:\n{emitted}"
    );
    assert!(
        emitted.contains("fn ipe_name(&self) -> &Self::Name"),
        "the witness getter must be declared on the trait; got main.rs:\n{emitted}"
    );
    assert!(
        emitted.contains("R1: IpeHasName<Name = String>"),
        "greet's row parameter must be a witness-bounded rustc generic; got \
         main.rs:\n{emitted}"
    );
    assert!(
        emitted.contains(".ipe_name()"),
        "the row-typed field read must route through the witness getter; got \
         main.rs:\n{emitted}"
    );
}

// ---------------------------------------------------------------------------
// row_poly_accessor — P8: the first-class accessor `.name` as a value.
// Accept end-to-end.
// ---------------------------------------------------------------------------

/// ipe-0: the compiler must accept `List.map .name people` — the first-class
/// accessor `.name` (which desugars to the getter `\r -> r.name`) — and emit a
/// CONCRETE getter closure whose parameter is the resolved superset struct
/// `RecAgeName`, never a generic. This is the accessor form of the mechanism-2
/// deferred field access plus mechanism-4 monomorphic pinning; the record
/// reaches the backend fully pinned so the A7 exact-sorted-field-set lookup
/// resolves it without a miss. Checked unconditionally (cheap, no `cargo`).
#[test]
fn accessor_ipec_accepts_and_resolves_concrete_getter() {
    let entry = golden_dir("row_poly_accessor").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("row_poly_accessor_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP row_poly_accessor: runtime not available");
        return;
    };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must accept row_poly_accessor (P8, first-class accessor \
         `.name` over a superset record list): {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");
    assert!(
        emitted.contains("struct RecAgeName"),
        "the superset struct RecAgeName must be resolved and emitted; got \
         main.rs:\n{emitted}"
    );
    assert!(
        emitted.contains("move |ipe_accessor_arg: RecAgeName| -> String"),
        "the accessor `.name` must lower to a CONCRETE getter closure over the \
         resolved superset struct (the A7 exact-key path), not a generic; got \
         main.rs:\n{emitted}"
    );
}

/// cargo-0 ∧ run-0: the emitted project actually compiles (SEAL) and prints the
/// `name` field read off each record through the accessor. Gated on
/// `IPE_E2E=1`.
#[test]
fn accessor_cargo_builds_and_prints_names() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let entry = golden_dir("row_poly_accessor").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_row_poly_accessor_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for row_poly_accessor: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("row_poly_accessor", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "row_poly_accessor binary must exit 0; got {:?}",
        outcome.exit_code
    );
    assert_eq!(
        outcome.stdout, "Ada, Bo\n",
        "must print the `name` fields read through the first-class accessor"
    );
}

// ---------------------------------------------------------------------------
// row_poly_greet — the increment-1 vertical slice: ONE row-polymorphic
// annotated function called with TWO different concrete shapes. No single
// closed struct can serve both, so this is the shape ADR-0001's two-superset
// tripwire forbade for the UNANNOTATED path — here it is accepted because the
// annotation opts into witness-trait monomorphisation. Accept end-to-end.
// ---------------------------------------------------------------------------

/// ipe-0: `greet : { r | name : String } -> String` called at `{ name, age }`
/// and `{ name, id }` must build. The backend emits `greet` as a rustc-generic
/// bounded by `IpeHasName<Name = String>`, one `IpeHasName` impl per struct
/// carrying `name`, and rustc monomorphises one machine copy per shape. Both
/// concrete structs must appear; the row parameter must be the witness-bounded
/// generic, never a concrete struct or a `dyn`.
#[test]
fn row_poly_greet_lowers_and_monomorphises_two_shapes() {
    let entry = golden_dir("row_poly_greet").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("row_poly_greet_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP row_poly_greet: runtime not available");
        return;
    };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must accept row_poly_greet (one row-poly fn at two shapes): \
         {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");
    // Both concrete argument shapes reach the struct registry unchanged — the
    // pinned-records ADR survives: the open row never becomes a Record here.
    assert!(
        emitted.contains("struct RecAgeName") && emitted.contains("struct RecIdName"),
        "both concrete argument structs must be emitted; got main.rs:\n{emitted}"
    );
    assert!(
        emitted.contains("R1: IpeHasName<Name = String>"),
        "greet's row parameter must be the witness-bounded generic, not a \
         concrete struct; got main.rs:\n{emitted}"
    );
    // One IpeHasName impl per struct carrying `name`.
    assert!(
        emitted.contains("IpeHasName for RecAgeName")
            && emitted.contains("IpeHasName for RecIdName"),
        "a witness impl must exist for every struct carrying `name`; got \
         main.rs:\n{emitted}"
    );
    assert!(
        !emitted.contains("dyn Any"),
        "row monomorphisation must be static — no dynamic field lookup; got \
         main.rs:\n{emitted}"
    );
}

/// cargo-0 ∧ run-0: the emitted project compiles (the SEAL: exit-0 ⇒
/// cargo-green) and prints both greetings. Gated on `IPE_E2E=1`. rustc
/// monomorphises `greet` to `RecAgeName` and `RecIdName` from the two call
/// sites.
#[test]
fn row_poly_greet_cargo_builds_and_prints_both() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let entry = golden_dir("row_poly_greet").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_row_poly_greet_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for row_poly_greet: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("row_poly_greet", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "row_poly_greet binary must exit 0 (SEAL); got {:?}",
        outcome.exit_code
    );
    assert_eq!(
        outcome.stdout, "Ada, Bo\n",
        "must print both greetings — one machine copy of greet per record shape"
    );
}

/// ipe-0: a row-generic field read that lands in a discarded-Task effect AND its
/// continuation must route BOTH reads through the borrowing witness getter. The
/// effect read is the load-bearing case: the Task-sequencing tail captures `rec`
/// into its continuation, so the emit-time capture-clone would otherwise rewrite
/// the effect's `rec.name` receiver to a `CloneVar` (a raw struct-field read on
/// the bare `R1` generic — E0609). The row generic also carries `Send + 'static`
/// for the boxed continuation.
#[test]
fn row_poly_task_seq_row_read_routes_effect_through_getter() {
    let entry = golden_dir("row_poly_task_seq_row_read").join("Main.ipe");
    let out =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("row_poly_task_seq_row_read_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP row_poly_task_seq_row_read: runtime not available");
        return;
    };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must accept row_poly_task_seq_row_read: {:?}",
        built.err()
    );

    // Collect all emitted Rust; compiled-source stdlib imports split user code
    // into src/ipe_mods/ipe_mod_main.rs alongside src/main.rs.
    let mut emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");
    let mod_main = out.join("src").join("ipe_mods").join("ipe_mod_main.rs");
    if let Ok(extra) = std::fs::read_to_string(&mod_main) {
        emitted.push_str(&extra);
    }
    // The effect read must NOT be a whole-row clone feeding a raw field read.
    assert!(
        !emitted.contains(".clone()).name") && !emitted.contains("(rec.clone()).name"),
        "the effect's row read must not become a raw struct-field read on a \
         cloned R1; got main.rs:\n{emitted}"
    );
    // Both the effect and the continuation route through the witness getter.
    assert!(
        emitted.matches("ipe_name()").count() >= 2,
        "both the effect and the continuation must route `name` through the \
         witness getter; got main.rs:\n{emitted}"
    );
    // The row generic carries the auto-trait bounds the boxed continuation needs.
    assert!(
        emitted.contains("Send") && emitted.contains("'static"),
        "a task-captured row generic must carry Send + 'static; got \
         main.rs:\n{emitted}"
    );
    assert!(
        !emitted.contains("dyn Any"),
        "row routing must stay static; got main.rs:\n{emitted}"
    );
}

/// cargo-0 ∧ run-0: the emitted project compiles (the SEAL: exit-0 ⇒
/// cargo-green) and prints each name twice — `report ada` runs its effect then
/// its continuation (`Ada` twice), then `report bo` (`Bo` twice). Gated on
/// `IPE_E2E=1`.
#[test]
fn row_poly_task_seq_row_read_cargo_builds_and_runs() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let entry = golden_dir("row_poly_task_seq_row_read").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_row_poly_task_seq_row_read_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for row_poly_task_seq_row_read: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("row_poly_task_seq_row_read", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "row_poly_task_seq_row_read binary must exit 0 (SEAL); got {:?}",
        outcome.exit_code
    );
    assert_eq!(
        outcome.stdout, "Ada\nAda\nBo\nBo\n",
        "each report prints its row field in the effect then the continuation"
    );
}

// ---------------------------------------------------------------------------
// Row-containment tripwires — a row-typed value is emittable ONLY as the direct
// receiver of a field read (`rec.name`). Each fixture below is a non-routable
// position that would otherwise reach the backend as a bare `R{n}` generic and
// emit Rust that cannot compile (or ICE at the type-lowering backstop). All
// must reject with IPE-L0131 and emit NO Rust. Compile-time only (no `cargo`),
// so no `IPE_E2E` gate.
// ---------------------------------------------------------------------------

/// A row-typed parameter re-bound to a fresh local (`let n = rec in n.name`)
/// lets the row value escape the direct-access form: `n` carries the bare `R1`
/// generic, so `n.name` would emit a struct read against an unknown struct
/// (E0609). The lowering containment check fails it closed with IPE-L0131.
#[test]
fn let_rebind_of_row_is_ipe_l0131() {
    let name = "row_poly_let_rebind_neg";
    let entry = golden_dir(name).join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_out"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP {name}: runtime not available");
        return;
    };
    let res = ipe::build(&entry, &out, &runtime);
    assert!(
        res.is_err(),
        "{name} must fail to compile (row value escapes)"
    );
    let Err(err) = res else { return };
    assert_eq!(
        diag_code(&err),
        Some(ipe_diagnostics::IPE_L0131),
        "a let-rebound row value must be IPE-L0131 (else the emitted `n.name` \
         is E0609); err = {err}"
    );
    assert!(
        !out.join("src").join("main.rs").exists(),
        "{name}: no Rust must be emitted on a rejection"
    );
}

/// A row-typed parameter bound with a SUBSET record pattern (`getName {name} =
/// name`) would have the lowerer destructure the bare `R1` generic with a
/// concrete struct pattern (E0308). Only a plain-variable binder over a row is
/// routable, so a subset-pattern binder must reject with IPE-L0131.
#[test]
fn subset_pattern_param_of_row_is_ipe_l0131() {
    let name = "row_poly_subset_pattern_param_neg";
    let entry = golden_dir(name).join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_out"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP {name}: runtime not available");
        return;
    };
    let res = ipe::build(&entry, &out, &runtime);
    assert!(
        res.is_err(),
        "{name} must fail to compile (subset pattern over a row)"
    );
    let Err(err) = res else { return };
    assert_eq!(
        diag_code(&err),
        Some(ipe_diagnostics::IPE_L0131),
        "a subset-pattern param over a row must be IPE-L0131 (was \
         exit-0-then-cargo-fail E0308); err = {err}"
    );
    assert!(
        !out.join("src").join("main.rs").exists(),
        "{name}: no Rust must be emitted on a rejection"
    );
}

/// A single-field row in a NON-FIRST argument position reached through an inner
/// body lambda (`getName n = \rec -> rec.name`) passes the signature gate but
/// leaves the row arrow in the trailing type the body never binds as a
/// parameter. Such a row must surface a clean IPE-L0131, never the IPE-I0001
/// ICE backstop the span-less type-lowering path would otherwise raise — a
/// well-typed program must not reach a compiler-internal invariant violation.
#[test]
fn non_first_arg_row_is_ipe_l0131_not_ice() {
    let name = "row_poly_non_first_arg_neg";
    let entry = golden_dir(name).join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_out"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP {name}: runtime not available");
        return;
    };
    let res = ipe::build(&entry, &out, &runtime);
    assert!(res.is_err(), "{name} must fail to compile");
    let Err(err) = res else { return };
    assert_eq!(
        diag_code(&err),
        Some(ipe_diagnostics::IPE_L0131),
        "a non-first-arg row reached via a body lambda must be a clean \
         IPE-L0131, never the IPE-I0001 ICE backstop; err = {err}"
    );
    assert!(
        !out.join("src").join("main.rs").exists(),
        "{name}: no Rust must be emitted on a rejection"
    );
}

/// A row-typed parameter captured into an inner lambda whose body reads the
/// field (`makeGetter rec = \_ -> rec.name`) is rewritten to the `CloneVar`
/// receiver form by the capture pass. The emitter routes a `Var` receiver
/// ONLY, so the captured `rec.name` would emit a struct-field read against the
/// bare `R1` generic (E0609 — exit-0-then-cargo-fail). The lowering containment
/// check fails it closed with IPE-L0131 and emits NO Rust.
#[test]
fn captured_clone_field_read_is_ipe_l0131() {
    let name = "row_poly_captured_clone_neg";
    let entry = golden_dir(name).join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_out"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP {name}: runtime not available");
        return;
    };
    let res = ipe::build(&entry, &out, &runtime);
    assert!(
        res.is_err(),
        "{name} must fail to compile (captured row field read escapes)"
    );
    let Err(err) = res else { return };
    assert_eq!(
        diag_code(&err),
        Some(ipe_diagnostics::IPE_L0131),
        "a row field read captured into an inner lambda must be IPE-L0131 \
         (else the emitted `rec.name` on the bare `R1` generic is E0609); \
         err = {err}"
    );
    assert!(
        !out.join("src").join("main.rs").exists(),
        "{name}: no Rust must be emitted on a rejection"
    );
}

// ---------------------------------------------------------------------------
// row_poly_accessor_two_shapes — the first-class accessor `.name` used
// polymorphically over TWO different record shapes through `List.map`. Each
// occurrence pins independently (D2), so both shapes read their `name`.
// Accept end-to-end.
// ---------------------------------------------------------------------------

/// cargo-0 ∧ run-0: `List.map .name` over a `{ name, age }` list AND a
/// `{ name, id }` list both compile and print their names. Each accessor
/// occurrence is its own monomorphic getter, so no witness trait is needed —
/// this exercises the shipped accessor path at two distinct shapes, the
/// companion to the annotated `greet` slice. Gated on `IPE_E2E=1`.
#[test]
fn accessor_two_shapes_cargo_builds_and_prints_both() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let entry = golden_dir("row_poly_accessor_two_shapes").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_row_poly_accessor_two_shapes_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for row_poly_accessor_two_shapes: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("row_poly_accessor_two_shapes", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "row_poly_accessor_two_shapes binary must exit 0; got {:?}",
        outcome.exit_code
    );
    assert_eq!(
        outcome.stdout, "Ada, Bo | Cy, Di\n",
        "must print names read through the accessor over two distinct shapes"
    );
}

// ---------------------------------------------------------------------------
// row_poly_multi — a row-polymorphic annotated function with TWO required
// fields (`{ r | name : String, id : Int }`) called at TWO different concrete
// shapes. Each field contributes one witness bound; rustc monomorphises one
// machine copy per shape. Accept end-to-end.
// ---------------------------------------------------------------------------

/// ipe-0: a multi-field argument-position open row erases to ONE rustc generic
/// carrying one witness bound per required field
/// (`IpeHasName<Name = String> + IpeHasId<Id = i64>`), with a witness impl for
/// each concrete struct carrying those fields. No `dyn`, no per-shape compiler
/// monomorphisation pass — rustc specialises per call-site shape.
#[test]
fn row_poly_multi_lowers_with_one_witness_bound_per_field() {
    let entry = golden_dir("row_poly_multi").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("row_poly_multi_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP row_poly_multi: runtime not available");
        return;
    };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must accept row_poly_multi (a two-field row at two shapes): \
         {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");
    // One generic bounded by BOTH field witnesses — the multi-field slice.
    assert!(
        emitted.contains("IpeHasName<Name = String>") && emitted.contains("IpeHasId<Id = i64>"),
        "the row parameter must carry one witness bound per required field; got \
         main.rs:\n{emitted}"
    );
    // Both concrete argument structs reach the registry unchanged; the open row
    // never becomes a Record (the pinned-records ADR survives).
    assert!(
        emitted.contains("struct RecAgeIdName") && emitted.contains("struct RecActiveIdName"),
        "both concrete argument structs must be emitted; got main.rs:\n{emitted}"
    );
    // A witness impl for EACH field on EACH struct.
    assert!(
        emitted.contains("IpeHasName for RecAgeIdName")
            && emitted.contains("IpeHasId for RecAgeIdName")
            && emitted.contains("IpeHasName for RecActiveIdName")
            && emitted.contains("IpeHasId for RecActiveIdName"),
        "each required field must have a witness impl on each carrying struct; \
         got main.rs:\n{emitted}"
    );
    assert!(
        !emitted.contains("dyn Any"),
        "row monomorphisation must be static — no type erasure; got \
         main.rs:\n{emitted}"
    );
}

/// cargo-0 ∧ run-0: the emitted project compiles (the SEAL) and prints both
/// labels, each field read off a different concrete shape. Gated on `IPE_E2E=1`.
#[test]
fn row_poly_multi_cargo_builds_and_prints_both() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let entry = golden_dir("row_poly_multi").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_row_poly_multi_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for row_poly_multi: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("row_poly_multi", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "row_poly_multi binary must exit 0 (SEAL); got {:?}",
        outcome.exit_code
    );
    assert_eq!(
        outcome.stdout, "Ada#1 Bo#2\n",
        "must print both labels — one machine copy of label per record shape"
    );
}

// ---------------------------------------------------------------------------
// row_poly_passthrough — G1 (return-position row): a pass-through function
// whose parameter and return both carry the SAME open row variable. The
// backend must emit `fn touch<R1: IpeHasN<N = i64> + Clone>(rec: R1) -> R1`.
// Accept end-to-end.
// ---------------------------------------------------------------------------

/// ipe-0: `touch : { r | n : Int } -> { r | n : Int }` is the G1 shape —
/// the return position reuses the SAME row variable as the argument, so the
/// backend emits `R1 -> R1`. The function body is `rec` (identity), which
/// threads the row param through. The emitted Rust must have the generic
/// `R1` as both param and return type.
#[test]
fn row_poly_passthrough_lowers_to_r1_to_r1() {
    let name = "row_poly_passthrough";
    let entry = golden_dir(name).join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_ipec_out"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP {name}: runtime not available");
        return;
    };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{name} must accept (G1: return-position row reusing the arg row var): {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");
    assert!(
        emitted.contains("(rec: R1) -> R1"),
        "touch must emit R1 -> R1 (same row var in arg + return positions, G1); got \
         main.rs:\n{emitted}"
    );
    assert!(
        !emitted.contains("dyn Any"),
        "row passthrough must be static — no type erasure; got main.rs:\n{emitted}"
    );
}

/// cargo-0 ∧ run-0: the emitted project compiles (SEAL) and prints the `n`
/// field of the record passed through `touch`. Gated on `IPE_E2E=1`.
#[test]
fn row_poly_passthrough_cargo_builds_and_runs() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let name = "row_poly_passthrough";
    let entry = golden_dir(name).join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for {name}: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{name} binary must exit 0 (SEAL); got {:?}",
        outcome.exit_code
    );
    assert_eq!(outcome.stdout, "1\n", "touch is identity — n stays 1");
}

// ---------------------------------------------------------------------------
// row_poly_update — G1 + G2: a row-polymorphic function that UPDATES a field
// and returns the same open-row type. The body `{ rec | n = rec.n + 1 }`
// must route through `ipe_with_n()` setter witness rather than direct field
// mutation on the opaque `R1` generic. Accept end-to-end at two distinct
// concrete shapes.
// ---------------------------------------------------------------------------

/// ipe-0: `bump : { r | n : Int } -> { r | n : Int }` with body
/// `{ rec | n = rec.n + 1 }` must lower without IPE-L0131. The backend must
/// emit a setter witness `IpeWithN` for field `n`, and the function body
/// must call `rec.ipe_with_n(…)` rather than a direct struct-field mutation.
/// Two concrete call sites (`ada : { n, label }` and `bo : { n, tag }`) force
/// rustc to monomorphise `bump` twice — one machine copy per shape.
#[test]
fn row_poly_update_lowers_to_setter_witness() {
    let name = "row_poly_update";
    let entry = golden_dir(name).join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_ipec_out"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP {name}: runtime not available");
        return;
    };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{name} must accept (G1 + G2: return-position row + update-through-row): {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");
    assert!(
        emitted.contains("pub trait IpeWithN"),
        "a setter witness trait IpeWithN must be synthesised for the updated field; \
         got main.rs:\n{emitted}"
    );
    assert!(
        emitted.contains("fn ipe_with_n(self"),
        "the setter witness method ipe_with_n must be declared; got main.rs:\n{emitted}"
    );
    assert!(
        emitted.contains(".ipe_with_n("),
        "the update body must route through ipe_with_n (not a bare struct field \
         mutation on R1); got main.rs:\n{emitted}"
    );
    assert!(
        !emitted.contains("__ipe_rec.n ="),
        "direct struct-field mutation must NOT appear for a row-generic update; \
         got main.rs:\n{emitted}"
    );
    assert!(
        !emitted.contains("dyn Any"),
        "row update must be static — no type erasure; got main.rs:\n{emitted}"
    );
}

/// cargo-0 ∧ run-0: the emitted project compiles (SEAL) and prints the
/// bumped `n` for both shapes. Gated on `IPE_E2E=1`.
#[test]
fn row_poly_update_cargo_builds_and_runs() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let name = "row_poly_update";
    let entry = golden_dir(name).join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for {name}: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{name} binary must exit 0 (SEAL); got {:?}",
        outcome.exit_code
    );
    // ada.n = 1 → bump → 2; bo.n = 10 → bump → 11
    assert_eq!(
        outcome.stdout, "2 11\n",
        "bump increments n: ada(1→2), bo(10→11)"
    );
}

// ---------------------------------------------------------------------------
// row_poly_map_update — G1 + G2 + G6: a row-polymorphic update function used
// as a first-class value in a typed higher-order function. The call site's
// concrete callback type pins the row, forcing rustc to monomorphise `bump`
// at that concrete shape. Accept end-to-end.
// ---------------------------------------------------------------------------

/// ipe-0: `bump : { r | n : Int } -> { r | n : Int }` passed as a value to
/// `apply : ({ n, label } -> { n, label }) -> { n, label } -> { n, label }`
/// must emit a `Box<dyn Fn(RecLabelN) -> RecLabelN + …>` wrapping `bump`.
/// The call site's concrete callback type (`RecLabelN -> RecLabelN`) pins the
/// row variable to `RecLabelN`, so rustc monomorphises correctly. The emitted
/// Rust must build (SEAL).
#[test]
fn row_poly_map_update_funcvalue_lowers_and_builds() {
    let name = "row_poly_map_update";
    let entry = golden_dir(name).join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_ipec_out"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP {name}: runtime not available");
        return;
    };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{name} must accept (G1 + G2 + G6: row-poly fn used as HOF value): {:?}",
        built.err()
    );
}

/// cargo-0 ∧ run-0: the emitted project compiles (SEAL) and prints the
/// bumped `n` concatenated with the `label`. Gated on `IPE_E2E=1`.
#[test]
fn row_poly_map_update_cargo_builds_and_runs() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let name = "row_poly_map_update";
    let entry = golden_dir(name).join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for {name}: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{name} binary must exit 0 (SEAL); got {:?}",
        outcome.exit_code
    );
    // bump {n=1, label="a"} → {n=2, label="a"}; print "2a"
    assert_eq!(
        outcome.stdout, "2a\n",
        "bump via HOF apply: n incremented (1→2) and label preserved (\"a\")"
    );
}
