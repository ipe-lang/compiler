//! A promoted Arc-root handler and a non-promoted
//! function-value sibling unified at ONE Rust type position.
//!
//! Without the fix, `ipe dev build` exits 0, but the emitted Rust fails `cargo build` with
//! E0308. A function-typed `let handler = \form -> …` flows into the
//! `Ui.onSubmit` kernel (a `requires_sync_capture` consumer), so the lowerer
//! promotes it to an `Expr::SharedLambda` — its reads render
//! `Arc<dyn Fn(..) + Send + Sync>`. When a read of `handler` sits in ONE branch
//! of an `if`/`case` whose SIBLING branch renders a function value at the
//! DEFAULT `Box<dyn Fn(..) + Send + Sync>` carrier, the two branches must unify
//! at one Rust type slot. `Arc` and `Box` are distinct types even with identical
//! trait bounds → E0308 (SEAL break: ipe exit 0, cargo fail). Four sibling
//! shapes exercise the whole class:
//!
//!   (1) inline-lambda sibling  (`else \form -> Noop`)                — base case
//!   (2) top-level function reference sibling (`else signIn`)        — `FuncValue`
//!   (3) `let`-bound lambda read as a `Var` sibling (`else alt`)     — `Var`
//!   (4) `case`/`match` (not `if`) with a `FuncValue` sibling arm    — `Match`
//!
//! Shape (2)/(4) is the reviewer's exact refutation of the prior
//! inline-lambda-only fix: an `Expr::FuncValue` sibling still rendered
//! `Box::new(main_sign_in)` against the promoted `Arc`, same E0308 one Expr shape
//! over.
//!
//! Fix (`promote_unification_sibling_lambdas` in `crates/ipe_lower/src/lower.rs`):
//! when `handler` becomes a `SharedLambda`, coerce EVERY sibling function-value
//! leaf in the unification group to the `Arc` carrier — an inline `Expr::Lambda`
//! directly to `SharedLambda`, every OTHER shape (`FuncValue`/`Var`/`Access`/
//! `Apply`/`Call`) via eta-expansion into `SharedLambda { body: Apply(f, [Var
//! (fresh0), …]) }` (rendering `Arc::new(move |x| (f)(x))`). The promoted
//! `handler` value-leaf read is cloned (`Arc::clone`) so it is not moved out of
//! the backend's synthetic `move |_x| (…)(_x)` re-wrap `Fn` closure (E0507).
//! Both branches then render the identical `Arc<dyn Fn(..) + Send + Sync>`
//! carrier and the crate type-checks AND builds.
//!
//! Run:
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_i172_mixed_arc_box_handler
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path, fixture: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe")
}

/// ipe-0 ∧ carrier-unification: the compiler must accept the program AND emit
/// the `Ui.onSubmit` argument's sibling branches through the identical `Arc`
/// carrier — checked unconditionally (cheap, no `cargo`), independent of the
/// `IPE_E2E` gate. This is the exact assertion the E0308/E0507 SEAL break cannot
/// recur: at the unification slot the emitted Rust must build the sibling
/// function value via `::std::sync::Arc::new` (never a bare `Box::new` at the
/// slot), and the promoted `handler` value-leaf must be CLONED (`.clone()`,
/// `Arc::clone`), never moved.
// `expect` on the emitted-file read is the test's own failure signal; the
// repo's `allow-expect-in-tests` clippy exemption covers only `#[test]` bodies,
// not this shared helper, so the allow is stated here (matching
// `golden_mm.rs` / `golden_multi_mod_split_pilot.rs`).
#[allow(clippy::expect_used)]
fn assert_ipec_unifies_to_arc(fixture: &str) {
    let root = repo_root();
    let entry = entry_path(&root, fixture);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{fixture}_ipec_out"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for {fixture}: {:?}",
        built.err()
    );

    // The user code lands in the per-module file under `ipe_mods/`; the aggregate
    // `main.rs` also `#[path]`-includes it, so read whichever exists.
    let module = out.join("src").join("ipe_mods").join("ipe_mod_main.rs");
    let aggregate = out.join("src").join("main.rs");
    let emitted = std::fs::read_to_string(&module)
        .or_else(|_| std::fs::read_to_string(&aggregate))
        .expect("emitted main module must exist");

    // The sibling function value at the `onSubmit` slot must render via
    // `Arc::new` — the eta-expanded (FuncValue/Var) or directly-coerced (inline
    // lambda) branch — matching the promoted `Arc` handler.
    assert!(
        emitted.contains("::std::sync::Arc::new"),
        "the sibling branch must be coerced to the `Arc` carrier via \
         `::std::sync::Arc::new` (#172); got:\n{emitted}"
    );
    // Guard against the unfixed shape: no bare `Box::new` may sit at the
    // `onSubmit` unification slot. The eta-expanded FuncValue body legitimately
    // still contains `Box::new(main_sign_in)` INSIDE the Arc wrapper, so we
    // cannot forbid `Box::new` outright — instead assert the promoted handler
    // read is cloned (proving the depth-0 move-out E0507 shape is closed).
    assert!(
        emitted.contains("handler.clone()"),
        "the promoted `handler` value-leaf must be cloned (`Arc::clone`), not \
         moved out of the re-wrap closure (#172 E0507 guard); got:\n{emitted}"
    );
}

/// cargo-0 ∧ run-0: the emitted project actually compiles with `rustc` (no
/// E0308/E0507) and renders the form. Gated on `IPE_E2E=1` — the only check that
/// would have caught the original SEAL violation (E0308, `ipe dev build` clean).
fn assert_cargo_builds_and_runs(fixture: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root, fixture);
    let out = crate::support::scratch_root().join(format!("ipec_{fixture}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for {fixture}: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted(fixture, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{fixture} binary must exit 0 (no E0308/E0507); got {:?} (stdout: {:?})",
        outcome.exit_code,
        outcome.stdout
    );
    // The rendered form proves the whole `Ui.onSubmit (if/case …)` expression
    // type-checked AND ran through the unified `Arc` carrier.
    assert!(
        outcome.stdout.contains("<form") && outcome.stdout.contains("sign in"),
        "must render the sign-in form through the unified handler; got: {:?}",
        outcome.stdout
    );
}

// ── Shape (1): inline-lambda sibling (base case) ──────────────────────────────

#[test]
fn i172_inline_lambda_ipec_unifies_to_arc() {
    assert_ipec_unifies_to_arc("mixed_arc_box_inline_lambda");
}

#[test]
fn i172_inline_lambda_cargo_builds_and_runs() {
    assert_cargo_builds_and_runs("mixed_arc_box_inline_lambda");
}

// ── Shape (2): top-level function reference sibling (Expr::FuncValue) ──────────

#[test]
fn i172_funcvalue_ipec_unifies_to_arc() {
    assert_ipec_unifies_to_arc("mixed_arc_box_funcvalue");
}

#[test]
fn i172_funcvalue_cargo_builds_and_runs() {
    assert_cargo_builds_and_runs("mixed_arc_box_funcvalue");
}

// ── Shape (3): let-bound lambda read as a Var sibling ─────────────────────────

#[test]
fn i172_var_sibling_ipec_unifies_to_arc() {
    assert_ipec_unifies_to_arc("mixed_arc_box_var_sibling");
}

#[test]
fn i172_var_sibling_cargo_builds_and_runs() {
    assert_cargo_builds_and_runs("mixed_arc_box_var_sibling");
}

// ── Shape (4): case/match with a FuncValue sibling arm ────────────────────────

#[test]
fn i172_match_funcvalue_ipec_unifies_to_arc() {
    assert_ipec_unifies_to_arc("mixed_arc_box_match_funcvalue");
}

#[test]
fn i172_match_funcvalue_cargo_builds_and_runs() {
    assert_cargo_builds_and_runs("mixed_arc_box_match_funcvalue");
}
