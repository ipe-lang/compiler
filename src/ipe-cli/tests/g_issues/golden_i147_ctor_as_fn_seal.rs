//! Seal — constructors as first-class function values.
//!
//! A constructor of arity N in a value / partial-application position must not
//! emit `Err(unsupported(…, Feature::CtorAsFunction))` (IPE-L0113).  The
//! lowerer routes such sites into `eta_expand_partial_ctor`, producing an
//! eta-wrapped closure that captures the supplied args (with T4 capture-
//! clone discipline) and takes the remaining ones as lambda parameters:
//!
//! ```text
//! Tagged "item"     (arity 2, 1 supplied)
//! ──────────────────────────────────────────────────────────────
//! Box::new(move |eta_0: i64| -> Item { Main_Tagged("item".to_string(), eta_0) })
//! ```
//!
//! Three scenarios:
//!
//! * **A1** (`ctor_map_bare`) — nullary-arity-1 ctor passed bare to
//!   `List.map`: `List.map Wrap [1,2,3]` → `[Wrap(1), Wrap(2), Wrap(3)]`.
//! * **A2** (`ctor_partial`) — partial multi-arg ctor + T4 String capture:
//!   `Tagged "item"` mapped over `[10, 20, 30]` → `"item:10, item:20, item:30"`.
//! * **A3** (`ctor_field`) — ctor as a HOF argument (user-fn taking `String -> Box`):
//!   `applyMk Wrap "hello"` → `"hello"`. (Records cannot hold function-typed fields
//!   per IPE-L0107; the equivalent "first-class ctor" story holds via HOF arguments.)
//!
//! All three also verify that the `gate_partial` fixture (formerly the
//! IPE-L0113 gate) now COMPILES SUCCESSFULLY as a positive regression.
//!
//! Gated: green fixtures (A1-A3) require `IPE_E2E=1` for the cargo build+run
//! step; the `gate_partial` positive-compile check runs always.
//!
//! ```text
//! # green suite (cargo-0 required):
//! IPE_E2E=1 cargo test -p ipe --test golden_i147_ctor_as_fn_seal
//!
//! # positive-compile check only (fast):
//! cargo test -p ipe --test golden_i147_ctor_as_fn_seal
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Assert that `ipe::build(fixture)` SUCCEEDS (exit-0 from the lowerer).
/// Runs without `IPE_E2E` so this check is always fast.
fn assert_ipec_ok(fixture: &str, out_suffix: &str) {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(out_suffix);
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for fixture {fixture}: {:?}",
        built.err()
    );
}

// ── gate_partial positive-compile (formerly IPE-L0113 gate) ──────────────

/// The `gate_partial` fixture (`Node x 1` — arity-3 ctor with 2 supplied
/// args) must COMPILE SUCCESSFULLY (not surface IPE-L0113).
#[test]
fn m3a_gate_partial_now_compiles() {
    assert_ipec_ok("gate_partial", "i147_m3a_gate_partial_positive");
}

// ── A1 — bare ctor passed to List.map ────────────────────────────────────────

/// `Wrap : Int -> Box` (arity 1) passed bare to `List.map`.
/// `List.map Wrap [1,2,3]` → `[Wrap(1), Wrap(2), Wrap(3)]` → unwrapped
/// and joined → `"1, 2, 3"`.
#[test]
fn a1_ctor_map_bare() {
    assert_ipec_ok("ctor_map_bare", "i147_ctor_map_bare_emit");

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let root = repo_root();
        let entry = root
            .join("tests")
            .join("golden")
            .join("ctor_map_bare")
            .join("Main.ipe");
        let out = crate::support::scratch_root().join("ipec_i147_ctor_map_bare_e2e");
        let _ = std::fs::remove_dir_all(&out);

        let runtime = e2e_support::require_runtime().into_path_buf();

        let built = ipe::build(&entry, &out, &runtime);
        assert!(
            built.is_ok(),
            "ipe build must succeed for ctor_map_bare: {:?}",
            built.err()
        );

        let outcome = crate::support::build_and_run_emitted("ctor_map_bare", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "A1: must exit 0 (was IPE-L0113 before #147)"
        );
        assert!(
            outcome.stdout.contains("1, 2, 3"),
            "A1: List.map with bare ctor must produce '1, 2, 3'; got:\n{}",
            outcome.stdout
        );
    }
}

// ── A2 — partial multi-arg ctor + T4 String capture ──────────────────────────

/// `Tagged "item"` (arity-2 ctor with 1 arg supplied) mapped over `[10, 20, 30]`.
/// The captured `"item" : String` is `CloneOk` — T4 rewrites it to
/// `.clone()` so the closure is `Fn` and survives multiple calls.
/// Expected output: `"item:10, item:20, item:30"`.
#[test]
fn a2_ctor_partial_multiarg_with_clone() {
    assert_ipec_ok("ctor_partial", "i147_ctor_partial_emit");

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let root = repo_root();
        let entry = root
            .join("tests")
            .join("golden")
            .join("ctor_partial")
            .join("Main.ipe");
        let out = crate::support::scratch_root().join("ipec_i147_ctor_partial_e2e");
        let _ = std::fs::remove_dir_all(&out);

        let runtime = e2e_support::require_runtime().into_path_buf();

        let built = ipe::build(&entry, &out, &runtime);
        assert!(
            built.is_ok(),
            "ipe build must succeed for ctor_partial: {:?}",
            built.err()
        );

        let outcome = crate::support::build_and_run_emitted("ctor_partial", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "A2: must exit 0 (was IPE-L0113 before #147)"
        );
        assert!(
            outcome.stdout.contains("item:10, item:20, item:30"),
            "A2: partial ctor with captured String must produce 'item:10, item:20, item:30'; got:\n{}",
            outcome.stdout
        );
    }
}

// ── A3 — ctor stored in record field then applied ─────────────────────────────

/// `applyMk Wrap "hello"` — `Wrap : String -> Box` is passed as a HOF
/// argument whose slot type is `String -> Box`.  The `VarCtor` path in
/// `lower_expr` eta-expands the bare ctor into a closure which the function
/// then calls.  Expected output: `"hello"`.
#[test]
fn a3_ctor_stored_in_record_field() {
    assert_ipec_ok("ctor_field", "i147_ctor_field_emit");

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let root = repo_root();
        let entry = root
            .join("tests")
            .join("golden")
            .join("ctor_field")
            .join("Main.ipe");
        let out = crate::support::scratch_root().join("ipec_i147_ctor_field_e2e");
        let _ = std::fs::remove_dir_all(&out);

        let runtime = e2e_support::require_runtime().into_path_buf();

        let built = ipe::build(&entry, &out, &runtime);
        assert!(
            built.is_ok(),
            "ipe build must succeed for ctor_field: {:?}",
            built.err()
        );

        let outcome = crate::support::build_and_run_emitted("ctor_field", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "A3: must exit 0 (was IPE-L0113 before #147)"
        );
        assert!(
            outcome.stdout.contains("hello"),
            "A3: ctor in record field then applied must produce 'hello'; got:\n{}",
            outcome.stdout
        );
    }
}
