//! Multi-module golden tests.
//!
//! Two kinds of assertion live here:
//!
//! **Positive fixtures** (`mm_local_pkg`, `mm_diamond`) compile successfully
//! and the emitted `main.rs` is byte-identical to the checked-in golden.
//! They also verify that `ipe build_project` handles three
//! multi-module blockers:
//!   * Defect 1 — kernel imports (`Ipe.Io`) accepted without
//!     IPE-N0020.
//!   * Defect 2 — same-named functions in different modules emit distinct
//!     Rust names (no E0428 from `cargo build`).
//!   * Defect 3 — same-named constructors from two modules trigger clean
//!     IPE-N0024 rather than silently resolving to the wrong type.
//!
//! **Negative fixtures** each contain a deliberate error and assert the
//! exact `Code` produced: `missing` → N0020, `cycle`/`selfimport` → N0021,
//! `notexposed` → N0022, `pathmismatch` → N0023, `ambigval`/`ambigctor`/
//! `samedef` → N0024, `reserved` → N0025, `sametype` → N0012.
//!
//! The golden `main.rs` files are the checked-in output of `ipe` against each
//! fixture.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(name: &str) -> PathBuf {
    repo_root().join("tests").join("golden").join(name)
}

// `fn runtime()` is a non-`#[test]` helper, so `allow-expect-in-tests = true`
// in clippy.toml does not exempt it automatically.  The explicit allow is
// correct: this is integration-test scaffolding that should panic loudly on a
// broken environment, and `expect` is the idiomatic way to express that.
#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    e2e_support::require_runtime().into_path_buf()
}

// ---------------------------------------------------------------------------
// Positive: mm_local_pkg
// Local module (Lib) exposes a value + ADT + ctors; Main imports both Lib
// and Ipe.Io. Exercises Defect-1 fix (kernel skip) and ensures the
// emitted Rust compiles with distinct names.
// ---------------------------------------------------------------------------

#[test]
fn mm_local_pkg_emits_byte_identical_main_rs() {
    let fixture = golden_dir("mm_local_pkg");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("mm_local_pkg");
    let _ = std::fs::remove_dir_all(&out);

    let res = ipe::build_project(&fixture.join("package.ipe"), &out, &runtime());
    assert!(res.is_ok(), "build_project failed: {:?}", res.err());

    // Emitted `src/main.rs` must equal the checked-in golden `main.rs`, routed
    // through the shared directory-diff helper (replaces the hand-rolled
    // `read_to_string` + `assert_eq!` pair).
    crate::support::assert_emitted_project_matches_golden_dir(&out, &fixture);
}

// ---------------------------------------------------------------------------
// Positive: mm_diamond — A→B, A→C, B→D, C→D. D is compiled exactly once.
// ---------------------------------------------------------------------------

#[test]
fn mm_diamond_emits_byte_identical_main_rs() {
    let fixture = golden_dir("mm_diamond");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("mm_diamond");
    let _ = std::fs::remove_dir_all(&out);

    let res = ipe::build_project(&fixture.join("package.ipe"), &out, &runtime());
    assert!(res.is_ok(), "build_project failed: {:?}", res.err());

    // Byte-diff half: emitted `src/main.rs` must equal the golden `main.rs`,
    // routed through the shared directory-diff helper.
    crate::support::assert_emitted_project_matches_golden_dir(&out, &fixture);

    // Seal half: D's `base` function must appear exactly once (D compiled once,
    // shared by B and C). D is a genuine own-home module, so the per-Ipê-module
    // split places `d_base` in `src/ipe_mods/ipe_mod_d.rs`
    // — scan the WHOLE emitted Ipê-side tree (main.rs + ipe_mods/*.rs) for the
    // count, robust to that placement. The directory-diff helper above cannot
    // express a substring-count assertion, so this reads the source directly.
    let emitted = crate::support::read_all_emitted_src(&out);
    let count = emitted.matches("fn d_base").count();
    assert_eq!(
        count, 1,
        "d_base must appear exactly once in the emitted output (D compiled once)"
    );
}

// ---------------------------------------------------------------------------
// Positive: mm_qualtype_local_shadow — Main defines local `type Msg` AND
// references `Counter.Msg` in a qualified annotation.  Exercises the
// `qualifier_paths` fix: without it the canonicaliser resolved `Counter.Msg`
// to Main's home (`["Main"]`) instead of Counter's (`["Counter"]`), causing
// a IPE-T0001 type-mismatch at the unification site.
// ---------------------------------------------------------------------------

#[test]
fn mm_qualtype_local_shadow_compiles() {
    let fixture = golden_dir("mm_qualtype_local_shadow");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("mm_qualtype_local_shadow");
    let _ = std::fs::remove_dir_all(&out);
    let res = ipe::build_project(&fixture.join("package.ipe"), &out, &runtime());
    assert!(res.is_ok(), "build_project failed: {:?}", res.err());
}

// ---------------------------------------------------------------------------
// Negative helpers
// ---------------------------------------------------------------------------

#[allow(clippy::expect_used)] // a failed precondition is the test failure
fn expect_error_code(fixture_name: &str, expected: ipe_diagnostics::Code) {
    let fixture = golden_dir(fixture_name);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(fixture_name);
    let _ = std::fs::remove_dir_all(&out);

    let res = ipe::build_project(&fixture.join("package.ipe"), &out, &runtime());
    assert!(
        res.is_err(),
        "fixture `{fixture_name}` must fail but succeeded"
    );
    let err = res.expect_err("`res` must be rejected");
    // Extract the Code from a Pipeline error; other variants have no code.
    let code = match &err {
        ipe::CliError::Pipeline { diag, .. } => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        code,
        Some(expected),
        "fixture `{fixture_name}`: expected error code {expected:?}, got {code:?}\nerr = {err}"
    );
}

// ---------------------------------------------------------------------------
// Negative: missing module → IPE-N0020
// ---------------------------------------------------------------------------

#[test]
fn mm_neg_missing_is_ipe_n0020() {
    expect_error_code("mm_neg_missing", ipe_diagnostics::IPE_N0020);
}

// ---------------------------------------------------------------------------
// Negative: import cycle → IPE-N0021
// ---------------------------------------------------------------------------

#[test]
fn mm_neg_cycle_is_ipe_n0021() {
    expect_error_code("mm_neg_cycle", ipe_diagnostics::IPE_N0021);
}

// ---------------------------------------------------------------------------
// Negative: self-import → IPE-N0021 (self is a degenerate cycle)
// ---------------------------------------------------------------------------

#[test]
fn mm_neg_selfimport_is_ipe_n0021() {
    expect_error_code("mm_neg_selfimport", ipe_diagnostics::IPE_N0021);
}

// ---------------------------------------------------------------------------
// Negative: name not exposed → IPE-N0022
// ---------------------------------------------------------------------------

#[test]
fn mm_neg_notexposed_is_ipe_n0022() {
    expect_error_code("mm_neg_notexposed", ipe_diagnostics::IPE_N0022);
}

// ---------------------------------------------------------------------------
// Negative: module path mismatch → IPE-N0023
// ---------------------------------------------------------------------------

#[test]
fn mm_neg_pathmismatch_is_ipe_n0023() {
    expect_error_code("mm_neg_pathmismatch", ipe_diagnostics::IPE_N0023);
}

// ---------------------------------------------------------------------------
// Negative: ambiguous value import → IPE-N0024
// ---------------------------------------------------------------------------

#[test]
fn mm_neg_ambigval_is_ipe_n0024() {
    expect_error_code("mm_neg_ambigval", ipe_diagnostics::IPE_N0024);
}

// ---------------------------------------------------------------------------
// Negative: ambiguous constructor import (Defect-3 gate) → IPE-N0024
// Without the Defect-3 fix this would silently resolve to the wrong type and
// later trigger a Rust E0308 from `cargo build`.
// ---------------------------------------------------------------------------

#[test]
fn mm_neg_ambigctor_is_ipe_n0024() {
    expect_error_code("mm_neg_ambigctor", ipe_diagnostics::IPE_N0024);
}

// ---------------------------------------------------------------------------
// Negative: reserved namespace (`Ipê.*` / `Ipe.*`) → IPE-N0025
// ---------------------------------------------------------------------------

#[test]
fn mm_neg_reserved_is_ipe_n0025() {
    expect_error_code("mm_neg_reserved", ipe_diagnostics::IPE_N0025);
}

// ---------------------------------------------------------------------------
// Negative: same-named value exported by two modules, both imported
// unqualified (Defect-2 regression guard — the name-level ambiguity must be
// caught by the canon layer, not survive to produce a Rust E0428) → IPE-N0024
// ---------------------------------------------------------------------------

#[test]
fn mm_neg_samedef_is_ipe_n0024() {
    expect_error_code("mm_neg_samedef", ipe_diagnostics::IPE_N0024);
}

// ---------------------------------------------------------------------------
// Negative: same type name from two modules both imported → IPE-N0012
// ---------------------------------------------------------------------------

#[test]
fn mm_neg_sametype_is_ipe_n0012() {
    expect_error_code("mm_neg_sametype", ipe_diagnostics::IPE_N0012);
}

// ---------------------------------------------------------------------------
// Negative: qualified cross-module reference with wrong argument type → IPE-T0001
//
// Lib.helper : Int -> Int; Main calls `Lib.helper "str"` — qualified, so
// IPE-N0024 does not fire.  Before the constrain re-key fix, `top_level` was
// keyed by bare Symbol so a same-named `Main.helper` (if present) would
// overwrite `Lib.helper`'s entry, making ipe exit 0 and emit wrong-type Rust
// that fails only at `cargo build` (E0308).  After the fix, `Lib.helper` is
// looked up under its own `(["Lib"], "helper")` key and the mismatch is
// diagnosed as IPE-T0001 right here, never reaching codegen.
// ---------------------------------------------------------------------------

#[test]
fn mm_neg_qualref_sig_is_ipe_t0001() {
    expect_error_code("mm_neg_qualref_sig", ipe_diagnostics::IPE_T0001);
}
