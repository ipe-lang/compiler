//! Parser-gaps golden gate — build+run fixtures for parser features that
//! otherwise have coverage only at parse-level unit tests. The
//! "every new feature becomes a regression test" rule requires a build+run
//! golden per feature, not just an AST-shape assertion; this file covers
//! five surfaces.
//!
//! ## Positives (build → run → byte-diff against the cached oracle)
//!
//! Each single-file positive compiles `tests/golden/<name>/Main.ipe` through
//! `ipe`, builds the emitted Rust project in the shared cargo target, runs it,
//! and checks stdout against the cached golden oracle (`oracle.meta` +
//! `expected_go.txt`). All three carry `oracle_divergence = false` ...//! reference compiler produces byte-identical stdout, captured via
//! `refresh-oracle`.
//!
//! * `intdiv` — `//` integer division. `20 // 2` → `10` and `(-7) // 2` →
//!   `-3` (truncation toward zero, Elm parity; a floor-division backend
//!   would give `-4`). Output: `"10 -3"`.
//! * `intdiv_minint` — F6 regression: `i64::MIN // -1`. Raw Rust `/`
//!   panics here unconditionally (signed-overflow hardware trap); Ipê
//!   returns `i64::MIN` (two's-complement wrap). `ipe_int_div` reproduces this
//!   via `wrapping_div`. Output: `"-9223372036854775808"`, exit 0.
//! * `let_fn` — a let-bound *function* (`inc n = n + 1`) applied inside the
//!   `in` body. Output: `"30"`.
//! * `blockcomment` — a `{- … -}` block comment containing an em-dash plus a
//!   nested `{- {- -} -}` comment; both are skipped and the program prints.
//!   Output: `"ok"`.
//!
//! The multi-module positive uses `ipe::build_project` (a `package.ipe` project
//! with a `Lib` module) then runs the emitted binary:
//!
//! * `mm_qualtype` — `Lib` exposes `type Box a = Box a`; `Main` annotates a
//!   binding with the *qualified* type name `Lib.Box Int` and unwraps it.
//!   Output: `"42"` (hand-verified). Multi-module goldens keep their source under
//!   `src/`, so the single-file oracle-cache layout does not apply; the run
//!   asserts the literal hand-verified stdout instead.
//!
//! ## Negatives (assert the exact `IPE-*` diagnostic / runtime classification)
//!
//! * `intdiv_divzero` — `10 // 0` at runtime. The runtime classifies this
//!   as `DivisionByZero` and aborts with exit code 101 (a Rust panic), rather
//!   than emitting a wrong answer. Asserted by building + running the emitted
//!   binary and checking the exit code (gated on `IPE_E2E`).
//! * `blockcomment_unterminated` — a `{-` that is never closed → `IPE-P0017`
//!   (unterminated block comment). This is a sanctioned stricter behaviour: the
//!   golden oracle leniently swallows the unterminated comment to EOF and builds an
//!   empty program, so there is no oracle to diff — the diagnostic code is the
//!   assertion.
//! * `mm_neg_qualtype_unknownmod` — an annotation referencing `Bogus.Box`, a
//!   module that is neither imported nor present → `IPE-N0004` (unknown module).
//!
//! Run the E2E positives + the runtime negative with:
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_parser_gaps
//! ```
//!
//! The compile-time negatives run unconditionally (no build/run, so no gate).

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(name: &str) -> PathBuf {
    repo_root().join("tests").join("golden").join(name)
}

// `runtime()` is a non-`#[test]` helper, so clippy's test-only `expect`
// exemption does not apply automatically. The explicit allow is correct: a
// broken toolchain environment should fail loudly here, not silently skip.
#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    e2e_support::require_runtime().into_path_buf()
}

// ---------------------------------------------------------------------------
// Single-file positive: build → run → cached-oracle byte-diff (IPE_E2E-gated).
// ---------------------------------------------------------------------------

fn assert_single_oracle(name: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = golden_dir(name);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let built = ipe::build(&entry, &out, &runtime());
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

#[test]
fn intdiv_builds_and_matches_oracle() {
    assert_single_oracle("intdiv");
}

#[test]
fn let_fn_builds_and_matches_oracle() {
    assert_single_oracle("let_fn");
}

#[test]
fn blockcomment_builds_and_matches_oracle() {
    assert_single_oracle("blockcomment");
}

// ---------------------------------------------------------------------------
// Multi-module positive: build_project → run → literal hand-verified stdout.
// ---------------------------------------------------------------------------

#[test]
fn qualtype_project_builds_and_prints_42() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let name = "mm_qualtype";
    let dir = golden_dir(name);
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let built = ipe::build_project(&dir.join("package.ipe"), &out, &runtime());
    assert!(
        built.is_ok(),
        "build_project failed for {name}: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted(name, &out);
    // hand-verified reference: `unbox (Box 42)` prints `42`. Multi-module goldens
    // store source under `src/`, so the single-file oracle cache does not apply.
    assert_eq!(
        outcome.stdout, "42\n",
        "qualified `Lib.Box Int` must yield 42"
    );
    assert_eq!(outcome.exit_code, Some(0), "clean exit");
}

// ---------------------------------------------------------------------------
// Runtime negative: `//` division by zero → DivisionByZero, exit 101.
// ---------------------------------------------------------------------------

#[test]
fn intdiv_by_zero_aborts_exit_101() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let name = "intdiv_divzero";
    let dir = golden_dir(name);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    // Codegen succeeds — the failure is a *runtime* classification, not a
    // compile error.
    let built = ipe::build(&entry, &out, &runtime());
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.exit_code,
        Some(101),
        "division by zero must abort with the Rust panic exit code, not print a value"
    );
    assert_eq!(
        outcome.stdout, "",
        "no value is printed once DivisionByZero fires"
    );
}

/// F6 regression — `i64::MIN // -1` must NOT panic.
///
/// Raw Rust `/` on `i64` panics here unconditionally (signed-overflow hardware
/// trap, present even with `overflow-checks = false`). Ipê uses two's-complement
/// arithmetic and returns `i64::MIN`. The fix routes `BinOp::IntDiv` through
/// `ipe_runtime::math::ipe_int_div(a, b)` which calls `a.wrapping_div(b)` for
/// non-zero divisors.
#[test]
fn intdiv_minint_by_neg1_does_not_panic() {
    assert_single_oracle("intdiv_minint");
}

// ---------------------------------------------------------------------------
// Compile-time negatives: exact IPE-* diagnostic codes (always run).
// ---------------------------------------------------------------------------

fn diag_code(err: &ipe::CliError) -> Option<ipe_diagnostics::Code> {
    match err {
        ipe::CliError::Pipeline { diag, .. } => Some(diag.code()),
        _ => None,
    }
}

#[test]
fn unterminated_blockcomment_is_ipe_p0017() {
    let name = "blockcomment_unterminated";
    let entry = golden_dir(name).join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}"));
    let _ = std::fs::remove_dir_all(&out);

    let res = ipe::build(&entry, &out, &runtime());
    assert!(res.is_err(), "{name} must fail to compile");
    let err = res.expect_err("`res` must be rejected");
    assert_eq!(
        diag_code(&err),
        Some(ipe_diagnostics::IPE_P0017),
        "unterminated `{{-` must be IPE-P0017; err = {err}"
    );
}

#[test]
fn unknown_module_in_annotation_is_ipe_n0004() {
    let name = "mm_neg_qualtype_unknownmod";
    let dir = golden_dir(name);
    let out = crate::support::scratch_root().join(format!("ipec_{name}"));
    let _ = std::fs::remove_dir_all(&out);

    let res = ipe::build_project(&dir.join("package.ipe"), &out, &runtime());
    assert!(res.is_err(), "{name} must fail to compile");
    let err = res.expect_err("`res` must be rejected");
    assert_eq!(
        diag_code(&err),
        Some(ipe_diagnostics::IPE_N0004),
        "`Bogus.Box` must be IPE-N0004 (unknown module); err = {err}"
    );
}
