//! Integration tests for the additive elm-coverage stdlib modules:
//! `Ipe.Bitwise`, `Ipe.Tuple`, and `Ipe.Random.Generator`.
//!
//! Locks the full seam for all three at once:
//!   * `Ipe.Bitwise` — a kernel-qualified Int surface whose members lower to
//!     the `bitwise_*` runtime functions;
//!   * `Ipe.Tuple` — a pure compiled-source module injected + canonicalised as
//!     ordinary Ipê source (its helpers pattern-match / build 2-tuples);
//!   * `Ipe.Random.Generator` — a compiled-source module whose combinators draw
//!     through the pure seeded `random_seeded_int` / `random_seeded_float`
//!     kernels, so the same seed reproduces the same values.
//!
//! Under `IPE_E2E=1` the emitted Cargo project builds and RUNS to a
//! deterministic line, proving the seed-reproducible contract end-to-end.

use std::path::PathBuf;

mod support;

#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    e2e_support::require_runtime().into_path_buf()
}

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn manifest() -> PathBuf {
    repo_root()
        .join("tests")
        .join("fixtures")
        .join("elm-coverage-additions")
        .join("package.ipe")
}

/// The project builds (Bitwise kernels resolve, Tuple + Generator inject as
/// compiled source) and the emitted Rust carries the load-bearing symbols for
/// each surface.
#[test]
fn project_builds_and_emits_all_three_surfaces() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("elm_coverage_additions");
    let _ = std::fs::remove_dir_all(&out);

    let res = ipe::build_project(&manifest(), &out, &runtime());
    assert!(
        res.is_ok(),
        "elm-coverage-additions build_project must succeed: {:?}",
        res.err()
    );

    let emitted = support::read_all_emitted_src(&out);

    // Bitwise lowers to the runtime bitwise_* functions.
    assert!(
        emitted.contains("bitwise_or")
            && emitted.contains("bitwise_and")
            && emitted.contains("bitwise_complement")
            && emitted.contains("bitwise_shift_left_by"),
        "emitted Rust must carry the Bitwise runtime calls:\n{emitted}"
    );

    // Tuple is compiled source: its helpers are homed + prefixed as functions.
    assert!(
        emitted.contains("ipe_tuple_map_both") && emitted.contains("ipe_tuple_first"),
        "emitted Rust must carry the compiled Ipe.Tuple functions:\n{emitted}"
    );

    // Generator draws through the pure seeded kernels.
    assert!(
        emitted.contains("random_seeded_int"),
        "emitted Rust must carry the seeded Generator primitive:\n{emitted}"
    );
}

/// GREEN GATE end-to-end: under `IPE_E2E=1` the emitted binary runs and prints
/// the deterministic line the three surfaces compute. The Generator values are
/// seed-fixed, so this pins the reproducibility contract.
#[test]
fn e2e_runs_and_prints_deterministic_line() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("elm_coverage_additions_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let res = ipe::build_project(&manifest(), &out, &runtime());
    assert!(res.is_ok(), "build must succeed: {:?}", res.err());

    let outcome = support::build_and_run_emitted("elm_coverage_additions", &out);
    // cleared = (1<<2 | 1) & ~1 = 5 & ~1 = 4; Tuple.first/second of the mapped
    // ( 3, 4 ) = 4 / 8; the trailing number is the seed-fixed Generator sum
    // (the full-64-bit unbiased seeded reduction, #2639/#2641).
    assert_eq!(
        outcome.stdout, "4 4 8 11\n",
        "the emitted binary must print the deterministic Bitwise/Tuple/Generator line"
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}
