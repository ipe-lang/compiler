//! Multi-arm tuple `case` — the tuple-pattern gap close.
//!
//! A `case` on a LITERAL tuple with more than one arm (or a refutable column)
//! lowers to a native Rust tuple `match`, matching each column against its own
//! slice / `&str` coercion (rather than fail-closing as IPE-L0115, the "tuple
//! pattern not supported here yet" product gap):
//!
//! ```text
//! match (xs.as_slice(), ys.as_slice()) {
//!     ([a, xrest @ ..], [b, yrest @ ..]) => …,
//!     _ => …,
//! }
//! ```
//!
//! This is the blocker `38-composite-ui-multibackend` hit at
//! `State.seedHistoryHelp` (`case ( offsets, flags ) of ( i :: ix, b :: bs ) ->
//! … ; _ -> …`). Coverage is proven UPSTREAM by the IPE-T0010 usefulness check
//! (product patterns decompose to `Head::Tuple`), so the backend never sees a
//! non-exhaustive tuple `case`; the fix is purely additive — a variable-scrutinee
//! or record product `case` stays fail-closed as IPE-L0115 (the m3b1/m3b2 gates).
//!
//! Gate check (fast, always): `ipe build` succeeds — no IPE-L0115.
//! Green check (`IPE_E2E=1`): the emitted Rust cargo-builds AND runs, proving the
//! Seal (ipe-0 ⟹ cargo-0) for the new tuple-match codegen.
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_tuple_multiarm_case
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry() -> PathBuf {
    repo_root()
        .join("tests")
        .join("golden")
        .join("i_tuple_multiarm_case")
        .join("Main.ipe")
}

/// Fast gate: a multi-arm LITERAL-tuple `case` builds cleanly — the IPE-L0115
/// product gap is closed for this shape.
#[test]
fn multi_arm_tuple_case_builds() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("tuple_multiarm_gate");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&fixture_entry(), &out, &runtime);
    assert!(
        built.is_ok(),
        "multi-arm tuple `case` must build (IPE-L0115 close); got {:?}",
        built.err()
    );
}

/// Seal: the emitted Rust cargo-builds and runs. `zipSum [1,2,3] [10,20,30] []`
/// is `[11, 22, 33]` (length 3); `classify True False` is `2`; sum is `5`.
#[test]
fn multi_arm_tuple_case_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let out = crate::support::scratch_root().join("ipec_tuple_multiarm_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&fixture_entry(), &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for i_tuple_multiarm_case: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("i_tuple_multiarm_case", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "emitted tuple-match program must exit 0"
    );
    assert!(
        outcome.stdout.contains('5'),
        "expected '5' (3 + 2); got:\n{}",
        outcome.stdout
    );
}
