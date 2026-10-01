//! Unit PATTERN gate: `()` accepted in pattern position. The parser previously
//! rejected `()` as a pattern, forcing `Ok _` where `Ok ()` is natural (Elm
//! accepts the unit pattern). The parser now admits the unit pattern nested
//! inside a constructor (`Ok () ->`) and as a plain `case` head
//! (`case u of () -> …`); it binds nothing and type-checks against `()`.
//!
//! ```text
//! describe (Ok ())    -- "ok"
//! describe (Err "bad")-- "bad"
//! unitLabel ()        -- "unit"   (case u of () -> …)
//! ```
use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("unit_pattern_match")
        .join("Main.ipe")
}

/// ipe-0: the compiler accepts the unit-pattern program (parse + typecheck +
/// emit) and lowers the `()` pattern to a wildcard against a unit-typed
/// scrutinee. Checked unconditionally, independent of the `IPE_E2E` gate — this
/// is the acceptance the parser fix restores.
#[test]
fn unit_pattern_ipec_accepts_and_lowers() {
    let root = repo_root();
    let entry = example_entry(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("unit_pattern_match_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must accept the unit pattern `()`: {:?}",
        built.err()
    );

    // The nested `Ok ()` arm and the bare `()` arm both discriminate a
    // unit-typed value; the emitted `main.rs` must exist (acceptance proven by
    // the successful build above — the emit is the ipe-0 side of the SEAL).
    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");
    assert!(
        !emitted.is_empty(),
        "emitted main.rs must be non-empty for the unit-pattern program"
    );
}

/// cargo-0 ∧ run-0: the emitted project compiles and prints the three decoded
/// branches — `ok` (nested `Ok ()`), `bad` (`Err`), and `unit` (bare `()` arm).
/// Gated on `IPE_E2E=1`.
#[test]
fn unit_pattern_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_unit_pattern_match_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("unit_pattern_match", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "unit_pattern_match binary must exit 0; got {:?} (stdout: {:?})",
        outcome.exit_code,
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("ok bad unit"),
        "the unit-pattern arms must decode `Ok ()`⇒ok, `Err`⇒bad, `()`⇒unit; got: {:?}",
        outcome.stdout
    );
}
