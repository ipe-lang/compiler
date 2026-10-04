//! FALSE-POSITIVE guard — the general kernel->bound map must
//! NOT over-bound.
//!
//! The stringify obligation is decided per-param by the EXACT `{{…}}`
//! interpolation argument position (arg 0), mirroring the `IpeRow` per-row-arg precision.
//! A wildcard `any` param used ONLY as a Db row (which correctly gains `IpeRow`)
//! must NOT ALSO gain a spurious `IpeStringify` bound just because a SIBLING
//! concrete `String` param is interpolated in the same body.
//!
//! Why precision matters: the row generic's real obligation is `IpeRow` alone.
//! A gratuitous stringify bound on it would be a bound the param does not need
//! and does not reflect its use — the over-bounding risk a broadened
//! kernel->bound map introduces. This probe asserts the wildcard row generic
//! carries `IpeRow` (its real obligation) but NO `IpeStringify`, and that the
//! whole crate builds and runs end-to-end.
//!
//! Run:
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_display_false_positive
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("display_false_positive")
        .join("Main.ipe")
}

/// ipe-0 ∧ the wildcard row generic carries `IpeRow` but NOT `Display` —
/// checked unconditionally (cheap, no `cargo`).
#[test]
fn i186_false_positive_ipec_no_spurious_display() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i186_display_false_positive_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for display_false_positive: {:?}",
        built.err()
    );

    let emitted = crate::support::read_all_emitted_src(&out);

    // The `grab` fn's wildcard row generic gets `IpeRow` (its real obligation)
    // and must NOT get `Display` (the sibling `String` is what is interpolated).
    let grab_sig = emitted.lines().find(|l| l.contains("fn main_grab"));
    assert!(
        grab_sig.is_some(),
        "emitted user source must declare main_grab; got:\n{emitted}"
    );
    let grab_sig = grab_sig.unwrap_or_default();
    assert!(
        grab_sig.contains("ipe_runtime::db::IpeRow"),
        "the wildcard row generic must carry its real `IpeRow` obligation; got: {grab_sig}"
    );
    assert!(
        !grab_sig.contains("stringify::IpeStringify"),
        "the wildcard row generic must NOT gain a spurious `IpeStringify` bound \
         from a SIBLING `String`'s interpolation — that would be over-bounding; \
         got: {grab_sig}"
    );
}

/// cargo-0 ∧ run-0 — end-to-end proof the precise-bound emit builds and runs.
/// Gated on `IPE_E2E=1`.
#[test]
fn i186_false_positive_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let out = crate::support::scratch_root().join("ipec_i186_display_false_positive_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for display_false_positive: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("display_false_positive", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "display_false_positive binary must cargo-build AND exit 0; got {:?} \
         (stdout: {:?})",
        outcome.exit_code,
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim(),
        "p:v",
        "stdout mismatch; got: {:?}",
        outcome.stdout
    );
}
