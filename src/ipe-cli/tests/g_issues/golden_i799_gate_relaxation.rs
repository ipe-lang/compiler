//! Narrowing L0126/L0127 against the `Decoder` / `SharedFun` carriers.
//!
//! Three leaf carrier-predicate corrections open exactly the sound
//! composite-builder captures the shipped carriers already serve, while every
//! genuinely non-`Clone` capture stays fail-closed:
//!
//! * a bare `Decoder a` is `Clone` (the runtime `Decoder<E, T>` is an
//!   `Arc`-backed carrier with an unconditional `Clone`), so a record carrying
//!   one is `Clone` and may be captured into a closure and the closure reused
//!   (`decoder_record_capture`).
//! * a bare `Generic` value captured into a closure clones under the emitted
//!   `T: Clone` bound, so an `enum`-name lookup that closes a `find`/`filter`
//!   predicate over a generic value type-checks (`codec_enum_generic_capture`).
//!
//! The boundary stays closed: a record carrying a `Task` (no `Clone` carrier)
//! captured through a closure still rejects `IPE-L0126`
//! (`task_record_capture_gated`).
//!
//! The load-bearing proof for the admitted cases is THE SEAL: under `IPE_E2E=1`
//! the emitted crate must `cargo build`, run, and exit 0 — before these
//! corrections both were `ipe`-reject `IPE-L0126`.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn entry_of(root: &Path, name: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe")
}

/// Emit gate + byte-identity golden for a newly-admitted case: the frontend must
/// accept the capture and re-emit the checked-in `main.rs` byte-for-byte. The
/// `cargo`-time soundness this covers is invisible to an accept-only check — see
/// the E2E test for THE SEAL proof.
fn assert_byte_identical(name: &str) {
    let root = repo_root();
    let entry = entry_of(&root, name);
    let golden = root.join("tests").join("golden").join(name).join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_emit"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a sound composite-builder capture must be accepted + emitted, got: {built:?}"
    );

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// THE SEAL for a newly-admitted case: under `IPE_E2E=1`, actually `cargo build`
/// and run the emitted crate, asserting the round-trip output.
fn assert_builds_and_runs(name: &str) {
    let root = repo_root();
    let entry = entry_of(&root, name);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{name} must be accepted, got: {built:?}");

    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{name}: emitted crate must build and exit 0 — a sound capture must not be \
         `ipe`-accept-then-`cargo`-fail; stdout:\n{}",
        outcome.stdout
    );
    let dir = root.join("tests").join("golden").join(name);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
}

/// A still-non-`Clone` capture must fail closed with `expected` at `ipe` time.
fn assert_fail_closed(name: &str, expected: ipe_diagnostics::Code) {
    let root = repo_root();
    let entry = entry_of(&root, name);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_gate"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    let got = match &built {
        Err(ipe::CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(expected),
        "fixture {name}: expected {expected:?}, got build result {built:?}"
    );
}

#[test]
fn decoder_record_capture_emits_byte_identical() {
    assert_byte_identical("decoder_record_capture");
}

#[test]
fn decoder_record_capture_builds_and_runs() {
    assert_builds_and_runs("decoder_record_capture");
}

#[test]
fn codec_enum_generic_capture_emits_byte_identical() {
    assert_byte_identical("codec_enum_generic_capture");
}

#[test]
fn codec_enum_generic_capture_builds_and_runs() {
    assert_builds_and_runs("codec_enum_generic_capture");
}

#[test]
fn task_record_capture_stays_gated() {
    assert_fail_closed("task_record_capture_gated", ipe_diagnostics::IPE_L0126);
}
