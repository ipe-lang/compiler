//! A value becomes text through its own show row, with no `Debug` fallback.
//!
//! `show_policy_every_leaf` shows one value of each constructible leaf the
//! old fallback printed through `Debug` (`Char`, `Set`, `Bytes`, `Regex`,
//! `Dsn`, `Task`), directly and inside a record and an enum: `ipe` accepts
//! it, and under `IPE_E2E=1` the emitted crate builds and runs, rendering each
//! `Redacted` leaf as its marker and never the DSN password.
//!
//! `show_refused_foreign` shows an opaque `Rust.*` handle, which has no show
//! row: `ipe` refuses it with IPE-T0014 before any Rust is emitted.

use std::path::{Path, PathBuf};

use crate::golden_ffi_nonclone_handle_reuse_seal::write_project;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_entry(root: &Path, name: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe")
}

/// The DSN password sentinel `show_policy_every_leaf` parses.
const DSN_PASSWORD: &str = "hunter2SENTINEL";

/// Builds the every-leaf fixture, refusing the test when `ipe` rejects it.
fn build_every_leaf() -> PathBuf {
    let entry = golden_entry(&repo_root(), "show_policy_every_leaf");
    let out = crate::support::scratch_root().join("ipec_show_policy_every_leaf");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "showing every constructible leaf must compile: {:?}",
        built.err()
    );
    out
}

#[test]
fn every_shown_leaf_is_accepted() {
    build_every_leaf();
}

#[test]
fn every_shown_leaf_renders_through_its_row() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let out = build_every_leaf();
    let outcome = crate::support::build_and_run_emitted("show_policy_every_leaf", &out);
    assert_eq!(outcome.exit_code, Some(0), "{}", outcome.stdout);
    let stdout = outcome.stdout;
    for line in [
        "bytes: <5 bytes>",
        "task: <Ipe.Task.Task>",
        "holds bytes: HoldsBytes <5 bytes>",
        "regex: <redacted>",
        "holds regex: HoldsRegex <redacted>",
        "dsn: <redacted>",
        "holds dsn: HoldsDsn <redacted>",
    ] {
        assert!(
            stdout.lines().any(|l| l == line),
            "missing line {line:?} in:\n{stdout}"
        );
    }
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with("record: ") && l.contains("<5 bytes>")),
        "a record renders its Bytes field through the Bytes row:\n{stdout}"
    );
    assert!(
        !stdout.contains(DSN_PASSWORD),
        "the DSN password reached the output:\n{stdout}"
    );
}

#[test]
#[allow(clippy::panic)] // a refused precondition is the test failure
fn showing_a_rust_handle_is_refused_before_cargo() {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let source = golden_entry(&repo_root(), "show_refused_foreign");
    let main = std::fs::read_to_string(&source)
        .unwrap_or_else(|e| panic!("read {}: {e}", source.display()));
    let tmp = crate::support::scratch_root().join("ipec_show_refused_foreign");
    assert!(
        write_project(&tmp, &main),
        "must write the fixture project + FFI cache to a temp dir"
    );
    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("show_refused_foreign_out");
    let _ = std::fs::remove_dir_all(&out);
    let Err(err) = ipe::build_loose_file(&entry, &out, &runtime) else {
        panic!("showing a `Rust.*` handle must be refused, but ipe accepted it")
    };
    let ipe::CliError::Pipeline { diag, .. } = &err else {
        panic!("expected a Pipeline diagnostic, got: {err}")
    };
    assert_eq!(
        diag.code().as_str(),
        "IPE-T0014",
        "showing a `Rust.*` handle must fail closed with IPE-T0014, got: {err}"
    );
}
