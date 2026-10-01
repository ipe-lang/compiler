//! Function values in record fields — the `SharedFun` carrier under carrier
//! normalization (Phase 1).
//!
//! A record whose fields include function values carries those slots on the
//! `Clone` `Arc<dyn Fn>` carrier ([`ipe_ir::IrType::SharedFun`]) — always, as a
//! total function of the record's shape. The whole struct then gets a
//! hand-written `Clone`, so the N-1 last-use clone rewrite makes it move-safe.
//! The record is storable regardless of whether it escapes; a record that also
//! carries a non-`Clone` field (`Task`) still fails closed on reuse.
//!
//! | Fixture | Shape | Outcome |
//! |---|---|---|
//! | `fn_record_reuse_promoted` | record of two functions + data, reused | stored; builds + prints `len: 8` |
//! | `fn_record_reuse_escapes` | that record RETURNED from a function | stored; builds + prints `12` |
//! | `fn_record_reuse_mixed` | fn field + `Task` field, reused | fail-closed IPE-L0127 (not whole-clonable) |
//!
//! Carrier normalization (Phase 1) makes a function in a record field always the
//! `Arc<dyn Fn>` carrier — a total function of the record's shape, not a
//! containment-gated promotion. So the escaping record (returned from `mk`) now
//! stores and reuses soundly: every occurrence of its shape agrees on `Arc` by
//! construction, with no frontier a `Box`-carried sibling could reach. The mixed
//! record still fails closed — its `Task` field is not `Clone`, so the whole
//! record cannot be, independent of the fn-slot carrier.
//!
//! A `Send`-not-`Sync` capture control is covered by the carrier-transparency
//! argument, not a distinct fixture: the emitted `Box`/`Arc` carrier already
//! bounds every captured free variable `Send + Sync + 'static`, so a
//! `Send`-not-`Sync` capture is rejected by rustc on the closure upstream of the
//! carrier choice, identically before and after the `Box`->`Arc` swap.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn entry_of(root: &Path, name: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe")
}

fn assert_byte_identical(name: &str) {
    let root = repo_root();
    let entry = entry_of(&root, name);
    let golden = root.join("tests").join("golden").join(name).join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_emit"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

fn assert_e2e_prints(name: &str, want_stdout: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let entry = entry_of(&root, name);
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.stdout, want_stdout,
        "promoted record prints its value"
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0 (THE SEAL)");
}

/// Build the named fixture and assert it fails closed with exactly `expected` —
/// a typed `ipe`-time diagnostic, never a panic and never an accept that would
/// defer to a raw rustc error.
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
fn record_of_functions_reuse_emits_byte_identical_main_rs() {
    assert_byte_identical("fn_record_reuse_promoted");
}

#[test]
fn record_of_functions_reuse_end_to_end() {
    assert_e2e_prints("fn_record_reuse_promoted", "len: 8\n");
}

#[test]
fn escaping_record_of_functions_builds() {
    // The record is returned from `mk`. Under carrier normalization its fn field
    // is the `Arc<dyn Fn>` carrier at every occurrence, so the escaping value
    // stores and reuses soundly — builds where it once failed closed (IPE-L0107).
    let root = repo_root();
    let entry = entry_of(&root, "fn_record_reuse_escapes");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fn_record_reuse_escapes_build");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "escaping record must build: {:?}",
        built.err()
    );
}

#[test]
fn escaping_record_of_functions_end_to_end() {
    // `useMk (mk 3)` = `c.f c.n + c.f c.n` = `(3+3)+(3+3)` = `12`.
    assert_e2e_prints("fn_record_reuse_escapes", "12\n");
}

#[test]
fn mixed_composite_reuse_stays_fail_closed() {
    // The `Task` field keeps the record non-`Clone` even after the fn-slot flip,
    // so reuse cannot be made move-safe: fail closed (IPE-L0127).
    assert_fail_closed("fn_record_reuse_mixed", ipe_diagnostics::IPE_L0127);
}
