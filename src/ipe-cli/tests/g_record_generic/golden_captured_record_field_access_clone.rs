//! A captured-record-into-`Fn`-closure move gap (SEAL).
//!
//! Without the fix, `ipe dev build` exits 0, but the emitted Rust fails `cargo build`
//! with E0507 — "cannot move out of `row`, a captured variable in an `Fn`
//! closure" — when a record is captured into a lambda whose FIRST use of it is a
//! field access and which then also uses the whole record.
//!
//! Root cause: a dotted local access (`row.lineStart`) lexes as one token, and
//! the parser gave the base `VarLocal` AND every `Access` node the SAME span (the
//! whole dotted-token span). The type-region map is keyed by `(module, span)`, so
//! the field's scalar (`Int`) result type overwrote the record type at that key.
//! The lowerer's capture classification looks a captured var's type up by the
//! span of its first use; reading the overwritten `Int`, it classified `row` as a
//! copy leaf and inserted no `CloneVar`, so the emitted `Fn` closure bare-moved
//! the whole record.
//!
//! Fix (`ident_expr` / `parse_field_accessor`, `src/compiler/parse/src/parser.rs`):
//! each node of an access chain gets a DISTINCT sub-span carved from the token's
//! byte range, so the base var's `(module, span)` region entry keeps the record
//! type. The captured record is then classified as clonable and `.clone()`d into
//! the closure.
//!
//! Run:
//! ```text
//! # fast (no cargo):
//! cargo test -p ipe --test g_record_generic captured_record_field_access_clone
//!
//! # full E2E (real `cargo build` of the emitted project — the only check that
//! # would have caught the original SEAL: ipe-0 then E0507):
//! IPE_E2E=1 cargo test -p ipe --test g_record_generic captured_record_field_access_clone
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("captured_record_field_access_clone")
}

fn entry_path(root: &Path) -> PathBuf {
    golden_dir(root).join("Main.ipe")
}

/// ipe-0 + emitted-source assertion (unconditional, cheap — no `cargo`): the
/// compiler must accept the program AND emit the captured record with a
/// `.clone()` inside the closure body rather than a bare move. This directly
/// asserts the E0507 trigger is gone, independent of the `IPE_E2E` gate.
#[test]
fn captured_record_field_access_is_cloned_not_moved() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("captured_record_field_access_clone_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for captured_record_field_access_clone: {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");

    // The captured record must be `.clone()`d into the closure (the invariant
    // that stops the `Fn` closure from moving out of it). Pre-fix the closure
    // captured `row` by bare move → E0507.
    assert!(
        emitted.contains("row.clone()"),
        "the captured record must be `.clone()`d into the closure, not bare-moved; \
         got main.rs:\n{emitted}"
    );
}

/// cargo-0 ∧ run-0: the emitted project actually compiles with `rustc` (no
/// E0507), runs, and prints the expected line. Gated on `IPE_E2E=1` — a real
/// `cargo build`, the only check that would have caught the original SEAL
/// violation (E0507, `ipe dev build` clean).
#[test]
fn captured_record_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let gdir = golden_dir(&root);
    let out = crate::support::scratch_root().join("ipec_captured_record_field_access_clone_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for captured_record_field_access_clone: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("captured_record_field_access_clone", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "captured_record_field_access_clone binary must exit 0 (no E0507); got {:?} \
         (stdout: {:?})",
        outcome.exit_code,
        outcome.stdout
    );

    crate::support::assert_go_parity("captured_record_field_access_clone", &gdir, &outcome.stdout);
}
