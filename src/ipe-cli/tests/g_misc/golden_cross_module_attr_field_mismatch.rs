//! Regression gate: a field-type mismatch (IPE-T0001) raised while resolving a
//! deferred field access must be framed against the module that OWNS the
//! access, never against a module whose bytes happen to collide.
//!
//! Every linked module shares one byte-offset space, so a span alone cannot
//! name its file. The type checker sites the error at the access's module, and
//! the driver frames it from that home. The fixture places the failing
//! `Dep.ipe` access at an offset that `Main.ipe`'s `main` body also covers with
//! a smaller distance from its start, so a byte-offset guess would pick
//! `Main.ipe`.
//!
//! Run:
//! ```text
//! cargo test -p ipe --test g_misc golden_cross_module_attr_field_mismatch
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn try_build(name: &str) -> Result<(), String> {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join(name)
        .join("src")
        .join("Main.ipe");
    if !entry.exists() {
        return Err(format!("fixture not found: {}", entry.display()));
    }
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_ipec_out"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build_loose_file(&entry, &out, &runtime).map_err(|e| e.to_string())
}

/// The IPE-T0001 must blame `Dep.ipe` (which owns `rec.present`), never the
/// byte-colliding `Main.ipe` nor an embedded stdlib module.
#[test]
fn field_mismatch_attributes_to_owning_module() {
    let err =
        try_build("cross_module_attr_field_mismatch").expect_err("the fixture must be refused");
    assert!(err.contains("IPE-T0001"), "expected IPE-T0001, got:\n{err}");
    assert!(
        err.contains("Dep.ipe:"),
        "the mismatch must be framed against the owning module Dep.ipe, got:\n{err}"
    );
    assert!(
        !err.contains("Main.ipe"),
        "the mismatch must NOT be framed against the byte-colliding Main.ipe, got:\n{err}"
    );
    assert!(
        !err.contains("<embedded-stdlib>"),
        "the mismatch must NOT be framed against a stdlib module, got:\n{err}"
    );
}
