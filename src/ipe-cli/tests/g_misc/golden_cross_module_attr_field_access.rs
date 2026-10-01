//! Regression gate — a post-solve field-access error (IPE-T0012) must attribute
//! to the module that actually OWNS the access, not to a byte-offset collision
//! in another merged module.
//!
//! Historical context (12-ipevote): `info.message` in `Lib/AuthHandlers.ipe`
//! failed to resolve (parked `Error`/`ErrorInfo` ADT leaves `info` a flex
//! record). The deferred field-access pass (`resolve_deferred`) returned the
//! diagnostic with an *empty* home, so the driver fell back to `source_for_span`
//! — the byte-offset heuristic — which picked a numerically-closer `class` call
//! in an unrelated `Page/Roadmap.ipe` def. The user saw
//! "`class` … has no field `message`" pointing at code that has nothing to do
//! with the failing access.
//!
//! Fix: `FieldAccess` / `RecordUpdate` now carry their def's `home` module path,
//! and `resolve_deferred` returns it alongside the diagnostic so
//! `infer_attributed` maps the error to the correct source file exactly, the
//! same way solver errors already do.
//!
//! This fixture is tuned so the failing `Dep.ipe` access sits at a byte offset
//! that the old heuristic mis-attributes to `Main.ipe` (its `main` body span
//! numerically contains the offset with a smaller `lo_dist` than `Dep`'s `bad`
//! body). This must render `--> Dep.ipe:14`, not the `--> Main.ipe:9` the old
//! heuristic produces.
//!
//! Run:
//! ```text
//! cargo test -p ipe --test golden_t0012_cross_module_attr
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

/// The IPE-T0012 must blame `Dep.ipe` (which owns `rec.missing`), never the
/// byte-colliding `Main.ipe`.
#[test]
fn t0012_field_error_attributes_to_owning_module() {
    let err = try_build("cross_module_attr_field_access").expect_err("the fixture must be refused");
    assert!(err.contains("IPE-T0012"), "expected IPE-T0012, got:\n{err}");
    assert!(
        err.contains("Dep.ipe:14"),
        "field error must attribute to the owning module Dep.ipe:14, got:\n{err}"
    );
    assert!(
        !err.contains("Main.ipe"),
        "field error must NOT mis-attribute to the byte-colliding Main.ipe, got:\n{err}"
    );
}
