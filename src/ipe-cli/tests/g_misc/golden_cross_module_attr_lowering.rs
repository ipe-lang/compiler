//! Regression gate — a LOWERING diagnostic (IPE-L0126, a forwarded fn-value
//! capture) raised in a dependency module must attribute to the module that
//! actually OWNS the failing def, not to a byte-offset collision in another
//! merged module.
//!
//! This is the lowering-pass analogue of `golden_t0012_cross_module_attr`
//! (which covers a post-solve field-access error). In
//! `36-composite-server`, `guarded h = wrap (rateLimit … h)` in `Server.ipe`
//! raises IPE-L0126; if lowering diagnostics carry only a bare, file-local
//! byte `Span` with no owning module, the driver's `source_for_span` heuristic
//! picks whichever merged def numerically CONTAINS that offset with the
//! smallest `lo_dist` — which can be `Main.ipe`'s `runMigrate`
//! (its body starts ~46 bytes before the offset while the real owner
//! `Server.run` starts ~1000 before), so the user sees the phantom
//! `--> Main.ipe:73`.
//!
//! Fix: `ipe_lower::lower` now pairs its diagnostic with the failing def's
//! `home` module path (mirroring `ipe_types::infer_attributed`), threaded
//! through `ipe_db::lower_program` / `emit_manifest`, so the driver resolves
//! the owning source file EXACTLY via `home_to_source`.
//!
//! This fixture is tuned so the failing `Dep.ipe` span sits at a byte offset
//! that the OLD heuristic mis-attributes to `Main.ipe` (its `main` body span
//! numerically contains the offset with a smaller `lo_dist` than the padded
//! `Dep.composed` body). This must render `--> Dep.ipe`, not the `-->
//! Main.ipe:20` the OLD heuristic produces.
//!
//! Run:
//! ```text
//! cargo test -p ipe --test golden_l0126_cross_module_attr
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

/// The IPE-L0126 must blame `Dep.ipe` (which owns the forwarded-capture def),
/// never the byte-colliding `Main.ipe`.
#[test]
fn l0126_lower_error_attributes_to_owning_module() {
    let err = try_build("cross_module_attr_lowering").expect_err("the fixture must be refused");
    assert!(err.contains("IPE-L0126"), "expected IPE-L0126, got:\n{err}");
    assert!(
        err.contains("Dep.ipe"),
        "lowering error must attribute to the owning module Dep.ipe, got:\n{err}"
    );
    assert!(
        !err.contains("Main.ipe"),
        "lowering error must NOT mis-attribute to the byte-colliding Main.ipe, got:\n{err}"
    );
}
