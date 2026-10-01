//! Regression gate — a LOCAL `type X` shadowing a dep-imported `X` must be
//! rejected AT THE DECLARATION with a clean IPE-N0012 (`DuplicateType`), not a
//! confusing downstream IPE-T0001 type mismatch three functions later.
//!
//! Root cause (see `docs/adr/0002-codegen-soundness-and-the-seal.md`,
//! item D): `canonicalise_with_env`'s `type_home_map.entry(..).or_insert_with(..)`
//! loop was a silent no-op when a dep import (`inject_dep_exports`) had already
//! registered a `Color` entry, so `type_home_map["Color"]` kept pointing at the
//! dep's home while the LOCAL union's ctors (`Warm`/`Cool`) were registered into
//! the environment. The `Color` annotation on `describe` then resolved to
//! `Dep.Color` while the case-arm ctors were `Main.Color`, surfacing as an
//! ordinary IPE-T0001 with no hint of the shadow.
//!
//! The fix adds a standalone pre-pass in `canonicalise_with_env` that mirrors
//! `inject_dep_type`'s existing dep-vs-dep clash check EXACTLY, closing the
//! asymmetry for the local-vs-dep case (both unions and aliases).
//!
//! This test only checks that `ipe::build` fails with IPE-N0012 (does NOT build
//! or run the emitted Rust project; does NOT require `IPE_E2E`).
//!
//! Run:
//! ```text
//! cargo test -p ipe --test golden_m102_local_type_shadows_dep
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

fn try_build(name: &str) -> Result<(), String> {
    let root = repo_root();
    let entry = golden_dir(&root, name).join("src").join("Main.ipe");
    if !entry.exists() {
        return Err(format!("fixture not found: {}", entry.display()));
    }
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_ipec_out"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build_loose_file(&entry, &out, &runtime).map_err(|e| e.to_string())
}

/// The exact two-module repro from item D — `Main` declares `type Color`
/// locally after `import Dep exposing (Color(..))`.  Must fail closed with
/// IPE-N0012 at the local declaration, NOT a downstream IPE-T0001.
#[test]
fn m102_local_type_shadows_dep_fails_n0012() {
    let err = try_build("local_type_shadows_dep").expect_err(
        "local_type_shadows_dep must fail (local `type Color` shadows the imported Dep.Color)",
    );
    assert!(
        err.contains("IPE-N0012"),
        "expected IPE-N0012 (DuplicateType) at the shadowing declaration, got:\n{err}"
    );
    assert!(
        !err.contains("IPE-T0001"),
        "must NOT surface as a downstream IPE-T0001 type mismatch, got:\n{err}"
    );
}
