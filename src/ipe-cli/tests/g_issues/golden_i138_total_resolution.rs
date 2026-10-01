//! Regression gate — total type-name resolution.
//!
//! Calling `unwrap_or_default()` in `ipe_canon::canonicalise_type` for any
//! unqualified type name absent from `type_home_map` would give it `home = []`.
//! Genuine builtins (in `RESERVED_BUILTIN_TYPES` / `EXTRA_BUILTIN_TYPE_NAMES`)
//! legitimately carry that empty-home sentinel; the lowerer resolves them by
//! explicit name arm.  Unknown names (user ADTs referenced without importing
//! their module) would also get `home = []`, falling through to the lowerer's
//! unique-match heuristic, which ICEs with IPE-I0001 when zero or multiple
//! matches exist.
//!
//! Resolution is instead TOTAL:
//!   • Unknown unqualified upper-case names → IPE-N0002 (`TypeNotFound`) at
//!     canon time, with a did-you-mean suggestion list.
//!   • Known builtins → empty-home sentinel as before.
//!   • The unique-match heuristic in `ir_type_from_canon` / `ir_type_from_ty`
//!     is removed; an empty-home non-builtin Con now ICEs with a clear message
//!     ("should have been caught by canon `TypeNotFound`") to flag the invariant
//!     violation without obscuring the root cause.
//!
//! Tests:
//!   1. `empty_home_bridge` — `Token` used in annotation, defined in both
//!      `ModA` and `ModB` but not imported as a type → IPE-N0002.
//!   2. `optbridge` — same shape, different payload types → IPE-N0002.
//!   3. `kernel_implicit_positive` — `Request` used without explicit import;
//!      it is in `RESERVED_BUILTIN_TYPES`, so the fix must NOT reject it → exit 0.
//!
//! Run:
//! ```text
//! cargo test -p ipe --test golden_i138_total_resolution
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

// ---------------------------------------------------------------------------
// Helper: compile a golden fixture, return the error string on failure.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Error cases — must fail closed with IPE-N0002
// ---------------------------------------------------------------------------

/// `Token` used in an annotation but never imported as a type; both `ModA` and
/// `ModB` define their own `Token` ADT.  The ambiguity must surface as
/// IPE-N0002, not an ICE.
#[test]
fn i138_empty_home_bridge_fails_n0002() {
    let err = try_build("empty_home_bridge")
        .expect_err("empty_home_bridge must fail (Token is not in scope)");
    assert!(err.contains("IPE-N0002"), "expected IPE-N0002, got:\n{err}");
    assert!(
        !err.contains("IPE-I0001"),
        "must NOT be an ICE (IPE-I0001), got:\n{err}"
    );
}

/// Same shape as `empty_home_bridge` but with different payload types — a
/// separate repro that caught a distinct ICE path in the original heuristic.
#[test]
fn i138_optbridge_fails_n0002() {
    let err = try_build("optbridge").expect_err("optbridge must fail (Token is not in scope)");
    assert!(err.contains("IPE-N0002"), "expected IPE-N0002, got:\n{err}");
    assert!(
        !err.contains("IPE-I0001"),
        "must NOT be an ICE (IPE-I0001), got:\n{err}"
    );
}

// ---------------------------------------------------------------------------
// Positive control — kernel-implicit builtin must still compile
// ---------------------------------------------------------------------------

/// `Request` is in `RESERVED_BUILTIN_TYPES` and receives the empty-home
/// sentinel regardless of whether the user explicitly imports
/// `Ipe.Http.Server`.  The `TypeNotFound` gate must NOT reject it.
#[test]
fn i138_kernel_implicit_positive_exits_zero() {
    try_build("kernel_implicit_positive")
        .expect("kernel_implicit_positive must compile (Request is a kernel builtin)");
}

/// `Value` is a kernel-implicit Prelude type that was missing from all
/// three builtin allowlists (`RESERVED_BUILTIN_TYPES`, `EXTRA_BUILTIN_TYPE_NAMES`,
/// `KERNEL_IMPLICIT_BUILTIN_TYPE_NAMES` — newly added by the fix).
/// After the fix it must receive the empty-home sentinel and compile clean.
/// The lowerer handles `Value` via an explicit arm (`IrType::Json`) placed
/// after the `enum_variants` guard.
#[test]
fn i138_kernel_implicit_value_exits_zero() {
    try_build("kernel_implicit_value")
        .expect("kernel_implicit_value must compile (Value is a kernel-implicit Prelude type)");
}
