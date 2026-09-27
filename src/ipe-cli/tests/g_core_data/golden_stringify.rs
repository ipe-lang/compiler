//! The STRINGIFY obligation (`Basics.toString : a -> String`, the shared
//! lever for the whole Stringify-bounded family). The argument carries a bounded
//! super-var → Rust `IpeStringify`. A scalar / record / ADT satisfies it; a bare
//! function is rejected AT TYPE-CHECK (fail-closed), never emitting an unbounded
//! `basics_to_string::<T>` that `cargo` would reject — the seal is preserved.
//!
//! Positive case is `IPE_E2E`-gated (build + run). The negative case is a pure
//! ipe compile (no cargo), so it always runs.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

fn compile_golden(name: &str) -> PathBuf {
    let root = repo_root();
    let entry = golden_dir(&root, name).join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else {
        return out;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());
    out
}

fn e2e_enabled() -> bool {
    std::env::var("IPE_E2E").is_ok()
}

/// `toString` on scalars compiles + runs (debug format: bool lowercases).
#[test]
fn tostring_scalars_run() {
    if !e2e_enabled() {
        return;
    }
    let dir = compile_golden("m_tostring");
    let out = crate::support::build_and_run_emitted("m_tostring", &dir);
    assert_eq!(out.exit_code, Some(0), "got {:?}", out.exit_code);
    assert_eq!(out.stdout.trim(), "42 true 3");
}

/// SEAL regression: `toString` on a concrete RECORD and ADT (alongside a scalar)
/// must ipe-accept AND the emitted crate must `cargo build`. Before the fix,
/// `basics_to_string<T: std::fmt::Display>` had no `Display` impl for a
/// record/ADT, so `ipe build` exited 0 but the emitted crate failed `cargo
/// build` with E0277 — an exit-0-then-cargo-fail SEAL breach. Routing the whole
/// stringify family through `IpeStringify` (which every scalar AND every emitted
/// composite implements) closes the class.
///
/// ipe-0 half runs unconditionally (cheap, no cargo); cargo-0 ∧ run-0 half is
/// `IPE_E2E`-gated — the only check that would have caught the original breach.
#[test]
fn tostring_record_and_adt_run() {
    // ipe-0: the compiler must accept `toString` on a record + ADT + scalar.
    let dir = compile_golden("m_tostring_composite");
    if !e2e_enabled() {
        return;
    }
    // cargo-0 ∧ run-0: the emitted crate builds and prints the composites.
    let out = crate::support::build_and_run_emitted("m_tostring_composite", &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "composite-toString crate must cargo-build AND exit 0 (no E0277); got {:?} \
         (stdout: {:?})",
        out.exit_code,
        out.stdout
    );
    // scalar `42`; record `{1 2}` (debug format, `_fieldIndex` order); ADT payload
    // `Circle 5`; ADT nullary `Empty`.
    assert_eq!(out.stdout.trim(), "42 | {1 2} | Circle 5 | Empty");
}

/// `Log.infoWith : String -> List a -> Task Error ()` with Stringify attrs
/// compiles (the obligation on the list element) — a pure ipe compile.
#[test]
fn log_info_with_stringify_attrs_compiles() {
    let root = repo_root();
    let entry = golden_dir(&root, "m_log_with").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m_log_with_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve");
    let Ok(runtime) = runtime else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "Log.infoWith with String attrs must compile: {:?}",
        built.err()
    );
}

/// SEAL-PRESERVING negative gate: `toString` on a FUNCTION is rejected at ipe
/// type-check (the Stringify obligation's `Fun` head-rejection), NOT deferred to
/// a cargo failure. A pure compile — no `IPE_E2E` needed.
#[test]
fn tostring_on_function_is_rejected_at_typecheck() {
    let root = repo_root();
    let entry = golden_dir(&root, "m_tostring_fn_rejected").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m_tostring_fn_rejected_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve");
    let Ok(runtime) = runtime else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_err(),
        "toString on a function MUST fail at ipec type-check (Stringify obligation), \
         not exit 0 and defer to cargo",
    );
}
