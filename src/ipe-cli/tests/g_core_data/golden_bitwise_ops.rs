//! All seven `Ipe.Bitwise` kernels (and / or / xor / complement /
//! shiftLeftBy / shiftRightBy / shiftRightZfBy) are callable from user code
//! and produce the expected bit-level results.
//!
//! Exercises the `interpret_shape` route for the Bitwise kernel scheme family
//! (`tests/golden/bitwise_ops/Main.ipe`), building and running the emitted
//! binary and asserting the stdout line.
//!
//! Gated on `IPE_E2E=1`. Run:
//! `IPE_E2E=1 cargo test -p ipe --test g_core_data bitwise_ops`.

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

#[test]
fn bitwise_ops_run_with_parity() {
    if !e2e_enabled() {
        return;
    }
    let dir = compile_golden("bitwise_ops");
    let out = crate::support::build_and_run_emitted("bitwise_ops", &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "expected a clean exit; got {:?}",
        out.exit_code
    );
    // and(12,10)=8  or(12,10)=14  xor(12,10)=6  complement(0)=-1
    // shiftLeftBy(2,3)=12  shiftRightBy(2,12)=3  shiftRightZfBy(2,12)=3
    assert_eq!(out.stdout.trim(), "8 14 6 -1 12 3 3");
}
