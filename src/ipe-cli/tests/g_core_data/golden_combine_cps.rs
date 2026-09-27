//! Soundness regression for the tail-recursive rewrite of `Result.combine` /
//! `Maybe.combine` — collecting a large list runs in CONSTANT native stack, so
//! a well-typed program cannot abort via a Rust stack overflow (guard-page
//! `abort()` → SIGABRT) on a long input.
//!
//! Both combinators walk their input with an accumulator helper and reverse
//! once at the base, a self-tail-recursive shape the backend lowers to a flat
//! `loop { … continue }`. The former recurse-then-cons body ran one frame per
//! element in a non-tail position, so a long input blew the native stack.
//!
//! This golden pins the fix: `Result.combine` and `Maybe.combine` over
//! `500_000` all-success elements each run to a clean exit under a 512 KiB
//! main-thread stack, printing the collected length (`500000`) — proving the
//! collection is value-correct as well as non-crashing. A one-frame-per-element
//! recursion of that depth would SIGABRT (`exit_code == None`) first.
//!
//! Gated on `IPE_E2E=1` (emitted-project cargo build/run), like the other
//! end-to-end goldens. Run: `IPE_E2E=1 cargo test --test g_core_data`.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe` into an emitted Rust project and
/// return its directory. Fails the test loudly on a compile error.
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

/// The soundness proof — `Result.combine` / `Maybe.combine` over `500_000`
/// elements run to a clean exit under a 512 KiB main-thread stack; a
/// one-frame-per-element recursion would SIGABRT (`exit_code == None`) first.
/// The printed lengths (`500000`) confirm the collection is value-correct, not
/// merely non-crashing.
#[test]
fn combine_large_input_runs_to_completion_constant_stack() {
    if !e2e_enabled() {
        return;
    }
    let dir = compile_golden("combine_cps_stack");
    let out = crate::support::build_and_run_stack_limited("combine_cps_stack", &dir, 512);
    assert_eq!(
        out.exit_code,
        Some(0),
        "expected a clean exit under a capped stack (a per-element recursion \
         would SIGABRT → exit_code None); got {:?}",
        out.exit_code
    );
    assert_eq!(out.stdout.trim(), "500000\n500000");
}
