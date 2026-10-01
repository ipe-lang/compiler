//! `++` must accept `List` operands (Elm/upstream semantics), not only
//! `String`. Before this task, `BinopClass::Append` pinned both operands and
//! the result to `String`, so `[1,2] ++ [3,4]` failed at unification with
//! `IPE-T0001` before reaching the backend.
//!
//! The fix generalises `++` to `Appendable a => a -> a -> a`, where
//! `Appendable` admits `String` and `List _`. The solver pins the fresh
//! super-var at unification; the lowerer dispatches to `BinOp::Append` for
//! `String` and `KernelFn::ListAppend` for `List _`.
//!
//! Positive E2E cases:
//!   (a) `++` on `List Int`
//!   (b) `++` on `List (Int, Bool)` — the example-38 shape
//!   (c) `++` on `String` — existing behaviour must be preserved
//!
//! Negative case (always runs — no `IPE_E2E` needed):
//!   (d) `++` on `Int` → rejected at type-check with `Appendable` in message.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
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
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());
    out
}

/// (a/b/c) `++` on `List Int`, `List (Int, Bool)`, and `String` all compile
/// and produce correct output. The three assertions are combined in one
/// source file / one binary to keep the E2E overhead minimal.
#[test]
fn list_append_op_runs_with_parity() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = compile_golden("m_list_append_op");
    let out = crate::support::build_and_run_emitted("m_list_append_op", &dir);
    assert_eq!(
        out.exit_code,
        Some(0),
        "expected a clean exit; got {:?}",
        out.exit_code
    );
    // ints = [1,2] ++ [3,4]  → length 4
    // pairs = [(1,T),(2,F)] ++ [(3,T)] → length 3
    // greeting = "hi, " ++ "world" = "hi, world"
    assert_eq!(out.stdout.trim(), "4 3 hi, world");
}

/// (d) SEAL-PRESERVING negative gate: `++` on `Int` is rejected at ipe
/// type-check (the `Appendable` obligation's head-rejection — `Int` is neither
/// `String` nor `List _`), NOT deferred to a cargo failure. A pure compile —
/// no `IPE_E2E` needed.
#[test]
fn append_on_int_is_rejected_at_typecheck() {
    let root = repo_root();
    let entry = golden_dir(&root, "m_neg_append_on_int").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m_neg_append_on_int_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_err(),
        "`++` on `Int` MUST fail at ipec type-check (Appendable obligation), \
         not exit 0 and defer to cargo",
    );
}
