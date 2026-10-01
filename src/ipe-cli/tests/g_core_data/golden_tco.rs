//! Tail-call optimization end-to-end regressions.
//!
//! The soundness proof: a deep self-tail-recursive Ipê function runs to
//! completion under a CAPPED main-thread stack (`tco_count`, 2,000,000 iters at
//! 512 KiB). Without TCO the same fixture SIGABRTs (`exit_code == None`) because
//! a Rust stack overflow trips the guard page and `abort()`s — NOT a catchable
//! panic, so the panic classifier never runs. TCO rewrites the body to a flat
//! `loop { … continue }`, keeping the stack constant.
//!
//! TCO is value-preserving, not merely non-crashing: every regression pairs a
//! value assertion (and the parity fixtures also byte-diff the golden oracle).
//!
//! Every test is gated on `IPE_E2E=1`; without it the test returns early. Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_tco
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe` into an emitted Rust project and return
/// its directory. Fails the test loudly on a compile error.
///
/// `scratch` names a per-CALLER scratch directory: several tests exercise the same
/// golden `name` (constant-stack vs oracle-parity), and a shared emit path would
/// let one test's start-of-run teardown wipe a sibling's live build under
/// nextest's parallelism. A distinct `scratch` per test keeps each emit isolated.
fn compile_golden(name: &str, scratch: &str) -> PathBuf {
    let root = repo_root();
    let entry = golden_dir(&root, name).join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{scratch}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());
    out
}

/// The soundness proof — constant stack. 2,000,000 self-tail-recursive iterations
/// run to a clean exit under a 512 KiB main-thread stack; a non-TCO recursion
/// would SIGABRT (`exit_code == None`) long before completing.
#[test]
fn tco_count_runs_to_completion_constant_stack() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = compile_golden("tco_count", "tco_count_stack");
    let out = crate::support::build_and_run_stack_limited("tco_count", &dir, 512);
    assert_eq!(
        out.exit_code,
        Some(0),
        "expected a clean exit under a capped stack (a non-TCO recursion would \
         SIGABRT → exit_code None); got {:?}",
        out.exit_code
    );
    assert_eq!(out.stdout.trim(), "2000000");
}

/// Arg-swap foreclosure. With 3 list elements the params swap an odd number of
/// times → `2,1`. A naive sequential (non-temporaries-first) reassignment would
/// clobber and print `1,1` (or `2,2`).
#[test]
fn tco_arg_swap_uses_temporaries_first() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = compile_golden("tco_swap", "tco_swap_temporaries");
    let out = crate::support::build_and_run_emitted("tco_swap", &dir);
    assert_eq!(out.exit_code, Some(0));
    assert_eq!(out.stdout.trim(), "2,1", "clobber would give 1,1 or 2,2");
}

/// Value-param double-use. Both jump args (`a + b` and `a`) read the CURRENT `a`;
/// temporaries-first reads each against the current params before any write.
/// `go 5 1 0` ⇒ 13 (see the fixture trace).
#[test]
fn tco_value_param_double_use_compiles_and_computes() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = compile_golden("tco_double_use", "tco_double_use_compute");
    let out = crate::support::build_and_run_emitted("tco_double_use", &dir);
    assert_eq!(out.exit_code, Some(0));
    assert_eq!(out.stdout.trim(), "13");
}

// ── golden-verified byte-diff — proves TCO is value-preserving, not just non-crashing ──

/// `tco_count_small` (`count 1000 0` → `1000`) matches the cached golden oracle. The
/// 2,000,000-iter run is reserved for the constant-stack proof above; a small N
/// keeps the golden oracle fast.
#[test]
fn tco_count_small_matches_go_oracle() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let dir = compile_golden("tco_count_small", "tco_count_small_oracle");
    let out = crate::support::build_and_run_emitted("tco_count_small", &dir);
    assert_eq!(out.exit_code, Some(0));
    crate::support::assert_go_parity(
        "tco_count_small",
        &golden_dir(&root, "tco_count_small"),
        &out.stdout,
    );
}

/// `tco_swap` matches the cached golden oracle.
#[test]
fn tco_swap_matches_go_oracle() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let dir = compile_golden("tco_swap", "tco_swap_oracle");
    let out = crate::support::build_and_run_emitted("tco_swap", &dir);
    assert_eq!(out.exit_code, Some(0));
    crate::support::assert_go_parity("tco_swap", &golden_dir(&root, "tco_swap"), &out.stdout);
}

/// `tco_double_use` matches the cached golden oracle.
#[test]
fn tco_double_use_matches_go_oracle() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let dir = compile_golden("tco_double_use", "tco_double_use_oracle");
    let out = crate::support::build_and_run_emitted("tco_double_use", &dir);
    assert_eq!(out.exit_code, Some(0));
    crate::support::assert_go_parity(
        "tco_double_use",
        &golden_dir(&root, "tco_double_use"),
        &out.stdout,
    );
}
