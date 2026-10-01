//! Soundness regression for Limitation #8 — a large `Ipe.List` pipeline
//! runs in CONSTANT native stack, so a well-typed program cannot abort via a
//! Rust stack overflow (guard-page `abort()` → SIGABRT, an unclassifiable
//! process death) on a big list.
//!
//! Backend note (verified against this tree): the List surface that is
//! REACHABLE from a compilable Ipê-Rust program is the kernel subset —
//! `map` / `filter` / `foldl` / `foldr` / `length` / `head` / `tail` / `member`
//! / `range` / `reverse` — and each of those routes to an ITERATIVE Rust
//! runtime kernel over `Vec` (`src/runtime/rust/src/list.rs`), with no
//! per-element recursion. This golden pins that: `range → map → foldr` over
//! `500_000` elements runs to a clean exit under a 512 KiB main-thread stack. A
//! one-frame-per-element recursion of that depth would SIGABRT
//! (`exit_code == None`) long before completing; a constant-stack kernel exits
//! `Some(0)`. It is a standing guard against a future regression that re-routes
//! any reachable List op onto a body-recursive path.
//!
//! The pure-Ipê combinators that WERE naively body-recursive in the non-tail
//! position — `append` / `concat` / `concatMap` / `take` / `zip` /
//! `indexedMap` — carry accumulator/CPS bodies in
//! `crates/ipec/stdlib/Ipe/Core/List.ipe` (byte-identical to upstream
//! `ipe-stdlib/Ipê/Core/List.ipe`). They are CALLABLE, but as
//! ITERATIVE Rust KERNELS (not by routing to those pure-Ipê bodies): canon
//! anchors every `List.x` to `VarHome::Kernel` unconditionally, so the kernel
//! path is the only exit-0-safe wiring (see
//! `docs/adr/0002-codegen-soundness-and-the-seal.md`). Those kernels are constant-
//! stack too — strictly better than the O(N)-stack pure-Ipê recursion the golden
//! backend uses — so the soundness thesis holds by a different mechanism. The
//! pure-Ipe `List.ipe` bodies stay as the (currently unreached) upstream-parity
//! reference for the eventual migration once typed-lambda lowering closes the
//! cross-module `cannot infer T2` hole. Reachable-List E2E coverage now lives in
//! `golden_list_ops_wiring.rs` (all nine ops + Elm edges); this file keeps the
//! capped-stack proof over the pre-existing kernel subset.
//!
//! Gated on `IPE_E2E=1` (emitted-project cargo build/run), like the other
//! end-to-end goldens. Run: `IPE_E2E=1 cargo test --test golden_list_cps`.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
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

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());
    out
}

/// The soundness proof — constant stack over the reachable List surface. A
/// `range → map → foldr` pipeline over `500_000` elements runs to a clean exit
/// under a 512 KiB main-thread stack; a one-frame-per-element recursion would
/// SIGABRT (`exit_code == None`) first. The value (`500000`, an element count)
/// is deterministic and also confirms the pipeline is value-correct, not merely
/// non-crashing.
#[test]
fn list_large_pipeline_runs_to_completion_constant_stack() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = compile_golden("list_cps_stack");
    let out = crate::support::build_and_run_stack_limited("list_cps_stack", &dir, 512);
    assert_eq!(
        out.exit_code,
        Some(0),
        "expected a clean exit under a capped stack (a per-element recursion \
         would SIGABRT → exit_code None); got {:?}",
        out.exit_code
    );
    assert_eq!(out.stdout.trim(), "500000");
}
