//! Refutable match-arm `as`-alias over a non-Copy payload.
//!
//! GREEN side: `Just ((a, b) as w)` over `Maybe (String, String)` must not
//! emit `Just(w @ (a, b))` in a by-value arm — a Rust partial move (E0382)
//! the moment the arm body reads `w` after `a`/`b` (ipe exit 0, cargo
//! exit 101: the exact exit-0-then-cargo-fail seal class). Instead it binds
//! the whole payload once and re-derives the inner bindings from a clone
//! (the same strategy, extended to by-value match arms).
//!
//! RED side: an alias over a dispatch-NEEDING inner (`(Just x) as inner`
//! nested in a ctor payload) is IPE-L0128 fail-closed — the clone-rebuild
//! repair is only sound for dispatch-free inners.
//!
//! Spec: `docs/adr/0002-codegen-soundness-and-the-seal.md` §1.
//!
//! Run: `IPE_E2E=1 cargo test golden_i99`

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// The alias-over-dispatch-free-tuple shape must be ipe-0 (the lowering-side
/// path accepts it) — cheap tier, always runs.
#[test]
fn i99_alias_tuple_match_arm_is_ipec_ok() {
    let root = repo_root();
    let entry = golden_dir(&root, "alias_tuple_match_arm").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i99_alias_tuple_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "#99: alias over a dispatch-free tuple in a match arm must be ipe-0: {:?}",
        built.err()
    );
}

/// `IPE_E2E` tier: the emitted project must cargo-build AND run with the
/// arm body reading `a`, `b`, AND `w` — proving the E0382 partial move is
/// gone and the values are correct (not just "compiles").
#[test]
fn i99_alias_tuple_match_arm_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let entry = golden_dir(&root, "alias_tuple_match_arm").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i99_alias_tuple_e2e_run");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("alias_tuple_match_arm", &out);
    assert_eq!(outcome.exit_code, Some(0), "must run clean");
    assert_eq!(
        outcome.stdout.trim(),
        "hello|world|hello-world",
        "arm body must read a, b, AND the alias binder w correctly"
    );
}

/// Self-edge case: an `as`-alias over a
/// CYCLIC self-edge (recursive) ctor field is boxed in the emitted enum, so
/// the clone-rebuild re-derivation must unbox the temp — otherwise both the
/// alias binder and the inner binder stay `Box<Tree>` (ipe-0, cargo-E0308).
#[test]
fn i99_alias_over_self_edge_is_ipec_ok() {
    let root = repo_root();
    let entry = golden_dir(&root, "alias_self_edge").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i99_self_edge_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "#99: alias over a cyclic self-edge field must be ipe-0: {:?}",
        built.err()
    );
}

/// `IPE_E2E` tier: the emitted self-edge project must cargo-build AND run
/// with the arm body reading BOTH the recursed value (`child`) and the
/// aliased whole (`w`) — proving the E0308 box mismatch is gone.
#[test]
fn i99_alias_over_self_edge_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let entry = golden_dir(&root, "alias_self_edge").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i99_self_edge_e2e_run");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("alias_self_edge", &out);
    assert_eq!(outcome.exit_code, Some(0), "must run clean");
    assert_eq!(
        outcome.stdout.trim(),
        "11",
        "self-edge arm must read child + w correctly (1 + 5 + 5 = 11)"
    );
}

/// RED-side control: an alias over a dispatch-NEEDING inner (`Just x`) in a
/// by-value ctor payload is a clean IPE-L0128 lowering rejection — never a
/// ipe-accept-then-cargo-fail, and never silently over-broad (the GREEN
/// fixture above proves the dispatch-free shape still passes).
#[test]
fn i99_alias_over_ctor_inner_is_ipe_l0128() {
    let root = repo_root();
    let entry = golden_dir(&root, "alias_ctor_rejected").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i99_alias_ctor_rejected");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    let err = built.expect_err("#99: alias over a dispatch-needing inner must be rejected");
    let rendered = format!("{err:?}");
    assert!(
        rendered.contains("AliasOverRefutablePayload") || rendered.contains("IPE-L0128"),
        "rejection must be the IPE-L0128 gate, got: {rendered}"
    );
    assert!(
        !out.join("src").join("main.rs").exists(),
        "no Rust may be emitted on a rejection"
    );
}
