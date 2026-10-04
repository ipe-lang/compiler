//! A reused-by-value generic param clone gap (SEAL).
//!
//! Without the fix, `ipe dev build` exits 0, but the emitted Rust fails `cargo build` with
//! E0382 (`use of moved value: x`) in the body of a function whose only generic
//! is used MORE THAN ONCE in a by-value consuming position:
//! `dup x = """{{x}}{{x}}"""` emits `interpolate_to_string(x)` TWICE with no
//! intervening `.clone()`, moving `x` on the first call.
//!
//! Root cause: `clone_class(IrType::Generic(_))` returned `NonClone`
//! (`crates/ipe_lower/src/lower.rs`), so the T5 multi-use-clone param pass
//! (which fires only for `CloneOk`) skipped generic params, while
//! `reject_fn_value_reuse` is a no-op for a bare `Generic`
//! (`ir_contains_fun(Generic) == false`) — so a reused generic silently moved
//! twice.
//!
//! Fix (`param_is_multiuse_clonable`, `crates/ipe_lower/src/lower.rs`): the two
//! T5 param loops (Typed + Untyped def arms) treat a reused bare
//! `IrType::Generic(_)` param as clonable, inserting `.clone()` on all-but-last
//! use. Sound because `render_fn_generics` (`ipe_backend_rust`) stamps
//! `T: Clone` on EVERY emitted generic fn type-param unconditionally — that
//! `T: Clone` bound is the gate: a non-`Clone` instantiation fails the bound at
//! the CALLER before the inserted `.clone()` is ever reached, so no unsoundness
//! (over-cloning is the only downside). Single source of truth: that predicate
//! and `render_fn_generics`' `with_clone()` emission must agree.
//!
//! Run:
//! ```text
//! # fast (no cargo):
//! cargo test -p ipe --test golden_i189_reused_generic_clone
//!
//! # full E2E (real `cargo build` of the emitted project — the only check that
//! # would have caught the original SEAL: ipe-0 then E0382):
//! IPE_E2E=1 cargo test -p ipe --test golden_i189_reused_generic_clone
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("reused_generic_clone")
}

fn entry_path(root: &Path) -> PathBuf {
    golden_dir(root).join("Main.ipe")
}

/// ipe-0 + emitted-source assertion (unconditional, cheap — no `cargo`): the
/// compiler must accept the program AND emit the reused generic param with a
/// `Clone` bound plus a `.clone()` on the non-final use. This directly asserts
/// the E0382 trigger is gone, independent of the `IPE_E2E` gate.
#[test]
fn i189_ipec_accepts_and_clones_reused_generic() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i189_reused_generic_clone_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for reused_generic_clone: {:?}",
        built.err()
    );

    let emitted = crate::support::read_all_emitted_src(&out);

    // The reused generic param `x` must carry a `Clone` bound (the invariant
    // that makes the inserted `.clone()` type-check).
    let sig_line = emitted.lines().find(|l| l.contains("fn main_dup<"));
    assert!(
        sig_line.is_some(),
        "emitted user source must define `main_dup`; got:\n{emitted}"
    );
    let sig_line = sig_line.unwrap_or_default();
    assert!(
        sig_line.contains("Clone"),
        "the reused generic param must carry a `Clone` bound (#189); got: {sig_line}"
    );

    // The T5 rewrite must insert `.clone()` on the non-final use — the emitted
    // body applies `interpolate_to_string` to `x.clone()` (first use) and then
    // `x` (last use). Without the fix both were bare `interpolate_to_string(x)`
    // → E0382.
    assert!(
        emitted.contains("interpolate_to_string(x.clone())"),
        "the reused generic param must be `.clone()`d on its non-final use \
         (#189); got emitted user source:\n{emitted}"
    );
}

/// cargo-0 ∧ run-0 ∧ golden-verified: the emitted project actually compiles with
/// `rustc` (no E0382), prints the two instantiations, and its stdout matches the
/// cached golden oracle. Gated on `IPE_E2E=1` — a real `cargo build`, the only check
/// that would have caught the original SEAL violation (E0382, `ipe dev build`
/// clean).
#[test]
fn i189_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let gdir = golden_dir(&root);
    let out = crate::support::scratch_root().join("ipec_i189_reused_generic_clone_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for reused_generic_clone: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("reused_generic_clone", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "reused_generic_clone binary must exit 0 (no E0382); got {:?} (stdout: {:?})",
        outcome.exit_code,
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim(),
        "4242hihi",
        "must print both generic instantiations (Int `dup 42` = 4242, String \
         `dup \"hi\"` = hihi) through the reused-then-cloned generic param; got: {:?}",
        outcome.stdout
    );

    // Cached-oracle parity: ipe's stdout must byte-match the golden's
    // refresh-oracle-generated `expected_go.txt` (staleness gate re-hashes
    // Main.ipe first; a hand-edited oracle.meta hard-fails here).
    crate::support::assert_go_parity("reused_generic_clone", &gdir, &outcome.stdout);
}
