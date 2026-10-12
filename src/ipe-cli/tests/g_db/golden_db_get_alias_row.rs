//! INDIRECTED (aliased) row argument.
//!
//! The structural `body_calls_db_get_on_param` walk originally matched the
//! wildcard param in row-argument position ONLY as a DIRECT `Var`/`CloneVar`.
//! A decoder that let-binds a pure alias of the payload and reads fields off
//! THAT alias therefore dropped the `+ IpeRow` bound:
//!
//! ```elm
//! decodeRow payload =
//!     let r = payload in
//!     { author = Db.getString "author" r }   -- row arg `r`, an alias of `payload`
//! ```
//!
//! → `ipe dev build` exit 0, but the emitted `main_decode_row<T1: Clone>` (NO
//! `IpeRow`) fails `cargo build` with E0277. The BASE commit's old body-TEXT
//! scan happened to bound it (the alias still renders as
//! `db_get_string(_, &r)`), so the structural rewrite REGRESSED this case — a
//! ipe-0-then-cargo-fail SEAL violation.
//!
//! The fix makes the walk alias-transparent (mirroring the alias-chain
//! resolution in `flows_into_sync_kernel_call`): a value-preserving
//! `let r = payload` tracks `r` as an additional alias of the wildcard row for
//! the rest of the `let` body, so `Db.getString _ r` obliges the bound exactly
//! as `Db.getString _ payload` would. Multi-hop chains
//! (`let r = payload; let r2 = r`) resolve by induction.
//!
//! Run:
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_i177_db_get_alias_row
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path, fixture: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe")
}

/// ipe-0 ∧ `+ IpeRow` lands on the decoder fn's wildcard-`any` generic even
/// though the row arg is an ALIAS of the param — checked unconditionally
/// (cheap, no `cargo`). The record STRUCT must stay unbounded.
// The `expect` guards a test-support invariant: a build asserted successful
// just above MUST have written `src/main.rs`; an unreadable file here means the
// emitter/fixture is broken, so aborting is the correct failure signal.
#[allow(clippy::expect_used)]
fn assert_ipec_bounds_fn_not_struct(fixture: &str) {
    let root = repo_root();
    let entry = entry_path(&root, fixture);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{fixture}_ipec_out"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for {fixture}: {:?}",
        built.err()
    );

    let emitted = crate::support::read_all_emitted_src(&out);

    // The alias in row position must NOT defeat the bound.
    assert!(
        emitted.contains("fn main_decode_row<T1: Clone + ipe_runtime::db::IpeRow>"),
        "the aliased-row decoder's wildcard-`any` generic must still carry the \
         `IpeRow` bound so its `db_get_string(_, &r)` body type-checks (#177 \
         FIX-UP 2); got emitted user source:\n{emitted}"
    );

    // The record struct itself MUST stay unbounded (reusable in non-row
    // contexts) — an over-bound regression guard.
    for line in emitted.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("pub struct ") || trimmed.starts_with("struct ") {
            assert!(
                !line.contains("IpeRow"),
                "the record struct must NOT carry a `IpeRow` bound (#177); \
                 offending line: {line}"
            );
        }
    }
}

/// cargo-0 ∧ run-0 for the emitted project — the only check that would have
/// caught the E0277 regression. Gated on `IPE_E2E=1`.
fn assert_cargo_builds_and_runs(fixture: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root, fixture);
    let out = crate::support::scratch_root().join(format!("ipec_{fixture}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for {fixture}: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted(fixture, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{fixture} binary must cargo-build AND exit 0 (no E0277); got {:?} (stdout: {:?})",
        outcome.exit_code,
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim(),
        "ada,hello",
        "{fixture} must print the record fields decoded off the aliased payload; \
         got: {:?}",
        outcome.stdout
    );
}

#[test]
fn i177_alias_row_ipec_bounds_fn_not_struct() {
    assert_ipec_bounds_fn_not_struct("db_get_alias_row");
}

#[test]
fn i177_alias_row_cargo_builds_and_runs() {
    assert_cargo_builds_and_runs("db_get_alias_row");
}

#[test]
fn i177_alias_chain_row_ipec_bounds_fn_not_struct() {
    assert_ipec_bounds_fn_not_struct("db_get_alias_chain_row");
}

#[test]
fn i177_alias_chain_row_cargo_builds_and_runs() {
    assert_cargo_builds_and_runs("db_get_alias_chain_row");
}
