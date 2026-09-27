//! End-to-end SEAL for the framework-injected row-security path: an
//! authenticated route mints a `Principal` (sole minter: the fail-closed auth
//! middleware) and its handler reads a secured store as that caller through
//! `Store.allAs`. The policy's owner filter compiles to a BOUND-PARAM `WHERE`
//! (`sql_column` for the validated column, `sql_param` for the subject), never
//! string interpolation — the emitted `ruleFragment` reads
//! `sql_eq(sql_column(col), sql_param(SqlString(principal_subject(principal))))`.
//!
//! Two proofs:
//!   * emit byte-identity — the frontend accepts the authed-route + `allAs`
//!     program and emits the checked-in `main.rs` + `ipe_mods/*.rs`
//!     byte-for-byte;
//!   * THE SEAL — under `IPE_E2E=1` the emitted crate must `cargo build` (the
//!     `jwt` feature the authed surface requires is selected; no live database
//!     or network is needed — the route builder is assembled, never served).

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const GOLDEN: &str = "authed_store_query_seal";

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// Emit gate + byte-identity golden: the frontend must accept the authed-route
/// `allAs` program and emit the checked-in project byte-for-byte.
#[test]
fn authed_store_query_emits_byte_identical() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("main.rs");
    let out = crate::support::scratch_root().join("ipec_authed_store_query_seal_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // resolver unavailable — skip
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "an authed route whose handler calls `Store.allAs` on the minted \
         `Principal` must be accepted and emitted, got: {built:?}"
    );

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// THE SEAL: under `IPE_E2E=1`, actually `cargo build` the emitted crate — `ipe`
/// accepting the program (exit 0) must imply a buildable emitted crate, with the
/// `jwt` feature the authed surface requires selected.
#[test]
fn authed_store_query_seal_builds() {
    let root = repo_root();
    let entry = fixture_entry(&root);
    let out = crate::support::scratch_root().join("ipec_authed_store_query_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "{GOLDEN} must be accepted, got: {built:?}");

    crate::support::assert_seal_builds(GOLDEN, &out);
}
