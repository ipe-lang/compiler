//! `Ipe.Db.Codec` codec↔SQL row bridge soundness gate.
//!
//! Proves the bridge's core guarantee for a record codec that exercises every
//! `ColType` at once (text, int, real, bool, a lossless `Decimal` stored as
//! TEXT, a nullable int, and a JSON-in-TEXT blob list): running `codecToBinds`
//! to bound `(column, SqlValue)` params, rebuilding a `Row` from those binds the
//! way the store reads a row back, then `codecFromRow`, returns the original
//! value. Every produced value is a BOUND `SqlValue` — the bridge builds no SQL
//! text.
//!
//! The fixture also asserts the two fail-closed paths: a bare-scalar codec has
//! no columns to bind (typed `Err`), and a row missing a required column decodes
//! to a typed `Err` (schema drift surfaces as an error, never a wrong value).
//! Prove-the-refusals: `CDecimal` binds as `SqlDecimal` (never `SqlString`);
//! `CMoney` binds as `SqlMoney` (never `SqlString`); both round-trip losslessly.
//!
//! The fixture prints one `db-codec-bridge-ok` line iff every check holds, so
//! the oracle is one line and any regression flips it, failing the seal loudly.
//!
//! Gated on `IPE_E2E=1` (build-and-run); without it the test returns early.
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test g_m4 golden_db_codec_bridge
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe`, build the emitted Cargo project, run
/// it, and assert its stdout matches the cached oracle. Gated on `IPE_E2E=1`.
fn assert_runs_and_matches_oracle(name: &str) {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = golden_dir(&root, name);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0, matching the oracle");
}

/// The codec↔SQL row bridge round-trips a record value through bound binds and a
/// rebuilt row across every `ColType`, and fails closed on a non-record codec
/// and a row missing a required column.
/// Output: `db-codec-bridge-ok`.
#[test]
fn db_codec_bridge() {
    assert_runs_and_matches_oracle("db_codec_bridge");
}
