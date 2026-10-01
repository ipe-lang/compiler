//! `Ipe.Db.Sql` negative gate: a naive string-concatenated WHERE
//! clause must be REJECTED at `ipe` compile time, never accepted and left to
//! misbehave (or be silently injectable) at runtime. This is the core
//! "parse, don't validate" property the `SqlFragment` newtype exists to
//! establish — `Db.findWhere` / `Db.deleteWhere` take `SqlFragment`, not
//! `String`, so a hand-built WHERE string is a `IPE-T0001` type mismatch, not
//! a representable runtime value.
//!
//! Compile-only: these fixtures never run (there is nothing to execute — the
//! program is ill-typed), so there is no oracle / `IPE_E2E` gate here, unlike
//! `golden_m5b_db.rs`'s runnable goldens.

use std::path::PathBuf;

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Build the named golden fixture and assert it surfaces exactly `expected` as
/// a pipeline diagnostic — never a panic, never a silent accept.
fn assert_gate(fixture: &str, out_suffix: &str, expected: ipe_diagnostics::Code) {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(out_suffix);
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(expected),
        "fixture {fixture}: expected {expected:?}, got build result {built:?}"
    );
}

/// `Db.findWhere conn "products" ("qty > " ++ "9")` — a plain `String` (built
/// by `++`, not any `Sql.*` combinator) where `SqlFragment` is required —
/// must be rejected with `IPE-T0001` at the call site. This is the exact
/// injection shape a raw `Db.unsafeFindWhere` would accept at runtime; `ipe`
/// refuses it before a single byte of Rust is emitted.
#[test]
fn db_findwhere_string_is_t0001() {
    assert_gate(
        "db_gate_findwhere_string",
        "m5b_db_gate_findwhere_string_emit",
        ipe_diagnostics::IPE_T0001,
    );
}
