//! Stdlib-contract-drift regression — three kernel-backed stdlib
//! surfaces (`Jwt.withClaim`, `Ipe.Db.Migration`/`Db.migrate`,
//! `Ipe.Http.Server.Response`) whose compiler contracts had drifted from the
//! reference `../ipe/ipe-stdlib` signatures, so `ipec` rejected a
//! verbatim-ported reference program with `IPE-T0001` ("expected String, found
//! Value" etc.).
//!
//! The reference Ipê-source signature IS the contract:
//!
//! * `withClaim : String -> JsonEnc.Value -> Claims -> Claims`
//!   (`Ipê/Core/Jwt.ipe:79`) — ours had drifted to `String -> String -> …`.
//! * `type alias Migration = { name : String, sql : String }` +
//!   `migrate : Db -> List Migration -> Task Error (List String)`
//!   (`Ipê/Db.ipe:237,300`) — ours had no `Migration` and `migrate` took
//!   `List (String, String)`.
//! * `type alias Response = { status : Int, body : String, headers : Dict
//!   String String, contentType : String }` (`Ipê/Http/Server.ipe:66`) — ours
//!   had registered it as an opaque nominal, so a record literal was rejected.
//!
//! Each test compiles a fixture that uses the surface as the reference does.
//! The cheap tier asserts `ipe` ACCEPTS the program (no IPE-T0001). The
//! `IPE_E2E=1` tier is THE SEAL: the emitted Rust must `cargo build` and run.
//!
//! Run:
//! ```text
//! cargo test -p ipe --test golden_i217_stdlib_contract_drift
//! IPE_E2E=1 cargo test -p ipe --test golden_i217_stdlib_contract_drift
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path, name: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe")
}

/// Compile a fixture and assert `ipe` accepts it (the contract now matches the
/// reference). Returns the emitted output dir for an optional E2E follow-up.
fn assert_ipec_accepts(name: &str) -> PathBuf {
    let root = repo_root();
    let entry = entry_path(&root, name);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_ipec_out"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for {name} (contract converged to reference): {:?}",
        built.err()
    );
    out
}

fn e2e_build_and_run(name: &str, expect_stdout_contains: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let entry = entry_path(&root, name);
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for {name}: {:?}",
        built.err()
    );

    // The emitted binary is run by the oracle with the TEST process's cwd
    // (`crates/ipe`), and `Db.connect ()` writes the default `ipe.db` there.
    // A `ipe.db` left by a PRIOR run (or a fixture edit that changed a
    // migration's SQL) would trip the checksum guard on the next run — a
    // spurious runtime failure unrelated to the contract under test. Clear the
    // stray DB from the likely cwd locations so each run starts clean; the
    // fixture also recovers migration errors to keep the SEAL check robust.
    for dir in [root.join("src").join("ipe-cli"), root.clone()] {
        for suffix in ["ipe.db", "ipe.db-shm", "ipe.db-wal"] {
            let _ = std::fs::remove_file(dir.join(suffix));
        }
    }

    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{name} emitted project must cargo-build and exit 0 (THE SEAL); stdout: {:?}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains(expect_stdout_contains),
        "{name} stdout must contain {expect_stdout_contains:?}; got: {:?}",
        outcome.stdout
    );
}

/// `Jwt.withClaim` accepts a `JsonEnc.Value` argument (string AND int claims).
#[test]
fn i217_jwt_with_claim_accepts_json_value() {
    assert_ipec_accepts("jwt_withclaim_value");
}

#[test]
fn i217_jwt_with_claim_e2e() {
    e2e_build_and_run("jwt_withclaim_value", "ok");
}

/// `Db.migrate` takes `List Migration`, where `Migration` is the record alias.
#[test]
fn i217_db_migration_record_accepted() {
    assert_ipec_accepts("db_migration_record");
}

#[test]
fn i217_db_migration_record_e2e() {
    e2e_build_and_run("db_migration_record", "applied:");
}

/// `Response` used as a record — literal construction + field projection.
#[test]
fn i217_server_response_record_accepted() {
    assert_ipec_accepts("server_response_record");
}

#[test]
fn i217_server_response_record_e2e() {
    e2e_build_and_run("server_response_record", "429");
}
