//! Regression for `Cache.get` returning `Nothing` when the value type is `Int`.
//!
//! Root cause: `Expr::Int(n)` emitted a bare Rust integer literal (`42`) with
//! no type suffix. Rust inferred `T2 = i32` (the default integer type) at the
//! `Cache.put` call site, storing `Box<i32>` in the cache. The `Cache.get` call
//! site inferred `T2 = i64` from the `IpeMaybe<i64>` result, so
//! `downcast_ref::<i64>()` always failed — a permanent miss even though the
//! entry was present and `Cache.size` reported it. The fix emits `{n}i64` for
//! every `Expr::Int` node so the stored and retrieved types are always `i64`.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("cache_int_get")
        .join("Main.ipe")
}

fn built(root: &Path, out: &Path) -> Result<(), ipe::CliError> {
    let entry = fixture_entry(root);
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, out, &runtime)
}

/// Emit assertion (default gate): the frontend must accept the
/// `Cache.get`-with-Int-value program and emit its crate.
#[test]
fn cache_int_get_emits() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_cache_int_get_emit");
    let built = built(&root, &out);
    assert!(
        built.is_ok(),
        "cache_int_get: must be accepted + emitted, got: {built:?}"
    );
}

/// End-to-end SEAL proof under `IPE_E2E=1`: the emitted crate must build,
/// run, and print the cache hit for the `Int` value.
/// Pre-fix: printed `FAIL: Int miss` (the `Box<i32>` / `i64` downcast
/// mismatch). Post-fix: prints `int=42`.
#[test]
fn cache_int_get_builds_and_runs() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_cache_int_get_e2e");
    let built = built(&root, &out);
    assert!(
        built.is_ok(),
        "cache_int_get: must be accepted, got: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("cache_int_get", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "cache_int_get: emitted crate must build and exit 0; stdout:\n{}",
            outcome.stdout
        );
        assert_eq!(
            outcome.stdout.trim(),
            "int=42",
            "cache_int_get: pre-fix prints `FAIL: Int miss` (Box<i32>/i64 downcast \
         mismatch); post-fix must print `int=42`"
        );
    }
}
