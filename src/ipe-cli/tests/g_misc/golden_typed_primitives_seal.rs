//! SEAL for the typed-primitive newtypes.
//!
//! `Ipe.Net.Port`, `Ipe.Duration.Duration`, and `Ipe.ByteSize.ByteSize` are
//! opaque newtypes whose only constructor is a parse/unit boundary. This golden
//! builds a program that constructs each through its boundary and reads it back
//! through its `toX` accessor, and — the load-bearing refusals — proves that an
//! out-of-range port (`70000`) and the reserved `0` sentinel are runtime `Err`
//! from `Net.fromInt`. It also pins `Ipe.Duration`'s non-negativity invariant: a
//! negative input to a constructor clamps to the zero span (`neg 0 0`), so a
//! negative-millisecond duration that could disable a timeout floor has no
//! representation. The `ttlField 0` line pins the same guarantee at the
//! config-field boundary: a negative span routed through `Cache.withTTL` (the
//! only surface that fills the ttl config field) reaches the field as `0`, so
//! no negative millisecond count can enter a timeout/ttl field through a
//! builder.
//!
//! The frontend-accepts assertion runs in the default gate; the build-and-run
//! proof is `IPE_E2E`-gated, matching every other golden in this suite.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("typed_primitives_seal")
        .join("Main.ipe")
}

fn built(root: &Path, out: &Path) -> Option<Result<(), ipe::CliError>> {
    let entry = fixture_entry(root);
    let _ = std::fs::remove_dir_all(out);
    let runtime = ipe::resolve_runtime().ok()?;
    Some(ipe::build(&entry, out, &runtime))
}

/// Emit assertion (default gate): the frontend must accept a program that drives
/// each newtype through its parse/unit boundary and back through its accessor.
#[test]
fn typed_primitives_seal_emits() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_typed_primitives_seal_emit");
    let Some(built) = built(&root, &out) else {
        return; // resolver unavailable — skip, matches the other goldens
    };
    assert!(
        built.is_ok(),
        "typed_primitives_seal: must be accepted + emitted, got: {built:?}"
    );
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, `cargo build` the emitted
/// crate and run it. The output pins both the positive round-trips and the
/// `Net.fromInt` refusals (out-of-range + zero).
#[test]
fn typed_primitives_seal_builds_and_runs() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_typed_primitives_seal_e2e");
    let Some(built) = built(&root, &out) else {
        return;
    };
    assert!(
        built.is_ok(),
        "typed_primitives_seal: must be accepted, got: {built:?}"
    );

    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let outcome = crate::support::build_and_run_emitted("typed_primitives_seal", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "typed_primitives_seal: emitted crate must build and exit 0; stdout:\n{}",
        outcome.stdout
    );
    let expected = "port 8080\n\
                    high rejected\n\
                    zero rejected\n\
                    dur 30000 120000\n\
                    neg 0 0\n\
                    bytes 10485760 4096\n\
                    sat 9223372036854720000 9223372036853727232\n\
                    ttlField 0";
    assert_eq!(
        outcome.stdout.trim(),
        expected,
        "typed-primitive round-trips + Port refusals produced the wrong output"
    );
}
