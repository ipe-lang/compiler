//! `Ipe.Secret` positive goldens — build + run + assert on
//! stdout directly (no cached-oracle comparison: `Secret` has no prior/the compiler
//! counterpart, same `oracle_divergence` posture as `SqlFragment`'s
//! goldens, but simple enough that a direct stdout assertion is clearer than
//! standing up oracle-cache scaffolding for a feature with no oracle to
//! diverge FROM).
//!
//! Companion files: `crates/ipe/tests/secret_gates.rs` (negative gates —
//! `mySecret ++ "x"` rejected at compile time) and
//! `crates/ipe/tests/model_admissibility.rs`
//! (`live_model_with_secret_field_is_rejected`, the Model-gate IPE-L0120
//! case).
//!
//! Run: `IPE_E2E=1 cargo test golden_secret`

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

fn e2e_enabled() -> bool {
    std::env::var("IPE_E2E").is_ok()
}

/// Compile `tests/golden/<name>/Main.ipe`, build the emitted Cargo project,
/// run it, and return the captured stdout. Fails the test on any build or
/// runtime error — a broken golden cannot pass silently.
fn compile_build_run(name: &str) -> crate::support::RunOutcome {
    let root = repo_root();
    let entry = golden_dir(&root, name).join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else {
        return crate::support::RunOutcome {
            stdout: String::new(),
            exit_code: None,
        };
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    crate::support::build_and_run_emitted(name, &out)
}

// ── (a) normal safe usage works end-to-end ──────────────────────────────────

/// `Secret.fromString` seals a plaintext `String`; `Secret.use` is the scoped
/// consume (applies a function to the plaintext, returns its result);
/// `Secret.redacted` is the explicit `"<redacted>"` accessor. Plaintext-grep-
/// guard: the marker string appears in stdout EXACTLY ONCE (the deliberate
/// `Secret.use` scoped-println line) — `redacted` never echoes it.
#[test]
fn seal_reveal_round_trips_and_redacted_never_leaks() {
    if !e2e_enabled() {
        return;
    }
    let out = compile_build_run("m_secret_seal_reveal");
    assert_eq!(out.exit_code, Some(0), "got {:?}", out.exit_code);
    let marker = "sk_live_zx9K3_MARKER";
    assert_eq!(
        out.stdout.matches(marker).count(),
        1,
        "the secret marker must appear in stdout EXACTLY ONCE (the deliberate \
         `Secret.use` scoped-println line) — any other count means either \
         `Secret.redacted` leaked it or the scoped consume didn't run. Full \
         stdout: {:?}",
        out.stdout
    );
    assert!(
        out.stdout.contains("<redacted>"),
        "Secret.redacted must print the fixed placeholder. Full stdout: {:?}",
        out.stdout
    );
}

// ── (b) every plausible accidental-stringification path is redacted ────────

/// `==` is `Secret`'s ONLY equality (hand-written, constant-time — safe by
/// construction). Exercises match / content-mismatch / length-mismatch.
#[test]
fn equality_is_constant_time_and_structural() {
    if !e2e_enabled() {
        return;
    }
    let out = compile_build_run("m_secret_eq");
    assert_eq!(out.exit_code, Some(0), "got {:?}", out.exit_code);
    assert_eq!(
        out.stdout.trim(),
        "TFF",
        "a==b (match) -> T, a==c (content mismatch) -> F, a==d (length \
         mismatch) -> F"
    );
}

/// A record containing a `Secret` field stays fully derivable
/// (`Clone`/`Debug`/`PartialEq`) — the derive-blast-radius fix. Record
/// `==` recurses into `Secret`'s own equality; `{ r | f = v }` requires
/// `Clone` on every field including the `Secret` one.
#[test]
fn record_containing_secret_stays_clone_debug_eq() {
    if !e2e_enabled() {
        return;
    }
    let out = compile_build_run("m_secret_record");
    assert_eq!(out.exit_code, Some(0), "got {:?}", out.exit_code);
    assert_eq!(
        out.stdout.trim(),
        "TFstaging",
        "cfg1==cfg2 (same fields) -> T, cfg1==cfg3 (label differs) -> F, \
         cfg3.label after the record update -> staging"
    );
}

/// Logging a `Secret` directly (`Log.infoWith "boot" [ aSecret ]`) is safe BY
/// CONSTRUCTION: the attr-list element's Stringify obligation routes through
/// `Secret`'s hand-written `IpeStringify`, which ALWAYS redacts. The marker
/// must NEVER appear anywhere in stdout.
#[test]
fn logging_a_secret_directly_never_leaks() {
    if !e2e_enabled() {
        return;
    }
    let out = compile_build_run("m_secret_log_redact");
    assert_eq!(out.exit_code, Some(0), "got {:?}", out.exit_code);
    let marker = "sk_live_LOGGED_SECRET_MARKER";
    assert!(
        !out.stdout.contains(marker),
        "logging a Secret directly must NEVER leak the plaintext. Full \
         stdout: {:?}",
        out.stdout
    );
    assert!(
        out.stdout.contains("<redacted>"),
        "the log line must contain the redacted placeholder. Full stdout: {:?}",
        out.stdout
    );
}

// ── (c) the one non-Ipê-code serialization-adjacent path: Auth's typed boundary ──

/// `Auth.signToken` / `Auth.verifyToken` are re-typed to take `Secret` (not
/// `String`) at the signing-key position. Full sign -> verify round trip
/// through the `AUTH_WRAPPERS` boundary that reveals the `Secret`
/// immediately before delegating to the runtime.
#[test]
fn auth_sign_verify_round_trip_with_secret_key() {
    if !e2e_enabled() {
        return;
    }
    let out = compile_build_run("m_secret_auth_roundtrip");
    assert_eq!(out.exit_code, Some(0), "got {:?}", out.exit_code);
    assert_eq!(out.stdout.trim(), "alice");
}

// ── (d) the un-applied-seal ban leaves the legitimate applied forms working ──

/// `List.map (\s -> Secret.fromString s) runtimeStrings` — the sanctioned
/// replacement for the banned point-free `List.map Secret.fromString …`. The
/// seal is FULLY APPLIED to the lambda's own parameter, so the committed-literal
/// gate still sees every argument; each element is a runtime `String` (an env
/// read), never a source literal. `Secret.redacted` maps each sealed value back
/// to the fixed placeholder — the plaintext markers must NEVER appear in stdout.
#[test]
fn map_seal_over_runtime_strings_builds_and_redacts() {
    if !e2e_enabled() {
        return;
    }
    let out = compile_build_run("m_secret_map_runtime");
    assert_eq!(out.exit_code, Some(0), "got {:?}", out.exit_code);
    for marker in ["sk_live_MAP_MARKER_A", "sk_live_MAP_MARKER_B"] {
        assert!(
            !out.stdout.contains(marker),
            "a sealed runtime String's plaintext must NEVER echo. Full stdout: {:?}",
            out.stdout
        );
    }
    assert_eq!(
        out.stdout.trim(),
        "<redacted>,<redacted>",
        "each sealed element redacts to the fixed placeholder. Full stdout: {:?}",
        out.stdout
    );
}

/// `Secret.fromString (System.getenvOr "APP_SECRET" "…")` — the seal applied
/// DIRECTLY to a runtime `String`. A saturated call whose argument is a runtime
/// value is accepted (only a source-text literal is refused); `Secret.redacted`
/// proves the plaintext (the default marker) never echoes.
#[test]
fn direct_seal_over_env_string_builds_and_redacts() {
    if !e2e_enabled() {
        return;
    }
    let out = compile_build_run("m_secret_env_direct");
    assert_eq!(out.exit_code, Some(0), "got {:?}", out.exit_code);
    assert!(
        !out.stdout.contains("sk_live_ENV_DIRECT_MARKER"),
        "the sealed env String's plaintext must NEVER echo. Full stdout: {:?}",
        out.stdout
    );
    assert_eq!(
        out.stdout.trim(),
        "<redacted>",
        "Secret.redacted must print the fixed placeholder. Full stdout: {:?}",
        out.stdout
    );
}

/// `sealParam raw` seals a function PARAMETER, and `Secret.fromString
/// (deriveAtRuntime "…")` seals a CROSS-FUNCTION result — neither of which the
/// LOCAL constant-fold can reduce, so the committed-literal gate (IPE-L0150)
/// accepts both (the honest residual). Proves the fold that catches
/// `let`/`do`/append literals does NOT over-reach into runtime-derived values:
/// the build succeeds and each sealed plaintext redacts to the fixed placeholder
/// (the markers must NEVER echo).
#[test]
fn runtime_derived_seals_are_accepted_and_redact() {
    if !e2e_enabled() {
        return;
    }
    let out = compile_build_run("m_secret_runtime_derived");
    assert_eq!(out.exit_code, Some(0), "got {:?}", out.exit_code);
    for marker in ["sk_live_PARAM_MARKER", "sk_live_DERIVE_MARKER"] {
        assert!(
            !out.stdout.contains(marker),
            "a runtime-derived sealed plaintext must NEVER echo. Full stdout: {:?}",
            out.stdout
        );
    }
    assert_eq!(
        out.stdout.trim(),
        "<redacted>,<redacted>",
        "both runtime-derived seals redact to the fixed placeholder. Full stdout: {:?}",
        out.stdout
    );
}

// ── Pure compile-only smoke (always runs, no IPE_E2E / no cargo) ───────────

/// All five fixtures above must at least `ipe`-compile cleanly even when
/// `IPE_E2E` is unset (CI without the heavy cargo-build tier still catches a
/// type-check regression).
#[test]
fn all_secret_goldens_compile() {
    let root = repo_root();
    for name in [
        "m_secret_seal_reveal",
        "m_secret_eq",
        "m_secret_record",
        "m_secret_log_redact",
        "m_secret_auth_roundtrip",
        "m_secret_map_runtime",
        "m_secret_env_direct",
        "m_secret_runtime_derived",
        // `Io.readSecret : String -> Task Error Secret` — the read secret flows
        // straight into the scoped `Secret.use`; proves the `Secret`-typed
        // result type-checks end to end.
        "m_secret_io_read",
    ] {
        let entry = golden_dir(&root, name).join("Main.ipe");
        let out = crate::support::scratch_root().join(format!("ipec_{name}_compileonly"));
        let _ = std::fs::remove_dir_all(&out);
        let Ok(runtime) = ipe::resolve_runtime() else {
            return;
        };
        let built = ipe::build(&entry, &out, &runtime);
        assert!(built.is_ok(), "{name} must ipec-compile: {:?}", built.err());
    }
}
