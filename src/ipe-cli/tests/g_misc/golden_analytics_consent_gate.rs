//! `Ipe.Analytics` consent-gate, `Pii`-redaction gate, and ambient-stringify
//! side-channel closure proof.
//!
//! Proves:
//!
//!   1. `track` with `Granted` consent reaches the sink (no crash, task
//!      succeeds, sentinel line printed to stdout).
//!   2. `track` with `Denied` or `Pending` consent is fail-closed — the event
//!      is dropped silently; the task still succeeds.
//!   3. `Pii` serialises as `"[redacted]"` through the explicit encode path
//!      (`encodePropValue`) — the raw plaintext is never reachable through the
//!      module's public API.
//!   4. `PMoney` serialises losslessly as `{"amount":"…","currency":"…"}`.
//!   5. `Basics.toString (Analytics.pii "…")` does NOT contain the plaintext —
//!      the ambient `toString` / string-interpolation side channel is closed.
//!      `Pii` wraps a `Secret`; the `Secret` field's `IpeStringify` impl always
//!      returns the redacted placeholder, making plaintext leakage structurally
//!      impossible in the emitted Rust.
//!   6. `Basics.toString (PPii (Analytics.pii "…"))` likewise does NOT expose
//!      the plaintext — the `PPii` constructor's `IpeStringify` auto-derive
//!      recurses into the `Secret` field's redacting impl.
//!
//! Invariants (3)–(6) are checked inside `Main.ipe`; `allPure` must be `true`
//! for the task chain to reach the sentinel stdout line. The E2E test is the
//! key evidence that the plaintext no longer appears: any stringification leak
//! causes `allPure = false` → stdout `analytics-FAIL-pure` → assertion fails.
//! Expected stdout: `analytics-consent-gate-ok` (one line).

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const fn golden_name() -> &'static str {
    "analytics_consent_gate"
}

fn entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(golden_name())
        .join("Main.ipe")
}

/// The fixture must be accepted by `ipe` (exit 0 — IPE-N0002/N0028 would
/// fire if the module is missing or any export is unresolved).
#[test]
fn analytics_module_resolves_and_builds() {
    let root = repo_root();
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("analytics_consent_gate_emit");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };

    let built = ipe::build(&entry(&root), &out, &runtime);
    assert!(
        built.is_ok(),
        "analytics_consent_gate: `ipe build` must exit 0 (Ipe.Analytics resolves \
         + consent-gate + Pii ADT accepted): {:?}",
        built.err()
    );
}

/// Full spine: compile → `cargo build` → run → assert stdout.
/// Gated on `IPE_E2E=1` so the default `cargo nextest` gate stays fast.
#[test]
fn analytics_consent_gate_end_to_end() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_analytics_consent_gate_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };

    let built = ipe::build(&entry(&root), &out, &runtime);
    assert!(
        built.is_ok(),
        "analytics_consent_gate: `ipe build` must exit 0: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted(golden_name(), &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "analytics_consent_gate: expected exit 0, got {:?}",
        outcome.exit_code
    );
    assert_eq!(
        outcome.stdout.trim(),
        "analytics-consent-gate-ok",
        "analytics_consent_gate: consent-gate + Pii-redaction + Money lossless \
         invariants must all hold"
    );
}
