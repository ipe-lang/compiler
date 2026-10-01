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
//!
//! The ambient string-interpolation side channel (`"""{{p}}"""` over a `Pii`)
//! is closed at type-check — interpolation admits only the scalar set, so a
//! `Pii` is refused with IPE-T0014 (see `interpolation_scalars.rs`).
//!
//! Invariants (3)–(4) are checked inside `Main.ipe`; `allPure` must be `true`
//! for the task chain to reach the sentinel stdout line; a violation
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

    let runtime = e2e_support::require_runtime().into_path_buf();

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
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_analytics_consent_gate_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

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
