//! `Ipe.Analytics` store-backed persistence gate.
//!
//! Proves:
//!
//!   1. `eventsStore` resolves — all column/table identifiers are valid SQL
//!      identifiers; `Store.fromColumns` returns `Ok`.
//!   2. `persist` with `Granted` consent inserts a row (totals increases by 1).
//!   3. `persist` with `Pending` consent is fail-closed — no row is inserted.
//!   4. A `PPii` prop is stored as `"[redacted]"` in the `props_json` column —
//!      plaintext PII never reaches the database (Security principle §0).
//!   5. `totals`, `uniqueUsers`, `eventCounts`, `recent` return correct values.
//!   6. `erase` deletes all rows for a given `userId`; other users' rows remain.
//!
//! Expected stdout matches `tests/golden/analytics_store_gate/expected.txt`.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const fn golden_name() -> &'static str {
    "analytics_store_gate"
}

fn entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(golden_name())
        .join("Main.ipe")
}

const EXPECTED: &str = "\
store:ok
totals-after-granted:1
totals-after-pending:1
pii-in-db:[redacted]
unique-users:1
erase-count:2
totals-after-erase:1
event-count-purchase:1
event-count-login:0";

/// The fixture must be accepted by `ipe` (exit 0 — IPE-N0002/N0028 would fire
/// if `Ipe.Analytics` or any of its store-surface exports are unresolved).
#[test]
fn analytics_store_gate_resolves_and_builds() {
    let root = repo_root();
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("analytics_store_gate_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry(&root), &out, &runtime);
    assert!(
        built.is_ok(),
        "analytics_store_gate: `ipe build` must exit 0 (Ipe.Analytics store \
         surface — eventsStore/persist/erase/totals/uniqueUsers/eventCounts/recent \
         — must all resolve and build): {:?}",
        built.err()
    );
}

/// Full spine: compile → `cargo build` → run → assert stdout.
/// Gated on `IPE_E2E=1` so the default `cargo nextest` gate stays fast.
#[test]
fn analytics_store_gate_end_to_end() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_analytics_store_gate_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry(&root), &out, &runtime);
    assert!(
        built.is_ok(),
        "analytics_store_gate: `ipe build` must exit 0: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted(golden_name(), &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "analytics_store_gate: expected exit 0, got {:?}",
        outcome.exit_code
    );

    assert_eq!(
        outcome.stdout.trim(),
        EXPECTED,
        "analytics_store_gate: store-persistence + consent-gate + PII-in-DB \
         + erase + aggregate query invariants must all hold"
    );
}
