//! `Ipe.Json.Encode` parity gate — JSON encoder kernels with
//! byte-for-byte golden parity.
//!
//! These golden tests exercise the `JsonEnc` kernel family end-to-end:
//!
//! * `JsonEnc.object` + `JsonEnc.string` + `JsonEnc.int` + `JsonEnc.list` +
//!   `JsonEnc.encode 0` — a nested `{name, age, tags:[…]}` object at compact
//!   (indent=0) output.  Keys are emitted in the list order given to `object`:
//!   `name, age, tags`.
//!   (`json_enc_object_compact`)
//!
//! * Same object at `encode 2` — 2-space pretty-print, keys in list order.
//!   (`json_enc_object_pretty`)
//!
//! * Float encoding thresholds — `1.5`, `1e20`, `1e-6`, `1.23e17` — plus
//!   `bool`/`null`.  Pins the decimal-vs-exponent selection and `e±NN` shape
//!   (serde's Ryū default would diverge: `1e20` → exponent form, etc.).
//!   (`json_enc_float`)
//!
//! * `JsonEnc.string` over a value carrying `"`, `<`, `>`, `&`, U+2028, and
//!   U+2029 — HTML-escaped by default (`\"`, `<`, `>`, `&`, `\\u2028`,
//!   `\\u2029`).  serde escapes only `\"`, so this pins the HTML-escape pass.
//!   (`json_enc_escape`)
//!
//! Every test is gated on `IPE_E2E=1`; without it the test returns early.  Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m4g
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe`, build the emitted Cargo project,
/// run it, and assert its stdout matches the cached oracle.  Gated on
/// `IPE_E2E=1`.
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

// ── compact object (indent 0) ────────────────────────────────────────────────

/// `JsonEnc.object [{name,age,tags}]` encoded at `indent=0`.
/// Keys in list order: `name, age, tags`.  Output: compact JSON line.
#[test]
fn json_enc_object_compact() {
    assert_runs_and_matches_oracle("json_enc_object_compact");
}

// ── pretty object (indent 2) ─────────────────────────────────────────────────

/// Same object encoded at `indent=2` — 2-space indentation, keys in list order.
#[test]
fn json_enc_object_pretty() {
    assert_runs_and_matches_oracle("json_enc_object_pretty");
}

// ── float + bool + null scalars ──────────────────────────────────────────────

/// Floats across the floatEncoder thresholds: `1.5`, `1e20`, `1e-6`,
/// `1.23e17` (decimal form) + `bool`/`null`.  Output:
/// `"1.5 100000000000000000000 0.000001 123000000000000000 true null"`.
#[test]
fn json_enc_float_bool_null() {
    assert_runs_and_matches_oracle("json_enc_float");
}

// ── string escaping ──────────────────────────────────────────────────────────

/// `JsonEnc.string` over `"`, `<`, `>`, `&`, U+2028, U+2029.  Pins
/// default HTML-escaping (`\"`, `<`, `>`, `&`, `\u2028`,
/// `\u2029`) against `serde_json`, which escapes only `\"`.
#[test]
fn json_enc_string_escape() {
    assert_runs_and_matches_oracle("json_enc_escape");
}
