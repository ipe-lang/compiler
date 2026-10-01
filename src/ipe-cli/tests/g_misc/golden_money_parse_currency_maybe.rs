//! `Money.parseCurrency` returns `Maybe Currency` gate.
//!
//! Proves that `parseCurrency : String -> Maybe Currency` compiles and emits
//! byte-identically to the stored golden, and (behind `IPE_E2E=1`) that the
//! emitted binary prints the correct `Just`/`Nothing` results — never a
//! silent `CurrencyRaw` default.
//!
//! Expected output (three lines):
//!   Just USD
//!   Nothing
//!   Nothing
//!
//! These three calls cover: a recognised code (`"USD"` → `Just USD`), an
//! unrecognised code (`"BOGUS"` → `Nothing`), and an empty string (`""` → `Nothing`).

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const fn golden_name() -> &'static str {
    "money_parse_currency_maybe"
}

fn entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(golden_name())
        .join("Main.ipe")
}

#[test]
fn emits_byte_identical_main_rs() {
    let root = repo_root();
    let golden = root
        .join("tests")
        .join("golden")
        .join(golden_name())
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("money_parse_currency_maybe_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry(&root), &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

/// Full spine: compile → cargo build → run → assert output.
/// Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_prints_just_nothing_nothing() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_money_parse_currency_maybe_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry(&root), &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(golden_name(), &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "exit 0; got {:?}",
        outcome.exit_code
    );
    assert_eq!(
        outcome.stdout.trim(),
        "Just USD\nNothing\nNothing",
        "parseCurrency must return Just for known codes and Nothing for unknown/empty"
    );
}
