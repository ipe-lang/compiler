//! Ipê-side parity fixture for the SQL-identifier gate.
//!
//! `Store.validSqlIdent` (dotted) and `Store.validSqlIdentPlain` (dot-free) must
//! stay byte-equivalent to the runtime SSOT `SqlIdent::parse_dotted` /
//! `SqlIdent::parse_plain` (`runtime/rust/src/db.rs`, whose `HOSTILE_IDENTS`
//! fixture this corpus mirrors). The fixture prints one `<label>:<plain><dotted>`
//! line per identifier; the pinned expected output fails if either Ipê gate
//! drifts from the runtime rule — in particular an empty-dot-segment string
//! (`.`, `a..b`, `users.`) must be rejected by BOTH.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

const fn golden_name() -> &'static str {
    "store_ident_parity"
}

fn entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(golden_name())
        .join("Main.ipe")
}

// `<plain><dotted>` verdicts. Bare/underscore names pass both; a dotted
// reference passes only the dotted gate; every empty-dot-segment string and
// every hostile identifier is rejected by both.
const EXPECTED: &str = "\
bare:TT
underscore:TT
dotted:FT
multi-dotted:FT
leading-dot:FF
trailing-dot:FF
double-dot:FF
lone-dot:FF
single-quote:FF
double-quote:FF
semicolon-drop:FF
space:FF
line-comment:FF
backtick:FF
call:FF
star:FF
empty:FF
digit-punct:FF
non-ascii:FF";

/// The fixture must be accepted by `ipe` (exit 0): both identifier predicates
/// resolve and build.
#[test]
fn store_ident_parity_resolves_and_builds() {
    let root = repo_root();
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("store_ident_parity_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry(&root), &out, &runtime);
    assert!(
        built.is_ok(),
        "store_ident_parity: `ipe build` must exit 0 (Store.validSqlIdent + \
         Store.validSqlIdentPlain must resolve and build): {:?}",
        built.err()
    );
}

/// Full spine: compile -> `cargo build` -> run -> assert stdout matches the
/// pinned verdicts. Gated on `IPE_E2E=1` so the default gate stays fast.
#[test]
fn store_ident_parity_end_to_end() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_store_ident_parity_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry(&root), &out, &runtime);
    assert!(
        built.is_ok(),
        "store_ident_parity: `ipe build` must exit 0: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted(golden_name(), &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "store_ident_parity: expected exit 0, got {:?}",
        outcome.exit_code
    );
    assert_eq!(
        outcome.stdout.trim(),
        EXPECTED,
        "store_ident_parity: the Ipê SQL-identifier gates must stay \
         byte-equivalent to the runtime SqlIdent parser (dotted + plain)"
    );
}
