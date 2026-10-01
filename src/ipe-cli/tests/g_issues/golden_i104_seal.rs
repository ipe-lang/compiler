//! Seal — multi-use-clone rewrite (T5).
//!
//! A `CloneOk` local used more than once in its scope must be `.clone()`d on
//! all but the syntactically last occurrence, or emitted Rust fails E0382
//! ("use of moved value").
//!
//! Two sub-classes covered:
//!
//! * **let-binding with multiple direct uses**
//!   `let s = String.fromInt n in if String.length s < 2 then "0" ++ s else s`
//!   `string_length(s)` moves `s` in Rust; both `if`-branches reuse it.
//!
//! * **lambda capture + post-capture use**
//!   `let mapped = List.map (\x -> String.append prefix x) items in … prefix …`
//!   The `move` closure steals `prefix`; the trailing `++ prefix ++ …` fails.
//!
//! Gated: the cargo build+run step requires `IPE_E2E=1`; without it the test
//! is a no-op so the default CI pass stays fast.
//!
//! ```text
//! # full E2E (cargo build + run):
//! IPE_E2E=1 cargo test -p ipe --test golden_i104_seal
//!
//! # gate only (fast, no cargo):
//! cargo test -p ipe --test golden_i104_seal
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

// ── F1 — let-binding multi-use ─────────────────────────────────────────

/// `pad2 7` must print `"07"`.  Without T5 the emitted `string_length(s)` would
/// move `s`, making the branches' reuse E0382.
#[test]
fn f1_multiuse_let_clone() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("multiuse_let_clone")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i104_multiuse_let_clone_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for multiuse_let_clone: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("multiuse_let_clone", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "must exit 0 (was E0382 multi-use let)"
    );
    assert!(
        outcome.stdout.trim_end_matches('\n').contains("07"),
        "pad2 7 must print '07'; got:\n{}",
        outcome.stdout
    );
}

// ── F2 — lambda capture + post-capture use ─────────────────────────────

/// `format "ipe-" ["one","two"]` must print `"ipe-one,ipe-two[ipe-]"`.
/// Without T5 the `move` closure steals `prefix`; the trailing
/// `++ "[" ++ prefix ++ "]"` is E0382.
#[test]
fn f2_closure_capture_reuse() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("closure_capture_reuse")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i112_closure_capture_reuse_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for closure_capture_reuse: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("closure_capture_reuse", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "must exit 0 (was E0382 capture + reuse)"
    );
    assert!(
        outcome.stdout.contains("ipe-one,ipe-two[ipe-]"),
        "format must print 'ipe-one,ipe-two[ipe-]'; got:\n{}",
        outcome.stdout
    );
}
