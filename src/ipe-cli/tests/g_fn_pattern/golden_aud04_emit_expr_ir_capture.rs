//! AUD-04 regression — `ipe_backend_rust::emit_expr`'s clone-capture and
//! let-inlining rewrites operate at the IR-level `Expr` tree, not on textual
//! (rendered-Rust-source) passes. A textual pass has no string-literal
//! or field-name awareness, so a captured-variable identifier that also
//! appears inside a string literal or as a record field key can be
//! silently corrupted (wrong output) or turned into invalid Rust (build
//! failure — a seal breach). See `docs/architecture/principles-audit-2026-07-09.md`
//! (AUD-04) for the finding.
//!
//! Four witnesses, one per fixture, each named `aud04_*`:
//!
//! - `string_literal`: `TaskSeq` clone-capture must not touch a string
//!   literal that shares a word with the captured variable.
//! - `record_field_collision`: `TaskSeq` clone-capture must not touch
//!   a record literal's field name that shares text with the captured
//!   variable.
//! - `taskseq_list`: multi-use Task-list `let`-inlining (two
//!   plain-argument uses, not closure captures) must not touch a nearby
//!   string literal.
//! - `taskseqsync_move`: a discarded effect sequenced into a `Task` chain
//!   needs the clone-capture rewrite, or a trailing use of the effect's own
//!   argument is a use-after-move (E0382).
//!
//! ```text
//! # compile-only check (fast, no IPE_E2E needed):
//! cargo test -p ipe --test golden_aud04_emit_expr_ir_capture
//!
//! # full E2E (run each emitted binary, assert stdout):
//! IPE_E2E=1 cargo test -p ipe --test golden_aud04_emit_expr_ir_capture
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Build `fixture` and assert `ipe::build` succeeds (a fast, always-on
/// compile check that alone covers the "invalid Rust" seal-breach witnesses
/// — the string-literal and record-field-collision cases — which otherwise
/// fail at `cargo build`).
fn assert_ipec_ok(fixture: &str, out_suffix: &str) {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(out_suffix);
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for fixture {fixture}: {:?}",
        built.err()
    );
}

/// Under `IPE_E2E=1`, additionally build the emitted Rust project and run
/// it, asserting exit 0 and that `expect_contains` appears verbatim in
/// stdout (covering the wrong-output witnesses, which compile fine but print a
/// corrupted string when the textual rewrite corrupts a shared word).
fn assert_e2e_output(fixture: &str, expect_contains: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{fixture}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for {fixture}: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted(fixture, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{fixture}: must exit 0; stdout:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains(expect_contains),
        "{fixture}: stdout must contain {expect_contains:?} verbatim (uncorrupted); got:\n{}",
        outcome.stdout
    );
}

/// Witness 1 — a string literal sharing a word with a TaskSeq-captured var
/// must render unmolested.
#[test]
fn aud04_string_literal_not_corrupted() {
    assert_ipec_ok("string_literal", "aud04_string_literal_emit");
    assert_e2e_output("string_literal", "the count is");
    assert_e2e_output("string_literal", "3");
}

/// Witness 2 — a record literal's field NAME sharing text with a
/// TaskSeq-captured var must not gain a spurious `.clone()` (without the fix, E0xxx
/// invalid Rust at the struct-literal field-key position).
#[test]
fn aud04_record_field_collision_compiles_and_runs() {
    assert_ipec_ok(
        "record_field_collision",
        "aud04_record_field_collision_emit",
    );
    // The final `Io.println (String.fromInt count)` must still print "3" —
    // proves the outer `count` binding survived the record-literal-adjacent
    // effect unmolested.
    assert_e2e_output("record_field_collision", "3");
}

/// Witness 3 — multi-use Task-list `let`-inlining must not touch a nearby
/// string literal that shares the bound name as a word.
#[test]
fn aud04_taskseq_list_inlining_not_corrupted() {
    assert_ipec_ok("taskseq_list", "aud04_taskseq_list_emit");
    assert_e2e_output("taskseq_list", "4");
}

/// Witness 4 — a discarded effect whose own argument is read again after it
/// needs the clone-capture rewrite; without it the argument moves out from
/// under the trailing read (E0382 use-after-move at `cargo build`).
#[test]
fn aud04_taskseqsync_move_compiles_and_runs() {
    assert_ipec_ok("taskseqsync_move", "aud04_taskseqsync_move_emit");
    assert_e2e_output("taskseqsync_move", "hello-msg");
}
