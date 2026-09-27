//! Class 4 item C — nested-constructor-payload function-argument patterns.
//!
//! Two shapes that the reference (../ipe) recurses into and compiles are
//! ACCEPTED (rather than fail-closing as IPE-L0112 record / IPE-L0116 cons):
//!
//! * A RECORD sub-pattern nested in a ctor payload (`Ok { name }`) — the
//!   constraint generator records a region on every `PCtor` (and `PTuple`)
//!   sub-pattern, so the lowerer recovers the nested record's complete field set
//!   exactly the way a top-level `case` / `let` binder already does. No backend
//!   change (a `Pat::Record` nested in `Pat::Ctor.args` is already valid Rust).
//! * A CONS / LIST sub-pattern nested in a ctor payload (`Just (h :: t)`,
//!   `Just [a, b]`) — a `Vec<T>` enum FIELD cannot be slice-pattern-matched
//!   inline, so the arg lowers to a fresh `Vec` binder PLUS an arm-level length
//!   GUARD (`Arm::guard`, new `Expr::ListLenCheck`) PLUS a body prelude that
//!   recovers the named head elements by index (`Expr::ListIndexClone`) and the
//!   tail by `List.drop`. The guard makes the arm refutable exactly as Ipê's
//!   semantics require: `Just []` FALLS THROUGH to the fallback, never panics.
//!
//! Residual scope, kept fail-closed with a clean diagnostic (documented in
//! `docs/adr/0002-codegen-soundness-and-the-seal.md` Item C):
//!
//! * A guarded nested-cons arm with NO trailing catch-all is guard-non-exhaustive
//!   to rustc, so it stays IPE-L0116 rather than an accept-then-cargo-fail.

use std::path::{Path, PathBuf};

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry(root: &Path, name: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe")
}

fn built_code(root: &Path, name: &str) -> (Result<(), CliError>, PathBuf) {
    let entry = fixture_entry(root, name);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_emit"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = crate::support::expect_runtime(name, ipe::resolve_runtime());
    (ipe::build(&entry, &out, &runtime), out)
}

/// Build a green fixture, assert acceptance, and (under `IPE_E2E=1`) build the
/// emitted crate and assert its runtime stdout — the load-bearing verification
/// that a now-accepted shape does not exit-0-then-cargo-fail.
fn assert_accepted_runs(name: &str, expected_stdout: &str) {
    let root = repo_root();
    let (built, out) = built_code(&root, name);
    assert!(built.is_ok(), "{name}: must be accepted, got: {built:?}");

    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{name}: emitted crate must build and exit 0; stdout:\n{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim(),
        expected_stdout,
        "{name}: wrong runtime output"
    );
}

/// Assert `name` stays fail-closed with `expected` — a clean diagnostic, never
/// an accept-then-cargo-fail.
fn assert_gated(name: &str, expected: ipe_diagnostics::Code) {
    let root = repo_root();
    let (built, _out) = built_code(&root, name);
    let code = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        code,
        Some(expected),
        "{name}: must stay fail-closed with {expected:?}, got: {built:?}"
    );
}

// ── Repro 2: record sub-pattern nested in a ctor payload (was IPE-L0112) ─────

#[test]
fn nested_record_payload_accepted() {
    assert_accepted_runs("nested_record_payload", "Ada");
}

/// Residual-scope probe: a record nested TWO levels deep (`Ok (Just {name})`).
/// The spec predicted this works "for free" because the region-threading runs on
/// every level of `PCtor` recursion. Confirmed here rather than assumed.
#[test]
fn nested_record_two_levels_accepted() {
    assert_accepted_runs("nested_record_two_levels", "Ada");
}

// ── Repro 1: cons / list sub-pattern nested in a ctor payload (was IPE-L0116) ─

#[test]
fn nested_cons_payload_accepted() {
    assert_accepted_runs("nested_cons_payload", "1");
}

/// THE decisive soundness test: `Just []` must FALL THROUGH the `Just (h::t)`
/// guarded arm to the wildcard and print `0`, never panic.
#[test]
fn nested_cons_payload_fallthrough_prints_zero() {
    assert_accepted_runs("nested_cons_payload_fallthrough", "0");
}

/// A CLOSED list literal nested in a ctor payload (`Just [a, b]`) — exact-length
/// guard (`.len() == 2`) plus indexed head bindings.
#[test]
fn nested_cons_closed_list_accepted() {
    assert_accepted_runs("nested_cons_closed_list", "30");
}

/// A nested-cons payload whose element type flows through a generic function
/// parameter — the backend emits a `T: Clone` bound, so the clone / `List.drop`
/// are sound and the shape is accepted.
#[test]
fn nested_cons_generic_elem_accepted() {
    assert_accepted_runs("nested_cons_generic_elem", "1");
}

// ── Residual scope: guard-non-exhaustive stays fail-closed ───────────────────

/// A nested-cons arm set that is Ipê-exhaustive (`Just (h::t)` + `Just []` +
/// `Nothing`) but has NO trailing wildcard is guard-non-exhaustive to rustc, so
/// it stays IPE-L0116 rather than an accept-then-cargo-fail.
#[test]
fn nested_cons_no_fallback_stays_gated() {
    assert_gated("nested_cons_no_fallback_gated", ipe_diagnostics::IPE_L0116);
}

/// Adversarial-review sibling gap (Finding A): a `PStr` sub-pattern nested TWO
/// levels deep in a ctor payload (`Just (Just "x")`) — one hop past the
/// direct-arg string-literal desugaring's scope (`Just "x"` at depth 1, which
/// `nested_strlit_ctor_payload_accepted` below confirms still works). Must
/// stay fail-closed with IPE-L0116, never accept-then-cargo-fail (silent
/// acceptance would emit `IpeMaybe::Just(IpeMaybe::Just("x"))`
/// — E0308 at `cargo build`, expected `String` found `&str`).
#[test]
fn nested_strlit_two_levels_stays_gated() {
    assert_gated("nested_strlit_two_levels_gated", ipe_diagnostics::IPE_L0116);
}

/// Companion positive control: the depth-1 direct-arg string-literal ctor
/// payload (`Just "live"`) that the C2 desugaring DOES support must still
/// be accepted and run correctly — guards the sibling-gap fix above from
/// over-tightening the gate.
#[test]
fn nested_strlit_ctor_payload_accepted() {
    assert_accepted_runs("nested_strlit_ctor_payload", "live");
}
