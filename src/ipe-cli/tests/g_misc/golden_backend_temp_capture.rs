//! A user local spelled like a backend temporary keeps its own value.
//!
//! The backend mints locals such as `__ipe_bind_0`, `__ipe_box_0` and
//! `_ipe_recursion_guard`, and the lexer admits a user identifier spelled the
//! same. Every `_`-leading user local other than the bare `_` is emitted
//! escaped as `__u_…`, outside the temporary namespace, so the temporary can no
//! longer shadow it: without the escape `bind-shadow` prints `5` (a silent
//! miscompile), and `bind-type`, `box-shadow` and `guard-shadow` pass `ipe` but
//! fail `cargo` (a SEAL break).
//!
//! The emit tier pins the escaped spelling in the emitted Rust; behind
//! `IPE_E2E=1` each project must build and print its line.
use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn fixture_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests")
        .join("fixtures")
        .join("backend-temp-capture")
        .join(name)
}

/// Emit `name`'s `Main.ipe` into `out` and return the emitted `main.rs` text.
fn emit(name: &str, out: &Path) -> String {
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(
        &fixture_dir(&repo_root(), name).join("Main.ipe"),
        out,
        &runtime,
    );
    assert!(built.is_ok(), "{name}: build failed: {:?}", built.err());
    crate::support::read_all_emitted_src(out)
}

/// The user local reaches Rust as `escaped`, never as the bare temporary spelling.
fn assert_emits_escaped(name: &str, escaped: &str) {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("temp_capture_{name}_emit"));
    let emitted = emit(name, &out);
    assert!(
        emitted.contains(escaped),
        "{name}: the user local must be emitted as `{escaped}`:\n{emitted}"
    );
}

/// Build and run `name`'s emitted project behind `IPE_E2E=1` and check its stdout.
fn assert_runs(name: &str, expected: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let out = crate::support::scratch_root().join(format!("ipec_temp_capture_{name}_e2e"));
    let _ = emit(name, &out);
    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(outcome.stdout, expected, "{name}: wrong output");
    assert_eq!(outcome.exit_code, Some(0), "{name}: exit 0");
}

#[test]
fn a_param_spelled_like_the_tuple_temp_is_escaped() {
    assert_emits_escaped("bind-shadow", "__u__ipe_bind_0");
}

#[test]
fn a_param_spelled_like_the_tuple_temp_keeps_its_value() {
    assert_runs("bind-shadow", "100\n");
}

#[test]
fn a_param_spelled_like_the_tuple_temp_keeps_its_type() {
    assert_emits_escaped("bind-type", "__u__ipe_bind_0");
    assert_runs("bind-type", "hi0\n");
}

#[test]
fn a_binder_spelled_like_the_box_temp_stays_distinct() {
    assert_emits_escaped("box-shadow", "__u__ipe_box_0");
    assert_runs("box-shadow", "42\n");
}

#[test]
fn a_param_spelled_like_the_recursion_guard_keeps_its_value() {
    assert_emits_escaped("guard-shadow", "__u_ipe_recursion_guard");
    assert_runs("guard-shadow", "42\n");
}
