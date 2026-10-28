//! A user local spelled like a bare-called global never shadows it.
//!
//! The backend calls every kernel by its bare runtime name
//! (`string_from_int(..)`), and a Rust `let` local shadows a same-named fn
//! item. Every user local holding an `_` is emitted escaped as `__u_…`, a
//! spelling no global carries, so the call still reaches the kernel: without
//! the escape `call-e0618` passes `ipe` but fails `cargo` with E0618 (a SEAL
//! break), and `same-sig-silent` builds and prints `user7/user1/user7` (a silent
//! miscompile).
//!
//! The emit tier pins the escaped spelling in the emitted Rust; behind
//! `IPE_E2E=1` each project must build and print its line.
use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn fixture_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests")
        .join("fixtures")
        .join("local-shadows-kernel")
        .join(name)
}

/// Emit `name`'s `Main.ipe` as a project into `out` and return the emitted `main.rs` text.
fn emit(name: &str, out: &Path) -> String {
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let source = std::fs::read_to_string(fixture_dir(&repo_root(), name).join("Main.ipe"));
    assert!(source.is_ok(), "{name}: the fixture source must read");
    let fixture = ipe::RootFixture::main(source.as_deref().unwrap_or_default());
    assert!(fixture.is_ok(), "{name}: the fixture project must resolve");
    let Ok(fixture) = fixture else {
        return String::new();
    };
    let built = ipe::build_fixture(&fixture, out, &runtime);
    assert!(
        built.is_ok(),
        "{name}: build failed: {:?}",
        built.as_ref().err()
    );
    crate::support::read_all_emitted_src(out)
}

/// The user local reaches Rust as `__u_string_from_int`, and the kernel is still called bare.
fn assert_emits_escaped(name: &str) {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("local_shadows_{name}_emit"));
    let emitted = emit(name, &out);
    assert!(
        emitted.contains("__u_string_from_int"),
        "{name}: the user local must be emitted as `__u_string_from_int`:\n{emitted}"
    );
    assert!(
        !emitted.contains("let string_from_int") && !emitted.contains("let mut string_from_int"),
        "{name}: the user local must not be emitted under the kernel's name:\n{emitted}"
    );
}

/// Build and run `name`'s emitted project behind `IPE_E2E=1` and check its stdout.
fn assert_runs(name: &str, expected: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let out = crate::support::scratch_root().join(format!("ipec_local_shadows_{name}_e2e"));
    let _ = emit(name, &out);
    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(outcome.stdout, expected, "{name}: wrong output");
    assert_eq!(outcome.exit_code, Some(0), "{name}: exit 0");
}

#[test]
fn a_local_spelled_like_a_kernel_does_not_break_its_call() {
    assert_emits_escaped("call-e0618");
    assert_runs("call-e0618", "6/6\n");
}

#[test]
fn a_same_typed_closure_spelled_like_a_kernel_is_not_called_for_it() {
    assert_emits_escaped("same-sig-silent");
    assert_runs("same-sig-silent", "user7/user1/7\n");
}
