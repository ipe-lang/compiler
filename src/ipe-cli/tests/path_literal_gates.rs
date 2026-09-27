//! `path "…"` literal — compile-time validation gates (IPE-P0063) and
//! positive E2E.
//!
//! Tests:
//! (a) A valid `path "src/Main.ipe"` literal compiles, lowers, and runs,
//!     printing the cleaned path string. (`IPE_E2E=1` required for the
//!     build+run step.)
//! (b) `path "../etc/passwd"` is a compile-time IPE-P0063 error — the `..`
//!     traversal escape is caught at the canonicalise stage.
//! (c) `path "safe\0bad"` (NUL byte) is a compile-time IPE-P0063 error.
//! (d) `path` used as a plain identifier (not followed by a string literal)
//!     compiles and runs normally — contextual keyword regression.

use std::path::{Path, PathBuf};

mod support;

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_entry(name: &str) -> PathBuf {
    repo_root()
        .join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe")
}

fn e2e_enabled() -> bool {
    std::env::var("IPE_E2E").is_ok()
}

/// Compile, build, and run the named golden fixture; return the captured
/// output. Fails the test on any build or runtime error.
fn compile_build_run(name: &str) -> support::RunOutcome {
    let entry = golden_entry(name);
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else {
        return support::RunOutcome {
            stdout: String::new(),
            exit_code: None,
        };
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    support::build_and_run_emitted(name, &out)
}

/// Build the named golden fixture and assert that it surfaces exactly
/// `expected` as a pipeline diagnostic.
fn assert_compile_error(fixture: &str, out_suffix: &str, expected: ipe_diagnostics::Code) {
    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let entry = golden_entry(fixture);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(out_suffix);
    let _ = std::fs::remove_dir_all(&out);

    let built = ipe::build(&entry, &out, &runtime);
    let got = match &built {
        Err(ipe::CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(expected),
        "fixture {fixture}: expected {expected:?}, got build result {built:?}"
    );
}

// ── (a) valid path literal compiles and runs ─────────────────────────────────

/// `path "src/Main.ipe"` is a valid compile-time-checked path literal with
/// type `Path`. `Path.toString` on it must print the cleaned form.
#[test]
fn valid_path_literal_builds_and_prints() {
    if !e2e_enabled() {
        return;
    }
    let out = compile_build_run("path_literal_valid");
    assert_eq!(
        out.exit_code,
        Some(0),
        "unexpected exit: {:?}",
        out.exit_code
    );
    assert_eq!(
        out.stdout.trim(),
        "src/Main.ipe",
        "path literal must print its cleaned value"
    );
}

// ── (b) `..` traversal escape is a compile error ─────────────────────────────

/// `path "../etc/passwd"` must be rejected at compile time (IPE-P0063) — the
/// `..`-traversal escape is caught in the canonicalise stage.
#[test]
fn traversal_path_literal_is_rejected() {
    assert_compile_error(
        "path_literal_traversal_rejected",
        "path_literal_traversal_rejected_emit",
        ipe_diagnostics::IPE_P0063,
    );
}

// ── (c) NUL byte in path literal is a compile error ──────────────────────────

/// `path "safe\0bad"` must be rejected at compile time (IPE-P0063) — a NUL
/// byte is a syscall-boundary truncation risk.
#[test]
fn nul_path_literal_is_rejected() {
    assert_compile_error(
        "path_literal_nul_rejected",
        "path_literal_nul_rejected_emit",
        ipe_diagnostics::IPE_P0063,
    );
}

// ── (d) `path` as plain identifier still works ───────────────────────────────

/// `path` is a contextual keyword: only special when immediately followed by a
/// string literal. As a plain binding name it must compile and run normally.
#[test]
fn path_as_identifier_still_compiles() {
    if !e2e_enabled() {
        return;
    }
    let out = compile_build_run("path_as_ident");
    assert_eq!(
        out.exit_code,
        Some(0),
        "unexpected exit: {:?}",
        out.exit_code
    );
    assert_eq!(
        out.stdout.trim(),
        "not a path literal",
        "`path` used as an identifier must print its value normally"
    );
}
