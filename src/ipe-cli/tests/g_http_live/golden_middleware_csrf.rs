//! `Ipe.Http.Middleware.withCsrf` golden.
//!
//! Pins that a `Ipe.Http.Server` route wrapped in `Middleware.withCsrf` emits
//! `middleware_with_csrf(...)` and that the emitted crate `cargo build`s (the
//! Seal: `ipe` exit 0 implies `cargo build` exit 0).
//!
//! Compile-only assertions always run; the cargo build is `IPE_E2E=1`-gated and
//! runs through `e2e_support::build_rust_binary` (unique package name → fresh
//! app fingerprint, warm shared dependency target reused). A broken emit still
//! fails to build, so the SEAL stays sound.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn out_dir() -> PathBuf {
    crate::support::scratch_root().join("ipec_m6_middleware_csrf")
}

/// Compile the fixture into `out`.
fn compile(out: &Path) -> Result<(), ipe::CliError> {
    let entry = repo_root()
        .join("tests")
        .join("golden")
        .join("middleware_csrf")
        .join("Main.ipe");
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, out, &runtime)
}

/// A `Server.post` route wrapped in `Middleware.withCsrf` must be ipe-0 and
/// emit `middleware_with_csrf(...)` wrapping the handler.
#[test]
fn middleware_with_csrf_emits_wrapped_handler() {
    let result = compile(&out_dir());
    assert!(
        result.is_ok(),
        "#63: Middleware.withCsrf-wrapped route must be ipe-0, got: {:?}",
        result.err(),
    );
    let main_rs = crate::support::read_all_emitted_src(&out_dir());
    assert!(
        main_rs.contains("middleware_with_csrf("),
        "#63: emitted user source must call middleware_with_csrf(...)\n{main_rs}",
    );
}

/// `IPE_E2E` tier: the emitted project must cargo-build (shared `e2e_support`
/// core: unique package, warm dep target)
/// — proves the seal (ipe exit 0 implies cargo build exit 0) for the new
/// `ServerResponse.cookies` field and the `middleware_with_csrf` kernel.
#[test]
fn middleware_with_csrf_cargo_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    // Emit into a PRIVATE dir this test alone owns, so the compile-only sibling
    // re-emitting into `out_dir()` in parallel cannot delete rustc's working
    // directory mid-build.
    let out = crate::support::scratch_root().join("ipec_m6_middleware_csrf_e2e");
    let result = compile(&out);
    assert!(
        result.is_ok(),
        "Middleware.withCsrf-wrapped route must be ipe-0, got: {:?}",
        result.err(),
    );

    let built = e2e_support::build_rust_binary("middleware_csrf", &out);
    assert!(
        built.is_ok(),
        "#63: Middleware.withCsrf project must cargo-build\n{}",
        built.err().unwrap_or_default(),
    );
}
