//! SEAL for the runtime-shape field-NAME SSOT (`ipe_ir::record_shapes`).
//!
//! Several Ipê record shapes fold to a nominal runtime struct: `ipe_lower`
//! intercepts a shape whose field NAMES *and* TYPES match into an opaque
//! `IrType` variant (so it never reaches the struct registry), and
//! `ipe_backend_rust`'s name-only fallback reconstructs the runtime struct name
//! from its own copy of the field-NAME set. Those two name sets are now ONE
//! definition in `ipe_ir::record_shapes`, and the lower-side name+type tables
//! bind their NAME column to it with `const _: ()` asserts — a drift is a
//! `cargo build` failure in `ipe_lower`.
//!
//! This golden is the defense-in-depth half: a `CacheCfg` and a `Response`
//! record literal (each fed to / read as its nominal runtime shape) must emit
//! the runtime struct (`CacheCfg { .. }` / `ServerResponse { .. }`), NOT a
//! backend-synthesised `Rec…`. A synthesised struct would mismatch the kernel's
//! nominal param and fail `cargo build` (E0308/E0063/E0560): the exact
//! `ipe`-exit-0-then-`cargo`-fail shape THE SEAL forbids.
//!
//! The first test inspects the emitted Rust text (no cargo build) so it runs in
//! the DEFAULT gate; the second is the `IPE_E2E`-gated build-and-run proof.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("runtime_shape_fold_seal")
        .join("Main.ipe")
}

/// Recursively concatenate every emitted `.rs` file under `dir`.
fn concat_emitted_rs(dir: &Path, out: &mut String) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            concat_emitted_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs")
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            out.push_str(&text);
            out.push('\n');
        }
    }
}

/// Build the fixture and return the concatenated emitted APP Rust source
/// (`src/main.rs` + `src/ipe_mods/`), scanning past the vendored
/// `src/ipe_runtime/` so the runtime's own struct definitions do not mask what
/// the app-side codegen chose. `None` when the build failed (the caller's
/// `assert!` reports the diag).
fn built_app_rs(root: &Path, out: &Path) -> (Result<(), ipe::CliError>, Option<String>) {
    let entry = fixture_entry(root);
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, out, &runtime);
    let emitted = if built.is_ok() {
        let mut acc = std::fs::read_to_string(out.join("src").join("main.rs")).unwrap_or_default();
        acc.push('\n');
        concat_emitted_rs(&out.join("src").join("ipe_mods"), &mut acc);
        Some(acc)
    } else {
        None
    };
    (built, emitted)
}

/// The raw `CacheCfg` / `Response` record literals must emit the runtime
/// structs the kernels take, NOT backend-synthesised `Rec…` structs.
#[test]
fn runtime_shape_literals_emit_nominal_structs() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_runtime_shape_fold_seal_emit");
    let (built, app_rs) = built_app_rs(&root, &out);
    assert!(
        built.is_ok(),
        "runtime_shape_fold_seal: must be accepted, got: {built:?}"
    );
    let app_rs = app_rs.expect("an accepted build yields the emitted source");

    assert!(
        app_rs.contains("CacheCfg {"),
        "the raw `CacheCfg` record literal fed to `Cache.new` must emit a \
         `CacheCfg {{ .. }}` runtime struct literal.\n--- emitted ---\n{app_rs}"
    );
    assert!(
        app_rs.contains("ServerResponse {"),
        "the raw `Response` record literal must emit a `ServerResponse {{ .. }}` \
         runtime struct literal.\n--- emitted ---\n{app_rs}"
    );
    // The name-only fallback appends the runtime-only `cookies` field for the
    // `ServerResponse` fold — its presence proves the fallback fired.
    assert!(
        app_rs.contains("cookies: Vec::new()"),
        "the `ServerResponse` fold must default the runtime-only `cookies` \
         field.\n--- emitted ---\n{app_rs}"
    );
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, `cargo build` the emitted
/// crate and run it. A synthesised `Rec…` fold would fail `cargo build`; the
/// nominal folds build and print `200` (empty new cache `size` 0 + response
/// `status` 200).
#[test]
fn runtime_shape_fold_seal_builds_and_runs() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_runtime_shape_fold_seal_e2e");
    let runtime = e2e_support::require_runtime().into_path_buf();
    let entry = fixture_entry(&root);
    let _ = std::fs::remove_dir_all(&out);
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "runtime_shape_fold_seal: must be accepted, got: {built:?}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let outcome = crate::support::build_and_run_emitted("runtime_shape_fold_seal", &out);
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "runtime_shape_fold_seal: emitted crate must build and exit 0; stdout:\n{}",
            outcome.stdout
        );
        assert_eq!(outcome.stdout.trim(), "200", "wrong runtime output");
    }
}
