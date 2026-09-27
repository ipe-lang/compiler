//! End-to-end gate: `ipe` must emit `main.rs` byte-identical to the
//! the compiler-reference golden, and (behind `IPE_E2E=1`) the emitted project must
//! build and print `1`.

use std::path::{Path, PathBuf};

/// The `ipe-lang` workspace root (two levels up from this crate's manifest).
fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn emits_byte_identical_main_rs_as_runtime_dependency() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("basics")
        .join("Main.ipe");
    let golden = root
        .join("tests")
        .join("golden")
        .join("basics")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m0_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve: {:?}", runtime.err());
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    // Directory-diff the emitted project against the golden dir: asserts the
    // emitted `src/main.rs` (and the golden's checked-in root `Cargo.toml`)
    // match byte-for-byte. Replaces the former hand-rolled `read_to_string` +
    // `assert_eq!` pair — proven equal in discriminating power side by side
    // before that block was removed.
    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );

    // The default native emit is the dependency model: no runtime source is
    // vendored into the user crate, and the manifest declares the runtime as a
    // path dependency instead. Assert both — the absence of the vendored tree
    // and the presence of the dependency line.
    assert!(
        !out.join("src").join("ipe_runtime").exists(),
        "the dependency-model emit must NOT vendor a runtime tree into the user crate",
    );
    let manifest =
        std::fs::read_to_string(out.join("Cargo.toml")).expect("emitted Cargo.toml must exist");
    assert!(
        manifest.contains("package = \"ipe-runtime-rust\""),
        "the manifest must declare the runtime as a path dependency; got:\n{manifest}",
    );
}

/// Full spine: compile, build the emitted Cargo project, and run it. Gated on
/// `IPE_E2E=1` so the default `cargo test` stays fast (the emitted project pulls
/// real crates and takes ~1 min to compile cold).
#[test]
fn end_to_end_builds_and_prints_one() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("basics")
        .join("Main.ipe");
    // Build OUTSIDE the workspace tree: an emitted project under the workspace's
    // own target/ dir is (correctly) rejected by cargo as a non-member package,
    // and the golden Cargo.toml carries no detaching `[workspace]` stanza.
    let out = crate::support::scratch_root().join("ipec_m0_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("basics", &out);
    crate::support::assert_go_parity(
        "basics",
        &repo_root().join("tests").join("golden").join("basics"),
        &outcome.stdout,
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

/// A `CliError::Pipeline` must render as a coded, prose-first report — not a
/// `{:?}` debug dump. We feed `build` a deliberately ill-formed `.ipe` source and
/// assert the displayed error carries a `-- … ERROR` title rule, its `IPE-…`
/// code, and the `ipe explain` footer pointer.
#[test]
fn pipeline_error_renders_with_code_and_explain_pointer() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("pipeline_err");
    let _ = std::fs::create_dir_all(&dir);
    let entry = dir.join("Bad.ipe");
    // Malformed: a top-level declaration with no right-hand side. This is
    // rejected at the parse stage boundary, the first pipeline stage.
    let wrote = std::fs::write(&entry, "module Main exposing (main)\n\nmain =\n");
    assert!(wrote.is_ok(), "must write ill-formed source");

    // The runtime dir is never reached: the parse error fires first. Pass a
    // path that need not exist.
    let runtime = dir.join("no-runtime");
    let built = ipe::build(&entry, &dir.join("out"), &runtime);

    assert!(
        matches!(&built, Err(ipe::CliError::Pipeline { .. })),
        "expected a pipeline error, got: {built:?}"
    );
    let Err(err) = built else { return };

    let rendered = err.to_string();
    assert!(
        rendered.starts_with("-- ") && !rendered.contains("(warning)"),
        "rendered error must lead with an error title rule, got:\n{rendered}"
    );
    assert!(
        rendered.contains("IPE-"),
        "rendered error must carry its code in the footer, got:\n{rendered}"
    );
    assert!(
        rendered.contains("ipe doc"),
        "rendered error must point at `ipe doc`, got:\n{rendered}"
    );
}
