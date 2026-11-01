#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::panic)] // test setup: a failed build/write IS the failure
//! The load-bearing soundness proof for the coverage probe's warm-shared-target
//! build (`ipe::coverage::probe::build_and_run`).
//!
//! The probe links each per-symbol emitted crate's heavy dependency tree from a
//! warm shared cargo target (`IPE_ORACLE_SHARED_TARGET`) instead of cold-building
//! it per symbol. That is sound ONLY because every probe's emitted APP crate gets
//! a UNIQUE package name (a project's crate identity joins its package name to
//! a digest of its canonical directory): cargo fingerprints an app crate on its own source hash under its own
//! package id, so a genuinely broken emit still fails to build even against a warm
//! target — the shared target reuses only DEPENDENCY artifacts, never masking a
//! broken app. If two probes instead shared ONE package name in ONE target, cargo
//! could reuse a prior probe's compiled crate and green a broken emit, defeating
//! the seal the coverage sweep exists to hold.
//!
//! This test drives the real project emit path (`ipe dev build` on two project
//! directories, as a subprocess) into ONE shared cargo target: a well-typed
//! crate warms the target and builds; a second crate — emitted under its own
//! unique package name, then corrupted with an injected Rust type error —
//! MUST fail to `cargo build` even though the target is warm. Gated on
//! `IPE_E2E=1` (it invokes cargo) like the other build tests.

use std::fs;
use std::path::Path;

use e2e_support::target::BuildTarget;
use ipe::RootFixture;

/// A minimal Ipê program that emits, builds, and runs.
const SRC: &str = "module Main exposing (main)\n\nimport Ipe.Io\n\nmain = Io.println \"ok\"\n";

/// The `ipe` binary under test, proven to exist; fails the test otherwise.
fn ipe_bin() -> std::path::PathBuf {
    e2e_support::cargo_bin!("ipe").into_path_buf()
}

/// A project holding [`SRC`], in its own private directory.
fn project() -> RootFixture {
    RootFixture::main(SRC).expect("the probe project resolves")
}

/// The crate identity the build derives for `project`: its package name joined
/// to a digest of its canonical directory.
fn identity_of(project: &RootFixture) -> String {
    let canonical = project
        .path()
        .canonicalize()
        .expect("canonical project dir");
    ipe_backend_rust::crate_identity(ipe::project_root::DEFAULT_NAME, &canonical)
        .as_str()
        .to_owned()
}

/// Emit `project` into `dir/out` via a subprocess `ipe dev build`, building
/// into `shared_target`.
/// Returns the emitted-project dir and whether `ipe dev build` succeeded.
fn ipe_build_into_shared(
    ipe: &Path,
    project: &RootFixture,
    dir: &Path,
    target: &BuildTarget,
) -> (std::path::PathBuf, bool) {
    let out_dir = dir.join("out");

    let status = e2e_support::target::ipe_command(ipe, target)
        .arg("dev")
        .arg("build")
        .arg(project.path())
        .arg("--out")
        .arg(&out_dir)
        .env("CARGO_BUILD_RUSTC_WRAPPER", "")
        .env("RUSTC_WRAPPER", "")
        .env("NO_COLOR", "1")
        .status()
        .expect("ipe dev build must spawn");
    // `--out` names the output root; the emitted crate is its `rust/` area.
    (out_dir.join("rust"), status.success())
}

/// Re-run `cargo build` on an already-emitted project into `target`, returning
/// cargo's success plus its stderr.
fn cargo_build_into_shared(out_dir: &Path, target: &BuildTarget) -> (bool, String) {
    let out = e2e_support::target::cargo_command(target)
        .arg("build")
        .current_dir(out_dir)
        .output()
        .expect("cargo must spawn");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A well-typed emit warms the shared target and builds; a second emit — under
/// its own unique crate identity, then corrupted with an injected type error and
/// re-built into the SAME warm target — MUST fail, proving the dep cache never
/// masks a broken app.
#[test]
fn probe_shared_target_never_masks_a_broken_emit() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let ipe = ipe_bin();
    // `ipe dev build` resolves the runtime itself; prove this host has one.
    let _runtime = e2e_support::require_runtime();

    let root = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ipe_probe_soundness_{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);

    // ONE exclusive tree, reused by every build below — the test's whole point
    // is proving that two app crates sharing this one warm target still
    // fingerprint independently, so a fresh tree per call would defeat it.
    let isolated =
        e2e_support::target::isolated(e2e_support::target::IsolationReason::ColdBuildUnderTest);
    let Ok(isolated) = isolated else {
        panic!("isolated build target: {isolated:?}")
    };
    let target = BuildTarget::Isolated(isolated);

    // 1. Well-typed emit → warms the shared target and builds under its own name.
    let good_project = project();
    let (good_out, good_ok) =
        ipe_build_into_shared(&ipe, &good_project, &root.join("good"), &target);
    assert!(
        good_ok,
        "the well-typed emit must build into the shared target"
    );
    let good_identity = identity_of(&good_project);
    let good_manifest =
        fs::read_to_string(good_out.join("Cargo.toml")).expect("emitted Cargo.toml");
    assert!(
        good_manifest.contains(&format!("name = \"{good_identity}\"")),
        "the emit must carry its crate identity (fingerprint isolation):\n{good_manifest}"
    );

    // 2. Second emit under its OWN unique name → warms/builds, then corrupt its
    //    emitted `main.rs` and rebuild into the warm target: it MUST fail.
    let bad_project = project();
    let (bad_out, bad_ok) = ipe_build_into_shared(&ipe, &bad_project, &root.join("bad"), &target);
    assert!(bad_ok, "the second emit must build clean before corruption");
    let bad_identity = identity_of(&bad_project);
    assert_ne!(
        good_identity, bad_identity,
        "two projects sharing a target must get distinct crate identities by directory alone"
    );
    let bad_manifest = fs::read_to_string(bad_out.join("Cargo.toml")).expect("emitted Cargo.toml");
    assert!(
        bad_manifest.contains(&format!("name = \"{bad_identity}\"")),
        "the second emit must carry its own crate identity:\n{bad_manifest}"
    );

    let main_rs = bad_out.join("src").join("main.rs");
    let mut source = fs::read_to_string(&main_rs).expect("read emitted main.rs");
    source.push_str("\nconst _IPE_PROBE_SOUNDNESS_BREAK: u32 = \"not a number\";\n");
    fs::write(&main_rs, source).expect("inject type error into emitted main.rs");

    let (rebuilt_ok, rebuilt_err) = cargo_build_into_shared(&bad_out, &target);
    assert!(
        !rebuilt_ok,
        "SOUNDNESS BREACH: a probe crate with an injected type error built successfully into the \
         warm shared target — the dep cache masked a broken app. The SEAL is only sound if this \
         build FAILS.\n{rebuilt_err}"
    );
    assert!(
        rebuilt_err.contains("E0308"),
        "the broken emit must fail with the injected type mismatch (E0308):\n{rebuilt_err}"
    );

    let _ = fs::remove_dir_all(&root);
}

/// The unit-level guard: two DISTINCT probe scratch dirs yield two DISTINCT,
/// valid Cargo package names (the property that keeps app-crate fingerprints
/// from colliding in a shared target), exercised through the public
/// `sanitize_cargo_name` the probe derives its per-crate name with.
#[test]
fn distinct_probe_dirs_yield_distinct_package_names() {
    let a = ipe_backend_rust::sanitize_cargo_name("ipe-coverage-probe-abc123");
    let b = ipe_backend_rust::sanitize_cargo_name("ipe-coverage-probe-def456");
    assert_ne!(
        a, b,
        "distinct scratch dirs must map to distinct crate names"
    );
    assert!(
        !a.is_empty() && !b.is_empty(),
        "a derived crate name is never empty"
    );
}
