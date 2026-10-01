#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::panic)] // test setup: a failed build/write IS the failure
//! The load-bearing soundness proof for the coverage probe's warm-shared-target
//! build (`ipe::coverage::probe::build_and_run`).
//!
//! The probe links each per-symbol emitted crate's heavy dependency tree from a
//! warm shared cargo target (`IPE_ORACLE_SHARED_TARGET`) instead of cold-building
//! it per symbol. That is sound ONLY because every probe's emitted APP crate gets
//! a UNIQUE package name (`IPE_EMIT_PACKAGE_NAME`, honoured by the single-file
//! emit): cargo fingerprints an app crate on its own source hash under its own
//! package id, so a genuinely broken emit still fails to build even against a warm
//! target — the shared target reuses only DEPENDENCY artifacts, never masking a
//! broken app. If two probes instead shared ONE package name in ONE target, cargo
//! could reuse a prior probe's compiled crate and green a broken emit, defeating
//! the seal the coverage sweep exists to hold.
//!
//! This test drives the real single-file emit path (`ipe build` with
//! `IPE_EMIT_PACKAGE_NAME` set, as a subprocess) into ONE shared cargo target: a
//! well-typed crate warms the target and builds; a second crate — emitted under
//! its own unique package name, then corrupted with an injected Rust type error —
//! MUST fail to `cargo build` even though the target is warm. Gated on
//! `IPE_E2E=1` (it invokes cargo) like the other build tests.

use std::fs;
use std::path::Path;
use std::process::Command;

/// A minimal single-file Ipê program that emits, builds, and runs.
const SRC: &str = "module Main exposing (main)\n\nimport Ipe.Io\n\nmain = Io.println \"ok\"\n";

/// The `ipe` binary under test, proven to exist; fails the test otherwise.
fn ipe_bin() -> std::path::PathBuf {
    e2e_support::cargo_bin!("ipe").into_path_buf()
}

/// Emit `SRC` at `dir/Main.ipe` into `dir/out` via a subprocess `ipe build`,
/// naming the emitted crate `package_name` and building into `shared_target`.
/// Returns the emitted-project dir and whether `ipe build` succeeded.
fn ipe_build_into_shared(
    ipe: &Path,
    dir: &Path,
    package_name: &str,
    shared_target: &Path,
) -> (std::path::PathBuf, bool) {
    let entry = dir.join("Main.ipe");
    fs::create_dir_all(dir)
        .and_then(|()| fs::write(&entry, SRC))
        .expect("write source");
    let out_dir = dir.join("out");

    let status = Command::new(ipe)
        .arg("build")
        .arg(&entry)
        .arg("--out")
        .arg(&out_dir)
        .env("IPE_EMIT_PACKAGE_NAME", package_name)
        .env("CARGO_TARGET_DIR", shared_target)
        .env("CARGO_BUILD_RUSTC_WRAPPER", "")
        .env("RUSTC_WRAPPER", "")
        .env("NO_COLOR", "1")
        .status()
        .expect("ipe build must spawn");
    // `--out` names the output root; the emitted crate is its `rust/` area.
    (out_dir.join("rust"), status.success())
}

/// Re-run `cargo build` on an already-emitted project into `shared_target`,
/// returning cargo's success plus its stderr.
fn cargo_build_into_shared(out_dir: &Path, shared_target: &Path) -> (bool, String) {
    let out = Command::new("cargo")
        .arg("build")
        .current_dir(out_dir)
        .env("CARGO_TARGET_DIR", shared_target)
        .env("CARGO_BUILD_RUSTC_WRAPPER", "")
        .env("RUSTC_WRAPPER", "")
        .output()
        .expect("cargo must spawn");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A well-typed emit warms the shared target and builds; a second emit — given
/// its own unique package name, then corrupted with an injected type error and
/// re-built into the SAME warm target — MUST fail, proving the dep cache never
/// masks a broken app.
#[test]
fn probe_shared_target_never_masks_a_broken_emit() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let ipe = ipe_bin();
    // `ipe build` resolves the runtime itself; prove this host has one.
    let _runtime = e2e_support::require_runtime();

    let root = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ipe_probe_soundness_{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let shared_target = root.join("shared-target");

    // 1. Well-typed emit → warms the shared target and builds under its own name.
    let (good_out, good_ok) =
        ipe_build_into_shared(&ipe, &root.join("good"), "ipe-probe-good", &shared_target);
    assert!(
        good_ok,
        "the well-typed emit must build into the shared target"
    );
    let good_manifest =
        fs::read_to_string(good_out.join("Cargo.toml")).expect("emitted Cargo.toml");
    assert!(
        good_manifest.contains("name = \"ipe-probe-good\""),
        "the emit must carry the unique package name (fingerprint isolation):\n{good_manifest}"
    );

    // 2. Second emit under its OWN unique name → warms/builds, then corrupt its
    //    emitted `main.rs` and rebuild into the warm target: it MUST fail.
    let (bad_out, bad_ok) =
        ipe_build_into_shared(&ipe, &root.join("bad"), "ipe-probe-bad", &shared_target);
    assert!(bad_ok, "the second emit must build clean before corruption");

    let main_rs = bad_out.join("src").join("main.rs");
    let mut source = fs::read_to_string(&main_rs).expect("read emitted main.rs");
    source.push_str("\nconst _IPE_PROBE_SOUNDNESS_BREAK: u32 = \"not a number\";\n");
    fs::write(&main_rs, source).expect("inject type error into emitted main.rs");

    let (rebuilt_ok, rebuilt_err) = cargo_build_into_shared(&bad_out, &shared_target);
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
