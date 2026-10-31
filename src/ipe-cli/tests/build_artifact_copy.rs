#![forbid(unsafe_code)]
//! T4 (prove the refusal): `ipe dev build` copies the freshly built native binary
//! into `<project>/out/bin/<name>` so it is findable under the project even when
//! `CARGO_TARGET_DIR` points at a shared cache OUTSIDE the project. And the
//! clobber regression: two different projects with the same package name, built
//! into one shared target, each keep their own artifact — their emitted crates
//! are told apart by directory (the crate identity), and the per-project copy
//! preserves each project's own binary either way.
//!
//! Gated on `IPE_E2E=1` (drives a real `cargo build`).
//!
//! ```text
//! IPE_E2E=1 cargo nextest run -p ipe --test build_artifact_copy
//! ```

use std::fs;
use std::path::PathBuf;

use e2e_support::target::{BuildTarget, IsolationReason};
use ipe::RootFixture;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

const SRC_A: &str = "module Main exposing (main)\n\nimport Ipe.Io\n\nmain = Io.println \"AAA\"\n";
const SRC_B: &str = "module Main exposing (main)\n\nimport Ipe.Io\n\nmain = Io.println \"BBB\"\n";

/// One project built by `ipe dev build` into a shared target.
struct SharedBuild {
    /// The project's own copy, `<project>/out/bin/<friendly name>`.
    delivered: PathBuf,
    /// The artifact cargo left in the shared target.
    in_target: PathBuf,
    /// The emitted crate's identity (its `[package] name`).
    identity: String,
}

/// The crate identity the build derives for `project`: its package name joined
/// to a digest of its canonical directory.
fn identity_of(project: &RootFixture) -> Result<String, BoxError> {
    let canonical = project.path().canonicalize()?;
    Ok(
        ipe_backend_rust::crate_identity(ipe::project_root::DEFAULT_NAME, &canonical)
            .as_str()
            .to_owned(),
    )
}

/// A project holding `src`, in its own private directory.
fn project_of(src: &str) -> Result<RootFixture, BoxError> {
    RootFixture::main(src).map_err(|e| -> BoxError { format!("write the project: {e:?}").into() })
}

/// Run `ipe dev build <project> --out <out>/out` against `target`.
///
/// `target` is a directory OUTSIDE the project that every call for one test
/// shares, so every project builds into the same `<target>/debug/` — the
/// exact Ipê-recommended setup that leaves the binary unfindable without the
/// out/bin copy.
fn build_into_shared_target(
    tag: &str,
    project: &RootFixture,
    target: &BuildTarget,
) -> Result<SharedBuild, BoxError> {
    let ipe_bin = e2e_support::cargo_bin!("ipe");
    let runtime_dir = e2e_support::require_runtime().into_path_buf();

    let scratch = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ipe_build_artifact_copy_{tag}"));
    let _ = fs::remove_dir_all(&scratch);
    fs::create_dir_all(&scratch)?;
    let out_dir = scratch.join("out");

    let status = e2e_support::target::ipe_command(ipe_bin.path(), target)
        .args(["dev", "build"])
        .arg(project.path())
        .arg("--out")
        .arg(&out_dir)
        .env("IPE_RUNTIME_DIR", &runtime_dir)
        .env("NO_COLOR", "1")
        .status()
        .map_err(|e| -> BoxError { format!("spawn ipe dev build: {e}").into() })?;
    if !status.success() {
        return Err(format!("[{tag}] ipe dev build must succeed, got {status:?}").into());
    }

    let identity = identity_of(project)?;
    let emitted = ipe::emitted_bin_name(&out_dir.join("rust"))
        .map_err(|e| -> BoxError { format!("[{tag}] emitted crate name: {e:?}").into() })?;
    assert_eq!(
        emitted, identity,
        "[{tag}] the emitted crate is named by the project's package name and directory"
    );

    // The artifact lands at `<out>/bin/<friendly>` (sibling of `out/rust`). The
    // DELIVERED name is the friendly project name, independent of the internal
    // crate identity that owns the shared-target slot. Locate-by-emitted-name,
    // deliver-by-friendly-name mirrors the release path.
    let friendly = ipe_backend_rust::sanitize_cargo_name(ipe::project_root::DEFAULT_NAME);
    Ok(SharedBuild {
        delivered: out_dir.join("bin").join(friendly),
        in_target: target
            .path()
            .join("debug")
            .join(format!("{identity}{}", std::env::consts::EXE_SUFFIX)),
        identity,
    })
}

/// The copied binary exists, is executable, and byte-matches the artifact cargo
/// produced in the shared target.
#[test]
fn build_copies_the_artifact_into_project_out_bin() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    // An exclusive private tree: the test forces `ipe dev build` to write
    // into one directory it fully controls, outside the project, to prove
    // the out/bin copy (not the shared target's own bookkeeping).
    let isolated = e2e_support::target::isolated(IsolationReason::ColdBuildUnderTest)
        .map_err(|e| -> BoxError { format!("isolated build target: {e}").into() })?;
    let target = BuildTarget::Isolated(isolated);

    let project = project_of(SRC_A)?;
    let built = build_into_shared_target("single", &project, &target)?;
    let copied = built.delivered;
    assert!(
        copied.is_file(),
        "the built binary must be copied to {}",
        copied.display()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(&copied)?.permissions().mode();
        assert!(
            mode & 0o111 != 0,
            "the copied artifact must be executable, mode = {mode:o}"
        );
    }

    // Byte-match against the artifact in the shared target cargo produced.
    let (a, b) = (fs::read(&copied)?, fs::read(&built.in_target)?);
    assert_eq!(
        a, b,
        "out/bin copy must be byte-identical to the shared-target artifact"
    );

    Ok(())
}

/// Clobber regression: build project A, then a DIFFERENT project B with the same
/// package name into the SAME shared target. Their emitted crates are told apart
/// by directory, so B's build leaves A's shared-target binary alone, and A's own
/// `out/bin/ipe-app` is still A's binary (it was copied within A's build).
#[test]
fn a_second_same_named_project_does_not_clobber_the_first_out_bin() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    // An exclusive private tree, shared across projects A and B within this
    // one test, to reproduce the exact Ipê-recommended setup of two projects
    // building into one shared target.
    let isolated = e2e_support::target::isolated(IsolationReason::ColdBuildUnderTest)
        .map_err(|e| -> BoxError { format!("isolated build target: {e}").into() })?;
    let target = BuildTarget::Isolated(isolated);

    // Project A → out/bin/ipe-app is A's binary.
    let project_a = project_of(SRC_A)?;
    let a = build_into_shared_target("clobberA", &project_a, &target)?;
    let a_before = fs::read(&a.delivered)?;
    let a_in_target_before = fs::read(&a.in_target)?;

    // Project B, same package name, same shared target.
    let project_b = project_of(SRC_B)?;
    let b = build_into_shared_target("clobberB", &project_b, &target)?;
    let b_after = fs::read(&b.delivered)?;

    assert_ne!(
        a.identity, b.identity,
        "same-named projects in different directories must get distinct crate identities"
    );

    // A's project-local copy is UNCHANGED — still A's binary, not B's.
    let a_after = fs::read(&a.delivered)?;
    assert_eq!(
        a_before, a_after,
        "project A's out/bin/ipe-app must survive project B's same-name build into the shared target"
    );
    assert_ne!(
        a_after, b_after,
        "A's and B's project-local artifacts must differ (each kept its own binary)"
    );
    assert_eq!(
        a_in_target_before,
        fs::read(&a.in_target)?,
        "project B's build must not overwrite project A's shared-target binary"
    );

    Ok(())
}
