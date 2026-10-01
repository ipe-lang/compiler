//! Regression: `ipe build` must propagate a failed emitted-crate `cargo build`
//! as a non-zero `ipe` exit — never report success while its cargo step failed.
//!
//! The cheap-gate SEAL depends on this: an exit-0-then-cargo-fail miscompile is
//! exactly the failure the gate exists to surface, so a `build` path that emits
//! a crate and then either skips compiling it, or swallows a non-zero cargo
//! exit, would silently hide a bad emit.
//!
//! This spawns the real `ipe` binary with a fake `cargo` on the `PATH` that
//! always exits non-zero (emitting an `E0609`-shaped stderr, the concrete miss
//! that first exposed the bug). The emit itself needs no external tool, so the
//! only cargo invocation is the emitted-crate compile — which fails. A `build`
//! that never runs cargo, or runs it and drops the failure, would exit 0 here
//! and fail this test.

use std::fs;
use std::path::Path;

/// Write an executable fake `cargo` at `dir/cargo` that prints an `E0609`-shaped
/// error to stderr and exits 1 for a `build` invocation, and prints a minimal
/// valid `cargo metadata` JSON for a `metadata` invocation (so any metadata
/// probe on the path does not itself spawn-fail before the build is reached).
#[cfg(unix)]
fn write_failing_cargo(dir: &Path) -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;
    let script = "#!/bin/sh\n\
         case \"$1\" in\n\
         metadata) echo '{\"target_directory\":\"/tmp/ipe-fake-target\"}'; exit 0 ;;\n\
         *) echo 'error[E0609]: no field `nope` on type `Foo`' 1>&2; exit 1 ;;\n\
         esac\n";
    let path = dir.join("cargo");
    fs::write(&path, script)?;
    let mut perms = fs::metadata(&path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms)?;
    Ok(path)
}

/// The failing-cargo propagation gate. Unix-only: it relies on a shell fake
/// `cargo` and on `PATH` scrubbing to guarantee the fake is the one resolved.
#[cfg(unix)]
#[test]
#[allow(clippy::panic)] // a refused precondition is the test failure
fn build_propagates_a_failed_emitted_cargo_build() {
    const SRC: &str = "module Main exposing (main)\n\nimport Ipe.Io\n\nmain = Io.println \"hi\"\n";

    // The runtime dir must resolve for the emit to reach the cargo step.
    let runtime_dir = e2e_support::require_runtime().into_path_buf();

    let ipe_bin = e2e_support::cargo_bin!("ipe");

    let dir =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipe_build_cargo_fail_e2e");
    let _ = fs::remove_dir_all(&dir);
    let bin_dir = dir.join("fakebin");
    let entry = dir.join("Main.ipe");
    let out_dir = dir.join("out");
    let setup = fs::create_dir_all(&bin_dir).and_then(|()| fs::write(&entry, SRC));
    assert!(setup.is_ok(), "write source + fake-bin dir: {setup:?}");

    let fake_cargo = write_failing_cargo(&bin_dir);
    assert!(fake_cargo.is_ok(), "write fake cargo: {fake_cargo:?}");

    // PATH holds ONLY the fake-bin dir, so the fake `cargo` is the one resolved
    // and no real cargo can be reached. `sh` is invoked by the fake cargo via
    // its shebang, which the kernel resolves without consulting PATH.
    let out = std::process::Command::new(ipe_bin)
        .args(["build", &entry.to_string_lossy(), "--out"])
        .arg(&out_dir)
        .env("PATH", &bin_dir)
        .env("IPE_RUNTIME_DIR", &runtime_dir)
        .env("NO_COLOR", "1")
        .output();
    let Ok(out) = out else {
        panic!("failed to spawn ipe build: {out:?}")
    };

    // The core assertion: a failed emitted-crate cargo build must NOT be a
    // success. Before the fix, `ipe build` emitted the crate and returned 0
    // without ever compiling it, so this exited 0 and masked the failure.
    assert!(
        !out.status.success(),
        "ipe build must exit non-zero when the emitted crate fails to compile; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // An unattributable emitted-crate cargo failure must surface as a humble
    // compiler-bug ICE — not as a bare rustc error presented as the user's
    // fault — while still carrying cargo's stderr as the reportable detail.
    let stderr = String::from_utf8_lossy(&out.stderr);

    // The ICE wording must be present.
    assert!(
        stderr.contains("bug in the Ipe")
            || stderr.contains("bug in Ipe")
            || stderr.contains("please report"),
        "unattributed cargo failure must render as a humble compiler-bug ICE, got:\n{stderr}"
    );

    // The cargo stderr detail (the E0609 error) must remain visible for
    // inclusion in a bug report — the ICE must not swallow it.
    assert!(
        stderr.contains("E0609"),
        "cargo stderr must be embedded in the ICE detail for reporting, got:\n{stderr}"
    );

    // The failure must NOT be presented as if it were the user's mistake.
    assert!(
        !stderr.contains("building the emitted program failed (cargo exited"),
        "unattributed cargo failure must not use the old plain-header form, got:\n{stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}
