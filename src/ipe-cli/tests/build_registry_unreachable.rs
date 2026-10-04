//! Regression: a cargo fetch failure caused by DNS/network unavailability must
//! render as IPE-E0001 ("could not reach the crate registry"), not as the
//! IPE-I0001 internal-compiler-error ICE that would invite a bogus bug report.
//!
//! This spawns the real `ipe` binary with a fake `cargo` on the PATH that
//! exits non-zero with stderr matching the patterns cargo emits when it cannot
//! reach crates.io (host-resolution failure + source-load failure). Ipê must
//! classify this as an environment error and render IPE-E0001 with a "check
//! your connection" message, never IPE-I0001 with "please report this bug".

use std::fs;
use std::path::Path;

/// Write an executable fake `cargo` at `dir/cargo` that exits non-zero with
/// the DNS/registry-error patterns cargo emits when offline or when the
/// registry is unreachable.
#[cfg(unix)]
fn write_offline_cargo(dir: &Path) -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;
    // The stderr lines mirror what cargo actually emits on a DNS failure:
    //   "Could not resolve host: index.crates.io"
    //   "failed to load source for dependency dlmalloc"
    let script = "#!/bin/sh\n\
         case \"$1\" in\n\
         metadata) echo '{\"target_directory\":\"/tmp/ipe-fake-target\"}'; exit 0 ;;\n\
         *) printf 'error: failed to load source for dependency `dlmalloc`\\n' 1>&2;\
            printf 'Caused by:\\n  Could not resolve host: index.crates.io\\n' 1>&2;\
            exit 101 ;;\n\
         esac\n";
    let path = dir.join("cargo");
    fs::write(&path, script)?;
    let mut perms = fs::metadata(&path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms)?;
    Ok(path)
}

/// Registry-unreachable classification gate. Unix-only: relies on a shell fake
/// `cargo` and PATH scrubbing to guarantee the fake is the one resolved.
#[cfg(unix)]
#[test]
#[allow(clippy::panic)] // a refused precondition is the test failure
fn build_registry_unreachable_renders_ipe_e0001_not_ice() {
    const SRC: &str = "module Main exposing (main)\n\nimport Ipe.Io\n\nmain = Io.println \"hi\"\n";

    let runtime_dir = e2e_support::require_runtime().into_path_buf();

    let ipe_bin = e2e_support::cargo_bin!("ipe");

    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("ipe_build_registry_unreachable_e2e");
    let _ = fs::remove_dir_all(&dir);
    let bin_dir = dir.join("fakebin");
    let entry = dir.join("Main.ipe");
    let out_dir = dir.join("out");
    let setup = fs::create_dir_all(&bin_dir).and_then(|()| fs::write(&entry, SRC));
    assert!(setup.is_ok(), "write source + fake-bin dir: {setup:?}");

    let fake_cargo = write_offline_cargo(&bin_dir);
    assert!(fake_cargo.is_ok(), "write fake cargo: {fake_cargo:?}");

    let out = std::process::Command::new(ipe_bin)
        .args(["dev", "build", &entry.to_string_lossy(), "--out"])
        .arg(&out_dir)
        .env("PATH", &bin_dir)
        .env("IPE_RUNTIME_DIR", &runtime_dir)
        .env("NO_COLOR", "1")
        .output();
    let Ok(out) = out else {
        panic!("failed to spawn ipe dev build: {out:?}")
    };

    let stderr = String::from_utf8_lossy(&out.stderr);

    // Must exit non-zero.
    assert!(
        !out.status.success(),
        "ipe dev build must exit non-zero on a registry failure; stderr:\n{stderr}"
    );

    // Must surface IPE-E0001, not the ICE IPE-I0001.
    assert!(
        stderr.contains("IPE-E0001"),
        "registry unreachable must surface IPE-E0001; stderr:\n{stderr}"
    );

    // Must NOT invite a bug report.
    assert!(
        !stderr.contains("IPE-I0001"),
        "registry unreachable must NOT surface IPE-I0001 ICE; stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("please report"),
        "registry unreachable must NOT say 'please report'; stderr:\n{stderr}"
    );

    // Must carry the network-problem guidance.
    assert!(
        stderr.contains("network") || stderr.contains("connection") || stderr.contains("registry"),
        "registry unreachable message must mention network/connection/registry; stderr:\n{stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}
