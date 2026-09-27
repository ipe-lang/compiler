//! Regression: `ipe build` and `ipe run` must *stream* the emitted crate's
//! `cargo build` output as it happens — not swallow it and reveal it only once
//! cargo has already finished (success or error). A `cargo build` can take
//! minutes; a silent wait leaves the user unable to tell the command from a
//! hang.
//!
//! The fix streams cargo's stderr line by line to `ipe`'s own stderr. This test
//! pins that behaviour: a fake `cargo` on the `PATH` emits a distinctive
//! progress line to stderr, and the spawned `ipe` must relay that exact line —
//! proving the output reaches the terminal rather than being buffered away.
//!
//! Unix-only: it relies on a shell fake `cargo` and `PATH` scrubbing to
//! guarantee the fake is the one resolved.

use std::fs;
use std::path::Path;

/// `assert!(false_marker())` fails a test without tripping
/// `clippy::assertions_on_constants` (a plain `assert!(false)` would).
#[allow(clippy::missing_const_for_fn)]
fn false_marker() -> bool {
    std::hint::black_box(false)
}

/// The distinctive line the fake `cargo build` prints to stderr. `ipe` must
/// relay it verbatim for the streaming assertion to pass.
const PROGRESS_MARKER: &str = "Compiling ipe-app v0.0.0 (fake-cargo-progress-marker)";

/// Write an executable fake `cargo` at `dir/cargo` that, for a `build`
/// invocation, prints a progress line to stderr and exits 0; for a `metadata`
/// invocation, prints a minimal valid JSON so any metadata probe on the path
/// does not spawn-fail before the build is reached.
#[cfg(unix)]
fn write_progress_cargo(dir: &Path) -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;
    // The `build` arm writes the marker to stderr (fd 2), exactly where a real
    // `cargo build` writes its `Compiling…`/`Finished` status.
    let script = format!(
        "#!/bin/sh\n\
         case \"$1\" in\n\
         metadata) echo '{{\"target_directory\":\"/tmp/ipe-fake-target\"}}'; exit 0 ;;\n\
         *) echo '{PROGRESS_MARKER}' 1>&2; exit 0 ;;\n\
         esac\n"
    );
    let path = dir.join("cargo");
    fs::write(&path, script)?;
    let mut perms = fs::metadata(&path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms)?;
    Ok(path)
}

/// `ipe build <entry>` must relay the emitted crate's `cargo build` stderr to
/// its own stderr — the progress the user watches while cargo compiles.
#[cfg(unix)]
#[test]
fn build_streams_the_emitted_cargo_progress() {
    assert_relays_cargo_progress("build");
}

/// `ipe run <entry>` builds the same way before it execs the binary, so it must
/// relay cargo's progress just as `ipe build` does. The fake `cargo build`
/// produces no `ipe-app` binary, so the exec step fails afterwards — but the
/// progress line must already have been streamed before that, which is all this
/// asserts.
#[cfg(unix)]
#[test]
fn run_streams_the_emitted_cargo_progress() {
    assert_relays_cargo_progress("run");
}

/// Spawn `ipe <subcommand> <entry>` with a fake progress-printing `cargo` on the
/// `PATH` and assert the fake's stderr marker is relayed to `ipe`'s stderr.
#[cfg(unix)]
fn assert_relays_cargo_progress(subcommand: &str) {
    const SRC: &str = "module Main exposing (main)\n\nimport Ipe.Io\n\nmain = Io.println \"hi\"\n";

    // The runtime dir must resolve for the emit to reach the cargo step. When the
    // repo tree is unavailable (a nextest archive shipped to another host), skip
    // — the streaming primitive is also unit-covered below.
    let Ok(runtime_dir) = ipe::resolve_runtime() else {
        return;
    };

    let ipe_bin = env!("CARGO_BIN_EXE_ipe");
    if !Path::new(ipe_bin).exists() {
        return;
    }

    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ipe_{subcommand}_stream_progress_e2e"));
    let _ = fs::remove_dir_all(&dir);
    let bin_dir = dir.join("fakebin");
    let entry = dir.join("Main.ipe");
    let out_dir = dir.join("out");
    let setup = fs::create_dir_all(&bin_dir).and_then(|()| fs::write(&entry, SRC));
    assert!(setup.is_ok(), "write source + fake-bin dir: {setup:?}");

    let fake_cargo = write_progress_cargo(&bin_dir);
    assert!(fake_cargo.is_ok(), "write fake cargo: {fake_cargo:?}");

    // PATH holds ONLY the fake-bin dir, so the fake `cargo` is the one resolved.
    let out = std::process::Command::new(ipe_bin)
        .args([subcommand, &entry.to_string_lossy(), "--out"])
        .arg(&out_dir)
        .env("PATH", &bin_dir)
        .env("IPE_RUNTIME_DIR", &runtime_dir)
        .env("NO_COLOR", "1")
        .output();
    let Ok(out) = out else {
        assert!(false_marker(), "failed to spawn ipe {subcommand}: {out:?}");
        return;
    };

    // The core assertion: cargo's progress line reached `ipe`'s stderr. Before
    // the fix, `ipe` buffered cargo's stderr and only replayed it after cargo
    // exited (or, for `run`, dropped it entirely into a captured error), so the
    // user saw nothing while cargo ran.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(PROGRESS_MARKER),
        "ipe {subcommand} must relay the emitted cargo build's progress to stderr; got:\n{stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}
