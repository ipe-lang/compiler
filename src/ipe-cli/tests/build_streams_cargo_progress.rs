//! Regression: `ipe dev build` and `ipe dev run` must *stream* the emitted crate's
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

/// The `rustc` a real toolchain carries beside its `cargo`: the pinned release.
#[cfg(unix)]
fn pinned_rustc() -> e2e_support::fake_toolchain::FakeRustc {
    e2e_support::fake_toolchain::FakeRustc::Reporting(ipe::toolchain::PINNED_RELEASE.to_string())
}

/// The release one step below the pin: the newest `rustc` the floor refuses.
#[cfg(unix)]
fn just_below_pin() -> e2e_support::fake_toolchain::FakeRustc {
    let pin = ipe::toolchain::PINNED_RELEASE.to_string();
    let parts: Vec<u32> = pin.split('.').filter_map(|n| n.parse().ok()).collect();
    let below = match parts.as_slice() {
        [major, minor, patch] => match (patch.checked_sub(1), minor.checked_sub(1)) {
            (Some(patch), _) => format!("{major}.{minor}.{patch}"),
            (None, Some(minor)) => format!("{major}.{minor}.999"),
            (None, None) => format!("{}.999.999", major.saturating_sub(1)),
        },
        _ => String::from("0.0.0"),
    };
    e2e_support::fake_toolchain::FakeRustc::Reporting(below)
}

/// The header `ipe` renders when it refuses the build's compiler.
#[cfg(unix)]
const FLOOR_HEADER: &str = "UNSUPPORTED HOST RUST TOOLCHAIN";

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
fn write_progress_cargo(
    dir: &Path,
    rustc: &e2e_support::fake_toolchain::FakeRustc,
) -> std::io::Result<std::path::PathBuf> {
    // The `build` arm writes the marker to stderr (fd 2), exactly where a real
    // `cargo build` writes its `Compiling…`/`Finished` status.
    let script = format!(
        "#!/bin/sh\n\
         case \"$1\" in\n\
         metadata) echo '{{\"target_directory\":\"/tmp/ipe-fake-target\"}}'; exit 0 ;;\n\
         *) echo '{PROGRESS_MARKER}' 1>&2; exit 0 ;;\n\
         esac\n"
    );
    e2e_support::fake_toolchain::stage(dir, &script, rustc)
}

/// `ipe dev build <dir>` must relay the emitted crate's `cargo build` stderr to
/// its own stderr — the progress the user watches while cargo compiles.
#[cfg(unix)]
#[test]
fn build_streams_the_emitted_cargo_progress() {
    assert_relays_cargo_progress("build");
}

/// A fake `cargo` whose `rustc` is one release below the pin is refused before
/// cargo builds: the floor header renders and no cargo progress is relayed.
#[cfg(unix)]
#[test]
fn build_refuses_a_rustc_below_the_pin_before_cargo_builds() {
    assert_floor_refuses("below_pin", &just_below_pin());
}

/// A fake `cargo` with no `rustc` beside it is refused before cargo builds:
/// the compiler the build would run cannot be found, so its version cannot be
/// confirmed.
#[cfg(unix)]
#[test]
fn build_refuses_a_missing_rustc_before_cargo_builds() {
    assert_floor_refuses("absent", &e2e_support::fake_toolchain::FakeRustc::Absent);
}

/// `ipe dev build` with `rustc` must exit non-zero with the floor header, and
/// the fake cargo's progress marker must never appear: `cargo build` never ran.
#[cfg(unix)]
fn assert_floor_refuses(tag: &str, rustc: &e2e_support::fake_toolchain::FakeRustc) {
    let Some((success, stderr)) = dev_with_fake_cargo("build", tag, rustc) else {
        return;
    };
    assert!(
        !success,
        "ipe dev build must refuse the build's compiler ({rustc:?}); stderr:\n{stderr}"
    );
    assert!(
        stderr.contains(FLOOR_HEADER),
        "the refusal must render {FLOOR_HEADER} ({rustc:?}); stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains(PROGRESS_MARKER),
        "cargo build must not run once the compiler is refused ({rustc:?}); stderr:\n{stderr}"
    );
}

/// `ipe dev run <dir>` builds the same way before it execs the binary, so it must
/// relay cargo's progress just as `ipe dev build` does. The fake `cargo build`
/// produces no `ipe-app` binary, so the exec step fails afterwards — but the
/// progress line must already have been streamed before that, which is all this
/// asserts.
#[cfg(unix)]
#[test]
fn run_streams_the_emitted_cargo_progress() {
    assert_relays_cargo_progress("run");
}

/// Spawn `ipe dev <subcommand> <dir>` with a fake progress-printing `cargo` on the
/// `PATH` and assert the fake's stderr marker is relayed to `ipe`'s stderr.
#[cfg(unix)]
fn assert_relays_cargo_progress(subcommand: &str) {
    let Some((_, stderr)) = dev_with_fake_cargo(subcommand, "pinned", &pinned_rustc()) else {
        return;
    };
    // The core assertion: cargo's progress line reached `ipe`'s stderr. Before
    // the fix, `ipe` buffered cargo's stderr and only replayed it after cargo
    // exited (or, for `run`, dropped it entirely into a captured error), so the
    // user saw nothing while cargo ran.
    assert!(
        stderr.contains(PROGRESS_MARKER),
        "ipe {subcommand} must relay the emitted cargo build's progress to stderr; got:\n{stderr}"
    );
}

/// Spawn `ipe dev <subcommand> <dir>` under a `PATH` holding only a fake
/// progress-printing `cargo` and the `rustc` named by `rustc`; return whether
/// it succeeded and its stderr. `None` after a failed setup assertion.
#[cfg(unix)]
fn dev_with_fake_cargo(
    subcommand: &str,
    tag: &str,
    rustc: &e2e_support::fake_toolchain::FakeRustc,
) -> Option<(bool, String)> {
    const SRC: &str = "module Main exposing (main)\n\nimport Ipe.Io\n\nmain = Io.println \"hi\"\n";

    // The runtime dir must resolve for the emit to reach the cargo step.
    let runtime_dir = e2e_support::require_runtime().into_path_buf();

    let ipe_bin = e2e_support::cargo_bin!("ipe");

    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ipe_{subcommand}_{tag}_stream_progress_e2e"));
    e2e_support::scratch::fresh(&dir);
    let bin_dir = dir.join("fakebin");
    let out_dir = dir.join("out");
    let setup = fs::create_dir_all(&bin_dir);
    assert!(setup.is_ok(), "make the fake-bin dir: {setup:?}");
    let fixture = ipe::RootFixture::main(SRC);
    let Ok(fixture) = fixture else {
        assert!(false_marker(), "write project: {fixture:?}");
        return None;
    };

    let fake_cargo = write_progress_cargo(&bin_dir, rustc);
    assert!(fake_cargo.is_ok(), "write fake cargo: {fake_cargo:?}");

    // `ipe dev build`/`ipe dev run` emit the fixed package `ipe-app`: an
    // exclusive tree avoids colliding with a concurrent same-shaped test over
    // the same package name in the shared target.
    let isolated =
        e2e_support::target::isolated(e2e_support::target::IsolationReason::FixedPackageName);
    let Ok(isolated) = isolated else {
        assert!(false_marker(), "isolated build target: {isolated:?}");
        return None;
    };
    let target = e2e_support::target::BuildTarget::Isolated(isolated);

    // PATH holds ONLY the fake-bin dir, so the fake `cargo` is the one resolved.
    let out = e2e_support::target::ipe_command(ipe_bin.path(), &target)
        .args([
            "dev",
            subcommand,
            &fixture.path().to_string_lossy(),
            "--out",
        ])
        .arg(&out_dir)
        .env("PATH", &bin_dir)
        .env("IPE_RUNTIME_DIR", &runtime_dir)
        .env("NO_COLOR", "1")
        .output();
    let Ok(out) = out else {
        assert!(false_marker(), "failed to spawn ipe {subcommand}: {out:?}");
        return None;
    };

    let _ = fs::remove_dir_all(&dir);
    Some((
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}
