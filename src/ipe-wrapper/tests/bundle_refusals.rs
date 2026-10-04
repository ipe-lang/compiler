#![forbid(unsafe_code)]
//! The built `ipe-wrapper` refuses, at its own call site, a bundle whose app
//! is not a release build: an app with no floor marker (a foreign or
//! hand-built binary) and an app carrying the development marker every
//! `ipe dev build` embeds. Both refusals happen before the jail is probed, so
//! the test needs no jail primitive.
//!
//! The wrapper is linked (or copied) beside each bundle, because bundle mode
//! reads `ipe-app` and `ipe.profile` from the directory of its own path.
#![cfg(target_os = "linux")]

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use ipe_sandbox::run_jail::{FloorIntent, SandboxProfile};

/// The longest a refusing wrapper may take before the test kills it.
const WRAPPER_CEILING: Duration = Duration::from_mins(1);

/// The most bytes the test reads back from each captured stream.
const CAPTURE_CAP: u64 = 64 * 1024;

/// The test's error channel: every helper failure, with its cause.
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The built wrapper: the run-time `CARGO_BIN_EXE_ipe-wrapper` nextest
/// exports, else the bin cargo places one level above this test's `deps/`.
fn wrapper_bin() -> TestResult<PathBuf> {
    let exported = ipe_env::var_os("CARGO_BIN_EXE_ipe-wrapper").map(PathBuf::from);
    let beside = std::env::current_exe()
        .ok()
        .as_deref()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(|dir| dir.join("ipe-wrapper"));
    exported
        .into_iter()
        .chain(beside)
        .find(|path| path.is_file())
        .ok_or_else(|| {
            "the built ipe-wrapper binary is absent (CARGO_BIN_EXE_ipe-wrapper or beside deps/)"
                .into()
        })
}

/// A fresh bundle directory holding the wrapper, `app` as `ipe-app`, and a
/// maximally isolated `ipe.profile` (a profile every floor admits).
fn bundle(tag: &str, app: &str) -> TestResult<PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ipe_wrapper_bundle_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let built = wrapper_bin()?;
    let wrapper = dir.join("ipe-wrapper");
    // A hard link holds no writable descriptor the exec could race; a copy
    // is the fallback across filesystems.
    if std::fs::hard_link(&built, &wrapper).is_err() {
        std::fs::copy(&built, &wrapper)?;
    }
    let app_path = dir.join("ipe-app");
    std::fs::write(&app_path, app)?;
    std::fs::set_permissions(&app_path, std::fs::Permissions::from_mode(0o755))?;
    std::fs::write(
        dir.join("ipe.profile"),
        SandboxProfile::maximally_isolated().to_profile_string(),
    )?;
    Ok(dir)
}

/// At most [`CAPTURE_CAP`] bytes of the captured stream at `path`.
fn read_capture(path: &Path) -> TestResult<String> {
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(CAPTURE_CAP)
        .read_to_string(&mut text)?;
    Ok(text)
}

/// Run the bundle's wrapper with no arguments under [`WRAPPER_CEILING`],
/// returning its exit status, stdout and stderr.
fn run_wrapper(dir: &Path) -> TestResult<(ExitStatus, String, String)> {
    let stdout_path = dir.join("stdout.txt");
    let stderr_path = dir.join("stderr.txt");
    let mut child = Command::new(dir.join("ipe-wrapper"))
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&stdout_path)?)
        .stderr(std::fs::File::create(&stderr_path)?)
        .spawn()?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if started.elapsed() >= WRAPPER_CEILING {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let status = status.ok_or("the wrapper outlived its ceiling")?;
    Ok((
        status,
        read_capture(&stdout_path)?,
        read_capture(&stderr_path)?,
    ))
}

/// The wrapper refuses a floorless app and a development-marked app, runs
/// neither, and names the remedy; a release-marked app under the same
/// profile passes the floor check (control: the refusals are the floor's).
#[test]
fn the_wrapper_refuses_a_floorless_and_a_development_app() -> TestResult {
    let isolated = SandboxProfile::maximally_isolated();

    let floorless = bundle("floorless", "#!/bin/sh\necho started\n")?;
    let (status, stdout, stderr) = run_wrapper(&floorless)?;
    let _ = std::fs::remove_dir_all(&floorless);
    assert!(
        !status.success() && !stdout.contains("started"),
        "a floorless app never runs:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("embeds no readable capability floor")
            && stderr.contains("rebuild it with `ipe release build`"),
        "the floorless refusal names why and the remedy:\nstderr:\n{stderr}"
    );

    let development = bundle(
        "development",
        &format!(
            "#!/bin/sh\n# {}\necho started\n",
            isolated.to_capfloor_line(FloorIntent::Development)
        ),
    )?;
    let (status, stdout, stderr) = run_wrapper(&development)?;
    let _ = std::fs::remove_dir_all(&development);
    assert!(
        !status.success() && !stdout.contains("started"),
        "a development app never runs:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("is a development build (`ipe dev`)")
            && stderr.contains("rebuild it with `ipe release build`"),
        "the development refusal names the build and the remedy:\nstderr:\n{stderr}"
    );

    let release = bundle(
        "release",
        &format!(
            "#!/bin/sh\n# {}\necho started\n",
            isolated.to_capfloor_line(FloorIntent::Release)
        ),
    )?;
    let (_, _, stderr) = run_wrapper(&release)?;
    let _ = std::fs::remove_dir_all(&release);
    assert!(
        !stderr.contains("capability floor")
            && !stderr.contains("is a development build (`ipe dev`)"),
        "a release app passes the floor check (control):\nstderr:\n{stderr}"
    );
    Ok(())
}
