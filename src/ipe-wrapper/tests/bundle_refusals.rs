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

/// The built wrapper: the run-time `CARGO_BIN_EXE_ipe-wrapper` nextest
/// exports, else the bin cargo places one level above this test's `deps/`.
fn wrapper_bin() -> PathBuf {
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
        .expect("the built ipe-wrapper binary exists (CARGO_BIN_EXE_ipe-wrapper or beside deps/)")
}

/// A fresh bundle directory holding the wrapper, `app` as `ipe-app`, and a
/// maximally isolated `ipe.profile` (a profile every floor admits).
fn bundle(tag: &str, app: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ipe_wrapper_bundle_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("bundle dir");
    let wrapper = dir.join("ipe-wrapper");
    // A hard link holds no writable descriptor the exec could race; a copy
    // is the fallback across filesystems.
    if std::fs::hard_link(wrapper_bin(), &wrapper).is_err() {
        std::fs::copy(wrapper_bin(), &wrapper).expect("copy the wrapper");
    }
    let app_path = dir.join("ipe-app");
    std::fs::write(&app_path, app).expect("write ipe-app");
    std::fs::set_permissions(&app_path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod ipe-app");
    std::fs::write(
        dir.join("ipe.profile"),
        SandboxProfile::maximally_isolated().to_profile_string(),
    )
    .expect("write ipe.profile");
    dir
}

/// Run the bundle's wrapper with no arguments under [`WRAPPER_CEILING`],
/// returning its exit status, stdout and stderr.
fn run_wrapper(dir: &Path) -> (ExitStatus, String, String) {
    let stdout_path = dir.join("stdout.txt");
    let stderr_path = dir.join("stderr.txt");
    let mut child = Command::new(dir.join("ipe-wrapper"))
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&stdout_path).expect("stdout file"))
        .stderr(std::fs::File::create(&stderr_path).expect("stderr file"))
        .spawn()
        .expect("start the wrapper");
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll the wrapper") {
            break Some(status);
        }
        if started.elapsed() >= WRAPPER_CEILING {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let status = status.expect("the wrapper exits within its ceiling");
    let read = |path: &Path| {
        let mut text = String::new();
        std::fs::File::open(path)
            .expect("open captured stream")
            .take(CAPTURE_CAP)
            .read_to_string(&mut text)
            .expect("read captured stream");
        text
    };
    (status, read(&stdout_path), read(&stderr_path))
}

/// The wrapper refuses a floorless app and a development-marked app, runs
/// neither, and names the remedy; a release-marked app under the same
/// profile passes the floor check (control: the refusals are the floor's).
#[test]
fn the_wrapper_refuses_a_floorless_and_a_development_app() {
    let isolated = SandboxProfile::maximally_isolated();

    let floorless = bundle("floorless", "#!/bin/sh\necho started\n");
    let (status, stdout, stderr) = run_wrapper(&floorless);
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
    );
    let (status, stdout, stderr) = run_wrapper(&development);
    let _ = std::fs::remove_dir_all(&development);
    assert!(
        !status.success() && !stdout.contains("started"),
        "a development app never runs:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("built by `ipe dev build`")
            && stderr.contains("rebuild it with `ipe release build`"),
        "the development refusal names the build and the remedy:\nstderr:\n{stderr}"
    );

    let release = bundle(
        "release",
        &format!(
            "#!/bin/sh\n# {}\necho started\n",
            isolated.to_capfloor_line(FloorIntent::Release)
        ),
    );
    let (_, _, stderr) = run_wrapper(&release);
    let _ = std::fs::remove_dir_all(&release);
    assert!(
        !stderr.contains("capability floor") && !stderr.contains("built by `ipe dev build`"),
        "a release app passes the floor check (control):\nstderr:\n{stderr}"
    );
}
