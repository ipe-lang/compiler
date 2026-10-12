//! Descriptor floor contract for `system::spawn_hardened{,_naming}` and `exec_naming`.
//!
//! A hardened child inherits stdio plus the descriptors its spawn names, and
//! no other descriptor of the parent:
//!
//! 1. a descriptor left inheritable in the parent never reaches the child;
//! 2. a named descriptor reaches its own child, never a sibling;
//! 3. a named descriptor is read from offset 0, wherever the parent left it;
//! 4. a process replaced through `exec_naming` keeps only what it names.
#![cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]

use ipe_runtime_rust::system::{NamedFds, exec_naming, spawn_hardened, spawn_hardened_naming};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Extra argument on the re-executed probe; its presence selects probe mode.
const EXEC_PROBE_MARKER: &str = "ipe-fd-floor-exec-probe";

/// Line the replacement shell prints once its checks pass, so a probe run that
/// never reached `exec_naming` (no test matched the filter) cannot pass.
const EXEC_PROBE_PASSED: &str = "ipe-fd-floor-exec-probe-passed";

/// Ceiling on every child wait in this file.
const WAIT_CEILING: Duration = Duration::from_secs(10);

/// Interval between polls of a running child.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Open `/dev/null`, close-on-exec or inheritable.
fn dev_null(cloexec: bool) -> rustix::io::Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags};
    let flags = if cloexec {
        OFlags::RDONLY | OFlags::CLOEXEC
    } else {
        OFlags::RDONLY
    };
    rustix::fs::open(c"/dev/null", flags, Mode::empty())
}

/// A `/bin/sh -c script` with positional `args` and null stdio.
fn sh(script: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(script)
        .arg("sh")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd
}

/// Wait for `child`, killing it (a failed status) past `WAIT_CEILING`.
fn bounded_wait(mut child: Child) -> std::io::Result<ExitStatus> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if started.elapsed() > WAIT_CEILING {
            let _ = child.kill();
            return child.wait();
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Whether descriptor `fd` is close-on-exec in this process.
fn is_cloexec(fd: &OwnedFd) -> rustix::io::Result<bool> {
    Ok(rustix::io::fcntl_getfd(fd)?.contains(rustix::io::FdFlags::CLOEXEC))
}

/// A descriptor the parent left inheritable is closed in the hardened child.
#[test]
fn a_hardened_child_inherits_no_unnamed_descriptor() {
    let leaked = dev_null(false).expect("open /dev/null");
    assert!(
        !is_cloexec(&leaked).expect("read descriptor flags"),
        "the probe descriptor must be inheritable"
    );
    let n = leaked.as_raw_fd().to_string();
    let child = spawn_hardened(sh("[ ! -e /dev/fd/$1 ]", &[&n])).expect("hardened spawn");
    assert!(
        bounded_wait(child).expect("wait child").success(),
        "descriptor {n} must not reach a hardened child"
    );
    assert!(
        !is_cloexec(&leaked).expect("read descriptor flags"),
        "the floor must not touch the parent's table"
    );
}

/// A named descriptor reaches the child it was handed to and no sibling.
#[test]
fn a_named_descriptor_reaches_only_its_child() {
    let named_fd = dev_null(true).expect("open /dev/null");
    let n = named_fd.as_raw_fd().to_string();
    let sibling = sh("[ ! -e /dev/fd/$1 ]", &[&n])
        .spawn()
        .expect("plain sibling");
    assert!(
        bounded_wait(sibling).expect("wait sibling").success(),
        "a named descriptor must never reach a sibling"
    );
    let mut named = NamedFds::none();
    named
        .push(named_fd)
        .expect("admit a close-on-exec descriptor");
    let child =
        spawn_hardened_naming(sh("[ -e /dev/fd/$1 ]", &[&n]), named).expect("hardened spawn");
    assert!(
        bounded_wait(child).expect("wait child").success(),
        "descriptor {n} must reach the child that names it"
    );
}

/// A named file is read from its first byte even when the parent sought past its end.
#[test]
fn a_named_descriptor_is_read_from_offset_zero() {
    use std::io::{Seek as _, SeekFrom, Write as _};
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ipe-fd-floor-offset-{}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&path)
        .expect("create named file");
    file.write_all(b"floor-bytes\n").expect("write named file");
    file.seek(SeekFrom::End(0)).expect("seek past the content");
    let fd = OwnedFd::from(file);
    let n = fd.as_raw_fd().to_string();
    let mut named = NamedFds::none();
    named.push(fd).expect("admit the named file");
    let child = spawn_hardened_naming(
        sh(
            "IFS= read -r line <&\"$1\" && [ \"$line\" = \"$2\" ]",
            &[&n, "floor-bytes"],
        ),
        named,
    )
    .expect("hardened spawn");
    let status = bounded_wait(child).expect("wait child");
    let _ = std::fs::remove_file(&path);
    assert!(
        status.success(),
        "the child must read the named file from offset 0"
    );
}

/// A process replaced through `exec_naming` keeps its named descriptor and no other.
///
/// In probe mode a returned error is the refused replacement.
#[test]
fn an_exec_replacement_inherits_only_named() -> std::io::Result<()> {
    if std::env::args_os().any(|arg| arg == EXEC_PROBE_MARKER) {
        // Probe mode: replace this process with a shell that checks its table.
        let leaked = dev_null(false).expect("open /dev/null");
        let named_fd = dev_null(true).expect("open /dev/null");
        let (leaked_n, named_n) = (
            leaked.as_raw_fd().to_string(),
            named_fd.as_raw_fd().to_string(),
        );
        let mut named = NamedFds::none();
        named
            .push(named_fd)
            .expect("admit a close-on-exec descriptor");
        let mut replacement = sh(
            "[ ! -e /dev/fd/$1 ] && [ -e /dev/fd/$2 ] && echo \"$3\"",
            &[&leaked_n, &named_n, EXEC_PROBE_PASSED],
        );
        replacement.stdout(Stdio::inherit());
        let refused = exec_naming(replacement, named);
        drop(leaked);
        return Err(refused);
    }
    let mut probe = Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "an_exec_replacement_inherits_only_named",
            "--exact",
            EXEC_PROBE_MARKER,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("re-exec probe");
    let stdout = probe.stdout.take().expect("piped probe stdout");
    let status = bounded_wait(probe).expect("wait probe");
    let mut printed = String::new();
    std::io::Read::read_to_string(&mut std::io::BufReader::new(stdout), &mut printed)
        .expect("read probe stdout");
    assert!(
        status.success() && printed.lines().any(|line| line == EXEC_PROBE_PASSED),
        "the replacement must run, holding its named descriptor and no other: {printed:?}"
    );
    Ok(())
}
