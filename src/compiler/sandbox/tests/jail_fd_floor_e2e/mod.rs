//! The jail descriptor floor, end to end: a jailed payload inherits stdio plus
//! exactly the descriptors its jail builder names, and a named descriptor is
//! never inheritable in this process.
//!
//! Each jail path is driven with a directory descriptor and a pipe the test
//! opens WITHOUT close-on-exec, the descriptors a raw spawn would hand on. An
//! unjailed control child sees them, so their absence from the payload's
//! `/proc/self/fd` is the floor's doing: the FFI inspection jail, the
//! subprocess-denying bubblewrap jail, the build jail, and the run jail that
//! replaces its process. A sibling child spawned by another thread while jails
//! launch never sees a jail's seccomp descriptor.

use std::ffi::OsString;
use std::os::fd::AsFd as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use ipe_sandbox::CanonicalPath;
use ipe_sandbox::run_jail::{SandboxProfile, exec_in_run_jail};

/// The `ls` every payload below lists its descriptors with.
const LS: &str = "/usr/bin/ls";

/// The environment marker that turns [`exec_jail_child`] from an inert ignored
/// test into the exec path's payload host.
const EXEC_CHILD: &str = "IPE_JAIL_FD_FLOOR_EXEC_CHILD";

/// Descriptors this process holds open without close-on-exec: a directory and
/// both ends of a pipe.
struct Planted {
    _dir: std::fs::File,
    dir_path: PathBuf,
    pipe_target: String,
    _read: std::io::PipeReader,
    _write: std::io::PipeWriter,
}

impl Planted {
    fn new(tag: &str) -> Self {
        let dir_path = scratch(tag);
        let dir = std::fs::File::open(&dir_path).expect("directory descriptor");
        let (read, write) = std::io::pipe().expect("pipe");
        for fd in [dir.as_fd(), read.as_fd(), write.as_fd()] {
            rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::empty()).expect("clear close-on-exec");
        }
        let inode = rustix::fs::fstat(read.as_fd()).expect("pipe inode").st_ino;
        Self {
            _dir: dir,
            dir_path,
            pipe_target: format!("pipe:[{inode}]"),
            _read: read,
            _write: write,
        }
    }

    /// Whether a listed target is one of these descriptors.
    fn names(&self, target: &str) -> bool {
        target == self.dir_path.to_string_lossy() || target == self.pipe_target
    }
}

impl Drop for Planted {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir_path);
    }
}

/// A fresh scratch directory under the test temp root, unique per call.
fn scratch(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir =
        ipe_test_temp::temp_root().join(format!("ipe-fd-floor-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    CanonicalPath::resolve(&dir)
        .expect("scratch resolves")
        .as_path()
        .to_path_buf()
}

/// The `(number, target)` pairs of an `ls -l /proc/self/fd` listing.
fn listed(listing: &str) -> Vec<(u32, String)> {
    listing
        .lines()
        .filter_map(|line| {
            let (head, target) = line.split_once(" -> ")?;
            let number = head.split_whitespace().last()?.parse().ok()?;
            Some((number, target.to_owned()))
        })
        .collect()
}

/// Assert `listing` names stdio, the listing's own `/proc` directory, and
/// nothing else: no planted descriptor and no descriptor beyond stdio the
/// payload did not open itself.
fn assert_floor(path: &str, listing: &str, planted: &Planted) {
    let fds = listed(listing);
    assert!(
        fds.iter().any(|(n, _)| *n == 0),
        "{path}: the listing parsed no stdio entry: {listing}"
    );
    for (number, target) in &fds {
        assert!(
            !planted.names(target),
            "{path}: the payload inherited a descriptor the jail never named \
             ({number} -> {target}): {listing}"
        );
        assert!(
            *number <= 2 || (target.starts_with("/proc/") && target.ends_with("/fd")),
            "{path}: the payload holds a descriptor beyond stdio and its own listing \
             ({number} -> {target}): {listing}"
        );
    }
}

/// The unjailed control: a raw child of this process sees the planted
/// descriptors, so their absence in a jail is the floor's.
fn assert_control_sees(planted: &Planted) {
    let out = Command::new(LS)
        .args(["-l", "/proc/self/fd"])
        .output()
        .expect("control ls");
    let listing = String::from_utf8_lossy(&out.stdout);
    let fds = listed(&listing);
    assert!(
        fds.iter()
            .any(|(_, t)| *t == planted.dir_path.to_string_lossy()),
        "control: the planted directory is not inheritable: {listing}"
    );
    assert!(
        fds.iter().any(|(_, t)| *t == planted.pipe_target),
        "control: the planted pipe is not inheritable: {listing}"
    );
}

/// The FFI inspection jail's spec over `scoped`.
fn inspection_spec(scoped: &Path) -> ipe_sandbox::JailSpec {
    ipe_sandbox::JailSpec {
        network: ipe_sandbox::NetworkPolicy::Denied,
        scoped_tmp: CanonicalPath::resolve(scoped).expect("scoped tmp resolves"),
        registry_cache: None,
        toolchain: None,
        toolchain_ro_binds: Vec::new(),
        homes: ipe_sandbox::HomeMasks::of_invoker().expect("the invoker's homes resolve"),
        path_prepend: Vec::new(),
        rustup_home: None,
        limits: ipe_sandbox::ResourceLimits::default(),
    }
}

/// The payload that lists its own descriptors.
fn ls_payload() -> [OsString; 3] {
    [LS, "-l", "/proc/self/fd"].map(OsString::from)
}

/// The bubblewrap capabilities, when the jail runs here and has its wall clock.
fn bwrap_caps() -> Option<ipe_sandbox::Capabilities> {
    super::e2e_tools()?;
    let caps = ipe_sandbox::probe();
    caps.timeout.as_ref()?;
    Some(caps)
}

#[test]
fn the_inspection_jail_payload_inherits_only_stdio() {
    let Some(caps) = bwrap_caps() else { return };
    let planted = Planted::new("ffi");
    assert_control_sees(&planted);
    let scoped = scratch("ffi-tmp");
    let out = ipe_sandbox::run_in_bwrap_jail(&caps, &inspection_spec(&scoped), &ls_payload());
    let _ = std::fs::remove_dir_all(&scoped);
    let out = out.expect("the inspection jail runs");
    assert_eq!(out.status, Some(0), "{out:?}");
    assert_floor(
        "inspection jail",
        &String::from_utf8_lossy(&out.stdout),
        &planted,
    );
}

#[test]
fn the_subprocess_denying_jail_payload_inherits_only_stdio() {
    let Some(caps) = bwrap_caps() else { return };
    let planted = Planted::new("fork");
    assert_control_sees(&planted);
    let scoped = scratch("fork-tmp");
    let out = ipe_sandbox::run_in_bwrap_jail_deny_subprocess(
        &caps,
        &inspection_spec(&scoped),
        &ls_payload(),
    );
    let _ = std::fs::remove_dir_all(&scoped);
    let out = out.expect("the subprocess-denying jail runs");
    assert_eq!(out.status, Some(0), "{out:?}");
    assert_floor(
        "subprocess-denying jail",
        &String::from_utf8_lossy(&out.stdout),
        &planted,
    );
}

#[test]
fn the_build_jail_payload_inherits_only_stdio() {
    let Some(tools) = super::e2e_tools() else {
        return;
    };
    let planted = Planted::new("build");
    assert_control_sees(&planted);
    let scoped = scratch("build-tmp");
    let bound = CanonicalPath::resolve(&scoped).expect("scratch resolves");
    let binds = ["/usr", "/bin", "/lib"]
        .into_iter()
        .map(Path::new)
        .filter(|p| p.exists())
        .map(|p| CanonicalPath::resolve(p).expect("system dir resolves"))
        .collect();
    let mounts = ipe_sandbox::JailMounts::of_invoker(bound.clone(), bound, binds)
        .expect("checked jail mounts");
    let out_file = scoped.join("fds");
    let mut script = OsString::from("exec ");
    script.push(LS);
    script.push(" -l /proc/self/fd > ");
    script.push(&out_file);
    let outcome = ipe_sandbox::build_jail::build_in_jail(
        &tools,
        &SandboxProfile::maximally_isolated(),
        &mounts,
        &[OsString::from("/bin/sh"), OsString::from("-c"), script],
    );
    let listing = std::fs::read_to_string(&out_file);
    let _ = std::fs::remove_dir_all(&scoped);
    assert!(outcome.is_clean(), "the build jail ran: {outcome:?}");
    assert_floor(
        "build jail",
        &listing.expect("the jailed listing"),
        &planted,
    );
}

#[test]
fn the_exec_run_jail_payload_inherits_only_stdio() {
    let Some(_tools) = super::e2e_tools() else {
        return;
    };
    let planted = Planted::new("exec");
    assert_control_sees(&planted);
    let exe = std::env::current_exe().expect("this test binary");
    let out = Command::new(exe)
        .args([
            "--exact",
            "jail_fd_floor_e2e::exec_jail_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(EXEC_CHILD, "1")
        .output()
        .expect("the exec child runs");
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "the exec'd run jail failed ({:?}): {listing}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert_floor("exec run jail", &listing, &planted);
}

/// The exec path's payload host: plants its own inheritable descriptors, then
/// replaces itself with the run jail around `ls -l /proc/self/fd`. Inert
/// unless [`the_exec_run_jail_payload_inherits_only_stdio`] launched it.
#[test]
#[ignore = "re-executed by the_exec_run_jail_payload_inherits_only_stdio"]
#[allow(clippy::panic)] // reaching the end is the failure: the exec returned
fn exec_jail_child() {
    if ipe_env::var_os(EXEC_CHILD).is_none() {
        return;
    }
    let tools = super::e2e_tools().expect("the parent proved the jail runs here");
    let planted = Planted::new("exec-child");
    let scoped = scratch("exec-child-tmp");
    let refusal = exec_in_run_jail(
        &tools,
        &SandboxProfile::maximally_isolated(),
        &scoped,
        &scoped,
        Path::new(LS),
        &["-l", "/proc/self/fd"].map(OsString::from),
    );
    drop(planted);
    let Err(defect) = refusal;
    panic!("the run jail did not replace this process: {defect:?}");
}

#[test]
fn a_sibling_child_never_inherits_a_jail_seccomp_descriptor() {
    let Some(caps) = bwrap_caps() else { return };
    // The control descriptor: inheritable here, so every sibling listing that
    // names it proves the sibling sees what a raw spawn hands on.
    let control = rustix::fs::memfd_create(c"ipe-sibling-control", rustix::fs::MemfdFlags::empty())
        .expect("control memfd");
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sibling = {
        let done = std::sync::Arc::clone(&done);
        std::thread::Builder::new()
            .name("ipe-fd-floor-sibling".to_owned())
            .spawn(move || {
                let mut listings = Vec::new();
                for _ in 0..2000 {
                    if done.load(std::sync::atomic::Ordering::Acquire) {
                        break;
                    }
                    let out = Command::new("/bin/sh")
                        .args(["-c", "ls -l /proc/self/fd"])
                        .output()
                        .expect("sibling sh");
                    listings.push(String::from_utf8_lossy(&out.stdout).into_owned());
                }
                listings
            })
            .expect("sibling thread spawns")
    };
    let scoped = scratch("sibling-tmp");
    let spec = inspection_spec(&scoped);
    let runs: Vec<_> = (0..20)
        .map(|_| ipe_sandbox::run_in_bwrap_jail(&caps, &spec, &[OsString::from("/bin/true")]))
        .collect();
    done.store(true, std::sync::atomic::Ordering::Release);
    let listings = sibling.join().expect("sibling thread");
    let _ = std::fs::remove_dir_all(&scoped);
    drop(control);
    assert!(
        runs.iter()
            .all(|run| matches!(run, Ok(out) if out.status == Some(0))),
        "every jail ran: {runs:?}"
    );
    assert!(!listings.is_empty(), "the sibling never listed");
    for listing in &listings {
        assert!(
            listing.contains("memfd:ipe-sibling-control"),
            "the sibling listing misses the inheritable control: {listing}"
        );
        assert!(
            !listing.contains("memfd:ipe-seccomp"),
            "a sibling child inherited a jail's seccomp descriptor: {listing}"
        );
    }
}
