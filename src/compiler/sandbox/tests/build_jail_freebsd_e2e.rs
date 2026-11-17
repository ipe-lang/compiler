// End-to-end proof of the FreeBSD returning build jail's differential
// confinement — the Tier-2 observation primitive on FreeBSD, mirroring the
// Linux `build_jail_e2e`.
//
// These are REAL jailed runs (they establish a `jail(8)` and run the admission
// probe fixture under it, then decode the child's exit into a `JailOutcome`), so
// they are gated behind IPE_E2E=1 and only compile on FreeBSD. They drive the
// SAME `build_in_jail` the production Tier-2 reconciler calls.
//
// The red-canary the ADR demands: the probe opens a socket while the
// declared-scoped jail WITHHOLDS `network` → the fixture's wrapper-owned exit
// code 10 decodes to `Denied { axis: Network }` (a differentially-probed axis).
// The jail (established as root inside the vmactions VM) gives the withheld case a
// fresh EMPTY `vnet` (no route → the socket is denied at the kernel) and chroots to
// a read-only nullfs view of the host with only the scratch writable (so an
// out-of-scratch write hits the read-only mount and is denied structurally).

#![cfg(target_os = "freebsd")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ipe_sandbox::build_jail::{CapabilityAxis, JailOutcome, build_in_jail};
use ipe_sandbox::run_jail::{FilesystemScope, RunJailDefect, RunJailTools, SandboxProfile};
use ipe_sandbox::{CanonicalPath, JailMounts};

fn fixture_path() -> PathBuf {
    e2e_support::manifest_dir!().join("../../../tests/fixtures/admission/untrusted-build.sh")
}

/// A per-test scratch dir under the system temp root.
fn scratch_dir(tag: &str) -> PathBuf {
    let dir =
        ipe_test_temp::temp_root().join(format!("ipe-build-fb-e2e-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

/// The FreeBSD jail resolves `jail(8)` and its helpers itself.
const fn inert_tools() -> RunJailTools {
    RunJailTools::Native
}

/// The declared-scoped probe profile: `subprocess` granted (the probe forks
/// python3 to open a socket / `rm`), the axis under test WITHHELD.
fn probe_profile(network: bool, filesystem: FilesystemScope) -> SandboxProfile {
    SandboxProfile {
        network,
        filesystem,
        subprocess: true,
        ..SandboxProfile::maximally_isolated()
    }
}

fn env_assignment(name: &str, value: &OsStr) -> OsString {
    let mut a = OsString::from(name);
    a.push("=");
    a.push(value);
    a
}

/// Run the admission fixture in `tier2` mode inside a jail scoped to `profile`,
/// exercising exactly `axis`, and return the decoded outcome.
fn run_fixture(
    profile: &SandboxProfile,
    scoped: &Path,
    axis: &str,
    escape_path: &str,
) -> JailOutcome {
    // The fixture must be readable+executable by the unprivileged jail user; copy
    // it into the scratch, which `build_in_jail` chowns to that user. Every path
    // the payload names is the canonical path the jail binds.
    let canonical = CanonicalPath::resolve(scoped).expect("canonical scratch");
    let scoped = canonical.as_path();
    let jailed_fixture = scoped.join("untrusted-build.sh");
    std::fs::copy(fixture_path(), &jailed_fixture).expect("copy fixture into scratch");
    let payload: Vec<OsString> = vec![
        OsString::from("/usr/bin/env"),
        OsString::from("PROBE_MODE=tier2"),
        env_assignment("TIER2_AXIS", axis.as_ref()),
        env_assignment("SCRATCH_DIR", scoped.as_os_str()),
        env_assignment("ESCAPE_PATH", escape_path.as_ref()),
        OsString::from("/bin/sh"),
        jailed_fixture.into_os_string(),
    ];
    let mounts = JailMounts::of_invoker(canonical.clone(), canonical, Vec::new())
        .expect("checked jail mounts");
    build_in_jail(&inert_tools(), profile, &mounts, &payload)
}

#[test]
fn a_socket_under_a_network_withholding_jail_is_denied_naming_network() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scoped = scratch_dir("net-denied");
    let outcome = run_fixture(
        &probe_profile(false, FilesystemScope::Isolated),
        &scoped,
        "network",
        &format!("{}/escape", scoped.display()),
    );
    let _ = std::fs::remove_dir_all(&scoped);
    assert_eq!(
        outcome,
        JailOutcome::Denied {
            axis: CapabilityAxis::Network
        },
        "a withheld-network jail must deny the socket and name the network axis"
    );
}

#[test]
fn an_out_of_scratch_write_under_a_filesystem_withholding_jail_is_denied_naming_filesystem() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scoped = scratch_dir("fs-denied");
    // A path outside the scratch: inside the chroot it lands on the read-only nullfs
    // view of the host, so the write is denied by the mount flag (structural, not a
    // mere permission denial).
    let outcome = run_fixture(
        &probe_profile(false, FilesystemScope::Isolated),
        &scoped,
        "filesystem",
        "/usr/ipe-tier2-escape-probe",
    );
    let _ = std::fs::remove_dir_all(&scoped);
    assert_eq!(
        outcome,
        JailOutcome::Denied {
            axis: CapabilityAxis::Filesystem
        },
        "a withheld-filesystem jail must deny the out-of-scratch write and name the filesystem axis"
    );
}

#[test]
fn a_benign_in_scratch_write_is_clean() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let scoped = scratch_dir("clean");
    let escape = format!("{}/in-scratch-write", scoped.display());
    let outcome = run_fixture(
        &probe_profile(false, FilesystemScope::Isolated),
        &scoped,
        "filesystem",
        &escape,
    );
    let _ = std::fs::remove_dir_all(&scoped);
    assert_eq!(
        outcome,
        JailOutcome::Clean,
        "a benign in-scratch build must be Clean (the only admit-eligible outcome)"
    );
    assert!(outcome.is_clean());
}

/// A writable bind inside a read-only bind, below a level a user can write:
/// its mountpoint would need a tmpfs inside the read-only bind, hiding part of
/// what that bind shows, so the jail refuses to establish.
#[test]
fn a_mountpoint_tmpfs_inside_an_earlier_bind_refuses_the_jail() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let outer = scratch_dir("hide-bind");
    let open = outer.join("open");
    let scoped = open.join("scratch");
    std::fs::create_dir_all(&scoped).expect("scratch");
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777))
        .expect("a user-writable level");
    let outer_canonical = CanonicalPath::resolve(&outer).expect("canonical outer");
    let canonical = CanonicalPath::resolve(&scoped).expect("canonical scratch");
    let mounts = JailMounts::of_invoker(canonical.clone(), canonical, vec![outer_canonical])
        .expect("checked jail mounts");
    let payload = vec![OsString::from("/usr/bin/true")];
    let outcome = build_in_jail(
        &inert_tools(),
        &probe_profile(false, FilesystemScope::Isolated),
        &mounts,
        &payload,
    );
    let _ = std::fs::remove_dir_all(&outer);
    assert!(
        matches!(
            &outcome,
            JailOutcome::Unavailable {
                defect: RunJailDefect::MountFailed { detail, .. }
            } if detail.contains("would hide an earlier mount")
        ),
        "{outcome:?}"
    );
}

/// The jail user base FreeBSD defines: `nobody`.
const NOBODY: u32 = 65_534;

/// The owner a test tree starts with: neither root nor the jail user.
const TREE_OWNER: u32 = 1_234;

/// The variable a re-executed child reads its expected home from.
const HOME_CHILD: &str = "IPE_FB_JAIL_BASE_CHILD";

/// The fix every jail-directory refusal names.
const HOME_HINT: &str = "run with HOME set to a home only root can write";

/// A per-test directory directly under `/`, owned by root and writable only by it.
fn root_only_dir(tag: &str) -> PathBuf {
    let dir = PathBuf::from(format!("/ipe-build-fb-e2e-{tag}-{}", std::process::id()));
    std::fs::DirBuilder::new()
        .mode(0o755)
        .create(&dir)
        .expect("a root-only directory");
    dir
}

/// Give the directory `dir` names to `owner` through a handle open on it.
fn give_dir(dir: &Path, owner: u32) {
    let held = std::fs::File::open(dir).expect("open the directory");
    std::os::unix::fs::fchown(&held, Some(owner), Some(owner)).expect("fchown the held directory");
}

/// Mount `source` read-only on `target` through `mount_nullfs(8)`.
fn mount_nullfs(source: &Path, target: &Path) -> ExitStatus {
    Command::new("/sbin/mount_nullfs")
        .args(["-o", "ro"])
        .arg(source)
        .arg(target)
        .status()
        .expect("mount_nullfs runs")
}

/// Force the newest mount on `target` off through `umount(8)`.
fn unmount(target: &Path) -> ExitStatus {
    Command::new("/sbin/umount")
        .arg("-f")
        .arg(target)
        .status()
        .expect("umount runs")
}

/// The bytes of a NUL-terminated C name, up to its first NUL.
fn c_name(chars: &[std::ffi::c_char]) -> Vec<u8> {
    chars
        .iter()
        .map(|c| u8::from_ne_bytes(c.to_ne_bytes()))
        .take_while(|byte| *byte != 0)
        .collect()
}

/// A canonical scratch with an empty `source` and `target` directory in it.
fn source_and_target(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    let outer = std::fs::canonicalize(scratch_dir(tag)).expect("canonical scratch");
    let source = outer.join("source");
    let target = outer.join("target");
    std::fs::create_dir(&source).expect("source");
    std::fs::create_dir(&target).expect("target");
    (outer, source, target)
}

/// V1: a nullfs mount root shows the source's inode on its own device.
#[test]
fn v1_a_nullfs_mount_root_keeps_the_source_inode_on_its_own_device() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (outer, source, target) = source_and_target("v1");
    let lower = std::fs::metadata(&source).expect("source facts");
    let mounted = mount_nullfs(&source, &target).success();
    let upper = std::fs::metadata(&target).expect("mount root facts");
    let unmounted = unmount(&target).success();
    let _ = std::fs::remove_dir_all(&outer);
    assert!(mounted && unmounted, "the nullfs mount and its unmount ran");
    assert_eq!(
        upper.ino(),
        lower.ino(),
        "the mount root shows the source inode"
    );
    assert_ne!(
        upper.dev(),
        lower.dev(),
        "the mount root is on the nullfs device"
    );
}

/// V2: `fstatfs` on a nullfs mount root names `nullfs` and the source spelling.
#[test]
fn v2_fstatfs_on_a_nullfs_mount_root_names_nullfs_and_the_source() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (outer, source, target) = source_and_target("v2");
    let mounted = mount_nullfs(&source, &target).success();
    let names = std::fs::File::open(&target)
        .ok()
        .and_then(|held| rustix::fs::fstatfs(&held).ok())
        .map(|stat| (c_name(&stat.f_fstypename), c_name(&stat.f_mntfromname)));
    let unmounted = unmount(&target).success();
    let _ = std::fs::remove_dir_all(&outer);
    assert!(mounted && unmounted, "the nullfs mount and its unmount ran");
    assert_eq!(
        names,
        Some((b"nullfs".to_vec(), source.as_os_str().as_bytes().to_vec())),
        "the mount root names its filesystem type and its source"
    );
}

/// V3: the recorded target shows its own device while mounted, and the covered
/// device again once `umount -f <target>` ran.
#[test]
fn v3_umount_of_the_recorded_target_returns_it_to_the_covered_device() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (outer, source, target) = source_and_target("v3");
    let covered = std::fs::metadata(&outer).expect("covered facts").dev();
    let mounted = mount_nullfs(&source, &target).success();
    let while_mounted = std::fs::metadata(&target).expect("mounted facts").dev();
    let unmounted = unmount(&target).success();
    let after = std::fs::metadata(&target).expect("unmounted facts").dev();
    let _ = std::fs::remove_dir_all(&outer);
    assert!(mounted && unmounted, "the nullfs mount and its unmount ran");
    assert_ne!(
        while_mounted, covered,
        "a mounted target shows the mount's device"
    );
    assert_eq!(
        after, covered,
        "the unmounted target shows the covered device"
    );
}

/// V4: the base system defines `nobody` as 65534, and the password database
/// the jail resolves `exec.jail_user` through agrees.
#[test]
fn v4_the_base_system_defines_nobody_as_65534() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let passwd = std::fs::read_to_string("/etc/passwd").expect("/etc/passwd");
    let resolved = Command::new("/usr/bin/id")
        .args(["-u", "nobody"])
        .output()
        .expect("id runs");
    assert!(
        passwd
            .lines()
            .any(|line| line.starts_with("nobody:*:65534:65534:")),
        "/etc/passwd defines nobody as 65534"
    );
    assert!(resolved.status.success(), "{resolved:?}");
    assert_eq!(
        String::from_utf8_lossy(&resolved.stdout).trim(),
        NOBODY.to_string()
    );
}

/// The owner and group ids `path` names now, without following a link.
fn owner_of(path: &Path) -> (u32, u32) {
    let facts = std::fs::symlink_metadata(path).expect("owner facts");
    (facts.uid(), facts.gid())
}

/// Swap `tree` for a link to `decoy` and back until `done`, returning how
/// many swaps landed. Every round ends with `tree` restored.
fn race_tree_name(tree: &Path, decoy: &Path, done: &AtomicBool) -> usize {
    let aside = tree.with_extension("aside");
    let mut swaps = 0_usize;
    while !done.load(Ordering::Relaxed) {
        if std::fs::rename(tree, &aside).is_ok() {
            if std::os::unix::fs::symlink(decoy, tree).is_ok() {
                swaps = swaps.saturating_add(1);
                let _ = std::fs::remove_file(tree);
            }
            let _ = std::fs::rename(&aside, tree);
        }
    }
    swaps
}

/// The working tree is given to the jail user and back through its held
/// handle only: a name swapped for a link to a root-owned decoy while jails
/// run never moves the decoy's owner, and the tree ends with its own owner.
#[test]
fn a_tree_swapped_for_a_symlink_after_hold_is_never_chowned_by_name() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let outer = std::fs::canonicalize(scratch_dir("tree-race")).expect("canonical outer");
    let tree = outer.join("tree");
    let decoy = outer.join("decoy");
    let scoped = outer.join("scratch");
    for dir in [&tree, &decoy, &scoped] {
        std::fs::create_dir(dir).expect("race directory");
    }
    give_dir(&tree, TREE_OWNER);
    let decoy_owner = owner_of(&decoy);
    let scoped_canonical = CanonicalPath::resolve(&scoped).expect("canonical scratch");
    let tree_canonical = CanonicalPath::resolve(&tree).expect("canonical tree");
    let mounts = JailMounts::of_invoker(scoped_canonical, tree_canonical, Vec::new())
        .expect("checked jail mounts");
    let profile = probe_profile(false, FilesystemScope::WorkingTreeReadWrite);
    let payload = vec![OsString::from("/usr/bin/true")];

    let control = build_in_jail(&inert_tools(), &profile, &mounts, &payload);
    let after_control = owner_of(&tree);

    let done = Arc::new(AtomicBool::new(false));
    let racer = {
        let (tree, decoy, done) = (tree.clone(), decoy.clone(), Arc::clone(&done));
        std::thread::Builder::new()
            .name("tree-racer".to_owned())
            .spawn(move || race_tree_name(&tree, &decoy, &done))
            .expect("the racer thread starts")
    };
    let raced: Vec<JailOutcome> = (0..32)
        .map(|_| build_in_jail(&inert_tools(), &profile, &mounts, &payload))
        .collect();
    done.store(true, Ordering::Relaxed);
    let swaps = racer.join().expect("the racer thread ends");
    let after_race = owner_of(&tree);
    let decoy_after = owner_of(&decoy);
    let _ = std::fs::remove_dir_all(&outer);

    assert_eq!(control, JailOutcome::Clean, "the unraced tree run is Clean");
    assert_eq!(
        after_control,
        (TREE_OWNER, TREE_OWNER),
        "the tree owner is restored"
    );
    assert!(
        swaps > 0,
        "the racer swapped the tree name during {raced:?}"
    );
    assert_eq!(decoy_after, decoy_owner, "the decoy owner never moves");
    assert_eq!(
        after_race,
        (TREE_OWNER, TREE_OWNER),
        "the tree owner is restored"
    );
}

/// The jail directories live under `HOME`; a home another user owns refuses
/// the jail before root creates anything in it, naming that home.
#[test]
fn a_jail_base_under_a_user_writable_home_refuses() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let base = root_only_dir("home");
    let home = base.join("home");
    std::fs::create_dir(&home).expect("the user home");
    give_dir(&home, NOBODY);
    let exe = std::env::current_exe().expect("this test binary");
    let out = Command::new(exe)
        .args([
            "--exact",
            "jail_base_home_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("HOME", &home)
        .env(HOME_CHILD, &home)
        .output()
        .expect("the child runs");
    let created = home.join(".cache").exists();
    let _ = std::fs::remove_dir_all(&base);
    assert!(
        out.status.success(),
        "the child under a user-owned HOME ({:?}): {}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!created, "root created nothing in the user-owned home");
}

/// The jail run under the `HOME` its parent test set. Inert unless
/// [`a_jail_base_under_a_user_writable_home_refuses`] launched it.
#[test]
#[ignore = "re-executed by a_jail_base_under_a_user_writable_home_refuses"]
fn jail_base_home_child() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let Some(home) = ipe_env::var_os(HOME_CHILD) else {
        return;
    };
    let scoped = scratch_dir("home-child");
    let canonical = CanonicalPath::resolve(&scoped).expect("canonical scratch");
    let mounts = JailMounts::of_invoker(canonical.clone(), canonical, Vec::new())
        .expect("checked jail mounts");
    let outcome = build_in_jail(
        &inert_tools(),
        &probe_profile(false, FilesystemScope::Isolated),
        &mounts,
        &[OsString::from("/usr/bin/true")],
    );
    let _ = std::fs::remove_dir_all(&scoped);
    let named = format!(
        "{} on the jail directory's path",
        Path::new(&home).display()
    );
    assert!(
        matches!(
            &outcome,
            JailOutcome::Unavailable {
                defect: RunJailDefect::MountFailed { detail, .. }
            } if detail.contains(&named) && detail.contains(HOME_HINT)
        ),
        "{outcome:?}"
    );
}
