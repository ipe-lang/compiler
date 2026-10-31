//! The one decider of the cargo target directory a test-spawned build uses.
//!
//! Every cargo or `ipe` child a test spawns takes its [`Command`] from
//! [`cargo_command`] or [`ipe_command`] over a typed [`BuildTarget`]:
//!
//! * [`BuildTarget::Shared`] links the warm shared dependency tree. A build in
//!   it hands back a [`SharedBuild`], which removes that package's leaf
//!   artifacts when dropped, so the shared tree only ever grows by its
//!   dependencies.
//! * [`BuildTarget::Isolated`] is a private tree for a test that cannot share,
//!   named by a closed [`IsolationReason`]. At most one exists per runner (an
//!   exclusive lock on `isolated/.lock`), and it is removed on drop.
//!
//! Under the end-to-end tier a missing or relative shared target is a typed
//! refusal, never a silent fall back to a private cold tree.

use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, TryLockError};
use std::io;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread::{self, ThreadId};
use std::time::{Duration, Instant};

pub use ipe_env::oracle_target::SharedTarget;
use ipe_env::oracle_target::{self, SHARED_VAR};

use crate::bin::{Tier, e2e_tier};

/// The cargo variable naming the target directory; set only in this module.
const TARGET_DIR_VAR: &str = "CARGO_TARGET_DIR";

/// The directory under the shared root that holds the one isolated tree.
const ISOLATED_DIR: &str = "isolated";

/// The lock file inside [`ISOLATED_DIR`] that serialises isolated trees.
const LOCK_FILE: &str = ".lock";

/// How long [`isolated`] waits for the isolated lock.
///
/// The nextest `ci` profile terminates a test after 300 s
/// (`slow-timeout = { period = "60s", terminate-after = 5 }`), and the OS
/// releases a dead holder's lock, so a live holder lets go within 300 s. The
/// wait stops 30 s short of that so a waiter reports the typed timeout before
/// its own termination.
pub const ISOLATED_LOCK_WAIT: Duration = Duration::from_secs(270);

/// The pause between two attempts at the isolated lock.
const LOCK_POLL: Duration = Duration::from_millis(100);

/// The filesystem step a [`TargetError::Io`] failed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetOp {
    /// Creating the `isolated/` directory.
    CreateIsolatedRoot,
    /// Opening `isolated/.lock`.
    OpenLock,
    /// Taking the lock on `isolated/.lock`.
    Lock,
    /// Listing `isolated/` to remove stale trees.
    ListIsolated,
    /// Removing a stale tree under `isolated/`.
    RemoveStale,
    /// Creating this process's isolated tree.
    CreateTree,
}

/// Why no build target could be chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetError {
    /// The end-to-end tier with neither `IPE_ORACLE_SHARED_TARGET` nor
    /// `CARGO_TARGET_DIR` set.
    SharedTargetUnset,
    /// A set variable is blank or not absolute. Carries the variable's name,
    /// never its value.
    SharedTargetNotAbsolute {
        /// The variable whose value was refused.
        var: &'static str,
    },
    /// Another process held the isolated lock past the wait.
    IsolatedLockTimedOut {
        /// How long this process waited.
        waited: Duration,
    },
    /// The calling thread already holds an isolated tree; a second would wait
    /// on its own lock. Other threads of the process wait on the lock instead.
    IsolatedAlreadyHeld,
    /// A filesystem step failed.
    Io {
        /// The step.
        op: TargetOp,
        /// The error kind.
        kind: io::ErrorKind,
    },
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SharedTargetUnset => write!(
                f,
                "the end-to-end tier needs a shared build target: set {SHARED_VAR} or \
                 {TARGET_DIR_VAR} to an absolute directory"
            ),
            Self::SharedTargetNotAbsolute { var } => {
                write!(f, "{var} is set but is not an absolute directory")
            }
            Self::IsolatedLockTimedOut { waited } => write!(
                f,
                "another test held the isolated build target for {}s",
                waited.as_secs()
            ),
            Self::IsolatedAlreadyHeld => {
                f.write_str("this test thread already holds the isolated build target")
            }
            Self::Io { op, kind } => write!(f, "isolated build target: {op:?} failed: {kind}"),
        }
    }
}

impl std::error::Error for TargetError {}

/// Why a test builds in a private tree instead of the shared one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationReason {
    /// The test asserts `ipe`'s own default target resolution.
    DefaultResolutionUnderTest,
    /// The test drives `ipe dev run`/`ipe dev build`, which emits the fixed package
    /// `ipe-app`; two such builds in one shared target overwrite each other's
    /// binary.
    FixedPackageName,
    /// A foreign triple (wasm32, wasi) whose dependency tree the shared target
    /// does not hold.
    ForeignTriple,
    /// The test asserts a cold or clean build.
    ColdBuildUnderTest,
}

impl IsolationReason {
    /// The directory-name slug of this reason.
    const fn slug(self) -> &'static str {
        match self {
            Self::DefaultResolutionUnderTest => "default-resolution",
            Self::FixedPackageName => "fixed-package",
            Self::ForeignTriple => "foreign-triple",
            Self::ColdBuildUnderTest => "cold-build",
        }
    }
}

/// The target a test-spawned build writes to.
#[derive(Debug)]
pub enum BuildTarget {
    /// The warm shared dependency target.
    Shared(SharedTarget),
    /// This process's private, lock-held tree.
    Isolated(IsolatedTarget),
}

impl BuildTarget {
    /// The target directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Shared(shared) => shared.path(),
            Self::Isolated(isolated) => &isolated.tree,
        }
    }
}

/// Decide the shared target from the tier and the two raw variable values.
///
/// An absolute `IPE_ORACLE_SHARED_TARGET` wins, then an absolute ambient
/// `CARGO_TARGET_DIR`. An empty value counts as unset.
///
/// # Errors
///
/// [`TargetError::SharedTargetNotAbsolute`] for a set value that is blank or
/// relative; [`TargetError::SharedTargetUnset`] under [`Tier::E2e`] when
/// neither is set.
pub fn resolve(
    tier: Tier,
    shared_raw: Option<&str>,
    ambient_raw: Option<&str>,
) -> Result<Option<SharedTarget>, TargetError> {
    for (var, raw) in [(SHARED_VAR, shared_raw), (TARGET_DIR_VAR, ambient_raw)] {
        match raw {
            None | Some("") => {}
            Some(raw) => {
                return oracle_target::parse(raw)
                    .map(Some)
                    .map_err(|_| TargetError::SharedTargetNotAbsolute { var });
            }
        }
    }
    match tier {
        Tier::E2e => Err(TargetError::SharedTargetUnset),
        Tier::Unit => Ok(None),
    }
}

/// The shared target for this process: [`resolve`] over the current tier and
/// environment.
///
/// # Errors
///
/// As [`resolve`].
pub fn shared() -> Result<Option<SharedTarget>, TargetError> {
    let shared_raw = ipe_env::var(SHARED_VAR).ok();
    let ambient_raw = ipe_env::var(TARGET_DIR_VAR).ok();
    resolve(e2e_tier(), shared_raw.as_deref(), ambient_raw.as_deref())
}

/// The `CARGO_TARGET_DIR` value a spawned `ipe`/`cargo` child should carry so
/// it links the warm shared target, or `None` to leave its environment as
/// inherited.
///
/// # Errors
///
/// As [`shared`].
pub fn shared_target_dir() -> Result<Option<PathBuf>, TargetError> {
    shared().map(|t| t.map(SharedTarget::into_path_buf))
}

/// [`shared_target_dir`] as the string a spawned child's `CARGO_TARGET_DIR`
/// or `--target-dir` takes, for call sites that forward the warm target.
///
/// A refused target (blank or relative, or none at all under the end-to-end
/// tier) fails the calling test instead of letting the child fall back to a
/// private tree.
#[must_use]
pub fn child_shared_target_from_env() -> Option<String> {
    match shared_target_dir() {
        Ok(dir) => dir.map(|d| d.to_string_lossy().into_owned()),
        Err(e) => crate::bin::fail(format_args!("{e}")),
    }
}

/// The `cargo` program to spawn: `$CARGO` when the running cargo set it (the
/// toolchain actually in use), else the bare name resolved through `PATH`.
///
/// The one place that names the `cargo` program for a test-spawned child, so
/// every other call site — a build through [`cargo_command`], or a probe that
/// only needs the program itself (`cargo metadata`, a dedicated warm-cache
/// build with its own target directory) — resolves it the same way instead of
/// hand-rolling the literal `"cargo"`.
#[must_use]
pub fn cargo_program() -> std::ffi::OsString {
    ipe_env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

/// A `cargo` command building into `target`, with the compiler wrapper
/// cleared.
///
/// The wrapper is cleared with EMPTY variables rather than removed: a wrapper
/// configured in `~/.cargo/config.toml` is overridden only by a set, empty
/// variable. A cwd-sensitive shared wrapper server is unsound under parallel
/// tests whose scratch directories are removed while it runs.
#[must_use]
pub fn cargo_command(target: &BuildTarget) -> Command {
    let mut cmd = Command::new(cargo_program());
    cmd.env(TARGET_DIR_VAR, target.path())
        .env("CARGO_BUILD_RUSTC_WRAPPER", "")
        .env("RUSTC_WRAPPER", "");
    cmd
}

/// An `ipe` command at `bin` building into `target`.
#[must_use]
pub fn ipe_command(bin: &Path, target: &BuildTarget) -> Command {
    let mut cmd = Command::new(bin);
    cmd.env(TARGET_DIR_VAR, target.path());
    cmd
}

/// Sets `cmd`'s target-directory variable to `dir`.
///
/// For a command [`cargo_command`]/[`ipe_command`] does not fit:
/// - a test that re-execs itself (rather than spawning `cargo`/`ipe` fresh) to
///   pin its own environment before an in-process library call drives the
///   build;
/// - a `cargo` spawn on a detached thread that must carry an owned, `'static`
///   directory rather than a borrowed [`BuildTarget`] (which is not `Clone` —
///   its `Drop` removes the tree it names), so `dir` is cloned from a
///   [`BuildTarget::path`] taken earlier in the same process;
/// - a test that builds into a directory it manages entirely itself (a
///   disposable, already-bounded scratch path it creates and removes, outside
///   the shared/isolated accounting `shared`/`isolated` provide) — `cargo`/
///   `ipe` still must not be spawned by a hand-rolled `CARGO_TARGET_DIR`
///   literal, so this is still the one place that names the variable.
///
/// Either way this stays the one place that names the variable, never a
/// second ad-hoc source.
pub fn set_target_dir_env(cmd: &mut Command, dir: &Path) {
    cmd.env(TARGET_DIR_VAR, dir);
}

/// Removes `cmd`'s target-directory variable.
///
/// The child then resolves its own default (e.g. `ipe`'s per-invocation
/// scratch build directory under its cache base) instead of inheriting this
/// process's ambient `CARGO_TARGET_DIR`.
pub fn clear_target_dir_env(cmd: &mut Command) {
    cmd.env_remove(TARGET_DIR_VAR);
}

/// The threads of this process that hold an [`IsolatedTarget`].
///
/// A thread asking for a second tree would wait on its own lock, so it is
/// refused; any other thread waits on the file lock, which conflicts between
/// two open handles of one process as between two processes.
static ISOLATED_HOLDERS: Mutex<Vec<ThreadId>> = Mutex::new(Vec::new());

/// [`ISOLATED_HOLDERS`], recovered from a poisoned lock: the list is only
/// ever pushed to or retained over, so a panic elsewhere leaves it consistent.
fn isolated_holders() -> MutexGuard<'static, Vec<ThreadId>> {
    ISOLATED_HOLDERS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Drop `holder` from [`ISOLATED_HOLDERS`].
fn release_holder(holder: ThreadId) {
    isolated_holders().retain(|h| *h != holder);
}

/// The sequence number of the next isolated tree in this process.
static ISOLATED_SEQ: AtomicU64 = AtomicU64::new(0);

/// This process's private build tree, under an exclusive lock that proves no
/// other live isolated tree exists. Removed, then unlocked, on drop.
#[derive(Debug)]
pub struct IsolatedTarget {
    tree: PathBuf,
    lock: File,
    holder: ThreadId,
}

impl IsolatedTarget {
    /// The tree's directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.tree
    }
}

impl Drop for IsolatedTarget {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir_all(&self.tree)
            && e.kind() != io::ErrorKind::NotFound
        {
            eprintln!(
                "e2e-support: could not remove isolated target {}: {e}",
                self.tree.display()
            );
        }
        if let Err(e) = self.lock.unlock() {
            eprintln!("e2e-support: could not release the isolated lock: {e}");
        }
        release_holder(self.holder);
    }
}

/// A private build tree for `reason`, under the shared root (or the test temp
/// root when no shared target is set).
///
/// # Errors
///
/// As [`shared`]; [`TargetError::IsolatedAlreadyHeld`] when the calling
/// thread already holds one; [`TargetError::IsolatedLockTimedOut`] past
/// [`ISOLATED_LOCK_WAIT`]; [`TargetError::Io`] when a filesystem step fails.
pub fn isolated(reason: IsolationReason) -> Result<IsolatedTarget, TargetError> {
    let base = shared()?.map_or_else(ipe_test_temp::temp_root, SharedTarget::into_path_buf);
    isolated_in(&base, reason, ISOLATED_LOCK_WAIT)
}

/// [`isolated`] under `base`, waiting at most `wait` for the lock.
fn isolated_in(
    base: &Path,
    reason: IsolationReason,
    wait: Duration,
) -> Result<IsolatedTarget, TargetError> {
    let holder = thread::current().id();
    {
        let mut holders = isolated_holders();
        if holders.contains(&holder) {
            return Err(TargetError::IsolatedAlreadyHeld);
        }
        holders.push(holder);
    }
    let held = take_isolated(base, reason, wait, holder);
    if held.is_err() {
        release_holder(holder);
    }
    held
}

/// Lock `base/isolated/.lock`, sweep every other entry, create the tree.
fn take_isolated(
    base: &Path,
    reason: IsolationReason,
    wait: Duration,
    holder: ThreadId,
) -> Result<IsolatedTarget, TargetError> {
    let io = |op| move |e: io::Error| TargetError::Io { op, kind: e.kind() };
    let root = base.join(ISOLATED_DIR);
    fs::create_dir_all(&root).map_err(io(TargetOp::CreateIsolatedRoot))?;
    let lock = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join(LOCK_FILE))
        .map_err(io(TargetOp::OpenLock))?;
    lock_within(&lock, wait)?;
    // Holding the lock proves no other live isolated tree exists: every entry
    // but the lock itself is a tree a killed holder left behind.
    for entry in fs::read_dir(&root).map_err(io(TargetOp::ListIsolated))? {
        let entry = entry.map_err(io(TargetOp::ListIsolated))?;
        if entry.file_name() == OsStr::new(LOCK_FILE) {
            continue;
        }
        let path = entry.path();
        let removed = if entry.file_type().is_ok_and(|t| t.is_dir()) {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        };
        removed.map_err(io(TargetOp::RemoveStale))?;
    }
    let seq = ISOLATED_SEQ.fetch_add(1, Ordering::Relaxed);
    let tree = root.join(format!("{}-{}-{seq}", reason.slug(), std::process::id()));
    fs::create_dir(&tree).map_err(io(TargetOp::CreateTree))?;
    Ok(IsolatedTarget { tree, lock, holder })
}

/// Take the exclusive lock on `lock`, polling until `wait` has passed.
fn lock_within(lock: &File, wait: Duration) -> Result<(), TargetError> {
    let start = Instant::now();
    loop {
        match lock.try_lock() {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) => {}
            Err(TryLockError::Error(e)) => {
                return Err(TargetError::Io {
                    op: TargetOp::Lock,
                    kind: e.kind(),
                });
            }
        }
        let waited = start.elapsed();
        if waited >= wait {
            return Err(TargetError::IsolatedLockTimedOut { waited });
        }
        std::thread::sleep(LOCK_POLL.min(wait.saturating_sub(waited)));
    }
}

/// A cargo artifact file or directory name: `<name>-<16 lowercase hex>`, with
/// any extension after the first `.` ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactStem<'a> {
    name: &'a str,
}

impl<'a> ArtifactStem<'a> {
    /// Parse a file name, or `None` when it is not `<name>-<16 hex>[.ext]`.
    #[must_use]
    pub fn parse(file_name: &'a str) -> Option<Self> {
        let stem = file_name
            .split_once('.')
            .map_or(file_name, |(stem, _)| stem);
        let (name, hash) = stem.rsplit_once('-')?;
        let is_hash = hash.len() == 16
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        (is_hash && !name.is_empty()).then_some(Self { name })
    }

    /// The crate or package name before the hash.
    #[must_use]
    pub const fn name(&self) -> &'a str {
        self.name
    }
}

/// A built emitted binary and the artifacts it owns.
///
/// Dropping it removes them: in the shared target, that package's leaf
/// artifacts (the dependency tree stays); in an isolated tree, the whole tree
/// it holds.
///
/// Derefs to the binary's path; hold it for as long as the binary runs.
#[derive(Debug)]
pub struct SharedBuild {
    exe: PathBuf,
    owned: Option<OwnedArtifacts>,
    isolated: Option<IsolatedTarget>,
}

/// The package whose leaf artifacts a [`SharedBuild`] removes.
#[derive(Debug)]
struct OwnedArtifacts {
    /// The shared target directory.
    root: PathBuf,
    /// The cargo profile directory name under `root`.
    profile: &'static str,
    /// The package name (`-` separated).
    package: String,
}

impl SharedBuild {
    /// A build in `target` of package `package` whose binary is at `exe`.
    ///
    /// A [`BuildTarget::Shared`] build owns its package's artifacts; a
    /// [`BuildTarget::Isolated`] build holds the isolated tree itself, so the
    /// binary inside it outlives the build call.
    pub(crate) fn new(exe: String, target: BuildTarget, package: &str) -> Self {
        let (owned, isolated) = match target {
            BuildTarget::Shared(shared) => (
                Some(OwnedArtifacts {
                    root: shared.into_path_buf(),
                    profile: "debug",
                    package: package.to_owned(),
                }),
                None,
            ),
            BuildTarget::Isolated(tree) => (None, Some(tree)),
        };
        Self {
            exe: PathBuf::from(exe),
            owned,
            isolated,
        }
    }

    /// The binary's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.exe
    }
}

impl Deref for SharedBuild {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.exe
    }
}

impl AsRef<OsStr> for SharedBuild {
    fn as_ref(&self) -> &OsStr {
        self.exe.as_os_str()
    }
}

impl AsRef<Path> for SharedBuild {
    fn as_ref(&self) -> &Path {
        &self.exe
    }
}

impl fmt::Display for SharedBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.exe.display().fmt(f)
    }
}

impl Drop for SharedBuild {
    fn drop(&mut self) {
        if let Some(owned) = &self.owned {
            owned.remove();
        }
        drop(self.isolated.take());
    }
}

impl OwnedArtifacts {
    /// Remove the package's leaf artifacts, enumerating each directory under
    /// the owned root; a path is never read back from a file or variable.
    fn remove(&self) {
        let crate_name = self.package.replace('-', "_");
        let profile = self.root.join(self.profile);
        // `<profile>/<bin>` and its `.d`: the uplifted binary named exactly
        // after the package.
        remove_matching(&profile, |file_name| {
            file_name
                .split_once('.')
                .map_or(file_name, |(stem, _)| stem)
                == self.package
        });
        for (dir, name) in [
            ("deps", crate_name.as_str()),
            (".fingerprint", self.package.as_str()),
            ("build", self.package.as_str()),
            ("incremental", crate_name.as_str()),
        ] {
            remove_matching(&profile.join(dir), |file_name| {
                ArtifactStem::parse(file_name).is_some_and(|stem| stem.name() == name)
            });
        }
    }
}

/// Remove every entry of `dir` whose UTF-8 file name satisfies `owned`.
fn remove_matching(dir: &Path, owned: impl Fn(&str) -> bool) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_str().is_some_and(&owned) {
            continue;
        }
        let path = entry.path();
        let removed = if entry.file_type().is_ok_and(|t| t.is_dir()) {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        };
        if let Err(e) = removed
            && e.kind() != io::ErrorKind::NotFound
        {
            eprintln!(
                "e2e-support: could not remove build artifact {}: {e}",
                path.display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactStem, BuildTarget, ISOLATED_LOCK_WAIT, IsolationReason, SharedBuild, TargetError,
        isolated_in, resolve,
    };
    use crate::bin::Tier;
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;

    const HASH: &str = "0123456789abcdef";

    /// An absolute path spelled for this host.
    fn host_absolute(leaf: &str) -> String {
        if cfg!(windows) {
            format!(r"C:\{leaf}")
        } else {
            format!("/{leaf}")
        }
    }

    /// A fresh directory under the test temp root.
    fn scratch(tag: &str) -> PathBuf {
        let dir =
            ipe_test_temp::temp_root().join(format!("e2e-target-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        assert!(fs::create_dir_all(&dir).is_ok(), "create {}", dir.display());
        dir
    }

    #[test]
    fn full_tier_without_any_target_is_refused() {
        assert_eq!(
            resolve(Tier::E2e, None, None),
            Err(TargetError::SharedTargetUnset)
        );
        assert_eq!(
            resolve(Tier::E2e, Some(""), Some("")),
            Err(TargetError::SharedTargetUnset)
        );
    }

    #[test]
    fn relative_shared_value_is_refused_not_isolated() {
        let ambient = host_absolute("ambient");
        for raw in [" ", ".", "target", "C:foo", r"\rooted"] {
            for tier in [Tier::Unit, Tier::E2e] {
                assert_eq!(
                    resolve(tier, Some(raw), Some(&ambient)),
                    Err(TargetError::SharedTargetNotAbsolute {
                        var: "IPE_ORACLE_SHARED_TARGET"
                    }),
                    "{raw:?}"
                );
            }
        }
    }

    #[test]
    fn relative_ambient_value_is_refused() {
        for tier in [Tier::Unit, Tier::E2e] {
            assert_eq!(
                resolve(tier, None, Some("target")),
                Err(TargetError::SharedTargetNotAbsolute {
                    var: "CARGO_TARGET_DIR"
                })
            );
        }
    }

    #[test]
    fn shared_wins_over_ambient() {
        let shared = host_absolute("shared");
        let ambient = host_absolute("ambient");
        let got = resolve(Tier::E2e, Some(&shared), Some(&ambient));
        assert_eq!(
            got.map(|t| t.map(super::SharedTarget::into_path_buf)),
            Ok(Some(PathBuf::from(&shared)))
        );
        let got = resolve(Tier::E2e, None, Some(&ambient));
        assert_eq!(
            got.map(|t| t.map(super::SharedTarget::into_path_buf)),
            Ok(Some(PathBuf::from(&ambient)))
        );
    }

    #[test]
    fn unit_tier_without_target_is_none() {
        assert_eq!(resolve(Tier::Unit, None, None), Ok(None));
    }

    #[test]
    fn artifact_stem_refuses_non_hex_and_wrong_width() {
        fn parsed(file_name: &str) -> Option<&str> {
            ArtifactStem::parse(file_name).map(|stem| stem.name())
        }
        assert_eq!(parsed(&format!("app_1-{HASH}")), Some("app_1"));
        assert_eq!(parsed(&format!("app_1-{HASH}.d")), Some("app_1"));
        assert_eq!(
            parsed(&format!("ipe-app-e2e-x-{HASH}")),
            Some("ipe-app-e2e-x")
        );
        for bad in [
            "app_1".to_owned(),
            format!("app_1-{}", &HASH[..15]),
            format!("app_1-{HASH}0"),
            "app_1-0123456789ABCDEF".to_owned(),
            "app_1-0123456789abcdeg".to_owned(),
            format!("-{HASH}"),
        ] {
            assert_eq!(parsed(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn shared_build_drop_removes_only_its_package() {
        let root = scratch("drop");
        let debug = root.join("debug");
        let plant = |rel: &str| {
            let path = debug.join(rel);
            if let Some(parent) = path.parent() {
                assert!(fs::create_dir_all(parent).is_ok());
            }
            assert!(fs::write(&path, b"x").is_ok(), "plant {rel}");
            path
        };
        let mine = [
            plant(&format!("deps/app_1-{HASH}")),
            plant(&format!("deps/app_1-{HASH}.d")),
            plant(&format!(".fingerprint/app-1-{HASH}/bin-app-1")),
            plant(&format!("incremental/app_1-{HASH}/s-x")),
            plant("app-1"),
            plant("app-1.d"),
        ];
        let theirs = [
            plant(&format!("deps/app_10-{HASH}")),
            plant(&format!("deps/app_1x-{HASH}")),
            plant(&format!(".fingerprint/app-10-{HASH}/bin")),
            plant(&format!("deps/libdep-{HASH}.rlib")),
            plant("app-10"),
        ];
        let shared = ipe_env::oracle_target::parse(&root.to_string_lossy());
        assert!(shared.is_ok(), "the scratch root is absolute");
        let Ok(shared) = shared else { return };
        let target = BuildTarget::Shared(shared);
        drop(SharedBuild::new(
            debug.join("app-1").to_string_lossy().into_owned(),
            target,
            "app-1",
        ));
        for path in &mine {
            assert!(!path.exists(), "{} must be removed", path.display());
        }
        assert!(!debug.join(format!(".fingerprint/app-1-{HASH}")).exists());
        for path in &theirs {
            assert!(path.exists(), "{} must stay", path.display());
        }
        let _ = fs::remove_dir_all(&root);
    }

    /// Every isolated-target case runs in one test: the process-level guard
    /// admits one isolated tree at a time, and unit tests share a process.
    #[test]
    #[allow(clippy::panic)] // the unwind under test is a test-scope panic
    fn isolated_target_lifecycle() {
        let base = scratch("isolated");
        let root = base.join("isolated");

        // A tree a killed holder left behind is swept once the lock is held;
        // the lock file stays.
        let stale = root.join("cold-build-1-0");
        assert!(fs::create_dir_all(&stale).is_ok());
        assert!(fs::write(stale.join("CACHEDIR.TAG"), b"x").is_ok());
        let first = isolated_in(&base, IsolationReason::ColdBuildUnderTest, Duration::ZERO);
        assert!(first.is_ok(), "{first:?}");
        assert!(!stale.exists(), "the stale tree is swept");
        assert!(root.join(".lock").exists(), "the lock file stays");

        // A second isolated tree on the holding thread is refused, not
        // deadlocked.
        assert_eq!(
            isolated_in(&base, IsolationReason::ForeignTriple, Duration::ZERO).map(|_| ()),
            Err(TargetError::IsolatedAlreadyHeld)
        );

        // Another thread of the same process is not refused: it waits on the
        // lock, which the main thread's tree keeps it out of until dropped.
        let peer = std::thread::scope(|s| {
            std::thread::Builder::new()
                .spawn_scoped(s, || {
                    isolated_in(&base, IsolationReason::ForeignTriple, Duration::ZERO).map(|_| ())
                })
                .map(std::thread::ScopedJoinHandle::join)
        });
        assert!(
            matches!(peer, Ok(Ok(Err(TargetError::IsolatedLockTimedOut { .. })))),
            "a peer thread waits on the lock, never the per-thread refusal: {peer:?}"
        );

        // The lock wait is bounded: another holder of the lock file keeps a
        // zero-deadline acquire out with the typed timeout.
        let other = fs::File::options().write(true).open(root.join(".lock"));
        assert!(other.is_ok());
        let Ok(other) = other else { return };
        let first_tree = first.as_ref().map(|t| t.path().to_path_buf()).ok();
        drop(first);
        if let Some(tree) = &first_tree {
            assert!(!tree.exists(), "dropping removes the tree");
        }
        assert!(
            other.try_lock().is_ok(),
            "the dropped guard released the lock"
        );
        assert!(matches!(
            isolated_in(&base, IsolationReason::ColdBuildUnderTest, Duration::ZERO),
            Err(TargetError::IsolatedLockTimedOut { .. })
        ));
        assert!(other.unlock().is_ok());

        // A tree is removed when its holder's scope unwinds.
        let tree: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);
        let unwound = std::panic::catch_unwind(|| {
            let held = isolated_in(&base, IsolationReason::ColdBuildUnderTest, Duration::ZERO);
            let Ok(held) = held else { return };
            let _ = fs::write(held.path().join("artifact"), b"x");
            if let Ok(mut slot) = tree.lock() {
                *slot = Some(held.path().to_path_buf());
            }
            panic!("unwind with the isolated tree held");
        });
        assert!(unwound.is_err(), "the scope unwound");
        let tree = tree.lock().ok().and_then(|slot| slot.clone());
        assert!(tree.is_some(), "the scope built a tree");
        if let Some(tree) = tree {
            assert!(!tree.exists(), "the unwound tree is removed");
        }
        let held = isolated_in(&base, IsolationReason::ColdBuildUnderTest, Duration::ZERO);
        assert!(
            held.is_ok(),
            "the unwound guard released the process slot and the lock"
        );
        let Ok(held) = held else { return };

        // A build in an isolated tree holds the tree: its binary outlives the
        // build call and goes with the build guard.
        let tree = held.path().to_path_buf();
        let bin = tree.join("debug").join("app-3");
        assert!(fs::create_dir_all(tree.join("debug")).is_ok());
        assert!(fs::write(&bin, b"x").is_ok());
        let build = SharedBuild::new(
            bin.to_string_lossy().into_owned(),
            BuildTarget::Isolated(held),
            "app-3",
        );
        assert!(bin.exists(), "the held tree keeps the binary");
        drop(build);
        assert!(
            !tree.exists(),
            "dropping the build removes its isolated tree"
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn the_lock_wait_stops_inside_the_nextest_ci_budget() {
        let config = crate::manifest_dir!().join("../../.config/nextest.toml");
        let text = fs::read_to_string(&config);
        assert!(text.is_ok(), "read {}", config.display());
        let text = text.unwrap_or_default();
        let ci = text.split("[profile.ci]").nth(1).unwrap_or_default();
        let line = ci
            .lines()
            .find(|l| l.trim_start().starts_with("slow-timeout"));
        assert_eq!(
            line.map(str::trim),
            Some(r#"slow-timeout = { period = "60s", terminate-after = 5 }"#),
            "the budget ISOLATED_LOCK_WAIT is stated against moved"
        );
        assert!(ISOLATED_LOCK_WAIT < Duration::from_mins(5));
    }
}
