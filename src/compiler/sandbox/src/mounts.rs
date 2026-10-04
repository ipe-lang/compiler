//! The one mount plan every jail that exposes the host root read-only applies.
//!
//! The root view exposes the whole host filesystem, so the invoker's homes — the
//! user home (`~/.ssh`, shell history) and the cargo home (`credentials.toml`) —
//! are masked with a tmpfs wherever they live, not only under `/home`. The only
//! paths visible below a mask are the explicit binds the caller asks for.
//!
//! Mounts apply in order: a later mask hides every earlier mount below it, and
//! a later bind re-exposes what it covers. [`mount_plan`] orders the steps so
//! that no bind after mask `M` equals or contains `M`: a bind that would
//! re-expose a whole home is itself masked afterwards. bwrap renders the plan
//! as argv ([`push_mounts`]); the FreeBSD jail renders it as `tmpfs` and
//! `mount_nullfs` mounts under its chroot.
//!
//! Every path a jail binds, and every path it hands the payload (`--chdir`,
//! `PATH`, `TMPDIR`, `RUSTUP_HOME`, the app), is one [`CanonicalPath`] value:
//! resolved once, so the path the payload is told about is the path bound.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::home::{HomeDir, HomeRefusal, RelativeToolHome, ToolHome};
use crate::vcs_metadata::{JailArm, PointerFault, VcsKind, WritableTree};

/// Directories masked in every jail, whoever the invoker is.
const STATIC_MASKS: [&str; 3] = ["/home", "/root", "/tmp"];

/// Why a jail refuses a path it would mount or hand to the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JailPathError {
    /// A path the jail binds or consumes does not resolve on the host.
    Unresolved {
        /// The path as given.
        path: PathBuf,
        /// Why resolution failed.
        kind: std::io::ErrorKind,
    },
    /// The invoker's home is not a [`HomeDir`], so which directory to mask is
    /// unknown; the refusal says why.
    UserHomeUnresolved(HomeRefusal),
    /// A tool-home variable is set to a relative path.
    ToolHomeRelative(RelativeToolHome),
    /// A path resolved earlier no longer resolves to itself: a component was
    /// swapped for a symlink or removed since.
    Moved {
        /// The canonical path as first resolved.
        path: PathBuf,
    },
    /// A jail path sits at or above the cargo home, so binding it would expose
    /// `credentials.toml`.
    ExposesCargoHome {
        /// The offending bind.
        bind: PathBuf,
        /// The cargo home it would expose.
        cargo_home: PathBuf,
    },
    /// A version-control entry in a writable working tree is a symlink, fifo,
    /// socket, device, or a form its tool never writes, so no carve can be
    /// proved to cover what the host executes from it.
    VcsEntryUnexpectedKind {
        /// The tool the entry belongs to.
        kind: VcsKind,
        /// The entry.
        path: PathBuf,
    },
    /// A version-control pointer file in a writable working tree cannot be
    /// followed to the metadata it names.
    VcsPointerUnreadable {
        /// The tool the pointer belongs to.
        kind: VcsKind,
        /// The pointer file.
        path: PathBuf,
        /// Why it cannot be followed.
        reason: PointerFault,
    },
    /// A version-control entry changed between the carve and its use.
    VcsEntryChanged {
        /// The entry that changed.
        path: PathBuf,
    },
    /// The jail arm cannot mount version-control metadata read-only under a
    /// writable working tree, so it refuses the tree.
    VcsMetadataUncarvable {
        /// The arm that refuses.
        arm: JailArm,
        /// The first metadata path the tree holds.
        path: PathBuf,
    },
}

impl fmt::Display for JailPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unresolved { path, kind } => write!(
                f,
                "the jail path {} does not resolve ({kind}); refusing to build the jail",
                path.display()
            ),
            Self::UserHomeUnresolved(refusal) => write!(
                f,
                "the invoker's home cannot be masked: {refusal}; refusing to build the jail"
            ),
            Self::ToolHomeRelative(relative) => {
                write!(f, "{relative}; refusing to build the jail")
            }
            Self::Moved { path } => write!(
                f,
                "the jail path {} changed after it was resolved; refusing to build the jail",
                path.display()
            ),
            Self::ExposesCargoHome { bind, cargo_home } => write!(
                f,
                "the bind {} would expose the cargo home {} (credentials.toml): no jail \
                 path may sit at or above it; refusing to build the jail",
                bind.display(),
                cargo_home.display()
            ),
            Self::VcsEntryUnexpectedKind { kind, path } => write!(
                f,
                "the {kind} entry {} in the writable working tree is not a form {kind} \
                 writes (a symlink, fifo, socket, or device), so it cannot be kept \
                 read-only; refusing to build the jail",
                path.display()
            ),
            Self::VcsPointerUnreadable { kind, path, reason } => write!(
                f,
                "the {kind} pointer file {} in the writable working tree {reason}; \
                 refusing to build the jail",
                path.display()
            ),
            Self::VcsEntryChanged { path } => write!(
                f,
                "the version-control entry {} changed after the jail checked it; \
                 refusing to build the jail",
                path.display()
            ),
            Self::VcsMetadataUncarvable { arm, path } => write!(
                f,
                "the {arm} jail cannot keep the version-control metadata {} read-only \
                 under a writable working tree: run without the filesystem grant, or \
                 from a tree without version-control metadata; refusing to build the jail",
                path.display()
            ),
        }
    }
}

impl std::error::Error for JailPathError {}

/// A host path in canonical form: the one spelling a jail binds and consumes.
///
/// Resolved once, fail-closed: a path that does not resolve is refused rather
/// than bound or exported as given, so no symlinked spelling can name a
/// location the mount plan hid.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalPath(PathBuf);

impl CanonicalPath {
    /// The canonical form of `path`.
    ///
    /// # Errors
    /// [`JailPathError::Unresolved`] when `path` does not resolve.
    pub fn resolve(path: &Path) -> Result<Self, JailPathError> {
        canonicalize(path)
            .map(Self)
            .map_err(|e| JailPathError::Unresolved {
                path: path.to_path_buf(),
                kind: e.kind(),
            })
    }

    /// Confirm the path still resolves to itself.
    ///
    /// # Errors
    /// [`JailPathError::Moved`] when it now resolves elsewhere or not at all.
    pub fn recheck(&self) -> Result<(), JailPathError> {
        match canonicalize(&self.0) {
            Ok(now) if now == self.0 => Ok(()),
            _ => Err(JailPathError::Moved {
                path: self.0.clone(),
            }),
        }
    }

    /// Test-only: `path` taken as already canonical, for pure argv tests over
    /// paths that need not exist.
    #[cfg(test)]
    #[must_use]
    pub fn assumed(path: &str) -> Self {
        Self(PathBuf::from(path))
    }

    /// The canonical path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for CanonicalPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

/// The host's canonical spelling of `path`.
#[cfg(not(windows))]
fn canonicalize(path: &Path) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(path)
}

/// The host's canonical spelling of `path`, in the plain drive form wherever
/// that form names the same file, so a child process that rejects the verbatim
/// `\\?\` prefix receives a path it accepts.
#[cfg(windows)]
fn canonicalize(path: &Path) -> std::io::Result<PathBuf> {
    dunce::canonicalize(path)
}

/// A host directory hidden behind a tmpfs in the jail.
///
/// Canonical, so the mask lands on the directory the jailed process resolves
/// the path to, whichever symlink it walks through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedDir(PathBuf);

impl MaskedDir {
    /// The directory `path` resolves to, or `None` when it resolves to no
    /// directory the invoker can reach: then nothing is there for the jail to
    /// see, so nothing needs hiding.
    #[must_use]
    pub fn resolve(path: &Path) -> Option<Self> {
        let canonical = canonicalize(path).ok()?;
        canonical.is_dir().then_some(Self(canonical))
    }

    /// The canonical directory.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// The invoker's homes, masked in every jail that binds `/`.
///
/// Only [`Self::resolve`] builds one, so a jail over an unknown user home is
/// unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeMasks {
    user_home: Option<MaskedDir>,
    cargo_home: Option<MaskedDir>,
}

impl HomeMasks {
    const fn new(user_home: Option<MaskedDir>, cargo_home: Option<MaskedDir>) -> Self {
        Self {
            user_home,
            cargo_home,
        }
    }

    /// Mask `user_home` and `cargo_home`.
    ///
    /// A home that resolves to no directory gets no mask: nothing is there to
    /// hide.
    ///
    /// Both homes arrive proven absolute ([`HomeDir`], [`ToolHome`]), so no
    /// judgement on their spelling is made here.
    ///
    /// # Errors
    /// [`JailPathError::UserHomeUnresolved`] carrying the refusal when
    /// `user_home` is not a [`HomeDir`]: which directory to hide is unknown.
    pub fn resolve(
        user_home: Result<&HomeDir, HomeRefusal>,
        cargo_home: Option<&ToolHome>,
    ) -> Result<Self, JailPathError> {
        let user_home = user_home.map_err(JailPathError::UserHomeUnresolved)?;
        Ok(Self::new(
            MaskedDir::resolve(user_home.as_path()),
            cargo_home.and_then(|dir| MaskedDir::resolve(dir.as_path())),
        ))
    }

    /// The homes of the invoking process: `HOME` and the cargo home
    /// (`CARGO_HOME`, else `$HOME/.cargo`).
    ///
    /// # Errors
    /// As [`Self::resolve`]; [`JailPathError::ToolHomeRelative`] also when
    /// `CARGO_HOME` is set to a relative path.
    pub fn of_invoker() -> Result<Self, JailPathError> {
        let home = crate::home::home_dir();
        let cargo_home = crate::home::tool_home("CARGO_HOME", home.as_ref().ok(), ".cargo")
            .map_err(JailPathError::ToolHomeRelative)?;
        Self::resolve(
            home.as_ref().map_err(|refusal| *refusal),
            cargo_home.as_ref(),
        )
    }

    /// Test-only: no home masks, for pure argv tests.
    #[cfg(test)]
    #[must_use]
    pub const fn unmasked() -> Self {
        Self::new(None, None)
    }

    fn dirs(&self) -> impl Iterator<Item = &Path> {
        self.user_home
            .iter()
            .chain(self.cargo_home.iter())
            .map(MaskedDir::as_path)
    }
}

/// One path a jail re-exposes at the same location inside the jail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bind<'a> {
    /// `--ro-bind`: visible, never writable.
    ReadOnly(&'a CanonicalPath),
    /// `--bind`: visible and writable.
    ReadWrite(&'a CanonicalPath),
    /// `--bind` of a working tree, with its version-control carve bound
    /// read-only over it.
    WorkingTree(&'a WritableTree),
}

impl<'a> Bind<'a> {
    /// The path the bind exposes.
    #[must_use]
    pub const fn path(self) -> &'a CanonicalPath {
        match self {
            Self::ReadOnly(path) | Self::ReadWrite(path) => path,
            Self::WorkingTree(tree) => tree.tree(),
        }
    }

    /// The narrower of two binds of one path: read-only when either is, and a
    /// working tree over a plain read-write bind so its carve is kept.
    const fn narrowed(self, other: Self) -> Self {
        match (self, other) {
            (_, Self::ReadOnly(_)) | (Self::ReadWrite(_), Self::WorkingTree(_)) => other,
            (Self::ReadOnly(_) | Self::WorkingTree(_), _)
            | (Self::ReadWrite(_), Self::ReadWrite(_)) => self,
        }
    }

    /// Whether the bind exposes its path writable.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        matches!(self, Self::ReadWrite(_) | Self::WorkingTree(_))
    }

    const fn flag(self) -> &'static str {
        match self {
            Self::ReadOnly(_) => "--ro-bind",
            Self::ReadWrite(_) | Self::WorkingTree(_) => "--bind",
        }
    }
}

/// The canonical form of a static mask, or the mask itself when it does not
/// resolve (bwrap then masks a path nothing lives at).
fn canonical_or_given(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn depth(path: &Path) -> usize {
    path.components().count()
}

/// One mount operation of a jail's mount plan, in the order it is applied.
///
/// A later mask hides every earlier mount below it; a later bind re-exposes
/// the path it names. Each platform renders the same plan: bwrap as
/// `--tmpfs`/`--ro-bind`/`--bind`, FreeBSD as `tmpfs` and `mount_nullfs` mounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountStep<'a> {
    /// A fresh empty tmpfs over the directory: nothing below it stays visible.
    Mask(PathBuf),
    /// The path re-exposed at the same location.
    Bind(Bind<'a>),
}

/// The masks and `binds` of one jail, in the order a jail applies them.
///
/// Masks come shallowest first. Each bind comes right after the mask that most
/// closely contains it, strictly; a bind no mask strictly contains comes before
/// every mask. A bind that equals or contains a mask therefore always precedes
/// that mask, which hides what the bind would have exposed there. Binds keep
/// their relative order within one mask; a path bound twice appears once, at
/// its first position, read-only when any of its binds is.
///
/// Each carve path of a [`Bind::WorkingTree`] is bound read-only right after
/// the last writable bind that contains it, so no writable bind re-exposes it
/// and every later mask that contains it still hides it: the carve is the last
/// word over each carved path. A carve no writable bind contains is already
/// read-only or hidden, and adds no step.
#[must_use]
pub fn mount_plan<'a>(homes: &HomeMasks, binds: &[Bind<'a>]) -> Vec<MountStep<'a>> {
    let mut masks: Vec<PathBuf> = STATIC_MASKS
        .iter()
        .map(|mask| canonical_or_given(Path::new(mask)))
        .chain(homes.dirs().map(Path::to_path_buf))
        .collect();
    masks.sort_by(|a, b| depth(a).cmp(&depth(b)).then_with(|| a.cmp(b)));
    masks.dedup();
    let mut unique: Vec<Bind<'a>> = Vec::with_capacity(binds.len());
    let mut first_at: std::collections::HashMap<_, usize> = std::collections::HashMap::new();
    for bind in binds {
        match first_at.entry(bind.path()) {
            std::collections::hash_map::Entry::Occupied(at) => {
                if let Some(kept) = unique.get_mut(*at.get()) {
                    *kept = kept.narrowed(*bind);
                }
            }
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(unique.len());
                unique.push(*bind);
            }
        }
    }
    let owners: Vec<Option<usize>> = unique
        .iter()
        .map(|bind| {
            let path = bind.path().as_path();
            masks
                .iter()
                .enumerate()
                .filter(|(_, mask)| path != mask.as_path() && path.starts_with(mask))
                .max_by_key(|(_, mask)| depth(mask))
                .map(|(index, _)| index)
        })
        .collect();
    let binds_of = |owner: Option<usize>| {
        unique
            .iter()
            .zip(&owners)
            .filter(move |(_, at)| **at == owner)
            .map(|(bind, _)| MountStep::Bind(*bind))
    };
    let mut plan: Vec<MountStep<'a>> = Vec::with_capacity(masks.len() + unique.len());
    plan.extend(binds_of(None));
    for (index, mask) in masks.into_iter().enumerate() {
        plan.push(MountStep::Mask(mask));
        plan.extend(binds_of(Some(index)));
    }
    with_carves(plan, &unique)
}

/// `plan` with each working-tree carve of `binds` bound read-only right after
/// the last writable step that contains it or lies inside it, so no writable
/// bind, not even one nested in a carved path, lands after its carve.
fn with_carves<'a>(plan: Vec<MountStep<'a>>, binds: &[Bind<'a>]) -> Vec<MountStep<'a>> {
    let carves: Vec<&'a CanonicalPath> = binds
        .iter()
        .filter_map(|bind| match bind {
            Bind::WorkingTree(tree) => Some(tree.carve().paths()),
            Bind::ReadOnly(_) | Bind::ReadWrite(_) => None,
        })
        .flatten()
        .collect();
    if carves.is_empty() {
        return plan;
    }
    let anchors: Vec<Option<usize>> = carves
        .iter()
        .map(|carve| {
            plan.iter().rposition(|step| {
                matches!(step, MountStep::Bind(bind)
                    if bind.is_writable()
                        && (carve.as_path().starts_with(bind.path().as_path())
                            || bind.path().as_path().starts_with(carve.as_path())))
            })
        })
        .collect();
    let mut out: Vec<MountStep<'a>> = Vec::with_capacity(plan.len() + carves.len());
    for (index, step) in plan.into_iter().enumerate() {
        out.push(step);
        out.extend(
            carves
                .iter()
                .zip(&anchors)
                .filter(|(_, anchor)| **anchor == Some(index))
                .map(|(carve, _)| MountStep::Bind(Bind::ReadOnly(carve))),
        );
    }
    out
}

/// Whether a jail binds its working tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkingTree {
    /// Not bound: the jail sees only what the masks leave of it, read-only.
    Unbound,
    /// Bound read-write.
    ReadWrite,
}

impl WorkingTree {
    /// The working-tree bind the filesystem axis `scope` grants.
    #[must_use]
    pub const fn granted_by(scope: &crate::run_jail::FilesystemScope) -> Self {
        match scope {
            crate::run_jail::FilesystemScope::Isolated => Self::Unbound,
            crate::run_jail::FilesystemScope::WorkingTreeReadWrite => Self::ReadWrite,
        }
    }
}

/// The bind set a jail over `mounts` exposes through its masks.
///
/// The read-only binds, the scratch read-write, and the working tree
/// read-write, its version-control carve read-only, only when `working_tree`
/// is [`WorkingTree::ReadWrite`]. Every
/// jail built from a [`crate::JailMounts`] binds exactly this set.
#[must_use]
pub fn jail_binds(mounts: &crate::JailMounts, working_tree: WorkingTree) -> Vec<Bind<'_>> {
    let mut binds: Vec<Bind<'_>> = mounts.read_only().iter().map(Bind::ReadOnly).collect();
    binds.push(Bind::ReadWrite(mounts.scoped_tmp()));
    if working_tree == WorkingTree::ReadWrite {
        binds.push(Bind::WorkingTree(mounts.writable_tree()));
    }
    binds
}

/// Push the bwrap rendering of the mount plan of `homes` and `binds` onto
/// `argv`.
///
/// Each mask is `--tmpfs <mask>` and each bind `--ro-bind`/`--bind <path>
/// <path>`, in [`mount_plan`] order.
pub fn push_mounts(argv: &mut Vec<OsString>, homes: &HomeMasks, binds: &[Bind<'_>]) {
    for step in mount_plan(homes, binds) {
        match step {
            MountStep::Mask(mask) => {
                argv.push("--tmpfs".into());
                argv.push(mask.into());
            }
            MountStep::Bind(bind) => {
                let path = bind.path().as_path().as_os_str();
                argv.push(bind.flag().into());
                argv.push(path.to_owned());
                argv.push(path.to_owned());
            }
        }
    }
}

/// Test oracle: the first bind of `plan` that follows a mask it equals or
/// contains (which would re-expose the masked tree), as `(mask, bind)`.
#[cfg(test)]
pub fn plan_bind_after_covered_mask(plan: &[MountStep<'_>]) -> Option<(PathBuf, PathBuf)> {
    first_bind_after_covered_mask(plan.iter().map(|step| match step {
        MountStep::Mask(mask) => OracleStep::Mask(mask.as_path()),
        MountStep::Bind(bind) => OracleStep::Bind(bind.path().as_path()),
    }))
    .map(|(mask, bind)| (mask.to_path_buf(), bind.to_path_buf()))
}

/// Test oracle: [`plan_bind_after_covered_mask`] over a rendered bwrap argv.
#[cfg(test)]
pub fn bind_after_covered_mask(argv: &[String]) -> Option<(String, String)> {
    let mut steps = Vec::new();
    let mut ops = argv.iter().map(String::as_str);
    while let Some(op) = ops.next() {
        match op {
            "--tmpfs" => steps.extend(ops.next().map(|mask| OracleStep::Mask(Path::new(mask)))),
            "--bind" | "--ro-bind" => {
                steps.extend(ops.nth(1).map(|dest| OracleStep::Bind(Path::new(dest))));
            }
            _ => {}
        }
    }
    first_bind_after_covered_mask(steps).map(|(mask, bind)| {
        (
            mask.to_string_lossy().into_owned(),
            bind.to_string_lossy().into_owned(),
        )
    })
}

/// One applied mount, as the test oracles read it.
#[cfg(test)]
#[derive(Clone, Copy)]
enum OracleStep<'p> {
    Mask(&'p Path),
    Bind(&'p Path),
}

/// The first bind that equals or contains a mask applied before it.
#[cfg(test)]
fn first_bind_after_covered_mask<'p>(
    steps: impl IntoIterator<Item = OracleStep<'p>>,
) -> Option<(&'p Path, &'p Path)> {
    let mut masks: Vec<&Path> = Vec::new();
    for step in steps {
        match step {
            OracleStep::Mask(mask) => masks.push(mask),
            OracleStep::Bind(bind) => {
                if let Some(mask) = masks.iter().find(|mask| mask.starts_with(bind)) {
                    return Some((mask, bind));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_dir::TestDir;

    /// A scratch dir holding a `bin` subdir, removed on drop.
    #[allow(clippy::expect_used)] // test fixture: the scratch dir must exist
    fn temp_dir(label: &str) -> TestDir {
        let dir = TestDir::new(&format!("mounts-{label}")).expect("test dir");
        make_dir(&dir.path().join("bin"));
        dir
    }

    #[allow(clippy::expect_used)] // test fixture: the directory must exist
    fn make_dir(path: &Path) {
        std::fs::create_dir_all(path).expect("create dir");
    }

    #[allow(clippy::expect_used)] // test fixture: the path exists, so it resolves
    fn canonical(path: &Path) -> CanonicalPath {
        CanonicalPath::resolve(path).expect("resolve fixture path")
    }

    fn rendered(homes: &HomeMasks, binds: &[Bind<'_>]) -> Vec<String> {
        let mut argv = Vec::new();
        push_mounts(&mut argv, homes, binds);
        argv.into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    fn position(argv: &[String], window: &[&str]) -> Option<usize> {
        argv.windows(window.len())
            .position(|w| w.iter().zip(window).all(|(a, b)| a == b))
    }

    #[test]
    fn a_missing_home_resolves_to_no_mask() {
        assert_eq!(
            MaskedDir::resolve(Path::new("/nonexistent/ipe-sandbox-home")),
            None
        );
    }

    #[test]
    fn an_unresolvable_jail_path_is_refused() {
        let missing = Path::new("/nonexistent/ipe-sandbox-bind");
        assert_eq!(
            CanonicalPath::resolve(missing),
            Err(JailPathError::Unresolved {
                path: missing.to_path_buf(),
                kind: std::io::ErrorKind::NotFound,
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_path_resolves_to_its_target() {
        let base_dir = temp_dir("canonical-symlink");
        let base = base_dir.path();
        let link = base.join("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(base.join("bin"), &link).expect("symlink");
        assert_eq!(canonical(&link).as_path(), base.join("bin"));
    }

    #[cfg(unix)]
    #[test]
    fn a_path_swapped_for_a_symlink_after_resolving_is_refused() {
        let base_dir = temp_dir("recheck-swap");
        let base = base_dir.path();
        let tree = base.join("tree");
        make_dir(&tree);
        let resolved = canonical(&tree);
        assert_eq!(resolved.recheck(), Ok(()));
        std::fs::remove_dir(&tree).expect("remove tree");
        std::os::unix::fs::symlink(base.join("bin"), &tree).expect("symlink");
        assert_eq!(
            resolved.recheck(),
            Err(JailPathError::Moved {
                path: resolved.as_path().to_path_buf()
            })
        );
    }

    #[test]
    fn a_path_removed_after_resolving_is_refused() {
        let base_dir = temp_dir("recheck-gone");
        let gone = base_dir.path().join("gone");
        make_dir(&gone);
        let resolved = canonical(&gone);
        std::fs::remove_dir(&gone).expect("remove dir");
        assert_eq!(
            resolved.recheck(),
            Err(JailPathError::Moved {
                path: resolved.as_path().to_path_buf()
            })
        );
    }

    #[test]
    fn an_unset_user_home_refuses_the_jail() {
        for refusal in [
            HomeRefusal::Unset,
            HomeRefusal::NotUtf8,
            HomeRefusal::ContainsNul,
            HomeRefusal::NotAbsolute,
            HomeRefusal::ParentComponent,
            HomeRefusal::WindowsDeviceOrVerbatim,
            HomeRefusal::WindowsUnc,
        ] {
            let refused = HomeMasks::resolve(Err(refusal), None);
            assert_eq!(
                refused,
                Err(JailPathError::UserHomeUnresolved(refusal)),
                "{refusal:?}"
            );
            let message = refused.err().map(|e| e.to_string()).unwrap_or_default();
            assert!(message.contains(&refusal.to_string()), "{message:?}");
        }
    }

    #[test]
    fn a_parsed_cargo_home_is_masked() {
        let user_home_dir = temp_dir("parsed-user");
        let cargo_home_dir = temp_dir("parsed-cargo");
        let user = crate::home::test_home(user_home_dir.path());
        let cargo = crate::home::test_tool_home(cargo_home_dir.path());
        let homes = HomeMasks::resolve(Ok(&user), Some(&cargo)).expect("parsed homes");
        assert_eq!(
            homes,
            HomeMasks::new(
                MaskedDir::resolve(user_home_dir.path()),
                MaskedDir::resolve(cargo_home_dir.path()),
            )
        );
        assert_eq!(homes.dirs().count(), 2);
    }

    #[cfg(not(windows))]
    #[test]
    fn an_absolute_user_home_that_does_not_exist_gets_no_mask() {
        let missing = crate::home::test_home(Path::new("/nonexistent/ipe-sandbox-home"));
        assert_eq!(
            HomeMasks::resolve(Ok(&missing), None),
            Ok(HomeMasks::unmasked())
        );
    }

    #[test]
    fn a_cargo_home_outside_home_is_masked_then_only_bin_rebound() {
        let cargo_home_dir = temp_dir("cargo-home-outside");
        let cargo_home = cargo_home_dir.path();
        let bin = canonical(&cargo_home.join("bin"));
        let homes = HomeMasks::new(None, MaskedDir::resolve(cargo_home));
        let argv = rendered(&homes, &[Bind::ReadOnly(&bin)]);
        let home = cargo_home.to_string_lossy().into_owned();
        let bin = bin.as_path().to_string_lossy().into_owned();
        let mask = position(&argv, &["--tmpfs", &home]).expect("cargo home masked");
        let rebind = position(&argv, &["--ro-bind", &bin, &bin]).expect("bin re-bound");
        assert!(
            rebind > mask,
            "bin must be re-bound after the mask: {argv:?}"
        );
        assert_eq!(bind_after_covered_mask(&argv), None, "{argv:?}");
    }

    #[test]
    fn a_user_home_outside_home_is_masked() {
        let user_home_dir = temp_dir("user-home-outside");
        let user_home = user_home_dir.path();
        let homes = HomeMasks::new(MaskedDir::resolve(user_home), None);
        let argv = rendered(&homes, &[]);
        let home = user_home.to_string_lossy().into_owned();
        assert!(position(&argv, &["--tmpfs", &home]).is_some(), "{argv:?}");
    }

    #[test]
    fn a_bind_equal_to_or_covering_a_home_is_masked_after() {
        let cargo_home_dir = temp_dir("cargo-home-covered");
        let cargo_home = cargo_home_dir.path();
        let home_bind = canonical(cargo_home);
        let parent = cargo_home.parent().map(canonical);
        let homes = HomeMasks::new(None, MaskedDir::resolve(cargo_home));
        let mut binds = vec![Bind::ReadOnly(&home_bind)];
        if let Some(parent) = &parent {
            binds.push(Bind::ReadWrite(parent));
        }
        let argv = rendered(&homes, &binds);
        assert_eq!(bind_after_covered_mask(&argv), None, "{argv:?}");
        let home = cargo_home.to_string_lossy().into_owned();
        let mask = position(&argv, &["--tmpfs", &home]).expect("cargo home masked");
        let bind = position(&argv, &["--ro-bind", &home, &home]).expect("home bind");
        assert!(
            bind < mask,
            "a bind of the home itself must be masked: {argv:?}"
        );
    }

    #[test]
    fn nested_homes_each_get_their_own_mask() {
        let user_home_dir = temp_dir("nested-user");
        let user_home = user_home_dir.path();
        let cargo_home = user_home.join("cargo");
        make_dir(&cargo_home.join("bin"));
        let user_bind = canonical(user_home);
        let bin = canonical(&cargo_home.join("bin"));
        let homes = HomeMasks::new(
            MaskedDir::resolve(user_home),
            MaskedDir::resolve(&cargo_home),
        );
        // A whole-user-home bind would re-expose the cargo home without its
        // own mask.
        let argv = rendered(&homes, &[Bind::ReadOnly(&user_bind), Bind::ReadOnly(&bin)]);
        assert_eq!(bind_after_covered_mask(&argv), None, "{argv:?}");
        let cargo = cargo_home.to_string_lossy().into_owned();
        let user = user_home.to_string_lossy().into_owned();
        let cargo_mask = position(&argv, &["--tmpfs", &cargo]).expect("cargo mask");
        let user_mask = position(&argv, &["--tmpfs", &user]).expect("user mask");
        assert!(cargo_mask > user_mask, "{argv:?}");
    }

    #[test]
    fn a_path_bound_twice_is_emitted_once_read_only_whichever_flag_comes_first() {
        let dir = temp_dir("bound-twice");
        let bin = canonical(&dir.path().join("bin"));
        let flat = bin.as_path().to_string_lossy().into_owned();
        for binds in [
            [Bind::ReadOnly(&bin), Bind::ReadWrite(&bin)],
            [Bind::ReadWrite(&bin), Bind::ReadOnly(&bin)],
        ] {
            let argv = rendered(&HomeMasks::unmasked(), &binds);
            assert!(
                position(&argv, &["--ro-bind", &flat, &flat]).is_some(),
                "{argv:?}"
            );
            assert_eq!(position(&argv, &["--bind", &flat, &flat]), None, "{argv:?}");
            let emitted = argv.iter().filter(|arg| **arg == flat).count();
            assert_eq!(emitted, 2, "one bind op, source and target: {argv:?}");
        }
    }

    #[test]
    fn a_path_bound_only_read_write_stays_writable() {
        let dir = temp_dir("bound-rw");
        let bin = canonical(&dir.path().join("bin"));
        let argv = rendered(
            &HomeMasks::unmasked(),
            &[Bind::ReadWrite(&bin), Bind::ReadWrite(&bin)],
        );
        let flat = bin.as_path().to_string_lossy().into_owned();
        assert!(
            position(&argv, &["--bind", &flat, &flat]).is_some(),
            "{argv:?}"
        );
        assert_eq!(
            position(&argv, &["--ro-bind", &flat, &flat]),
            None,
            "{argv:?}"
        );
    }

    #[test]
    fn the_oracle_flags_a_bind_that_re_exposes_a_mask() {
        let argv: Vec<String> = ["--tmpfs", "/srv/home", "--ro-bind", "/srv", "/srv"]
            .map(str::to_owned)
            .to_vec();
        assert_eq!(
            bind_after_covered_mask(&argv),
            Some(("/srv/home".to_owned(), "/srv".to_owned()))
        );
    }

    fn assumed_homes(user_home: &str, cargo_home: &str) -> HomeMasks {
        HomeMasks::new(
            Some(MaskedDir(PathBuf::from(user_home))),
            Some(MaskedDir(PathBuf::from(cargo_home))),
        )
    }

    #[test]
    fn the_plan_oracle_flags_a_bind_that_re_exposes_a_mask() {
        let srv = CanonicalPath::assumed("/srv");
        let plan = [
            MountStep::Mask(PathBuf::from("/srv/home")),
            MountStep::Bind(Bind::ReadOnly(&srv)),
        ];
        assert_eq!(
            plan_bind_after_covered_mask(&plan),
            Some((PathBuf::from("/srv/home"), PathBuf::from("/srv")))
        );
    }

    #[test]
    fn mount_plan_masks_every_home_before_any_bind_it_contains() {
        let user = "/srv/a/b/u";
        let cargo = "/srv/a/b/u/.cargo";
        let homes = assumed_homes(user, cargo);
        let whole_user = CanonicalPath::assumed(user);
        let whole_cargo = CanonicalPath::assumed(cargo);
        let above = CanonicalPath::assumed("/srv/a/b");
        let bin = CanonicalPath::assumed("/srv/a/b/u/.cargo/bin");
        let tree = CanonicalPath::assumed("/srv/a/b/u/tree");
        let plan = mount_plan(
            &homes,
            &[
                Bind::ReadOnly(&whole_user),
                Bind::ReadOnly(&bin),
                Bind::ReadWrite(&whole_cargo),
                Bind::ReadWrite(&above),
                Bind::ReadWrite(&tree),
            ],
        );
        assert_eq!(plan_bind_after_covered_mask(&plan), None, "{plan:?}");
        let mask_at = |mask: &str| {
            plan.iter()
                .position(|step| *step == MountStep::Mask(PathBuf::from(mask)))
        };
        let masks = (mask_at(user), mask_at(cargo));
        assert!(
            masks.0.is_some() && masks.1.is_some(),
            "both homes are masked: {plan:?}"
        );
        let (Some(user_mask), Some(cargo_mask)) = masks else {
            return;
        };
        assert!(user_mask < cargo_mask, "shallowest mask first: {plan:?}");
        for (at, step) in plan.iter().enumerate() {
            let MountStep::Bind(bind) = step else {
                continue;
            };
            let path = bind.path().as_path();
            for (mask, mask_index) in [(user, user_mask), (cargo, cargo_mask)] {
                if path != Path::new(mask) && path.starts_with(mask) {
                    assert!(
                        mask_index < at,
                        "{} must follow the mask {mask}: {plan:?}",
                        path.display()
                    );
                }
            }
        }
    }

    #[test]
    fn bwrap_argv_is_the_rendered_plan() {
        let user = "/srv/a/b/u";
        let cargo = "/srv/a/b/u/.cargo";
        let homes = assumed_homes(user, cargo);
        let bin = CanonicalPath::assumed("/srv/a/b/u/.cargo/bin");
        let scratch = CanonicalPath::assumed("/var/lib/ipe/scratch");
        let tree = CanonicalPath::assumed("/srv/a/b/u/tree");
        let argv = rendered(
            &homes,
            &[
                Bind::ReadOnly(&bin),
                Bind::ReadWrite(&scratch),
                Bind::ReadWrite(&tree),
            ],
        );
        let mut statics: Vec<PathBuf> = STATIC_MASKS
            .iter()
            .map(|mask| canonical_or_given(Path::new(mask)))
            .collect();
        statics.sort_by(|a, b| depth(a).cmp(&depth(b)).then_with(|| a.cmp(b)));
        statics.dedup();
        assert!(
            statics
                .iter()
                .all(|mask| depth(mask) < depth(Path::new(user))),
            "the fixture homes sit below every static mask: {statics:?}"
        );
        let mut expected: Vec<String> = ["--bind", "/var/lib/ipe/scratch", "/var/lib/ipe/scratch"]
            .map(str::to_owned)
            .to_vec();
        for mask in &statics {
            expected.push("--tmpfs".to_owned());
            expected.push(mask.to_string_lossy().into_owned());
        }
        expected.extend(
            [
                "--tmpfs",
                user,
                "--bind",
                "/srv/a/b/u/tree",
                "/srv/a/b/u/tree",
                "--tmpfs",
                cargo,
                "--ro-bind",
                "/srv/a/b/u/.cargo/bin",
                "/srv/a/b/u/.cargo/bin",
            ]
            .map(str::to_owned),
        );
        assert_eq!(argv, expected);
    }

    /// What a path is inside a jail after the rendered `argv` mounts.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Mode {
        /// No step covers it: the read-only root shows it.
        Root,
        /// A mask hides it.
        Hidden,
        /// A read-only bind exposes it.
        ReadOnly,
        /// A writable bind exposes it.
        ReadWrite,
    }

    /// Test oracle: the mode of `path` after replaying `argv` in order, the last
    /// covering step winning.
    fn effective_mode(argv: &[String], path: &Path) -> Mode {
        let mut mode = Mode::Root;
        let mut ops = argv.iter().map(String::as_str);
        while let Some(op) = ops.next() {
            let (step, target) = match op {
                "--tmpfs" => (Mode::Hidden, ops.next()),
                "--ro-bind" => (Mode::ReadOnly, ops.nth(1)),
                "--bind" => (Mode::ReadWrite, ops.nth(1)),
                _ => continue,
            };
            if target.is_some_and(|target| path.starts_with(target)) {
                mode = step;
            }
        }
        mode
    }

    #[test]
    fn a_read_write_tree_binds_its_git_dir_read_only_after_the_tree() {
        let scratch = CanonicalPath::assumed("/srv/scratch");
        let tree = WritableTree::assumed(
            CanonicalPath::assumed("/srv/tree"),
            vec![CanonicalPath::assumed("/srv/tree/.git")],
        );
        let argv = rendered(
            &HomeMasks::unmasked(),
            &[Bind::ReadWrite(&scratch), Bind::WorkingTree(&tree)],
        );
        let bind = position(&argv, &["--bind", "/srv/tree", "/srv/tree"]);
        let carve = position(&argv, &["--ro-bind", "/srv/tree/.git", "/srv/tree/.git"]);
        assert!(
            matches!((bind, carve), (Some(bind), Some(carve)) if bind < carve),
            "{argv:?}"
        );
        assert_eq!(
            effective_mode(&argv, Path::new("/srv/tree/.git/hooks/pre-commit")),
            Mode::ReadOnly
        );
        assert_eq!(
            effective_mode(&argv, Path::new("/srv/tree/src/main.rs")),
            Mode::ReadWrite,
            "the rest of the tree stays writable"
        );
    }

    #[test]
    fn a_working_tree_bound_twice_keeps_its_carve() {
        let path = CanonicalPath::assumed("/srv/tree");
        let tree =
            WritableTree::assumed(path.clone(), vec![CanonicalPath::assumed("/srv/tree/.git")]);
        for binds in [
            [Bind::ReadWrite(&path), Bind::WorkingTree(&tree)],
            [Bind::WorkingTree(&tree), Bind::ReadWrite(&path)],
        ] {
            let argv = rendered(&HomeMasks::unmasked(), &binds);
            assert_eq!(
                effective_mode(&argv, Path::new("/srv/tree/.git/config")),
                Mode::ReadOnly,
                "{argv:?}"
            );
        }
    }

    #[test]
    fn a_masked_home_tree_keeps_its_carve_hidden() {
        let user = "/srv/u";
        let homes = assumed_homes(user, "/srv/u/.cargo");
        let scratch = CanonicalPath::assumed("/srv/scratch");
        let tree = WritableTree::assumed(
            CanonicalPath::assumed(user),
            vec![CanonicalPath::assumed("/srv/u/.git")],
        );
        let argv = rendered(
            &homes,
            &[Bind::ReadWrite(&scratch), Bind::WorkingTree(&tree)],
        );
        let carve = position(&argv, &["--ro-bind", "/srv/u/.git", "/srv/u/.git"]);
        let mask = position(&argv, &["--tmpfs", user]);
        assert!(
            matches!((carve, mask), (Some(carve), Some(mask)) if carve < mask),
            "the carve precedes the home mask that hides it: {argv:?}"
        );
        assert_eq!(
            effective_mode(&argv, Path::new("/srv/u/.git/hooks")),
            Mode::Hidden
        );
    }

    #[test]
    fn the_carve_is_the_last_word_over_each_carved_path() {
        let user = "/srv/u";
        let scratch = CanonicalPath::assumed("/srv/scratch");
        let layouts: [(&str, HomeMasks, &str, Vec<&str>); 3] = [
            (
                "the tree is the scratch",
                HomeMasks::unmasked(),
                "/srv/scratch",
                vec!["/srv/scratch/.git", "/srv/scratch/.hg"],
            ),
            (
                "the tree lies under a masked home",
                assumed_homes(user, "/srv/u/.cargo"),
                "/srv/u/proj",
                vec!["/srv/u/proj/.git", "/srv/u/proj/_darcs"],
            ),
            (
                "a gitfile names a gitdir in the scratch",
                HomeMasks::unmasked(),
                "/srv/tree",
                vec![
                    "/srv/tree/.git",
                    "/srv/scratch/gd",
                    "/srv/scratch/gd/common",
                ],
            ),
        ];
        for (layout, homes, tree, carve) in layouts {
            let tree = WritableTree::assumed(
                CanonicalPath::assumed(tree),
                carve
                    .iter()
                    .map(|path| CanonicalPath::assumed(path))
                    .collect(),
            );
            let argv = rendered(
                &homes,
                &[Bind::ReadWrite(&scratch), Bind::WorkingTree(&tree)],
            );
            for path in &carve {
                let inside = Path::new(path).join("hooks");
                let mode = effective_mode(&argv, &inside);
                assert!(
                    matches!(mode, Mode::ReadOnly | Mode::Hidden),
                    "{layout}: {path} ends {mode:?}: {argv:?}"
                );
            }
            assert_eq!(bind_after_covered_mask(&argv), None, "{layout}: {argv:?}");
        }
    }

    #[test]
    fn a_writable_bind_nested_in_a_carve_never_lands_after_it() {
        let tree = WritableTree::assumed(
            CanonicalPath::assumed("/srv/tree"),
            vec![CanonicalPath::assumed("/srv/tree/.git")],
        );
        let nested = CanonicalPath::assumed("/srv/tree/.git/scratch");
        let argv = rendered(
            &HomeMasks::unmasked(),
            &[Bind::WorkingTree(&tree), Bind::ReadWrite(&nested)],
        );
        assert_eq!(
            effective_mode(&argv, Path::new("/srv/tree/.git/scratch/hooks")),
            Mode::ReadOnly,
            "a writable bind inside a carve is covered by the carve: {argv:?}"
        );
        assert_eq!(
            effective_mode(&argv, Path::new("/srv/tree/.git/config")),
            Mode::ReadOnly,
            "{argv:?}"
        );
    }
}
