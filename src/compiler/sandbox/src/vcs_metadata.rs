//! The version-control metadata a writable working tree holds, carved read-only.
//!
//! The host runs code that version-control metadata names: `.git/hooks/*`, the
//! drivers `.git/config` points at, `.hg/hgrc` hooks, `.jj/repo/config.toml`,
//! `_darcs` posthooks. A jailed child that can write that metadata escapes the
//! jail the next time the developer runs the tool on the host. A read-write
//! working-tree grant therefore enters a jail only as a [`WritableTree`]: the
//! tree parsed once against [`VcsKind::ALL`], carrying every metadata entry and
//! every in-grant directory a pointer file names. The shared mount plan renders
//! that carve read-only over the grant; an arm that cannot refuses the jail.
//! The configuration each carved entry's tool reads is then scanned
//! ([`crate::scan_vcs_config`]), so no carved setting names code the jail can
//! write.
//!
//! The parse is bounded by construction: four entry names, one pointer read of
//! at most [`POINTER_CAP`] bytes per pointer file, and a fixed chain of at most
//! two hops (a gitfile names a gitdir, whose `commondir` names the shared
//! `.git`).

use std::fmt;
use std::io::Read as _;
use std::path::Path;

use crate::vcs_config::{ConfigLimits, ConfigRoots, Grants, Home, scan};
use crate::{CanonicalPath, JailPathError, path_covers};

/// The most bytes a version-control pointer file may hold.
pub const POINTER_CAP: u64 = 4096;

/// One version-control system whose in-tree metadata the host executes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VcsKind {
    /// Git: `.git/hooks/*`, and the `core.fsmonitor`, `core.hooksPath`,
    /// `core.pager`, `core.sshCommand`, filter and diff drivers `.git/config`
    /// names.
    Git,
    /// Mercurial: the hooks and extensions `.hg/hgrc` names.
    Mercurial,
    /// Jujutsu: the commands and hooks `.jj/repo/config.toml` names.
    Jujutsu,
    /// Darcs: the posthooks `_darcs/prefs/defaults` names.
    Darcs,
}

impl VcsKind {
    /// Every kind, the one list every carve, rule and test derives from.
    pub const ALL: [Self; 4] = [Self::Git, Self::Mercurial, Self::Jujutsu, Self::Darcs];

    /// The entry name the kind keeps its metadata under at a tree's root.
    #[must_use]
    pub const fn entry_name(self) -> &'static str {
        match self {
            Self::Git => ".git",
            Self::Mercurial => ".hg",
            Self::Jujutsu => ".jj",
            Self::Darcs => "_darcs",
        }
    }
}

impl fmt::Display for VcsKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tool = match self {
            Self::Git => "Git",
            Self::Mercurial => "Mercurial",
            Self::Jujutsu => "Jujutsu",
            Self::Darcs => "Darcs",
        };
        write!(f, "{tool} ({})", self.entry_name())
    }
}

/// Why a version-control pointer file cannot be followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerFault {
    /// The file, or its metadata, cannot be read.
    Unreadable(std::io::ErrorKind),
    /// The file holds more than [`POINTER_CAP`] bytes.
    OverCap,
    /// The file is not UTF-8.
    NotUtf8,
    /// The file is not exactly one path line in the tool's pointer form.
    Malformed,
    /// The named path does not resolve, so it cannot be proved outside every
    /// writable grant.
    Unresolvable(std::io::ErrorKind),
    /// The named path is not a directory.
    NotADirectory,
    /// The named directory equals or contains a writable jail path, so no
    /// read-only carve can cover it without covering the grant.
    CoversWritableGrant,
}

impl fmt::Display for PointerFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable(kind) => write!(f, "cannot be read ({kind})"),
            Self::OverCap => write!(f, "holds more than {POINTER_CAP} bytes"),
            Self::NotUtf8 => f.write_str("is not UTF-8"),
            Self::Malformed => f.write_str("is not exactly one path line"),
            Self::Unresolvable(kind) => write!(f, "names a path that does not resolve ({kind})"),
            Self::NotADirectory => f.write_str("names a path that is not a directory"),
            Self::CoversWritableGrant => {
                f.write_str("names a directory at or above a writable jail path")
            }
        }
    }
}

/// A jail arm that cannot yet mount a carve read-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JailArm {
    /// The FreeBSD `jail(2)` arm.
    Freebsd,
    /// The Windows `AppContainer` arm.
    Windows,
}

impl fmt::Display for JailArm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Freebsd => "FreeBSD",
            Self::Windows => "Windows",
        })
    }
}

/// What an entry was when the parse classified it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Dir,
    File,
    /// A symlink, fifo, socket, or device.
    Other,
}

/// The identity of a carved entry, compared again before the jail spawns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Identity {
    dir: bool,
    node: Option<(u64, u64)>,
}

impl Identity {
    /// The kind of `meta`, and its `(dev, ino)` on unix; no portable node
    /// identity exists off unix, so the kind alone is compared there.
    fn of(meta: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        let node = {
            use std::os::unix::fs::MetadataExt as _;
            Some((meta.dev(), meta.ino()))
        };
        #[cfg(not(unix))]
        let node = None;
        Self {
            dir: meta.is_dir(),
            node,
        }
    }
}

/// One path a writable tree's grant must leave read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarvePath {
    path: CanonicalPath,
    identity: Identity,
}

impl CarvePath {
    /// The carved path.
    #[must_use]
    pub const fn path(&self) -> &CanonicalPath {
        &self.path
    }
}

/// Every path a writable tree's grant must leave read-only.
///
/// Empty when the tree holds no version-control metadata: a typed state, not a
/// skipped check. Only [`WritableTree::parse`] fills one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VcsCarve(Vec<CarvePath>);

impl VcsCarve {
    /// The carved paths, in parse order.
    pub fn paths(&self) -> impl Iterator<Item = &CanonicalPath> {
        self.0.iter().map(CarvePath::path)
    }

    /// Whether the tree holds no version-control metadata.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn contains(&self, path: &CanonicalPath) -> bool {
        self.0.iter().any(|carved| carved.path == *path)
    }
}

/// A working tree a jail grants read-write, with the carve it must render.
///
/// Built only by [`Self::parse`], so no arm receives a writable tree whose
/// version-control metadata was never looked for, nor one whose carved
/// configuration names code inside a writable grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WritableTree {
    tree: CanonicalPath,
    carve: VcsCarve,
}

impl WritableTree {
    /// `tree` with its carve: each [`VcsKind::ALL`] entry present at its root,
    /// and each directory a pointer file names that lies inside `tree` or one of
    /// `other_grants` (the jail's other writable paths).
    ///
    /// The configuration each carved entry's tool reads is scanned against
    /// those grants, with `home` the invoker's home the tool expands `~`
    /// against.
    ///
    /// # Errors
    /// - [`JailPathError::VcsEntryUnexpectedKind`] when an entry, or a pointer
    ///   file inside one, is a symlink, fifo, socket, or device, or a form the
    ///   tool never writes.
    /// - [`JailPathError::VcsPointerUnreadable`] when a pointer file cannot be
    ///   read, exceeds [`POINTER_CAP`], is malformed, or names a path that does
    ///   not resolve, is no directory, or covers a writable grant.
    /// - [`JailPathError::VcsEntryChanged`] when an entry changed while it was
    ///   read.
    /// - [`JailPathError::VcsConfig`] when a configuration the tool reads names,
    ///   or may name, code inside a writable grant, or cannot be read.
    pub fn parse(
        tree: CanonicalPath,
        other_grants: &[&CanonicalPath],
        home: &Home,
    ) -> Result<Self, JailPathError> {
        let (carve, roots) = Carver::carve(&tree, other_grants)?;
        scan_roots(&tree, other_grants, &carve, &roots, home)?;
        Ok(Self { tree, carve })
    }

    /// Confirm the tree still holds exactly the carve it was parsed with, and
    /// its configuration still names no code inside a writable grant.
    ///
    /// # Errors
    /// [`JailPathError::VcsEntryChanged`] when an entry appeared, vanished, or
    /// was replaced since the parse; any error of [`Self::parse`] the tree now
    /// raises.
    pub fn recheck(
        &self,
        other_grants: &[&CanonicalPath],
        home: &Home,
    ) -> Result<(), JailPathError> {
        let (now, roots) = Carver::carve(&self.tree, other_grants)?;
        if now == self.carve {
            return scan_roots(&self.tree, other_grants, &now, &roots, home);
        }
        let changed = self
            .carve
            .0
            .iter()
            .find(|was| !now.0.contains(was))
            .or_else(|| now.0.iter().find(|is| !self.carve.0.contains(is)))
            .map_or(&self.tree, CarvePath::path);
        Err(JailPathError::VcsEntryChanged {
            path: changed.as_path().to_path_buf(),
        })
    }

    /// The tree the grant covers.
    #[must_use]
    pub const fn tree(&self) -> &CanonicalPath {
        &self.tree
    }

    /// The paths the grant must leave read-only.
    #[must_use]
    pub const fn carve(&self) -> &VcsCarve {
        &self.carve
    }

    /// Test-only: `tree` taken with `carve` as given, for pure plan tests over
    /// paths that need not exist.
    #[cfg(test)]
    #[must_use]
    pub fn assumed(tree: CanonicalPath, carve: Vec<CanonicalPath>) -> Self {
        let identity = Identity {
            dir: true,
            node: None,
        };
        Self {
            tree,
            carve: VcsCarve(
                carve
                    .into_iter()
                    .map(|path| CarvePath { path, identity })
                    .collect(),
            ),
        }
    }
}

/// The directories one carved entry's tool reads its configuration from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum VcsRoot {
    /// A gitdir, and the common dir its `commondir` names.
    Git {
        gitdir: CanonicalPath,
        commondir: Option<CanonicalPath>,
    },
    /// A `.hg` dir, and the share source its `sharedpath` names.
    Mercurial {
        dot_hg: CanonicalPath,
        shared: Option<CanonicalPath>,
    },
    /// A `.jj` dir and the repository directory it uses.
    Jujutsu {
        dot_jj: CanonicalPath,
        repo: CanonicalPath,
    },
    /// A `_darcs` dir.
    Darcs { dot_darcs: CanonicalPath },
}

impl VcsRoot {
    /// The roots the configuration scan starts from.
    fn config_roots(&self) -> ConfigRoots<'_> {
        match self {
            Self::Git { gitdir, commondir } => ConfigRoots::Git {
                gitdir: gitdir.as_path(),
                commondir: commondir.as_ref().map(CanonicalPath::as_path),
            },
            Self::Mercurial { dot_hg, shared } => ConfigRoots::Mercurial {
                dot_hg: dot_hg.as_path(),
                shared: shared.as_ref().map(CanonicalPath::as_path),
            },
            Self::Jujutsu { dot_jj, repo } => ConfigRoots::Jujutsu {
                dot_jj: dot_jj.as_path(),
                repo: repo.as_path(),
            },
            Self::Darcs { dot_darcs } => ConfigRoots::Darcs {
                dot_darcs: dot_darcs.as_path(),
            },
        }
    }
}

/// Scan the configuration every one of `roots` reads against the writable
/// grants `tree` and `other_grants`, with `carve` mounted read-only over them.
fn scan_roots(
    tree: &CanonicalPath,
    other_grants: &[&CanonicalPath],
    carve: &VcsCarve,
    roots: &[VcsRoot],
    home: &Home,
) -> Result<(), JailPathError> {
    let carves: Vec<&CanonicalPath> = carve.paths().collect();
    let grants = Grants::new(tree, other_grants).with_carves(&carves);
    roots.iter().try_for_each(|root| {
        scan(&root.config_roots(), &grants, home, ConfigLimits::DEFAULT)
            .map_err(JailPathError::VcsConfig)
    })
}

/// One parse of a tree: its writable grants, the carve found so far, and the
/// configuration roots of each carved entry.
struct Carver<'g> {
    tree: &'g CanonicalPath,
    grants: Vec<&'g CanonicalPath>,
    carve: VcsCarve,
    roots: Vec<VcsRoot>,
}

impl<'g> Carver<'g> {
    fn carve(
        tree: &'g CanonicalPath,
        other_grants: &[&'g CanonicalPath],
    ) -> Result<(VcsCarve, Vec<VcsRoot>), JailPathError> {
        let mut carver = Self {
            tree,
            grants: std::iter::once(tree)
                .chain(other_grants.iter().copied())
                .collect(),
            carve: VcsCarve::default(),
            roots: Vec::new(),
        };
        for kind in VcsKind::ALL {
            carver.entry(kind)?;
        }
        Ok((carver.carve, carver.roots))
    }

    /// Carve `kind`'s root entry, and follow the pointer files it holds.
    fn entry(&mut self, kind: VcsKind) -> Result<(), JailPathError> {
        let entry = self.tree.as_path().join(kind.entry_name());
        let Some((shape, meta)) = classify(kind, &entry)? else {
            return Ok(());
        };
        let unexpected = || JailPathError::VcsEntryUnexpectedKind {
            kind,
            path: entry.clone(),
        };
        let root = match (kind, shape) {
            (_, Shape::Other) | (VcsKind::Mercurial, Shape::File) => return Err(unexpected()),
            (VcsKind::Jujutsu | VcsKind::Darcs, Shape::File) => {
                self.add_entry(&entry, &meta)?;
                None
            }
            (VcsKind::Darcs, Shape::Dir) => Some(VcsRoot::Darcs {
                dot_darcs: self.add_entry(&entry, &meta)?,
            }),
            (VcsKind::Git, Shape::Dir) => {
                // Git reads `commondir` in every gitdir, the root `.git` dir
                // included, and takes config and hooks from the dir it names.
                let gitdir = self.add_entry(&entry, &meta)?;
                let commondir = self.inner_pointer(kind, &entry.join("commondir"), false)?;
                Some(VcsRoot::Git { gitdir, commondir })
            }
            (VcsKind::Git, Shape::File) => {
                self.add_entry(&entry, &meta)?;
                let text = read_pointer(kind, &entry, &meta)?;
                let gitdir = text
                    .strip_prefix("gitdir: ")
                    .and_then(one_line)
                    .ok_or_else(|| pointer_fault(kind, &entry, PointerFault::Malformed))?;
                let gitdir = self.target(kind, &entry, self.tree.as_path(), gitdir)?;
                let commondir =
                    self.inner_pointer(kind, &gitdir.as_path().join("commondir"), false)?;
                Some(VcsRoot::Git { gitdir, commondir })
            }
            (VcsKind::Mercurial, Shape::Dir) => {
                let dot_hg = self.add_entry(&entry, &meta)?;
                let shared = self.inner_pointer(kind, &entry.join("sharedpath"), false)?;
                Some(VcsRoot::Mercurial { dot_hg, shared })
            }
            (VcsKind::Jujutsu, Shape::Dir) => {
                // Without a repository directory Jujutsu reads no configuration.
                let dot_jj = self.add_entry(&entry, &meta)?;
                self.inner_pointer(kind, &entry.join("repo"), true)?
                    .map(|repo| VcsRoot::Jujutsu { dot_jj, repo })
            }
        };
        self.roots.extend(root);
        Ok(())
    }

    /// Follow the optional pointer file `pointer`, whose relative path resolves
    /// against its parent; a directory there is admitted only when `dir_ok`.
    ///
    /// The directory reached: the one the pointer names, the directory at
    /// `pointer` itself, or `None` when nothing is there.
    fn inner_pointer(
        &mut self,
        kind: VcsKind,
        pointer: &Path,
        dir_ok: bool,
    ) -> Result<Option<CanonicalPath>, JailPathError> {
        let Some((shape, meta)) = classify(kind, pointer)? else {
            return Ok(None);
        };
        match shape {
            Shape::Dir if dir_ok => CanonicalPath::resolve(pointer).map(Some).map_err(|_| {
                JailPathError::VcsEntryChanged {
                    path: pointer.to_path_buf(),
                }
            }),
            Shape::Dir | Shape::Other => Err(JailPathError::VcsEntryUnexpectedKind {
                kind,
                path: pointer.to_path_buf(),
            }),
            Shape::File => {
                let text = read_pointer(kind, pointer, &meta)?;
                let named = one_line(&text)
                    .ok_or_else(|| pointer_fault(kind, pointer, PointerFault::Malformed))?;
                let base = pointer.parent().unwrap_or(pointer);
                self.target(kind, pointer, base, named).map(Some)
            }
        }
    }

    /// The directory `named` (relative to `base`) that `pointer` names, carved
    /// when it lies inside a writable grant.
    fn target(
        &mut self,
        kind: VcsKind,
        pointer: &Path,
        base: &Path,
        named: &str,
    ) -> Result<CanonicalPath, JailPathError> {
        let fault = |reason| pointer_fault(kind, pointer, reason);
        let target = CanonicalPath::resolve(&base.join(named)).map_err(|e| match e {
            JailPathError::Unresolved { kind: io, .. } => fault(PointerFault::Unresolvable(io)),
            other => other,
        })?;
        let meta = std::fs::metadata(target.as_path())
            .map_err(|e| fault(PointerFault::Unresolvable(e.kind())))?;
        if !meta.is_dir() {
            return Err(fault(PointerFault::NotADirectory));
        }
        if self
            .grants
            .iter()
            .any(|grant| path_covers(target.as_path(), grant.as_path()))
        {
            return Err(fault(PointerFault::CoversWritableGrant));
        }
        if self
            .grants
            .iter()
            .any(|grant| path_covers(grant.as_path(), target.as_path()))
        {
            self.add(target.clone(), Identity::of(&meta));
        }
        Ok(target)
    }

    /// Carve the root entry `entry`, classified with `meta`, and return its
    /// canonical path.
    fn add_entry(
        &mut self,
        entry: &Path,
        meta: &std::fs::Metadata,
    ) -> Result<CanonicalPath, JailPathError> {
        let changed = || JailPathError::VcsEntryChanged {
            path: entry.to_path_buf(),
        };
        let path = CanonicalPath::resolve(entry).map_err(|_| changed())?;
        let now = std::fs::symlink_metadata(path.as_path()).map_err(|_| changed())?;
        let identity = Identity::of(meta);
        if Identity::of(&now) != identity {
            return Err(changed());
        }
        self.add(path.clone(), identity);
        Ok(path)
    }

    fn add(&mut self, path: CanonicalPath, identity: Identity) {
        if !self.carve.contains(&path) {
            self.carve.0.push(CarvePath { path, identity });
        }
    }
}

/// What `path` is, without following a final symlink; `None` when absent.
fn classify(
    kind: VcsKind,
    path: &Path,
) -> Result<Option<(Shape, std::fs::Metadata)>, JailPathError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            let file_type = meta.file_type();
            let shape = if file_type.is_dir() {
                Shape::Dir
            } else if file_type.is_file() {
                Shape::File
            } else {
                Shape::Other
            };
            Ok(Some((shape, meta)))
        }
        Err(e) if is_absent(e.kind()) => Ok(None),
        Err(e) => Err(pointer_fault(
            kind,
            path,
            PointerFault::Unreadable(e.kind()),
        )),
    }
}

/// Whether an `lstat` error proves nothing is at the path: it is missing, or
/// its parent is no directory.
const fn is_absent(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

/// The text of the regular file `path`, classified as `meta`, read through one
/// handle that never follows a link and is proved to be that same file.
fn read_pointer(
    kind: VcsKind,
    path: &Path,
    meta: &std::fs::Metadata,
) -> Result<String, JailPathError> {
    let fault = |reason| pointer_fault(kind, path, reason);
    let file = open_no_follow(path).map_err(|e| fault(PointerFault::Unreadable(e.kind())))?;
    let held = file
        .metadata()
        .map_err(|e| fault(PointerFault::Unreadable(e.kind())))?;
    if !held.is_file() || Identity::of(&held) != Identity::of(meta) {
        return Err(JailPathError::VcsEntryChanged {
            path: path.to_path_buf(),
        });
    }
    let mut bytes = Vec::new();
    file.take(POINTER_CAP.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| fault(PointerFault::Unreadable(e.kind())))?;
    if u64::try_from(bytes.len())
        .ok()
        .is_none_or(|len| len > POINTER_CAP)
    {
        return Err(fault(PointerFault::OverCap));
    }
    String::from_utf8(bytes).map_err(|_| fault(PointerFault::NotUtf8))
}

/// `path` opened read-only without following a final symlink and without
/// blocking on a fifo.
#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(std::fs::File::from(fd))
}

/// `path` opened read-only; the handle's metadata is then proved to be the
/// regular file the parse classified.
#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// The one path line `text` holds: one trailing line ending allowed, no other
/// line break, no NUL, not empty.
fn one_line(text: &str) -> Option<&str> {
    let line = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    let clean = !line.is_empty() && !line.contains(['\n', '\r', '\0']);
    clean.then_some(line)
}

fn pointer_fault(kind: VcsKind, path: &Path, reason: PointerFault) -> JailPathError {
    JailPathError::VcsPointerUnreadable {
        kind,
        path: path.to_path_buf(),
        reason,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // test fixtures: the scratch dirs must exist
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::test_dir::TestDir;

    struct Fixture {
        _dir: TestDir,
        root: PathBuf,
        tree: PathBuf,
        tmp: PathBuf,
    }

    fn fixture(label: &str) -> Fixture {
        let dir = TestDir::new(&format!("vcs-{label}")).expect("test dir");
        let root = std::fs::canonicalize(dir.path()).expect("canonical root");
        let tree = root.join("tree");
        let tmp = root.join("tmp");
        make_dir(&tree);
        make_dir(&tmp);
        Fixture {
            _dir: dir,
            root,
            tree,
            tmp,
        }
    }

    fn make_dir(path: &Path) {
        std::fs::create_dir_all(path).expect("create dir");
    }

    fn write(path: &Path, text: &str) {
        std::fs::write(path, text).expect("write fixture file");
    }

    fn canonical(path: &Path) -> CanonicalPath {
        CanonicalPath::resolve(path).expect("canonical fixture path")
    }

    fn parse(fixture: &Fixture) -> Result<WritableTree, JailPathError> {
        WritableTree::parse(
            canonical(&fixture.tree),
            &[&canonical(&fixture.tmp)],
            &Home::unknown(),
        )
    }

    fn carved(tree: &WritableTree) -> Vec<PathBuf> {
        tree.carve()
            .paths()
            .map(|path| path.as_path().to_path_buf())
            .collect()
    }

    #[test]
    fn a_tree_without_metadata_has_the_empty_carve() {
        let fixture = fixture("empty");
        make_dir(&fixture.tree.join("src"));
        let tree = parse(&fixture).expect("a plain tree parses");
        assert!(tree.carve().is_empty(), "{tree:?}");
    }

    #[test]
    fn every_vcs_kind_present_is_carved() {
        for kind in VcsKind::ALL {
            let fixture = fixture("every-kind");
            let entry = fixture.tree.join(kind.entry_name());
            make_dir(&entry);
            let tree = parse(&fixture).expect("a metadata dir parses");
            assert_eq!(carved(&tree), vec![entry], "{kind}");
        }
        let fixture = fixture("all-kinds");
        for kind in VcsKind::ALL {
            make_dir(&fixture.tree.join(kind.entry_name()));
        }
        let tree = parse(&fixture).expect("every metadata dir parses");
        let expected: Vec<PathBuf> = VcsKind::ALL
            .iter()
            .map(|kind| fixture.tree.join(kind.entry_name()))
            .collect();
        assert_eq!(carved(&tree), expected);
    }

    #[test]
    fn a_git_file_pointing_inside_the_tree_carves_the_gitdir_and_commondir() {
        let fixture = fixture("gitfile-inside");
        let common = fixture.tree.join("main.git");
        let gitdir = common.join("worktrees").join("wt");
        make_dir(&gitdir);
        write(&gitdir.join("commondir"), "../..\n");
        write(
            &fixture.tree.join(".git"),
            "gitdir: main.git/worktrees/wt\n",
        );
        let tree = parse(&fixture).expect("an in-tree gitfile parses");
        assert_eq!(
            carved(&tree),
            vec![fixture.tree.join(".git"), gitdir, common]
        );
    }

    #[test]
    fn a_git_file_pointing_into_the_scratch_carves_the_gitdir() {
        let fixture = fixture("gitfile-scratch");
        let gitdir = fixture.tmp.join("repo.git");
        make_dir(&gitdir);
        write(
            &fixture.tree.join(".git"),
            &format!("gitdir: {}", gitdir.display()),
        );
        let tree = parse(&fixture).expect("a scratch gitfile parses");
        assert_eq!(carved(&tree), vec![fixture.tree.join(".git"), gitdir]);
    }

    #[test]
    fn a_git_file_pointing_outside_every_grant_carves_only_the_file() {
        let fixture = fixture("gitfile-outside");
        let common = fixture.root.join("main").join(".git");
        let gitdir = common.join("worktrees").join("wt");
        make_dir(&gitdir);
        write(&gitdir.join("commondir"), "../..\n");
        write(
            &fixture.tree.join(".git"),
            &format!("gitdir: {}\n", gitdir.display()),
        );
        let tree = parse(&fixture).expect("an out-of-grant gitfile parses");
        assert_eq!(carved(&tree), vec![fixture.tree.join(".git")]);
    }

    #[test]
    fn a_commondir_pointing_back_into_the_tree_is_carved() {
        let fixture = fixture("commondir-back");
        let gitdir = fixture.root.join("elsewhere");
        let common = fixture.tree.join("shared.git");
        make_dir(&gitdir);
        make_dir(&common);
        write(
            &gitdir.join("commondir"),
            &format!("{}\n", common.display()),
        );
        write(
            &fixture.tree.join(".git"),
            &format!("gitdir: {}\n", gitdir.display()),
        );
        let tree = parse(&fixture).expect("the chain parses");
        assert_eq!(carved(&tree), vec![fixture.tree.join(".git"), common]);
    }

    #[test]
    fn a_commondir_in_the_root_git_dir_is_followed() {
        let fixture = fixture("dir-commondir");
        let git = fixture.tree.join(".git");
        let common = fixture.tree.join("shared.git");
        make_dir(&git);
        make_dir(&common);
        write(&git.join("commondir"), "../shared.git\n");
        let tree = parse(&fixture).expect("the root gitdir parses");
        assert_eq!(carved(&tree), vec![git.clone(), common]);
        write(&git.join("commondir"), "../missing\n");
        assert!(matches!(
            parse(&fixture),
            Err(JailPathError::VcsPointerUnreadable {
                kind: VcsKind::Git,
                reason: PointerFault::Unresolvable(_),
                ..
            })
        ));
    }

    #[test]
    fn a_shared_store_and_a_jj_repo_pointer_inside_the_tree_are_carved() {
        let fixture = fixture("hg-jj-pointers");
        let hg = fixture.tree.join(".hg");
        let jj = fixture.tree.join(".jj");
        let store = fixture.tree.join("store");
        let repo = fixture.tree.join("jj-repo");
        make_dir(&hg);
        make_dir(&jj);
        make_dir(&store);
        make_dir(&repo);
        write(&hg.join("sharedpath"), "../store");
        write(&jj.join("repo"), "../jj-repo");
        let tree = parse(&fixture).expect("the pointers parse");
        assert_eq!(carved(&tree), vec![hg, store, jj, repo]);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_git_entry_refuses() {
        let fixture = fixture("symlink");
        let real = fixture.root.join("real.git");
        make_dir(&real);
        std::os::unix::fs::symlink(&real, fixture.tree.join(".git")).expect("symlink");
        assert!(matches!(
            parse(&fixture),
            Err(JailPathError::VcsEntryUnexpectedKind { kind: VcsKind::Git, path })
                if path == fixture.tree.join(".git")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_pointer_inside_a_metadata_dir_refuses() {
        let fixture = fixture("symlink-inner");
        let hg = fixture.tree.join(".hg");
        make_dir(&hg);
        write(&fixture.root.join("target"), "/");
        std::os::unix::fs::symlink(fixture.root.join("target"), hg.join("sharedpath"))
            .expect("symlink");
        assert!(matches!(
            parse(&fixture),
            Err(JailPathError::VcsEntryUnexpectedKind { kind: VcsKind::Mercurial, path })
                if path == hg.join("sharedpath")
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_fifo_git_entry_refuses() {
        let fixture = fixture("fifo");
        let entry = fixture.tree.join(".git");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &entry,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .expect("mkfifo");
        assert!(matches!(
            parse(&fixture),
            Err(JailPathError::VcsEntryUnexpectedKind { kind: VcsKind::Git, path })
                if path == entry
        ));
    }

    #[test]
    fn a_mercurial_file_entry_refuses() {
        let fixture = fixture("hg-file");
        write(&fixture.tree.join(".hg"), "not a repo");
        assert!(matches!(
            parse(&fixture),
            Err(JailPathError::VcsEntryUnexpectedKind {
                kind: VcsKind::Mercurial,
                ..
            })
        ));
    }

    #[test]
    fn an_oversize_gitfile_refuses() {
        let fixture = fixture("oversize");
        make_dir(&fixture.tree.join("gd"));
        let cap = usize::try_from(POINTER_CAP).expect("cap fits usize");
        let at_cap = format!("gitdir: gd{}", " ".repeat(cap - "gitdir: gd".len()));
        write(&fixture.tree.join(".git"), &format!("{at_cap} "));
        assert!(matches!(
            parse(&fixture),
            Err(JailPathError::VcsPointerUnreadable {
                kind: VcsKind::Git,
                reason: PointerFault::OverCap,
                ..
            })
        ));
        write(&fixture.tree.join(".git"), &at_cap);
        assert!(
            matches!(
                parse(&fixture),
                Err(JailPathError::VcsPointerUnreadable {
                    reason: PointerFault::Unresolvable(_),
                    ..
                })
            ),
            "a file at the cap is read; its trailing blanks name no directory"
        );
    }

    #[test]
    fn a_malformed_gitfile_refuses() {
        let fixture = fixture("malformed");
        make_dir(&fixture.tree.join("gd"));
        for text in [
            "",
            "gitdir:gd",
            "gitdir: ",
            "gitdir: gd\nextra",
            "gitdir: gd\n\n",
            "gitdir: g\0d",
            "worktree: gd",
        ] {
            write(&fixture.tree.join(".git"), text);
            assert!(
                matches!(
                    parse(&fixture),
                    Err(JailPathError::VcsPointerUnreadable {
                        kind: VcsKind::Git,
                        reason: PointerFault::Malformed,
                        ..
                    })
                ),
                "{text:?}"
            );
        }
        write(&fixture.tree.join(".git"), "gitdir: gd\n");
        assert!(parse(&fixture).is_ok(), "the well-formed pointer parses");
        std::fs::write(fixture.tree.join(".git"), b"gitdir: \xff").expect("write");
        assert!(matches!(
            parse(&fixture),
            Err(JailPathError::VcsPointerUnreadable {
                reason: PointerFault::NotUtf8,
                ..
            })
        ));
    }

    #[test]
    fn an_unresolvable_gitdir_target_refuses() {
        let fixture = fixture("unresolvable");
        write(&fixture.tree.join(".git"), "gitdir: ../missing/.git\n");
        assert!(matches!(
            parse(&fixture),
            Err(JailPathError::VcsPointerUnreadable {
                kind: VcsKind::Git,
                reason: PointerFault::Unresolvable(_),
                ..
            })
        ));
        write(&fixture.root.join("plain"), "");
        write(&fixture.tree.join(".git"), "gitdir: ../plain\n");
        assert!(matches!(
            parse(&fixture),
            Err(JailPathError::VcsPointerUnreadable {
                reason: PointerFault::NotADirectory,
                ..
            })
        ));
    }

    #[test]
    fn a_gitdir_at_or_above_a_writable_grant_refuses() {
        let fixture = fixture("covers-grant");
        for named in [".", "..", "../tmp"] {
            write(&fixture.tree.join(".git"), &format!("gitdir: {named}\n"));
            assert!(
                matches!(
                    parse(&fixture),
                    Err(JailPathError::VcsPointerUnreadable {
                        reason: PointerFault::CoversWritableGrant,
                        ..
                    })
                ),
                "{named}"
            );
        }
    }

    #[test]
    fn a_metadata_dir_replaced_after_the_parse_refuses_on_recheck() {
        let fixture = fixture("recheck");
        let grants = [canonical(&fixture.tmp)];
        let grants: Vec<&CanonicalPath> = grants.iter().collect();
        let home = Home::unknown();
        let tree =
            WritableTree::parse(canonical(&fixture.tree), &grants, &home).expect("empty tree");
        assert!(tree.recheck(&grants, &home).is_ok());
        make_dir(&fixture.tree.join(".git"));
        assert!(
            matches!(
                tree.recheck(&grants, &home),
                Err(JailPathError::VcsEntryChanged { path }) if path == fixture.tree.join(".git")
            ),
            "metadata created after the parse is a change"
        );
    }
}
