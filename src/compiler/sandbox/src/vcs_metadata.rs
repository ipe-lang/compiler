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
//! Metadata is found at any depth: the parse walks the whole tree once through
//! held directory handles, never following a link, and carves every entry whose
//! name a [`VcsKind`] keeps its metadata under. The walk is bounded by
//! construction: an explicit stack no deeper than [`MAX_DEPTH`], at most
//! [`MAX_WALK_ENTRIES`] entries listed and [`MAX_HELD_NAME_BYTES`] of names
//! held, at most [`MAX_CARVE_ENTRIES`] carved paths, one pointer read of at most
//! [`POINTER_CAP`] bytes per pointer file, and a fixed chain of at most two hops
//! per entry (a gitfile names a gitdir, whose `commondir` names the shared
//! `.git`). A ceiling reached refuses the tree, since metadata past it could go
//! uncarved.

use std::fmt;
use std::io::Read as _;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use ipe_fs_open::{EntryCap, EntryName, FileKind, HeldDir, HintedKind, OpenRefusal};

use crate::vcs_config::{ConfigLimits, ConfigRoots, Grants, Home, scan};
use crate::{CanonicalPath, JailPathError, path_covers};

/// The most bytes a version-control pointer file may hold.
pub const POINTER_CAP: u64 = 4096;

/// `n` as a ceiling; a zero `n` is the smallest ceiling, one.
const fn ceiling(n: u32) -> NonZeroU32 {
    NonZeroU32::MIN.saturating_add(n.saturating_sub(1))
}

/// The most directory entries one walk of a writable tree lists.
pub const MAX_WALK_ENTRIES: NonZeroU32 = ceiling(200_000);
/// The deepest directory one walk enters below the tree's root.
pub const MAX_DEPTH: NonZeroU32 = ceiling(64);
/// The most paths, and the most configuration roots, one tree's carve holds.
pub const MAX_CARVE_ENTRIES: NonZeroU32 = ceiling(256);
/// The most ancestor directories a carve's mount plan pins in place.
pub const MAX_PIN_MOUNTS: NonZeroU32 = ceiling(1024);
/// The most bytes of entry names one walk holds while it is pending.
pub const MAX_HELD_NAME_BYTES: NonZeroU32 = ceiling(16 << 20);

// Every legal carve can be pinned: the pin pass is never the first ceiling hit.
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the pin ceiling drops below the carve ceiling [ledger #boundary]
const _: () = assert!(MAX_PIN_MOUNTS.get() >= MAX_CARVE_ENTRIES.get());

/// The ceilings one writable tree's walk, pins, and configuration scan share.
///
/// Production uses [`Self::DEFAULT`]; only tests size it otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkLimits {
    entries: NonZeroU32,
    depth: NonZeroU32,
    carve_entries: NonZeroU32,
    pins: NonZeroU32,
    held_name_bytes: NonZeroU32,
    config: ConfigLimits,
}

impl WalkLimits {
    /// The ceilings every jail uses.
    pub const DEFAULT: Self = Self {
        entries: MAX_WALK_ENTRIES,
        depth: MAX_DEPTH,
        carve_entries: MAX_CARVE_ENTRIES,
        pins: MAX_PIN_MOUNTS,
        held_name_bytes: MAX_HELD_NAME_BYTES,
        config: ConfigLimits::DEFAULT,
    };

    /// Test-only: the walk and pin ceilings sized as given, the rest default.
    #[cfg(test)]
    #[must_use]
    pub const fn sized(entries: u32, depth: u32, carve_entries: u32, pins: u32) -> Self {
        Self {
            entries: ceiling(entries),
            depth: ceiling(depth),
            carve_entries: ceiling(carve_entries),
            pins: ceiling(pins),
            ..Self::DEFAULT
        }
    }

    /// The most ancestor directories a carve's mount plan pins.
    #[must_use]
    pub const fn pins(&self) -> NonZeroU32 {
        self.pins
    }
}

/// Which walk ceiling a writable tree reached, with its limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkCeiling {
    /// More directory entries than the walk lists.
    Entries(NonZeroU32),
    /// A directory nested deeper than the walk enters.
    Depth(NonZeroU32),
    /// More carved paths or configuration roots than one carve holds.
    CarveEntries(NonZeroU32),
    /// More ancestor directories to pin than one mount plan holds.
    Pins(NonZeroU32),
    /// More bytes of pending entry names than the walk holds.
    HeldNameBytes(NonZeroU32),
}

impl fmt::Display for WalkCeiling {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entries(n) => write!(f, "holds more than {n} entries"),
            Self::Depth(n) => write!(f, "nests deeper than {n} directories"),
            Self::CarveEntries(n) => {
                write!(f, "holds more than {n} version-control directories")
            }
            Self::Pins(n) => write!(
                f,
                "needs more than {n} directories pinned to keep its version-control \
                 directories in place"
            ),
            Self::HeldNameBytes(n) => write!(f, "holds more than {n} bytes of entry names"),
        }
    }
}

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

    /// The kind whose metadata entry `name` spells, compared ASCII
    /// case-insensitively on every OS.
    ///
    /// A case-insensitive volume opens `.GIT` as `.git`; on a case-sensitive one
    /// carving it anyway is a harmless over-carve.
    #[must_use]
    pub fn of_entry_name(name: &EntryName) -> Option<Self> {
        let bytes = name.as_os_str().as_encoded_bytes();
        Self::ALL
            .into_iter()
            .find(|kind| bytes.eq_ignore_ascii_case(kind.entry_name().as_bytes()))
    }

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
    limits: WalkLimits,
}

impl WritableTree {
    /// `tree` with its carve: each [`VcsKind`] entry found at any depth below
    /// it, and each directory a pointer file names that lies inside `tree` or
    /// one of `other_grants` (the jail's other writable paths).
    ///
    /// The configuration each carved entry's tool reads is scanned against
    /// those grants, with `home` the invoker's home the tool expands `~`
    /// against.
    ///
    /// # Errors
    /// - [`JailPathError::VcsWalkCeiling`] when the tree holds more entries,
    ///   nests deeper, or holds more metadata than one walk proves.
    /// - [`JailPathError::VcsWalkUnreadable`] when a directory in the tree
    ///   cannot be opened or listed.
    /// - [`JailPathError::VcsWalkCrossDevice`] when a directory in the tree is
    ///   on another filesystem than its root.
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
        Self::parse_under(tree, other_grants, home, WalkLimits::DEFAULT)
    }

    /// [`Self::parse`] under `limits`.
    fn parse_under(
        tree: CanonicalPath,
        other_grants: &[&CanonicalPath],
        home: &Home,
        limits: WalkLimits,
    ) -> Result<Self, JailPathError> {
        let (carve, roots) = Carver::carve(&tree, other_grants, limits)?;
        scan_roots(&tree, other_grants, &carve, &roots, home, limits)?;
        Ok(Self {
            tree,
            carve,
            limits,
        })
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
        let (now, roots) = Carver::carve(&self.tree, other_grants, self.limits)?;
        if now == self.carve {
            return scan_roots(&self.tree, other_grants, &now, &roots, home, self.limits);
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

    /// The ceilings the tree was parsed under, which its mount plan obeys too.
    #[must_use]
    pub const fn limits(&self) -> &WalkLimits {
        &self.limits
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
            limits: WalkLimits::DEFAULT,
        }
    }

    /// Test-only: this tree under `limits` instead of the defaults.
    #[cfg(test)]
    #[must_use]
    pub const fn under_limits(mut self, limits: WalkLimits) -> Self {
        self.limits = limits;
        self
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
    limits: WalkLimits,
) -> Result<(), JailPathError> {
    let carves: Vec<&CanonicalPath> = carve.paths().collect();
    let grants = Grants::new(tree, other_grants).with_carves(&carves);
    roots.iter().try_for_each(|root| {
        scan(&root.config_roots(), &grants, home, limits.config).map_err(JailPathError::VcsConfig)
    })
}

/// One directory the walk holds open, and its listed entries not yet visited.
struct Frame {
    dir: HeldDir,
    path: PathBuf,
    pending: Vec<(EntryName, HintedKind)>,
}

/// What one walk has spent of its listing and held-name ceilings.
struct Budget {
    limits: WalkLimits,
    listed: u32,
    held_bytes: u32,
}

impl Budget {
    const fn new(limits: WalkLimits) -> Self {
        Self {
            limits,
            listed: 0,
            held_bytes: 0,
        }
    }

    /// The entries of `dir` at `path`, charged at listing and ordered so the
    /// walk pops them in ascending name order.
    fn list(
        &mut self,
        dir: &HeldDir,
        path: &Path,
    ) -> Result<Vec<(EntryName, HintedKind)>, JailPathError> {
        let limits = self.limits;
        let entries_ceiling = || walk_ceiling(WalkCeiling::Entries(limits.entries), path);
        let remaining = limits.entries.get().saturating_sub(self.listed);
        let cap = EntryCap::from_nonzero(NonZeroU32::new(remaining).unwrap_or(NonZeroU32::MIN));
        let mut entries = dir.entries_hinted(cap).map_err(|refusal| match refusal {
            OpenRefusal::TooManyEntries(_) => entries_ceiling(),
            other => walk_unreadable(path, other),
        })?;
        let count = u32::try_from(entries.len()).unwrap_or(u32::MAX);
        self.listed = self.listed.saturating_add(count);
        if self.listed > self.limits.entries.get() {
            return Err(entries_ceiling());
        }
        let bytes = entries
            .iter()
            .fold(0_u32, |sum, (name, _)| sum.saturating_add(name_bytes(name)));
        self.held_bytes = self.held_bytes.saturating_add(bytes);
        if self.held_bytes > self.limits.held_name_bytes.get() {
            return Err(walk_ceiling(
                WalkCeiling::HeldNameBytes(self.limits.held_name_bytes),
                path,
            ));
        }
        entries.sort_unstable_by(|(a, _), (b, _)| {
            b.as_os_str()
                .as_encoded_bytes()
                .cmp(a.as_os_str().as_encoded_bytes())
        });
        Ok(entries)
    }

    /// Release the held bytes of `name`, taken off the stack.
    fn release(&mut self, name: &EntryName) {
        self.held_bytes = self.held_bytes.saturating_sub(name_bytes(name));
    }
}

fn name_bytes(name: &EntryName) -> u32 {
    u32::try_from(name.as_os_str().len()).unwrap_or(u32::MAX)
}

/// One parse of a tree: its writable grants, the carve found so far, and the
/// configuration roots of each carved entry.
struct Carver<'g> {
    tree: &'g CanonicalPath,
    grants: Vec<&'g CanonicalPath>,
    limits: WalkLimits,
    carve: VcsCarve,
    roots: Vec<VcsRoot>,
}

impl<'g> Carver<'g> {
    fn carve(
        tree: &'g CanonicalPath,
        other_grants: &[&'g CanonicalPath],
        limits: WalkLimits,
    ) -> Result<(VcsCarve, Vec<VcsRoot>), JailPathError> {
        let mut carver = Self {
            tree,
            grants: std::iter::once(tree)
                .chain(other_grants.iter().copied())
                .collect(),
            limits,
            carve: VcsCarve::default(),
            roots: Vec::new(),
        };
        carver.walk()?;
        Ok((carver.carve, carver.roots))
    }

    /// Walk the tree depth-first through held handles, carving every metadata
    /// entry met and descending every other directory.
    ///
    /// The stack holds one frame per open directory, so recursion depth and
    /// open handles stay at [`WalkLimits`]' depth plus one. A matched entry is
    /// carved whole and never descended; a link is never followed; another
    /// grant's root is never entered.
    fn walk(&mut self) -> Result<(), JailPathError> {
        let tree = self.tree;
        let root_path = tree.as_path();
        let root =
            HeldDir::open_root(root_path).map_err(|refusal| walk_unreadable(root_path, refusal))?;
        let device = device_of(&root, root_path)?;
        let mut budget = Budget::new(self.limits);
        let pending = budget.list(&root, root_path)?;
        let mut stack = vec![Frame {
            dir: root,
            path: root_path.to_path_buf(),
            pending,
        }];
        loop {
            let depth = stack.len();
            let Some(top) = stack.last_mut() else {
                break;
            };
            let Some((name, hint)) = top.pending.pop() else {
                stack.pop();
                continue;
            };
            budget.release(&name);
            let path = top.path.join(name.as_os_str());
            if let Some(kind) = VcsKind::of_entry_name(&name) {
                self.entry_at(kind, &top.path, &path)?;
                self.within_carve_ceiling(&path)?;
                continue;
            }
            let is_dir = match hint {
                HintedKind::Dir => true,
                HintedKind::Unknown => matches!(
                    top.dir
                        .kind_of(&name)
                        .map_err(|refusal| walk_unreadable(&path, refusal))?,
                    Some(FileKind::Dir)
                ),
                HintedKind::Regular | HintedKind::Link | HintedKind::Other => false,
            };
            if !is_dir || self.grants.iter().skip(1).any(|g| g.as_path() == path) {
                continue;
            }
            if u32::try_from(depth)
                .ok()
                .is_none_or(|depth| depth > self.limits.depth.get())
            {
                return Err(walk_ceiling(WalkCeiling::Depth(self.limits.depth), &path));
            }
            let Some(child) = open_child(&top.dir, &name, &path)? else {
                continue;
            };
            if device_of(&child, &path)? != device {
                return Err(JailPathError::VcsWalkCrossDevice { path });
            }
            let pending = match budget.list(&child, &path) {
                Err(JailPathError::VcsWalkUnreadable {
                    refusal: OpenRefusal::Absent,
                    ..
                }) => continue,
                listed => listed?,
            };
            stack.push(Frame {
                dir: child,
                path,
                pending,
            });
        }
        Ok(())
    }

    /// Refuse a carve holding more paths, or more configuration roots, than
    /// the limits admit; `at` is the entry that reached the ceiling.
    fn within_carve_ceiling(&self, at: &Path) -> Result<(), JailPathError> {
        let limit = self.limits.carve_entries;
        let over = |len: usize| u32::try_from(len).ok().is_none_or(|len| len > limit.get());
        if over(self.carve.0.len()) || over(self.roots.len()) {
            return Err(walk_ceiling(WalkCeiling::CarveEntries(limit), at));
        }
        Ok(())
    }

    /// Carve `kind`'s entry `entry` in the directory `parent`, and follow the
    /// pointer files it holds; a gitfile's `gitdir:` resolves against `parent`.
    fn entry_at(
        &mut self,
        kind: VcsKind,
        parent: &Path,
        entry: &Path,
    ) -> Result<(), JailPathError> {
        let Some((shape, meta)) = classify(kind, entry)? else {
            return Ok(());
        };
        let unexpected = || JailPathError::VcsEntryUnexpectedKind {
            kind,
            path: entry.to_path_buf(),
        };
        let root = match (kind, shape) {
            (_, Shape::Other) | (VcsKind::Mercurial, Shape::File) => return Err(unexpected()),
            (VcsKind::Jujutsu | VcsKind::Darcs, Shape::File) => {
                self.add_entry(entry, &meta)?;
                None
            }
            (VcsKind::Darcs, Shape::Dir) => Some(VcsRoot::Darcs {
                dot_darcs: self.add_entry(entry, &meta)?,
            }),
            (VcsKind::Git, Shape::Dir) => {
                // Git reads `commondir` in every gitdir, the root `.git` dir
                // included, and takes config and hooks from the dir it names.
                let gitdir = self.add_entry(entry, &meta)?;
                let commondir = self.inner_pointer(kind, &entry.join("commondir"), false)?;
                Some(VcsRoot::Git { gitdir, commondir })
            }
            (VcsKind::Git, Shape::File) => {
                self.add_entry(entry, &meta)?;
                let text = read_pointer(kind, entry, &meta)?;
                let gitdir = text
                    .strip_prefix("gitdir: ")
                    .and_then(one_line)
                    .ok_or_else(|| pointer_fault(kind, entry, PointerFault::Malformed))?;
                let gitdir = self.target(kind, entry, parent, gitdir)?;
                let commondir =
                    self.inner_pointer(kind, &gitdir.as_path().join("commondir"), false)?;
                Some(VcsRoot::Git { gitdir, commondir })
            }
            (VcsKind::Mercurial, Shape::Dir) => {
                let dot_hg = self.add_entry(entry, &meta)?;
                let shared = self.inner_pointer(kind, &entry.join("sharedpath"), false)?;
                Some(VcsRoot::Mercurial { dot_hg, shared })
            }
            (VcsKind::Jujutsu, Shape::Dir) => {
                // Without a repository directory Jujutsu reads no configuration.
                let dot_jj = self.add_entry(entry, &meta)?;
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

    /// Carve the metadata entry `entry`, classified with `meta`, and return its
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

    /// Add `path` to the carve, keeping it containment-minimal: a path under a
    /// carved one is already covered, and a carved path under `path` is dropped.
    fn add(&mut self, path: CanonicalPath, identity: Identity) {
        if self
            .carve
            .0
            .iter()
            .any(|carved| path.as_path().starts_with(carved.path.as_path()))
        {
            return;
        }
        self.carve
            .0
            .retain(|carved| !carved.path.as_path().starts_with(path.as_path()));
        self.carve.0.push(CarvePath { path, identity });
    }
}

/// The subdirectory `name` of `dir`, at `path`; `None` when it vanished,
/// became a link, or became something other than a directory since it was
/// listed, so it holds nothing to walk.
fn open_child(
    dir: &HeldDir,
    name: &EntryName,
    path: &Path,
) -> Result<Option<HeldDir>, JailPathError> {
    match dir.child_dir(name) {
        Ok(child) => Ok(Some(child)),
        Err(OpenRefusal::Absent | OpenRefusal::Link | OpenRefusal::NotRegular(_)) => Ok(None),
        Err(
            refusal @ (OpenRefusal::Denied
            | OpenRefusal::InUse
            | OpenRefusal::TooLarge(_)
            | OpenRefusal::TooManyEntries(_)
            | OpenRefusal::BadName
            | OpenRefusal::NotUtf8
            | OpenRefusal::Io(_)),
        ) => Err(walk_unreadable(path, refusal)),
    }
}

/// The device the held directory at `path` lives on (unix).
#[cfg(unix)]
fn device_of(dir: &HeldDir, path: &Path) -> Result<Option<u64>, JailPathError> {
    use std::os::unix::fs::MetadataExt as _;
    dir.handle()
        .metadata()
        .map(|meta| Some(meta.dev()))
        .map_err(|e| walk_unreadable(path, OpenRefusal::Io(e.kind())))
}

/// No device is compared off unix: a Windows volume mounted in a folder is a
/// reparse point, which the listing reports as a link and the walk never enters.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // the unix twin is fallible
const fn device_of(_dir: &HeldDir, _path: &Path) -> Result<Option<u64>, JailPathError> {
    Ok(None)
}

fn walk_ceiling(ceiling: WalkCeiling, at: &Path) -> JailPathError {
    JailPathError::VcsWalkCeiling {
        ceiling,
        at: at.to_path_buf(),
    }
}

fn walk_unreadable(path: &Path, refusal: OpenRefusal) -> JailPathError {
    JailPathError::VcsWalkUnreadable {
        path: path.to_path_buf(),
        refusal,
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
        assert!(
            gitdir.starts_with(&common),
            "the common dir covers the gitdir"
        );
        assert_eq!(carved(&tree), vec![fixture.tree.join(".git"), common]);
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

    fn parse_under(fixture: &Fixture, limits: WalkLimits) -> Result<WritableTree, JailPathError> {
        WritableTree::parse_under(
            canonical(&fixture.tree),
            &[&canonical(&fixture.tmp)],
            &Home::unknown(),
            limits,
        )
    }

    #[test]
    fn the_build_jail_recheck_rescans_config() {
        let fixture = fixture("recheck-config");
        let git = fixture.tree.join(".git");
        make_dir(&git);
        write(
            &git.join("config"),
            "[core]\n\trepositoryformatversion = 0\n",
        );
        let grants = [canonical(&fixture.tmp)];
        let grants: Vec<&CanonicalPath> = grants.iter().collect();
        let home = Home::unknown();
        let tree =
            WritableTree::parse(canonical(&fixture.tree), &grants, &home).expect("clean config");
        assert!(tree.recheck(&grants, &home).is_ok());
        write(&git.join("config"), "[core]\n\thooksPath = .husky\n");
        let rechecked = tree.recheck(&grants, &home);
        assert!(
            matches!(
                &rechecked,
                Err(JailPathError::VcsConfig(crate::ConfigRefusal::NamesWritableCode {
                    kind: VcsKind::Git,
                    named: crate::Named::InGrant(path),
                    ..
                })) if *path == fixture.tree.join(".husky")
            ),
            "a config edited after the parse refuses on recheck: {rechecked:?}"
        );
    }

    #[test]
    fn walk_refuses_entry_ceiling() {
        let fixture = fixture("walk-entries");
        make_dir(&fixture.tree.join("a"));
        write(&fixture.tree.join("a").join("one"), "");
        write(&fixture.tree.join("two"), "");
        let limits = WalkLimits::sized(3, 64, 256, 1024);
        assert!(
            parse_under(&fixture, limits).is_ok(),
            "three entries at a ceiling of three are walked"
        );
        write(&fixture.tree.join("a").join("three"), "");
        let walked = parse_under(&fixture, limits);
        assert!(
            matches!(
                &walked,
                Err(JailPathError::VcsWalkCeiling {
                    ceiling: WalkCeiling::Entries(limit),
                    at,
                }) if limit.get() == 3 && *at == fixture.tree.join("a")
            ),
            "the fourth entry refuses: {walked:?}"
        );
    }

    #[test]
    fn walk_refuses_depth_ceiling() {
        let fixture = fixture("walk-depth");
        let deepest = fixture.tree.join("a").join("b");
        make_dir(&deepest);
        let limits = WalkLimits::sized(1000, 2, 256, 1024);
        assert!(
            parse_under(&fixture, limits).is_ok(),
            "a directory at the depth ceiling is walked"
        );
        make_dir(&deepest.join("c"));
        let walked = parse_under(&fixture, limits);
        assert!(
            matches!(
                &walked,
                Err(JailPathError::VcsWalkCeiling {
                    ceiling: WalkCeiling::Depth(limit),
                    at,
                }) if limit.get() == 2 && *at == deepest.join("c")
            ),
            "one directory past the depth ceiling refuses: {walked:?}"
        );
    }

    #[test]
    fn walk_refuses_carve_ceiling() {
        let fixture = fixture("walk-carves");
        make_dir(&fixture.tree.join("a").join(".git"));
        make_dir(&fixture.tree.join("b").join(".git"));
        let limits = WalkLimits::sized(1000, 64, 2, 1024);
        assert!(
            parse_under(&fixture, limits).is_ok(),
            "two carves at a ceiling of two are admitted"
        );
        make_dir(&fixture.tree.join("c").join(".git"));
        let walked = parse_under(&fixture, limits);
        assert!(
            matches!(
                &walked,
                Err(JailPathError::VcsWalkCeiling {
                    ceiling: WalkCeiling::CarveEntries(limit),
                    at,
                }) if limit.get() == 2 && *at == fixture.tree.join("c").join(".git")
            ),
            "the third carve refuses: {walked:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn walk_refuses_unreadable_dir() {
        use std::os::unix::fs::PermissionsExt as _;
        if rustix::process::geteuid().is_root() {
            return; // root opens a mode-000 directory, so nothing is refused
        }
        let fixture = fixture("walk-unreadable");
        let locked = fixture.tree.join("locked");
        make_dir(&locked);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .expect("lock the dir");
        let walked = parse(&fixture);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
            .expect("unlock the dir");
        assert!(
            matches!(
                &walked,
                Err(JailPathError::VcsWalkUnreadable {
                    path,
                    refusal: OpenRefusal::Denied,
                }) if *path == locked
            ),
            "an unreadable directory could hide metadata: {walked:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn walk_skips_vanished_and_linked_child() {
        let fixture = fixture("walk-skips");
        let outside = fixture.root.join("outside");
        make_dir(&outside.join(".git"));
        std::os::unix::fs::symlink(&outside, fixture.tree.join("link")).expect("dir link");
        write(&fixture.tree.join("file"), "");
        let tree = parse(&fixture).expect("a linked dir is never descended");
        assert!(tree.carve().is_empty(), "{tree:?}");
        let held = HeldDir::open_root(&fixture.tree).expect("hold the tree");
        for name in ["link", "file", "vanished"] {
            let entry = EntryName::new(std::ffi::OsStr::new(name)).expect("entry name");
            let opened = open_child(&held, &entry, &fixture.tree.join(name));
            assert!(matches!(opened, Ok(None)), "{name} is skipped: {opened:?}");
        }
    }

    #[test]
    fn walk_carves_nested_gitfile_relative_to_parent() {
        let fixture = fixture("walk-gitfile");
        let modules = fixture.tree.join(".git").join("modules").join("sub");
        make_dir(&modules);
        let sub = fixture.tree.join("sub");
        make_dir(&sub);
        write(&sub.join(".git"), "gitdir: ../.git/modules/sub\n");
        let tree = parse(&fixture).expect("the nested gitfile resolves against its parent");
        assert_eq!(
            carved(&tree),
            vec![fixture.tree.join(".git"), sub.join(".git")],
            "the module dir lies under the carved root `.git`"
        );
    }

    #[test]
    fn walk_name_match_case_insensitive() {
        let name = |text: &str| EntryName::new(std::ffi::OsStr::new(text)).expect("entry name");
        for (text, kind) in [
            (".GIT", VcsKind::Git),
            (".Hg", VcsKind::Mercurial),
            (".jJ", VcsKind::Jujutsu),
            ("_DARCS", VcsKind::Darcs),
        ] {
            assert_eq!(VcsKind::of_entry_name(&name(text)), Some(kind), "{text}");
        }
        for text in ["git", ".gitx", ".git_", "darcs"] {
            assert_eq!(VcsKind::of_entry_name(&name(text)), None, "{text}");
        }
        let fixture = fixture("walk-case");
        let upper = fixture.tree.join("sub").join(".GIT");
        make_dir(&upper);
        let tree = parse(&fixture).expect("an upper-case gitdir parses");
        assert_eq!(carved(&tree), vec![upper]);
    }

    #[test]
    fn nested_carve_on_windows_and_freebsd_refuses() {
        let fixture = fixture("walk-uncarvable");
        let hg = fixture.tree.join("sub").join(".hg");
        make_dir(&hg);
        let tree = parse(&fixture).expect("nested metadata parses");
        for (arm, planned) in [
            (
                JailArm::Windows,
                crate::run_jail::windows::windows_working_tree_plan(&tree),
            ),
            (
                JailArm::Freebsd,
                crate::build_jail::freebsd_working_tree_plan(&tree),
            ),
        ] {
            assert!(
                matches!(
                    &planned,
                    Err(JailPathError::VcsMetadataUncarvable { arm: refused, path })
                        if *refused == arm && *path == hg
                ),
                "{arm} refuses nested-only metadata: {planned:?}"
            );
        }
    }

    #[test]
    fn a_nested_gitfile_config_is_scanned() {
        let fixture = fixture("walk-nested-config");
        let gitdir = fixture.root.join("outside").join("gd");
        make_dir(&gitdir);
        let named = fixture.tree.join("x");
        write(
            &gitdir.join("config"),
            &format!("[core]\n\tfsmonitor = {}\n", named.display()),
        );
        let sub = fixture.tree.join("sub");
        make_dir(&sub);
        write(
            &sub.join(".git"),
            &format!("gitdir: {}\n", gitdir.display()),
        );
        let walked = parse(&fixture);
        assert!(
            matches!(
                &walked,
                Err(JailPathError::VcsConfig(crate::ConfigRefusal::NamesWritableCode {
                    kind: VcsKind::Git,
                    named: crate::Named::InGrant(path),
                    ..
                })) if *path == named
            ),
            "a nested repository's configuration is judged: {walked:?}"
        );
    }

    #[test]
    fn a_nested_gitfile_config_naming_dot_dot_is_unprovable() {
        let fixture = fixture("walk-nested-config-dotdot");
        let gitdir = fixture.root.join("outside").join("gd");
        make_dir(&gitdir);
        write(&gitdir.join("config"), "[core]\n\tfsmonitor = ../tree/x\n");
        let sub = fixture.tree.join("sub");
        make_dir(&sub);
        write(
            &sub.join(".git"),
            &format!("gitdir: {}\n", gitdir.display()),
        );
        let walked = parse(&fixture);
        assert!(
            matches!(
                &walked,
                Err(JailPathError::VcsConfig(
                    crate::ConfigRefusal::NamesWritableCode {
                        kind: VcsKind::Git,
                        named: crate::Named::Unprovable(crate::Unprovable::DotDot),
                        ..
                    }
                ))
            ),
            "a parent step in a nested configuration value is refused: {walked:?}"
        );
    }

    #[test]
    fn walk_ceiling_display_names_the_remedy_escaped() {
        let refusal = JailPathError::VcsWalkCeiling {
            ceiling: WalkCeiling::Entries(MAX_WALK_ENTRIES),
            at: PathBuf::from("/tree/a\nb\u{1b}[2J"),
        };
        let shown = refusal.to_string();
        assert!(shown.contains("/tree/a\\u{a}b\\u{1b}[2J"), "{shown}");
        assert!(
            !shown.contains('\n') && !shown.contains('\u{1b}'),
            "{shown}"
        );
        assert!(shown.contains("run `ipe clean`"), "{shown}");
    }
}
