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
//! name a [`VcsKind`] keeps its metadata under. Each entry, and each pointer
//! file inside one, is opened once through its held parent, and every fact the
//! carve records about it is read from that handle; the path recorded is then
//! proven to name the held object. The walk is bounded by
//! construction: an explicit stack no deeper than [`MAX_DEPTH`], at most
//! [`MAX_WALK_ENTRIES`] entries listed and [`MAX_HELD_NAME_BYTES`] of names
//! held, at most [`MAX_CARVE_ENTRIES`] carved paths, one pointer read of at most
//! [`POINTER_CAP`] bytes per pointer file, and a fixed chain of at most two hops
//! per entry (a gitfile names a gitdir, whose `commondir` names the shared
//! `.git`). A ceiling reached refuses the tree, since metadata past it could go
//! uncarved.

use std::ffi::OsStr;
use std::fmt;
use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};

use ipe_fs_open::{
    ByteCap, EntryCap, EntryName, FileId, FileKind, HeldDir, HintedKind, OpenRefusal, RegularFile,
};

use crate::vcs_config::{ConfigLimits, ConfigRoots, Grants, Home, scan};
use crate::{CanonicalPath, JailPathError, path_covers};

/// The most bytes a version-control pointer file may hold.
pub const POINTER_CAP: u64 = 4096;

/// [`POINTER_CAP`] as the ceiling a pointer file is read under.
const POINTER_BYTE_CAP: ByteCap =
    ByteCap::from_nonzero(NonZeroU64::MIN.saturating_add(POINTER_CAP.saturating_sub(1)));

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

// One pin per legal carve fits; deeper carves can still exceed it, and refuse.
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

    /// Test-only: these ceilings with at most `bytes` of entry names held.
    #[cfg(test)]
    #[must_use]
    pub const fn with_held_name_bytes(mut self, bytes: u32) -> Self {
        self.held_name_bytes = ceiling(bytes);
        self
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

/// Declares [`VcsKind`], its [`VcsKind::ALL`], its entry names and its tool
/// names from one row list, so no kind lacks a name or a slot.
macro_rules! closed_vcs_kinds {
    ($($doc:literal, $variant:ident, $entry:literal, $tool:literal;)+) => {
        /// One version-control system whose in-tree metadata the host executes from.
        ///
        /// The set is closed: [`VcsKind::ALL`] lists each kind once, in
        /// declaration order.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum VcsKind {
            $(
                #[doc = $doc]
                $variant,
            )+
        }

        impl VcsKind {
            /// Every kind, the one list every carve, rule and test derives from.
            pub const ALL: [Self; Self::COUNT] = [$(Self::$variant),+];

            const COUNT: usize = [$(Self::$variant),+].len();

            /// The entry name the kind keeps its metadata under at a tree's root.
            #[must_use]
            pub const fn entry_name(self) -> &'static str {
                match self {
                    $(Self::$variant => $entry,)+
                }
            }

            /// The tool's name.
            const fn tool(self) -> &'static str {
                match self {
                    $(Self::$variant => $tool,)+
                }
            }
        }
    };
}

closed_vcs_kinds! {
    "Git: `.git/hooks/*`, and the `core.fsmonitor`, `core.hooksPath`, \
     `core.pager`, `core.sshCommand`, filter and diff drivers `.git/config` names.",
    Git, ".git", "Git";
    "Mercurial: the hooks and extensions `.hg/hgrc` names.", Mercurial, ".hg", "Mercurial";
    "Jujutsu: the commands and hooks `.jj/repo/config.toml` names.", Jujutsu, ".jj", "Jujutsu";
    "Darcs: the posthooks `_darcs/prefs/defaults` names.", Darcs, "_darcs", "Darcs";
}

impl VcsKind {
    /// The kind whose metadata entry a case-folding volume may open `name` as
    /// ([`ipe_fs_open::may_open_as`]), on every OS.
    ///
    /// A case-insensitive volume opens `.GIT` or `_darcſ` as the metadata entry;
    /// on a case-sensitive one carving it anyway is a harmless over-carve.
    #[must_use]
    pub fn of_entry_name(name: &EntryName) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| ipe_fs_open::may_open_as(name.as_os_str(), kind.entry_name()))
    }
}

impl fmt::Display for VcsKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.tool(), self.entry_name())
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

/// What a carved entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Dir,
    File,
}

impl Shape {
    /// The shape an entry of `kind` has; `None` for a kind no carved entry is.
    const fn of(kind: FileKind) -> Option<Self> {
        match kind {
            FileKind::Dir => Some(Self::Dir),
            FileKind::Regular => Some(Self::File),
            FileKind::Symlink
            | FileKind::Fifo
            | FileKind::Socket
            | FileKind::Device
            | FileKind::Other => None,
        }
    }
}

/// The identity of a carved entry, read from the handle the parse held it by.
///
/// [`WritableTree::recheck`] proves it again before the jail spawns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Identity {
    shape: Shape,
    id: FileId,
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
    /// - [`JailPathError::VcsWalkOpaqueReparse`] when an entry in the tree is
    ///   a reparse point a filter driver answers for.
    /// - [`JailPathError::VcsEntryUnexpectedKind`] when an entry, or a pointer
    ///   file inside one, is a link, reparse point, fifo, socket, or device, or
    ///   a form the tool never writes.
    /// - [`JailPathError::VcsPointerUnreadable`] when a pointer file cannot be
    ///   read, exceeds [`POINTER_CAP`], is malformed, or names a path that does
    ///   not resolve, is no directory, or covers a writable grant.
    /// - [`JailPathError::VcsEntryChanged`] when a carved path no longer names
    ///   the object the parse read through its held parent.
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
        Self::parse_probed(tree, other_grants, home, limits, device_of)
    }

    /// [`Self::parse_under`] with `device` naming the filesystem each held
    /// directory of the walk lies on.
    fn parse_probed(
        tree: CanonicalPath,
        other_grants: &[&CanonicalPath],
        home: &Home,
        limits: WalkLimits,
        device: DeviceOf,
    ) -> Result<Self, JailPathError> {
        let (carve, roots) = Carver::carve(&tree, other_grants, limits, device)?;
        scan_roots(&tree, other_grants, &carve, &roots, home, limits)?;
        Ok(Self {
            tree,
            carve,
            limits,
        })
    }

    /// Prove again that every carved path names the object the parse read.
    ///
    /// Run just before the jail spawns, so a carved entry swapped since the
    /// parse refuses the jail instead of leaving the swapped-in object
    /// unprotected.
    ///
    /// # Errors
    /// [`JailPathError::Moved`] when a carved path now resolves elsewhere;
    /// [`JailPathError::VcsEntryChanged`] when the object it names is no
    /// longer the one carved.
    pub fn recheck(&self) -> Result<(), JailPathError> {
        self.carve.0.iter().try_for_each(|carved| {
            carved.path.recheck()?;
            prove_named(&carved.path, carved.identity)
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

/// What the walk does with one listed entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Carve the metadata entry of this kind; its open refuses a link or a
    /// reparse point of any tag.
    Carve(VcsKind),
    /// Enter the directory.
    Descend,
    /// Ask the held directory what the entry is, and enter it if a directory.
    Settle,
    /// Pass over an entry that holds no directory to walk.
    Skip,
    /// Refuse the tree: a filter driver answers for the entry, so what it
    /// holds cannot be seen.
    Refuse,
}

/// The step for the listed entry `name`, hinted `hint`.
///
/// A metadata name is carved whatever its hint, so no hint can hide it. A
/// link is never followed. A transparent reparse point refuses, since skipping
/// it would leave whatever metadata it holds uncarved.
fn step_of(name: &EntryName, hint: HintedKind) -> Step {
    if let Some(kind) = VcsKind::of_entry_name(name) {
        return Step::Carve(kind);
    }
    match hint {
        HintedKind::Dir => Step::Descend,
        HintedKind::Unknown => Step::Settle,
        HintedKind::Regular | HintedKind::Link | HintedKind::Other => Step::Skip,
        HintedKind::Transparent => Step::Refuse,
    }
}

/// One parse of a tree: its writable grants, the carve found so far, and the
/// configuration roots of each carved entry.
struct Carver<'g> {
    tree: &'g CanonicalPath,
    grants: Vec<&'g CanonicalPath>,
    limits: WalkLimits,
    device: DeviceOf,
    carve: VcsCarve,
    roots: Vec<VcsRoot>,
}

impl<'g> Carver<'g> {
    fn carve(
        tree: &'g CanonicalPath,
        other_grants: &[&'g CanonicalPath],
        limits: WalkLimits,
        device: DeviceOf,
    ) -> Result<(VcsCarve, Vec<VcsRoot>), JailPathError> {
        let mut carver = Self {
            tree,
            grants: std::iter::once(tree)
                .chain(other_grants.iter().copied())
                .collect(),
            limits,
            device,
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
        let device = (self.device)(&root, root_path)?;
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
            let is_dir = match step_of(&name, hint) {
                Step::Carve(kind) => {
                    self.entry_at(kind, &top.dir, &top.path, &name)?;
                    self.within_carve_ceiling(&path)?;
                    continue;
                }
                Step::Refuse => return Err(JailPathError::VcsWalkOpaqueReparse { path }),
                Step::Descend => true,
                Step::Skip => false,
                Step::Settle => matches!(
                    top.dir
                        .kind_of(&name)
                        .map_err(|refusal| walk_unreadable(&path, refusal))?,
                    Some(FileKind::Dir)
                ),
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
            if (self.device)(&child, &path)? != device {
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

    /// Carve `kind`'s entry `name` of the held directory `parent` at
    /// `parent_path`, and follow the pointer files it holds.
    ///
    /// The entry is opened once, through `parent`, and every fact about it is
    /// read from that handle; its path is then proven to name the held object.
    /// A gitfile's `gitdir:` resolves against `parent_path`.
    fn entry_at(
        &mut self,
        kind: VcsKind,
        parent: &HeldDir,
        parent_path: &Path,
        name: &EntryName,
    ) -> Result<(), JailPathError> {
        let entry = parent_path.join(name.as_os_str());
        let Some(held) = open_entry(kind, parent, name, &entry)? else {
            return Ok(());
        };
        let identity = held.identity().map_err(|refusal| {
            pointer_fault(kind, &entry, PointerFault::Unreadable(refusal.kind()))
        })?;
        let mut targets = Vec::new();
        let root = match (kind, held) {
            (VcsKind::Mercurial, Held::File(_)) => {
                return Err(JailPathError::VcsEntryUnexpectedKind { kind, path: entry });
            }
            (VcsKind::Jujutsu | VcsKind::Darcs, Held::File(_)) => {
                self.carve_entry(&entry, identity)?;
                None
            }
            (VcsKind::Darcs, Held::Dir(_)) => Some(VcsRoot::Darcs {
                dot_darcs: self.carve_entry(&entry, identity)?,
            }),
            (VcsKind::Git, Held::Dir(dir)) => {
                // Git reads `commondir` in every gitdir, the root `.git` dir
                // included, and takes config and hooks from the dir it names.
                let commondir =
                    self.inner_pointer(kind, &dir, &entry, "commondir", false, &mut targets)?;
                let gitdir = self.carve_entry(&entry, identity)?;
                Some(VcsRoot::Git { gitdir, commondir })
            }
            (VcsKind::Git, Held::File(file)) => {
                let text = read_pointer(kind, &entry, file)?;
                let named = text
                    .strip_prefix("gitdir: ")
                    .and_then(one_line)
                    .ok_or_else(|| pointer_fault(kind, &entry, PointerFault::Malformed))?;
                let (gitdir, held_gitdir) =
                    self.target(kind, &entry, parent_path, named, &mut targets)?;
                let commondir = self.inner_pointer(
                    kind,
                    &held_gitdir,
                    gitdir.as_path(),
                    "commondir",
                    false,
                    &mut targets,
                )?;
                self.carve_entry(&entry, identity)?;
                Some(VcsRoot::Git { gitdir, commondir })
            }
            (VcsKind::Mercurial, Held::Dir(dir)) => {
                let shared =
                    self.inner_pointer(kind, &dir, &entry, "sharedpath", false, &mut targets)?;
                let dot_hg = self.carve_entry(&entry, identity)?;
                Some(VcsRoot::Mercurial { dot_hg, shared })
            }
            (VcsKind::Jujutsu, Held::Dir(dir)) => {
                // Without a repository directory Jujutsu reads no configuration.
                let repo = self.inner_pointer(kind, &dir, &entry, "repo", true, &mut targets)?;
                let dot_jj = self.carve_entry(&entry, identity)?;
                repo.map(|repo| VcsRoot::Jujutsu { dot_jj, repo })
            }
        };
        for target in targets {
            self.add(target);
        }
        self.roots.extend(root);
        Ok(())
    }

    /// Follow the optional pointer file `name` of the held metadata directory
    /// `dir` at `dir_path`, opened through `dir`; a relative path it names
    /// resolves against `dir_path`.
    ///
    /// The directory reached: the one the pointer names, the directory `name`
    /// itself when `dir_ok`, or `None` when nothing is there. An in-grant
    /// directory the pointer names is pushed onto `targets`.
    fn inner_pointer(
        &self,
        kind: VcsKind,
        dir: &HeldDir,
        dir_path: &Path,
        name: &'static str,
        dir_ok: bool,
        targets: &mut Vec<CarvePath>,
    ) -> Result<Option<CanonicalPath>, JailPathError> {
        let pointer = dir_path.join(name);
        let entry = EntryName::new(OsStr::new(name)).ok_or_else(|| {
            pointer_fault(
                kind,
                &pointer,
                PointerFault::Unreadable(std::io::ErrorKind::InvalidInput),
            )
        })?;
        match open_entry(kind, dir, &entry, &pointer)? {
            None => Ok(None),
            Some(Held::Dir(held)) if dir_ok => {
                let id = held.id().map_err(|refusal| {
                    pointer_fault(kind, &pointer, PointerFault::Unreadable(refusal.kind()))
                })?;
                let identity = Identity {
                    shape: Shape::Dir,
                    id,
                };
                proven(&pointer, identity).map(Some)
            }
            Some(Held::Dir(_)) => Err(JailPathError::VcsEntryUnexpectedKind {
                kind,
                path: pointer,
            }),
            Some(Held::File(file)) => {
                let text = read_pointer(kind, &pointer, file)?;
                let named = one_line(&text)
                    .ok_or_else(|| pointer_fault(kind, &pointer, PointerFault::Malformed))?;
                self.target(kind, &pointer, dir_path, named, targets)
                    .map(|(target, _)| Some(target))
            }
        }
    }

    /// The directory `named` (relative to `base`) that `pointer` names, with
    /// the handle it is held by.
    ///
    /// A pointer names an absolute target outside the walk, so the target is
    /// opened from its canonical path, and its identity read from that
    /// handle. When it lies inside a writable grant, it is proven to be the
    /// directory its canonical path names and pushed onto `targets`.
    fn target(
        &self,
        kind: VcsKind,
        pointer: &Path,
        base: &Path,
        named: &str,
        targets: &mut Vec<CarvePath>,
    ) -> Result<(CanonicalPath, HeldDir), JailPathError> {
        let fault = |reason| pointer_fault(kind, pointer, reason);
        let target = CanonicalPath::resolve(&base.join(named)).map_err(|e| match e {
            JailPathError::Unresolved { kind: io, .. } => fault(PointerFault::Unresolvable(io)),
            other => other,
        })?;
        let held = HeldDir::open_root(target.as_path()).map_err(|refusal| match refusal {
            OpenRefusal::NotRegular(_) => fault(PointerFault::NotADirectory),
            other => fault(PointerFault::Unresolvable(other.kind())),
        })?;
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
            let id = held
                .id()
                .map_err(|refusal| fault(PointerFault::Unresolvable(refusal.kind())))?;
            let identity = Identity {
                shape: Shape::Dir,
                id,
            };
            prove_named(&target, identity)?;
            targets.push(CarvePath {
                path: target.clone(),
                identity,
            });
        }
        Ok((target, held))
    }

    /// Carve the metadata entry at `entry`, held with `identity`, once its
    /// path is proven to name the held object, and return its canonical path.
    fn carve_entry(
        &mut self,
        entry: &Path,
        identity: Identity,
    ) -> Result<CanonicalPath, JailPathError> {
        let path = proven(entry, identity)?;
        self.add(CarvePath {
            path: path.clone(),
            identity,
        });
        Ok(path)
    }

    /// Add `carved` to the carve, keeping it containment-minimal: a path under
    /// a carved one is already covered, and a carved path under it is dropped.
    fn add(&mut self, carved: CarvePath) {
        let path = carved.path.as_path();
        if self
            .carve
            .0
            .iter()
            .any(|kept| path.starts_with(kept.path.as_path()))
        {
            return;
        }
        self.carve
            .0
            .retain(|kept| !kept.path.as_path().starts_with(path));
        self.carve.0.push(carved);
    }
}

/// A metadata entry or pointer file, held by the one handle every fact about
/// it is read from.
enum Held {
    Dir(HeldDir),
    File(RegularFile),
}

impl Held {
    /// The shape and identity of the held object, read from its handle.
    fn identity(&self) -> Result<Identity, OpenRefusal> {
        match self {
            Self::Dir(dir) => dir.id().map(|id| Identity {
                shape: Shape::Dir,
                id,
            }),
            Self::File(file) => file.id().map(|id| Identity {
                shape: Shape::File,
                id,
            }),
        }
    }
}

/// The entry `name` of `dir`, at `path`, opened once without following a
/// link; `None` when absent.
///
/// A directory is held as a directory and a regular file as a file. A link, a
/// reparse point of any tag, a fifo, a socket, or a device refuses.
fn open_entry(
    kind: VcsKind,
    dir: &HeldDir,
    name: &EntryName,
    path: &Path,
) -> Result<Option<Held>, JailPathError> {
    let refused = |refusal: OpenRefusal| match refusal {
        OpenRefusal::Absent => Ok(None),
        OpenRefusal::Link | OpenRefusal::NotRegular(_) => {
            Err(JailPathError::VcsEntryUnexpectedKind {
                kind,
                path: path.to_path_buf(),
            })
        }
        other @ (OpenRefusal::Denied
        | OpenRefusal::InUse
        | OpenRefusal::TooLarge(_)
        | OpenRefusal::TooManyEntries(_)
        | OpenRefusal::BadName
        | OpenRefusal::NotUtf8
        | OpenRefusal::Io(_)) => Err(pointer_fault(
            kind,
            path,
            PointerFault::Unreadable(other.kind()),
        )),
    };
    match dir.child_dir(name) {
        Ok(held) => Ok(Some(Held::Dir(held))),
        Err(OpenRefusal::NotRegular(FileKind::Regular)) => match dir.open_regular(name) {
            Ok(file) => Ok(Some(Held::File(file))),
            Err(refusal) => refused(refusal),
        },
        Err(refusal) => refused(refusal),
    }
}

/// `path` resolved, and proven to name the object `identity` was read from.
fn proven(path: &Path, identity: Identity) -> Result<CanonicalPath, JailPathError> {
    let changed = || JailPathError::VcsEntryChanged {
        path: path.to_path_buf(),
    };
    let canonical = CanonicalPath::resolve(path).map_err(|_| changed())?;
    prove_named(&canonical, identity).map_err(|_| changed())?;
    Ok(canonical)
}

/// Prove the canonical `path` names the object `identity` was read from.
///
/// The parent of `path` is reopened and the entry it holds under `path`'s
/// name must be that object, read without following a link: the path the
/// jail mounts is the object the parse read, not one a renamed ancestor put
/// in its place.
fn prove_named(path: &CanonicalPath, identity: Identity) -> Result<(), JailPathError> {
    let changed = || JailPathError::VcsEntryChanged {
        path: path.as_path().to_path_buf(),
    };
    let (Some(parent), Some(name)) = (path.as_path().parent(), path.as_path().file_name()) else {
        return Err(changed());
    };
    let name = EntryName::new(name).ok_or_else(changed)?;
    let parent = HeldDir::open_root(parent).map_err(|_| changed())?;
    let shape = parent.kind_of(&name).map_err(|_| changed())?;
    let id = parent.entry_id(&name).map_err(|_| changed())?;
    if shape.and_then(Shape::of) == Some(identity.shape) && id == Some(identity.id) {
        Ok(())
    } else {
        Err(changed())
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

/// The filesystem a held directory lies on, compared across one walk.
type DeviceOf = fn(&HeldDir, &Path) -> Result<u64, JailPathError>;

/// The volume the held directory at `path` lives on, read from its handle on
/// every OS.
fn device_of(dir: &HeldDir, path: &Path) -> Result<u64, JailPathError> {
    dir.id()
        .map(|id| id.volume())
        .map_err(|refusal| walk_unreadable(path, refusal))
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

/// The text of the held pointer file `file` at `path`, read under
/// [`POINTER_CAP`].
fn read_pointer(kind: VcsKind, path: &Path, file: RegularFile) -> Result<String, JailPathError> {
    file.read_utf8(POINTER_BYTE_CAP).map_err(|refusal| {
        let reason = match refusal {
            OpenRefusal::TooLarge(_) => PointerFault::OverCap,
            OpenRefusal::NotUtf8 => PointerFault::NotUtf8,
            other @ (OpenRefusal::Absent
            | OpenRefusal::Link
            | OpenRefusal::NotRegular(_)
            | OpenRefusal::Denied
            | OpenRefusal::InUse
            | OpenRefusal::TooManyEntries(_)
            | OpenRefusal::BadName
            | OpenRefusal::Io(_)) => PointerFault::Unreadable(other.kind()),
        };
        pointer_fault(kind, path, reason)
    })
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

    impl WritableTree {
        /// Test-only: `tree` taken with `carve` as given, for pure plan tests
        /// over paths that need not exist.
        #[must_use]
        pub fn assumed(tree: CanonicalPath, carve: Vec<CanonicalPath>) -> Self {
            let id = HeldDir::open_root(Path::new(""))
                .and_then(|dir| dir.id())
                .expect("the working directory has an identity");
            let identity = Identity {
                shape: Shape::Dir,
                id,
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
        #[must_use]
        pub const fn under_limits(mut self, limits: WalkLimits) -> Self {
            self.limits = limits;
            self
        }
    }

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

    fn parse_under(fixture: &Fixture, limits: WalkLimits) -> Result<WritableTree, JailPathError> {
        WritableTree::parse_under(
            canonical(&fixture.tree),
            &[&canonical(&fixture.tmp)],
            &Home::unknown(),
            limits,
        )
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

    #[test]
    fn walk_refuses_held_name_bytes_ceiling() {
        let fixture = fixture("walk-held-bytes");
        write(&fixture.tree.join("aaaa"), "");
        write(&fixture.tree.join("bbbb"), "");
        let limits = WalkLimits::DEFAULT.with_held_name_bytes(8);
        assert!(
            parse_under(&fixture, limits).is_ok(),
            "eight bytes of names at a ceiling of eight are held"
        );
        write(&fixture.tree.join("cccc"), "");
        let walked = parse_under(&fixture, limits);
        assert!(
            matches!(
                &walked,
                Err(JailPathError::VcsWalkCeiling {
                    ceiling: WalkCeiling::HeldNameBytes(limit),
                    at,
                }) if limit.get() == 8 && *at == fixture.tree
            ),
            "twelve bytes of names refuse: {walked:?}"
        );
    }

    #[test]
    fn walk_refuses_an_absent_root() {
        let fixture = fixture("walk-absent");
        let tree = canonical(&fixture.tree);
        std::fs::remove_dir(&fixture.tree).expect("remove the tree");
        let walked = WritableTree::parse(tree, &[&canonical(&fixture.tmp)], &Home::unknown());
        assert!(
            matches!(
                &walked,
                Err(JailPathError::VcsWalkUnreadable {
                    path,
                    refusal: OpenRefusal::Absent,
                }) if *path == fixture.tree
            ),
            "a tree that vanished proves no carve: {walked:?}"
        );
    }

    /// A stand-in filesystem probe: a directory named `other-fs` lies on a
    /// device of its own.
    fn other_fs_device(dir: &HeldDir, path: &Path) -> Result<u64, JailPathError> {
        let device = device_of(dir, path)?;
        let other = path.file_name() == Some(std::ffi::OsStr::new("other-fs"));
        Ok(if other {
            device.wrapping_add(1)
        } else {
            device
        })
    }

    #[test]
    fn walk_refuses_a_cross_device_dir() {
        let fixture = fixture("walk-cross-device");
        let other = fixture.tree.join("sub").join("other-fs");
        make_dir(&other.join(".git"));
        let probed = |device: DeviceOf| {
            WritableTree::parse_probed(
                canonical(&fixture.tree),
                &[&canonical(&fixture.tmp)],
                &Home::unknown(),
                WalkLimits::DEFAULT,
                device,
            )
        };
        let same = probed(device_of).expect("one filesystem parses");
        assert_eq!(carved(&same), vec![other.join(".git")]);
        let walked = probed(other_fs_device);
        assert!(
            matches!(
                &walked,
                Err(JailPathError::VcsWalkCrossDevice { path }) if *path == other
            ),
            "a directory on another filesystem could hide metadata: {walked:?}"
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

    /// Every metadata name is carved under every hint, so no listing hint can
    /// hide it; a transparent reparse point refuses; a link is never entered.
    #[test]
    fn step_of_carves_every_metadata_name_and_refuses_a_transparent_entry() {
        let hints = [
            HintedKind::Dir,
            HintedKind::Regular,
            HintedKind::Link,
            HintedKind::Transparent,
            HintedKind::Other,
            HintedKind::Unknown,
        ];
        for kind in VcsKind::ALL {
            let name = EntryName::new(OsStr::new(kind.entry_name())).expect("entry name");
            assert_eq!(VcsKind::of_entry_name(&name), Some(kind));
            for hint in hints {
                assert_eq!(
                    step_of(&name, hint),
                    Step::Carve(kind),
                    "{kind} hinted {hint:?}"
                );
            }
        }
        let plain = EntryName::new(OsStr::new("src")).expect("entry name");
        for (hint, step) in [
            (HintedKind::Dir, Step::Descend),
            (HintedKind::Unknown, Step::Settle),
            (HintedKind::Regular, Step::Skip),
            (HintedKind::Link, Step::Skip),
            (HintedKind::Other, Step::Skip),
            (HintedKind::Transparent, Step::Refuse),
        ] {
            assert_eq!(step_of(&plain, hint), step, "src hinted {hint:?}");
        }
    }

    /// A stand-in filesystem probe that, as the walk enters `a`, moves it to
    /// `a-moved` and links `a` to the directory `decoy` beside the tree.
    #[cfg(unix)]
    fn swap_ancestor(dir: &HeldDir, path: &Path) -> Result<u64, JailPathError> {
        if path.file_name() == Some(OsStr::new("a")) {
            let tree = path.parent().expect("`a` lies in the tree");
            let decoy = tree
                .parent()
                .expect("the tree lies in the root")
                .join("decoy");
            std::fs::rename(path, tree.join("a-moved")).expect("move the ancestor");
            std::os::unix::fs::symlink(decoy, path).expect("link the ancestor to the decoy");
        }
        device_of(dir, path)
    }

    #[cfg(unix)]
    fn parse_swapped(fixture: &Fixture) -> Result<WritableTree, JailPathError> {
        WritableTree::parse_probed(
            canonical(&fixture.tree),
            &[&canonical(&fixture.tmp)],
            &Home::unknown(),
            WalkLimits::DEFAULT,
            swap_ancestor,
        )
    }

    /// An ancestor swapped for a link to a decoy while the walk holds it
    /// refuses: the recorded path no longer names the entry the parse read.
    #[cfg(unix)]
    #[test]
    fn an_ancestor_swapped_mid_walk_refuses() {
        let fixture = fixture("swap-ancestor");
        let entry = fixture.tree.join("a").join(".git");
        make_dir(&entry);
        make_dir(&fixture.root.join("decoy").join(".git"));
        let walked = parse_swapped(&fixture);
        assert!(
            matches!(
                &walked,
                Err(JailPathError::VcsEntryChanged { path }) if *path == entry
            ),
            "a carve naming the decoy would leave the real entry writable: {walked:?}"
        );
    }

    /// A pointer inside an entry is opened through the held entry, so an
    /// ancestor swapped to a decoy without the pointer cannot hide it.
    #[cfg(unix)]
    #[test]
    fn an_inner_pointer_is_read_through_the_held_entry() {
        let fixture = fixture("swap-inner");
        let entry = fixture.tree.join("a").join(".git");
        make_dir(&entry);
        std::os::unix::fs::symlink(fixture.root.join("elsewhere"), entry.join("commondir"))
            .expect("symlink");
        make_dir(&fixture.root.join("decoy").join(".git"));
        let walked = parse_swapped(&fixture);
        assert!(
            matches!(
                &walked,
                Err(JailPathError::VcsEntryUnexpectedKind { kind: VcsKind::Git, path })
                    if *path == entry.join("commondir")
            ),
            "the held entry's own pointer is the one read: {walked:?}"
        );
    }

    /// A carved entry swapped for another directory after the parse refuses
    /// the recheck run before the jail spawns.
    #[test]
    fn recheck_refuses_a_carved_entry_swapped_after_the_parse() {
        let fixture = fixture("recheck");
        let git = fixture.tree.join(".git");
        make_dir(&git);
        let tree = parse(&fixture).expect("a plain gitdir parses");
        let unchanged = tree.recheck();
        assert!(unchanged.is_ok(), "{unchanged:?}");
        std::fs::rename(&git, fixture.tree.join(".git-old")).expect("move the gitdir");
        make_dir(&git);
        let rechecked = tree.recheck();
        assert!(
            matches!(
                &rechecked,
                Err(JailPathError::VcsEntryChanged { path }) if *path == git
            ),
            "a swapped-in gitdir was never carved: {rechecked:?}"
        );
    }

    /// A junction `.git` is a name-surrogate reparse point, refused like a link.
    #[cfg(windows)]
    #[test]
    fn a_junction_git_entry_refuses() {
        let fixture = fixture("junction");
        let real = fixture.root.join("real.git");
        make_dir(&real);
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(canonical(&fixture.tree).as_path().join(".git"))
            .arg(canonical(&real).as_path())
            .status()
            .expect("run mklink");
        assert!(made.success(), "mklink /J creates the junction fixture");
        let walked = parse(&fixture);
        assert!(
            matches!(
                &walked,
                Err(JailPathError::VcsEntryUnexpectedKind {
                    kind: VcsKind::Git,
                    ..
                })
            ),
            "{walked:?}"
        );
    }

    #[test]
    fn opaque_reparse_display_names_the_remedy_escaped() {
        let refusal = JailPathError::VcsWalkOpaqueReparse {
            path: PathBuf::from("/tree/a\nb\u{1b}[2J"),
        };
        let shown = refusal.to_string();
        assert!(shown.contains("/tree/a\\u{a}b\\u{1b}[2J"), "{shown}");
        assert!(
            !shown.contains('\n') && !shown.contains('\u{1b}'),
            "{shown}"
        );
        assert!(shown.contains("Always keep on this device"), "{shown}");
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

    /// A spelling a Unicode-folding volume opens as a metadata entry is carved
    /// as that entry: a long s, a dotless i, an HFS+-ignored code point.
    #[test]
    fn walk_name_match_unicode_folded() {
        let name = |text: &str| EntryName::new(std::ffi::OsStr::new(text)).expect("entry name");
        for (text, kind) in [
            (".g\u{131}t", VcsKind::Git),
            (".g\u{200C}it", VcsKind::Git),
            ("\u{FEFF}.hg", VcsKind::Mercurial),
            (".j\u{202E}j", VcsKind::Jujutsu),
            ("_darc\u{17F}", VcsKind::Darcs),
        ] {
            assert_eq!(VcsKind::of_entry_name(&name(text)), Some(kind), "{text:?}");
        }
        for text in [".g\u{130}t", "\u{FF0E}git", "_darcs\u{17F}", "\u{200C}"] {
            assert_eq!(VcsKind::of_entry_name(&name(text)), None, "{text:?}");
        }
        let fixture = fixture("walk-unicode-fold");
        let folded = fixture.tree.join("sub").join("_darc\u{17F}");
        make_dir(&folded);
        let tree = parse(&fixture).expect("a folded darcs dir parses");
        assert_eq!(carved(&tree), vec![folded]);
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
