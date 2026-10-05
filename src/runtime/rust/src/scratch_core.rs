// Private scratch directories and files: the one primitive every temporary write goes through.
//
// The single source of truth shared by the runtime and the compiler sandbox.
// The runtime declares this file as the module `scratch_core`, so it vendors
// with `ipe_runtime` into every emitted app; `ipe_sandbox::scratch`
// `include!`s this exact file, since the runtime cannot depend on the
// compiler. Each host supplies a sibling `scratch_host` module with the entropy
// source (`fill_entropy`), the profile variable name (`PROFILE_VAR`), and, off
// Unix, the profile directory (`profile_dir`).
//
// A scratch path is handed to writers that re-resolve it by name (`curl -o`,
// the jail, an Ipe program's own file kernels), so it is only safe while no
// other user can read, predict, or replace any component of it. Every
// constructor therefore establishes:
//
// - the base is resolved and proven trusted: on Unix it is canonicalised and
//   every ancestor is a real directory owned by the effective user or root,
//   writable by no one else unless sticky; elsewhere, where the standard
//   library offers no owner-only creation, it must resolve inside the current
//   user's profile directory, which the OS keeps private to that user;
// - entries are created under the resolved base, never the given path, so a
//   link on the given path re-pointed after the check cannot redirect them;
// - every created name carries 128 bits of OS CSPRNG entropy (an unavailable
//   CSPRNG fails the creation, never weakens the name), is created exclusively
//   (directories 0700, files 0600 with `O_NOFOLLOW`), retries a collision with
//   a fresh name a bounded number of times, and is re-verified: a real
//   directory or regular file, owned by the effective user, no group/other
//   permission bits;
// - a name joined inside a scratch directory is a `LeafName`, one validated
//   path component, so no caller string can add a component or name a device.
//
// A failed check refuses with `io::ErrorKind::PermissionDenied` carrying a
// `ScratchError` or a `ScratchRootRefusal`: nothing is created under an
// untrusted base and nothing is written through a planted link.
//
// The OS temp root is private to this module: every caller reaches it through
// a typed constructor (`ScratchDir::new`, `ScratchDir::new_fitting`,
// `ScratchFile::create`, `private_temp_file`), so no temporary entry anywhere
// is created by name outside these guarantees.
//
// A stale atomic-replace sibling is reclaimed only when its writer is provably
// gone, within two limits:
//
// - liveness is probed in this process's pid namespace on this host; a writer
//   in another pid namespace or on another host sharing the directory looks
//   gone, so only the staleness age protects its sibling, and should that
//   writer outlive the age, its `AtomicSibling::commit` fails with `NotFound`
//   rather than losing the write silently;
// - off Unix there is no portable liveness probe or POSIX owner, so only this
//   process counts as live and every entry counts as owned: reclamation there
//   rests on the exact sibling-name shape and the staleness age alone.
//
// Regular (`//`) comments, not inner docs: this file is `include!`d verbatim
// into a sandbox module, where an inner doc is an illegal mid-file attribute.

use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

use super::scratch_host;

/// Attempts at a fresh name before creation gives up.
const MAX_ATTEMPTS: usize = 8;

/// Bytes of OS CSPRNG entropy in every scratch name (128 bits).
const ENTROPY_BYTES: usize = 16;

/// Longest caller label kept in a scratch name.
const MAX_LABEL_CHARS: usize = 64;

/// The label used when a caller label confines to nothing.
const FALLBACK_LABEL: &str = "scratch";

/// The variable naming the current user's profile directory on Windows.
pub const PROFILE_VAR: &str = scratch_host::PROFILE_VAR;

/// Longest leaf name, in bytes, one filesystem component may carry.
const MAX_LEAF_BYTES: usize = 255;

/// The OS CSPRNG could not supply entropy, so no unguessable name can be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntropyUnavailable {
    /// The rendered entropy-source error.
    pub detail: String,
}

impl fmt::Display for EntropyUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "refusing to create a scratch entry: the OS random source is unavailable ({}), \
             so no unguessable name can be made",
            self.detail
        )
    }
}

impl std::error::Error for EntropyUnavailable {}

impl From<EntropyUnavailable> for io::Error {
    fn from(unavailable: EntropyUnavailable) -> Self {
        Self::other(unavailable)
    }
}

/// Why a string is not a single leaf name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafNameRefusal {
    /// The name is empty.
    Empty,
    /// The name exceeds the per-component byte limit.
    TooLong,
    /// The name is `.` or `..`, or does not parse as one plain component.
    DotName,
    /// The name carries a separator, a stream marker, a Windows-reserved
    /// character (`< > " | ? *`), or a control character.
    ForbiddenChar(char),
    /// The name ends in `.` or a space, which Windows silently strips.
    TrailingDotOrSpace,
    /// The name is a Windows device name (`CON`, `NUL`, `COM1`, `CONIN$`, and so on).
    ReservedDevice,
}

impl fmt::Display for LeafNameRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("a leaf name must not be empty"),
            Self::TooLong => write!(f, "a leaf name must be at most {MAX_LEAF_BYTES} bytes"),
            Self::DotName => {
                f.write_str("a leaf name must be one plain component, not `.` or `..`")
            }
            Self::ForbiddenChar(c) => write!(f, "a leaf name must not contain {c:?}"),
            Self::TrailingDotOrSpace => f.write_str("a leaf name must not end in `.` or a space"),
            Self::ReservedDevice => f.write_str("a leaf name must not be a device name"),
        }
    }
}

impl std::error::Error for LeafNameRefusal {}

impl From<LeafNameRefusal> for io::Error {
    fn from(refusal: LeafNameRefusal) -> Self {
        Self::new(io::ErrorKind::InvalidInput, refusal)
    }
}

/// Windows device names, reserved in every directory and under any extension.
///
/// Compared ASCII-case-insensitively; the superscript digits Windows also
/// accepts after `COM`/`LPT` match exactly.
const RESERVED_DEVICES: [&str; 30] = [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "COM\u{b9}",
    "COM\u{b2}",
    "COM\u{b3}",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "LPT\u{b9}",
    "LPT\u{b2}",
    "LPT\u{b3}",
    "CONIN$",
    "CONOUT$",
];

/// Characters no leaf name may carry: separators, the stream marker, and the
/// characters Windows reserves in a file name.
const FORBIDDEN_LEAF_CHARS: [char; 9] = ['/', '\\', ':', '<', '>', '"', '|', '?', '*'];

/// One validated path component: the only name a scratch directory joins.
///
/// The rules are the same on every target, so a name accepted on one host
/// names exactly one plain entry on all of them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LeafName(String);

impl LeafName {
    /// Parse `name` as exactly one plain path component.
    ///
    /// # Errors
    /// The [`LeafNameRefusal`] naming the first rule `name` violates.
    pub fn new(name: &str) -> Result<Self, LeafNameRefusal> {
        if name.is_empty() {
            return Err(LeafNameRefusal::Empty);
        }
        if name.len() > MAX_LEAF_BYTES {
            return Err(LeafNameRefusal::TooLong);
        }
        if name == "." || name == ".." {
            return Err(LeafNameRefusal::DotName);
        }
        if let Some(c) = name
            .chars()
            .find(|&c| FORBIDDEN_LEAF_CHARS.contains(&c) || c.is_control())
        {
            return Err(LeafNameRefusal::ForbiddenChar(c));
        }
        if name.ends_with(['.', ' ']) {
            return Err(LeafNameRefusal::TrailingDotOrSpace);
        }
        let stem = name.split('.').next().unwrap_or(name).trim_end();
        if RESERVED_DEVICES
            .iter()
            .any(|device| stem.eq_ignore_ascii_case(device))
        {
            return Err(LeafNameRefusal::ReservedDevice);
        }
        let mut components = Path::new(name).components();
        match (components.next(), components.next()) {
            (Some(Component::Normal(one)), None) if one == name => Ok(Self(name.to_owned())),
            _ => Err(LeafNameRefusal::DotName),
        }
    }

    /// The validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for LeafName {
    type Error = LeafNameRefusal;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        Self::new(name)
    }
}

impl AsRef<Path> for LeafName {
    fn as_ref(&self) -> &Path {
        Path::new(&self.0)
    }
}

impl fmt::Display for LeafName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Variables that name the OS temp root, a base other local users can write.
///
/// No environment reader outside this module answers them: the temp root is
/// resolved only by [`temp_root`], behind the base checks every constructor
/// runs. The compiler's `ipe_env` refuses the same names; the sandbox asserts
/// the two lists agree at build time.
pub const TEMP_ROOT_NAMES: [&str; 3] = ["TMPDIR", "TMP", "TEMP"];

/// Whether `key` spells a [`TEMP_ROOT_NAMES`] entry under any case mapping.
///
/// Fails closed: a key matches when its per-character ASCII fold or its full
/// Unicode uppercase equals a name, ASCII case ignored.
#[must_use]
pub fn is_temp_root_key(key: &str) -> bool {
    let folded: String = key
        .chars()
        .map(|c| {
            c.to_uppercase()
                .next()
                .filter(char::is_ascii_alphabetic)
                .or_else(|| c.to_lowercase().next().filter(char::is_ascii_alphabetic))
                .unwrap_or(c)
        })
        .collect();
    let upper = key.to_uppercase();
    TEMP_ROOT_NAMES
        .iter()
        .any(|n| n.eq_ignore_ascii_case(&folded) || n.eq_ignore_ascii_case(&upper))
}

/// The OS temp root; WebAssembly has none.
///
/// # Errors
/// `Unsupported` on WebAssembly, where the standard library's temp lookup
/// panics instead of answering.
fn temp_root() -> io::Result<PathBuf> {
    if cfg!(target_family = "wasm") {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this target has no OS temp directory",
        ))
    } else {
        #[expect(
            clippy::disallowed_methods,
            reason = "the one temp-root lookup, behind every constructor's base checks"
        )]
        let root = std::env::temp_dir();
        Ok(root)
    }
}

/// The OS temp root, held only to be erased from text.
///
/// Redaction is its whole surface: no `AsRef<Path>`, `Into<PathBuf>`, `Deref`,
/// `Display` or `Debug` hands the root back, so no caller can create an entry
/// under the shared base or print it. Temporary entries come only from this
/// module's constructors.
pub struct TempRootRedactor(String);

impl TempRootRedactor {
    /// The current OS temp root; `None` where [`temp_root`] has none, or where
    /// it is empty (an empty pattern would match everywhere).
    #[must_use]
    pub fn current() -> Option<Self> {
        let text = temp_root().ok()?.to_string_lossy().into_owned();
        (!text.is_empty()).then_some(Self(text))
    }

    /// `input` with every occurrence of the root replaced by `placeholder`.
    #[must_use]
    pub fn redact(&self, input: &str, placeholder: &str) -> String {
        input.replace(self.0.as_str(), placeholder)
    }

    /// The root's length in bytes, to order it among other redactions
    /// longest-first.
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.0.len()
    }
}

/// The OS temp root for this crate's test code.
///
/// Tests that need the shared base itself (to plant a hostile entry, or to
/// build a fixture next to a scratch entry) read it here, never through the
/// standard library directly.
#[cfg(all(test, not(target_arch = "wasm32")))]
#[must_use]
#[expect(
    clippy::disallowed_methods,
    reason = "the sanctioned test reader of the temp root"
)]
pub fn test_temp_root() -> PathBuf {
    std::env::temp_dir()
}

/// The bases a length-bounded entry may live under: the OS temp root, then, on Unix, the short `/tmp`.
///
/// # Errors
/// `Unsupported` where [`temp_root`] has none.
fn fitting_bases() -> io::Result<Vec<PathBuf>> {
    let root = temp_root()?;
    #[cfg(unix)]
    let bases = vec![root, PathBuf::from("/tmp")];
    #[cfg(not(unix))]
    let bases = vec![root];
    Ok(bases)
}

/// Why a scratch location was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScratchRefusal {
    /// The entry is not a real directory (a symlink, a file, or another type).
    NotADirectory,
    /// The entry is not a regular file.
    NotARegularFile,
    /// The entry is owned by a user other than the effective user (or root, for a base).
    ForeignOwner,
    /// The entry is writable by other users without the sticky bit.
    WritableByOthers,
    /// A private entry grants group or other permission bits.
    NotPrivate,
}

impl fmt::Display for ScratchRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotADirectory => "not a real directory",
            Self::NotARegularFile => "not a regular file",
            Self::ForeignOwner => "owned by another user",
            Self::WritableByOthers => "writable by other users without the sticky bit",
            Self::NotPrivate => "grants group or other permissions",
        })
    }
}

impl std::error::Error for ScratchRefusal {}

/// A refused scratch location: the path and the reason.
#[derive(Debug)]
pub struct ScratchError {
    /// The path that failed verification.
    pub path: PathBuf,
    /// Why it was refused.
    pub refusal: ScratchRefusal,
}

impl fmt::Display for ScratchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "refusing scratch location {}: {}",
            self.path.display(),
            self.refusal
        )
    }
}

impl std::error::Error for ScratchError {}

/// Wrap a refusal of `path` as a `PermissionDenied` I/O error.
fn refused(path: &Path, refusal: ScratchRefusal) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        ScratchError {
            path: path.to_path_buf(),
            refusal,
        },
    )
}

/// Why a scratch root cannot be proven private to the current user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScratchRootRefusal {
    /// No absolute profile directory is set, so no root can be proven private.
    NoProfile,
    /// A path could not be resolved to its canonical form.
    Unresolvable {
        /// The path that failed to resolve.
        path: PathBuf,
        /// The rendered OS error.
        detail: String,
    },
    /// The root resolves outside the profile directory.
    OutsideProfile {
        /// The canonical scratch root.
        root: PathBuf,
        /// The canonical profile directory.
        profile: PathBuf,
    },
}

/// The remedy every root refusal names.
const FIX: &str = "set TEMP and TMP to a directory inside your user profile, \
                   such as %LOCALAPPDATA%\\Temp (the Windows default)";

impl fmt::Display for ScratchRootRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProfile => write!(
                f,
                "refusing to create scratch files: {PROFILE_VAR} does not name an absolute \
                 directory, so the scratch location cannot be proven private to you; {FIX}"
            ),
            Self::Unresolvable { path, detail } => write!(
                f,
                "refusing to create scratch files: cannot resolve {} ({detail}), so it cannot \
                 be proven private to you; {FIX}",
                path.display()
            ),
            Self::OutsideProfile { root, profile } => write!(
                f,
                "refusing to create scratch files under {}: it lies outside your user profile \
                 ({}), so other local users may read or modify what is written there; {FIX}",
                root.display(),
                profile.display()
            ),
        }
    }
}

impl std::error::Error for ScratchRootRefusal {}

impl From<ScratchRootRefusal> for io::Error {
    fn from(refusal: ScratchRootRefusal) -> Self {
        Self::new(io::ErrorKind::PermissionDenied, refusal)
    }
}

/// No candidate base left room for the entry within its path-length limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoFittingBase;

impl fmt::Display for NoFittingBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no scratch base leaves room for the entry within its path-length limit")
    }
}

impl std::error::Error for NoFittingBase {}

/// Every one of the [`MAX_ATTEMPTS`] fresh names already existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamesExhausted;

impl fmt::Display for NamesExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "could not create a unique scratch entry after {MAX_ATTEMPTS} attempts"
        )
    }
}

impl std::error::Error for NamesExhausted {}

/// The ownership and permission facts a verdict needs about one filesystem entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryFacts {
    /// The entry's file type, as seen without following a final symlink.
    pub kind: EntryKind,
    /// Owning uid.
    pub owner: u32,
    /// Owning gid.
    pub group: u32,
    /// Full mode bits (permission, sticky, setuid/setgid).
    pub mode: u32,
}

/// The file type of an entry, as seen without following a final symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A real directory.
    Directory,
    /// A regular file.
    File,
    /// Anything else, a symlink included.
    Other,
}

/// The effective identity scratch entries must belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    /// Effective uid.
    pub euid: u32,
    /// Effective gid.
    pub egid: u32,
}

const ROOT_UID: u32 = 0;
const STICKY: u32 = 0o1000;
const GROUP_WRITE: u32 = 0o020;
const OTHER_WRITE: u32 = 0o002;
const GROUP_OTHER_BITS: u32 = 0o077;

/// Whether `entry` may be an ancestor of (or be) the base a private directory is created under.
///
/// The base must be a directory owned by the effective user or root. A world-
/// writable base must be sticky; a group-writable one must be sticky or be the
/// effective user's own directory with the effective group (a user-private group).
///
/// # Errors
/// The [`ScratchRefusal`] naming the first violated condition.
pub const fn base_verdict(entry: EntryFacts, who: Identity) -> Result<(), ScratchRefusal> {
    if !matches!(entry.kind, EntryKind::Directory) {
        return Err(ScratchRefusal::NotADirectory);
    }
    if entry.owner != who.euid && entry.owner != ROOT_UID {
        return Err(ScratchRefusal::ForeignOwner);
    }
    let sticky = entry.mode & STICKY != 0;
    if entry.mode & OTHER_WRITE != 0 && !sticky {
        return Err(ScratchRefusal::WritableByOthers);
    }
    let own_private_group = entry.owner == who.euid && entry.group == who.egid;
    if entry.mode & GROUP_WRITE != 0 && !sticky && !own_private_group {
        return Err(ScratchRefusal::WritableByOthers);
    }
    Ok(())
}

/// Whether `entry` is a private scratch entry of the expected `kind`.
///
/// It must be exactly that kind (never a symlink), owned by the effective user,
/// and grant no group or other permission bits.
///
/// # Errors
/// The [`ScratchRefusal`] naming the first violated condition.
pub const fn private_verdict(
    entry: EntryFacts,
    kind: EntryKind,
    who: Identity,
) -> Result<(), ScratchRefusal> {
    match (entry.kind, kind) {
        (EntryKind::Directory, EntryKind::Directory) | (EntryKind::File, EntryKind::File) => {}
        (EntryKind::Directory | EntryKind::Other, EntryKind::File) => {
            return Err(ScratchRefusal::NotARegularFile);
        }
        (
            EntryKind::Directory | EntryKind::File | EntryKind::Other,
            EntryKind::Directory | EntryKind::Other,
        ) => return Err(ScratchRefusal::NotADirectory),
    }
    if entry.owner != who.euid {
        return Err(ScratchRefusal::ForeignOwner);
    }
    if entry.mode & GROUP_OTHER_BITS != 0 {
        return Err(ScratchRefusal::NotPrivate);
    }
    Ok(())
}

/// Decide whether a canonical scratch root lies inside a canonical profile.
///
/// Both paths are expected canonical (absolute, links resolved). Anything that
/// is not provably inside is refused: a profile that is relative, holds a `..`
/// segment, or names a bare filesystem root (which would make every path
/// "private"); a root that is relative, holds a `..` segment, or lies outside
/// the profile, compared component-wise so `/home/al` never contains
/// `/home/alice`.
///
/// # Errors
/// Returns the [`ScratchRootRefusal`] that the root fails.
pub fn root_within_profile(root: &Path, profile: &Path) -> Result<(), ScratchRootRefusal> {
    let has_parent_dir = |p: &Path| p.components().any(|c| matches!(c, Component::ParentDir));
    let names_a_directory = profile
        .components()
        .any(|c| matches!(c, Component::Normal(_)));
    if !profile.is_absolute() || has_parent_dir(profile) || !names_a_directory {
        return Err(ScratchRootRefusal::NoProfile);
    }
    if root.is_absolute() && !has_parent_dir(root) && root.starts_with(profile) {
        Ok(())
    } else {
        Err(ScratchRootRefusal::OutsideProfile {
            root: root.to_path_buf(),
            profile: profile.to_path_buf(),
        })
    }
}

/// Resolve `root` and `profile`, require the root inside the profile, and return the resolved root.
///
/// `profile` is the raw value of [`PROFILE_VAR`]; an unset, empty, or relative
/// value proves nothing and is refused. Resolution follows every link, so a
/// link inside the profile that points outside it is refused too. Entries must
/// be created under the returned path, not under `root`, so that a link on
/// `root` re-pointed after the check cannot redirect the creation.
///
/// # Errors
/// Returns a [`ScratchRootRefusal`] when either path cannot be resolved or the
/// resolved root lies outside the resolved profile.
pub fn verify_root_within_profile(
    root: &Path,
    profile: Option<&OsStr>,
) -> Result<PathBuf, ScratchRootRefusal> {
    let profile = profile
        .map(Path::new)
        .filter(|p| p.is_absolute())
        .ok_or(ScratchRootRefusal::NoProfile)?;
    let root = canonical(root)?;
    root_within_profile(&root, &canonical(profile)?)?;
    Ok(root)
}

/// The canonical form of `path`, or the refusal naming why it has none.
fn canonical(path: &Path) -> Result<PathBuf, ScratchRootRefusal> {
    std::fs::canonicalize(path).map_err(|e| ScratchRootRefusal::Unresolvable {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })
}

#[cfg(unix)]
mod platform {
    use super::{EntryFacts, EntryKind, Identity};
    use std::os::unix::fs::MetadataExt as _;

    /// The effective uid and gid of this process.
    #[must_use]
    pub fn identity() -> Identity {
        Identity {
            euid: rustix::process::geteuid().as_raw(),
            egid: rustix::process::getegid().as_raw(),
        }
    }

    /// The verdict facts of `meta`.
    #[must_use]
    pub fn facts(meta: &std::fs::Metadata) -> EntryFacts {
        let ft = meta.file_type();
        let kind = if ft.is_dir() {
            EntryKind::Directory
        } else if ft.is_file() {
            EntryKind::File
        } else {
            EntryKind::Other
        };
        EntryFacts {
            kind,
            owner: meta.uid(),
            group: meta.gid(),
            mode: meta.mode(),
        }
    }
}

/// Resolve `base` to the trusted canonical directory private entries are created under.
///
/// Creates `base` when absent, canonicalises it (so no ancestor is a symlink), and
/// requires [`base_verdict`] of every ancestor.
#[cfg(unix)]
fn trusted_base(base: &Path) -> io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt as _;
    // Components this call creates are private, so they pass `base_verdict`
    // without the owner-group exception.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(base)?;
    let canonical = std::fs::canonicalize(base)?;
    let who = platform::identity();
    for dir in canonical.ancestors() {
        let meta = std::fs::symlink_metadata(dir)?;
        base_verdict(platform::facts(&meta), who).map_err(|r| refused(dir, r))?;
    }
    Ok(canonical)
}

/// Resolve `base` to the directory private entries are created under, proven inside the user's profile.
///
/// Non-unix hosts carry no POSIX owner or mode bits, so an entry inherits its
/// parent's access control. The nearest existing ancestor of `base` is proven
/// inside the profile before any missing component is created, and `base`
/// itself is proven again once it exists; the resolved path is returned.
#[cfg(not(unix))]
fn trusted_base(base: &Path) -> io::Result<PathBuf> {
    let home = scratch_host::profile_dir();
    let profile = home.as_deref().map(Path::as_os_str);
    let existing = base
        .ancestors()
        .find(|a| !a.as_os_str().is_empty() && a.exists())
        .unwrap_or(base);
    verify_root_within_profile(existing, profile)?;
    std::fs::create_dir_all(base)?;
    verify_root_within_profile(base, profile).map_err(io::Error::from)
}

/// Verify that `path` is a private directory of the effective user.
///
/// # Errors
/// A `PermissionDenied` [`ScratchError`] when it is a symlink, not a directory,
/// foreign-owned, or grants group/other bits; the lookup error otherwise.
pub fn verify_private_dir(path: &Path) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    verify_private(path, &meta, EntryKind::Directory)
}

#[cfg(unix)]
fn verify_private(path: &Path, meta: &std::fs::Metadata, kind: EntryKind) -> io::Result<()> {
    private_verdict(platform::facts(meta), kind, platform::identity()).map_err(|r| refused(path, r))
}

#[cfg(not(unix))]
fn verify_private(path: &Path, meta: &std::fs::Metadata, kind: EntryKind) -> io::Result<()> {
    let ft = meta.file_type();
    let ok = match kind {
        EntryKind::Directory => ft.is_dir() && !ft.is_symlink(),
        EntryKind::File => ft.is_file() && !ft.is_symlink(),
        EntryKind::Other => false,
    };
    if ok {
        return Ok(());
    }
    Err(refused(
        path,
        if matches!(kind, EntryKind::File) {
            ScratchRefusal::NotARegularFile
        } else {
            ScratchRefusal::NotADirectory
        },
    ))
}

/// Confine a caller label to one bounded, non-empty path component.
///
/// ASCII alphanumerics, `-`, `_` and `.` are kept, every other character
/// becomes `_`, and at most [`MAX_LABEL_CHARS`] characters survive, so a label
/// can never add a path component or reach an alternate data stream. A label is
/// never a whole name (a `-<entropy>` suffix always follows it), so a kept `.`
/// cannot form `.`/`..`; every assembled name is still parsed as a [`LeafName`].
fn confined_label(label: &str) -> String {
    let confined: String = label
        .chars()
        .take(MAX_LABEL_CHARS)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if confined.is_empty() {
        FALLBACK_LABEL.to_owned()
    } else {
        confined
    }
}

/// The suffix of every atomic-replace sibling name, `.<label>-<pid>-<hex>.ipe-tmp`.
///
/// Such a name is hidden (it starts with `.`) and carries this suffix, so a file
/// watcher or a directory listing can recognise and skip it; `ipe dev watch`
/// mirrors this value and the CLI asserts the two agree at build time.
pub const TEMP_SIBLING_SUFFIX: &str = ".ipe-tmp";

/// The shape of a created scratch name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameShape {
    /// `<label>-<pid>-<32 hex chars>`: a scratch directory or file.
    Plain,
    /// `.<label>-<pid>-<32 hex chars>.ipe-tmp`: a hidden atomic-replace sibling.
    HiddenTemp,
}

/// The name of shape `shape` for `label`, its 32 hex chars drawn from `fill`; WebAssembly, having no pid, omits it.
///
/// # Errors
/// The [`EntropyUnavailable`] error when `fill` fails; `InvalidInput` with a
/// [`LeafNameRefusal`] when the assembled name is not one plain leaf (a label
/// whose first dot-segment is a Windows device name, such as `nul.x`).
fn scratch_name(
    label: &str,
    shape: NameShape,
    fill: &mut impl FnMut(&mut [u8]) -> Result<(), EntropyUnavailable>,
) -> io::Result<LeafName> {
    use std::fmt::Write as _;
    let mut entropy = [0u8; ENTROPY_BYTES];
    fill(&mut entropy)?;
    let mut name = String::new();
    if shape == NameShape::HiddenTemp {
        name.push('.');
    }
    name.push_str(&confined_label(label));
    #[cfg(not(target_family = "wasm"))]
    {
        let _ = write!(name, "-{}", std::process::id());
    }
    name.push('-');
    for byte in entropy {
        let _ = write!(name, "{byte:02x}");
    }
    if shape == NameShape::HiddenTemp {
        name.push_str(TEMP_SIBLING_SUFFIX);
    }
    LeafName::new(&name).map_err(io::Error::from)
}

/// The length in bytes of every scratch directory or file name this process gives an entry tagged `label`.
///
/// Lets a caller bounded by a path-length ceiling (a `sockaddr_un`) refuse a
/// base before anything is created under it.
#[must_use]
pub fn scratch_name_len(label: &str) -> usize {
    let len = confined_label(label)
        .len()
        .saturating_add(1 + 2 * ENTROPY_BYTES);
    #[cfg(not(target_family = "wasm"))]
    let len = len
        .saturating_add(1)
        .saturating_add(std::process::id().to_string().len());
    len
}

/// Create an entry under the trusted `base` with `create`, retrying a collision with a fresh name.
///
/// At most [`MAX_ATTEMPTS`] names are tried; `fill` supplies each name's entropy
/// and its failure fails the creation before any entry is attempted.
fn create_unique<T>(
    base: &Path,
    label: &str,
    shape: NameShape,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), EntropyUnavailable>,
    mut create: impl FnMut(&Path) -> io::Result<T>,
) -> io::Result<(PathBuf, T)> {
    for _ in 0..MAX_ATTEMPTS {
        let path = base.join(scratch_name(label, shape, &mut fill)?);
        match create(&path) {
            Ok(entry) => return Ok((path, entry)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, NamesExhausted))
}

/// Create an entry as [`create_unique`] does, then hold it to `verify`; a refused entry is removed.
///
/// The name was created exclusively by this call, so the entry under it is
/// ours: a refusal (a filesystem that cannot hold owner-only modes, say) drops
/// the handle and removes the entry with `remove` before the refusal is
/// returned, so a refused creation leaves nothing behind. `remove` is
/// non-recursive (`remove_file` / `remove_dir`), never following into content
/// another party may have placed in a refused directory.
fn create_verified<T>(
    base: &Path,
    label: &str,
    shape: NameShape,
    create: impl FnMut(&Path) -> io::Result<T>,
    verify: impl FnOnce(&Path, &T) -> io::Result<()>,
    remove: fn(&Path) -> io::Result<()>,
) -> io::Result<(PathBuf, T)> {
    let (path, entry) = create_unique(base, label, shape, scratch_host::fill_entropy, create)?;
    match verify(&path, &entry) {
        Ok(()) => Ok((path, entry)),
        Err(refusal) => {
            drop(entry);
            let _ = remove(&path);
            Err(refusal)
        }
    }
}

/// The verification every created scratch file passes: its open handle is a private regular file.
fn verify_file_handle(path: &Path, file: &File) -> io::Result<()> {
    verify_private(path, &file.metadata()?, EntryKind::File)
}

/// Create the directory `path` exclusively with mode 0700; only the final component is created.
#[cfg(unix)]
fn exclusive_mkdir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(false)
        .create(path)
}

/// Create the directory `path` exclusively, inheriting the proven-private parent's access control.
#[cfg(not(unix))]
fn exclusive_mkdir(path: &Path) -> io::Result<()> {
    std::fs::create_dir(path)
}

/// Signal interruptions `exclusive_open` retries before it surfaces `Interrupted`.
#[cfg(unix)]
const OPEN_INTERRUPT_RETRIES: u32 = 8;

/// Open a new file at `path`: exclusive, never through a final symlink, mode 0600.
#[cfg(unix)]
fn exclusive_open(path: &Path) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut interrupts = 0;
    loop {
        match rustix::fs::open(path, flags, Mode::from_raw_mode(0o600)) {
            Ok(fd) => return Ok(File::from(fd)),
            Err(rustix::io::Errno::INTR) if interrupts < OPEN_INTERRUPT_RETRIES => interrupts += 1,
            Err(e) => return Err(e.into()),
        }
    }
}

/// Open a new file at `path` exclusively, inheriting the proven-private parent's access control.
#[cfg(not(unix))]
fn exclusive_open(path: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

/// Create a private regular file directly under the trusted `base`, kept past this call.
///
/// The name is `<label>-<pid>-<32 hex CSPRNG chars>` as in
/// [`ScratchDir::new_under`]; the file is opened exclusively, never through a
/// final symlink, with mode 0600, and its handle is verified private.
///
/// # Errors
/// See [`ScratchDir::new_under`]; also `PermissionDenied` with a
/// [`ScratchError`] when the opened handle is not a private regular file of the
/// effective user (the refused file is removed first); `InvalidInput` with a
/// [`LeafNameRefusal`] when the label makes a device name.
pub fn private_file_under(base: &Path, label: &str) -> io::Result<(PathBuf, File)> {
    private_file_under_with(base, label, verify_file_handle)
}

/// Create a private file directly under the OS temp root, as [`private_file_under`] does.
///
/// # Errors
/// `Unsupported` where the target has no OS temp root; otherwise see
/// [`private_file_under`].
pub fn private_temp_file(label: &str) -> io::Result<(PathBuf, File)> {
    private_file_under(&temp_root()?, label)
}

/// [`private_file_under`] with the handle verification supplied, so a refusal can be driven in tests.
fn private_file_under_with(
    base: &Path,
    label: &str,
    verify: impl FnOnce(&Path, &File) -> io::Result<()>,
) -> io::Result<(PathBuf, File)> {
    let base = trusted_base(base)?;
    create_verified(
        &base,
        label,
        NameShape::Plain,
        exclusive_open,
        verify,
        |p: &Path| std::fs::remove_file(p),
    )
}

// ── AtomicSibling ────────────────────────────────────────────────────────────

/// An atomic replacement of `target`: a private sibling written, then renamed over it.
///
/// The sibling is created beside `target` under a hidden, unguessable name
/// (`.<target name>-<pid>-<32 hex>.ipe-tmp`, see [`TEMP_SIBLING_SUFFIX`]),
/// exclusively, never through a final symlink, with mode 0600, and verified
/// private; a sibling that fails verification is removed before the refusal
/// returns. Until [`AtomicSibling::commit`] renames it over `target`, dropping
/// the guard removes the sibling, so no failure between creation and rename
/// (a refused verdict, a short write, a failed rename) leaves it behind. Only a
/// process that dies inside that window can leave one, under a name the
/// suffix identifies; the next replacement of a target with the same label
/// reclaims such a leftover once it is stale and its writer is gone.
///
/// The directory is the caller's chosen destination, so it is not held to the
/// scratch-base trust rules; the name still carries CSPRNG entropy, so a name
/// planted in advance can neither redirect nor block the write.
#[derive(Debug)]
pub struct AtomicSibling {
    target: PathBuf,
    tmp: PathBuf,
    file: File,
    committed: bool,
}

impl AtomicSibling {
    /// Create the private sibling that will replace `target`.
    ///
    /// # Errors
    /// `PermissionDenied` with a [`ScratchError`] when the created sibling is not
    /// a private regular file of the effective user (on a filesystem that cannot
    /// hold owner-only modes, for one) — the sibling is removed first; the
    /// [`EntropyUnavailable`] error when the OS CSPRNG is unavailable;
    /// `AlreadyExists` carrying [`NamesExhausted`] when every fresh name
    /// collided; any other open error.
    pub fn create(target: &Path) -> io::Result<Self> {
        Self::create_with(target, verify_file_handle)
    }

    /// Create the private sibling that will replace `target`, whose leftovers were already reclaimed.
    ///
    /// Unlike [`AtomicSibling::create`] it reads no directory, so a caller on an
    /// async executor can replace the same target on every write.
    ///
    /// # Errors
    /// See [`AtomicSibling::create`].
    pub fn create_reclaimed(target: &ReclaimedTarget) -> io::Result<Self> {
        Self::create_reclaimed_with(target, verify_file_handle)
    }

    /// [`AtomicSibling::create`] with the handle verification supplied, so a refusal can be driven in tests.
    fn create_with(
        target: &Path,
        verify: impl FnOnce(&Path, &File) -> io::Result<()>,
    ) -> io::Result<Self> {
        Self::create_reclaimed_with(&ReclaimedTarget::new(target), verify)
    }

    /// [`AtomicSibling::create_reclaimed`] with the handle verification supplied.
    fn create_reclaimed_with(
        target: &ReclaimedTarget,
        verify: impl FnOnce(&Path, &File) -> io::Result<()>,
    ) -> io::Result<Self> {
        let (parent, label) = sibling_home(&target.0);
        let (tmp, file) = create_verified(
            parent,
            label,
            NameShape::HiddenTemp,
            exclusive_open,
            verify,
            |p: &Path| std::fs::remove_file(p),
        )?;
        Ok(Self {
            target: target.0.clone(),
            tmp,
            file,
            committed: false,
        })
    }

    /// The sibling's path.
    #[must_use]
    pub fn tmp_path(&self) -> &Path {
        &self.tmp
    }

    /// Append `bytes` to the sibling.
    ///
    /// # Errors
    /// Any write error; the sibling is still removed when the guard drops.
    pub fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        use std::io::Write as _;
        self.file.write_all(bytes)
    }

    /// Flush the sibling and rename it over the target.
    ///
    /// The handle stays open across the rename (the standard library opens
    /// files shareable for deletion on Windows, so the rename is allowed there
    /// too) and closes when the guard drops.
    ///
    /// # Errors
    /// Any flush or rename error; the sibling is removed when the guard drops.
    pub fn commit(mut self) -> io::Result<()> {
        use std::io::Write as _;
        self.file.flush()?;
        std::fs::rename(&self.tmp, &self.target)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for AtomicSibling {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

/// The directory an atomic-replace sibling of `target` lives in, and the label naming it.
fn sibling_home(target: &Path) -> (&Path, &str) {
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let label = target
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(FALLBACK_LABEL);
    (parent, label)
}

/// A replacement target whose stale atomic-replace siblings have been reclaimed.
///
/// Built once where blocking I/O is allowed, it lets
/// [`AtomicSibling::create_reclaimed`] replace the target any number of times
/// without scanning its directory again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimedTarget(PathBuf);

impl ReclaimedTarget {
    /// Reclaim the stale siblings that dead writers left for `target`.
    ///
    /// The sweep is the one [`AtomicSibling::create`] runs first: bounded to
    /// [`MAX_RECLAIM_ENTRIES`] directory entries, once per directory and
    /// label per process, and best effort, so it never fails.
    #[must_use]
    pub fn new(target: &Path) -> Self {
        #[cfg(not(target_family = "wasm"))]
        {
            let (parent, label) = sibling_home(target);
            reclaim_stale_siblings(parent, label);
        }
        Self(target.to_path_buf())
    }

    /// The target path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

// ── Stale-sibling reclamation ────────────────────────────────────────────────

/// How long a leftover atomic-replace sibling sits unmodified before it is stale.
#[cfg(not(target_family = "wasm"))]
const STALE_SIBLING_AGE: std::time::Duration = std::time::Duration::from_hours(1);

/// The most directory entries one reclamation sweep reads.
#[cfg(not(target_family = "wasm"))]
const MAX_RECLAIM_ENTRIES: usize = 4096;

/// The most swept `(directory, label)` pairs this process remembers.
#[cfg(not(target_family = "wasm"))]
const MAX_RECLAIM_MEMO: usize = 64;

/// The `(directory, label)` pairs this process has swept, as `directory/label`.
#[cfg(not(target_family = "wasm"))]
static RECLAIMED: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

/// The facts an atomic-replace sibling name carries.
#[cfg(not(target_family = "wasm"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SiblingName {
    /// The pid of the process that created the sibling.
    pid: u32,
}

/// Parse `name` as an atomic-replace sibling name for `label`: `.<label>-<pid>-<32 hex>.ipe-tmp`.
///
/// The label is confined as [`scratch_name`] confines it, the pid is decimal
/// digits only, and the entropy is exactly 32 lowercase hex characters; any
/// other name, including another target's sibling, is `None`.
#[cfg(not(target_family = "wasm"))]
fn parse_sibling_name(name: &str, label: &str) -> Option<SiblingName> {
    let rest = name
        .strip_prefix('.')?
        .strip_prefix(confined_label(label).as_str())?
        .strip_prefix('-')?
        .strip_suffix(TEMP_SIBLING_SUFFIX)?;
    let (pid, hex) = rest.split_once('-')?;
    let pid_is_decimal = !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit());
    let hex_is_entropy = hex.len() == 2 * ENTROPY_BYTES
        && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !(pid_is_decimal && hex_is_entropy) {
        return None;
    }
    pid.parse().ok().map(|pid| SiblingName { pid })
}

/// Whether the process that created `sibling` may still be writing it.
///
/// This process is always live; another pid is live unless the kernel reports
/// no such process. A pid that is not a valid process id is treated as live,
/// so an unprovable death keeps the sibling.
#[cfg(unix)]
fn writer_may_be_alive(sibling: SiblingName) -> bool {
    if sibling.pid == std::process::id() {
        return true;
    }
    i32::try_from(sibling.pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .is_none_or(|pid| rustix::process::test_kill_process(pid) != Err(rustix::io::Errno::SRCH))
}

/// Whether the process that created `sibling` may still be writing it.
///
/// Without a portable liveness probe only this process is known live; the
/// staleness age alone protects another process's sibling.
#[cfg(all(not(unix), not(target_family = "wasm")))]
fn writer_may_be_alive(sibling: SiblingName) -> bool {
    sibling.pid == std::process::id()
}

/// Whether `meta` belongs to the effective user.
#[cfg(unix)]
fn owned_by_effective_user(meta: &std::fs::Metadata) -> bool {
    platform::facts(meta).owner == platform::identity().euid
}

/// Whether `meta` belongs to the effective user; non-unix entries carry no POSIX owner.
#[cfg(all(not(unix), not(target_family = "wasm")))]
const fn owned_by_effective_user(_meta: &std::fs::Metadata) -> bool {
    true
}

/// The facts deciding whether a sibling-named entry is a leftover this process may remove.
#[cfg(not(target_family = "wasm"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LeftoverFacts {
    /// The entry is a regular file, not a symlink, directory or other kind.
    regular_file: bool,
    /// The entry belongs to the effective user.
    owned: bool,
    /// How long ago it was last modified; `None` when unknown or in the future.
    age: Option<std::time::Duration>,
    /// The process that created it may still be writing it.
    writer_alive: bool,
}

/// Whether `facts` describe a removable leftover.
///
/// Only an owned regular file unmodified for [`STALE_SIBLING_AGE`] whose
/// creator is provably gone qualifies; any unknown fact keeps the entry.
#[cfg(not(target_family = "wasm"))]
fn is_leftover(facts: LeftoverFacts) -> bool {
    facts.regular_file
        && facts.owned
        && facts.age.is_some_and(|age| age >= STALE_SIBLING_AGE)
        && !facts.writer_alive
}

/// The [`LeftoverFacts`] of the sibling-named entry with `meta`, read at `now`.
///
/// A modification time after `now`, or an unreadable one, yields an unknown age.
#[cfg(not(target_family = "wasm"))]
fn leftover_facts(
    meta: &std::fs::Metadata,
    sibling: SiblingName,
    now: std::time::SystemTime,
) -> LeftoverFacts {
    LeftoverFacts {
        regular_file: meta.file_type().is_file(),
        owned: owned_by_effective_user(meta),
        age: meta
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok()),
        writer_alive: writer_may_be_alive(sibling),
    }
}

/// Whether the sibling-named entry with `meta` is [`is_leftover`] at `now`.
#[cfg(not(target_family = "wasm"))]
fn is_reclaimable(
    meta: &std::fs::Metadata,
    sibling: SiblingName,
    now: std::time::SystemTime,
) -> bool {
    is_leftover(leftover_facts(meta, sibling, now))
}

/// Record that `key` is being swept; `false` when this process already swept it.
///
/// Once [`MAX_RECLAIM_MEMO`] keys are remembered, further keys are swept on
/// every call rather than forgotten.
#[cfg(not(target_family = "wasm"))]
fn first_sweep(key: PathBuf) -> bool {
    let Ok(mut swept) = RECLAIMED.lock() else {
        return true;
    };
    if swept.contains(&key) {
        return false;
    }
    if swept.len() < MAX_RECLAIM_MEMO {
        swept.push(key);
    }
    true
}

/// Remove the stale atomic-replace siblings for `label` that dead writers left in `parent`.
///
/// Runs once per `(parent, label)` per process, reads at most
/// [`MAX_RECLAIM_ENTRIES`] entries, and removes only entries whose name
/// parses as this label's sibling ([`parse_sibling_name`]) and that are
/// [`is_reclaimable`]. `remove_file` unlinks the name alone, never following
/// it. Reclamation is best effort: an unreadable directory or a failed removal
/// leaves the leftover and never fails the replacement.
#[cfg(not(target_family = "wasm"))]
fn reclaim_stale_siblings(parent: &Path, label: &str) {
    if !first_sweep(parent.join(confined_label(label))) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    let now = std::time::SystemTime::now();
    for entry in entries.take(MAX_RECLAIM_ENTRIES).flatten() {
        let name = entry.file_name();
        let Some(sibling) = name.to_str().and_then(|n| parse_sibling_name(n, label)) else {
            continue;
        };
        let path = entry.path();
        if std::fs::symlink_metadata(&path).is_ok_and(|meta| is_reclaimable(&meta, sibling, now)) {
            let _ = std::fs::remove_file(&path);
        }
    }
}

// ── ScratchDir ───────────────────────────────────────────────────────────────

/// A verified private, unpredictably named temporary directory, removed on drop.
///
/// Use [`ScratchDir::path`] for the directory itself and [`ScratchDir::child`] to
/// build paths inside it; [`ScratchDir::into_path`] transfers ownership without
/// automatic cleanup.
#[derive(Debug)]
pub struct ScratchDir(PathBuf);

impl ScratchDir {
    /// Create a private directory under the OS temp root.
    ///
    /// # Errors
    /// `Unsupported` where [`temp_root`] has none; otherwise see [`ScratchDir::new_under`].
    pub fn new(label: &str) -> io::Result<Self> {
        Self::new_under(&temp_root()?, label)
    }

    /// Create a private directory directly under the resolved `base`, creating `base` when absent.
    ///
    /// The name is `<label>-<pid>-<32 hex CSPRNG chars>`; `label` is a diagnostic
    /// tag only, confined to one bounded component (ASCII alphanumerics, `-`,
    /// `_` and `.`; others become `_`; at most 64 characters).
    ///
    /// # Errors
    /// `PermissionDenied` with a [`ScratchError`] when `base` (or an ancestor) or
    /// the created directory fails verification (a refused directory is removed
    /// first), or with a [`ScratchRootRefusal`] when a non-unix `base` cannot be
    /// proven inside the user's profile; `InvalidInput` with a
    /// [`LeafNameRefusal`] when the label makes a device name; the
    /// [`EntropyUnavailable`] error when the OS CSPRNG is unavailable; `AlreadyExists`
    /// carrying [`NamesExhausted`] when every fresh name collided; any other I/O
    /// error.
    pub fn new_under(base: &Path, label: &str) -> io::Result<Self> {
        Self::new_under_with(base, label, |path, ()| verify_private_dir(path))
    }

    /// [`ScratchDir::new_under`] with the directory verification supplied, so a refusal can be driven in tests.
    fn new_under_with(
        base: &Path,
        label: &str,
        verify: impl FnOnce(&Path, &()) -> io::Result<()>,
    ) -> io::Result<Self> {
        let base = trusted_base(base)?;
        let (path, ()) = create_verified(
            &base,
            label,
            NameShape::Plain,
            exclusive_mkdir,
            verify,
            |p: &Path| std::fs::remove_dir(p),
        )?;
        Ok(Self(path))
    }

    /// Create a private directory under the OS temp root, or on Unix `/tmp`, whose `entry` path fits `max_bytes`.
    ///
    /// For a path with a hard length ceiling, such as a Unix socket's
    /// `sockaddr_un`, when the OS temp root is too deep to hold it.
    ///
    /// # Errors
    /// `Unsupported` where the target has no OS temp root; otherwise see
    /// [`ScratchDir::new_fitting_under`].
    pub fn new_fitting(label: &str, entry: &LeafName, max_bytes: usize) -> io::Result<Self> {
        Self::new_fitting_under(&fitting_bases()?, label, entry, max_bytes)
    }

    /// Create a private directory under the first of `bases` where the path of `entry` inside it fits `max_bytes`.
    ///
    /// A base whose given path already leaves no room is skipped untouched; a
    /// base that resolves longer than given, or that refuses the directory, is
    /// passed over for the next one, and a too-long directory is removed.
    ///
    /// # Errors
    /// The last base's refusal (see [`ScratchDir::new_under`]); `InvalidInput`
    /// carrying [`NoFittingBase`] when no base was tried or every resolved
    /// path was too long.
    pub fn new_fitting_under(
        bases: &[PathBuf],
        label: &str,
        entry: &LeafName,
        max_bytes: usize,
    ) -> io::Result<Self> {
        let entry_len = scratch_name_len(label)
            .saturating_add(1)
            .saturating_add(entry.as_str().len());
        let mut refused = None;
        for base in bases {
            if base
                .as_os_str()
                .len()
                .saturating_add(1)
                .saturating_add(entry_len)
                > max_bytes
            {
                continue;
            }
            match Self::new_under(base, label) {
                Ok(dir) if dir.child(entry).as_os_str().len() <= max_bytes => return Ok(dir),
                Ok(_too_long) => {}
                Err(err) => refused = Some(err),
            }
        }
        Err(refused.unwrap_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, NoFittingBase)))
    }

    /// The path of this scratch directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Build the path of the entry `name` inside this directory (not created by this call).
    #[must_use]
    pub fn child(&self, name: &LeafName) -> PathBuf {
        self.0.join(name)
    }

    /// Re-verify that this directory is still a private directory of the effective user.
    ///
    /// # Errors
    /// See [`verify_private_dir`].
    pub fn verify(&self) -> io::Result<()> {
        verify_private_dir(&self.0)
    }

    /// Consume this guard and return the directory path without removing it.
    ///
    /// The path moves out of a never-dropped guard: forgetting the guard
    /// instead would leak the path it owns.
    #[must_use]
    pub fn into_path(self) -> PathBuf {
        let mut guard = std::mem::ManuallyDrop::new(self);
        std::mem::take(&mut guard.0)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ── ScratchFile ──────────────────────────────────────────────────────────────

/// A verified private temporary file inside its own private [`ScratchDir`].
///
/// The owned [`File`] handle outlives the name: read back what an external writer
/// wrote through [`ScratchFile::read_all`], never by re-opening the path. The file
/// and its directory are removed on drop.
#[derive(Debug)]
pub struct ScratchFile {
    /// The open handle; [`ScratchFile::rewind`] before reading external writes.
    pub file: File,
    path: PathBuf,
    // Declared last so the handle closes before the directory is removed.
    dir: ScratchDir,
}

impl ScratchFile {
    /// Create a private file inside a fresh private directory under the OS temp root.
    ///
    /// Both the directory and the file are named from `label` as in
    /// [`ScratchDir::new_under`]; the file is the confined label itself.
    ///
    /// # Errors
    /// See [`ScratchDir::new_under`]; also `PermissionDenied` with a
    /// [`ScratchError`] when the opened handle is not a private regular file of the
    /// effective user, `InvalidInput` with a [`LeafNameRefusal`] when the confined
    /// label is a device name, and any open error (a planted symlink fails
    /// `O_NOFOLLOW`).
    pub fn create(label: &str) -> io::Result<Self> {
        let name = LeafName::new(&confined_label(label))?;
        Self::create_in(ScratchDir::new(label)?, &name)
    }

    /// Create the file `name` inside the private directory `dir`, taking ownership of it.
    fn create_in(dir: ScratchDir, name: &LeafName) -> io::Result<Self> {
        let path = dir.child(name);
        let file = exclusive_open(&path)?;
        verify_private(&path, &file.metadata()?, EntryKind::File)?;
        dir.verify()?;
        Ok(Self { file, path, dir })
    }

    /// The path of this scratch file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The private directory holding this file.
    #[must_use]
    pub const fn dir(&self) -> &ScratchDir {
        &self.dir
    }

    /// Rewind the retained handle to offset 0.
    ///
    /// # Errors
    /// Propagates any `seek` error.
    pub fn rewind(&mut self) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(0)).map(|_| ())
    }

    /// Read all bytes through the retained handle, from offset 0.
    ///
    /// # Errors
    /// Propagates any seek or read error.
    pub fn read_all(&mut self) -> io::Result<Vec<u8>> {
        self.rewind()?;
        let mut buf = Vec::new();
        self.file.read_to_end(&mut buf)?;
        Ok(buf)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    const ME: Identity = Identity {
        euid: 1000,
        egid: 1000,
    };

    const fn dir(owner: u32, group: u32, mode: u32) -> EntryFacts {
        EntryFacts {
            kind: EntryKind::Directory,
            owner,
            group,
            mode,
        }
    }

    /// A fresh directory tree unique to this test, removed on drop.
    struct Tree(PathBuf);

    impl Tree {
        fn new(tag: &str) -> io::Result<Self> {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let root = test_temp_root().join(format!(
                "ipe-private-scratch-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(root.join("profile").join("temp"))?;
            std::fs::create_dir_all(root.join("shared"))?;
            Ok(Self(root))
        }

        fn profile(&self) -> PathBuf {
            self.0.join("profile")
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn base_verdict_accepts_own_root_and_sticky_bases() {
        assert_eq!(base_verdict(dir(1000, 1000, 0o700), ME), Ok(()));
        assert_eq!(base_verdict(dir(0, 0, 0o755), ME), Ok(()));
        assert_eq!(base_verdict(dir(0, 0, 0o1777), ME), Ok(()));
        assert_eq!(base_verdict(dir(1000, 1000, 0o775), ME), Ok(()));
    }

    #[test]
    fn base_verdict_refuses_foreign_owner() {
        assert_eq!(
            base_verdict(dir(1001, 1001, 0o755), ME),
            Err(ScratchRefusal::ForeignOwner)
        );
    }

    #[test]
    fn base_verdict_refuses_non_sticky_world_or_group_writable() {
        assert_eq!(
            base_verdict(dir(0, 0, 0o777), ME),
            Err(ScratchRefusal::WritableByOthers)
        );
        assert_eq!(
            base_verdict(dir(1000, 1000, 0o777), ME),
            Err(ScratchRefusal::WritableByOthers)
        );
        assert_eq!(
            base_verdict(dir(0, 100, 0o775), ME),
            Err(ScratchRefusal::WritableByOthers)
        );
        assert_eq!(
            base_verdict(dir(1000, 100, 0o775), ME),
            Err(ScratchRefusal::WritableByOthers)
        );
    }

    #[test]
    fn base_verdict_refuses_a_symlink() {
        let link = EntryFacts {
            kind: EntryKind::Other,
            ..dir(1000, 1000, 0o777)
        };
        assert_eq!(base_verdict(link, ME), Err(ScratchRefusal::NotADirectory));
    }

    #[test]
    fn private_verdict_accepts_only_owned_owner_only_entries() {
        assert_eq!(
            private_verdict(dir(1000, 1000, 0o700), EntryKind::Directory, ME),
            Ok(())
        );
        assert_eq!(
            private_verdict(dir(1001, 1000, 0o700), EntryKind::Directory, ME),
            Err(ScratchRefusal::ForeignOwner)
        );
        assert_eq!(
            private_verdict(dir(0, 0, 0o700), EntryKind::Directory, ME),
            Err(ScratchRefusal::ForeignOwner)
        );
        assert_eq!(
            private_verdict(dir(1000, 1000, 0o750), EntryKind::Directory, ME),
            Err(ScratchRefusal::NotPrivate)
        );
        assert_eq!(
            private_verdict(dir(1000, 1000, 0o700), EntryKind::File, ME),
            Err(ScratchRefusal::NotARegularFile)
        );
        let link = EntryFacts {
            kind: EntryKind::Other,
            ..dir(1000, 1000, 0o700)
        };
        assert_eq!(
            private_verdict(link, EntryKind::Directory, ME),
            Err(ScratchRefusal::NotADirectory)
        );
    }

    /// A host-absolute path built from role segments.
    ///
    /// Judged `is_absolute`/`starts_with` under the SAME regime as the
    /// function under test on every host, never a Unix-only `/` literal on
    /// Windows.
    #[cfg(windows)]
    fn host_abs(segments: &[&str]) -> PathBuf {
        let mut p = PathBuf::from(r"C:\");
        p.extend(segments);
        p
    }

    /// See the Windows twin above.
    #[cfg(not(windows))]
    fn host_abs(segments: &[&str]) -> PathBuf {
        let mut p = PathBuf::from("/");
        p.extend(segments);
        p
    }

    #[test]
    fn root_inside_or_equal_to_profile_is_accepted() {
        let profile = host_abs(&["home", "alice"]);
        let nested = host_abs(&["home", "alice", "AppData", "Local", "Temp"]);
        assert_eq!(root_within_profile(&nested, &profile), Ok(()));
        assert_eq!(root_within_profile(&profile, &profile), Ok(()));
    }

    #[test]
    fn root_outside_profile_is_refused() {
        let refused = root_within_profile(&host_abs(&["tmp"]), &host_abs(&["home", "alice"]));
        assert!(matches!(
            refused,
            Err(ScratchRootRefusal::OutsideProfile { .. })
        ));
    }

    #[test]
    fn sibling_sharing_a_name_prefix_is_refused() {
        let refused = root_within_profile(
            &host_abs(&["home", "alice-shared"]),
            &host_abs(&["home", "alice"]),
        );
        assert!(matches!(
            refused,
            Err(ScratchRootRefusal::OutsideProfile { .. })
        ));
    }

    #[test]
    fn parent_dir_escape_is_refused() {
        let profile = host_abs(&["home", "alice"]);
        let mut root = profile.clone();
        root.push("..");
        root.push("bob");
        let refused = root_within_profile(&root, &profile);
        assert!(matches!(
            refused,
            Err(ScratchRootRefusal::OutsideProfile { .. })
        ));
    }

    #[test]
    fn relative_root_is_refused() {
        let refused = root_within_profile(Path::new("alice/temp"), &host_abs(&["home", "alice"]));
        assert!(matches!(
            refused,
            Err(ScratchRootRefusal::OutsideProfile { .. })
        ));
    }

    #[test]
    fn relative_profile_proves_nothing() {
        assert_eq!(
            root_within_profile(Path::new("/home/alice/temp"), Path::new("alice")),
            Err(ScratchRootRefusal::NoProfile)
        );
    }

    #[test]
    fn filesystem_root_profile_proves_nothing() {
        assert_eq!(
            root_within_profile(Path::new("/tmp"), Path::new("/")),
            Err(ScratchRootRefusal::NoProfile)
        );
    }

    #[test]
    fn unset_empty_or_relative_profile_variable_is_refused() -> io::Result<()> {
        let tree = Tree::new("noprofile")?;
        let root = tree.profile().join("temp");
        for profile in [
            None,
            Some(OsStr::new("")),
            Some(OsStr::new("relative/profile")),
        ] {
            assert_eq!(
                verify_root_within_profile(&root, profile),
                Err(ScratchRootRefusal::NoProfile)
            );
        }
        Ok(())
    }

    #[test]
    fn resolved_root_inside_profile_is_accepted() -> io::Result<()> {
        let tree = Tree::new("inside")?;
        let profile = tree.profile();
        let resolved = std::fs::canonicalize(profile.join("temp"))?;
        assert_eq!(
            verify_root_within_profile(&profile.join("temp"), Some(profile.as_os_str())),
            Ok(resolved)
        );
        Ok(())
    }

    /// The accepted root is returned resolved, so creation lands under the
    /// checked location even when the given path runs through a link.
    #[cfg(unix)]
    #[test]
    fn accepted_root_is_returned_resolved() -> io::Result<()> {
        let tree = Tree::new("resolved")?;
        let profile = tree.profile();
        let link = profile.join("temp-link");
        std::os::unix::fs::symlink(profile.join("temp"), &link)?;
        let resolved = verify_root_within_profile(&link, Some(profile.as_os_str()));
        assert_eq!(resolved, Ok(std::fs::canonicalize(profile.join("temp"))?));
        Ok(())
    }

    #[test]
    fn shared_root_outside_profile_is_refused() -> io::Result<()> {
        let tree = Tree::new("shared")?;
        let profile = tree.profile();
        let refused = verify_root_within_profile(&tree.0.join("shared"), Some(profile.as_os_str()));
        assert!(matches!(
            refused,
            Err(ScratchRootRefusal::OutsideProfile { .. })
        ));
        Ok(())
    }

    #[test]
    fn dot_dot_path_leaving_profile_is_refused() -> io::Result<()> {
        let tree = Tree::new("dotdot")?;
        let profile = tree.profile();
        let escaping = profile.join("temp").join("..").join("..").join("shared");
        let refused = verify_root_within_profile(&escaping, Some(profile.as_os_str()));
        assert!(matches!(
            refused,
            Err(ScratchRootRefusal::OutsideProfile { .. })
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn link_inside_profile_pointing_outside_is_refused() -> io::Result<()> {
        let tree = Tree::new("link")?;
        let profile = tree.profile();
        let link = profile.join("temp-link");
        std::os::unix::fs::symlink(tree.0.join("shared"), &link)?;
        let refused = verify_root_within_profile(&link, Some(profile.as_os_str()));
        assert!(matches!(
            refused,
            Err(ScratchRootRefusal::OutsideProfile { .. })
        ));
        Ok(())
    }

    #[test]
    fn missing_root_is_refused() -> io::Result<()> {
        let tree = Tree::new("missing")?;
        let profile = tree.profile();
        let refused =
            verify_root_within_profile(&profile.join("absent"), Some(profile.as_os_str()));
        assert!(matches!(
            refused,
            Err(ScratchRootRefusal::Unresolvable { .. })
        ));
        Ok(())
    }

    #[test]
    fn every_root_refusal_names_the_fix_and_denies_permission() {
        let refusals = [
            ScratchRootRefusal::NoProfile,
            ScratchRootRefusal::Unresolvable {
                path: PathBuf::from("/x"),
                detail: "not found".to_owned(),
            },
            ScratchRootRefusal::OutsideProfile {
                root: PathBuf::from("/tmp"),
                profile: PathBuf::from("/home/alice"),
            },
        ];
        for refusal in refusals {
            assert!(
                refusal.to_string().contains("set TEMP and TMP"),
                "{refusal}"
            );
            assert_eq!(
                io::Error::from(refusal).kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    /// An unavailable CSPRNG fails the creation before any entry is attempted;
    /// no weaker name is ever produced.
    #[test]
    fn entropy_failure_fails_closed() -> io::Result<()> {
        let tree = Tree::new("entropy")?;
        let mut attempts = 0usize;
        let result = create_unique(
            &tree.0,
            "ipe-test",
            NameShape::Plain,
            |_: &mut [u8]| {
                Err(EntropyUnavailable {
                    detail: "test source".to_owned(),
                })
            },
            |p: &Path| {
                attempts += 1;
                exclusive_mkdir(p)
            },
        );
        assert!(result.is_err());
        assert_eq!(attempts, 0);
        assert_eq!(
            std::fs::read_dir(&tree.0)?.count(),
            2,
            "only the fixture tree"
        );
        Ok(())
    }

    /// Fixed entropy collides on every attempt after the first entry, and the
    /// retry loop stops at its bound with `AlreadyExists`.
    #[test]
    fn collisions_stop_at_the_attempt_bound() -> io::Result<()> {
        let tree = Tree::new("collide")?;
        let zeros = |buf: &mut [u8]| {
            buf.fill(0);
            Ok::<(), EntropyUnavailable>(())
        };
        create_unique(
            &tree.0,
            "ipe-test",
            NameShape::Plain,
            zeros,
            exclusive_mkdir,
        )?;
        let mut attempts = 0usize;
        let second = create_unique(&tree.0, "ipe-test", NameShape::Plain, zeros, |p: &Path| {
            attempts += 1;
            exclusive_mkdir(p)
        });
        assert!(second.is_err(), "every name collides");
        let Err(err) = second else {
            return Ok(());
        };
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(err.to_string().contains("unique scratch entry"), "{err}");
        assert_eq!(attempts, MAX_ATTEMPTS);
        Ok(())
    }

    /// A hostile label cannot add a path component, reach an alternate data
    /// stream, or grow the name without bound.
    #[test]
    fn label_is_confined_to_one_bounded_component() -> io::Result<()> {
        let mut fill = |buf: &mut [u8]| {
            buf.fill(0xab);
            Ok::<(), EntropyUnavailable>(())
        };
        let hostile = format!("../../etc/x:y\\z<>|?*\"{}", "a".repeat(500));
        let leaf = scratch_name(&hostile, NameShape::Plain, &mut fill)?;
        let name = leaf.as_str();
        assert!(
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
            "{name}"
        );
        assert!(name.starts_with(".._.._etc_x_y_z______"), "{name}");
        assert!(name.ends_with(&"ab".repeat(ENTROPY_BYTES)), "{name}");
        assert!(name.len() <= MAX_LABEL_CHARS + 2 + 10 + 2 * ENTROPY_BYTES);
        assert_eq!(name.len(), scratch_name_len(&hostile));
        for label in ["", "ipe-pg-relay", "a.b", ".", ".."] {
            let leaf = scratch_name(label, NameShape::Plain, &mut fill)?;
            assert_eq!(leaf.as_str().len(), scratch_name_len(label));
            assert_eq!(Path::new(leaf.as_str()).components().count(), 1);
        }
        assert!(
            scratch_name("store.json", NameShape::Plain, &mut fill)?
                .as_str()
                .starts_with("store.json-"),
            "a `.` in a label is kept"
        );
        Ok(())
    }

    /// A label whose first dot-segment is a device name is refused before any entry exists.
    #[test]
    fn device_stem_label_is_refused_and_creates_nothing() -> io::Result<()> {
        let mut entropy = |buf: &mut [u8]| {
            buf.fill(0xab);
            Ok::<(), EntropyUnavailable>(())
        };
        for label in ["nul.x", "CON.log", "com1.db"] {
            let refused = scratch_name(label, NameShape::Plain, &mut entropy).err();
            assert_eq!(
                refused.as_ref().map(io::Error::kind),
                Some(io::ErrorKind::InvalidInput),
                "{label:?}"
            );
        }
        // Confinement maps `$` to `_`, so no label spells `CONIN$` or `CONOUT$`.
        let confined = scratch_name("conin$.x", NameShape::Plain, &mut entropy)?;
        assert!(confined.as_str().starts_with("conin_.x-"), "{confined:?}");
        let tree = Tree::new("devlabel")?;
        let dir = ScratchDir::new_under(&tree.0, "nul.x").err();
        let file = private_file_under(&tree.0, "nul.x").err();
        for err in [dir, file] {
            assert_eq!(
                err.as_ref().map(io::Error::kind),
                Some(io::ErrorKind::InvalidInput)
            );
        }
        assert_eq!(
            std::fs::read_dir(&tree.0)?.count(),
            2,
            "only the fixture tree"
        );
        Ok(())
    }

    /// A sibling name is hidden and carries the temp suffix, whatever the target is called.
    #[test]
    fn sibling_name_is_hidden_and_suffixed() -> io::Result<()> {
        let mut fill = |buf: &mut [u8]| {
            buf.fill(0xab);
            Ok::<(), EntropyUnavailable>(())
        };
        for label in ["store.json", "con.txt", "", "a/b", "."] {
            let leaf = scratch_name(label, NameShape::HiddenTemp, &mut fill)?;
            let name = leaf.as_str();
            assert!(name.starts_with('.'), "{name}");
            assert!(name.ends_with(TEMP_SIBLING_SUFFIX), "{name}");
        }
        Ok(())
    }

    fn refuse_file(path: &Path, _: &File) -> io::Result<()> {
        assert!(path.is_file(), "the refused file was created");
        Err(refused(path, ScratchRefusal::NotPrivate))
    }

    fn assert_refused(err: Option<&io::Error>) {
        assert_eq!(
            err.map(io::Error::kind),
            Some(io::ErrorKind::PermissionDenied)
        );
    }

    /// A created file that fails verification is removed before the refusal returns.
    #[test]
    fn refused_private_file_is_removed() -> io::Result<()> {
        let root = ScratchDir::new("ipe-scratch-refusefile")?;
        let base = root.path();
        assert_refused(
            private_file_under_with(base, "ipe-kernel", refuse_file)
                .err()
                .as_ref(),
        );
        assert_eq!(std::fs::read_dir(base)?.count(), 0);
        Ok(())
    }

    /// A created directory that fails verification is removed before the refusal returns.
    #[test]
    fn refused_scratch_dir_is_removed() -> io::Result<()> {
        let root = ScratchDir::new("ipe-scratch-refusedir")?;
        let base = root.path();
        let refuse = |p: &Path, (): &()| {
            assert!(p.is_dir(), "the refused directory was created");
            Err(refused(p, ScratchRefusal::NotPrivate))
        };
        assert_refused(
            ScratchDir::new_under_with(base, "ipe-dir", refuse)
                .err()
                .as_ref(),
        );
        assert_eq!(std::fs::read_dir(base)?.count(), 0);
        Ok(())
    }

    /// A created sibling that fails verification is removed, and the target is untouched.
    #[test]
    fn refused_sibling_is_removed_and_target_untouched() -> io::Result<()> {
        let tree = Tree::new("refusesib")?;
        let base = tree.0.join("shared");
        let target = base.join("store.db");
        std::fs::write(&target, b"old")?;
        assert_refused(
            AtomicSibling::create_with(&target, refuse_file)
                .err()
                .as_ref(),
        );
        assert_eq!(std::fs::read_dir(&base)?.count(), 1, "only the target");
        assert_eq!(std::fs::read(&target)?, b"old");
        Ok(())
    }

    #[test]
    fn atomic_sibling_is_hidden_beside_the_target_until_commit() -> io::Result<()> {
        let tree = Tree::new("sibling")?;
        let base = tree.0.join("shared");
        let target = base.join("store.db");
        let a = AtomicSibling::create(&target)?;
        let b = AtomicSibling::create(&target)?;
        assert_ne!(a.tmp_path(), b.tmp_path());
        let canonical = std::fs::canonicalize(&base)?;
        for sib in [&a, &b] {
            let parent = sib
                .tmp_path()
                .parent()
                .map(std::fs::canonicalize)
                .transpose()?;
            assert_eq!(parent.as_deref(), Some(canonical.as_path()));
            let name = sib.tmp_path().file_name().and_then(OsStr::to_str);
            assert!(
                name.is_some_and(|n| n.starts_with(".store.db-")),
                "{name:?}"
            );
            assert!(
                name.is_some_and(|n| n.ends_with(TEMP_SIBLING_SUFFIX)),
                "{name:?}"
            );
        }
        assert!(
            !target.exists(),
            "the target is never created before commit"
        );
        drop((a, b));
        assert_eq!(std::fs::read_dir(&base)?.count(), 0, "drop removes both");
        Ok(())
    }

    #[test]
    fn committed_sibling_replaces_the_target_and_leaves_no_sibling() -> io::Result<()> {
        let tree = Tree::new("commit")?;
        let base = tree.0.join("shared");
        let target = base.join("store.db");
        std::fs::write(&target, b"old")?;
        let mut sib = AtomicSibling::create(&target)?;
        sib.write_all(b"new")?;
        assert_eq!(std::fs::read(&target)?, b"old", "unchanged before commit");
        sib.commit()?;
        assert_eq!(std::fs::read(&target)?, b"new");
        assert_eq!(std::fs::read_dir(&base)?.count(), 1, "only the target");
        Ok(())
    }

    /// A dead writer's pid: above every supported kernel's pid ceiling, so no process holds it.
    const DEAD_PID: u32 = 4_194_305;

    /// An age past [`STALE_SIBLING_AGE`].
    const OLD: std::time::Duration = std::time::Duration::from_hours(2);

    /// A sibling name for `label` carrying the pid spelled `pid` and the entropy spelled `hex`.
    fn sibling_leaf(label: &str, pid: &str, hex: &str) -> String {
        format!(".{label}-{pid}-{hex}{TEMP_SIBLING_SUFFIX}")
    }

    /// `len` copies of `c`, standing in for a name's entropy.
    fn entropy_of(c: char, len: usize) -> String {
        std::iter::repeat_n(c, len).collect()
    }

    /// Create a file at `path` last modified `age` ago.
    fn plant(path: &Path, age: std::time::Duration) -> io::Result<()> {
        let modified = std::time::SystemTime::now()
            .checked_sub(age)
            .ok_or_else(|| io::Error::other("the clock is before the planted age"))?;
        File::create(path)?.set_modified(modified)
    }

    /// Only a name in the exact sibling shape for the label parses, carrying its pid.
    #[test]
    fn sibling_names_parse_only_in_their_exact_shape() {
        let hex = entropy_of('a', 2 * ENTROPY_BYTES);
        assert_eq!(
            parse_sibling_name(&sibling_leaf("store.db", "42", &hex), "store.db"),
            Some(SiblingName { pid: 42 })
        );
        assert_eq!(
            parse_sibling_name(&sibling_leaf("a_b", "7", &hex), "a b"),
            Some(SiblingName { pid: 7 }),
            "the label is confined as a created name's is"
        );
        let refused = [
            sibling_leaf("store.db", "42", &entropy_of('a', 2 * ENTROPY_BYTES - 1)),
            sibling_leaf("store.db", "42", &entropy_of('a', 2 * ENTROPY_BYTES + 1)),
            sibling_leaf("store.db", "42", &entropy_of('A', 2 * ENTROPY_BYTES)),
            sibling_leaf("store.db", "42", &entropy_of('g', 2 * ENTROPY_BYTES)),
            sibling_leaf("store.db", "", &hex),
            sibling_leaf("store.db", "+42", &hex),
            sibling_leaf("store.db", "4x", &hex),
            sibling_leaf("store.db", "99999999999", &hex),
            sibling_leaf("store.db.bak", "42", &hex),
            sibling_leaf("store", "42", &hex),
            format!("store.db-42-{hex}{TEMP_SIBLING_SUFFIX}"),
            format!(".store.db-42-{hex}"),
            format!(".store.db-42-{hex}{TEMP_SIBLING_SUFFIX}.x"),
        ];
        for name in &refused {
            assert_eq!(parse_sibling_name(name, "store.db"), None, "{name}");
        }
        assert_eq!(
            parse_sibling_name(&sibling_leaf("a-5", "42", &hex), "a"),
            None,
            "a longer target's sibling is not a shorter one's"
        );
    }

    /// Only an owned, stale regular file whose writer is gone is a leftover; every other fact keeps it.
    #[test]
    fn only_an_owned_stale_file_of_a_gone_writer_is_a_leftover() {
        let leftover = LeftoverFacts {
            regular_file: true,
            owned: true,
            age: Some(STALE_SIBLING_AGE),
            writer_alive: false,
        };
        assert!(is_leftover(leftover));
        let kept = [
            LeftoverFacts {
                regular_file: false,
                ..leftover
            },
            LeftoverFacts {
                owned: false,
                ..leftover
            },
            LeftoverFacts {
                age: None,
                ..leftover
            },
            LeftoverFacts {
                age: STALE_SIBLING_AGE.checked_sub(std::time::Duration::from_secs(1)),
                ..leftover
            },
            LeftoverFacts {
                writer_alive: true,
                ..leftover
            },
        ];
        for facts in kept {
            assert!(!is_leftover(facts), "{facts:?}");
        }
    }

    /// A stale sibling a gone writer left beside the target is reclaimed by the next replacement.
    #[test]
    fn stale_sibling_of_a_gone_writer_is_reclaimed() -> io::Result<()> {
        let tree = Tree::new("reclaim")?;
        let base = tree.0.join("shared");
        let target = base.join("store.db");
        let stale = base.join(sibling_leaf(
            "store.db",
            &DEAD_PID.to_string(),
            &entropy_of('a', 2 * ENTROPY_BYTES),
        ));
        plant(&stale, OLD)?;
        let sib = AtomicSibling::create(&target)?;
        assert!(!stale.exists(), "the leftover is reclaimed");
        drop(sib);
        assert_eq!(std::fs::read_dir(&base)?.count(), 0);
        Ok(())
    }

    /// A fresh, live, foreign-target or misshapen sibling-like file survives a replacement.
    #[test]
    fn fresh_live_foreign_or_misshapen_siblings_are_kept() -> io::Result<()> {
        let tree = Tree::new("reclaimkeep")?;
        let base = tree.0.join("shared");
        let target = base.join("store.db");
        let dead = DEAD_PID.to_string();
        let own = std::process::id().to_string();
        let full = 2 * ENTROPY_BYTES;
        let kept = [
            (
                sibling_leaf("store.db", &dead, &entropy_of('a', full)),
                std::time::Duration::ZERO,
            ),
            (sibling_leaf("store.db", &own, &entropy_of('b', full)), OLD),
            (sibling_leaf("other.db", &dead, &entropy_of('c', full)), OLD),
            (
                sibling_leaf("store.db", &dead, &entropy_of('d', full - 1)),
                OLD,
            ),
            (sibling_leaf("store.db", &dead, &entropy_of('G', full)), OLD),
            (
                format!(
                    "store.db-{dead}-{}{TEMP_SIBLING_SUFFIX}",
                    entropy_of('f', full)
                ),
                OLD,
            ),
        ];
        for (name, age) in &kept {
            plant(&base.join(name), *age)?;
        }
        drop(AtomicSibling::create(&target)?);
        for (name, _) in &kept {
            assert!(base.join(name).is_file(), "{name} is kept");
        }
        Ok(())
    }

    /// A rename that fails (the target is a non-empty directory) leaves no sibling behind.
    #[test]
    fn failed_commit_leaves_no_sibling() -> io::Result<()> {
        let tree = Tree::new("failcommit")?;
        let base = tree.0.join("shared");
        let target = base.join("store.db");
        std::fs::create_dir(&target)?;
        std::fs::write(target.join("keep"), b"keep")?;
        let mut sib = AtomicSibling::create(&target)?;
        sib.write_all(b"new")?;
        assert!(sib.commit().is_err());
        assert_eq!(std::fs::read_dir(&base)?.count(), 1, "only the target dir");
        assert_eq!(std::fs::read(target.join("keep"))?, b"keep");
        Ok(())
    }

    /// A writer whose sibling was reclaimed underneath it gets `NotFound` from `commit`, never a silent loss.
    #[test]
    fn commit_of_a_reclaimed_sibling_fails_not_found() -> io::Result<()> {
        let tree = Tree::new("reclaimedcommit")?;
        let target = tree.0.join("shared").join("store.db");
        std::fs::write(&target, b"old")?;
        let mut sib = AtomicSibling::create(&target)?;
        sib.write_all(b"new")?;
        std::fs::remove_file(sib.tmp_path())?;
        let committed = sib.commit();
        assert_eq!(
            committed.as_ref().err().map(io::Error::kind),
            Some(io::ErrorKind::NotFound),
            "{committed:?}"
        );
        assert_eq!(std::fs::read(&target)?, b"old", "the target is untouched");
        Ok(())
    }

    /// A sibling modified in the future has an unknown age on disk, so it is kept however dead its writer.
    #[test]
    fn future_modified_sibling_on_disk_is_not_reclaimable() -> io::Result<()> {
        let tree = Tree::new("futuremtime")?;
        let path = tree.0.join("shared").join(sibling_leaf(
            "store.db",
            &DEAD_PID.to_string(),
            &entropy_of('a', 2 * ENTROPY_BYTES),
        ));
        let now = std::time::SystemTime::now();
        let future = now
            .checked_add(OLD)
            .ok_or_else(|| io::Error::other("the clock cannot reach the planted time"))?;
        File::create(&path)?.set_modified(future)?;
        let dead = SiblingName { pid: DEAD_PID };
        let facts = leftover_facts(&std::fs::symlink_metadata(&path)?, dead, now);
        assert_eq!(facts.age, None, "{facts:?}");
        assert!(
            facts.regular_file && facts.owned && !facts.writer_alive,
            "{facts:?}"
        );
        assert!(!is_reclaimable(
            &std::fs::symlink_metadata(&path)?,
            dead,
            now
        ));
        plant(&path, OLD)?;
        assert!(
            is_reclaimable(&std::fs::symlink_metadata(&path)?, dead, now),
            "the same file, stale, is a leftover: the future time alone kept it"
        );
        Ok(())
    }

    /// A reclaimed target sweeps once on construction, and replacing it never scans the directory again.
    #[test]
    fn reclaimed_target_sweeps_once_and_its_writes_never_scan() -> io::Result<()> {
        let tree = Tree::new("reclaimonce")?;
        let base = tree.0.join("shared");
        let target = base.join("store.db");
        let dead = DEAD_PID.to_string();
        let first = base.join(sibling_leaf(
            "store.db",
            &dead,
            &entropy_of('a', 2 * ENTROPY_BYTES),
        ));
        plant(&first, OLD)?;
        let reclaimed = ReclaimedTarget::new(&target);
        assert!(!first.exists(), "construction reclaims the leftover");
        assert_eq!(reclaimed.path(), target.as_path());
        let later = base.join(sibling_leaf(
            "store.db",
            &dead,
            &entropy_of('b', 2 * ENTROPY_BYTES),
        ));
        plant(&later, OLD)?;
        let mut sib = AtomicSibling::create_reclaimed(&reclaimed)?;
        sib.write_all(b"new")?;
        sib.commit()?;
        assert_eq!(std::fs::read(&target)?, b"new");
        assert!(later.is_file(), "a write reads no directory");
        Ok(())
    }

    /// A base too long for the entry is skipped untouched; alone it is refused with [`NoFittingBase`].
    #[test]
    fn fitting_dir_skips_a_base_too_long_for_its_entry() -> io::Result<()> {
        let tree = Tree::new("fitting")?;
        let short = tree.0.join("shared");
        let long = short.join("d".repeat(200));
        let entry = LeafName::new(".s.PGSQL.5432")?;
        let max = std::fs::canonicalize(&short)?
            .as_os_str()
            .len()
            .saturating_add(1)
            .saturating_add(scratch_name_len("ipe-fit"))
            .saturating_add(1)
            .saturating_add(entry.as_str().len());
        let alone =
            ScratchDir::new_fitting_under(std::slice::from_ref(&long), "ipe-fit", &entry, max);
        let refusal = alone.err();
        assert!(
            refusal
                .as_ref()
                .and_then(io::Error::get_ref)
                .is_some_and(<dyn std::error::Error + Send + Sync + 'static>::is::<NoFittingBase>),
            "{refusal:?}"
        );
        assert!(!long.exists(), "a skipped base is never created");
        let dir =
            ScratchDir::new_fitting_under(&[long.clone(), short.clone()], "ipe-fit", &entry, max)?;
        assert_eq!(
            dir.path().parent(),
            Some(std::fs::canonicalize(&short)?.as_path())
        );
        assert!(dir.child(&entry).as_os_str().len() <= max);
        assert!(!long.exists());
        let tight = ScratchDir::new_fitting_under(
            std::slice::from_ref(&short),
            "ipe-fit",
            &entry,
            max.saturating_sub(1),
        );
        assert!(tight.is_err(), "one byte short of the entry is refused");
        Ok(())
    }

    /// A sibling whose parent directory is absent fails and creates nothing.
    #[test]
    fn sibling_of_a_missing_parent_fails_and_creates_nothing() -> io::Result<()> {
        let tree = Tree::new("noparent")?;
        let target = tree.0.join("absent").join("store.db");
        assert!(AtomicSibling::create(&target).is_err());
        assert!(!tree.0.join("absent").exists());
        Ok(())
    }

    /// Every hostile or empty label yields exactly one entry directly under the resolved base.
    #[test]
    fn hostile_label_creates_one_entry_directly_under_the_base() -> io::Result<()> {
        let root = ScratchDir::new("ipe-scratch-label")?;
        let base = std::fs::canonicalize(root.path())?;
        let mut kept = Vec::new();
        for bad in ["", "a/b", "../x", "a\0b", ".", ".."] {
            let sd = ScratchDir::new_under(root.path(), bad)?;
            assert_eq!(sd.path().parent(), Some(base.as_path()), "label {bad:?}");
            kept.push(sd);
        }
        let sf = ScratchFile::create("../x")?;
        assert_eq!(sf.path().parent(), Some(sf.dir().path()));
        assert_eq!(std::fs::read_dir(root.path())?.count(), kept.len());
        Ok(())
    }

    #[test]
    fn unique_entries_differ_and_live_under_base() -> io::Result<()> {
        let tree = Tree::new("unique")?;
        let base = std::fs::canonicalize(&tree.0)?;
        let a = ScratchDir::new_under(&tree.0, "ipe-test")?;
        let b = ScratchDir::new_under(&tree.0, "ipe-test")?;
        let c = ScratchFile::create_in(
            ScratchDir::new_under(&tree.0, "ipe-test")?,
            &LeafName::new("f")?,
        )?;
        assert_ne!(a.path(), b.path());
        for entry in [a.path(), b.path(), c.dir().path()] {
            assert_eq!(entry.parent(), Some(base.as_path()));
        }
        Ok(())
    }

    #[test]
    fn scratch_dir_raii_cleanup() -> io::Result<()> {
        let path = {
            let sd = ScratchDir::new("ipe-scratch-raii")?;
            assert!(sd.path().is_dir());
            sd.path().to_path_buf()
        };
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn scratch_file_lives_in_its_own_private_dir_and_is_removed() -> io::Result<()> {
        let (file_path, dir_path) = {
            let sf = ScratchFile::create("ipe-scratch-file")?;
            assert_eq!(sf.path().parent(), Some(sf.dir().path()));
            sf.dir().verify()?;
            (sf.path().to_path_buf(), sf.dir().path().to_path_buf())
        };
        assert!(!file_path.exists());
        assert!(!dir_path.exists());
        Ok(())
    }

    #[test]
    fn plain_leaf_names_are_accepted() {
        for name in [
            "Main.ipe",
            "console.db",
            "probe",
            ".hidden",
            "a b",
            "CONSOLE",
            "x.CON",
        ] {
            assert_eq!(
                LeafName::new(name).map(|l| l.as_str().to_owned()),
                Ok(name.to_owned())
            );
        }
        assert_eq!(
            LeafName::new(&"a".repeat(MAX_LEAF_BYTES)).map(|l| l.as_str().len()),
            Ok(MAX_LEAF_BYTES)
        );
    }

    /// Every string that could add a component, climb out, reach a stream or a
    /// device, or alias another name is refused before any path is built.
    #[test]
    fn hostile_leaf_names_are_refused() {
        let too_long = "a".repeat(MAX_LEAF_BYTES + 1);
        let cases: [(&str, LeafNameRefusal); 25] = [
            ("", LeafNameRefusal::Empty),
            (too_long.as_str(), LeafNameRefusal::TooLong),
            (".", LeafNameRefusal::DotName),
            ("..", LeafNameRefusal::DotName),
            ("a/b", LeafNameRefusal::ForbiddenChar('/')),
            ("/etc", LeafNameRefusal::ForbiddenChar('/')),
            ("..\\x", LeafNameRefusal::ForbiddenChar('\\')),
            ("file:stream", LeafNameRefusal::ForbiddenChar(':')),
            ("C:", LeafNameRefusal::ForbiddenChar(':')),
            ("a\0b", LeafNameRefusal::ForbiddenChar('\0')),
            ("a\nb", LeafNameRefusal::ForbiddenChar('\n')),
            ("name.", LeafNameRefusal::TrailingDotOrSpace),
            ("name ", LeafNameRefusal::TrailingDotOrSpace),
            ("nul.txt", LeafNameRefusal::ReservedDevice),
            ("Com1", LeafNameRefusal::ReservedDevice),
            ("COM\u{b9}", LeafNameRefusal::ReservedDevice),
            ("lpt\u{b3}.txt", LeafNameRefusal::ReservedDevice),
            ("CONIN$", LeafNameRefusal::ReservedDevice),
            ("conout$.x", LeafNameRefusal::ReservedDevice),
            ("a<b", LeafNameRefusal::ForbiddenChar('<')),
            ("a>b", LeafNameRefusal::ForbiddenChar('>')),
            ("a\"b", LeafNameRefusal::ForbiddenChar('"')),
            ("a|b", LeafNameRefusal::ForbiddenChar('|')),
            ("a?b", LeafNameRefusal::ForbiddenChar('?')),
            ("a*b", LeafNameRefusal::ForbiddenChar('*')),
        ];
        for (name, refusal) in cases {
            assert_eq!(LeafName::new(name), Err(refusal), "{name:?}");
            assert_eq!(io::Error::from(refusal).kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn private_file_under_is_unique_and_directly_under_the_base() -> io::Result<()> {
        let tree = Tree::new("pfile")?;
        let base = std::fs::canonicalize(&tree.0)?;
        let (a, _) = private_file_under(&tree.0, "../x")?;
        let (b, _) = private_file_under(&tree.0, "../x")?;
        assert_ne!(a, b);
        for entry in [&a, &b] {
            assert_eq!(entry.parent(), Some(base.as_path()));
        }
        Ok(())
    }

    #[cfg(unix)]
    mod unix {
        use super::super::*;
        use super::{DEAD_PID, OLD, Tree, entropy_of, plant, sibling_leaf};
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        }

        /// A real file another user owns reads as not owned, and that fact alone keeps it.
        ///
        /// Running as root owns every file, so there the ownership reading is
        /// checked against the entry's uid alone.
        #[test]
        fn a_foreign_owned_file_on_disk_is_not_owned() -> io::Result<()> {
            let meta = std::fs::symlink_metadata("/etc/passwd")?;
            let dead = SiblingName { pid: DEAD_PID };
            let facts = leftover_facts(&meta, dead, std::time::SystemTime::now());
            let euid = rustix::process::geteuid().as_raw();
            assert_eq!(facts.owned, meta.uid() == euid, "{facts:?}");
            if euid != meta.uid() {
                assert!(!facts.owned);
                assert!(!is_leftover(LeftoverFacts {
                    age: Some(OLD),
                    ..facts
                }));
                assert!(
                    is_leftover(LeftoverFacts {
                        age: Some(OLD),
                        owned: true,
                        ..facts
                    }),
                    "ownership alone decides"
                );
            }
            Ok(())
        }

        /// Only a pid the kernel reports as no process is a gone writer.
        #[test]
        fn writer_liveness_keeps_every_unprovable_death() {
            let alive = |pid| writer_may_be_alive(SiblingName { pid });
            assert!(alive(std::process::id()), "this process");
            assert!(alive(1), "the init process");
            assert!(alive(0), "not a process id");
            assert!(alive(u32::MAX), "beyond pid_t");
            assert!(!alive(DEAD_PID), "no such process");
        }

        /// A stale sibling-named directory, or a symlink to a stale file, is never reclaimed.
        #[test]
        fn sibling_named_directory_or_symlink_is_kept() -> io::Result<()> {
            let tree = Tree::new("reclaimkind")?;
            let base = tree.0.join("shared");
            let target = base.join("store.db");
            let dead = DEAD_PID.to_string();
            let full = 2 * ENTROPY_BYTES;
            let dir = base.join(sibling_leaf("store.db", &dead, &entropy_of('a', full)));
            std::fs::create_dir(&dir)?;
            File::open(&dir)?.set_modified(
                std::time::SystemTime::now()
                    .checked_sub(OLD)
                    .ok_or_else(|| io::Error::other("the clock is before the planted age"))?,
            )?;
            let pointee = tree.0.join("pointee");
            plant(&pointee, OLD)?;
            let link = base.join(sibling_leaf("store.db", &dead, &entropy_of('b', full)));
            std::os::unix::fs::symlink(&pointee, &link)?;
            drop(AtomicSibling::create(&target)?);
            assert!(dir.is_dir(), "the directory is kept");
            assert!(
                std::fs::symlink_metadata(&link).is_ok_and(|m| m.file_type().is_symlink()),
                "the link is kept"
            );
            assert!(pointee.is_file(), "the link's target is untouched");
            Ok(())
        }

        #[test]
        fn created_dir_is_0700_and_owned_by_the_effective_user() -> io::Result<()> {
            let sd = ScratchDir::new("ipe-scratch-mode")?;
            let meta = std::fs::symlink_metadata(sd.path())?;
            assert!(meta.file_type().is_dir());
            assert_eq!(meta.mode() & 0o777, 0o700);
            assert_eq!(meta.uid(), rustix::process::geteuid().as_raw());
            Ok(())
        }

        #[test]
        fn created_file_is_0600() -> io::Result<()> {
            let sf = ScratchFile::create("ipe-scratch-fmode")?;
            let meta = std::fs::symlink_metadata(sf.path())?;
            assert!(meta.file_type().is_file());
            assert_eq!(meta.mode() & 0o777, 0o600);
            Ok(())
        }

        /// Entries are owner-only and their exclusive creators refuse an existing name.
        #[test]
        fn unix_entries_are_owner_only() -> io::Result<()> {
            let tree = Tree::new("mode")?;
            let dir = ScratchDir::new_under(&tree.0, "ipe-test")?;
            let file = ScratchFile::create_in(
                ScratchDir::new_under(&tree.0, "ipe-test")?,
                &LeafName::new("f")?,
            )?;
            let mode = |p: &Path| std::fs::metadata(p).map(|m| m.permissions().mode() & 0o777);
            assert_eq!(mode(dir.path())? & 0o077, 0);
            assert_eq!(mode(file.path())? & 0o077, 0);
            assert_eq!(
                exclusive_mkdir(dir.path()).map_err(|e| e.kind()),
                Err(io::ErrorKind::AlreadyExists)
            );
            assert_eq!(
                exclusive_open(file.path()).map(drop).map_err(|e| e.kind()),
                Err(io::ErrorKind::AlreadyExists)
            );
            Ok(())
        }

        #[test]
        fn symlinked_private_dir_is_refused_and_target_untouched() -> io::Result<()> {
            let root = ScratchDir::new("ipe-scratch-symdir")?;
            let target = root.child(&LeafName::new("target")?);
            exclusive_mkdir(&target)?;
            std::fs::write(target.join("canary"), b"canary")?;
            let link = root.child(&LeafName::new("link")?);
            std::os::unix::fs::symlink(&target, &link)?;

            let err = verify_private_dir(&link).err();
            assert_eq!(
                err.as_ref().map(io::Error::kind),
                Some(io::ErrorKind::PermissionDenied)
            );
            assert_eq!(std::fs::read(target.join("canary"))?, b"canary");
            Ok(())
        }

        #[test]
        fn group_or_world_accessible_private_dir_is_refused() -> io::Result<()> {
            let root = ScratchDir::new("ipe-scratch-open")?;
            let open = root.child(&LeafName::new("open")?);
            exclusive_mkdir(&open)?;
            for mode in [0o777, 0o750, 0o705] {
                set_mode(&open, mode)?;
                let err = verify_private_dir(&open).err();
                assert_eq!(
                    err.as_ref().map(io::Error::kind),
                    Some(io::ErrorKind::PermissionDenied),
                    "mode {mode:o} must be refused"
                );
            }
            Ok(())
        }

        #[test]
        fn non_sticky_world_writable_base_is_refused_and_left_empty() -> io::Result<()> {
            let root = ScratchDir::new("ipe-scratch-wbase")?;
            let base = root.child(&LeafName::new("base")?);
            exclusive_mkdir(&base)?;
            set_mode(&base, 0o777)?;
            let err = ScratchDir::new_under(&base, "ipe-under").err();
            assert_eq!(
                err.as_ref().map(io::Error::kind),
                Some(io::ErrorKind::PermissionDenied)
            );
            assert_eq!(std::fs::read_dir(&base)?.count(), 0);
            Ok(())
        }

        #[test]
        fn sticky_world_writable_base_is_accepted() -> io::Result<()> {
            let root = ScratchDir::new("ipe-scratch-sbase")?;
            let base = root.child(&LeafName::new("base")?);
            exclusive_mkdir(&base)?;
            set_mode(&base, 0o1777)?;
            let sd = ScratchDir::new_under(&base, "ipe-under")?;
            sd.verify()?;
            Ok(())
        }

        #[test]
        fn missing_base_components_are_created_private() -> io::Result<()> {
            let root = ScratchDir::new("ipe-scratch-mkbase")?;
            let outer = root.child(&LeafName::new("outer")?);
            let base = outer.join("inner");
            let sd = ScratchDir::new_under(&base, "ipe-under")?;
            sd.verify()?;
            for created in [&outer, &base] {
                let mode = std::fs::symlink_metadata(created)?.permissions().mode();
                assert_eq!(
                    mode & 0o7777,
                    0o700,
                    "{} must be created 0700",
                    created.display()
                );
            }
            Ok(())
        }

        #[test]
        fn base_reached_through_a_symlink_is_canonicalised() -> io::Result<()> {
            let root = ScratchDir::new("ipe-scratch-lbase")?;
            let real = root.child(&LeafName::new("real")?);
            exclusive_mkdir(&real)?;
            let link = root.child(&LeafName::new("link")?);
            std::os::unix::fs::symlink(&real, &link)?;
            let sd = ScratchDir::new_under(&link, "ipe-under")?;
            assert_eq!(
                sd.path().parent(),
                Some(std::fs::canonicalize(&real)?.as_path())
            );
            Ok(())
        }

        #[test]
        fn preplanted_symlink_at_the_file_path_is_refused_and_target_untouched() -> io::Result<()> {
            let root = ScratchDir::new("ipe-scratch-symfile")?;
            let canary = root.child(&LeafName::new("canary")?);
            std::fs::write(&canary, b"canary")?;
            let dir = ScratchDir::new_under(root.path(), "ipe-private")?;
            std::os::unix::fs::symlink(&canary, dir.child(&LeafName::new("tag")?))?;

            let err = ScratchFile::create_in(dir, &LeafName::new("tag")?).err();
            assert!(err.is_some(), "a planted symlink must not be opened");
            assert_eq!(std::fs::read(&canary)?, b"canary");
            Ok(())
        }

        #[test]
        fn private_file_under_is_0600_and_refuses_an_untrusted_base() -> io::Result<()> {
            let root = ScratchDir::new("ipe-scratch-pfile")?;
            let (path, _) = private_file_under(root.path(), "ipe-kernel")?;
            let meta = std::fs::symlink_metadata(&path)?;
            assert!(meta.file_type().is_file());
            assert_eq!(meta.mode() & 0o777, 0o600);

            let open = root.child(&LeafName::new("open")?);
            exclusive_mkdir(&open)?;
            set_mode(&open, 0o777)?;
            let err = private_file_under(&open, "ipe-kernel").err();
            assert_eq!(
                err.as_ref().map(io::Error::kind),
                Some(io::ErrorKind::PermissionDenied)
            );
            assert_eq!(std::fs::read_dir(&open)?.count(), 0);
            Ok(())
        }

        /// A sibling is 0600, and its commit replaces a symlinked target's link, never the link's target.
        #[test]
        fn atomic_sibling_is_0600_and_never_writes_through_a_link() -> io::Result<()> {
            let root = ScratchDir::new("ipe-scratch-sib")?;
            let canary = root.child(&LeafName::new("canary")?);
            std::fs::write(&canary, b"canary")?;
            let target = root.child(&LeafName::new("store.db")?);
            std::os::unix::fs::symlink(&canary, &target)?;

            let mut sib = AtomicSibling::create(&target)?;
            let meta = std::fs::symlink_metadata(sib.tmp_path())?;
            assert!(meta.file_type().is_file());
            assert_eq!(meta.mode() & 0o777, 0o600);
            sib.write_all(b"new")?;
            sib.commit()?;

            assert!(std::fs::symlink_metadata(&target)?.file_type().is_file());
            assert_eq!(std::fs::read(&target)?, b"new");
            assert_eq!(std::fs::read(&canary)?, b"canary");
            Ok(())
        }

        #[test]
        fn dangling_symlink_at_the_file_path_creates_nothing() -> io::Result<()> {
            let root = ScratchDir::new("ipe-scratch-dangle")?;
            let victim = root.child(&LeafName::new("victim")?);
            let dir = ScratchDir::new_under(root.path(), "ipe-private")?;
            std::os::unix::fs::symlink(&victim, dir.child(&LeafName::new("tag")?))?;

            assert!(ScratchFile::create_in(dir, &LeafName::new("tag")?).is_err());
            assert!(std::fs::symlink_metadata(&victim).is_err());
            Ok(())
        }
    }
}
