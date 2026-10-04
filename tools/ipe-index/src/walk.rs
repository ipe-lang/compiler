//! The repository walk: which files the index reads, parsed once at the git boundary.
//!
//! Every indexed path names a regular file by its exact bytes. Git listings are
//! read NUL-separated (`-z`), so a newline inside a name never splits one path
//! into two; a name that is not UTF-8 is refused, never lossily decoded. An
//! entry git records as a symbolic link (mode 120000) or a submodule commit
//! (mode 160000) is refused from its mode, and every listed path is then
//! checked on disk without following links (`symlink_metadata` on the leaf and
//! on each directory above it), so a working-tree link, tracked or untracked,
//! never leads a read outside the repository. Reading goes through
//! [`read_indexed`] only: it re-parses the name, repeats the no-follow check,
//! refuses a handle whose file is not the one that check saw, and reads at
//! most [`MAX_FILE_BYTES`] from the held handle.

use crate::model::{Lang, RepoTag, Role, lang_of, role_of};
use crate::repo_set::DeclaredRoot;
use anyhow::{Result, bail};
use std::fmt::{self, Write as _};
use std::fs::File;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024; // 2 MB cap (anti-OOM)

pub struct Tracked {
    pub path: String,
    pub lang: Lang,
    #[allow(dead_code)]
    pub role: Role,
}

impl Tracked {
    fn at(path: String) -> Self {
        Self {
            lang: lang_of(&path),
            role: role_of(&path),
            path,
        }
    }
}

/// Build-output / VCS / generated path segments the index must NEVER touch, even
/// when `.gitignore` hygiene is imperfect. The `--others` walk only respects
/// `.gitignore`, so a crate that forgot to ignore its `target/` would otherwise
/// flood the index with build artifacts (deps/fingerprints/rlibs) — defeating
/// the bounded-memory guarantee that is this tool's whole reason to exist.
/// Matched as a WHOLE path segment and case-sensitively, so legitimate source
/// dirs are never hit.
const SKIP_SEGMENTS: &[&str] = &[
    "target",
    "node_modules",
    "dist-newstyle",
    "ipe-out",
    ".ipe-index",
    ".git",
    // Cargo build-directory internals. These appear even when a build ran with
    // a non-`target/` output dir (a bare `debug/`), which the `target` segment
    // above would miss; both names are cargo-only and never a source directory.
    ".fingerprint",
    "incremental",
];

pub(crate) fn is_indexable(path: &str) -> bool {
    !path.split('/').any(|seg| SKIP_SEGMENTS.contains(&seg))
}

/// Which git listing a [`WalkError`] was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listing {
    /// `git ls-files -z -s` (tracked entries with their index mode).
    Staged,
    /// `git ls-files -z --others --exclude-standard` (untracked, not ignored).
    Untracked,
    /// `git diff --raw -z --no-renames` (changes between two commits).
    Diff,
}

impl fmt::Display for Listing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Staged => "git ls-files -z -s",
            Self::Untracked => "git ls-files -z --others",
            Self::Diff => "git diff --raw -z",
        })
    }
}

/// A git listing whose framing is not the documented one, so no entry of it is trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkError {
    /// Record `record` (0-based) does not have the shape its listing documents.
    MalformedRecord { listing: Listing, record: usize },
    /// The listing does not end with the NUL that terminates its last record.
    Unterminated { listing: Listing },
    /// A change header at `record` has no path record after it.
    MissingPath { listing: Listing, record: usize },
}

impl fmt::Display for WalkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedRecord { listing, record } => {
                write!(f, "`{listing}` record {record} is malformed")
            }
            Self::Unterminated { listing } => {
                write!(f, "`{listing}` output does not end with a NUL")
            }
            Self::MissingPath { listing, record } => {
                write!(f, "`{listing}` record {record} has no path after it")
            }
        }
    }
}

impl std::error::Error for WalkError {}

/// Why one listed entry is left out of the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The name is not UTF-8; `offset` is the index of its first invalid byte.
    NonUtf8Name { offset: usize },
    /// The name is not a plain repository-relative path.
    ///
    /// Empty, absolute, or holding a `.`, `..` or empty segment.
    NotRepoRelative { path: String },
    /// Git records the entry as a symbolic link (mode 120000).
    SymlinkEntry { path: String },
    /// Git records the entry as a submodule commit (mode 160000).
    GitlinkEntry { path: String },
    /// Git records a mode that names no regular file.
    UnknownMode { path: String, mode: String },
    /// `--others` lists an untracked nested repository as `<path>/`.
    NestedRepository { path: String },
    /// On disk the path is not a regular file reached through real directories.
    NotRegularOnDisk { path: String, found: DiskRefusal },
}

/// What the no-follow disk check found instead of a regular file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiskRefusal {
    /// The path itself is a symbolic link.
    Symlink,
    /// A directory above the path, named here, is a symbolic link or not a directory.
    LinkedAncestor { ancestor: String },
    /// The path is a directory, device, socket, or FIFO.
    NotAFile,
    /// The metadata read failed for a reason other than absence.
    Unreadable { kind: io::ErrorKind },
    /// A directory above the path sits where the declared root `root` was
    /// parsed, but it is no longer that directory.
    RootMoved { root: String },
}

/// Renders untrusted text injectively in printable ASCII.
///
/// `\` becomes `\\` and every char that is neither a space nor ASCII graphic
/// becomes `\u{..}`, so a name can never move the terminal cursor or forge a
/// line.
pub fn shown(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ' ' => out.push(' '),
            c if c.is_ascii_graphic() => out.push(c),
            c => {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
        }
    }
    out
}

impl Refusal {
    /// The parsed repository-relative path the entry names, if it names one.
    fn listed_path(&self) -> Option<&str> {
        match self {
            Self::SymlinkEntry { path }
            | Self::GitlinkEntry { path }
            | Self::UnknownMode { path, .. }
            | Self::NestedRepository { path } => Some(path.as_str()),
            Self::NonUtf8Name { .. }
            | Self::NotRepoRelative { .. }
            | Self::NotRegularOnDisk { .. } => None,
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonUtf8Name { offset } => write!(
                f,
                "a name that is not UTF-8 (first invalid byte at offset {offset})"
            ),
            Self::NotRepoRelative { path } => {
                write!(f, "{}: not a repository-relative path", shown(path))
            }
            Self::SymlinkEntry { path } => {
                write!(f, "{}: tracked as a symbolic link", shown(path))
            }
            Self::GitlinkEntry { path } => {
                write!(f, "{}: tracked as a submodule commit", shown(path))
            }
            Self::UnknownMode { path, mode } => {
                write!(f, "{}: tracked with mode {}", shown(path), shown(mode))
            }
            Self::NestedRepository { path } => {
                write!(f, "{}/: an untracked nested repository", shown(path))
            }
            Self::NotRegularOnDisk { path, found } => {
                write!(f, "{}: {}", shown(path), disk_why(found))
            }
        }
    }
}

/// What a [`DiskRefusal`] found, as a predicate on the refused path.
fn disk_why(found: &DiskRefusal) -> String {
    match found {
        DiskRefusal::Symlink => "is a symbolic link".to_string(),
        DiskRefusal::LinkedAncestor { ancestor } => {
            format!("sits under {}, not a real directory", shown(ancestor))
        }
        DiskRefusal::NotAFile => "is not a regular file".to_string(),
        DiskRefusal::Unreadable { kind } => format!("cannot be inspected ({kind})"),
        DiskRefusal::RootMoved { root } => format!(
            "sits where the declared root `{}` was, which changed after the root set was parsed",
            shown(root)
        ),
    }
}

/// The index mode git records for an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    /// 100644 or 100755.
    File,
    /// 120000.
    Symlink,
    /// 160000.
    Gitlink,
    /// Any other six-digit octal mode (`000000` for an absent side of a change).
    Unknown(String),
}

impl Mode {
    /// Parses a six-digit octal mode field, or `None` when the field is not one.
    fn parse(field: &[u8]) -> Option<Self> {
        if field.len() != 6 || !field.iter().all(|b| (b'0'..=b'7').contains(b)) {
            return None;
        }
        Some(match field {
            b"100644" | b"100755" => Self::File,
            b"120000" => Self::Symlink,
            b"160000" => Self::Gitlink,
            other => Self::Unknown(other.iter().map(|&b| char::from(b)).collect()),
        })
    }

    /// The refusal this mode earns for `path`, or `None` for a regular file.
    fn refusal(&self, path: &str) -> Option<Refusal> {
        let path = path.to_string();
        match self {
            Self::File => None,
            Self::Symlink => Some(Refusal::SymlinkEntry { path }),
            Self::Gitlink => Some(Refusal::GitlinkEntry { path }),
            Self::Unknown(mode) => Some(Refusal::UnknownMode {
                path,
                mode: mode.clone(),
            }),
        }
    }
}

/// The NUL-terminated records of a `-z` listing; an empty listing has none.
fn records(out: &[u8], listing: Listing) -> Result<Vec<&[u8]>, WalkError> {
    if out.is_empty() {
        return Ok(Vec::new());
    }
    let Some(body) = out.strip_suffix(b"\0") else {
        return Err(WalkError::Unterminated { listing });
    };
    Ok(body.split(|&b| b == 0).collect())
}

/// A listed name as a repository-relative UTF-8 path, or the refusal it earns.
fn path_of(name: &[u8]) -> Result<String, Refusal> {
    let path = std::str::from_utf8(name).map_err(|e| Refusal::NonUtf8Name {
        offset: e.valid_up_to(),
    })?;
    let relative = !path.is_empty()
        && !path.starts_with('/')
        && path.split('/').all(|seg| !matches!(seg, "" | "." | ".."));
    if relative {
        Ok(path.to_string())
    } else {
        Err(Refusal::NotRepoRelative {
            path: path.to_string(),
        })
    }
}

/// A plain repository-relative UTF-8 path, parsed once.
///
/// Non-empty, not absolute, and no empty, `.` or `..` segment, so it never
/// climbs out of the root it is joined to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelPath(String);

impl RelPath {
    pub fn parse(name: &str) -> Result<Self, Refusal> {
        path_of(name.as_bytes()).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One listed path the name and mode checks admitted, or the refusal it earned.
pub type Listed = Result<String, Refusal>;

/// Parses `git ls-files -z -s`: `<mode> <object> <stage>\t<name>\0` per record.
///
/// The stages of an unmerged path are one entry, refused when any stage is not
/// a regular file. Paths under a build-output segment are dropped silently.
pub fn parse_staged(out: &[u8]) -> Result<Vec<Listed>, WalkError> {
    let listing = Listing::Staged;
    let mut entries: Vec<(&[u8], Mode)> = Vec::new();
    for (record, rec) in records(out, listing)?.into_iter().enumerate() {
        let malformed = WalkError::MalformedRecord { listing, record };
        let Some(tab) = rec.iter().position(|&b| b == b'\t') else {
            return Err(malformed);
        };
        let (header, name) = rec.split_at(tab);
        let name = name.get(1..).unwrap_or_default();
        let mut fields = header.split(|&b| b == b' ');
        let (Some(mode), Some(object), Some(stage), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(malformed);
        };
        let Some(mode) = Mode::parse(mode) else {
            return Err(malformed);
        };
        if object.is_empty()
            || !object.iter().all(u8::is_ascii_hexdigit)
            || !matches!(stage, b"0" | b"1" | b"2" | b"3")
            || name.is_empty()
        {
            return Err(malformed);
        }
        let same_path = entries.last().is_some_and(|(last, _)| *last == name);
        if !same_path {
            entries.push((name, mode));
        } else if let Some((_, kept)) = entries.last_mut()
            && *kept == Mode::File
        {
            *kept = mode;
        }
    }
    Ok(entries
        .into_iter()
        .filter_map(|(name, mode)| match path_of(name) {
            Err(refusal) => Some(Err(refusal)),
            Ok(path) if !is_indexable(&path) => None,
            Ok(path) => Some(mode.refusal(&path).map_or(Ok(path), Err)),
        })
        .collect())
}

/// Parses `git ls-files -z --others`: one `<name>\0` per record.
pub fn parse_untracked(out: &[u8]) -> Result<Vec<Listed>, WalkError> {
    let listing = Listing::Untracked;
    let mut listed = Vec::new();
    for (record, name) in records(out, listing)?.into_iter().enumerate() {
        if name.is_empty() {
            return Err(WalkError::MalformedRecord { listing, record });
        }
        if let Some(dir) = name.strip_suffix(b"/")
            && let Ok(path) = path_of(dir)
        {
            if is_indexable(&path) {
                listed.push(Err(Refusal::NestedRepository { path }));
            }
            continue;
        }
        match path_of(name) {
            Err(refusal) => listed.push(Err(refusal)),
            Ok(path) if !is_indexable(&path) => {}
            Ok(path) => listed.push(Ok(path)),
        }
    }
    Ok(listed)
}

/// The identity of a file: device and inode on unix.
///
/// Off unix every file compares equal, so the handle check in [`read_held`]
/// is the no-follow check alone there, and a [`RepoSet`](crate::repo_set::RepoSet) refuses a second root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl FileId {
    #[cfg(unix)]
    pub fn of(md: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            dev: md.dev(),
            ino: md.ino(),
        }
    }

    #[cfg(not(unix))]
    pub fn of(_md: &std::fs::Metadata) -> Self {
        Self {}
    }
}

/// What the no-follow disk check found at a listed path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OnDisk {
    /// A regular file reached through real directories only.
    Regular(FileId),
    /// Nothing at the path (deleted in the working tree).
    Absent,
    /// A directory above the path is the declared root this tag names, which owns it.
    Claimed(RepoTag),
    /// Something other than a regular file.
    Refused(DiskRefusal),
}

/// The refusal for a path at `inner`'s declared place that is no longer `inner`.
fn moved(inner: &DeclaredRoot) -> OnDisk {
    OnDisk::Refused(DiskRefusal::RootMoved {
        root: inner.tag().as_str().to_string(),
    })
}

/// Classifies `root/rel` without following any link, at the leaf or above it.
///
/// A directory above the leaf whose identity is one of `claimed` (the roots
/// declared directly inside `root`) makes the path [`OnDisk::Claimed`]: it
/// belongs to that deeper root alone. A directory at a claimed root's prefix
/// that is not that root is [`DiskRefusal::RootMoved`].
fn on_disk(root: &Path, rel: &str, claimed: &[&DeclaredRoot]) -> OnDisk {
    let mut at = PathBuf::from(root);
    let (dirs, leaf) = rel.rsplit_once('/').unwrap_or(("", rel));
    let mut ancestor = String::new();
    for seg in dirs.split('/').filter(|s| !s.is_empty()) {
        at.push(seg);
        if !ancestor.is_empty() {
            ancestor.push('/');
        }
        ancestor.push_str(seg);
        let declared_here = claimed
            .iter()
            .find(|c| c.within().is_some_and(|w| w.prefix().as_str() == ancestor));
        let found = std::fs::symlink_metadata(&at);
        if let Ok(md) = &found
            && md.file_type().is_dir()
        {
            let id = FileId::of(md);
            if let Some(owner) = claimed.iter().find(|c| c.id() == id) {
                return OnDisk::Claimed(owner.tag().clone());
            }
            if let Some(inner) = declared_here {
                return moved(inner);
            }
            continue;
        }
        if let Some(inner) = declared_here {
            return moved(inner);
        }
        match found {
            Ok(_) => return OnDisk::Refused(DiskRefusal::LinkedAncestor { ancestor }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return OnDisk::Absent,
            Err(e) => return OnDisk::Refused(DiskRefusal::Unreadable { kind: e.kind() }),
        }
    }
    at.push(leaf);
    match std::fs::symlink_metadata(&at) {
        Ok(md) if md.file_type().is_file() => OnDisk::Regular(FileId::of(&md)),
        Ok(md) if md.file_type().is_symlink() => OnDisk::Refused(DiskRefusal::Symlink),
        Ok(_) => OnDisk::Refused(DiskRefusal::NotAFile),
        Err(e) if e.kind() == io::ErrorKind::NotFound => OnDisk::Absent,
        Err(e) => OnDisk::Refused(DiskRefusal::Unreadable { kind: e.kind() }),
    }
}

/// A pre-configured `git -C <repo>` invocation shared by every git plumbing
/// call below. Centralising it lets us harden all call sites at once:
///   * `core.quotePath=false` — emit non-ASCII paths literally (UTF-8) instead
///     of C-quoting them; the `-z` listings never quote, and the setting keeps
///     every other output literal too.
///   * no inherited `GIT_DIR` / `GIT_WORK_TREE` / `GIT_INDEX_FILE` /
///     `GIT_COMMON_DIR` — a git hook (the recommended `post-commit` refresh)
///     runs with them set, and they would list another repository or index
///     than the one `repo` names.
///   * `GIT_TERMINAL_PROMPT=0` + a null stdin — a credential helper / askpass /
///     pager that tries to prompt would otherwise block on stdin forever and
///     wedge the indexer; both make any such prompt fail fast instead.
pub(crate) fn git_command(repo: &str) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-c")
        .arg("core.quotePath=false")
        .arg("-C")
        .arg(repo)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_COMMON_DIR")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null());
    cmd
}

/// Runs `git <args>` in `repo`; a failed run is an error, never empty output.
pub(crate) fn git_stdout(repo: &str, args: &[&str]) -> Result<Vec<u8>> {
    let out = git_command(repo).args(args).output()?;
    if !out.status.success() {
        bail!(
            "git {} failed in {}: {}",
            args.first().copied().unwrap_or_default(),
            shown(repo),
            shown(String::from_utf8_lossy(&out.stderr).trim())
        );
    }
    Ok(out.stdout)
}

/// Reports each refusal on stderr; the refused entry is not indexed.
fn report(refused: &[Refusal]) {
    for refusal in refused {
        eprintln!("ipe-index: not indexing {refusal}");
    }
}

/// Whether `root/rel` is the directory of one of the `claimed` inner roots.
fn is_claimed_dir(root: &Path, rel: &str, claimed: &[&DeclaredRoot]) -> bool {
    std::fs::symlink_metadata(root.join(rel))
        .is_ok_and(|md| md.is_dir() && claimed.iter().any(|c| c.id() == FileId::of(&md)))
}

/// Whether a refused entry is, or sits under, one of the `claimed` inner roots.
///
/// Such an entry belongs to that root, whose own walk refuses or skips it, so
/// the outer walk neither indexes nor reports it.
fn refused_elsewhere(root: &Path, refusal: &Refusal, claimed: &[&DeclaredRoot]) -> bool {
    !claimed.is_empty()
        && refusal.listed_path().is_some_and(|path| {
            is_claimed_dir(root, path, claimed)
                || matches!(on_disk(root, path, claimed), OnDisk::Claimed(_))
        })
}

/// Splits listed paths into regular files on disk and refusals.
///
/// Absent paths are dropped, and so is every path a `claimed` inner root owns:
/// it is indexed under that root's tag alone.
fn admit(
    root: &Path,
    listed: Vec<Listed>,
    claimed: &[&DeclaredRoot],
) -> (Vec<Tracked>, Vec<Refusal>) {
    let mut files = Vec::new();
    let mut refused = Vec::new();
    for entry in listed {
        match entry {
            Err(refusal) if refused_elsewhere(root, &refusal, claimed) => {}
            Err(refusal) => refused.push(refusal),
            Ok(path) => match on_disk(root, &path, claimed) {
                OnDisk::Regular(_) => files.push(Tracked::at(path)),
                OnDisk::Absent | OnDisk::Claimed(_) => {}
                OnDisk::Refused(found) => refused.push(Refusal::NotRegularOnDisk { path, found }),
            },
        }
    }
    (files, refused)
}

/// Fails the run when the walk met a declared root that changed after parsing.
///
/// Which root owns a path is no longer known then, so no path is stored.
fn refuse_moved_roots(refused: &[Refusal]) -> Result<()> {
    for refusal in refused {
        if let Refusal::NotRegularOnDisk {
            found: DiskRefusal::RootMoved { .. },
            ..
        } = refusal
        {
            bail!("ipe-index: {refusal}; re-run with the current roots");
        }
    }
    Ok(())
}

/// Refuses a walk of `root` once its directory is not the one the set parsed.
pub(crate) fn verify_root(root: &DeclaredRoot) -> Result<()> {
    let same = std::fs::symlink_metadata(root.root())
        .is_ok_and(|md| md.is_dir() && FileId::of(&md) == root.id());
    if !same {
        bail!(
            "ipe-index: the declared root `{}` changed after the root set was parsed; re-run with the current roots",
            shown(root.tag().as_str())
        );
    }
    Ok(())
}

/// The admitted files and the refusals of one walk of `root`.
fn listing(root: &DeclaredRoot, claimed: &[&DeclaredRoot]) -> Result<(Vec<Tracked>, Vec<Refusal>)> {
    verify_root(root)?;
    let repo = root.root_str();
    let mut listed = parse_staged(&git_stdout(repo, &["ls-files", "-z", "-s"])?)?;
    listed.extend(parse_untracked(&git_stdout(
        repo,
        &["ls-files", "-z", "--others", "--exclude-standard"],
    )?)?);
    let (files, refused) = admit(root.root(), listed, claimed);
    refuse_moved_roots(&refused)?;
    Ok((files, refused))
}

/// All git-tracked AND untracked-but-not-ignored regular files in `root`.
///
/// Respects .gitignore via `--exclude-standard`, so generated dirs stay
/// excluded — bounded, no OOM risk. Including untracked-non-ignored files
/// keeps the index faithful to the working tree: a newly-added, not-yet-staged
/// source file is part of the repo's current state, and omitting it produces
/// false "missing" results. `--others` (untracked) is disjoint from the
/// tracked listing, so the two concatenate without dedup. Symbolic links,
/// submodules, non-UTF-8 names and anything that is not a regular file on disk
/// are refused (reported on stderr, never indexed). Paths under a `claimed`
/// root (one declared directly inside `root`) are skipped: that root owns them.
pub fn tracked(root: &DeclaredRoot, claimed: &[&DeclaredRoot]) -> Result<Vec<Tracked>> {
    let (files, refused) = listing(root, claimed)?;
    report(&refused);
    Ok(files)
}

/// One change record of `git diff --raw -z --no-renames`, before the disk check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The path holds a regular file at the new commit.
    Upsert(String),
    /// The path holds no indexable file at the new commit.
    ///
    /// Deleted, or now a link or a submodule; its stale units leave the index.
    Delete(String),
    /// The entry is refused; a refused name is never stored, so it has nothing to delete.
    Refused(Refusal),
}

/// Parses `git diff --raw -z --no-renames`.
///
/// Each change is a `:<old> <new> <osha> <nsha> <status>` record followed by
/// one `<name>` record; renames and copies never appear (`--no-renames`).
pub fn parse_diff(out: &[u8]) -> Result<Vec<Change>, WalkError> {
    let listing = Listing::Diff;
    let mut recs = records(out, listing)?.into_iter().enumerate();
    let mut changes = Vec::new();
    while let Some((record, header)) = recs.next() {
        let malformed = WalkError::MalformedRecord { listing, record };
        let Some(header) = header.strip_prefix(b":") else {
            return Err(malformed);
        };
        let mut fields = header.split(|&b| b == b' ');
        let (Some(_old), Some(new), Some(_osha), Some(_nsha), Some(status), None) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Err(malformed);
        };
        let Some(new) = Mode::parse(new) else {
            return Err(malformed);
        };
        let deleted = match status {
            b"D" => true,
            b"A" | b"M" | b"T" => false,
            _ => return Err(malformed),
        };
        let Some((_, name)) = recs.next() else {
            return Err(WalkError::MissingPath { listing, record });
        };
        if name.is_empty() {
            return Err(malformed);
        }
        let path = match path_of(name) {
            Err(refusal) => {
                changes.push(Change::Refused(refusal));
                continue;
            }
            Ok(path) if !is_indexable(&path) => continue,
            Ok(path) => path,
        };
        if deleted {
            changes.push(Change::Delete(path));
            continue;
        }
        match new.refusal(&path) {
            None => changes.push(Change::Upsert(path)),
            Some(refusal) => {
                changes.push(Change::Refused(refusal));
                changes.push(Change::Delete(path));
            }
        }
    }
    Ok(changes)
}

/// Changed/added + deleted paths between `since` sha and HEAD (for incremental update).
///
/// A path that is no longer a regular file (a link or submodule at HEAD, or
/// not a regular file on disk) is a delete, so its stale units leave the index.
/// The diff is `--relative`: only paths under `root` are listed, relative to
/// it, even when `root` is a subdirectory of its work tree. A path under a
/// `claimed` root is neither upserted nor deleted here: that root owns it.
pub fn changed(
    root: &DeclaredRoot,
    since: &str,
    claimed: &[&DeclaredRoot],
) -> Result<(Vec<Tracked>, Vec<String>)> {
    // `since` is interpolated into a positional commit-range token
    // (`{since}..HEAD`). Reject anything that git could parse as an option
    // (leading '-', e.g. `--output=…`) or that carries path/shell-hostile
    // bytes, so a crafted ref can't smuggle options or write arbitrary files.
    if since.is_empty()
        || since.starts_with('-')
        || !since
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
    {
        bail!("refusing unsafe git since-ref: {}", shown(since));
    }
    // `--no-renames` decomposes renames into a `D oldpath` + `A newpath` pair,
    // so every change record carries exactly one path.
    let range = format!("{since}..HEAD");
    // `--` ends the revisions, so a range git cannot resolve is an error,
    // never a pathspec naming a file called `<since>..HEAD`.
    verify_root(root)?;
    let out = git_stdout(
        root.root_str(),
        &[
            "diff",
            "--raw",
            "-z",
            "--no-renames",
            "--relative",
            &range,
            "--",
        ],
    )?;
    let (upserts, deletes, refused) = classify(root.root(), parse_diff(&out)?, claimed);
    report(&refused);
    refuse_moved_roots(&refused)?;
    Ok((upserts, deletes))
}

/// Sorts the changes of one diff of `dir` into upserts, deletes and refusals.
///
/// A change at or under a `claimed` root is dropped, refusal included: that
/// root's own diff owns it.
fn classify(
    dir: &Path,
    changes: Vec<Change>,
    claimed: &[&DeclaredRoot],
) -> (Vec<Tracked>, Vec<String>, Vec<Refusal>) {
    let mut upserts = Vec::new();
    let mut deletes = Vec::new();
    let mut refused = Vec::new();
    for change in changes {
        match change {
            Change::Delete(path) => match on_disk(dir, &path, claimed) {
                OnDisk::Claimed(_) => {}
                OnDisk::Refused(found @ DiskRefusal::RootMoved { .. }) => {
                    refused.push(Refusal::NotRegularOnDisk { path, found });
                }
                OnDisk::Regular(_) | OnDisk::Absent | OnDisk::Refused(_) => deletes.push(path),
            },
            Change::Refused(refusal) if refused_elsewhere(dir, &refusal, claimed) => {}
            Change::Refused(refusal) => refused.push(refusal),
            Change::Upsert(path) => match on_disk(dir, &path, claimed) {
                OnDisk::Regular(_) => upserts.push(Tracked::at(path)),
                OnDisk::Absent => deletes.push(path),
                OnDisk::Claimed(_) => {}
                OnDisk::Refused(found @ DiskRefusal::RootMoved { .. }) => {
                    refused.push(Refusal::NotRegularOnDisk { path, found });
                }
                OnDisk::Refused(found) => {
                    refused.push(Refusal::NotRegularOnDisk {
                        path: path.clone(),
                        found,
                    });
                    deletes.push(path);
                }
            },
        }
    }
    (upserts, deletes, refused)
}

/// Why [`read_indexed`] returned no text for a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadRefusal {
    /// The name is not a plain repository-relative UTF-8 path.
    Name(Refusal),
    /// Nothing at the path.
    Absent,
    /// The no-follow check found something other than a regular file.
    NotRegular(DiskRefusal),
    /// The opened handle names another file than the no-follow check saw.
    Replaced,
    /// A directory above the path is the declared root this tag names, which owns it.
    Claimed(RepoTag),
    /// The file holds more than [`MAX_FILE_BYTES`]; `at_least` bytes were seen.
    TooLarge { at_least: u64 },
    /// The content is not UTF-8 (a binary file).
    NotUtf8,
    /// Opening or reading failed.
    Io(io::ErrorKind),
}

impl ReadRefusal {
    /// Whether the refusal is worth a line on stderr: an absent or binary file is not.
    pub fn is_reported(&self) -> bool {
        match self {
            Self::Absent | Self::NotUtf8 => false,
            Self::Name(_)
            | Self::NotRegular(_)
            | Self::Replaced
            | Self::Claimed(_)
            | Self::TooLarge { .. }
            | Self::Io(_) => true,
        }
    }
}

impl fmt::Display for ReadRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(refusal) => write!(f, "{refusal}"),
            Self::Absent => f.write_str("absent"),
            Self::NotRegular(found) => f.write_str(&disk_why(found)),
            Self::Replaced => f.write_str("replaced while it was opened"),
            Self::Claimed(tag) => {
                write!(f, "owned by the declared root `{}`", shown(tag.as_str()))
            }
            Self::TooLarge { at_least } => write!(
                f,
                "larger than the {MAX_FILE_BYTES}-byte read ceiling ({at_least}+ bytes)"
            ),
            Self::NotUtf8 => f.write_str("not UTF-8 text"),
            Self::Io(kind) => write!(f, "unreadable ({kind})"),
        }
    }
}

/// Reads the regular file `root/rel` as text, refusing anything the walk would.
///
/// `rel` is parsed again, so a stored name never escapes `root`; the leaf and
/// every directory above it are checked without following links; the opened
/// handle must be the file that check saw; at most [`MAX_FILE_BYTES`] are read.
pub fn read_indexed(root: &Path, rel: &str) -> Result<String, ReadRefusal> {
    read_owned(root, rel, &[])
}

/// [`read_indexed`] for a walked root: a path under one of the `claimed` roots
/// declared inside `root` is refused, since only the root that owns it reads it.
pub fn read_owned(
    root: &Path,
    rel: &str,
    claimed: &[&DeclaredRoot],
) -> Result<String, ReadRefusal> {
    let rel = path_of(rel.as_bytes()).map_err(ReadRefusal::Name)?;
    let seen = match on_disk(root, &rel, claimed) {
        OnDisk::Regular(id) => id,
        OnDisk::Absent => return Err(ReadRefusal::Absent),
        OnDisk::Claimed(tag) => return Err(ReadRefusal::Claimed(tag)),
        OnDisk::Refused(found) => return Err(ReadRefusal::NotRegular(found)),
    };
    let file = File::open(root.join(&rel)).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => ReadRefusal::Absent,
        kind => ReadRefusal::Io(kind),
    })?;
    read_held(file, seen)
}

/// Reads an opened file that must be the regular file `seen` names, capped.
fn read_held(file: File, seen: FileId) -> Result<String, ReadRefusal> {
    let md = file.metadata().map_err(|e| ReadRefusal::Io(e.kind()))?;
    if !md.is_file() || FileId::of(&md) != seen {
        return Err(ReadRefusal::Replaced);
    }
    if md.len() > MAX_FILE_BYTES {
        return Err(ReadRefusal::TooLarge { at_least: md.len() });
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| ReadRefusal::Io(e.kind()))?;
    let read = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if read > MAX_FILE_BYTES {
        return Err(ReadRefusal::TooLarge { at_least: read });
    }
    String::from_utf8(bytes).map_err(|_| ReadRefusal::NotUtf8)
}

pub fn head_sha(repo: &str) -> Result<String> {
    let out = git_stdout(repo, &["rev-parse", "HEAD"])?;
    let Ok(sha) = String::from_utf8(out) else {
        bail!("git rev-parse HEAD in {} printed non-UTF-8", shown(repo));
    };
    Ok(sha.trim().to_string())
}

/// Git repositories for the tests of this crate.
#[cfg(all(test, unix))]
pub(crate) mod fixture {
    use super::{git_command, tracked};
    use crate::model::{RepoSpec, RepoTag};
    use crate::repo_set::{DeclaredRoot, RepoSet};
    use std::path::PathBuf;
    use std::process::Stdio;

    /// A git repository beside the test binary, inside the build's own target directory.
    pub struct Fixture(pub PathBuf);

    impl Fixture {
        #[allow(clippy::expect_used)] // a fixture that cannot be built fails the test
        pub fn new(name: &str) -> Self {
            let exe = std::env::current_exe().expect("test binary path");
            let root = exe
                .parent()
                .expect("test binary dir")
                .join("walk-fixtures")
                .join(format!("{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).expect("create fixture");
            let fx = Self(root);
            fx.git(&["init", "-q"]);
            fx
        }

        pub fn root(&self) -> &str {
            self.0.to_str().unwrap_or_default()
        }

        /// `rel` inside the fixture, as UTF-8 text.
        pub fn path(&self, rel: &str) -> String {
            self.0.join(rel).to_str().unwrap_or_default().to_string()
        }

        #[allow(clippy::expect_used)] // a fixture command that fails fails the test
        fn git_in(dir: &str, args: &[&str]) {
            let ok = git_command(dir)
                .args(args)
                .stdout(Stdio::null())
                .status()
                .expect("run git")
                .success();
            assert!(ok, "git {args:?} failed");
        }

        pub fn git(&self, args: &[&str]) {
            Self::git_in(self.root(), args);
        }

        /// Makes `rel` a repository of its own, nested in this one.
        pub fn init_nested(&self, rel: &str) {
            Self::git_in(&self.path(rel), &["init", "-q"]);
        }

        #[allow(clippy::expect_used)] // a fixture file that cannot be written fails the test
        pub fn write(&self, rel: &str, text: &str) {
            let at = self.0.join(rel);
            if let Some(dir) = at.parent() {
                std::fs::create_dir_all(dir).expect("create fixture dir");
            }
            std::fs::write(at, text).expect("write fixture file");
        }

        /// Commits the whole work tree.
        pub fn commit(&self, message: &str) {
            self.git(&["add", "-A"]);
            self.git(&[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                message,
            ]);
        }

        /// The sorted paths a walk of this repository, declared alone, admits.
        pub fn paths(&self) -> Vec<String> {
            let set = set(&[("ipe", self.root())]);
            let root = root_of(&set, "ipe");
            let mut v: Vec<String> = tracked(root, &set.claimed_in(root))
                .unwrap()
                .into_iter()
                .map(|t| t.path)
                .collect();
            v.sort();
            v
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The parsed set of `(tag, root)` pairs.
    pub fn set(specs: &[(&str, &str)]) -> RepoSet {
        let specs: Vec<RepoSpec> = specs
            .iter()
            .map(|(tag, root)| RepoSpec {
                tag: RepoTag::parse(tag).unwrap(),
                root: (*root).to_string(),
            })
            .collect();
        RepoSet::parse(&specs).unwrap()
    }

    /// The declared root of `set` tagged `tag`.
    pub fn root_of<'a>(set: &'a RepoSet, tag: &str) -> &'a DeclaredRoot {
        set.iter().find(|r| r.tag().as_str() == tag).unwrap()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::fixture::{Fixture, root_of, set};
    use super::*;

    const SHA: &str = "6178079822d17af2d34fce4cfbdf355568324720";

    fn staged_bytes(mode: &str, name: &[u8]) -> Vec<u8> {
        let mut out = format!("{mode} {SHA} 0\t").into_bytes();
        out.extend_from_slice(name);
        out.push(0);
        out
    }

    fn staged(lines: &[(&str, &str)]) -> Vec<u8> {
        lines
            .iter()
            .flat_map(|(mode, name)| staged_bytes(mode, name.as_bytes()))
            .collect()
    }

    fn admitted(listed: &[Listed]) -> Vec<&str> {
        listed
            .iter()
            .filter_map(|l| l.as_ref().ok().map(String::as_str))
            .collect()
    }

    #[test]
    fn parses_staged_listing() {
        let out = staged(&[
            ("100644", "crates/ipe_parse/src/lexer.rs"),
            ("100755", "runtime/src/list.rs"),
            ("100644", "Ipe/Core/List.ipe"),
        ]);
        let listed = parse_staged(&out).unwrap();
        assert_eq!(
            admitted(&listed),
            [
                "crates/ipe_parse/src/lexer.rs",
                "runtime/src/list.rs",
                "Ipe/Core/List.ipe"
            ]
        );
        let t = Tracked::at("Ipe/Core/List.ipe".to_string());
        assert_eq!(t.role, crate::model::Role::StdlibIpe);
        assert_eq!(
            Tracked::at("a.rs".to_string()).lang,
            crate::model::Lang::Rust
        );
    }

    #[test]
    fn skips_build_output_dirs() {
        let out = staged(&[
            ("100644", "runtime/src/path.rs"),
            ("100644", "tools/ipe-index/target/release/deps/foo.rs"),
            (
                "100644",
                "tools/ipe-index/target/debug/build/bar/out/baz.rs",
            ),
            ("100644", "web/node_modules/pkg/index.ts"),
            ("100644", "examples/01/ipe-out/main.rs"),
            ("100644", "crates/ipe_lower/src/compile.rs"),
        ]);
        let listed = parse_staged(&out).unwrap();
        assert_eq!(
            admitted(&listed),
            ["runtime/src/path.rs", "crates/ipe_lower/src/compile.rs"]
        );
        assert_eq!(listed.len(), 2);
    }

    #[test]
    fn a_symlink_entry_is_refused() {
        let out = staged(&[("120000", "leak.rs"), ("100644", "ok.rs")]);
        assert_eq!(
            parse_staged(&out).unwrap(),
            [
                Listed::Err(Refusal::SymlinkEntry {
                    path: "leak.rs".to_string()
                }),
                Listed::Ok("ok.rs".to_string()),
            ]
        );
    }

    #[test]
    fn a_gitlink_entry_is_refused() {
        let out = staged(&[("160000", "vendor/sub")]);
        assert_eq!(
            parse_staged(&out).unwrap(),
            [Listed::Err(Refusal::GitlinkEntry {
                path: "vendor/sub".to_string()
            })]
        );
    }

    #[test]
    fn an_unknown_mode_is_refused() {
        let out = staged(&[("100664", "odd.rs")]);
        assert_eq!(
            parse_staged(&out).unwrap(),
            [Listed::Err(Refusal::UnknownMode {
                path: "odd.rs".to_string(),
                mode: "100664".to_string()
            })]
        );
    }

    #[test]
    fn an_unmerged_path_with_a_symlink_stage_is_one_refusal() {
        let mut out = Vec::new();
        for (mode, stage) in [("100644", "1"), ("120000", "2"), ("100644", "3")] {
            out.extend_from_slice(format!("{mode} {SHA} {stage}\tc.rs\0").as_bytes());
        }
        assert_eq!(
            parse_staged(&out).unwrap(),
            [Listed::Err(Refusal::SymlinkEntry {
                path: "c.rs".to_string()
            })]
        );
    }

    #[test]
    fn a_newline_in_a_name_is_one_path() {
        let out = staged(&[("100644", "src/a\nb.rs")]);
        assert_eq!(
            parse_staged(&out).unwrap(),
            [Listed::Ok("src/a\nb.rs".to_string())]
        );
        assert_eq!(
            parse_untracked(b"new\nname.rs\0").unwrap(),
            [Listed::Ok("new\nname.rs".to_string())]
        );
    }

    #[test]
    fn a_non_utf8_name_is_refused_with_its_offset() {
        let out = staged_bytes("100644", b"src/\xffbad.rs");
        assert_eq!(
            parse_staged(&out).unwrap(),
            [Listed::Err(Refusal::NonUtf8Name { offset: 4 })]
        );
        assert_eq!(
            parse_untracked(b"ab\xc3(.rs\0").unwrap(),
            [Listed::Err(Refusal::NonUtf8Name { offset: 2 })]
        );
    }

    #[test]
    fn a_name_that_is_not_repo_relative_is_refused() {
        for name in ["/etc/passwd", "a/../b.rs", "./a.rs", "a//b.rs", "a//", "/"] {
            assert_eq!(
                parse_untracked(format!("{name}\0").as_bytes()).unwrap(),
                [Listed::Err(Refusal::NotRepoRelative {
                    path: name.to_string()
                })],
                "{name}"
            );
        }
    }

    // `git ls-files --others` names an untracked nested repository `<dir>/`.
    #[test]
    fn an_untracked_nested_repository_is_its_own_refusal() {
        assert_eq!(
            parse_untracked(b"worktrees/sync/\0ok.rs\0target/x/\0").unwrap(),
            [
                Listed::Err(Refusal::NestedRepository {
                    path: "worktrees/sync".to_string()
                }),
                Listed::Ok("ok.rs".to_string()),
            ]
        );
        assert_eq!(
            Refusal::NestedRepository {
                path: "w/s".to_string()
            }
            .to_string(),
            "w/s/: an untracked nested repository"
        );
    }

    // A stored name is parsed again before a read, so `..` never leaves the root.
    #[test]
    fn a_read_refuses_a_name_that_leaves_the_root() {
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        for rel in ["../ipe-index/Cargo.toml", "/etc/passwd", "./Cargo.toml"] {
            assert_eq!(
                read_indexed(here, rel),
                Err(ReadRefusal::Name(Refusal::NotRepoRelative {
                    path: rel.to_string()
                })),
                "{rel}"
            );
        }
        assert!(read_indexed(here, "Cargo.toml").is_ok());
    }

    // The held handle must be the file the no-follow check saw.
    #[cfg(unix)]
    #[test]
    fn a_read_refuses_a_handle_to_another_file() {
        let here = Path::new(env!("CARGO_MANIFEST_DIR"));
        let seen = FileId::of(&std::fs::symlink_metadata(here.join("Cargo.toml")).unwrap());
        let other = File::open(here.join("README.md")).unwrap();
        assert_eq!(read_held(other, seen), Err(ReadRefusal::Replaced));
    }

    #[test]
    fn malformed_framing_refuses_the_whole_listing() {
        assert_eq!(
            parse_staged(b"100644 abc 0\ta.rs"),
            Err(WalkError::Unterminated {
                listing: Listing::Staged
            })
        );
        for rec in [
            &b"100644 abc 0 a.rs\0"[..],
            b"10064 abc 0\ta.rs\0",
            b"100644 abc 4\ta.rs\0",
            b"100644 xyz 0\ta.rs\0",
            b"100644 abc 0\t\0",
            b"100644 abc 0 extra\ta.rs\0",
        ] {
            assert_eq!(
                parse_staged(rec),
                Err(WalkError::MalformedRecord {
                    listing: Listing::Staged,
                    record: 0
                }),
                "{}",
                rec.escape_ascii()
            );
        }
        assert!(parse_staged(b"").unwrap().is_empty());
        assert_eq!(
            parse_untracked(b"a.rs\0\0"),
            Err(WalkError::MalformedRecord {
                listing: Listing::Untracked,
                record: 1
            })
        );
    }

    #[test]
    fn diff_maps_link_and_submodule_changes_to_deletes() {
        let out = b":100644 100644 aaa bbb M\0a.rs\0\
                    :100644 120000 aaa bbb T\0leak.rs\0\
                    :000000 160000 000 bbb A\0sub\0\
                    :100644 000000 aaa 000 D\0gone.rs\0\
                    :000000 100644 000 bbb A\0two\nlines.rs\0\
                    :000000 100644 000 bbb A\0\xfe.rs\0";
        assert_eq!(
            parse_diff(out).unwrap(),
            [
                Change::Upsert("a.rs".to_string()),
                Change::Refused(Refusal::SymlinkEntry {
                    path: "leak.rs".to_string()
                }),
                Change::Delete("leak.rs".to_string()),
                Change::Refused(Refusal::GitlinkEntry {
                    path: "sub".to_string()
                }),
                Change::Delete("sub".to_string()),
                Change::Delete("gone.rs".to_string()),
                Change::Upsert("two\nlines.rs".to_string()),
                Change::Refused(Refusal::NonUtf8Name { offset: 0 }),
            ]
        );
    }

    #[test]
    fn diff_framing_errors_refuse_the_whole_listing() {
        assert_eq!(
            parse_diff(b":100644 100644 a b M\0"),
            Err(WalkError::MissingPath {
                listing: Listing::Diff,
                record: 0
            })
        );
        for rec in [
            &b"100644 100644 a b M\0a.rs\0"[..],
            b":100644 100644 a b R100\0a.rs\0",
            b":100644 100644 a b\0a.rs\0",
            b":100644 1006 a b M\0a.rs\0",
        ] {
            assert_eq!(
                parse_diff(rec),
                Err(WalkError::MalformedRecord {
                    listing: Listing::Diff,
                    record: 0
                }),
                "{}",
                rec.escape_ascii()
            );
        }
    }

    #[test]
    fn refusals_render_without_raw_control_bytes() {
        let r = Refusal::SymlinkEntry {
            path: "a\n\u{1b}[2J\u{202e}\\.rs".to_string(),
        };
        assert_eq!(
            r.to_string(),
            "a\\u{a}\\u{1b}[2J\\u{202e}\\\\.rs: tracked as a symbolic link"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_untracked_symlink_is_skipped() {
        use std::os::unix::fs::symlink;
        let fx = Fixture::new("untracked-symlink");
        std::fs::write(fx.0.join("ok.rs"), "fn a() {}").unwrap();
        symlink("/etc/passwd", fx.0.join("leak.rs")).unwrap();
        std::fs::create_dir(fx.0.join("real")).unwrap();
        std::fs::write(fx.0.join("real/r.rs"), "fn r() {}").unwrap();
        symlink(fx.0.join("real"), fx.0.join("linked")).unwrap();
        assert_eq!(
            on_disk(&fx.0, "leak.rs", &[]),
            OnDisk::Refused(DiskRefusal::Symlink)
        );
        assert_eq!(fx.paths(), ["ok.rs", "real/r.rs"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_tracked_symlink_and_a_gitlink_are_refused_end_to_end() {
        use std::os::unix::fs::symlink;
        let fx = Fixture::new("tracked-links");
        std::fs::write(fx.0.join("ok.rs"), "fn a() {}").unwrap();
        symlink("/etc/passwd", fx.0.join("leak.rs")).unwrap();
        fx.git(&["add", "ok.rs", "leak.rs"]);
        let cacheinfo = format!("160000,{SHA},sub");
        fx.git(&["update-index", "--add", "--cacheinfo", cacheinfo.as_str()]);
        assert_eq!(fx.paths(), ["ok.rs"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_tracked_file_replaced_by_a_link_on_disk_is_refused() {
        use std::os::unix::fs::symlink;
        let fx = Fixture::new("swapped-on-disk");
        std::fs::create_dir(fx.0.join("dir")).unwrap();
        std::fs::write(fx.0.join("dir/a.rs"), "fn a() {}").unwrap();
        std::fs::write(fx.0.join("b.rs"), "fn b() {}").unwrap();
        fx.git(&["add", "dir/a.rs", "b.rs"]);
        std::fs::remove_file(fx.0.join("b.rs")).unwrap();
        symlink("/etc/passwd", fx.0.join("b.rs")).unwrap();
        std::fs::rename(fx.0.join("dir"), fx.0.join("moved")).unwrap();
        symlink(fx.0.join("moved"), fx.0.join("dir")).unwrap();
        assert_eq!(
            on_disk(&fx.0, "dir/a.rs", &[]),
            OnDisk::Refused(DiskRefusal::LinkedAncestor {
                ancestor: "dir".to_string()
            })
        );
        assert_eq!(on_disk(&fx.0, "gone.rs", &[]), OnDisk::Absent);
        assert_eq!(fx.paths(), ["moved/a.rs"]);
        assert_eq!(
            read_indexed(&fx.0, "b.rs"),
            Err(ReadRefusal::NotRegular(DiskRefusal::Symlink))
        );
        assert_eq!(
            read_indexed(&fx.0, "dir/a.rs"),
            Err(ReadRefusal::NotRegular(DiskRefusal::LinkedAncestor {
                ancestor: "dir".to_string()
            }))
        );
        assert_eq!(
            read_indexed(&fx.0, "moved/a.rs").as_deref(),
            Ok("fn a() {}")
        );
    }

    // The read ceiling holds at the handle: one byte past it is refused.
    #[cfg(unix)]
    #[test]
    fn a_read_past_the_ceiling_is_refused() {
        let fx = Fixture::new("read-ceiling");
        let limit = usize::try_from(MAX_FILE_BYTES).unwrap();
        std::fs::write(fx.0.join("at.rs"), vec![b'a'; limit]).unwrap();
        std::fs::write(fx.0.join("past.rs"), vec![b'a'; limit + 1]).unwrap();
        assert_eq!(read_indexed(&fx.0, "at.rs").map(|s| s.len()), Ok(limit));
        assert_eq!(
            read_indexed(&fx.0, "past.rs"),
            Err(ReadRefusal::TooLarge {
                at_least: MAX_FILE_BYTES + 1
            })
        );
    }

    // A range git cannot resolve is an error, never a pathspec for a file of that name.
    #[cfg(unix)]
    #[test]
    fn an_unresolvable_since_ref_is_an_error_not_a_pathspec() {
        let fx = Fixture::new("since-pathspec");
        std::fs::write(fx.0.join("abc..HEAD"), "x").unwrap();
        fx.git(&["add", "abc..HEAD"]);
        let set = set(&[("ipe", fx.root())]);
        assert!(changed(root_of(&set, "ipe"), "abc", &[]).is_err());
    }

    #[cfg(unix)]
    fn sorted(files: Vec<Tracked>) -> Vec<String> {
        let mut v: Vec<String> = files.into_iter().map(|t| t.path).collect();
        v.sort();
        v
    }

    // A nested repository nobody declared is still refused; the declared one is
    // skipped, because its own root owns it.
    #[cfg(unix)]
    #[test]
    fn nested_untracked_repo_still_refused() {
        let fx = Fixture::new("nested-repo");
        fx.write("top.rs", "fn t() {}");
        fx.write("inner/x.rs", "fn x() {}");
        fx.write("other/y.rs", "fn y() {}");
        fx.init_nested("inner");
        fx.init_nested("other");
        let set = set(&[("out", fx.root()), ("in", &fx.path("inner"))]);
        let out = root_of(&set, "out");
        let (files, refused) = listing(out, &set.claimed_in(out)).unwrap();
        assert_eq!(sorted(files), ["top.rs"]);
        assert_eq!(
            refused,
            [Refusal::NestedRepository {
                path: "other".to_string()
            }]
        );
    }

    // A declared root inside the outer work tree owns its files: the outer walk
    // skips them and the inner walk lists them relative to the inner root.
    #[cfg(unix)]
    #[test]
    fn a_nested_root_in_one_work_tree_owns_its_files() {
        let fx = Fixture::new("nested-dir");
        fx.write("top.rs", "fn t() {}");
        fx.write("inner/x.rs", "fn x() {}");
        let set = set(&[("out", fx.root()), ("in", &fx.path("inner"))]);
        let out = root_of(&set, "out");
        let inner = root_of(&set, "in");
        assert_eq!(
            sorted(tracked(out, &set.claimed_in(out)).unwrap()),
            ["top.rs"]
        );
        assert_eq!(
            sorted(tracked(inner, &set.claimed_in(inner)).unwrap()),
            ["x.rs"]
        );
        assert_eq!(
            read_owned(out.root(), "inner/x.rs", &set.claimed_in(out)),
            Err(ReadRefusal::Claimed(inner.tag().clone()))
        );
    }

    // A root below the top of its work tree diffs relative to itself: a change
    // outside it never appears, and a change inside it is named from the root.
    #[cfg(unix)]
    #[test]
    fn update_in_subdir_root_is_root_relative() {
        let fx = Fixture::new("subdir-update");
        fx.write("sub/x.rs", "fn a() {}");
        fx.write("top.rs", "fn t() {}");
        fx.commit("one");
        let first = head_sha(fx.root()).unwrap();
        fx.write("sub/x.rs", "fn b() {}");
        fx.write("top.rs", "fn u() {}");
        fx.commit("two");
        let set = set(&[("sub", &fx.path("sub"))]);
        let (ups, dels) = changed(root_of(&set, "sub"), &first, &[]).unwrap();
        assert_eq!(sorted(ups), ["x.rs"]);
        assert_eq!(dels, Vec::<String>::new());
    }

    // A change under a declared inner root is neither upserted nor deleted by
    // the outer root's update.
    #[cfg(unix)]
    #[test]
    fn update_skips_claimed_paths() {
        let fx = Fixture::new("claimed-update");
        fx.write("top.rs", "fn t() {}");
        fx.write("inner/x.rs", "fn x() {}");
        fx.write("inner/y.rs", "fn y() {}");
        fx.commit("one");
        let first = head_sha(fx.root()).unwrap();
        fx.write("top.rs", "fn u() {}");
        fx.write("inner/x.rs", "fn z() {}");
        std::fs::remove_file(fx.0.join("inner/y.rs")).unwrap();
        fx.commit("two");
        let set = set(&[("out", fx.root()), ("in", &fx.path("inner"))]);
        let out = root_of(&set, "out");
        let (ups, dels) = changed(out, &first, &set.claimed_in(out)).unwrap();
        assert_eq!(sorted(ups), ["top.rs"]);
        assert_eq!(dels, Vec::<String>::new());
    }

    // An inner root swapped for another directory of the same name after the
    // set was parsed fails the walk: which root owns its files is unknown.
    #[cfg(unix)]
    #[test]
    fn root_moved_between_parse_and_walk_refused() {
        let fx = Fixture::new("root-moved");
        fx.write("top.rs", "fn t() {}");
        fx.write("inner/x.rs", "fn x() {}");
        let set = set(&[("out", fx.root()), ("in", &fx.path("inner"))]);
        std::fs::rename(fx.0.join("inner"), fx.0.join("inner-old")).unwrap();
        fx.write("inner/x.rs", "fn other() {}");
        let out = root_of(&set, "out");
        let moved = tracked(out, &set.claimed_in(out))
            .err()
            .map(|e| e.to_string());
        assert!(
            moved
                .as_deref()
                .is_some_and(|e| e.contains("sits where the declared root `in` was")),
            "{moved:?}"
        );
        let inner = root_of(&set, "in");
        assert!(tracked(inner, &[]).is_err());
        assert_eq!(
            on_disk(out.root(), "inner/x.rs", &set.claimed_in(out)),
            OnDisk::Refused(DiskRefusal::RootMoved {
                root: "in".to_string()
            })
        );
    }

    // A refused entry under a declared inner root is that root's to report: the
    // outer walk drops it, a grandchild nested repository included, and the
    // inner walk still refuses its own entries.
    #[cfg(unix)]
    #[test]
    fn listing_refusals_under_a_claimed_root_are_its_own() {
        let fx = Fixture::new("claimed-refusals");
        fx.write("top.rs", "fn t() {}");
        fx.write("inner/x.rs", "fn x() {}");
        std::os::unix::fs::symlink("x.rs", fx.0.join("inner/link.rs")).unwrap();
        fx.commit("one");
        fx.write("inner/deep/d.rs", "fn d() {}");
        fx.init_nested("inner/deep");
        let set = set(&[
            ("out", fx.root()),
            ("in", &fx.path("inner")),
            ("deep", &fx.path("inner/deep")),
        ]);
        let out = root_of(&set, "out");
        let (files, refused) = listing(out, &set.claimed_in(out)).unwrap();
        assert_eq!(sorted(files), ["top.rs"]);
        assert_eq!(refused, Vec::<Refusal>::new());
        let inner = root_of(&set, "in");
        let (files, refused) = listing(inner, &set.claimed_in(inner)).unwrap();
        assert_eq!(sorted(files), ["x.rs"]);
        assert_eq!(
            refused,
            [Refusal::SymlinkEntry {
                path: "link.rs".to_string()
            }]
        );
    }

    // A diff refusal under a declared inner root is dropped by the outer
    // update; one outside every inner root is still reported and deleted.
    #[cfg(unix)]
    #[test]
    fn diff_refusals_under_a_claimed_root_are_its_own() {
        let fx = Fixture::new("claimed-diff-refusals");
        fx.write("top.rs", "fn t() {}");
        fx.write("inner/x.rs", "fn x() {}");
        let set = set(&[("out", fx.root()), ("in", &fx.path("inner"))]);
        let out = root_of(&set, "out");
        let link = |path: &str| Refusal::SymlinkEntry {
            path: path.to_string(),
        };
        let (ups, dels, refused) = classify(
            out.root(),
            vec![
                Change::Refused(link("inner/l.rs")),
                Change::Delete("inner/l.rs".to_string()),
                Change::Refused(link("l.rs")),
                Change::Delete("l.rs".to_string()),
            ],
            &set.claimed_in(out),
        );
        assert_eq!(sorted(ups), Vec::<String>::new());
        assert_eq!(dels, ["l.rs"]);
        assert_eq!(refused, [link("l.rs")]);
    }
}
