//! The single ingest budget for every byte the CLI takes from a remote party.
//!
//! A package fetch, the index clone `ipe package publish` makes, the installer
//! `ipe upgrade` downloads, and every HTTP response the CLI reads (the GitHub
//! API, the OAuth device flow, the registry read API, the release feed) arrive
//! through this module. Each surface has a declared [`Budget`]: a ceiling on the
//! bytes and entries it may put on disk, the bytes it may buffer in memory, and
//! the wall time it may take. Crossing any of them is an [`IngestRefusal`],
//! surfaced as [`CliError::RemoteIngestExceeded`]; the transfer is stopped, and
//! the caller discards whatever it staged, so nothing partial reaches the lock,
//! the manifest or the package cache.
//!
//! One [`Transfer`] carries one budget and one start instant: every child a
//! transfer runs is held to the same deadline, so a transfer made of several
//! steps shares one wall-time ceiling rather than restarting it per step.
//!
//! Two mechanisms enforce the budgets:
//!
//! - [`read_capped`] reads a stream through `take(cap + 1)`, so an oversized
//!   body is refused without ever being buffered past `cap + 1` bytes.
//! - [`Git`] and [`Curl`] run a child whose output lands on disk. The child is
//!   started in its own process group (on Unix platforms with `waitid`), so a
//!   refusal kills every process it started, not only the direct child; the
//!   interrupt, quit, hangup, stop and continue signals reaching the CLI are
//!   relayed to that group, except a signal the CLI inherited as ignored. The
//!   staged path's size and entry count are sampled at a fixed
//!   interval and the group is killed once either crosses the budget. After the
//!   child exits, its group is killed and one final exact measurement decides
//!   acceptance, so an accepted transfer is always within budget. While it
//!   runs, the disk may briefly hold more than the ceiling, by at most one
//!   [`POLL_INTERVAL`] of transfer throughput.
//!
//! [`Git`] and [`Curl`] are the only constructors of a `git` or `curl` child in
//! the CLI; each fixes the hardened environment and arguments once.
//!
//! LIMIT: a termination request (`SIGTERM`) is not relayed to the groups.
//! `ipe watch` owns the process's `SIGTERM` disposition for its orderly
//! shutdown, and a process holds one disposition per signal, so a relay that
//! ended the CLI on `SIGTERM` would cut that shutdown short. A CLI ended by
//! `SIGTERM` mid-transfer leaves the transfer's group running until it exits on
//! its own; on Linux the direct child receives the parent-death signal, the
//! processes it started do not.
//!
//! LIMIT: git's resident memory is bounded only by the transfer deadline and the
//! group kill. Every fetch step receives the server's ref advertisement, which
//! may differ from the one a pre-checked `ls-remote` saw, and `index-pack`
//! memory scales with the pack. [`Git::isolated`] caps each single allocation
//! at the package per-file ceiling (`GIT_ALLOC_LIMIT`); a cap on the child's
//! address space would need a pre-exec hook, which needs `unsafe`.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::CliError;
use crate::package_name::PackageName;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// Ceiling on every byte budget of a remote-ingest surface.
///
/// No surface may stage, read or keep more than 1 GiB from a remote; the
/// package fetch, the largest, sits exactly at it.
pub const MAX_REMOTE_BYTES: u64 = GIB;

/// Ceiling on every entry budget of a remote-ingest surface.
///
/// The index clone, the widest surface, sits exactly at it.
pub const MAX_REMOTE_ENTRIES: u64 = 262_144;

/// A byte ceiling of one remote-ingest surface, never above [`MAX_REMOTE_BYTES`].
///
/// The only values are the named constants of this module: [`ByteBudget::NONE`]
/// for a surface that stages nothing, and in-range literals whose bound the
/// build checks. Code outside this module cannot build one, so no caller can
/// hand a transfer, a capped read or a curl limit an unbounded ceiling.
///
/// ```compile_fail,E0624
/// let _ = ipe::remote_ingest::ByteBudget::of::<1>();
/// ```
///
/// ```compile_fail,E0423
/// let _ = ipe::remote_ingest::ByteBudget(u64::MAX);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteBudget(u64);

impl ByteBudget {
    /// No bytes: a surface that stages or keeps nothing.
    pub const NONE: Self = Self(0);

    /// The ceiling `N`, which the build refuses outside `1..=MAX_REMOTE_BYTES`.
    const fn of<const N: u64>() -> Self {
        // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD when a named byte budget is zero or above `MAX_REMOTE_BYTES` [ledger #boundary]
        const { assert!(N > 0 && N <= MAX_REMOTE_BYTES) };
        Self(N)
    }

    /// The ceiling in bytes.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The ceiling `bytes`, or `None` outside `1..=MAX_REMOTE_BYTES`, for a test to drive the refusals.
    #[cfg(test)]
    #[must_use]
    pub const fn for_test(bytes: u64) -> Option<Self> {
        if bytes == 0 || bytes > MAX_REMOTE_BYTES {
            None
        } else {
            Some(Self(bytes))
        }
    }
}

/// An entry ceiling of one remote-ingest surface, never above [`MAX_REMOTE_ENTRIES`].
///
/// Built only as [`ByteBudget`] is: [`EntryBudget::NONE`] or a named in-range
/// constant of this module.
///
/// ```compile_fail,E0624
/// let _ = ipe::remote_ingest::EntryBudget::of::<1>();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntryBudget(u64);

impl EntryBudget {
    /// No entries: a surface that stages nothing.
    pub const NONE: Self = Self(0);

    /// The ceiling `N`, which the build refuses outside `1..=MAX_REMOTE_ENTRIES`.
    const fn of<const N: u64>() -> Self {
        // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD when a named entry budget is zero or above `MAX_REMOTE_ENTRIES` [ledger #boundary]
        const { assert!(N > 0 && N <= MAX_REMOTE_ENTRIES) };
        Self(N)
    }

    /// The ceiling in entries.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The ceiling `entries`, or `None` outside `1..=MAX_REMOTE_ENTRIES`, for a test to drive the refusals.
    #[cfg(test)]
    #[must_use]
    pub const fn for_test(entries: u64) -> Option<Self> {
        if entries == 0 || entries > MAX_REMOTE_ENTRIES {
            None
        } else {
            Some(Self(entries))
        }
    }
}

/// Ceiling on the bytes of one package source tree the content hash walks.
///
/// Summed over every hashed file. 256 MiB is far above any published Ipê source
/// package while refusing a checkout that a small compressed pack inflates into
/// gigabytes.
pub const PACKAGE_TREE_MAX_BYTES: u64 = 256 * MIB;

/// Ceiling on the entries (files and directories) one package source tree walk visits.
///
/// 32 768 is far above any real source package while refusing a tree of
/// millions of empty files built to exhaust the walk.
pub const PACKAGE_TREE_MAX_ENTRIES: u64 = 32_768;

/// Ceiling on the bytes of one file in a package source tree.
///
/// 64 MiB is far above any real published source file while refusing a
/// multi-GiB blob.
pub const PACKAGE_FILE_MAX_BYTES: u64 = 64 * MIB;

/// Ceiling on the directory depth of a package source tree.
///
/// A published package source is never this deep; a deeper tree is refused
/// before the walk can exhaust the stack.
pub const PACKAGE_TREE_MAX_DEPTH: u32 = 64;

/// Ceiling on the bytes of the ref advertisement a package source may present.
///
/// 1 MiB holds thousands of tags and branches while refusing an advertisement
/// built to exhaust memory.
pub const REFS_MAX_BYTES: ByteBudget = ByteBudget::of::<MIB>();

/// Ceiling on the lines of the ref advertisement a package source may present.
///
/// A peeled `^{}` line counts as one line.
pub const REFS_MAX_COUNT: u64 = 4_096;

/// Entries a fetch stage holds besides the checked-out tree and its refs.
///
/// The `.git` skeleton `git init` writes from its default template (the sample
/// hooks included), `HEAD`, `config`, the index, `FETCH_HEAD`, `shallow`,
/// `packed-refs`, and the one pack with its index and reverse index that
/// `transfer.unpackLimit=1` keeps every fetched object in.
pub const GIT_STAGE_OVERHEAD_ENTRIES: u64 = 64;

/// Ceiling on the bytes of one HTTP JSON response body.
///
/// Every JSON document the CLI reads (a GitHub API object, an OAuth token
/// response, a registry index entry, the release feed) is a few KiB; 4 MiB
/// leaves wide headroom and refuses a response built to exhaust memory.
pub const JSON_RESPONSE_MAX_BYTES: ByteBudget = ByteBudget::of::<{ 4 * MIB }>();

/// Ceiling on the stderr kept from one child process.
///
/// Stderr only feeds a diagnostic (a remote's `remote:` lines among it), so
/// output past 64 KiB is read and dropped rather than kept.
pub const CHILD_STDERR_MAX_BYTES: ByteBudget = ByteBudget::of::<{ 64 * KIB }>();

/// Ceiling on the stdout of a child that only reports a status.
///
/// `curl -w '%{http_code}'` writes three digits; 64 bytes is ample.
pub const STATUS_STDOUT_MAX_BYTES: ByteBudget = ByteBudget::of::<64>();

/// The wall-time ceiling of one HTTP request.
///
/// Passed to curl as `--max-time` and enforced again by the watcher; a server
/// that trickles a response is cut off rather than holding the CLI.
pub const HTTP_MAX_TIME: Duration = Duration::from_secs(60);

/// How often the watcher samples a running child's staged bytes and clock.
///
/// The disk may overshoot a ceiling by one interval's throughput before the kill
/// lands; the final post-exit measurement still refuses the result.
pub const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// How long the watcher waits for a child's output pipes to close after it exited or was killed.
///
/// A process the child started that still holds a pipe open cannot make the
/// CLI wait longer; the wait ends in [`RunError::PipeDrainTimeout`].
const PIPE_DRAIN_GRACE: Duration = Duration::from_secs(5);

/// The ceilings of a local `git` query, which stages nothing on disk.
///
/// Its stdout (a revision, a remote URL, a porcelain status) is held to 4 MiB
/// and its run to one minute.
const QUERY_LIMITS: Limits = Limits {
    disk_bytes: 0,
    disk_entries: 0,
    stdout_bytes: 4 * MIB,
    wall: Duration::from_secs(60),
};

/// The declared ingest ceilings of one remote surface.
///
/// The fields are private and every production value is a named constant of
/// this module, so a caller can neither build a budget nor widen one.
///
/// ```compile_fail,E0451
/// use ipe::remote_ingest::{Budget, GITHUB_API};
/// let _ = Budget { wall: std::time::Duration::MAX, ..GITHUB_API };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    source: IngestSource,
    disk_bytes: ByteBudget,
    disk_entries: EntryBudget,
    stdout_bytes: ByteBudget,
    wall: Duration,
}

impl Budget {
    /// The surface named in a refusal.
    #[must_use]
    pub const fn source(&self) -> IngestSource {
        self.source
    }

    /// Bytes the staged path may hold on disk.
    #[must_use]
    pub const fn disk_bytes(&self) -> ByteBudget {
        self.disk_bytes
    }

    /// Entries (files and directories) the staged path may hold.
    #[must_use]
    pub const fn disk_entries(&self) -> EntryBudget {
        self.disk_entries
    }

    /// Bytes the child's stdout may carry.
    #[must_use]
    pub const fn stdout_bytes(&self) -> ByteBudget {
        self.stdout_bytes
    }

    /// Wall time the whole transfer may take.
    #[must_use]
    pub const fn wall(&self) -> Duration {
        self.wall
    }

    /// This budget with its disk byte ceiling set, for a test to drive the refusals.
    #[cfg(test)]
    #[must_use]
    pub const fn with_disk_bytes(self, bytes: ByteBudget) -> Self {
        Self {
            disk_bytes: bytes,
            ..self
        }
    }

    /// This budget with its disk entry ceiling set, for a test to drive the refusals.
    #[cfg(test)]
    #[must_use]
    pub const fn with_disk_entries(self, entries: EntryBudget) -> Self {
        Self {
            disk_entries: entries,
            ..self
        }
    }

    /// This budget with its stdout ceiling set, for a test to drive the refusals.
    #[cfg(test)]
    #[must_use]
    pub const fn with_stdout(self, bytes: ByteBudget) -> Self {
        Self {
            stdout_bytes: bytes,
            ..self
        }
    }

    /// This budget with its wall time set, for a test to drive the refusals.
    #[cfg(test)]
    #[must_use]
    pub const fn with_wall(self, wall: Duration) -> Self {
        Self { wall, ..self }
    }

    /// The ceilings the watcher enforces, without the surface name.
    const fn limits(&self) -> Limits {
        Limits {
            disk_bytes: self.disk_bytes.get(),
            disk_entries: self.disk_entries.get(),
            stdout_bytes: self.stdout_bytes.get(),
            wall: self.wall,
        }
    }
}

/// The budget of one package source fetch (`git init` + `fetch` + `checkout`).
///
/// Disk holds the fetched pack plus the checked-out tree, each at most
/// [`PACKAGE_TREE_MAX_BYTES`]; 1 GiB leaves headroom over both. The entry
/// ceiling covers the tree's [`PACKAGE_TREE_MAX_ENTRIES`] plus the advertised
/// refs and git's own bookkeeping. Ten minutes covers a slow link fetching a
/// large package, across every step. Paired with its tree ceiling only through
/// [`PACKAGE_SOURCE`].
const PACKAGE_FETCH: Budget = Budget {
    source: IngestSource::PackageFetch,
    disk_bytes: ByteBudget::of::<GIB>(),
    disk_entries: EntryBudget::of::<{ 4 * PACKAGE_TREE_MAX_ENTRIES }>(),
    stdout_bytes: CHILD_STDERR_MAX_BYTES,
    wall: Duration::from_secs(600),
};

/// The ceilings of the ref advertisement one package fetch reads.
const PACKAGE_REFS: RefsCeiling = RefsCeiling {
    bytes: REFS_MAX_BYTES,
    count: REFS_MAX_COUNT,
};

/// The ceilings of one package source tree the content hash walks.
const PACKAGE_TREE: TreeCeiling = TreeCeiling {
    bytes: PACKAGE_TREE_MAX_BYTES,
    entries: PACKAGE_TREE_MAX_ENTRIES,
    per_file: PACKAGE_FILE_MAX_BYTES,
    depth: PACKAGE_TREE_MAX_DEPTH,
};

/// The one budget every package source fetch and every package tree hash is held to.
pub const PACKAGE_SOURCE: FetchBudget = FetchBudget {
    transfer: PACKAGE_FETCH,
    refs: PACKAGE_REFS,
    tree: PACKAGE_TREE,
};

// Every relation of `FetchBudget::pairing` holds for the production budget, so a
// drifted pair breaks the build.
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the production transfer, ref and tree ceilings drift out of pairing [ledger #boundary]
const _: () = assert!(PACKAGE_SOURCE.pairing().is_ok());

/// The ceilings of the ref advertisement a fetch reads before an all-refs fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefsCeiling {
    bytes: ByteBudget,
    count: u64,
}

impl RefsCeiling {
    /// Bytes the advertisement may carry.
    #[must_use]
    pub const fn bytes(&self) -> ByteBudget {
        self.bytes
    }

    /// Lines the advertisement may hold, a peeled line counting as one.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// A ref ceiling with explicit values, for a test to drive the refusals.
    #[cfg(test)]
    #[must_use]
    pub const fn for_test(bytes: ByteBudget, count: u64) -> Self {
        Self { bytes, count }
    }
}

/// The ceilings one package source tree walk is held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeCeiling {
    bytes: u64,
    entries: u64,
    per_file: u64,
    depth: u32,
}

impl TreeCeiling {
    /// Bytes summed over every hashed file.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Entries (files and directories) visited.
    #[must_use]
    pub const fn entries(&self) -> u64 {
        self.entries
    }

    /// Bytes of any one file.
    #[must_use]
    pub const fn per_file(&self) -> u64 {
        self.per_file
    }

    /// Directory levels below the root.
    #[must_use]
    pub const fn depth(&self) -> u32 {
        self.depth
    }

    /// A tree ceiling with explicit values, for a test to drive the refusals.
    ///
    /// # Errors
    /// [`BudgetPairing::FileOverTree`] when `per_file` exceeds `bytes`.
    #[cfg(test)]
    pub const fn for_test(
        bytes: u64,
        entries: u64,
        per_file: u64,
        depth: u32,
    ) -> Result<Self, BudgetPairing> {
        if per_file > bytes {
            return Err(BudgetPairing::FileOverTree);
        }
        Ok(Self {
            bytes,
            entries,
            per_file,
            depth,
        })
    }
}

/// A relation a [`FetchBudget`] must hold between its transfer and tree ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetPairing {
    /// The transfer disk ceiling holds less than a pack and a checkout at the tree ceiling.
    TransferBytesUnderTree,
    /// The transfer entry ceiling holds less than a tree at its ceiling, its refs and `.git`.
    TransferEntriesUnderTree,
    /// One file may be larger than the whole tree.
    FileOverTree,
}

/// The paired ceilings of one fetched-tree surface: what `git` may stage, the
/// ref advertisement it may read, and the tree the content hash may walk.
///
/// The transfer ceilings are the looser ones, since the stage also holds the
/// pack and `.git`, so a tree at its ceiling is never refused by the transfer
/// first. The fields are private and the only production value is
/// [`PACKAGE_SOURCE`], whose pairing the build asserts; a caller cannot pair a
/// transfer budget with a different tree ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchBudget {
    transfer: Budget,
    refs: RefsCeiling,
    tree: TreeCeiling,
}

impl FetchBudget {
    /// The ceilings the `git` children of the fetch are held to.
    #[must_use]
    pub const fn transfer(&self) -> &Budget {
        &self.transfer
    }

    /// The ceilings of the ref advertisement the fetch reads.
    #[must_use]
    pub const fn refs(&self) -> &RefsCeiling {
        &self.refs
    }

    /// The ceilings of the fetched tree's content hash.
    #[must_use]
    pub const fn tree(&self) -> &TreeCeiling {
        &self.tree
    }

    /// The first relation between the ceilings that does not hold, if any.
    const fn pairing(&self) -> Result<(), BudgetPairing> {
        if self.transfer.disk_bytes.get() < self.tree.bytes.saturating_mul(2) {
            return Err(BudgetPairing::TransferBytesUnderTree);
        }
        let staged_entries = self
            .tree
            .entries
            .saturating_add(self.refs.count)
            .saturating_add(GIT_STAGE_OVERHEAD_ENTRIES);
        if self.transfer.disk_entries.get() < staged_entries {
            return Err(BudgetPairing::TransferEntriesUnderTree);
        }
        if self.tree.per_file > self.tree.bytes {
            return Err(BudgetPairing::FileOverTree);
        }
        Ok(())
    }

    /// A budget with explicit ceilings, for a test to drive the refusals.
    ///
    /// # Errors
    /// The first [`BudgetPairing`] relation the ceilings break.
    #[cfg(test)]
    pub const fn for_test(
        transfer: Budget,
        refs: RefsCeiling,
        tree: TreeCeiling,
    ) -> Result<Self, BudgetPairing> {
        let budget = Self {
            transfer,
            refs,
            tree,
        };
        match budget.pairing() {
            Ok(()) => Ok(budget),
            Err(broken) => Err(broken),
        }
    }
}

/// The budget of the shallow index clone `ipe package publish` makes.
///
/// The index is one small TOML file per package; 512 MiB and 262 144 entries
/// hold an index far larger than any registry while refusing a fork that
/// inflates without bound.
pub const INDEX_CLONE: Budget = Budget {
    source: IngestSource::IndexClone,
    disk_bytes: ByteBudget::of::<{ 512 * MIB }>(),
    disk_entries: EntryBudget::of::<MAX_REMOTE_ENTRIES>(),
    stdout_bytes: CHILD_STDERR_MAX_BYTES,
    wall: Duration::from_secs(600),
};

/// The budget of the local commit and push steps of `ipe package publish`, taken together.
///
/// Nothing is staged on disk from the remote; only git's own output is held.
/// Ten minutes covers a push over a slow link.
pub const INDEX_PUSH: Budget = Budget {
    source: IngestSource::IndexPush,
    disk_bytes: ByteBudget::NONE,
    disk_entries: EntryBudget::NONE,
    stdout_bytes: CHILD_STDERR_MAX_BYTES,
    wall: Duration::from_secs(600),
};

/// The budget of one GitHub API call made through `curl -o <scratch>`.
///
/// The body lands in one scratch file (one entry) capped at
/// [`JSON_RESPONSE_MAX_BYTES`]; stdout carries only the status code.
pub const GITHUB_API: Budget = Budget {
    source: IngestSource::GithubApi,
    disk_bytes: JSON_RESPONSE_MAX_BYTES,
    disk_entries: EntryBudget::of::<1>(),
    stdout_bytes: STATUS_STDOUT_MAX_BYTES,
    wall: HTTP_MAX_TIME,
};

/// The budget of one OAuth device-flow request (`ipe login`), whose body arrives on curl's stdout.
pub const OAUTH_FORM: Budget = Budget {
    source: IngestSource::OauthDevice,
    disk_bytes: ByteBudget::NONE,
    disk_entries: EntryBudget::NONE,
    stdout_bytes: JSON_RESPONSE_MAX_BYTES,
    wall: HTTP_MAX_TIME,
};

/// The budget of the installer script `ipe upgrade` downloads before running it.
///
/// The script lands in one private scratch file; 1 MiB is far above the
/// installer's size while refusing a response built to fill the disk.
pub const INSTALLER: Budget = Budget {
    source: IngestSource::Installer,
    disk_bytes: ByteBudget::of::<MIB>(),
    disk_entries: EntryBudget::of::<1>(),
    stdout_bytes: STATUS_STDOUT_MAX_BYTES,
    wall: HTTP_MAX_TIME,
};

/// The remote surface an ingest refusal names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestSource {
    /// A package source fetched from its git remote.
    PackageFetch,
    /// The index fork cloned by `ipe package publish`.
    IndexClone,
    /// The commit and push steps on that clone.
    IndexPush,
    /// A GitHub REST API response.
    GithubApi,
    /// A GitHub OAuth device-flow response.
    OauthDevice,
    /// A plain HTTP GET response (the registry read API, the release feed).
    HttpGet,
    /// The installer script `ipe upgrade` downloads.
    Installer,
}

impl std::fmt::Display for IngestSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::PackageFetch => "package fetch",
            Self::IndexClone => "index clone",
            Self::IndexPush => "index push",
            Self::GithubApi => "GitHub API response",
            Self::OauthDevice => "GitHub sign-in response",
            Self::HttpGet => "HTTP response",
            Self::Installer => "installer script",
        })
    }
}

/// The ceiling an ingest crossed, with its declared value, or the shape it refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestLimit {
    /// A byte ceiling (on disk, in memory, or on one file).
    Bytes(u64),
    /// An entry-count ceiling on disk.
    Entries(u64),
    /// A directory-depth ceiling.
    Depth(u32),
    /// A wall-time ceiling.
    Time(Duration),
    /// A file name that is not valid UTF-8, which the tree hash cannot name.
    NonUtf8Name,
    /// An entry that is neither a regular file, a directory nor a link.
    SpecialFile,
    /// A symbolic link, which the tree hash never follows.
    Symlink,
    /// A ref advertisement line that is not a SHA and a safe tag or branch name.
    MalformedRef,
}

impl IngestLimit {
    /// Whether this names an entry the walk refuses by its shape rather than a crossed ceiling.
    const fn is_shape(self) -> bool {
        match self {
            Self::NonUtf8Name | Self::SpecialFile | Self::Symlink | Self::MalformedRef => true,
            Self::Bytes(_) | Self::Entries(_) | Self::Depth(_) | Self::Time(_) => false,
        }
    }
}

impl std::fmt::Display for IngestLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bytes(max) => write!(f, "{max}-byte"),
            Self::Entries(max) => write!(f, "{max}-entry"),
            Self::Depth(max) => write!(f, "{max}-level depth"),
            Self::Time(max) => match max.as_secs() {
                0 => write!(f, "{} ms", max.as_millis()),
                1 => f.write_str("1 second"),
                secs => write!(f, "{secs} seconds"),
            },
            Self::NonUtf8Name => f.write_str("a file name that is not valid UTF-8"),
            Self::SpecialFile => f.write_str("a special file (FIFO, socket or device)"),
            Self::Symlink => f.write_str("a symbolic link"),
            Self::MalformedRef => f.write_str("a malformed or unsafe ref advertisement"),
        }
    }
}

/// The subject a refusal names: its surface, and the package when one is known.
struct Subject<'a, S> {
    source: &'a S,
    name: Option<&'a PackageName>,
}

impl<S: std::fmt::Display> std::fmt::Display for Subject<'_, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.name {
            Some(name) => write!(f, "{} of `{name}`", self.source),
            None => self.source.fmt(f),
        }
    }
}

/// A remote transfer stopped at its budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestRefusal {
    /// The surface that crossed its budget.
    pub source: IngestSource,
    /// The ceiling it crossed.
    pub limit: IngestLimit,
    /// The package whose source the transfer fetched, once the resolver names it.
    pub name: Option<PackageName>,
}

impl IngestRefusal {
    /// This refusal naming the package `name` whose source it stopped.
    #[must_use]
    pub fn with_name(self, name: &PackageName) -> Self {
        Self {
            name: Some(name.clone()),
            ..self
        }
    }
}

impl std::fmt::Display for IngestRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let subject = Subject {
            source: &self.source,
            name: self.name.as_ref(),
        };
        f.write_str(&match (self.limit, self.source) {
            (limit, _) if limit.is_shape() => {
                crate::text::cli_remote_ingest_refused(&subject, &limit)
            }
            (IngestLimit::Time(_), _) => {
                crate::text::cli_remote_ingest_timed_out(&subject, &self.limit)
            }
            (_, IngestSource::PackageFetch) => {
                crate::text::cli_package_source_exceeded(&subject, &self.limit)
            }
            _ => crate::text::cli_remote_ingest_exceeded(&subject, &self.limit),
        })
    }
}

impl From<IngestRefusal> for CliError {
    fn from(refusal: IngestRefusal) -> Self {
        Self::RemoteIngestExceeded(refusal)
    }
}

/// The local work a [`LocalRefusal`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalSource {
    /// A package source tree on disk being hashed.
    PackageTree,
    /// A `git` query on a local repository.
    GitQuery,
}

impl std::fmt::Display for LocalSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::PackageTree => "package source tree",
            Self::GitQuery => "git query",
        })
    }
}

/// Local work stopped at its ceiling: no remote transfer was involved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRefusal {
    /// The work that crossed its ceiling.
    pub source: LocalSource,
    /// The ceiling it crossed.
    pub limit: IngestLimit,
    /// The package whose tree the work read, once the resolver names it.
    pub name: Option<PackageName>,
}

impl LocalRefusal {
    /// This refusal naming the package `name` whose tree it stopped.
    #[must_use]
    pub fn with_name(self, name: &PackageName) -> Self {
        Self {
            name: Some(name.clone()),
            ..self
        }
    }
}

impl std::fmt::Display for LocalRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let subject = Subject {
            source: &self.source,
            name: self.name.as_ref(),
        };
        f.write_str(&match (self.limit, self.source) {
            (limit, _) if limit.is_shape() => crate::text::cli_local_tree_refused(&subject, &limit),
            (IngestLimit::Time(_), _) => crate::text::cli_local_timed_out(&subject, &self.limit),
            (_, LocalSource::PackageTree) => {
                crate::text::cli_package_source_exceeded(&subject, &self.limit)
            }
            _ => crate::text::cli_local_limit_exceeded(&subject, &self.limit),
        })
    }
}

impl From<LocalRefusal> for CliError {
    fn from(refusal: LocalRefusal) -> Self {
        Self::LocalLimitExceeded(refusal)
    }
}

/// Why a bounded read failed.
#[derive(Debug)]
pub enum CappedReadError {
    /// The stream failed before its end.
    Io(std::io::Error),
    /// The stream held more than the cap.
    Exceeded(IngestRefusal),
}

/// Read `reader` to its end, refusing it once it yields more than `cap` bytes.
///
/// At most `cap + 1` bytes are ever buffered.
///
/// # Errors
/// [`CappedReadError::Exceeded`] past `cap`; [`CappedReadError::Io`] when the
/// read fails.
pub fn read_capped(
    reader: impl Read,
    cap: ByteBudget,
    source: IngestSource,
) -> Result<Vec<u8>, CappedReadError> {
    let cap = cap.get();
    let mut buf = Vec::new();
    reader
        .take(cap.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(CappedReadError::Io)?;
    if u64::try_from(buf.len()).map_or(true, |len| len > cap) {
        return Err(CappedReadError::Exceeded(IngestRefusal {
            source,
            limit: IngestLimit::Bytes(cap),
            name: None,
        }));
    }
    Ok(buf)
}

/// The size a staged path occupies, counted until it passes a ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    /// Bytes of the regular files seen.
    pub bytes: u64,
    /// Entries (files, directories, links) seen.
    pub entries: u64,
}

/// The ceilings the watcher enforces on one child.
#[derive(Debug, Clone, Copy)]
struct Limits {
    disk_bytes: u64,
    disk_entries: u64,
    stdout_bytes: u64,
    wall: Duration,
}

/// Measure `root` without following links, stopping once either disk ceiling of `budget` is passed.
///
/// An entry is counted when its directory is listed, before it is queued, so
/// the queue never holds more than the entry ceiling however wide a directory
/// is. A missing `root` measures empty. An entry that vanishes mid-walk stays
/// counted but contributes no bytes (git renames its temporary files while it
/// works); any other failure to read is an error, so an unmeasurable stage is
/// never taken as a small one.
///
/// # Errors
/// The path and I/O error of an entry that cannot be inspected.
pub fn measure(root: &Path, budget: &Budget) -> Result<Usage, (PathBuf, std::io::Error)> {
    measure_limits(root, &budget.limits())
}

/// [`measure`] against bare [`Limits`].
fn measure_limits(root: &Path, limits: &Limits) -> Result<Usage, (PathBuf, std::io::Error)> {
    let mut usage = Usage::default();
    let root_meta = match std::fs::symlink_metadata(root) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(usage),
        Err(e) => return Err((root.to_path_buf(), e)),
    };
    if !root_meta.is_dir() {
        usage.entries = 1;
        if root_meta.is_file() {
            usage.bytes = root_meta.len();
        }
        return Ok(usage);
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let listing = match std::fs::read_dir(&dir) {
            Ok(listing) => listing,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err((dir, e)),
        };
        for entry in listing {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err((dir, e)),
            };
            usage.entries = usage.entries.saturating_add(1);
            let path = entry.path();
            match std::fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_dir() => pending.push(path),
                Ok(meta) if meta.is_file() => usage.bytes = usage.bytes.saturating_add(meta.len()),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err((path, e)),
            }
            if exceeded(usage, limits).is_some() {
                return Ok(usage);
            }
        }
    }
    Ok(usage)
}

/// The first disk ceiling of `limits` that `usage` passes, if any.
const fn exceeded(usage: Usage, limits: &Limits) -> Option<IngestLimit> {
    if usage.bytes > limits.disk_bytes {
        Some(IngestLimit::Bytes(limits.disk_bytes))
    } else if usage.entries > limits.disk_entries {
        Some(IngestLimit::Entries(limits.disk_entries))
    } else {
        None
    }
}

/// What a watched child left behind once it exited within budget.
#[derive(Debug)]
pub struct Captured {
    /// The child's exit status.
    pub status: ExitStatus,
    /// The child's stdout, within the budget's stdout ceiling.
    pub stdout: Vec<u8>,
    /// The child's stderr, truncated at [`CHILD_STDERR_MAX_BYTES`].
    pub stderr: Vec<u8>,
}

/// One of a child's two output pipes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    /// The child's standard output.
    Stdout,
    /// The child's standard error.
    Stderr,
}

impl std::fmt::Display for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        })
    }
}

/// Why a watched child produced no [`Captured`] result.
///
/// `R` is the refusal a crossed ceiling carries: an [`IngestRefusal`] for a
/// remote transfer, a [`LocalRefusal`] for a local query.
#[derive(Debug)]
pub enum RunError<R = IngestRefusal> {
    /// The child could not be started.
    Spawn(std::io::Error),
    /// Waiting on the child failed.
    Wait(std::io::Error),
    /// The staged path could not be measured.
    Measure(PathBuf, std::io::Error),
    /// The child crossed its budget and was killed.
    Exceeded(R),
    /// The child finished, but a process it started held this pipe open past the grace.
    PipeDrainTimeout(Stream),
}

impl<R> RunError<R> {
    /// The same failure with its refusal mapped through `f`.
    fn map_refusal<S>(self, f: impl FnOnce(R) -> S) -> RunError<S> {
        match self {
            Self::Spawn(e) => RunError::Spawn(e),
            Self::Wait(e) => RunError::Wait(e),
            Self::Measure(path, e) => RunError::Measure(path, e),
            Self::Exceeded(refusal) => RunError::Exceeded(f(refusal)),
            Self::PipeDrainTimeout(stream) => RunError::PipeDrainTimeout(stream),
        }
    }
}

impl<R: std::fmt::Display> std::fmt::Display for RunError<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(e) => write!(f, "could not start the transfer: {e}"),
            Self::Wait(e) => write!(f, "could not wait for the transfer: {e}"),
            Self::Measure(path, e) => write!(f, "could not measure {}: {e}", path.display()),
            Self::Exceeded(refusal) => refusal.fmt(f),
            Self::PipeDrainTimeout(stream) => {
                f.write_str(&crate::text::cli_child_pipe_held(stream))
            }
        }
    }
}

/// One remote transfer in progress: its budget and the instant it began.
///
/// Every child run under the same `Transfer` is held to the one deadline
/// `started + budget.wall`, so a transfer of several steps cannot take longer
/// than its budget by restarting the clock per step.
#[derive(Debug, Clone, Copy)]
pub struct Transfer {
    budget: Budget,
    started: Instant,
}

impl Transfer {
    /// Begin a transfer under `budget`; its clock starts now.
    #[must_use]
    pub fn begin(budget: Budget) -> Self {
        Self {
            budget,
            started: Instant::now(),
        }
    }

    /// This transfer with its stdout ceiling set to `bytes`, for one step whose
    /// output is the data it reads rather than a diagnostic.
    ///
    /// The deadline and every other ceiling stay those of this transfer.
    #[must_use]
    pub const fn with_stdout_ceiling(&self, bytes: ByteBudget) -> Self {
        let mut budget = self.budget;
        budget.stdout_bytes = bytes;
        Self {
            budget,
            started: self.started,
        }
    }

    /// The refusal naming this transfer's surface and `limit`.
    #[must_use]
    pub const fn refusal(&self, limit: IngestLimit) -> IngestRefusal {
        IngestRefusal {
            source: self.budget.source,
            limit,
            name: None,
        }
    }

    /// Run `command` under this transfer's budget and deadline.
    fn run(
        &self,
        command: Command,
        stdin: Option<Zeroizing<Vec<u8>>>,
        watch: Option<&Path>,
        mode: Mode,
    ) -> Result<Captured, RunError> {
        run_core(
            command,
            stdin,
            watch,
            &self.budget.limits(),
            self.started,
            mode,
        )
        .map_err(|e| e.map_refusal(|limit| self.refusal(limit)))
    }
}

/// Whether a watched child is detached from the terminal in its own process group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Its own process group: a refusal kills every process it started.
    Detached,
    /// The CLI's process group, keeping the terminal for a prompt (a signing
    /// passphrase); a refusal kills the direct child.
    Attached,
}

/// Run `command`, killing it the moment it crosses a ceiling of `limits`.
///
/// `stdin`, when given, is fed to the child on its own thread and the pipe is
/// then closed; otherwise stdin is the null device. `watch`, when given, is the
/// path the child stages its output in: its size and entry count are held to
/// the disk ceilings while the child runs and measured exactly once it exits.
/// The deadline is `started + limits.wall`. Stdout is held to its ceiling;
/// stderr is truncated at [`CHILD_STDERR_MAX_BYTES`].
fn run_core(
    mut command: Command,
    stdin: Option<Zeroizing<Vec<u8>>>,
    watch: Option<&Path>,
    limits: &Limits,
    started: Instant,
    mode: Mode,
) -> Result<Captured, RunError<IngestLimit>> {
    let out_of_time = || started.elapsed() >= limits.wall;
    if out_of_time() {
        return Err(RunError::Exceeded(IngestLimit::Time(limits.wall)));
    }
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut running = Running::spawn(command, mode).map_err(RunError::Spawn)?;
    let stdout = running
        .child
        .stdout
        .take()
        .map(|pipe| spawn_capture(pipe, limits.stdout_bytes))
        .transpose()
        .map_err(RunError::Spawn)?;
    let stderr = running
        .child
        .stderr
        .take()
        .map(|pipe| spawn_capture(pipe, CHILD_STDERR_MAX_BYTES.get()))
        .transpose()
        .map_err(RunError::Spawn)?;
    if let (Some(bytes), Some(pipe)) = (stdin, running.child.stdin.take()) {
        spawn_feed(pipe, bytes).map_err(RunError::Spawn)?;
    }

    let status = loop {
        if running.exited().map_err(RunError::Wait)? {
            break running.finish().map_err(RunError::Wait)?;
        }
        if out_of_time() {
            return Err(RunError::Exceeded(IngestLimit::Time(limits.wall)));
        }
        if let Some(path) = watch {
            let usage =
                measure_limits(path, limits).map_err(|(path, e)| RunError::Measure(path, e))?;
            if let Some(limit) = exceeded(usage, limits) {
                return Err(RunError::Exceeded(limit));
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    };

    if let Some(path) = watch {
        let usage = measure_limits(path, limits).map_err(|(path, e)| RunError::Measure(path, e))?;
        if let Some(limit) = exceeded(usage, limits) {
            return Err(RunError::Exceeded(limit));
        }
    }
    let (stdout, stdout_over) = drain(stdout.as_ref(), Stream::Stdout)?;
    if stdout_over {
        return Err(RunError::Exceeded(IngestLimit::Bytes(limits.stdout_bytes)));
    }
    let (stderr, _) = drain(stderr.as_ref(), Stream::Stderr)?;
    Ok(Captured {
        status,
        stdout,
        stderr,
    })
}

/// A spawned child that is killed and reaped however the watcher leaves it.
///
/// The order is fixed: kill the group, deregister it from the signal relay,
/// then reap the leader. Until the leader is reaped its process ID, which is
/// also the group ID, cannot be reused, so no kill can reach an unrelated group.
struct Running {
    child: Child,
    group: Option<group::GroupId>,
    reaped: bool,
}

impl Running {
    /// Spawn `command` in `mode` through the runtime's hardened spawner, bound
    /// to the CLI's lifetime where the platform allows.
    fn spawn(command: Command, mode: Mode) -> std::io::Result<Self> {
        let (child, group) = match mode {
            Mode::Detached => group::spawn_detached(command)?,
            Mode::Attached => (ipe_runtime_rust::system::spawn_hardened(command)?, None),
        };
        Ok(Self {
            child,
            group,
            reaped: false,
        })
    }

    /// Whether the child has exited, leaving it unreaped where it leads a group.
    fn exited(&mut self) -> std::io::Result<bool> {
        match self.group {
            Some(id) => group::exited(id),
            None => self.child.try_wait().map(|status| status.is_some()),
        }
    }

    /// Kill what the exited child left running in its group, then reap it.
    ///
    /// # Errors
    /// Waiting failed, or a relayed signal ended every transfer
    /// ([`std::io::ErrorKind::Interrupted`]): the relay may have killed the
    /// child, so its status is not the transfer's outcome.
    fn finish(&mut self) -> std::io::Result<ExitStatus> {
        if let Some(id) = self.group.take() {
            group::kill(id);
            group::forget(id);
        }
        let status = self.child.wait();
        self.reaped = true;
        if group::ended() {
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        status
    }

    /// Kill the child (and its group) and reap it, unless already reaped.
    fn stop(&mut self) {
        if self.reaped {
            return;
        }
        if let Some(id) = self.group.take() {
            group::kill(id);
            group::forget(id);
        }
        // The child may already have exited; either way it is reaped below.
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.reaped = true;
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A child's own process group, on the Unix platforms that can peek at an exit with `waitid`.
#[cfg(all(unix, not(any(target_os = "openbsd", target_os = "redox"))))]
mod group {
    use std::os::unix::process::CommandExt as _;
    use std::process::{Child, Command};
    use std::sync::{Mutex, PoisonError};

    use rustix::process::{Pid, Signal, WaitId, WaitidOptions};

    /// A live group's ID: its leader's process ID.
    pub type GroupId = Pid;

    /// The groups spawned and not yet killed, for the signal relay.
    struct Registry {
        /// Every live group.
        live: Vec<Pid>,
        /// Whether a relayed signal ended every transfer; no group starts after it.
        ended: bool,
    }

    impl Registry {
        /// Admit a new group, unless a relayed signal ended every transfer.
        fn admit(&self) -> std::io::Result<()> {
            if self.ended {
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            Ok(())
        }
    }

    static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
        live: Vec::new(),
        ended: false,
    });

    /// Spawn `command` as the leader of a new process group.
    ///
    /// The group is registered with the relay while the registry is held, so a
    /// relayed signal either sees the group or runs before it exists.
    ///
    /// # Errors
    /// The relay could not be installed, a relayed signal ended every transfer
    /// ([`std::io::ErrorKind::Interrupted`]), or the spawn failed.
    pub fn spawn_detached(mut command: Command) -> std::io::Result<(Child, Option<Pid>)> {
        super::relay::ensure()?;
        command.process_group(0);
        let mut registry = REGISTRY.lock().unwrap_or_else(PoisonError::into_inner);
        registry.admit()?;
        let child = ipe_runtime_rust::system::spawn_hardened(command)?;
        let pid = Pid::from_child(&child);
        registry.live.push(pid);
        drop(registry);
        Ok((child, Some(pid)))
    }

    /// Whether the leader `id` has exited, without reaping it.
    pub fn exited(id: Pid) -> std::io::Result<bool> {
        match rustix::process::waitid(
            WaitId::Pid(id),
            WaitidOptions::EXITED | WaitidOptions::NOHANG | WaitidOptions::NOWAIT,
        ) {
            Ok(status) => Ok(status.is_some()),
            Err(rustix::io::Errno::INTR) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Kill every process in group `id`.
    pub fn kill(id: Pid) {
        // A group whose members have all exited is already gone.
        let _ = rustix::process::kill_process_group(id, Signal::Kill);
    }

    /// Deregister group `id` from the relay.
    pub fn forget(id: Pid) {
        REGISTRY
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .live
            .retain(|live| *live != id);
    }

    /// Send `signal` to every registered group.
    pub fn signal_all(signal: Signal) {
        let registry = REGISTRY.lock().unwrap_or_else(PoisonError::into_inner);
        for id in &registry.live {
            let _ = rustix::process::kill_process_group(*id, signal);
        }
    }

    /// Kill every registered group and refuse every later one.
    pub fn end_all() {
        let mut registry = REGISTRY.lock().unwrap_or_else(PoisonError::into_inner);
        registry.ended = true;
        for id in &registry.live {
            let _ = rustix::process::kill_process_group(*id, Signal::Kill);
        }
    }

    /// Whether a relayed signal ended every transfer.
    pub fn ended() -> bool {
        REGISTRY
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .ended
    }

    #[cfg(test)]
    mod tests {
        use super::Registry;

        #[test]
        fn an_ended_registry_refuses_every_new_group() {
            let mut registry = Registry {
                live: Vec::new(),
                ended: false,
            };
            assert!(registry.admit().is_ok());
            registry.ended = true;
            assert_eq!(
                registry.admit().map_err(|e| e.kind()),
                Err(std::io::ErrorKind::Interrupted)
            );
        }
    }
}

/// No process groups here: a refusal kills the direct child only.
#[cfg(not(all(unix, not(any(target_os = "openbsd", target_os = "redox")))))]
mod group {
    use std::process::{Child, Command};

    /// Uninhabited: no group is ever created on this platform.
    #[derive(Debug, Clone, Copy)]
    pub enum GroupId {}

    /// Spawn `command` as a plain child.
    pub fn spawn_detached(command: Command) -> std::io::Result<(Child, Option<GroupId>)> {
        Ok((ipe_runtime_rust::system::spawn_hardened(command)?, None))
    }

    /// Unreachable: no `GroupId` exists.
    pub const fn exited(id: GroupId) -> std::io::Result<bool> {
        match id {}
    }

    /// Unreachable: no `GroupId` exists.
    pub const fn kill(id: GroupId) {
        match id {}
    }

    /// Unreachable: no `GroupId` exists.
    pub const fn forget(id: GroupId) {
        match id {}
    }

    /// Never: no relay runs without process groups.
    pub const fn ended() -> bool {
        false
    }
}

/// Relays the interrupt, quit, hangup, stop and continue signals to every detached group.
///
/// A detached group is outside the terminal's foreground group, so these
/// signals reach only the CLI. Each relayed signal is handled by what the CLI
/// inherited for it:
///
/// - inherited as ignored: it is not registered, so it stays ignored for the
///   CLI and its transfers (a `nohup`'d CLI keeps its transfer through a hangup);
/// - inherited with the default action: an interrupt, quit or hangup kills
///   every group and the CLI then ends by the signal; a stop stops every group
///   and then the CLI;
/// - inherited disposition unreadable: the signal is relayed to the groups
///   only, and the CLI never takes a default action it may have inherited as
///   ignored. An interrupt, quit or hangup kills every group and refuses every
///   later one, so the command ends with an error rather than by the signal; a
///   stop stops only the groups, which the transfer deadline still bounds.
///   Leaving the signal unregistered instead would let a default-action
///   interrupt end the CLI and orphan the transfer, unbounded where no
///   parent-death signal reaches it.
///
/// A continue is always relayed: the kernel resumes the CLI whatever it
/// inherited. The inherited set is read from `/proc/self/status` on Linux and
/// from `/bin/ps -o sigignore=` elsewhere.
#[cfg(all(unix, not(any(target_os = "openbsd", target_os = "redox"))))]
mod relay {
    use std::ffi::c_int;
    use std::sync::OnceLock;

    use rustix::process::Signal;
    use signal_hook::consts::{SIGCONT, SIGHUP, SIGINT, SIGQUIT, SIGTSTP};
    use signal_hook::iterator::Signals;

    /// What a relayed signal does to the process that takes its default action.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Effect {
        /// Ends it: an interrupt, quit or hangup.
        Ends,
        /// Stops it: a terminal stop.
        Stops,
        /// Resumes it.
        Continues,
    }

    /// The signals relayed to the detached groups, each with its default effect.
    const RELAYED: [(c_int, Effect); 5] = [
        (SIGINT, Effect::Ends),
        (SIGQUIT, Effect::Ends),
        (SIGHUP, Effect::Ends),
        (SIGTSTP, Effect::Stops),
        (SIGCONT, Effect::Continues),
    ];

    /// A set of signals, bit `n - 1` standing for signal `n`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct SignalSet(u64);

    impl SignalSet {
        /// Whether `signal` is in the set; a number outside `1..=64` never is.
        fn contains(self, signal: c_int) -> bool {
            u32::try_from(signal)
                .ok()
                .and_then(|number| number.checked_sub(1))
                .and_then(|bit| 1u64.checked_shl(bit))
                .is_some_and(|bit| self.0 & bit != 0)
        }
    }

    /// The signal dispositions the CLI inherited.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Inherited {
        /// The set of signals inherited as ignored; every other relayed signal
        /// has its default action.
        Known(SignalSet),
        /// The inherited dispositions could not be read.
        Unknown,
    }

    /// How the relay handles one signal.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Handling {
        /// Not registered: the inherited disposition stays in force.
        Unregistered,
        /// Relayed to the groups, then the CLI takes the default action.
        RelayThenDefault,
        /// Relayed to the groups only.
        RelayOnly,
    }

    impl Inherited {
        /// The dispositions this process inherited.
        fn read() -> Self {
            ignored_set().map_or(Self::Unknown, Self::Known)
        }

        /// How the relay handles `signal`, whose default action has `effect`.
        fn handling(self, signal: c_int, effect: Effect) -> Handling {
            match effect {
                Effect::Continues => Handling::RelayOnly,
                Effect::Ends | Effect::Stops => match self {
                    Self::Known(set) if set.contains(signal) => Handling::Unregistered,
                    Self::Known(_) => Handling::RelayThenDefault,
                    Self::Unknown => Handling::RelayOnly,
                },
            }
        }
    }

    /// One registered signal: its default effect and how it is handled.
    #[derive(Debug, Clone, Copy)]
    struct Step {
        signal: c_int,
        effect: Effect,
        handling: Handling,
    }

    /// Every relayed signal the relay registers under `inherited`.
    fn plan(inherited: Inherited) -> Vec<Step> {
        RELAYED
            .into_iter()
            .map(|(signal, effect)| Step {
                signal,
                effect,
                handling: inherited.handling(signal, effect),
            })
            .filter(|step| step.handling != Handling::Unregistered)
            .collect()
    }

    /// Whether the relay was installed, once per process.
    static INSTALLED: OnceLock<Result<(), std::io::ErrorKind>> = OnceLock::new();

    /// Install the relay if it is not yet installed.
    ///
    /// # Errors
    /// The relay could not be installed; no group may then be detached, since
    /// the terminal's keys could no longer reach it.
    pub fn ensure() -> std::io::Result<()> {
        (*INSTALLED.get_or_init(install)).map_err(std::io::Error::from)
    }

    /// Register the relayed signals and start the relay thread.
    fn install() -> Result<(), std::io::ErrorKind> {
        let steps = plan(Inherited::read());
        let wanted: Vec<c_int> = steps.iter().map(|step| step.signal).collect();
        let mut signals = Signals::new(&wanted).map_err(|e| e.kind())?;
        std::thread::Builder::new()
            .name("ipe-transfer-signals".to_owned())
            .spawn(move || {
                for signal in signals.forever() {
                    if let Some(step) = steps.iter().find(|step| step.signal == signal) {
                        dispatch(*step);
                    }
                }
            })
            .map(drop)
            .map_err(|e| e.kind())
    }

    /// Act on one relayed signal.
    fn dispatch(step: Step) {
        match step.effect {
            Effect::Ends => super::group::end_all(),
            Effect::Stops => super::group::signal_all(Signal::Stop),
            Effect::Continues => super::group::signal_all(Signal::Cont),
        }
        match step.handling {
            Handling::RelayThenDefault => {
                let _ = signal_hook::low_level::emulate_default_handler(step.signal);
            }
            Handling::RelayOnly | Handling::Unregistered => {}
        }
    }

    /// The signals this process inherited as ignored, read from `/proc/self/status`.
    #[cfg(target_os = "linux")]
    fn ignored_set() -> Option<SignalSet> {
        use std::io::Read as _;
        let mut status = String::new();
        std::fs::File::open("/proc/self/status")
            .ok()?
            .take(64 * 1024)
            .read_to_string(&mut status)
            .ok()?;
        sig_ign_mask(&status).map(SignalSet)
    }

    /// The signals this process inherited as ignored, read through `ps`.
    #[cfg(not(target_os = "linux"))]
    fn ignored_set() -> Option<SignalSet> {
        ps_ignored(std::process::id())
    }

    /// The `SigIgn:` mask of a `/proc/<pid>/status` text.
    #[cfg(target_os = "linux")]
    pub fn sig_ign_mask(status: &str) -> Option<u64> {
        status
            .lines()
            .find_map(|line| line.strip_prefix("SigIgn:"))
            .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
    }

    /// The signals process `pid` ignores, as `/bin/ps -o sigignore=` reports them.
    ///
    /// `ps` runs attached, with an empty environment and its absolute path, so
    /// neither `PATH` nor the environment chooses the program; a missing or
    /// failing `ps` reads as unknown.
    #[cfg(any(not(target_os = "linux"), test))]
    fn ps_ignored(pid: u32) -> Option<SignalSet> {
        let mut command = std::process::Command::new("/bin/ps");
        command
            .env_clear()
            .args(["-o", "sigignore=", "-p"])
            .arg(pid.to_string());
        let limits = super::Limits {
            disk_bytes: 0,
            disk_entries: 0,
            stdout_bytes: PS_STDOUT_MAX_BYTES,
            wall: PS_WALL,
        };
        let captured = super::run_core(
            command,
            None,
            None,
            &limits,
            std::time::Instant::now(),
            super::Mode::Attached,
        )
        .ok()?;
        if !captured.status.success() {
            return None;
        }
        ps_mask(&captured.stdout).map(SignalSet)
    }

    /// The most `ps` may print for one process's mask.
    #[cfg(any(not(target_os = "linux"), test))]
    const PS_STDOUT_MAX_BYTES: u64 = 256;

    /// The longest `ps` may take to report one process's mask.
    #[cfg(any(not(target_os = "linux"), test))]
    const PS_WALL: std::time::Duration = std::time::Duration::from_secs(5);

    /// The hexadecimal mask `ps -o sigignore=` printed: one field of hex digits.
    #[cfg(any(not(target_os = "linux"), test))]
    fn ps_mask(stdout: &[u8]) -> Option<u64> {
        let text = std::str::from_utf8(stdout).ok()?.trim();
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        u64::from_str_radix(text, 16).ok()
    }

    #[cfg(test)]
    mod tests {
        use super::{Effect, Handling, Inherited, SignalSet, plan, ps_mask};
        use signal_hook::consts::{SIGCONT, SIGHUP, SIGINT, SIGQUIT, SIGTSTP};
        use std::io::Write as _;

        /// The set holding exactly `signals`.
        fn set(signals: &[i32]) -> SignalSet {
            SignalSet(signals.iter().fold(0, |mask, signal| {
                let bit = u32::try_from(*signal - 1).expect("a signal number");
                mask | (1u64 << bit)
            }))
        }

        #[test]
        fn a_mask_bit_marks_its_signal_ignored() {
            assert!(SignalSet(0b10).contains(2));
            assert!(!SignalSet(0b10).contains(1));
            assert!(!SignalSet(u64::MAX).contains(0));
            assert!(!SignalSet(u64::MAX).contains(-1));
            assert!(!SignalSet(u64::MAX).contains(65));
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn the_sigign_line_parses_as_hex() {
            let status = "Name:\tipe\nSigBlk:\t0000000000000000\nSigIgn:\t0000000000000001\n";
            assert_eq!(super::sig_ign_mask(status), Some(1));
            assert_eq!(super::sig_ign_mask("Name:\tipe\n"), None);
            assert_eq!(super::sig_ign_mask("SigIgn:\tzz\n"), None);
        }

        #[test]
        fn a_known_ignored_signal_stays_unregistered() {
            let inherited = Inherited::Known(set(&[SIGHUP, SIGTSTP]));
            assert_eq!(
                inherited.handling(SIGHUP, Effect::Ends),
                Handling::Unregistered
            );
            assert_eq!(
                inherited.handling(SIGTSTP, Effect::Stops),
                Handling::Unregistered
            );
            assert_eq!(
                inherited.handling(SIGINT, Effect::Ends),
                Handling::RelayThenDefault
            );
            let registered: Vec<i32> = plan(inherited).iter().map(|step| step.signal).collect();
            assert_eq!(registered, [SIGINT, SIGQUIT, SIGCONT]);
        }

        #[test]
        fn unknown_relays_ends_and_stops_without_the_default() {
            for signal in [SIGINT, SIGQUIT, SIGHUP] {
                assert_eq!(
                    Inherited::Unknown.handling(signal, Effect::Ends),
                    Handling::RelayOnly
                );
            }
            assert_eq!(
                Inherited::Unknown.handling(SIGTSTP, Effect::Stops),
                Handling::RelayOnly
            );
        }

        #[test]
        fn every_relayed_signal_is_registered_when_unknown() {
            let steps = plan(Inherited::Unknown);
            let registered: Vec<i32> = steps.iter().map(|step| step.signal).collect();
            assert_eq!(registered, [SIGINT, SIGQUIT, SIGHUP, SIGTSTP, SIGCONT]);
            assert!(
                steps
                    .iter()
                    .all(|step| step.handling == Handling::RelayOnly)
            );
        }

        #[test]
        fn continue_is_always_relayed_without_the_default() {
            for inherited in [
                Inherited::Unknown,
                Inherited::Known(set(&[])),
                Inherited::Known(set(&[SIGCONT])),
            ] {
                assert_eq!(
                    inherited.handling(SIGCONT, Effect::Continues),
                    Handling::RelayOnly
                );
            }
        }

        #[test]
        fn the_ps_mask_is_one_hex_field() {
            assert_eq!(ps_mask(b"00001000\n"), Some(0x1000));
            assert_eq!(ps_mask(b"  0000000000000001  \n"), Some(1));
            assert_eq!(ps_mask(b""), None);
            assert_eq!(ps_mask(b"\n"), None);
            assert_eq!(ps_mask(b"+1"), None);
            assert_eq!(ps_mask(b"1 2"), None);
            assert_eq!(ps_mask(b"SIGHUP"), None);
            assert_eq!(ps_mask(b"10000000000000000"), None);
            assert_eq!(ps_mask(b"\xff"), None);
        }

        /// Poll `ps` for `pid` until it reports `signal` ignored, for at most 5 s.
        #[cfg(target_os = "linux")]
        fn poll_ps(pid: u32, signal: i32) -> Option<SignalSet> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let seen = super::ps_ignored(pid);
                if seen.is_some_and(|ignored| ignored.contains(signal))
                    || std::time::Instant::now() >= deadline
                {
                    return seen;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn the_ps_probe_reads_an_inherited_ignored_hangup() {
            let mut child = std::process::Command::new("/bin/sh")
                .args(["-c", "trap '' HUP; exec sleep 30"])
                .spawn()
                .expect("spawn sh");
            let pid = child.id();
            let seen = poll_ps(pid, SIGHUP);
            let proc_mask = std::fs::read_to_string(format!("/proc/{pid}/status"))
                .ok()
                .and_then(|status| super::sig_ign_mask(&status));
            let _ = child.kill();
            let _ = child.wait();
            let seen = seen.expect("ps reports a mask");
            assert!(seen.contains(SIGHUP), "ps misses the ignored hangup");
            let proc_mask = proc_mask.expect("a SigIgn line");
            assert_eq!(seen.0 & 0xffff_ffff, proc_mask & 0xffff_ffff);
        }

        /// Printed by [`hangup_child`] once its transfer outlived the hangup.
        #[cfg(target_os = "linux")]
        const SURVIVED: &str = "ipe-relay-hangup-survived";

        /// Printed by [`hangup_child_default`] just before it raises the hangup.
        #[cfg(target_os = "linux")]
        const ARMED: &str = "ipe-relay-hangup-armed";

        /// Run the ignored test `name` of this binary as a child, through `sh`
        /// running `prelude` first.
        #[cfg(target_os = "linux")]
        fn run_child(prelude: &str, name: &str) -> std::process::Output {
            let exe = std::env::current_exe().expect("the test binary");
            std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("{prelude} exec \"$0\" \"$@\""))
                .arg(exe)
                .args([
                    "--exact",
                    name,
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .output()
                .expect("run the child test")
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn an_inherited_ignored_hangup_leaves_the_cli_and_its_transfer_running() {
            let output = run_child("trap '' HUP;", "remote_ingest::relay::tests::hangup_child");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(output.status.success(), "child failed: {output:?}");
            assert!(stdout.contains(SURVIVED), "child output: {output:?}");
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn a_default_hangup_ends_the_cli() {
            use std::os::unix::process::ExitStatusExt as _;
            let parent = Inherited::read();
            if parent == Inherited::Unknown
                || matches!(parent, Inherited::Known(ignored) if ignored.contains(SIGHUP))
            {
                return;
            }
            let output = run_child(
                "trap - HUP;",
                "remote_ingest::relay::tests::hangup_child_default",
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains(ARMED), "child output: {output:?}");
            assert_eq!(output.status.signal(), Some(SIGHUP), "{output:?}");
        }

        /// The child half of the inherited-ignored hangup test: a hangup raised
        /// while a transfer group runs leaves both the CLI and the group alive.
        #[cfg(target_os = "linux")]
        #[test]
        #[ignore = "child half of an_inherited_ignored_hangup_leaves_the_cli_and_its_transfer_running"]
        fn hangup_child() {
            let Inherited::Known(inherited) = Inherited::read() else {
                return;
            };
            if !inherited.contains(SIGHUP) {
                return;
            }
            let mut sleeper = std::process::Command::new("sleep");
            sleeper.arg("30");
            let (mut child, id) =
                super::super::group::spawn_detached(sleeper).expect("spawn sleep");
            let id = id.expect("a detached group");
            signal_hook::low_level::raise(SIGHUP).expect("raise the hangup");
            std::thread::sleep(std::time::Duration::from_millis(500));
            let alive = !super::super::group::exited(id).expect("probe the group");
            super::super::group::kill(id);
            super::super::group::forget(id);
            let _ = child.wait();
            assert!(alive, "the hangup ended the transfer group");
            writeln!(std::io::stdout(), "{SURVIVED}").expect("report the marker to the parent");
        }

        /// The child half of the default hangup test: the relay kills the
        /// group and the CLI ends by the hangup.
        #[cfg(target_os = "linux")]
        #[test]
        #[ignore = "child half of a_default_hangup_ends_the_cli"]
        fn hangup_child_default() {
            let mut sleeper = std::process::Command::new("sleep");
            sleeper.arg("30");
            let (mut child, _) = super::super::group::spawn_detached(sleeper).expect("spawn sleep");
            writeln!(std::io::stdout(), "{ARMED}").expect("report the marker to the parent");
            signal_hook::low_level::raise(SIGHUP).expect("raise the hangup");
            std::thread::sleep(std::time::Duration::from_secs(5));
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// A pipe being read on its own thread: the bytes kept, and whether more than `cap` arrived.
type Capture = mpsc::Receiver<(Vec<u8>, bool)>;

/// Read `pipe` on a thread, keeping at most `cap` bytes and draining the rest.
fn spawn_capture(pipe: impl Read + Send + 'static, cap: u64) -> std::io::Result<Capture> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("ipe-child-capture".to_owned())
        .spawn(move || {
            let _ = tx.send(capture(pipe, cap));
        })?;
    Ok(rx)
}

/// Write `bytes` to `pipe` on a thread, then close it.
///
/// The write runs beside the output captures, so a child that echoes more
/// than a pipe buffer before reading the rest of its input cannot deadlock.
fn spawn_feed(
    mut pipe: impl std::io::Write + Send + 'static,
    bytes: Zeroizing<Vec<u8>>,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("ipe-child-stdin".to_owned())
        .spawn(move || {
            // A child that exits without reading its stdin is judged by its
            // exit status, not by this write.
            let _ = pipe.write_all(&bytes);
        })
        .map(drop)
}

/// Keep at most `cap` bytes of `pipe`, then read the rest into a sink.
///
/// The flag reports whether anything past `cap` arrived. The pipe is drained to
/// its end so the child never blocks on a full pipe.
fn capture(mut pipe: impl Read, cap: u64) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let _ = (&mut pipe).take(cap).read_to_end(&mut kept);
    let over = std::io::copy(&mut pipe, &mut std::io::sink()).is_ok_and(|rest| rest > 0);
    (kept, over)
}

/// Collect a capture thread's result, giving up after [`PIPE_DRAIN_GRACE`].
fn drain(
    capture: Option<&Capture>,
    stream: Stream,
) -> Result<(Vec<u8>, bool), RunError<IngestLimit>> {
    capture.map_or_else(
        || Ok((Vec::new(), false)),
        |capture| {
            capture
                .recv_timeout(PIPE_DRAIN_GRACE)
                .map_err(|_| RunError::PipeDrainTimeout(stream))
        },
    )
}

/// The one constructor of a `git` child, with its environment and configuration fixed.
///
/// Both flavours clear the variables that would redirect git at another
/// repository, never prompt on the terminal, never run a hook, never start a
/// background maintenance or file-system monitor, and never download large
/// files through a filter.
pub struct Git {
    command: Command,
}

/// The `GIT_ALLOW_PROTOCOL` list of an isolated git: exactly the
/// [`Transport`](crate::index::Transport) set a source URL can parse to.
const ISOLATED_GIT_PROTOCOLS: &str = "https:ssh:file";

// The isolated protocol list is exactly the source-URL transports, in order,
// so a transport added or dropped on either side breaks the build.
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the isolated git's protocol list drifts from the source-URL transports [ledger #boundary]
const _: () = assert!(names_every_transport(ISOLATED_GIT_PROTOCOLS));

/// Whether `list` is exactly the `:`-joined
/// [`git_protocol`](crate::index::Transport::git_protocol) names of
/// [`Transport::ALL`](crate::index::Transport::ALL), in order.
const fn names_every_transport(list: &str) -> bool {
    let mut rest = list.as_bytes();
    let mut transports: &[crate::index::Transport] = &crate::index::Transport::ALL;
    let mut first = true;
    while let [transport, later @ ..] = transports {
        if !first {
            match rest {
                [b':', tail @ ..] => rest = tail,
                _ => return false,
            }
        }
        first = false;
        let name = transport.git_protocol().as_bytes();
        let Some((head, tail)) = rest.split_at_checked(name.len()) else {
            return false;
        };
        if !bytes_equal(head, name) {
            return false;
        }
        rest = tail;
        transports = later;
    }
    rest.is_empty()
}

/// Byte-wise equality usable in a `const` context.
const fn bytes_equal(mut left: &[u8], mut right: &[u8]) -> bool {
    loop {
        match (left, right) {
            ([], []) => return true,
            ([l, left_tail @ ..], [r, right_tail @ ..]) if *l == *r => {
                left = left_tail;
                right = right_tail;
            }
            _ => return false,
        }
    }
}

/// Variables that point git at a repository other than the working directory's.
const GIT_LOCATION_VARS: [&str; 7] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
];

/// Variables that inject configuration or a helper program into git from the environment.
const GIT_INJECTION_VARS: [&str; 7] = [
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_SSH_COMMAND",
    "GIT_SSH",
    "GIT_ASKPASS",
    "GIT_PROXY_COMMAND",
    "GIT_TEMPLATE_DIR",
];

impl Git {
    /// The shared hardening of both flavours, run in `cwd`.
    fn base(cwd: &Path) -> Command {
        let mut command = Command::new("git");
        command.current_dir(cwd);
        for var in GIT_LOCATION_VARS {
            command.env_remove(var);
        }
        command
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_LFS_SKIP_SMUDGE", "1")
            .args(["-c", "core.hooksPath=/dev/null"])
            .args(["-c", "gc.auto=0"])
            .args(["-c", "maintenance.auto=false"])
            .args(["-c", "core.fsmonitor=false"]);
        command
    }

    /// git on a repository the CLI owns and fills from a remote, blind to every user and system setting.
    ///
    /// No system or global configuration is read and no configuration, helper
    /// or template is taken from the environment, so a setting cannot swap the
    /// transport, run a program, or rewrite a URL. Only the
    /// `ISOLATED_GIT_PROTOCOLS` transports are allowed; ssh runs in batch mode,
    /// submodules are not fetched, and every fetched object stays in one pack
    /// rather than unpacking into loose files, so the stage's entry count is
    /// bounded by [`GIT_STAGE_OVERHEAD_ENTRIES`] beyond the tree and its refs.
    /// No single allocation git makes may exceed the package per-file ceiling
    /// (`GIT_ALLOC_LIMIT`), so one oversized object dies in git rather than
    /// being held in memory.
    #[must_use]
    pub fn isolated(cwd: &Path) -> Self {
        let mut command = Self::base(cwd);
        for var in GIT_INJECTION_VARS {
            command.env_remove(var);
        }
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_ALLOW_PROTOCOL", ISOLATED_GIT_PROTOCOLS)
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env(
                "GIT_ALLOC_LIMIT",
                PACKAGE_SOURCE.tree().per_file().to_string(),
            )
            .args(["-c", "core.sshCommand=ssh -o BatchMode=yes"])
            .args(["-c", "fetch.recurseSubmodules=false"])
            .args(["-c", "transfer.unpackLimit=1"]);
        Self { command }
    }

    /// git on the author's own repository or on the author's behalf.
    ///
    /// The user's configuration is kept, because publishing needs it: a push
    /// authenticates through the author's credential helper, and a commit is
    /// signed with the author's key. Only the `https` transport is allowed, and
    /// no large-file filter runs.
    #[must_use]
    pub fn user(cwd: &Path) -> Self {
        let mut command = Self::base(cwd);
        command
            .env("GIT_ALLOW_PROTOCOL", "https")
            .args(["-c", "filter.lfs.smudge="])
            .args(["-c", "filter.lfs.process="])
            .args(["-c", "filter.lfs.required=false"]);
        Self { command }
    }

    /// Append `args` (the subcommand and its arguments).
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.command.args(args);
        self
    }

    /// Append one argument.
    #[must_use]
    pub fn arg(mut self, arg: impl AsRef<std::ffi::OsStr>) -> Self {
        self.command.arg(arg);
        self
    }

    /// Run detached in its own process group under `transfer`, watching `watch`.
    ///
    /// # Errors
    /// See [`RunError`].
    pub fn run_detached(
        self,
        watch: Option<&Path>,
        transfer: &Transfer,
    ) -> Result<Captured, RunError> {
        transfer.run(self.command, None, watch, Mode::Detached)
    }

    /// Run in the CLI's process group under `transfer`, keeping the terminal for a signing prompt.
    ///
    /// # Errors
    /// See [`RunError`].
    pub fn run_attached(self, transfer: &Transfer) -> Result<Captured, RunError> {
        transfer.run(self.command, None, None, Mode::Attached)
    }

    /// Run a local query, held to a query's output and time ceilings.
    ///
    /// # Errors
    /// See [`RunError`]; a crossed ceiling is a [`LocalRefusal`] naming `source`.
    pub fn query(self, source: LocalSource) -> Result<Captured, RunError<LocalRefusal>> {
        run_core(
            self.command,
            None,
            None,
            &QUERY_LIMITS,
            Instant::now(),
            Mode::Detached,
        )
        .map_err(|e| {
            e.map_refusal(|limit| LocalRefusal {
                source,
                limit,
                name: None,
            })
        })
    }

    /// The arguments given so far.
    #[cfg(test)]
    pub fn get_args(&self) -> std::process::CommandArgs<'_> {
        self.command.get_args()
    }
}

/// The one constructor of a `curl` child: HTTPS only, blind to the user's `.curlrc`.
pub struct Curl {
    command: Command,
}

impl Curl {
    /// A curl that ignores `.curlrc` and speaks only HTTPS, redirects included.
    #[must_use]
    pub fn https() -> Self {
        Self::https_of(Command::new("curl"))
    }

    /// [`Curl::https`] over the executable at `program`, for a test's fake `curl`.
    #[cfg(test)]
    #[must_use]
    pub fn https_at(program: &Path) -> Self {
        Self::https_of(Command::new(program))
    }

    /// `command` restricted to HTTPS and blind to `.curlrc`.
    fn https_of(mut command: Command) -> Self {
        // `-q` is honoured only as the first argument.
        command.args(["-q", "--proto", "=https", "--proto-redir", "=https"]);
        Self { command }
    }

    /// Append `args`.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.command.args(args);
        self
    }

    /// Append one argument.
    #[must_use]
    pub fn arg(mut self, arg: impl AsRef<std::ffi::OsStr>) -> Self {
        self.command.arg(arg);
        self
    }

    /// Run detached in its own process group under `transfer`.
    ///
    /// `stdin`, when given, is copied into a buffer wiped after the write and
    /// fed to curl (a `--config -` header, a `-d @-` body).
    ///
    /// # Errors
    /// See [`RunError`].
    pub fn run(
        self,
        stdin: Option<&[u8]>,
        watch: Option<&Path>,
        transfer: &Transfer,
    ) -> Result<Captured, RunError> {
        let stdin = stdin.map(|bytes| Zeroizing::new(bytes.to_vec()));
        transfer.run(self.command, stdin, watch, Mode::Detached)
    }

    /// The arguments given so far.
    #[cfg(test)]
    pub fn get_args(&self) -> std::process::CommandArgs<'_> {
        self.command.get_args()
    }
}

/// A `git` for building a test fixture repository, blind to the developer's configuration.
#[cfg(test)]
#[must_use]
pub fn fixture_git(dir: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t");
    for var in GIT_LOCATION_VARS {
        command.env_remove(var);
    }
    command
}

/// curl's exit code for a response larger than `--max-filesize`.
const CURL_FILESIZE_EXCEEDED: i32 = 63;

/// curl's exit code for a transfer cut off by `--max-time`.
const CURL_OPERATION_TIMEDOUT: i32 = 28;

/// The curl arguments holding one transfer to `response_bytes` and `budget`'s wall time.
///
/// curl stops early on a declared oversized length and on the deadline; the
/// watcher and the bounded read-back remain the backstop for a length curl
/// cannot know in advance.
#[must_use]
pub fn curl_limit_args(response_bytes: ByteBudget, budget: &Budget) -> [String; 4] {
    [
        "--max-filesize".to_owned(),
        response_bytes.get().to_string(),
        "--max-time".to_owned(),
        budget.wall.as_secs().to_string(),
    ]
}

/// The refusal a curl exit reports when curl stopped at a [`curl_limit_args`] limit.
#[must_use]
pub fn curl_refusal(
    status: ExitStatus,
    response_bytes: ByteBudget,
    budget: &Budget,
) -> Option<IngestRefusal> {
    let limit = match status.code()? {
        CURL_FILESIZE_EXCEEDED => IngestLimit::Bytes(response_bytes.get()),
        CURL_OPERATION_TIMEDOUT => IngestLimit::Time(budget.wall),
        _ => return None,
    };
    Some(IngestRefusal {
        source: budget.source,
        limit,
        name: None,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        Budget, BudgetPairing, ByteBudget, CappedReadError, Captured, EntryBudget, FetchBudget,
        GITHUB_API, Git, IngestLimit, IngestRefusal, IngestSource, LocalRefusal, LocalSource,
        MAX_REMOTE_BYTES, MAX_REMOTE_ENTRIES, Mode, PACKAGE_SOURCE, PackageName, RefsCeiling,
        RunError, Stream, Transfer, TreeCeiling, Usage, curl_limit_args, curl_refusal, measure,
        read_capped, run_core,
    };
    use std::process::Command;
    use std::time::{Duration, Instant};

    const CAP: u64 = 16;

    /// The byte ceiling `n`, zero naming a surface that stages nothing.
    #[allow(clippy::expect_used)] // fixture ceilings are literal in-range values
    fn bytes(n: u64) -> ByteBudget {
        if n == 0 {
            ByteBudget::NONE
        } else {
            ByteBudget::for_test(n).expect("in-range byte budget")
        }
    }

    /// The entry ceiling `n`, zero naming a surface that stages nothing.
    #[allow(clippy::expect_used)] // fixture ceilings are literal in-range values
    fn entries(n: u64) -> EntryBudget {
        if n == 0 {
            EntryBudget::NONE
        } else {
            EntryBudget::for_test(n).expect("in-range entry budget")
        }
    }

    fn budget(disk_bytes: u64, disk_entries: u64) -> Budget {
        PACKAGE_SOURCE
            .transfer()
            .with_disk_bytes(bytes(disk_bytes))
            .with_disk_entries(entries(disk_entries))
            .with_stdout(bytes(CAP))
            .with_wall(Duration::from_secs(30))
    }

    /// A byte or entry ceiling exists only inside `1..=MAX`; zero and one past are refused.
    #[test]
    fn a_ceiling_outside_its_range_is_refused() {
        assert_eq!(ByteBudget::for_test(0), None);
        assert_eq!(ByteBudget::for_test(1).map(ByteBudget::get), Some(1));
        assert_eq!(
            ByteBudget::for_test(MAX_REMOTE_BYTES).map(ByteBudget::get),
            Some(MAX_REMOTE_BYTES)
        );
        assert_eq!(ByteBudget::for_test(MAX_REMOTE_BYTES + 1), None);
        assert_eq!(EntryBudget::for_test(0), None);
        assert_eq!(EntryBudget::for_test(1).map(EntryBudget::get), Some(1));
        assert_eq!(
            EntryBudget::for_test(MAX_REMOTE_ENTRIES).map(EntryBudget::get),
            Some(MAX_REMOTE_ENTRIES)
        );
        assert_eq!(EntryBudget::for_test(MAX_REMOTE_ENTRIES + 1), None);
    }

    /// Every named surface budget sits inside the remote ceilings.
    #[test]
    fn every_named_budget_is_within_the_remote_ceilings() {
        let named = [
            *PACKAGE_SOURCE.transfer(),
            super::INDEX_CLONE,
            super::INDEX_PUSH,
            GITHUB_API,
            super::OAUTH_FORM,
            super::INSTALLER,
        ];
        for budget in named {
            assert!(budget.disk_bytes().get() <= MAX_REMOTE_BYTES, "{budget:?}");
            assert!(
                budget.stdout_bytes().get() <= MAX_REMOTE_BYTES,
                "{budget:?}"
            );
            assert!(
                budget.disk_entries().get() <= MAX_REMOTE_ENTRIES,
                "{budget:?}"
            );
        }
    }

    fn scratch() -> crate::scratch::ScratchDir {
        crate::scratch::ScratchDir::new("ipe-ingest-test").expect("scratch dir")
    }

    /// Run `command` detached under `budget`, its clock starting now.
    fn run(
        command: Command,
        stdin: Option<&[u8]>,
        watch: Option<&std::path::Path>,
        budget: &Budget,
    ) -> Result<Captured, RunError<IngestLimit>> {
        run_core(
            command,
            stdin.map(|bytes| zeroize::Zeroizing::new(bytes.to_vec())),
            watch,
            &budget.limits(),
            Instant::now(),
            Mode::Detached,
        )
    }

    #[test]
    fn a_body_of_exactly_the_cap_is_read_whole() {
        let body = vec![b'x'; 16];
        let read = read_capped(body.as_slice(), bytes(CAP), IngestSource::GithubApi);
        assert!(matches!(read, Ok(ref bytes) if bytes == &body));
    }

    #[test]
    fn a_body_one_byte_past_the_cap_is_refused() {
        let body = vec![b'x'; 17];
        let read = read_capped(body.as_slice(), bytes(CAP), IngestSource::GithubApi);
        assert!(matches!(
            read,
            Err(CappedReadError::Exceeded(IngestRefusal {
                source: IngestSource::GithubApi,
                limit: IngestLimit::Bytes(CAP),
                name: None,
            }))
        ));
    }

    #[test]
    fn an_endless_body_is_refused_after_cap_plus_one_bytes() {
        let read = read_capped(std::io::repeat(b'x'), bytes(CAP), IngestSource::HttpGet);
        assert!(matches!(read, Err(CappedReadError::Exceeded(_))));
    }

    #[test]
    fn a_tree_at_its_ceilings_measures_within_budget() {
        let dir = scratch();
        std::fs::create_dir(dir.path().join("sub")).expect("sub");
        std::fs::write(dir.path().join("sub").join("a"), [0u8; 10]).expect("a");
        std::fs::write(dir.path().join("b"), [0u8; 6]).expect("b");
        let budget = budget(16, 3);
        let usage = measure(dir.path(), &budget).expect("measures");
        assert_eq!(
            usage,
            Usage {
                bytes: 16,
                entries: 3
            }
        );
        assert!(super::exceeded(usage, &budget.limits()).is_none());
    }

    #[test]
    fn a_tree_one_byte_past_its_ceiling_is_over_budget() {
        let dir = scratch();
        std::fs::write(dir.path().join("a"), [0u8; 17]).expect("a");
        let budget = budget(16, 8);
        let usage = measure(dir.path(), &budget).expect("measures");
        assert_eq!(
            super::exceeded(usage, &budget.limits()),
            Some(IngestLimit::Bytes(16))
        );
    }

    #[test]
    fn a_tree_one_entry_past_its_ceiling_is_over_budget() {
        let dir = scratch();
        for name in ["a", "b", "c", "d"] {
            std::fs::write(dir.path().join(name), b"").expect("entry");
        }
        let budget = budget(1024, 3);
        let usage = measure(dir.path(), &budget).expect("measures");
        assert_eq!(
            super::exceeded(usage, &budget.limits()),
            Some(IngestLimit::Entries(3))
        );
    }

    /// An entry is counted as its directory is listed, so a directory wider
    /// than the ceiling is cut short rather than queued whole.
    #[test]
    fn a_wide_directory_stops_the_measure_at_the_entry_ceiling() {
        let dir = scratch();
        for index in 0..64 {
            std::fs::create_dir(dir.path().join(format!("d{index}"))).expect("entry");
        }
        let budget = budget(1024, 3);
        let usage = measure(dir.path(), &budget).expect("measures");
        assert_eq!(usage.entries, 4);
        assert_eq!(
            super::exceeded(usage, &budget.limits()),
            Some(IngestLimit::Entries(3))
        );
    }

    /// The production budget is paired: its tree ceiling fits inside its transfer ceiling.
    #[test]
    fn the_package_source_budget_is_paired() {
        let source = super::PACKAGE_SOURCE;
        assert!(source.pairing().is_ok());
        assert_eq!(source.transfer().source, IngestSource::PackageFetch);
        assert_eq!(source.tree().bytes(), super::PACKAGE_TREE_MAX_BYTES);
        assert_eq!(source.tree().entries(), super::PACKAGE_TREE_MAX_ENTRIES);
        assert_eq!(source.refs().count(), super::REFS_MAX_COUNT);
    }

    fn tree(bytes: u64, entries: u64) -> TreeCeiling {
        TreeCeiling::for_test(bytes, entries, bytes, 8).expect("tree ceiling")
    }

    /// Each pairing relation holds at its edge and refuses one step past it.
    #[test]
    fn an_unpaired_fetch_budget_is_refused() {
        let refs = RefsCeiling::for_test(bytes(64), 2);
        let at_bytes = budget(20, 1_000);
        assert!(FetchBudget::for_test(at_bytes, refs, tree(10, 4)).is_ok());
        assert_eq!(
            FetchBudget::for_test(budget(19, 1_000), refs, tree(10, 4)),
            Err(BudgetPairing::TransferBytesUnderTree)
        );
        let staged = 4 + 2 + super::GIT_STAGE_OVERHEAD_ENTRIES;
        assert!(FetchBudget::for_test(budget(20, staged), refs, tree(10, 4)).is_ok());
        assert_eq!(
            FetchBudget::for_test(budget(20, staged - 1), refs, tree(10, 4)),
            Err(BudgetPairing::TransferEntriesUnderTree)
        );
        assert!(TreeCeiling::for_test(10, 4, 10, 8).is_ok());
        assert_eq!(
            TreeCeiling::for_test(10, 4, 11, 8),
            Err(BudgetPairing::FileOverTree)
        );
    }

    /// Each limit renders its own phrase, and a shape refusal is not called a ceiling.
    #[test]
    fn every_limit_renders_its_phrase() {
        let cases = [
            (IngestLimit::Bytes(7), "7-byte"),
            (IngestLimit::Entries(3), "3-entry"),
            (IngestLimit::Depth(64), "64-level depth"),
            (IngestLimit::Time(Duration::from_secs(9)), "9 seconds"),
            (IngestLimit::Time(Duration::from_secs(1)), "1 second"),
            (IngestLimit::Time(Duration::from_millis(1)), "1 ms"),
            (IngestLimit::NonUtf8Name, "not valid UTF-8"),
            (IngestLimit::SpecialFile, "special file"),
            (IngestLimit::Symlink, "symbolic link"),
            (IngestLimit::MalformedRef, "malformed or unsafe ref"),
        ];
        for (limit, phrase) in cases {
            assert!(limit.to_string().contains(phrase), "{limit}");
            let ceiling = !limit.is_shape() && !matches!(limit, IngestLimit::Time(_));
            let text = LocalRefusal {
                source: LocalSource::PackageTree,
                limit,
                name: None,
            }
            .to_string();
            assert!(text.contains(phrase), "{text}");
            assert_eq!(text.contains("ceiling"), ceiling, "{text}");
            let remote = IngestRefusal {
                source: IngestSource::PackageFetch,
                limit,
                name: None,
            }
            .to_string();
            assert!(remote.contains(phrase), "{remote}");
            assert_eq!(remote.contains("ceiling"), ceiling, "{remote}");
        }
    }

    /// A package source past a size ceiling names the publisher's fix, on the
    /// transfer and on the tree alike.
    #[test]
    fn a_package_source_past_a_size_ceiling_names_the_publishers_fix() {
        for limit in [
            IngestLimit::Bytes(7),
            IngestLimit::Entries(3),
            IngestLimit::Depth(64),
        ] {
            let remote = IngestRefusal {
                source: IngestSource::PackageFetch,
                limit,
                name: None,
            }
            .to_string();
            let tree = LocalRefusal {
                source: LocalSource::PackageTree,
                limit,
                name: None,
            }
            .to_string();
            for text in [remote, tree] {
                assert!(
                    text.contains(&format!("exceeds the {limit} ceiling ipe accepts")),
                    "{text}"
                );
                assert!(text.contains("shrink the published tree"), "{text}");
                assert!(text.contains("republish"), "{text}");
                assert!(text.contains("nothing was recorded"), "{text}");
            }
        }
    }

    /// A surface other than a package source past a size ceiling is not told to
    /// republish anything.
    #[test]
    fn a_non_package_surface_past_a_size_ceiling_names_no_publisher_fix() {
        let remote = IngestRefusal {
            source: IngestSource::GithubApi,
            limit: IngestLimit::Bytes(7),
            name: None,
        }
        .to_string();
        let local = LocalRefusal {
            source: LocalSource::GitQuery,
            limit: IngestLimit::Bytes(7),
            name: None,
        }
        .to_string();
        for text in [remote, local] {
            assert!(text.contains("exceeded the 7-byte ceiling"), "{text}");
            assert!(!text.contains("republish"), "{text}");
        }
    }

    /// A transfer past its wall time says it did not finish and points at the
    /// network; a local query past its wall time does not blame the network.
    #[test]
    fn a_timed_out_refusal_says_it_did_not_finish() {
        let limit = IngestLimit::Time(Duration::from_secs(9));
        let remote = IngestRefusal {
            source: IngestSource::PackageFetch,
            limit,
            name: None,
        }
        .to_string();
        assert!(
            remote.contains("did not finish within 9 seconds"),
            "{remote}"
        );
        assert!(
            remote.contains("check the network or the source host"),
            "{remote}"
        );
        assert!(!remote.contains("republish"), "{remote}");
        let local = LocalRefusal {
            source: LocalSource::GitQuery,
            limit,
            name: None,
        }
        .to_string();
        assert!(local.contains("did not finish within 9 seconds"), "{local}");
        assert!(!local.contains("network"), "{local}");
    }

    /// A refusal the resolver named carries the package in its text; an
    /// unnamed one names only its surface.
    #[test]
    fn a_named_refusal_names_its_package() {
        let name = PackageName::parse("lib").expect("fixture name parses");
        let unnamed = IngestRefusal {
            source: IngestSource::PackageFetch,
            limit: IngestLimit::Bytes(7),
            name: None,
        };
        assert!(!unnamed.to_string().contains("`lib`"), "{unnamed}");
        let named = unnamed.with_name(&name);
        assert_eq!(named.name.as_ref(), Some(&name));
        assert!(
            named.to_string().starts_with("package fetch of `lib`: "),
            "{named}"
        );
        let tree = LocalRefusal {
            source: LocalSource::PackageTree,
            limit: IngestLimit::SpecialFile,
            name: None,
        }
        .with_name(&name);
        assert!(
            tree.to_string()
                .starts_with("package source tree of `lib`: "),
            "{tree}"
        );
    }

    /// A step with its own stdout ceiling keeps the transfer's deadline.
    #[test]
    fn a_stdout_ceiling_step_shares_the_transfer_deadline() {
        let transfer = Transfer::begin(budget(0, 0));
        let step = transfer.with_stdout_ceiling(bytes(7));
        assert_eq!(step.started, transfer.started);
        assert_eq!(step.budget.stdout_bytes, bytes(7));
        assert_eq!(step.budget.wall, transfer.budget.wall);
        assert_eq!(step.budget.disk_bytes, transfer.budget.disk_bytes);
    }

    #[test]
    fn a_missing_stage_measures_empty() {
        let dir = scratch();
        let usage = measure(&dir.path().join("absent"), &budget(0, 0)).expect("measures");
        assert_eq!(usage, Usage::default());
    }

    /// A local refusal names local work, never a remote transfer.
    #[test]
    fn a_local_refusal_does_not_claim_a_remote_transfer() {
        let refusal = LocalRefusal {
            source: LocalSource::PackageTree,
            limit: IngestLimit::Bytes(16),
            name: None,
        };
        let text = refusal.to_string();
        assert!(text.contains("package source tree"), "{text}");
        assert!(!text.contains("remote"), "{text}");
    }

    /// `sh -c <script>`, the portable way to make a child write a known number of bytes.
    fn sh(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        command
    }

    #[cfg(unix)]
    #[test]
    fn a_child_staging_exactly_the_cap_is_accepted() {
        let dir = scratch();
        let out = dir.path().join("out");
        let mut command = sh("head -c 16 /dev/zero > \"$0\"");
        command.arg(&out);
        let run = run(command, None, Some(&out), &budget(16, 1));
        assert!(matches!(run, Ok(ref captured) if captured.status.success()));
    }

    #[cfg(unix)]
    #[test]
    fn a_child_staging_one_byte_past_the_cap_is_refused() {
        let dir = scratch();
        let out = dir.path().join("out");
        let mut command = sh("head -c 17 /dev/zero > \"$0\"");
        command.arg(&out);
        let run = run(command, None, Some(&out), &budget(16, 1));
        assert!(matches!(
            run,
            Err(RunError::Exceeded(IngestLimit::Bytes(16)))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_child_growing_without_end_is_killed_at_the_cap() {
        let dir = scratch();
        let out = dir.path().join("out");
        let mut command = sh("cat /dev/zero > \"$0\"");
        command.arg(&out);
        let cap = 1024 * 1024;
        let run = run(command, None, Some(&out), &budget(cap, 1));
        assert!(matches!(
            run,
            Err(RunError::Exceeded(IngestLimit::Bytes(c))) if c == cap
        ));
    }

    /// `sh` making `count` empty files in `stage`.
    #[cfg(unix)]
    fn touch_files(stage: &std::path::Path, count: u32) -> Command {
        let mut command =
            sh("i=0; while [ \"$i\" -lt \"$1\" ]; do : > \"$0/f$i\"; i=$((i + 1)); done");
        command.arg(stage).arg(count.to_string());
        command
    }

    #[cfg(unix)]
    #[test]
    fn a_child_staging_exactly_the_entry_cap_is_accepted() {
        let dir = scratch();
        let command = touch_files(dir.path(), 4);
        let run = run(command, None, Some(dir.path()), &budget(0, 4));
        assert!(matches!(run, Ok(ref captured) if captured.status.success()));
    }

    #[cfg(unix)]
    #[test]
    fn a_child_staging_one_entry_past_the_cap_is_refused() {
        let dir = scratch();
        let command = touch_files(dir.path(), 5);
        let run = run(command, None, Some(dir.path()), &budget(0, 4));
        assert!(matches!(
            run,
            Err(RunError::Exceeded(IngestLimit::Entries(4)))
        ));
    }

    /// A transfer stage of exactly its entry ceiling is accepted.
    #[cfg(unix)]
    #[test]
    fn a_transfer_staging_exactly_its_entry_ceiling_is_accepted() {
        let dir = scratch();
        let transfer = Transfer::begin(budget(0, 4));
        let run = transfer.run(
            touch_files(dir.path(), 4),
            None,
            Some(dir.path()),
            Mode::Detached,
        );
        assert!(matches!(run, Ok(ref captured) if captured.status.success()));
    }

    /// A transfer stage one entry past its ceiling is refused as a remote
    /// ingest naming the transfer's surface.
    #[cfg(unix)]
    #[test]
    fn a_transfer_staging_one_entry_past_its_ceiling_is_refused() {
        let dir = scratch();
        let transfer = Transfer::begin(budget(0, 4));
        let run = transfer.run(
            touch_files(dir.path(), 5),
            None,
            Some(dir.path()),
            Mode::Detached,
        );
        assert!(
            matches!(
                run,
                Err(RunError::Exceeded(IngestRefusal {
                    source: IngestSource::PackageFetch,
                    limit: IngestLimit::Entries(4),
                    name: None,
                }))
            ),
            "{run:?}"
        );
    }

    /// A refusal kills the processes the child started, not only the child.
    #[cfg(all(unix, not(any(target_os = "openbsd", target_os = "redox"))))]
    #[test]
    fn a_refusal_kills_the_grandchild_writing_the_stage() {
        let dir = scratch();
        let out = dir.path().join("out");
        let mut command = sh("(cat /dev/zero > \"$0\") & wait");
        command.arg(&out);
        let cap = 1024 * 1024;
        let run = run(command, None, Some(&out), &budget(cap, 1));
        assert!(matches!(
            run,
            Err(RunError::Exceeded(IngestLimit::Bytes(c))) if c == cap
        ));
        let size = |path: &std::path::Path| std::fs::metadata(path).map_or(0, |meta| meta.len());
        std::thread::sleep(Duration::from_millis(300));
        let settled = size(&out);
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(size(&out), settled, "the grandchild kept writing");
    }

    /// A grandchild left behind by a finished child dies with its group, so its pipe closes.
    #[cfg(all(unix, not(any(target_os = "openbsd", target_os = "redox"))))]
    #[test]
    fn a_finished_childs_lingering_grandchild_is_killed() {
        let started = Instant::now();
        let run = run(sh("sleep 30 & exit 0"), None, None, &budget(0, 0));
        assert!(matches!(run, Ok(ref captured) if captured.status.success()));
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    /// An attached child's grandchild holding stdout ends in a typed drain timeout, not a byte refusal.
    #[cfg(unix)]
    #[test]
    fn a_pipe_held_past_the_grace_is_a_drain_timeout() {
        let run = run_core(
            sh("sleep 8 & exit 0"),
            None,
            None,
            &budget(0, 0).limits(),
            Instant::now(),
            Mode::Attached,
        );
        assert!(matches!(
            run,
            Err(RunError::PipeDrainTimeout(Stream::Stdout))
        ));
    }

    /// Every step of one transfer shares its deadline.
    #[cfg(unix)]
    #[test]
    fn a_second_step_is_held_to_the_first_steps_deadline() {
        let mut limits = budget(0, 0).limits();
        limits.wall = Duration::from_secs(2);
        let started = Instant::now();
        let first = run_core(
            sh("sleep 1.2"),
            None,
            None,
            &limits,
            started,
            Mode::Detached,
        );
        assert!(matches!(first, Ok(ref captured) if captured.status.success()));
        let second = run_core(
            sh("sleep 1.2"),
            None,
            None,
            &limits,
            started,
            Mode::Detached,
        );
        assert!(matches!(
            second,
            Err(RunError::Exceeded(IngestLimit::Time(_)))
        ));
    }

    /// A step started after the deadline is refused without running.
    #[test]
    fn a_step_after_the_deadline_never_starts() {
        let mut limits = budget(0, 0).limits();
        limits.wall = Duration::ZERO;
        let run = run_core(
            Command::new("ipe-no-such-program"),
            None,
            None,
            &limits,
            Instant::now(),
            Mode::Detached,
        );
        assert!(matches!(run, Err(RunError::Exceeded(IngestLimit::Time(_)))));
    }

    #[cfg(unix)]
    #[test]
    fn stdout_of_exactly_the_cap_is_kept_and_one_past_is_refused() {
        let at_cap = run(sh("head -c 16 /dev/zero"), None, None, &budget(0, 0));
        assert!(matches!(at_cap, Ok(ref captured) if captured.stdout.len() == 16));
        let past = run(sh("head -c 17 /dev/zero"), None, None, &budget(0, 0));
        assert!(matches!(
            past,
            Err(RunError::Exceeded(IngestLimit::Bytes(CAP)))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_child_past_its_wall_time_is_killed() {
        let quick = budget(0, 0).with_wall(Duration::from_millis(200));
        let run = run(sh("sleep 30"), None, None, &quick);
        assert!(matches!(run, Err(RunError::Exceeded(IngestLimit::Time(_)))));
    }

    #[cfg(unix)]
    #[test]
    fn stdin_reaches_the_child() {
        let run = run(sh("cat"), Some(b"ping"), None, &GITHUB_API);
        assert!(matches!(run, Ok(ref captured) if captured.stdout == b"ping"));
    }

    /// Stdin larger than a pipe buffer, echoed back, completes: the feed runs beside the captures.
    #[cfg(unix)]
    #[test]
    fn stdin_larger_than_a_pipe_buffer_does_not_deadlock() {
        let input = vec![b'x'; 1024 * 1024];
        let wide = budget(0, 0).with_stdout(bytes(2 * 1024 * 1024));
        let run = run(sh("cat"), Some(&input), None, &wide);
        assert!(matches!(run, Ok(ref captured) if captured.stdout.len() == input.len()));
    }

    /// The isolated git reads no user or system configuration and runs no hook.
    #[test]
    fn isolated_git_is_blind_to_ambient_configuration() {
        let dir = scratch();
        let git = Git::isolated(dir.path()).args(["fetch", "origin"]);
        let envs: Vec<(String, Option<String>)> = git
            .command
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        let set = |name: &str, value: &str| {
            envs.iter()
                .any(|(k, v)| k == name && v.as_deref() == Some(value))
        };
        let removed = |name: &str| envs.iter().any(|(k, v)| k == name && v.is_none());
        assert!(set("GIT_CONFIG_NOSYSTEM", "1"));
        assert!(set("GIT_CONFIG_GLOBAL", "/dev/null"));
        assert!(set("GIT_TERMINAL_PROMPT", "0"));
        assert!(set("GIT_ALLOW_PROTOCOL", "https:ssh:file"));
        assert!(set("GIT_NO_REPLACE_OBJECTS", "1"));
        assert!(set(
            "GIT_ALLOC_LIMIT",
            &PACKAGE_SOURCE.tree().per_file().to_string()
        ));
        for var in super::GIT_LOCATION_VARS
            .iter()
            .chain(super::GIT_INJECTION_VARS.iter())
        {
            assert!(removed(var), "{var} is not cleared");
        }
        let args: Vec<String> = git
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            args.windows(2)
                .any(|w| w == ["-c", "core.hooksPath=/dev/null"])
        );
        assert!(args.windows(2).any(|w| w == ["-c", "core.fsmonitor=false"]));
        assert!(
            args.windows(2)
                .any(|w| w == ["-c", "transfer.unpackLimit=1"])
        );
        assert!(args.ends_with(&["fetch".to_owned(), "origin".to_owned()]));
    }

    /// The isolated git allows exactly the transports a source URL can parse
    /// to, so the plaintext `git://` transport is refused at both boundaries.
    #[test]
    fn isolated_git_protocols_are_the_source_url_transports() {
        let transports: Vec<&str> = crate::index::Transport::ALL
            .into_iter()
            .map(crate::index::Transport::git_protocol)
            .collect();
        assert_eq!(super::ISOLATED_GIT_PROTOCOLS, transports.join(":"));
        assert!(!super::ISOLATED_GIT_PROTOCOLS.split(':').any(|p| p == "git"));
    }

    /// The build-time transport check accepts only the exact ordered list, so
    /// a list that adds plaintext `git`, drops, reorders, or pads a transport
    /// is refused.
    #[test]
    fn transport_list_check_refuses_every_drift() {
        assert!(super::names_every_transport("https:ssh:file"));
        for drifted in [
            "https:ssh:file:git",
            "git:https:ssh:file",
            "https:ssh",
            "ssh:https:file",
            "https:ssh:files",
            "https:ssh:file:",
            "https::ssh:file",
            "",
        ] {
            assert!(
                !super::names_every_transport(drifted),
                "{drifted:?} accepted"
            );
        }
    }

    /// The user git allows only HTTPS and never prompts.
    #[test]
    fn user_git_allows_only_https() {
        let dir = scratch();
        let git = Git::user(dir.path());
        let allowed = git
            .command
            .get_envs()
            .find(|(k, _)| *k == "GIT_ALLOW_PROTOCOL")
            .and_then(|(_, v)| v.map(|v| v.to_string_lossy().into_owned()));
        assert_eq!(allowed.as_deref(), Some("https"));
    }

    /// curl ignores `.curlrc` only when `-q` is its first argument.
    #[test]
    fn curl_ignores_curlrc_and_speaks_only_https() {
        let args: Vec<String> = super::Curl::https()
            .arg("https://example.invalid")
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args.first().map(String::as_str), Some("-q"));
        assert!(args.windows(2).any(|w| w == ["--proto", "=https"]));
        assert!(args.windows(2).any(|w| w == ["--proto-redir", "=https"]));
    }

    /// curl's limit exits map to typed refusals; any other exit is not a refusal.
    #[cfg(unix)]
    #[test]
    fn curl_limit_exits_are_refusals() {
        use std::os::unix::process::ExitStatusExt as _;
        let exit = |code: i32| std::process::ExitStatus::from_raw(code << 8);
        assert_eq!(
            curl_refusal(exit(63), bytes(7), &GITHUB_API),
            Some(IngestRefusal {
                source: IngestSource::GithubApi,
                limit: IngestLimit::Bytes(7),
                name: None,
            })
        );
        assert_eq!(
            curl_refusal(exit(28), bytes(7), &GITHUB_API),
            Some(IngestRefusal {
                source: IngestSource::GithubApi,
                limit: IngestLimit::Time(GITHUB_API.wall),
                name: None,
            })
        );
        assert_eq!(curl_refusal(exit(0), bytes(7), &GITHUB_API), None);
        assert_eq!(curl_refusal(exit(22), bytes(7), &GITHUB_API), None);
    }

    /// The curl limit arguments carry the response ceiling and the wall time in seconds.
    #[test]
    fn curl_limit_args_carry_both_ceilings() {
        let args = curl_limit_args(bytes(4096), &GITHUB_API);
        assert_eq!(
            args,
            [
                "--max-filesize".to_owned(),
                "4096".to_owned(),
                "--max-time".to_owned(),
                GITHUB_API.wall.as_secs().to_string(),
            ]
        );
    }
}
