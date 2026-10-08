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
//!   relayed to that group, except a signal the CLI inherited as ignored, and a
//!   termination request (`SIGTERM`) kills every group before the CLI acts on
//!   it, so no group outlives a CLI that a signal ends. The child's pipes are
//!   read and written on the waiting thread itself, so no thread of the CLI is
//!   left behind by a process that keeps a pipe open. The
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
//! LIMIT: git's resident memory is bounded only by the transfer deadline and the
//! group kill. Every fetch step receives the server's ref advertisement, which
//! may differ from the one a pre-checked `ls-remote` saw, and `index-pack`
//! memory scales with the pack. [`Git::isolated`] caps each single allocation
//! at the package per-file ceiling (`GIT_ALLOC_LIMIT`); a cap on the child's
//! address space would need a pre-exec hook, which needs `unsafe`.

use std::io::Read;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::CliError;
use crate::package_name::PackageName;
use crate::style::TerminalSafe;

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

/// Ceiling on every wall-time budget of a remote-ingest surface, in seconds.
///
/// No surface may run longer than ten minutes; the package fetch and the index
/// clone sit exactly at it.
pub const MAX_WALL_SECS: u64 = 600;

/// A byte ceiling of one remote-ingest surface, in `1..=MAX_REMOTE_BYTES`.
///
/// The only values are the named constants of this module, in-range literals
/// whose bound the build checks; zero has no representation, so no ceiling can
/// read as "unlimited" (curl takes `--max-filesize 0` as no limit). Code
/// outside this module cannot build one, so no caller can hand a transfer, a
/// capped read or a curl limit an unbounded ceiling. A surface that stages
/// nothing says so with [`Staging::Nothing`], never with a zero ceiling.
///
/// ```compile_fail,E0624
/// let _ = ipe::remote_ingest::ByteBudget::of::<1>();
/// ```
///
/// ```compile_fail,E0423
/// let _ = ipe::remote_ingest::ByteBudget(u64::MAX);
/// ```
///
/// ```compile_fail,E0599
/// let _ = ipe::remote_ingest::ByteBudget::NONE;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteBudget(NonZeroU64);

impl ByteBudget {
    /// The ceiling `N`, which the build refuses outside `1..=MAX_REMOTE_BYTES`.
    const fn of<const N: u64>() -> Self {
        let ceiling = const {
            // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD when a named byte budget is zero or above `MAX_REMOTE_BYTES` [ledger #boundary]
            assert!(N > 0 && N <= MAX_REMOTE_BYTES);
            match NonZeroU64::new(N) {
                Some(ceiling) => ceiling,
                None => NonZeroU64::MIN,
            }
        };
        Self(ceiling)
    }

    /// The ceiling in bytes, never zero.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// The ceiling `bytes`, or `None` outside `1..=MAX_REMOTE_BYTES`, for a test to drive the refusals.
    #[cfg(test)]
    #[must_use]
    pub fn for_test(bytes: u64) -> Option<Self> {
        NonZeroU64::new(bytes)
            .filter(|ceiling| ceiling.get() <= MAX_REMOTE_BYTES)
            .map(Self)
    }
}

/// An entry ceiling of one remote-ingest surface, in `1..=MAX_REMOTE_ENTRIES`.
///
/// Built only as [`ByteBudget`] is: a named in-range constant of this module.
///
/// ```compile_fail,E0624
/// let _ = ipe::remote_ingest::EntryBudget::of::<1>();
/// ```
///
/// ```compile_fail,E0599
/// let _ = ipe::remote_ingest::EntryBudget::NONE;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntryBudget(NonZeroU64);

impl EntryBudget {
    /// The ceiling `N`, which the build refuses outside `1..=MAX_REMOTE_ENTRIES`.
    const fn of<const N: u64>() -> Self {
        let ceiling = const {
            // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD when a named entry budget is zero or above `MAX_REMOTE_ENTRIES` [ledger #boundary]
            assert!(N > 0 && N <= MAX_REMOTE_ENTRIES);
            match NonZeroU64::new(N) {
                Some(ceiling) => ceiling,
                None => NonZeroU64::MIN,
            }
        };
        Self(ceiling)
    }

    /// The ceiling in entries, never zero.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// The ceiling `entries`, or `None` outside `1..=MAX_REMOTE_ENTRIES`, for a test to drive the refusals.
    #[cfg(test)]
    #[must_use]
    pub fn for_test(entries: u64) -> Option<Self> {
        NonZeroU64::new(entries)
            .filter(|ceiling| ceiling.get() <= MAX_REMOTE_ENTRIES)
            .map(Self)
    }
}

/// A wall-time ceiling of one remote-ingest surface: whole seconds in `1..=MAX_WALL_SECS`.
///
/// A zero or sub-second wall has no representation, so `--max-time` is always
/// a whole number of seconds of at least one (curl takes `--max-time 0` as no
/// limit) and the watcher's deadline is always the same value.
///
/// ```compile_fail,E0080
/// let _ = ipe::remote_ingest::WallBudget::of_secs::<0>();
/// ```
///
/// ```compile_fail,E0080
/// let _ = ipe::remote_ingest::WallBudget::of_secs::<601>();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WallBudget(NonZeroU64);

impl WallBudget {
    /// The ceiling of `S` seconds, which the build refuses outside `1..=MAX_WALL_SECS`.
    #[must_use]
    pub const fn of_secs<const S: u64>() -> Self {
        let secs = const {
            // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD when a named wall budget is zero or above `MAX_WALL_SECS` [ledger #boundary]
            assert!(S > 0 && S <= MAX_WALL_SECS);
            match NonZeroU64::new(S) {
                Some(secs) => secs,
                None => NonZeroU64::MIN,
            }
        };
        Self(secs)
    }

    /// The ceiling in whole seconds, never zero.
    #[must_use]
    pub const fn secs(self) -> u64 {
        self.0.get()
    }

    /// The ceiling as a duration.
    #[must_use]
    pub const fn get(self) -> Duration {
        Duration::from_secs(self.0.get())
    }

    /// The ceiling `wall`, or `None` unless it is whole seconds in `1..=MAX_WALL_SECS`, for a test to drive the refusals.
    #[cfg(test)]
    #[must_use]
    pub fn for_test(wall: Duration) -> Option<Self> {
        if wall.subsec_nanos() != 0 {
            return None;
        }
        NonZeroU64::new(wall.as_secs())
            .filter(|secs| secs.get() <= MAX_WALL_SECS)
            .map(Self)
    }

    /// The ceiling as the wall a watcher enforces and a refusal names.
    #[must_use]
    pub const fn limit(self) -> WallSecs {
        WallSecs(self.0)
    }
}

/// Ceiling on every wall-time ceiling of a local child, in seconds.
///
/// The longest local child is a self-run of `ipe dev run`, which contains a
/// full cargo build: the cargo build wall plus [`SELF_RUN_MARGIN_SECS`]. The
/// jailed FFI inspector allows 900 seconds, so a local wall may exceed
/// [`MAX_WALL_SECS`]; this is the type's ceiling, not a default.
pub const MAX_LOCAL_WALL_SECS: u64 =
    crate::cargo_step::CARGO_BUILD_WALL_SECS + SELF_RUN_MARGIN_SECS;

// Every remote wall fits a local one, so a remote wall reused as a local
// ceiling is in range by construction.
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the remote wall ceiling outgrows the local one [ledger #boundary]
const _: () = assert!(MAX_WALL_SECS <= MAX_LOCAL_WALL_SECS);

/// The wall a watched child was held to: whole seconds, never zero.
///
/// Built only from a [`WallBudget`] or a [`LocalWall`], so the watcher's
/// deadline and the refusal that names it are the same value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WallSecs(NonZeroU64);

impl WallSecs {
    /// The wall in whole seconds, never zero.
    #[must_use]
    pub const fn secs(self) -> u64 {
        self.0.get()
    }

    /// The wall as a duration.
    #[must_use]
    pub const fn get(self) -> Duration {
        Duration::from_secs(self.0.get())
    }
}

/// A wall-time ceiling of one local child: whole seconds in `1..=MAX_LOCAL_WALL_SECS`.
///
/// Built only as [`WallBudget`] is, with the local ceiling as its bound.
///
/// ```compile_fail,E0080
/// let _ = ipe::remote_ingest::LocalWall::of_secs::<0>();
/// ```
///
/// ```compile_fail,E0080
/// let _ = ipe::remote_ingest::LocalWall::of_secs::<3661>();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LocalWall(NonZeroU64);

impl LocalWall {
    /// The ceiling of `S` seconds, which the build refuses outside `1..=MAX_LOCAL_WALL_SECS`.
    #[must_use]
    pub const fn of_secs<const S: u64>() -> Self {
        let secs = const {
            // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD when a named local wall is zero or above `MAX_LOCAL_WALL_SECS` [ledger #boundary]
            assert!(S > 0 && S <= MAX_LOCAL_WALL_SECS);
            match NonZeroU64::new(S) {
                Some(secs) => secs,
                None => NonZeroU64::MIN,
            }
        };
        Self(secs)
    }

    /// The remote wall `wall` as a local one; every remote wall is in range.
    #[must_use]
    pub const fn of_remote(wall: WallBudget) -> Self {
        Self(wall.0)
    }

    /// The ceiling in whole seconds, never zero.
    #[must_use]
    pub const fn secs(self) -> u64 {
        self.0.get()
    }

    /// The ceiling as the wall a watcher enforces and a refusal names.
    #[must_use]
    pub const fn limit(self) -> WallSecs {
        WallSecs(self.0)
    }
}

/// What a remote-ingest surface may leave on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Staging {
    /// Nothing: one staged byte or entry is a refusal.
    Nothing,
    /// A staged path held to both ceilings.
    Disk {
        /// Bytes of the regular files the staged path may hold.
        bytes: ByteBudget,
        /// Entries (files, directories, links) the staged path may hold.
        entries: EntryBudget,
    },
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
pub const HTTP_MAX_TIME: WallBudget = WallBudget::of_secs::<60>();

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

/// The ceilings of one local child: its stdout and its wall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalLimits {
    stdout_bytes: ByteBudget,
    wall: LocalWall,
}

/// The ceilings of a local child run through [`run_local`] or [`run_local_fed`].
///
/// Opaque: every production value is a named constant of this module, so a
/// caller can neither build a ceiling nor widen one. A local child stages
/// nothing on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalCeiling(LocalLimits);

impl LocalCeiling {
    /// Bytes the child's stdout may carry.
    #[must_use]
    pub const fn stdout_bytes(&self) -> ByteBudget {
        self.0.stdout_bytes
    }

    /// Wall time the child may run.
    #[must_use]
    pub const fn wall(&self) -> LocalWall {
        self.0.wall
    }

    /// This ceiling with its wall time set, for a test to drive the refusals.
    #[cfg(test)]
    #[must_use]
    pub const fn with_wall(self, wall: LocalWall) -> Self {
        let Self(limits) = self;
        Self(LocalLimits { wall, ..limits })
    }

    /// This ceiling with its stdout ceiling set, for a test to drive the refusals.
    #[cfg(test)]
    #[must_use]
    pub const fn with_stdout(self, stdout_bytes: ByteBudget) -> Self {
        let Self(limits) = self;
        Self(LocalLimits {
            stdout_bytes,
            ..limits
        })
    }

    /// The ceilings the watcher enforces.
    const fn limits(&self) -> RunLimits {
        RunLimits {
            staging: Staging::Nothing,
            stdout_bytes: self.0.stdout_bytes,
            wall: self.0.wall.limit(),
        }
    }
}

/// The ceilings of a local `git` query, which stages nothing on disk.
///
/// Its stdout (a revision, a remote URL, a porcelain status) is held to 4 MiB
/// and its run to one minute.
const QUERY_LIMITS: LocalCeiling = LocalCeiling(LocalLimits {
    stdout_bytes: ByteBudget::of::<{ 4 * MIB }>(),
    wall: LocalWall::of_secs::<60>(),
});

/// The ceilings of an offline `cargo generate-lockfile`, which reads only the local registry cache.
///
/// Its stdout is held to 64 KiB and its run to two minutes, so a held
/// `.package-cache` lock or a wedged resolve cannot hold the CLI.
pub const LOCK_RESOLVE_LIMITS: LocalCeiling = LocalCeiling(LocalLimits {
    stdout_bytes: ByteBudget::of::<{ 64 * KIB }>(),
    wall: LocalWall::of_secs::<120>(),
});

/// The ceilings of a networked `cargo generate-lockfile`, which may fetch the registry index.
///
/// Its stdout is held to 64 KiB and its run to ten minutes, the wall of
/// [`INDEX_CLONE`].
pub const LOCK_FETCH_LIMITS: LocalCeiling = LocalCeiling(LocalLimits {
    stdout_bytes: ByteBudget::of::<{ 64 * KIB }>(),
    wall: LocalWall::of_remote(INDEX_CLONE.wall),
});

/// The ceilings of `cargo metadata --no-deps`, which reads only the crate's manifests.
///
/// Its stdout (the metadata document) is held to 16 MiB and its run to two
/// minutes, so a held cargo lock or a wedged config read cannot hold the CLI.
pub const METADATA_LIMITS: LocalCeiling = LocalCeiling(LocalLimits {
    stdout_bytes: ByteBudget::of::<{ 16 * MIB }>(),
    wall: LocalWall::of_secs::<120>(),
});

/// The ceilings of a toolchain query (`cargo-deny --version`, `rustup target list --installed`).
///
/// Its stdout (a version line, a target list) is held to 64 KiB and its run
/// to one minute.
pub const TOOL_QUERY_LIMITS: LocalCeiling = LocalCeiling(LocalLimits {
    stdout_bytes: ByteBudget::of::<{ 64 * KIB }>(),
    wall: LocalWall::of_secs::<60>(),
});

/// The ceilings of a `cargo-deny check`, which may fetch the advisory database.
///
/// Its stdout is held to 1 MiB and its run to ten minutes, the wall of
/// [`INDEX_CLONE`].
pub const SUPPLY_CHAIN_SCAN_LIMITS: LocalCeiling = LocalCeiling(LocalLimits {
    stdout_bytes: ByteBudget::of::<MIB>(),
    wall: LocalWall::of_remote(INDEX_CLONE.wall),
});

/// The ceilings of a `rustc -vV` query.
///
/// Its stdout (a handful of `key: value` lines) is held to 64 KiB and its run
/// to one minute.
pub const RUSTC_QUERY_LIMITS: LocalCeiling = LocalCeiling(LocalLimits {
    stdout_bytes: ByteBudget::of::<{ 64 * KIB }>(),
    wall: LocalWall::of_secs::<60>(),
});

/// The ceilings of the `ipe health` link probe, which compiles and links an empty program.
///
/// Its stdout is held to 64 KiB and its run to two minutes.
pub const LINK_PROBE_LIMITS: LocalCeiling = LocalCeiling(LocalLimits {
    stdout_bytes: ByteBudget::of::<{ 64 * KIB }>(),
    wall: LocalWall::of_secs::<120>(),
});

/// The ceilings of the unsandboxed FFI inspector.
///
/// The jailed inspector's defaults: its stdout (the inspection report) is held
/// to 256 MiB and its run to fifteen minutes.
pub const FFI_INSPECT_LIMITS: LocalCeiling = LocalCeiling(LocalLimits {
    stdout_bytes: ByteBudget::of::<{ 256 * MIB }>(),
    wall: LocalWall::of_secs::<900>(),
});

/// The ceilings of a wasm bundle tool (`wasm-bindgen`, `wasm-opt`).
///
/// Its stdout is held to 1 MiB and its run to ten minutes.
pub const WASM_TOOL_LIMITS: LocalCeiling = LocalCeiling(LocalLimits {
    stdout_bytes: ByteBudget::of::<MIB>(),
    wall: LocalWall::of_secs::<600>(),
});

/// The seconds a self-run of this CLI may take beyond the `cargo build` it contains.
pub const SELF_RUN_MARGIN_SECS: u64 = 60;

/// The wall of a self-run of this CLI: the cargo build wall plus
/// [`SELF_RUN_MARGIN_SECS`].
const SELF_RUN_WALL: LocalWall =
    LocalWall::of_secs::<{ crate::cargo_step::CARGO_BUILD_WALL_SECS + SELF_RUN_MARGIN_SECS }>();

// A self-run contains a full cargo build, so its wall outlasts the build's own
// wall: a hung build is refused by the build's typed timeout, never cut short
// by the self-run wall first.
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the self-run wall does not outlast the cargo build wall it contains [ledger #boundary]
const _: () = assert!(SELF_RUN_WALL.secs() > crate::cargo_step::CARGO_BUILD_WALL.secs());

/// The ceilings of a self-run of this CLI (`ipe dev run <snippet>`), which contains a full cargo build.
///
/// Its stdout (the snippet's output) is held to 1 MiB and its run to the
/// cargo build wall plus [`SELF_RUN_MARGIN_SECS`].
pub const SELF_RUN_LIMITS: LocalCeiling = LocalCeiling(LocalLimits {
    stdout_bytes: ByteBudget::of::<MIB>(),
    wall: SELF_RUN_WALL,
});

/// Run a local `command` detached in its own process group, held to `ceiling`.
///
/// Stdin is the null device; stdout is held to the ceiling and stderr
/// truncated at [`CHILD_STDERR_MAX_BYTES`]. A crossed ceiling kills the
/// child's group and is a [`LocalRefusal`] naming `source`.
///
/// # Errors
/// See [`RunError`].
pub fn run_local(
    command: Command,
    ceiling: LocalCeiling,
    source: LocalSource,
) -> Result<Captured, RunError<LocalRefusal>> {
    run_local_core(command, None, ceiling, source)
}

/// Run a local `command` as [`run_local`] does, with `stdin` fed to it as it reads.
///
/// # Errors
/// See [`RunError`].
pub fn run_local_fed(
    command: Command,
    stdin: Zeroizing<Vec<u8>>,
    ceiling: LocalCeiling,
    source: LocalSource,
) -> Result<Captured, RunError<LocalRefusal>> {
    run_local_core(command, Some(stdin), ceiling, source)
}

/// The one body of [`run_local`] and [`run_local_fed`].
fn run_local_core(
    command: Command,
    stdin: Option<Zeroizing<Vec<u8>>>,
    ceiling: LocalCeiling,
    source: LocalSource,
) -> Result<Captured, RunError<LocalRefusal>> {
    run_core(
        command,
        stdin,
        None,
        &ceiling.limits(),
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

/// Why a child whose stdio is the terminal's needs no ceiling.
///
/// Its output never enters the CLI's memory (the bytes go straight to the
/// terminal's descriptors), its input is the terminal or bytes already bounded
/// upstream, and its duration is the user's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InheritedRole {
    /// An install the user consented to and watches; a wall would kill a slow but legitimate one.
    InteractiveInstall,
    /// This CLI run again, which holds its own children to their ceilings.
    SelfBuild,
    /// The user's own program, which they asked to run and can interrupt.
    UserProgram,
}

impl InheritedRole {
    /// Whether a child in this role must read every byte it is fed.
    ///
    /// An installer that stops reading its script early ran only part of it,
    /// whatever its exit status says; a build or the user's program may stop
    /// reading when it has what it needs.
    const fn consumes_all_input(self) -> bool {
        match self {
            Self::InteractiveInstall => true,
            Self::SelfBuild | Self::UserProgram => false,
        }
    }
}

/// What an inherited child reads on its stdin.
#[derive(Debug)]
pub enum InheritedInput {
    /// The CLI's own stdin, the user's terminal.
    Terminal,
    /// The null device: the child reads the end of its input at once.
    Null,
    /// These bytes, already held to a ceiling where they were read.
    Bytes(Zeroizing<Vec<u8>>),
}

/// Why an inherited child produced no exit status the caller may accept.
#[derive(Debug)]
pub enum InheritedError {
    /// The hardened spawner refused or failed to start the child.
    Spawn(ipe_runtime_rust::system::SpawnRefusal),
    /// The child, in a role that must read all of its input, exited 0 with part of it unwritten.
    Feed(std::io::ErrorKind),
    /// Waiting on the child failed.
    Wait(std::io::Error),
}

impl std::fmt::Display for InheritedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(refusal) => refusal.fmt(f),
            Self::Feed(kind) => write!(f, "the child stopped reading its input early ({kind})"),
            Self::Wait(e) => e.fmt(f),
        }
    }
}

impl From<InheritedError> for std::io::Error {
    fn from(error: InheritedError) -> Self {
        match error {
            InheritedError::Spawn(refusal) => refusal.into(),
            InheritedError::Feed(kind) => kind.into(),
            InheritedError::Wait(e) => e,
        }
    }
}

/// Run `command` with the terminal's stdout and stderr, in `role`, until it exits.
///
/// The child starts through the runtime's hardened spawner, so it inherits no
/// descriptor besides stdio and, on Linux, dies with the CLI. No ceiling holds
/// it; `role` names why none is needed. Stdout and stderr keep whatever the
/// caller set on `command` (the terminal's by default). `input` is its stdin:
/// the terminal, the null device, or bytes fed to a pipe while the CLI waits on
/// the child, the pipe closed once they are written or the child exits.
///
/// A fed child that closes its stdin or exits before the CLI wrote every byte
/// has not read its whole input. In a role that must read all of it
/// ([`InheritedRole::InteractiveInstall`]) that is refused on exit 0, which
/// cannot then mean the whole input ran; a non-zero exit is already a failure
/// and is returned as the status that names it. Another role is judged by its
/// exit status alone. Bytes written into the pipe and never read by an exiting
/// child are not seen.
///
/// # Errors
/// [`InheritedError::Spawn`] when the child cannot start;
/// [`InheritedError::Feed`] when a child that must read all of its input
/// exited 0 without reading it; [`InheritedError::Wait`] when waiting on it fails.
pub fn run_inherited(
    mut command: Command,
    role: InheritedRole,
    input: InheritedInput,
) -> Result<ExitStatus, InheritedError> {
    let bytes = match input {
        InheritedInput::Terminal => {
            command.stdin(Stdio::inherit());
            None
        }
        InheritedInput::Null => {
            command.stdin(Stdio::null());
            None
        }
        InheritedInput::Bytes(bytes) => {
            command.stdin(Stdio::piped());
            Some(bytes)
        }
    };
    let mut child =
        ipe_runtime_rust::system::spawn_hardened(command).map_err(InheritedError::Spawn)?;
    let Some(bytes) = bytes else {
        return child.wait().map_err(InheritedError::Wait);
    };
    let (status, shortfall) = feed_until_exit(&mut child, bytes)?;
    match shortfall {
        Some(kind) if role.consumes_all_input() && status.success() => {
            Err(InheritedError::Feed(kind))
        }
        Some(_) | None => Ok(status),
    }
}

/// Feed `bytes` to `child`'s stdin while waiting for it, returning its status and how the feed fell short.
///
/// The write never blocks the wait: the feed is pumped between polls of the
/// child, and once the child exits the pipe closes with whatever is left, so a
/// child, or a descendant holding its stdin, that stops reading cannot hold
/// the CLI past the child's own exit.
fn feed_until_exit(
    child: &mut Child,
    bytes: Zeroizing<Vec<u8>>,
) -> Result<(ExitStatus, Option<std::io::ErrorKind>), InheritedError> {
    let feed = child
        .stdin
        .take()
        .ok_or(std::io::ErrorKind::BrokenPipe)
        .and_then(|pipe| pipes::Feed::new(pipe, bytes).map_err(|e| e.kind()));
    let mut feed = match feed {
        Ok(feed) => feed,
        Err(kind) => {
            let status = child.wait().map_err(InheritedError::Wait)?;
            return Ok((status, Some(kind)));
        }
    };
    let mut idle = IDLE_MIN;
    let status = loop {
        let moved = feed.pump();
        if !feed.is_open() {
            break child.wait().map_err(InheritedError::Wait)?;
        }
        if let Some(status) = child.try_wait().map_err(InheritedError::Wait)? {
            break status;
        }
        idle = pause(moved, idle);
    };
    Ok((status, feed.shortfall()))
}

/// The declared ingest ceilings of one remote surface.
///
/// The fields are private and every production value is a named constant of
/// this module, so a caller can neither build a budget nor widen one.
///
/// ```compile_fail,E0451
/// use ipe::remote_ingest::{Budget, GITHUB_API};
/// let _ = Budget { wall: ipe::remote_ingest::WallBudget::of_secs::<600>(), ..GITHUB_API };
/// ```
///
/// ```compile_fail,E0451
/// use ipe::remote_ingest::{Budget, OAUTH_FORM, Staging};
/// let _ = Budget { staging: Staging::Nothing, ..OAUTH_FORM };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    source: IngestSource,
    staging: Staging,
    stdout_bytes: ByteBudget,
    wall: WallBudget,
}

impl Budget {
    /// The surface named in a refusal.
    #[must_use]
    pub const fn source(&self) -> IngestSource {
        self.source
    }

    /// What the staged path may hold on disk.
    #[must_use]
    pub const fn staging(&self) -> Staging {
        self.staging
    }

    /// Bytes the child's stdout may carry.
    #[must_use]
    pub const fn stdout_bytes(&self) -> ByteBudget {
        self.stdout_bytes
    }

    /// Wall time the whole transfer may take.
    #[must_use]
    pub const fn wall(&self) -> WallBudget {
        self.wall
    }

    /// This budget with what it may stage set, for a test to drive the refusals.
    #[cfg(test)]
    #[must_use]
    pub const fn with_staging(self, staging: Staging) -> Self {
        Self { staging, ..self }
    }

    /// This budget with its staged byte ceiling set, for a test to drive the refusals.
    ///
    /// `None` for a budget that stages nothing.
    #[cfg(test)]
    #[must_use]
    pub const fn with_staged_bytes(self, bytes: ByteBudget) -> Option<Self> {
        match self.staging {
            Staging::Nothing => None,
            Staging::Disk { entries, .. } => {
                Some(self.with_staging(Staging::Disk { bytes, entries }))
            }
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
    pub const fn with_wall(self, wall: WallBudget) -> Self {
        Self { wall, ..self }
    }

    /// The ceilings the watcher enforces, without the surface name.
    const fn limits(&self) -> RunLimits {
        RunLimits {
            staging: self.staging,
            stdout_bytes: self.stdout_bytes,
            wall: self.wall.limit(),
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
    staging: Staging::Disk {
        bytes: ByteBudget::of::<GIB>(),
        entries: EntryBudget::of::<{ 4 * PACKAGE_TREE_MAX_ENTRIES }>(),
    },
    stdout_bytes: CHILD_STDERR_MAX_BYTES,
    wall: WallBudget::of_secs::<600>(),
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
    /// The transfer stages nothing, or its disk ceiling holds less than a pack and a checkout at the tree ceiling.
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
        let Staging::Disk { bytes, entries } = self.transfer.staging else {
            return Err(BudgetPairing::TransferBytesUnderTree);
        };
        if bytes.get() < self.tree.bytes.saturating_mul(2) {
            return Err(BudgetPairing::TransferBytesUnderTree);
        }
        let staged_entries = self
            .tree
            .entries
            .saturating_add(self.refs.count)
            .saturating_add(GIT_STAGE_OVERHEAD_ENTRIES);
        if entries.get() < staged_entries {
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
    staging: Staging::Disk {
        bytes: ByteBudget::of::<{ 512 * MIB }>(),
        entries: EntryBudget::of::<MAX_REMOTE_ENTRIES>(),
    },
    stdout_bytes: CHILD_STDERR_MAX_BYTES,
    wall: WallBudget::of_secs::<600>(),
};

/// The budget of the local commit and push steps of `ipe package publish`, taken together.
///
/// Nothing is staged on disk from the remote; only git's own output is held.
/// Ten minutes covers a push over a slow link.
pub const INDEX_PUSH: Budget = Budget {
    source: IngestSource::IndexPush,
    staging: Staging::Nothing,
    stdout_bytes: CHILD_STDERR_MAX_BYTES,
    wall: WallBudget::of_secs::<600>(),
};

/// The budget of one GitHub API call made through `curl -o <scratch>`.
///
/// The body lands in one scratch file (one entry) capped at
/// [`JSON_RESPONSE_MAX_BYTES`]; stdout carries only the status code.
pub const GITHUB_API: Budget = Budget {
    source: IngestSource::GithubApi,
    staging: Staging::Disk {
        bytes: JSON_RESPONSE_MAX_BYTES,
        entries: EntryBudget::of::<1>(),
    },
    stdout_bytes: STATUS_STDOUT_MAX_BYTES,
    wall: HTTP_MAX_TIME,
};

/// The budget of one OAuth device-flow request (`ipe login`), whose body arrives on curl's stdout.
pub const OAUTH_FORM: Budget = Budget {
    source: IngestSource::OauthDevice,
    staging: Staging::Nothing,
    stdout_bytes: JSON_RESPONSE_MAX_BYTES,
    wall: HTTP_MAX_TIME,
};

/// Ceiling on the bytes of the installer script `ipe upgrade` downloads.
///
/// The script lands in one private scratch file; 1 MiB is far above the
/// installer's size while refusing a response built to fill the disk.
pub const INSTALLER_MAX_BYTES: ByteBudget = ByteBudget::of::<MIB>();

/// The budget of the installer script `ipe upgrade` downloads before running it.
///
/// The script lands in one file held to [`INSTALLER_MAX_BYTES`].
pub const INSTALLER: Budget = Budget {
    source: IngestSource::Installer,
    staging: Staging::Disk {
        bytes: INSTALLER_MAX_BYTES,
        entries: EntryBudget::of::<1>(),
    },
    stdout_bytes: STATUS_STDOUT_MAX_BYTES,
    wall: HTTP_MAX_TIME,
};

/// Every named surface budget, for a test to hold each to the remote ceilings.
#[cfg(test)]
const ALL_BUDGETS: [Budget; 6] = [
    PACKAGE_FETCH,
    INDEX_CLONE,
    INDEX_PUSH,
    GITHUB_API,
    OAUTH_FORM,
    INSTALLER,
];

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
    Time(WallSecs),
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
            Self::Time(max) => match max.secs() {
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
    /// An offline `cargo generate-lockfile` resolving from the local registry cache.
    LockResolve,
    /// A networked `cargo generate-lockfile` resolving an emitted crate's graph.
    LockFetch,
    /// A `cargo metadata --no-deps` reading a crate's target directory.
    CargoMetadata,
    /// A toolchain query: a tool's version or its installed targets.
    ToolQuery,
    /// A `cargo-deny check` over an emitted crate's dependency graph.
    SupplyChainScan,
    /// A `rustc -vV` query of the active toolchain.
    RustcQuery,
    /// The `ipe health` probe that links an empty program.
    LinkProbe,
    /// The FFI inspector run without the jail.
    FfiInspect,
    /// A wasm bundle tool (`wasm-bindgen`, `wasm-opt`).
    WasmTool,
    /// This CLI run again on a snippet (`ipe dev run`).
    SelfRun,
}

impl std::fmt::Display for LocalSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::PackageTree => "package source tree",
            Self::GitQuery => "git query",
            Self::LockResolve => "offline cargo lock resolve",
            Self::LockFetch => "cargo lock resolve",
            Self::CargoMetadata => "cargo metadata query",
            Self::ToolQuery => "toolchain query",
            Self::SupplyChainScan => "cargo-deny supply-chain scan",
            Self::RustcQuery => "rustc version query",
            Self::LinkProbe => "linker probe",
            Self::FfiInspect => "FFI inspector",
            Self::WasmTool => "wasm bundle tool",
            Self::SelfRun => "self-run of a snippet",
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
struct RunLimits {
    staging: Staging,
    stdout_bytes: ByteBudget,
    wall: WallSecs,
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

/// [`measure`] against bare [`RunLimits`].
fn measure_limits(root: &Path, limits: &RunLimits) -> Result<Usage, (PathBuf, std::io::Error)> {
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
///
/// A surface that stages nothing refuses its first staged byte or entry.
const fn exceeded(usage: Usage, limits: &RunLimits) -> Option<IngestLimit> {
    let (bytes, entries) = match limits.staging {
        Staging::Nothing => (0, 0),
        Staging::Disk { bytes, entries } => (bytes.get(), entries.get()),
    };
    if usage.bytes > bytes {
        Some(IngestLimit::Bytes(bytes))
    } else if usage.entries > entries {
        Some(IngestLimit::Entries(entries))
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
    /// The child's stderr, truncated at [`CHILD_STDERR_MAX_BYTES`] with the cut marked.
    pub stderr: ChildStderr,
}

/// A child's stderr as kept: whole, or cut at [`CHILD_STDERR_MAX_BYTES`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildStderr {
    /// Every byte the child wrote.
    Whole(Vec<u8>),
    /// The first [`CHILD_STDERR_MAX_BYTES`] bytes; the rest was read and dropped.
    Truncated(Vec<u8>),
}

impl ChildStderr {
    /// The bytes kept, without the truncation marker.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Whole(bytes) | Self::Truncated(bytes) => bytes,
        }
    }

    /// Whether the child wrote more than was kept.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::Truncated(_))
    }

    /// The kept text, trimmed and sanitised for the terminal, with the cut named when one was made.
    #[must_use]
    pub fn to_terminal(&self) -> TerminalSafe {
        let text = String::from_utf8_lossy(self.bytes());
        let text = text.trim();
        match self {
            Self::Whole(_) => TerminalSafe::sanitize(text),
            Self::Truncated(_) => {
                let marker = crate::text::cli_child_stderr_truncated(&IngestLimit::Bytes(
                    CHILD_STDERR_MAX_BYTES.get(),
                ));
                TerminalSafe::sanitize(&format!("{text}\n{marker}"))
            }
        }
    }
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
    /// Reading this pipe failed, so what was read is not the child's whole output.
    PipeRead(Stream, std::io::ErrorKind),
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
            Self::PipeRead(stream, kind) => RunError::PipeRead(stream, kind),
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
            Self::PipeRead(stream, kind) => {
                f.write_str(&crate::text::cli_child_pipe_unread(stream, kind))
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
            started: transfer_start(),
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

/// The instant a new [`Transfer`] starts its clock at: now.
#[cfg(not(test))]
fn transfer_start() -> Instant {
    Instant::now()
}

#[cfg(test)]
thread_local! {
    /// How long before now every transfer this thread begins counts as started.
    static TRANSFER_HEAD_START: std::cell::Cell<Duration> =
        const { std::cell::Cell::new(Duration::ZERO) };
}

/// Start every transfer this thread begins `spent` in the past, for a test to drive a deadline refusal.
///
/// A wall is at least one second, so a test that must cross it without waiting
/// spends the clock instead of shrinking the wall.
#[cfg(test)]
pub fn spend_transfer_clock_for_test(spent: Duration) {
    TRANSFER_HEAD_START.with(|head_start| head_start.set(spent));
}

/// The instant a new [`Transfer`] starts its clock at: now, less the head start a test spent.
#[cfg(test)]
fn transfer_start() -> Instant {
    let now = Instant::now();
    now.checked_sub(TRANSFER_HEAD_START.with(std::cell::Cell::get))
        .unwrap_or(now)
}

/// Whether a watched child is detached from the terminal in its own process group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Its own process group: a refusal kills every process it started.
    Detached,
    /// The CLI's process group, keeping the terminal for a prompt (a signing
    /// passphrase); a refusal or a termination request kills the direct child.
    Attached,
    /// A probe the signal owners run while reading the dispositions they act
    /// on: in the CLI's process group and known to no signal owner, since
    /// none is installed yet.
    #[cfg(all(unix, any(not(target_os = "linux"), test)))]
    Probe,
}

/// Run `command`, killing it the moment it crosses a ceiling of `limits`.
///
/// `stdin`, when given, is fed to the child as it reads and the pipe is then
/// closed; otherwise stdin is the null device. Every pipe is read and written
/// on the calling thread and closed before this returns. `watch`, when given,
/// is the path the child stages its output in: its size and entry count are
/// held to the disk ceilings while the child runs and measured exactly once it
/// exits.
/// The deadline is `started + limits.wall`. Stdout is held to its ceiling and
/// the child is killed the moment it writes past it; stderr is truncated at
/// [`CHILD_STDERR_MAX_BYTES`]. Once the child exits, its pipes have
/// [`PIPE_DRAIN_GRACE`] to reach their end.
fn run_core(
    mut command: Command,
    stdin: Option<Zeroizing<Vec<u8>>>,
    watch: Option<&Path>,
    limits: &RunLimits,
    started: Instant,
    mode: Mode,
) -> Result<Captured, RunError<IngestLimit>> {
    let out_of_time = || started.elapsed() >= limits.wall.get();
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
    let mut io =
        ChildIo::take(&mut running.child, stdin, limits.stdout_bytes).map_err(RunError::Spawn)?;
    let stdout_over = || RunError::Exceeded(IngestLimit::Bytes(limits.stdout_bytes.get()));
    let check_disk = |path: &Path| -> Result<(), RunError<IngestLimit>> {
        let usage = measure_limits(path, limits).map_err(|(path, e)| RunError::Measure(path, e))?;
        exceeded(usage, limits).map_or(Ok(()), |limit| Err(RunError::Exceeded(limit)))
    };

    let mut idle = IDLE_MIN;
    let mut measured: Option<Instant> = None;
    let status = loop {
        let moved = io.pump();
        if io.stdout.is_over() {
            return Err(stdout_over());
        }
        if let Some((stream, kind)) = io.read_failure() {
            return Err(RunError::PipeRead(stream, kind));
        }
        if running.exited().map_err(RunError::Wait)? {
            break running.finish().map_err(RunError::Wait)?;
        }
        if out_of_time() {
            return Err(RunError::Exceeded(IngestLimit::Time(limits.wall)));
        }
        if let Some(path) = watch
            && measured.is_none_or(|at| at.elapsed() >= POLL_INTERVAL)
        {
            check_disk(path)?;
            measured = Some(Instant::now());
        }
        idle = pause(moved, idle);
    };

    if let Some(path) = watch {
        check_disk(path)?;
    }
    io.close_stdin();
    let exited = Instant::now();
    let mut idle = IDLE_MIN;
    loop {
        let moved = io.pump();
        if io.stdout.is_over() {
            return Err(stdout_over());
        }
        if let Some((stream, kind)) = io.read_failure() {
            return Err(RunError::PipeRead(stream, kind));
        }
        let Some(stream) = io.open_stream() else {
            break;
        };
        if exited.elapsed() >= PIPE_DRAIN_GRACE {
            return Err(RunError::PipeDrainTimeout(stream));
        }
        idle = pause(moved, idle);
    }
    let ChildIo { stdout, stderr, .. } = io;
    let stderr = if stderr.is_over() {
        ChildStderr::Truncated(stderr.into_kept())
    } else {
        ChildStderr::Whole(stderr.into_kept())
    };
    Ok(Captured {
        status,
        stdout: stdout.into_kept(),
        stderr,
    })
}

/// Run a local probe attached, with no stdin, its stdout held to `stdout_bytes` and its run to `wall`.
///
/// It registers no signal handler, so a signal owner may run it while reading
/// the dispositions it acts on. Any failure reads as `None`.
#[cfg(all(unix, any(not(target_os = "linux"), test)))]
pub(crate) fn run_probe(
    command: Command,
    stdout_bytes: ByteBudget,
    wall: WallBudget,
) -> Option<Captured> {
    let limits = RunLimits {
        staging: Staging::Nothing,
        stdout_bytes,
        wall: wall.limit(),
    };
    run_core(command, None, None, &limits, Instant::now(), Mode::Probe).ok()
}

/// The most a signal owner's disposition probe may print.
#[cfg(all(unix, any(not(target_os = "linux"), test)))]
pub(crate) const PROBE_STDOUT_MAX_BYTES: ByteBudget = ByteBudget::of::<256>();

/// Kill every transfer's process group and refuse every later one.
///
/// The termination owner calls it on every termination request, before the
/// CLI acts on the request.
#[cfg(unix)]
pub(crate) fn end_transfers() {
    group::end_all();
}

/// The process-group primitives, for the signal owners' tests.
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod test_group {
    pub use super::group::{exited, forget, forget_attached, kill, spawn_attached, spawn_detached};
}

/// A spawned child that is killed and reaped however the watcher leaves it.
///
/// The order is fixed: kill the group, deregister it from the signal relay,
/// then reap the leader. Until the leader is reaped its process ID, which is
/// also the group ID, cannot be reused, so no kill can reach an unrelated group.
struct Running {
    child: Child,
    group: Option<group::GroupId>,
    /// The attached child, while the termination owner may kill it.
    attached: Option<group::AttachedId>,
    reaped: bool,
}

impl Running {
    /// Spawn `command` in `mode` through the runtime's hardened spawner, bound
    /// to the CLI's lifetime where the platform allows.
    fn spawn(command: Command, mode: Mode) -> std::io::Result<Self> {
        let (child, group, attached) = match mode {
            Mode::Detached => {
                let (child, group) = group::spawn_detached(command)?;
                (child, group, None)
            }
            Mode::Attached => {
                let (child, attached) = group::spawn_attached(command)?;
                (child, None, attached)
            }
            #[cfg(all(unix, any(not(target_os = "linux"), test)))]
            Mode::Probe => (
                ipe_runtime_rust::system::spawn_hardened(command)?,
                None,
                None,
            ),
        };
        Ok(Self {
            child,
            group,
            attached,
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
    /// Waiting failed, or a signal ended every transfer
    /// ([`std::io::ErrorKind::Interrupted`]): its owner may have killed the
    /// child, so its status is not the transfer's outcome.
    fn finish(&mut self) -> std::io::Result<ExitStatus> {
        if let Some(id) = self.group.take() {
            group::kill(id);
            group::forget(id);
        }
        if let Some(id) = self.attached.take() {
            group::forget_attached(id);
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
        if let Some(id) = self.attached.take() {
            group::forget_attached(id);
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

impl Running {
    /// Kill the child's group, or the child where it leads none, leaving it unreaped.
    fn kill(&mut self) {
        match self.group {
            Some(id) => group::kill(id),
            None => {
                // The child may already have exited; `reap` or `stop` reaps it.
                let _ = self.child.kill();
            }
        }
    }

    /// Reap the exited child, leaving what it started in its group running.
    ///
    /// # Errors
    /// Waiting failed, or a signal ended every transfer
    /// ([`std::io::ErrorKind::Interrupted`]): its owner may have killed the
    /// child, so its status is not the run's outcome.
    fn reap(&mut self) -> std::io::Result<ExitStatus> {
        if let Some(id) = self.group.take() {
            group::forget(id);
        }
        if let Some(id) = self.attached.take() {
            group::forget_attached(id);
        }
        let status = self.child.wait();
        self.reaped = true;
        if group::ended() {
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        status
    }
}

/// A child leading its own process group, killed and reaped however it is left.
///
/// The group lets a wall stop every process the child started, not only the
/// child. Outside the terminal's foreground group, the child hears an
/// interrupt, a quit, a hangup, a stop and a continue only through the relay
/// every detached group shares, and its group is killed on a termination
/// request. On a platform without process groups it is a plain child.
pub struct GroupedChild(Running);

impl GroupedChild {
    /// Spawn `command` as the leader of a new process group.
    ///
    /// The child starts through the runtime's hardened spawner.
    ///
    /// # Errors
    /// The termination owner or the relay could not be installed, a signal
    /// ended every detached group ([`std::io::ErrorKind::Interrupted`]), or
    /// the spawn failed.
    pub fn spawn(command: Command) -> std::io::Result<Self> {
        Running::spawn(command, Mode::Detached).map(Self)
    }

    /// Take the child's stdout and stderr pipes, when piped.
    pub const fn take_pipes(&mut self) -> (Option<ChildStdout>, Option<ChildStderr>) {
        (self.0.child.stdout.take(), self.0.child.stderr.take())
    }

    /// Whether the child has exited, leaving it unreaped.
    ///
    /// # Errors
    /// The platform could not report the child's state.
    pub fn exited(&mut self) -> std::io::Result<bool> {
        self.0.exited()
    }

    /// Kill the child and every process in its group, leaving the child unreaped.
    pub fn kill(&mut self) {
        self.0.kill();
    }

    /// Reap the exited child; what it started in its group is left running.
    ///
    /// # Errors
    /// Waiting failed, or a signal ended every detached group
    /// ([`std::io::ErrorKind::Interrupted`]), so its status is not the run's
    /// outcome.
    pub fn reap(&mut self) -> std::io::Result<ExitStatus> {
        self.0.reap()
    }

    /// Kill the child's whole group and reap the child.
    ///
    /// # Errors
    /// As [`Self::reap`].
    pub fn finish(&mut self) -> std::io::Result<ExitStatus> {
        self.0.finish()
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

    /// A live attached child's process ID.
    pub type AttachedId = Pid;

    /// The groups and attached children spawned and not yet reaped, for the
    /// signal owners.
    struct Registry {
        /// Every live group.
        live: Vec<Pid>,
        /// Every live attached child; it shares the CLI's group, so it is
        /// killed by its own ID.
        attached: Vec<Pid>,
        /// Whether a signal ended every transfer; no group starts after it.
        ended: bool,
    }

    impl Registry {
        /// Admit a new group, unless a signal ended every transfer.
        fn admit(&self) -> std::io::Result<()> {
            if self.ended {
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            Ok(())
        }
    }

    static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
        live: Vec::new(),
        attached: Vec::new(),
        ended: false,
    });

    /// Spawn `command` as the leader of a new process group.
    ///
    /// The group is registered while the registry is held, so a signal either
    /// sees the group or is answered before it exists.
    ///
    /// # Errors
    /// The termination owner or the relay could not be installed, a signal
    /// ended every transfer ([`std::io::ErrorKind::Interrupted`]), or the
    /// spawn failed.
    pub fn spawn_detached(mut command: Command) -> std::io::Result<(Child, Option<Pid>)> {
        crate::terminate::ensure()?;
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

    /// Spawn `command` in the CLI's process group, known to the termination owner.
    ///
    /// The child is registered while the registry is held, so a termination
    /// request either sees it or is answered before it exists. Its ID stays
    /// its own until it is reaped, which happens only after
    /// [`forget_attached`].
    ///
    /// # Errors
    /// The termination owner could not be installed, a signal ended every
    /// transfer ([`std::io::ErrorKind::Interrupted`]), or the spawn failed.
    pub fn spawn_attached(command: Command) -> std::io::Result<(Child, Option<Pid>)> {
        crate::terminate::ensure()?;
        let mut registry = REGISTRY.lock().unwrap_or_else(PoisonError::into_inner);
        registry.admit()?;
        let child = ipe_runtime_rust::system::spawn_hardened(command)?;
        let pid = Pid::from_child(&child);
        registry.attached.push(pid);
        drop(registry);
        Ok((child, Some(pid)))
    }

    /// Deregister attached child `id`; it is reaped only after this.
    pub fn forget_attached(id: Pid) {
        REGISTRY
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .attached
            .retain(|live| *live != id);
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

    /// Kill every registered group and attached child, and refuse every later one.
    pub fn end_all() {
        let mut registry = REGISTRY.lock().unwrap_or_else(PoisonError::into_inner);
        registry.ended = true;
        for id in &registry.live {
            let _ = rustix::process::kill_process_group(*id, Signal::Kill);
        }
        for id in &registry.attached {
            let _ = rustix::process::kill_process(*id, Signal::Kill);
        }
    }

    /// Whether a signal ended every transfer.
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
                attached: Vec::new(),
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

    /// Uninhabited: no attached child is tracked on this platform.
    #[derive(Debug, Clone, Copy)]
    pub enum AttachedId {}

    /// Spawn `command` as a plain child.
    pub fn spawn_detached(command: Command) -> std::io::Result<(Child, Option<GroupId>)> {
        Ok((ipe_runtime_rust::system::spawn_hardened(command)?, None))
    }

    /// Spawn `command` as a plain child.
    pub fn spawn_attached(command: Command) -> std::io::Result<(Child, Option<AttachedId>)> {
        Ok((ipe_runtime_rust::system::spawn_hardened(command)?, None))
    }

    /// Unreachable: no `AttachedId` exists.
    pub const fn forget_attached(id: AttachedId) {
        match id {}
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

    /// Nothing to end: no group is ever created on this platform.
    #[cfg(unix)]
    pub const fn end_all() {}
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
/// - caught by a handler of the host process, or unreadable: the signal is
///   relayed to the groups only, and the CLI never takes a default action over
///   a handler or one it may have inherited as ignored. An interrupt, quit or
///   hangup kills every group and refuses every later one, so the command ends
///   with an error rather than by the signal; a stop stops only the groups,
///   which the transfer deadline still bounds. Leaving the signal unregistered
///   instead would let a default-action interrupt end the CLI and orphan the
///   transfer, unbounded where no parent-death signal reaches it.
///
/// A continue is always relayed: the kernel resumes the CLI whatever it
/// inherited. The inherited dispositions are the termination owner's one
/// reading, taken before either owner registers a handler.
#[cfg(all(unix, not(any(target_os = "openbsd", target_os = "redox"))))]
mod relay {
    use std::ffi::c_int;
    use std::sync::OnceLock;

    use rustix::process::Signal;
    use signal_hook::consts::{SIGCONT, SIGHUP, SIGINT, SIGQUIT, SIGTSTP};
    use signal_hook::iterator::Signals;

    use crate::terminate::{Effect, Handling, Inherited};

    /// The signals relayed to the detached groups, each with its default effect.
    const RELAYED: [(c_int, Effect); 5] = [
        (SIGINT, Effect::Ends),
        (SIGQUIT, Effect::Ends),
        (SIGHUP, Effect::Ends),
        (SIGTSTP, Effect::Stops),
        (SIGCONT, Effect::Continues),
    ];

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
        let steps = plan(crate::terminate::inherited());
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

    #[cfg(test)]
    mod tests {
        use super::{Handling, Inherited, plan};
        use crate::terminate::SignalSet;
        use signal_hook::consts::{SIGCONT, SIGHUP, SIGINT, SIGQUIT, SIGTSTP};
        #[cfg(target_os = "linux")]
        use std::io::Write as _;

        /// The set holding exactly `signals`.
        fn set(signals: &[i32]) -> SignalSet {
            SignalSet(signals.iter().fold(0, |mask, signal| {
                let bit = u32::try_from(*signal - 1).expect("a signal number");
                mask | (1u64 << bit)
            }))
        }

        #[test]
        fn a_known_ignored_signal_stays_unregistered() {
            let inherited = Inherited::Known {
                ignored: set(&[SIGHUP, SIGTSTP]),
                caught: set(&[]),
            };
            let registered: Vec<i32> = plan(inherited).iter().map(|step| step.signal).collect();
            assert_eq!(registered, [SIGINT, SIGQUIT, SIGCONT]);
        }

        #[test]
        fn a_caught_signal_is_relayed_without_the_default() {
            let inherited = Inherited::Known {
                ignored: set(&[]),
                caught: set(&[SIGINT]),
            };
            let steps = plan(inherited);
            assert!(
                steps
                    .iter()
                    .any(|step| step.signal == SIGINT && step.handling == Handling::RelayOnly)
            );
            assert!(
                steps
                    .iter()
                    .any(|step| step.signal == SIGQUIT
                        && step.handling == Handling::RelayThenDefault)
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

        /// Printed by [`hangup_child`] once its transfer outlived the hangup.
        #[cfg(target_os = "linux")]
        const SURVIVED: &str = "ipe-relay-hangup-survived";

        /// Printed by [`hangup_child_default`] just before it raises the hangup.
        #[cfg(target_os = "linux")]
        const ARMED: &str = "ipe-relay-hangup-armed";

        #[cfg(target_os = "linux")]
        #[test]
        fn an_inherited_ignored_hangup_leaves_the_cli_and_its_transfer_running() {
            let output = crate::terminate::tests::test_child::run(
                "trap '' HUP;",
                "remote_ingest::relay::tests::hangup_child",
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(output.status.success(), "child failed: {output:?}");
            assert!(stdout.contains(SURVIVED), "child output: {output:?}");
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn a_default_hangup_ends_the_cli() {
            use std::os::unix::process::ExitStatusExt as _;
            let parent = crate::terminate::inherited();
            if parent == Inherited::Unknown
                || matches!(parent, Inherited::Known { ignored, .. } if ignored.contains(SIGHUP))
            {
                return;
            }
            let output = crate::terminate::tests::test_child::run(
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
            let Inherited::Known { ignored, .. } = crate::terminate::inherited() else {
                return;
            };
            if !ignored.contains(SIGHUP) {
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

/// How many reads or writes one pump of a pipe makes at most.
const PUMP_ROUNDS: u32 = 16;

/// The most bytes one read takes from a pipe.
const PUMP_CHUNK: usize = 16 * 1024;

/// The pause after the first pump that moved nothing; it doubles up to [`POLL_INTERVAL`].
const IDLE_MIN: Duration = Duration::from_millis(1);

/// Pause before the next pump unless the last one moved bytes, returning the pause after that.
///
/// A pump that moved bytes resets the pause; one that moved nothing doubles
/// it, up to [`POLL_INTERVAL`].
fn pause(moved: bool, idle: Duration) -> Duration {
    if moved {
        return IDLE_MIN;
    }
    std::thread::sleep(idle);
    idle.saturating_mul(2).min(POLL_INTERVAL)
}

/// What one output pipe left once it was read to its end.
#[cfg(any(not(unix), test))]
#[derive(Debug, PartialEq, Eq)]
enum CaptureOutcome {
    /// Every byte the pipe carried, within the cap.
    Complete(Vec<u8>),
    /// The first `cap` bytes; more arrived and was read and dropped.
    Overflowed(Vec<u8>),
    /// A read failed before the end, so the bytes read are not the whole output.
    ReadFailed(std::io::ErrorKind),
}

/// Keep at most `cap` bytes of `pipe`, then read the rest into a sink.
///
/// The pipe is drained to its end so the child never blocks on a full pipe. A
/// failed read, on the kept part or the drained rest, is
/// [`CaptureOutcome::ReadFailed`], never bytes that look complete.
#[cfg(any(not(unix), test))]
fn capture(mut pipe: impl Read, cap: ByteBudget) -> CaptureOutcome {
    let mut kept = Vec::new();
    if let Err(e) = (&mut pipe).take(cap.get()).read_to_end(&mut kept) {
        return CaptureOutcome::ReadFailed(e.kind());
    }
    match std::io::copy(&mut pipe, &mut std::io::sink()) {
        Err(e) => CaptureOutcome::ReadFailed(e.kind()),
        Ok(0) => CaptureOutcome::Complete(kept),
        Ok(_) => CaptureOutcome::Overflowed(kept),
    }
}

/// A watched child's pipes, read and written by the thread that waits on it.
///
/// Stdout is held to its ceiling, stderr is truncated at
/// [`CHILD_STDERR_MAX_BYTES`], and stdin is fed from its buffer as the child
/// reads it. Dropping it closes every pipe it holds.
struct ChildIo {
    stdout: pipes::Reader,
    stderr: pipes::Reader,
    stdin: Option<pipes::Feed>,
}

impl ChildIo {
    /// Take `child`'s pipes, holding stdout to `stdout_bytes`; `stdin`, when given, is fed to its stdin.
    fn take(
        child: &mut Child,
        stdin: Option<Zeroizing<Vec<u8>>>,
        stdout_bytes: ByteBudget,
    ) -> std::io::Result<Self> {
        let stdout = pipes::Reader::new(child.stdout.take(), stdout_bytes)?;
        let stderr = pipes::Reader::new(child.stderr.take(), CHILD_STDERR_MAX_BYTES)?;
        let stdin = match (stdin, child.stdin.take()) {
            (Some(bytes), Some(pipe)) => Some(pipes::Feed::new(pipe, bytes)?),
            _ => None,
        };
        Ok(Self {
            stdout,
            stderr,
            stdin,
        })
    }

    /// Move what every pipe has ready, returning whether any byte moved.
    fn pump(&mut self) -> bool {
        let fed = self.stdin.as_mut().is_some_and(pipes::Feed::pump);
        let read_out = self.stdout.pump();
        let read_err = self.stderr.pump();
        fed || read_out || read_err
    }

    /// Stop feeding stdin and close its pipe.
    fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// The first output pipe whose read failed, stdout before stderr, with how it failed.
    const fn read_failure(&self) -> Option<(Stream, std::io::ErrorKind)> {
        if let Some(kind) = self.stdout.failure() {
            Some((Stream::Stdout, kind))
        } else if let Some(kind) = self.stderr.failure() {
            Some((Stream::Stderr, kind))
        } else {
            None
        }
    }

    /// The first output pipe not yet at its end, stdout before stderr.
    const fn open_stream(&self) -> Option<Stream> {
        if self.stdout.is_open() {
            Some(Stream::Stdout)
        } else if self.stderr.is_open() {
            Some(Stream::Stderr)
        } else {
            None
        }
    }
}

/// A child's pipes made non-blocking, so the waiting thread moves their bytes itself.
#[cfg(unix)]
mod pipes {
    use std::fs::File;
    use std::io::{ErrorKind, Read as _, Write as _};
    use std::os::fd::OwnedFd;

    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
    use zeroize::Zeroizing;

    use super::{ByteBudget, PUMP_CHUNK, PUMP_ROUNDS};

    /// `pipe` as a file whose reads and writes never block.
    fn nonblocking(pipe: impl Into<OwnedFd>) -> std::io::Result<File> {
        let fd: OwnedFd = pipe.into();
        let flags = fcntl_getfl(&fd)?;
        fcntl_setfl(&fd, flags | OFlags::NONBLOCK)?;
        Ok(File::from(fd))
    }

    /// The bytes kept from one output pipe.
    struct Kept {
        /// At most `cap` bytes.
        bytes: Vec<u8>,
        /// The most bytes kept.
        cap: ByteBudget,
        /// Whether more than `cap` bytes arrived.
        over: bool,
    }

    impl Kept {
        /// Keep what of `chunk` fits under the cap and note whether any did not.
        fn keep(&mut self, chunk: &[u8]) {
            let held = u64::try_from(self.bytes.len()).unwrap_or(u64::MAX);
            let room = usize::try_from(self.cap.get().saturating_sub(held)).unwrap_or(usize::MAX);
            let fits = chunk.get(..room).unwrap_or(chunk);
            self.bytes.extend_from_slice(fits);
            self.over |= fits.len() < chunk.len();
        }
    }

    /// One output pipe, read until its end.
    pub struct Reader {
        /// The pipe, until it reaches its end or fails.
        pipe: Option<File>,
        kept: Kept,
        /// How the read failed, once it did.
        failed: Option<ErrorKind>,
    }

    impl Reader {
        /// Read `pipe`, keeping at most `cap` bytes; no pipe is a pipe at its end.
        pub fn new(pipe: Option<impl Into<OwnedFd>>, cap: ByteBudget) -> std::io::Result<Self> {
            Ok(Self {
                pipe: pipe.map(nonblocking).transpose()?,
                kept: Kept {
                    bytes: Vec::new(),
                    cap,
                    over: false,
                },
                failed: None,
            })
        }

        /// Read what the pipe has ready, returning whether any byte arrived.
        ///
        /// The end of the pipe closes it; a failed read closes it and is kept
        /// as [`Self::failure`], so the bytes read so far never pass as the
        /// whole output.
        pub fn pump(&mut self) -> bool {
            let Some(pipe) = self.pipe.as_mut() else {
                return false;
            };
            let mut chunk = [0u8; PUMP_CHUNK];
            let mut moved = false;
            for _ in 0..PUMP_ROUNDS {
                match pipe.read(&mut chunk) {
                    Err(e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Ok(0) => {
                        self.pipe = None;
                        break;
                    }
                    Err(e) => {
                        self.pipe = None;
                        self.failed = Some(e.kind());
                        break;
                    }
                    Ok(n) => {
                        moved = true;
                        self.kept.keep(chunk.get(..n).unwrap_or_default());
                    }
                }
            }
            moved
        }

        /// Whether the pipe has not reached its end.
        pub const fn is_open(&self) -> bool {
            self.pipe.is_some()
        }

        /// Whether more than the cap arrived.
        pub const fn is_over(&self) -> bool {
            self.kept.over
        }

        /// How reading the pipe failed, if it did.
        pub const fn failure(&self) -> Option<ErrorKind> {
            self.failed
        }

        /// The bytes kept.
        pub fn into_kept(self) -> Vec<u8> {
            self.kept.bytes
        }
    }

    /// A stdin pipe fed from a buffer, closed once the buffer is written.
    pub struct Feed {
        /// The pipe, until the buffer is written or a write fails.
        pipe: Option<File>,
        bytes: Zeroizing<Vec<u8>>,
        /// How many of `bytes` were written.
        written: usize,
        /// How the write failed, once it did.
        failed: Option<ErrorKind>,
    }

    impl Feed {
        /// Feed `bytes` to `pipe`.
        pub fn new(pipe: impl Into<OwnedFd>, bytes: Zeroizing<Vec<u8>>) -> std::io::Result<Self> {
            Ok(Self {
                pipe: Some(nonblocking(pipe)?),
                bytes,
                written: 0,
                failed: None,
            })
        }

        /// Whether the pipe is still open, the buffer neither written nor refused.
        pub const fn is_open(&self) -> bool {
            self.pipe.is_some()
        }

        /// How the feed fell short of the whole buffer, if it did.
        ///
        /// A buffer not wholly written with no failed write is a pipe the
        /// child left before reading it: [`ErrorKind::BrokenPipe`].
        pub fn shortfall(&self) -> Option<ErrorKind> {
            (self.written < self.bytes.len())
                .then_some(self.failed.unwrap_or(ErrorKind::BrokenPipe))
        }

        /// Write what the pipe takes, returning whether any byte was written.
        ///
        /// A failed write closes the pipe and is kept for [`Self::shortfall`].
        pub fn pump(&mut self) -> bool {
            let Some(pipe) = self.pipe.as_mut() else {
                return false;
            };
            let mut moved = false;
            for _ in 0..PUMP_ROUNDS {
                let rest = self.bytes.get(self.written..).unwrap_or_default();
                if rest.is_empty() {
                    self.pipe = None;
                    break;
                }
                match pipe.write(rest) {
                    Err(e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Ok(0) => {
                        self.pipe = None;
                        self.failed = Some(ErrorKind::WriteZero);
                        break;
                    }
                    Err(e) => {
                        self.pipe = None;
                        self.failed = Some(e.kind());
                        break;
                    }
                    Ok(n) => {
                        moved = true;
                        self.written = self.written.saturating_add(n);
                    }
                }
            }
            moved
        }
    }
}

/// A child's pipes read and written on threads, where the platform has no non-blocking pipes.
#[cfg(not(unix))]
mod pipes {
    use std::io::{ErrorKind, Read};
    use std::sync::mpsc;

    use zeroize::Zeroizing;

    use super::{ByteBudget, CaptureOutcome, POLL_INTERVAL, capture};

    /// One output pipe, read to its end on its own thread.
    pub struct Reader {
        /// The reading thread's result, until it arrives.
        capture: Option<mpsc::Receiver<CaptureOutcome>>,
        kept: Vec<u8>,
        over: bool,
        /// How the read failed, once it did.
        failed: Option<ErrorKind>,
    }

    impl Reader {
        /// Read `pipe` on a thread, keeping at most `cap` bytes; no pipe is a pipe at its end.
        pub fn new(
            pipe: Option<impl Read + Send + 'static>,
            cap: ByteBudget,
        ) -> std::io::Result<Self> {
            let capture = pipe
                .map(|pipe| {
                    let (tx, rx) = mpsc::channel();
                    std::thread::Builder::new()
                        .name("ipe-child-capture".to_owned())
                        .spawn(move || {
                            let _ = tx.send(capture(pipe, cap));
                        })
                        .map(|_| rx)
                })
                .transpose()?;
            Ok(Self {
                capture,
                kept: Vec::new(),
                over: false,
                failed: None,
            })
        }

        /// Collect the thread's result if it arrived, returning whether it did.
        pub fn pump(&mut self) -> bool {
            let Some(capture) = self.capture.as_ref() else {
                return false;
            };
            match capture.try_recv() {
                Ok(outcome) => {
                    match outcome {
                        CaptureOutcome::Complete(kept) => self.kept = kept,
                        CaptureOutcome::Overflowed(kept) => {
                            self.kept = kept;
                            self.over = true;
                        }
                        CaptureOutcome::ReadFailed(kind) => self.failed = Some(kind),
                    }
                    self.capture = None;
                    true
                }
                Err(mpsc::TryRecvError::Empty) => false,
                Err(mpsc::TryRecvError::Disconnected) => {
                    // The reading thread ended without a result, so nothing
                    // read stands for the whole output.
                    self.capture = None;
                    self.failed = Some(ErrorKind::BrokenPipe);
                    false
                }
            }
        }

        /// Whether the pipe has not reached its end.
        pub const fn is_open(&self) -> bool {
            self.capture.is_some()
        }

        /// Whether more than the cap arrived.
        pub const fn is_over(&self) -> bool {
            self.over
        }

        /// How reading the pipe failed, if it did.
        pub const fn failure(&self) -> Option<ErrorKind> {
            self.failed
        }

        /// The bytes kept.
        pub fn into_kept(self) -> Vec<u8> {
            self.kept
        }
    }

    /// A stdin pipe fed from a buffer on its own thread.
    pub struct Feed {
        /// Signalled with the write's outcome once it ended, until it is seen.
        done: Option<mpsc::Receiver<Result<(), ErrorKind>>>,
        /// The write's outcome, once seen.
        outcome: Option<Result<(), ErrorKind>>,
    }

    impl Feed {
        /// Write `bytes` to `pipe` on a thread, then close it.
        pub fn new(
            mut pipe: impl std::io::Write + Send + 'static,
            bytes: Zeroizing<Vec<u8>>,
        ) -> std::io::Result<Self> {
            let (tx, rx) = mpsc::channel();
            std::thread::Builder::new()
                .name("ipe-child-stdin".to_owned())
                .spawn(move || {
                    // The outcome reaches the waiting thread, which judges a
                    // short write by the child's role.
                    let _ = tx.send(pipe.write_all(&bytes).map_err(|e| e.kind()));
                })?;
            Ok(Self {
                done: Some(rx),
                outcome: None,
            })
        }

        /// Whether the write ended since the last pump.
        pub fn pump(&mut self) -> bool {
            let Some(done) = self.done.as_ref() else {
                return false;
            };
            let outcome = match done.try_recv() {
                Ok(outcome) => outcome,
                Err(mpsc::TryRecvError::Empty) => return false,
                Err(mpsc::TryRecvError::Disconnected) => Err(ErrorKind::BrokenPipe),
            };
            self.outcome = Some(outcome);
            self.done = None;
            true
        }

        /// Whether the write is still running.
        pub const fn is_open(&self) -> bool {
            self.done.is_some()
        }

        /// How the feed fell short of the whole buffer, if it did.
        ///
        /// A write still running is given [`POLL_INTERVAL`] to end, since the
        /// child it feeds has exited; one that does not end by then fell short.
        pub fn shortfall(&mut self) -> Option<ErrorKind> {
            if let Some(done) = self.done.take() {
                self.outcome = Some(
                    done.recv_timeout(POLL_INTERVAL)
                        .unwrap_or(Err(ErrorKind::BrokenPipe)),
                );
            }
            match self.outcome {
                Some(Ok(())) => None,
                Some(Err(kind)) => Some(kind),
                None => Some(ErrorKind::BrokenPipe),
            }
        }
    }
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
        run_local(self.command, QUERY_LIMITS, source)
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
        budget.wall.secs().to_string(),
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
        CURL_OPERATION_TIMEDOUT => IngestLimit::Time(budget.wall.limit()),
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
        ALL_BUDGETS, Budget, BudgetPairing, ByteBudget, CHILD_STDERR_MAX_BYTES, CappedReadError,
        CaptureOutcome, Captured, ChildStderr, EntryBudget, FetchBudget, GITHUB_API, Git,
        IngestLimit, IngestRefusal, IngestSource, InheritedInput, InheritedRole, LocalRefusal,
        LocalSource, LocalWall, MAX_REMOTE_BYTES, MAX_REMOTE_ENTRIES, MAX_WALL_SECS, Mode,
        PACKAGE_SOURCE, PackageName, RefsCeiling, RunError, Staging, Stream, TOOL_QUERY_LIMITS,
        Transfer, TreeCeiling, Usage, WallBudget, capture, curl_limit_args, curl_refusal, measure,
        read_capped, run_core, run_inherited, run_local_fed,
    };
    use std::io::Read;
    use std::process::Command;
    use std::time::{Duration, Instant};

    const CAP: u64 = 16;

    /// The byte ceiling `n`.
    #[allow(clippy::expect_used)] // fixture ceilings are literal in-range values
    fn bytes(n: u64) -> ByteBudget {
        ByteBudget::for_test(n).expect("in-range byte budget")
    }

    /// The entry ceiling `n`.
    #[allow(clippy::expect_used)] // fixture ceilings are literal in-range values
    fn entries(n: u64) -> EntryBudget {
        EntryBudget::for_test(n).expect("in-range entry budget")
    }

    /// The wall ceiling of `secs` seconds.
    #[allow(clippy::expect_used)] // fixture ceilings are literal in-range values
    fn wall(secs: u64) -> WallBudget {
        WallBudget::for_test(Duration::from_secs(secs)).expect("in-range wall budget")
    }

    /// A fixture budget that stages nothing.
    fn unstaged() -> Budget {
        PACKAGE_SOURCE
            .transfer()
            .with_staging(Staging::Nothing)
            .with_stdout(bytes(CAP))
            .with_wall(wall(30))
    }

    /// A fixture budget staging at most `disk_bytes` bytes in `disk_entries` entries.
    fn staged(disk_bytes: u64, disk_entries: u64) -> Budget {
        unstaged().with_staging(Staging::Disk {
            bytes: bytes(disk_bytes),
            entries: entries(disk_entries),
        })
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

    /// A wall ceiling exists only as whole seconds inside `1..=MAX_WALL_SECS`.
    #[test]
    fn a_sub_second_wall_has_no_representation() {
        assert_eq!(WallBudget::for_test(Duration::ZERO), None);
        assert_eq!(WallBudget::for_test(Duration::from_millis(1)), None);
        assert_eq!(WallBudget::for_test(Duration::from_millis(999)), None);
        assert_eq!(WallBudget::for_test(Duration::from_millis(1_500)), None);
        assert_eq!(
            WallBudget::for_test(Duration::from_secs(1)).map(WallBudget::secs),
            Some(1)
        );
        assert_eq!(
            WallBudget::for_test(Duration::from_secs(MAX_WALL_SECS)).map(WallBudget::get),
            Some(Duration::from_secs(MAX_WALL_SECS))
        );
        assert_eq!(
            WallBudget::for_test(Duration::from_secs(MAX_WALL_SECS + 1)),
            None
        );
    }

    /// Every named surface budget sits inside the remote ceilings.
    #[test]
    fn every_named_budget_is_within_the_remote_ceilings() {
        assert!(ALL_BUDGETS.contains(PACKAGE_SOURCE.transfer()));
        for budget in ALL_BUDGETS {
            if let Staging::Disk { bytes, entries } = budget.staging() {
                assert!(bytes.get() <= MAX_REMOTE_BYTES, "{budget:?}");
                assert!(entries.get() <= MAX_REMOTE_ENTRIES, "{budget:?}");
            }
            assert!(
                budget.stdout_bytes().get() <= MAX_REMOTE_BYTES,
                "{budget:?}"
            );
            assert!(budget.wall().secs() <= MAX_WALL_SECS, "{budget:?}");
        }
    }

    /// No named budget yields a curl argument curl reads as "no limit" (`0`).
    #[test]
    fn curl_limit_args_never_emit_an_unlimited_value() {
        for budget in ALL_BUDGETS {
            let mut ceilings = vec![budget.stdout_bytes()];
            if let Staging::Disk { bytes, .. } = budget.staging() {
                ceilings.push(bytes);
            }
            for ceiling in ceilings {
                let [max_filesize, filesize, max_time, time] = curl_limit_args(ceiling, &budget);
                assert_eq!(max_filesize, "--max-filesize");
                assert_eq!(max_time, "--max-time");
                for value in [filesize, time] {
                    assert!(
                        value.parse::<u64>().is_ok_and(|n| n > 0),
                        "{budget:?} printed `{value}`"
                    );
                }
            }
        }
    }

    /// The response cap a curl call site passes is the byte ceiling its surface stages under.
    ///
    /// Curl's `--max-filesize`, the scratch watcher and the read-back all hold
    /// the same body to one ceiling.
    #[test]
    fn a_curl_response_cap_is_its_surfaces_staged_ceiling() {
        for (budget, cap) in [
            (GITHUB_API, super::JSON_RESPONSE_MAX_BYTES),
            (super::INSTALLER, super::INSTALLER_MAX_BYTES),
        ] {
            assert!(
                matches!(budget.staging(), Staging::Disk { bytes, .. } if bytes == cap),
                "{budget:?}"
            );
        }
    }

    /// A surface that stages nothing refuses its first staged byte.
    #[test]
    fn staging_nothing_refuses_one_staged_byte() {
        let dir = scratch();
        let empty = measure(dir.path(), &unstaged()).expect("measures");
        assert_eq!(empty, Usage::default());
        assert!(super::exceeded(empty, &unstaged().limits()).is_none());
        std::fs::write(dir.path().join("a"), [0u8; 1]).expect("a");
        let usage = measure(dir.path(), &unstaged()).expect("measures");
        assert_eq!(
            usage,
            Usage {
                bytes: 1,
                entries: 1
            }
        );
        assert_eq!(
            super::exceeded(usage, &unstaged().limits()),
            Some(IngestLimit::Bytes(0))
        );
    }

    /// A surface that stages nothing refuses its first staged entry, an empty file included.
    #[test]
    fn staging_nothing_refuses_one_staged_entry() {
        let dir = scratch();
        std::fs::write(dir.path().join("a"), b"").expect("a");
        let usage = measure(dir.path(), &unstaged()).expect("measures");
        assert_eq!(
            super::exceeded(usage, &unstaged().limits()),
            Some(IngestLimit::Entries(0))
        );
    }

    /// A fetch budget whose transfer stages nothing is not paired with any tree.
    #[test]
    fn a_fetch_budget_that_stages_nothing_is_refused() {
        let refs = RefsCeiling::for_test(bytes(64), 2);
        assert_eq!(
            FetchBudget::for_test(unstaged(), refs, tree(10, 4)),
            Err(BudgetPairing::TransferBytesUnderTree)
        );
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
        let budget = staged(16, 3);
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
        let budget = staged(16, 8);
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
        let budget = staged(1024, 3);
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
        let budget = staged(1024, 3);
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
        let at_bytes = staged(20, 1_000);
        assert!(FetchBudget::for_test(at_bytes, refs, tree(10, 4)).is_ok());
        assert_eq!(
            FetchBudget::for_test(staged(19, 1_000), refs, tree(10, 4)),
            Err(BudgetPairing::TransferBytesUnderTree)
        );
        let stage_entries = 4 + 2 + super::GIT_STAGE_OVERHEAD_ENTRIES;
        assert!(FetchBudget::for_test(staged(20, stage_entries), refs, tree(10, 4)).is_ok());
        assert_eq!(
            FetchBudget::for_test(staged(20, stage_entries - 1), refs, tree(10, 4)),
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
            (IngestLimit::Time(wall(9).limit()), "9 seconds"),
            (IngestLimit::Time(wall(1).limit()), "1 second"),
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
        let limit = IngestLimit::Time(wall(9).limit());
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
        let transfer = Transfer::begin(unstaged());
        let step = transfer.with_stdout_ceiling(bytes(7));
        assert_eq!(step.started, transfer.started);
        assert_eq!(step.budget.stdout_bytes, bytes(7));
        assert_eq!(step.budget.wall, transfer.budget.wall);
        assert_eq!(step.budget.staging, transfer.budget.staging);
    }

    #[test]
    fn a_missing_stage_measures_empty() {
        let dir = scratch();
        let usage = measure(&dir.path().join("absent"), &unstaged()).expect("measures");
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
        let run = run(command, None, Some(&out), &staged(16, 1));
        assert!(matches!(run, Ok(ref captured) if captured.status.success()));
    }

    #[cfg(unix)]
    #[test]
    fn a_child_staging_one_byte_past_the_cap_is_refused() {
        let dir = scratch();
        let out = dir.path().join("out");
        let mut command = sh("head -c 17 /dev/zero > \"$0\"");
        command.arg(&out);
        let run = run(command, None, Some(&out), &staged(16, 1));
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
        let run = run(command, None, Some(&out), &staged(cap, 1));
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
        let run = run(command, None, Some(dir.path()), &staged(1, 4));
        assert!(matches!(run, Ok(ref captured) if captured.status.success()));
    }

    #[cfg(unix)]
    #[test]
    fn a_child_staging_one_entry_past_the_cap_is_refused() {
        let dir = scratch();
        let command = touch_files(dir.path(), 5);
        let run = run(command, None, Some(dir.path()), &staged(1, 4));
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
        let transfer = Transfer::begin(staged(1, 4));
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
        let transfer = Transfer::begin(staged(1, 4));
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
        let run = run(command, None, Some(&out), &staged(cap, 1));
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
        let run = run(sh("sleep 30 & exit 0"), None, None, &unstaged());
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
            &unstaged().limits(),
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
        let mut limits = unstaged().limits();
        limits.wall = wall(2).limit();
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
        let limits = unstaged().with_wall(wall(1)).limits();
        let spent = Instant::now()
            .checked_sub(Duration::from_secs(2))
            .expect("the clock reads two seconds past its origin");
        let run = run_core(
            Command::new("ipe-no-such-program"),
            None,
            None,
            &limits,
            spent,
            Mode::Detached,
        );
        assert!(matches!(run, Err(RunError::Exceeded(IngestLimit::Time(_)))));
    }

    #[cfg(unix)]
    #[test]
    fn stdout_of_exactly_the_cap_is_kept_and_one_past_is_refused() {
        let at_cap = run(sh("head -c 16 /dev/zero"), None, None, &unstaged());
        assert!(matches!(at_cap, Ok(ref captured) if captured.stdout.len() == 16));
        let past = run(sh("head -c 17 /dev/zero"), None, None, &unstaged());
        assert!(matches!(
            past,
            Err(RunError::Exceeded(IngestLimit::Bytes(CAP)))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_child_past_its_wall_time_is_killed() {
        let quick = unstaged().with_wall(wall(1));
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
        let wide = unstaged().with_stdout(bytes(2 * 1024 * 1024));
        let run = run(sh("cat"), Some(&input), None, &wide);
        assert!(matches!(run, Ok(ref captured) if captured.stdout.len() == input.len()));
    }

    /// How many threads of this process carry a name starting with `prefix`.
    #[cfg(target_os = "linux")]
    fn threads_named(prefix: &str) -> usize {
        std::fs::read_dir("/proc/self/task")
            .expect("list this process's threads")
            .filter_map(Result::ok)
            .filter_map(|task| std::fs::read_to_string(task.path().join("comm")).ok())
            .filter(|name| name.starts_with(prefix))
            .count()
    }

    /// Kill the escaped process whose ID a child wrote to `pid_file`.
    #[cfg(target_os = "linux")]
    fn kill_escaped(pid_file: &std::path::Path) {
        let pid = std::fs::read_to_string(pid_file)
            .ok()
            .and_then(|text| text.trim().parse::<i32>().ok())
            .and_then(rustix::process::Pid::from_raw)
            .expect("the child wrote the escaped process's ID");
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::Kill);
    }

    /// A process that left the transfer's group and holds its output pipes
    /// ends the run within the grace, and no thread of the CLI waits on it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_setsid_grandchild_holding_stdout_returns_within_the_grace_and_leaves_no_thread() {
        let dir = scratch();
        let pid_file = dir.path().join("escaped.pid");
        // The escaped process writes its own ID once it has left the group, and
        // the child exits only then: the group kill at exit cannot reach it.
        let mut command = sh(
            "setsid sh -c 'echo $$ > \"$0\"; exec sleep 30' \"$0\" & i=0; while [ ! -s \"$0\" ] && [ $i -lt 500 ]; do sleep 0.01; i=$((i+1)); done; exit 0",
        );
        command.arg(&pid_file);
        let started = Instant::now();
        let run = run(command, None, None, &unstaged());
        let elapsed = started.elapsed();
        let lingering = threads_named("ipe-child-");
        kill_escaped(&pid_file);
        assert!(
            matches!(run, Err(RunError::PipeDrainTimeout(Stream::Stdout))),
            "{run:?}"
        );
        assert!(elapsed < Duration::from_secs(10), "took {elapsed:?}");
        assert_eq!(lingering, 0, "a pipe thread outlived the run");
    }

    /// A process that left the group holding stdin unread neither hangs the
    /// run nor leaves a thread writing to it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_grandchild_that_never_reads_stdin_leaves_no_feeding_thread() {
        let dir = scratch();
        let pid_file = dir.path().join("escaped.pid");
        let mut command = sh(
            "exec 3<&0; setsid sh -c 'echo $$ > \"$0\"; exec sleep 30' \"$0\" <&3 3<&- >/dev/null 2>&1 & i=0; while [ ! -s \"$0\" ] && [ $i -lt 500 ]; do sleep 0.01; i=$((i+1)); done; exit 0",
        );
        command.arg(&pid_file);
        let input = vec![b'x'; 1024 * 1024];
        let run = run(command, Some(&input), None, &unstaged());
        let lingering = threads_named("ipe-child-");
        kill_escaped(&pid_file);
        assert!(
            matches!(run, Ok(ref captured) if captured.status.success()),
            "{run:?}"
        );
        assert_eq!(lingering, 0, "a feeding thread outlived the run");
    }

    /// Stderr past its ceiling is cut, never a refusal and never a hang.
    #[cfg(unix)]
    #[test]
    fn stderr_over_its_ceiling_alone_is_truncated_not_hung() {
        let cap = CHILD_STDERR_MAX_BYTES.get();
        let script = format!("head -c {} /dev/zero >&2", cap.saturating_mul(3));
        let run = run(sh(&script), None, None, &unstaged());
        assert!(
            matches!(run, Ok(ref captured) if captured.status.success()
                && captured.stdout.is_empty()
                && captured.stderr.is_truncated()
                && u64::try_from(captured.stderr.bytes().len()).ok() == Some(cap)),
            "{run:?}"
        );
    }

    /// A child is refused the moment its stdout passes the ceiling, not when it exits.
    #[cfg(unix)]
    #[test]
    fn a_child_writing_past_its_stdout_ceiling_is_killed_before_it_exits() {
        let slow = unstaged().with_wall(wall(20));
        let started = Instant::now();
        let run = run(sh("head -c 17 /dev/zero; exec sleep 30"), None, None, &slow);
        assert!(
            matches!(run, Err(RunError::Exceeded(IngestLimit::Bytes(CAP)))),
            "{run:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// A live child writing exactly the stdout ceiling keeps running and exits on its own.
    ///
    /// The exit status is the discriminator: a kill at the cap instead of one
    /// byte past it would leave a signal status, not success.
    #[cfg(unix)]
    #[test]
    fn stdout_of_exactly_the_cap_from_a_live_child_is_kept_without_a_kill() {
        let budget = unstaged().with_wall(wall(10));
        let run = run(
            sh("head -c 16 /dev/zero; sleep 1; exit 0"),
            None,
            None,
            &budget,
        );
        assert!(
            matches!(run, Ok(ref captured) if captured.status.success()
                && u64::try_from(captured.stdout.len()).ok() == Some(CAP)),
            "{run:?}"
        );
    }

    /// One byte past the stdout ceiling kills a still-running child well before its wall.
    #[cfg(unix)]
    #[test]
    fn one_byte_past_the_cap_from_a_live_child_is_killed_early() {
        let budget = unstaged().with_wall(wall(60));
        let started = Instant::now();
        let run = run(sh("head -c 17 /dev/zero; sleep 30"), None, None, &budget);
        assert!(
            matches!(run, Err(RunError::Exceeded(IngestLimit::Bytes(CAP)))),
            "{run:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// A pipe that yields some bytes and then fails.
    struct FailingPipe {
        sent: bool,
    }

    impl Read for FailingPipe {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.sent {
                return Err(std::io::Error::other("pipe broke"));
            }
            self.sent = true;
            let n = buf.len().min(8);
            buf.iter_mut().take(n).for_each(|byte| *byte = b'x');
            Ok(n)
        }
    }

    /// A read error on an output pipe is a failed capture, never bytes that look complete.
    #[test]
    fn a_stdout_read_error_is_refused_not_truncated() {
        let outcome = capture(FailingPipe { sent: false }, bytes(CAP));
        assert_eq!(
            outcome,
            CaptureOutcome::ReadFailed(std::io::ErrorKind::Other)
        );
    }

    /// A pipe read to its end within the cap is complete; past it, overflowed.
    #[test]
    fn a_capture_names_whether_the_pipe_overflowed() {
        let within = capture([b'x'; 16].as_slice(), bytes(CAP));
        assert_eq!(within, CaptureOutcome::Complete(vec![b'x'; 16]));
        let past = capture([b'x'; 17].as_slice(), bytes(CAP));
        assert_eq!(past, CaptureOutcome::Overflowed(vec![b'x'; 16]));
    }

    /// A failed read on a live output pipe is kept as a failure, never taken for the pipe's end.
    ///
    /// A read on a directory descriptor fails (`EISDIR`); the watcher then
    /// names the pipe and how it failed, so the bytes read so far cannot pass
    /// as the child's whole output.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_pipe_read_is_a_failure_not_an_end() {
        let dir = std::fs::File::open("/").expect("open the root directory");
        let mut io = super::ChildIo {
            stdout: super::pipes::Reader::new(Some(dir), bytes(CAP)).expect("stdout reader"),
            stderr: super::pipes::Reader::new(None::<std::fs::File>, bytes(CAP))
                .expect("stderr reader"),
            stdin: None,
        };
        let _ = io.pump();
        assert!(io.open_stream().is_none(), "a failed pipe is closed");
        assert_eq!(
            io.read_failure(),
            Some((Stream::Stdout, std::io::ErrorKind::IsADirectory))
        );
    }

    /// Stderr one byte past its ceiling is kept to the ceiling and marked truncated.
    #[cfg(unix)]
    #[test]
    fn a_stderr_past_its_ceiling_is_marked_truncated() {
        let cap = CHILD_STDERR_MAX_BYTES.get();
        let script = format!("head -c {} /dev/zero >&2", cap.saturating_add(1));
        let run = run(sh(&script), None, None, &unstaged());
        assert!(
            matches!(run, Ok(ref captured) if captured.stderr.is_truncated()
                && u64::try_from(captured.stderr.bytes().len()).ok() == Some(cap)),
            "{run:?}"
        );
    }

    /// Stderr of exactly its ceiling is whole.
    #[cfg(unix)]
    #[test]
    fn a_stderr_within_its_ceiling_is_whole() {
        let cap = CHILD_STDERR_MAX_BYTES.get();
        let script = format!("head -c {cap} /dev/zero >&2");
        let run = run(sh(&script), None, None, &unstaged());
        assert!(
            matches!(run, Ok(ref captured) if !captured.stderr.is_truncated()
                && u64::try_from(captured.stderr.bytes().len()).ok() == Some(cap)),
            "{run:?}"
        );
    }

    /// The rendered cut names the stderr ceiling; a whole stderr carries no marker.
    #[test]
    fn the_truncation_marker_names_the_stderr_ceiling() {
        let ceiling = IngestLimit::Bytes(CHILD_STDERR_MAX_BYTES.get()).to_string();
        let cut = ChildStderr::Truncated(b"boom".to_vec()).to_terminal();
        assert!(cut.as_str().starts_with("boom"), "{}", cut.as_str());
        assert!(cut.as_str().contains(&ceiling), "{}", cut.as_str());
        let whole = ChildStderr::Whole(b"boom".to_vec()).to_terminal();
        assert_eq!(whole.as_str(), "boom");
    }

    /// The unsandboxed FFI inspector is held to the jailed inspector's default stdout and wall caps.
    #[test]
    fn the_ffi_inspect_ceiling_is_the_jails_default() {
        let jail = ipe_sandbox::ResourceLimits::default();
        assert_eq!(
            super::FFI_INSPECT_LIMITS.stdout_bytes().get(),
            jail.out_cap_bytes
        );
        assert_eq!(super::FFI_INSPECT_LIMITS.wall().secs(), jail.wall_secs);
    }

    /// A fed local child reads the bytes it is given on its stdin.
    #[cfg(unix)]
    #[test]
    fn a_fed_local_child_reads_its_stdin() {
        let run = run_local_fed(
            sh("cat"),
            zeroize::Zeroizing::new(b"hello".to_vec()),
            TOOL_QUERY_LIMITS,
            LocalSource::ToolQuery,
        );
        assert!(
            matches!(run, Ok(ref captured) if captured.status.success()
                && captured.stdout == b"hello"),
            "{run:?}"
        );
    }

    /// A fed local child still running at its wall is killed and refused on time.
    #[cfg(unix)]
    #[test]
    fn a_fed_local_child_past_its_wall_is_killed() {
        let started = Instant::now();
        let run = run_local_fed(
            sh("exec sleep 30"),
            zeroize::Zeroizing::new(b"hello".to_vec()),
            TOOL_QUERY_LIMITS.with_wall(LocalWall::of_secs::<1>()),
            LocalSource::ToolQuery,
        );
        assert!(
            matches!(
                run,
                Err(RunError::Exceeded(LocalRefusal {
                    source: LocalSource::ToolQuery,
                    limit: IngestLimit::Time(_),
                    ..
                }))
            ),
            "{run:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// An inherited child gets stdio and nothing else the CLI holds open.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_inherited_child_inherits_no_extra_descriptor() {
        use std::os::fd::AsRawFd as _;
        let held = rustix::fs::open(
            "/dev/null",
            rustix::fs::OFlags::RDONLY,
            rustix::fs::Mode::empty(),
        )
        .expect("open /dev/null");
        assert!(
            rustix::io::fcntl_getfd(&held)
                .is_ok_and(|flags| !flags.contains(rustix::io::FdFlags::CLOEXEC)),
            "the probe descriptor must be inheritable"
        );
        let script = format!("[ -e /dev/fd/{} ] && exit 3; exit 0", held.as_raw_fd());
        let status = run_inherited(
            sh(&script),
            InheritedRole::UserProgram,
            InheritedInput::Bytes(zeroize::Zeroizing::new(Vec::new())),
        );
        assert!(
            matches!(status, Ok(ref status) if status.success()),
            "{status:?}"
        );
        drop(held);
    }

    /// A first line, then more bytes than one pipe buffer holds, so a child that stops reading leaves some unwritten.
    #[cfg(unix)]
    fn script_past_pipe_buffer() -> zeroize::Zeroizing<Vec<u8>> {
        let mut bytes = b"first\n".to_vec();
        bytes.resize(256 * 1024, b'x');
        zeroize::Zeroizing::new(bytes)
    }

    /// An installer that closes its stdin and exits 0 before reading its whole script is refused.
    #[cfg(unix)]
    #[test]
    fn an_installer_that_leaves_its_script_unread_is_refused() {
        let outcome = run_inherited(
            sh("read -r line; exec 0<&-; exit 0"),
            InheritedRole::InteractiveInstall,
            InheritedInput::Bytes(script_past_pipe_buffer()),
        );
        assert!(
            matches!(outcome, Err(super::InheritedError::Feed(_))),
            "{outcome:?}"
        );
    }

    /// An installer that fails before reading its whole script keeps the exit status naming the failure.
    #[cfg(unix)]
    #[test]
    fn an_installer_that_fails_early_reports_its_exit_status() {
        let outcome = run_inherited(
            sh("read -r line; exec 0<&-; exit 2"),
            InheritedRole::InteractiveInstall,
            InheritedInput::Bytes(script_past_pipe_buffer()),
        );
        assert!(
            matches!(outcome, Ok(ref status) if status.code() == Some(2)),
            "{outcome:?}"
        );
    }

    /// An installer that reads its whole script is judged by its exit status.
    #[cfg(unix)]
    #[test]
    fn an_installer_that_reads_its_whole_script_is_accepted() {
        let outcome = run_inherited(
            sh("cat >/dev/null; exit 0"),
            InheritedRole::InteractiveInstall,
            InheritedInput::Bytes(script_past_pipe_buffer()),
        );
        assert!(
            matches!(outcome, Ok(ref status) if status.success()),
            "{outcome:?}"
        );
    }

    /// A child outside the installer role may stop reading its input; its exit status decides.
    #[cfg(unix)]
    #[test]
    fn a_user_program_may_leave_its_input_unread() {
        let outcome = run_inherited(
            sh("read -r line; exec 0<&-; exit 0"),
            InheritedRole::UserProgram,
            InheritedInput::Bytes(script_past_pipe_buffer()),
        );
        assert!(
            matches!(outcome, Ok(ref status) if status.success()),
            "{outcome:?}"
        );
    }

    /// A descendant that holds the fed pipe without reading it cannot hold the CLI past the child's exit.
    #[cfg(unix)]
    #[test]
    fn a_descendant_holding_the_fed_pipe_does_not_outlive_the_child() {
        let started = Instant::now();
        let outcome = run_inherited(
            sh("exec 3<&0; sleep 20 <&3 >/dev/null 2>&1 & exit 0"),
            InheritedRole::UserProgram,
            InheritedInput::Bytes(script_past_pipe_buffer()),
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(
            matches!(outcome, Ok(ref status) if status.success()),
            "{outcome:?}"
        );
    }

    /// A child given the null device reads the end of its input at once.
    #[cfg(unix)]
    #[test]
    fn a_null_input_child_reads_end_of_input() {
        let outcome = run_inherited(
            sh("read -r line && exit 3; exit 0"),
            InheritedRole::UserProgram,
            InheritedInput::Null,
        );
        assert!(
            matches!(outcome, Ok(ref status) if status.success()),
            "{outcome:?}"
        );
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
                limit: IngestLimit::Time(GITHUB_API.wall.limit()),
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
                GITHUB_API.wall.secs().to_string(),
            ]
        );
    }

    /// A self-run outlasts the cargo build it contains by its whole margin, so a
    /// hung build is refused as the build's typed timeout, never cut first by
    /// the self-run wall.
    #[test]
    fn a_self_run_outlasts_its_cargo_build_wall_by_the_whole_margin() {
        let build = crate::cargo_step::CARGO_BUILD_WALL.secs();
        let self_run = super::SELF_RUN_LIMITS.wall().secs();
        assert_eq!(self_run, build + super::SELF_RUN_MARGIN_SECS);
        assert!(self_run <= super::MAX_LOCAL_WALL_SECS);
    }
}
