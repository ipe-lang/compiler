//! Test-artifact resolution that fails the calling test rather than skipping it.
//!
//! Every resolver here returns a proof of the artifact's existence or panics
//! with the full [`ResolveError`]: inside a test a panic is a test failure,
//! which is the designed outcome for a missing binary, runtime tree, or
//! manifest directory. None of them reports "absent" to a caller that could
//! then return early and pass without having run. The bin resolution logic
//! lives in [`ipe_env::artifact`], shared with the production resolvers; the
//! checkout walk to the runtime tree, [`in_repo_runtime_src`], lives here only,
//! so no production crate can reach it.
//!
//! The one sanctioned early exit from a test body is the tier gate,
//! `if e2e_tier() == Tier::Unit { return; }`, and [`e2e_tier`] is the one
//! reader of `IPE_E2E`.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

pub use ipe_env::artifact::{
    ProvenBin, RUNTIME_LOOKUP_CEILING, ResolveError, Source, Tried, resolve_bin, resolve_bin_from,
};

/// The tier-selecting variable.
pub const E2E_VAR: &str = "IPE_E2E";

/// The only value of [`E2E_VAR`] that selects the end-to-end tier.
pub const E2E_ON: &str = "1";

/// Which test tier this run is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// `IPE_E2E` unset: the fast tier; heavy build-and-run checks are skipped.
    Unit,
    /// `IPE_E2E=1`: the end-to-end tier; every heavy check runs.
    E2e,
}

/// Parse an `IPE_E2E` value into a [`Tier`].
///
/// # Errors
///
/// The raw value when it is set to anything but [`E2E_ON`] (including empty):
/// an unrecognised value is refused rather than read as either tier.
pub fn parse_tier(raw: Option<&OsStr>) -> Result<Tier, OsString> {
    match raw {
        None => Ok(Tier::Unit),
        Some(v) if v == E2E_ON => Ok(Tier::E2e),
        Some(v) => Err(v.to_os_string()),
    }
}

/// The current test tier, read from `IPE_E2E`.
///
/// # Panics
///
/// When `IPE_E2E` is set to anything but `1`: a malformed value fails the test.
#[must_use]
pub fn e2e_tier() -> Tier {
    parse_tier(ipe_env::var_os(E2E_VAR).as_deref()).unwrap_or_else(|raw| {
        fail(format_args!(
            "{E2E_VAR}=`{}` is neither unset nor `{E2E_ON}`; refusing to guess the test tier",
            raw.display()
        ))
    })
}

/// Fail the calling test with `msg`.
#[allow(clippy::panic)] // a failed artifact resolution IS a failed test: the designed outcome
pub(crate) fn fail(msg: fmt::Arguments<'_>) -> ! {
    // IPE-RUST-AUDIT:ACCEPTED — test-support failure path; a panic fails the calling test
    panic!("{msg}")
}

/// Unwrap a host capability the end-to-end tier needs, failing the calling
/// test when it is present but unusable.
///
/// A capability the host offers (a jail primitive that resolved, a toolchain,
/// the outbound route a control run needs) that then fails to work is a
/// defect of the host the job runs on, never a reason to pass without having
/// run: the one sanctioned skip is the first-statement tier gate.
///
/// # Panics
///
/// With `what` and the error when `probe` is `Err`.
pub fn require_host<T, E: fmt::Debug>(what: &str, probe: Result<T, E>) -> T {
    probe.unwrap_or_else(|e| fail(format_args!("{what}: {e:?}")))
}

/// Resolve cargo bin target `name`; the body of [`cargo_bin!`](crate::cargo_bin).
///
/// Reads the run-time `CARGO_BIN_EXE_<name>` (re-exported by nextest, correct
/// under an archive) before the compile-time `baked` path.
///
/// # Panics
///
/// With the [`ResolveError`] when neither path is an existing regular file.
#[must_use]
pub fn require_bin(name: &'static str, baked: &str) -> ProvenBin {
    let runtime = ipe_env::var_os(format!("CARGO_BIN_EXE_{name}"));
    resolve_bin(name, runtime, Path::new(baked)).unwrap_or_else(|e| fail(format_args!("{e}")))
}

/// The checkout's runtime crate, proven by a walk that followed no link.
///
/// Its crate root holds a regular `Cargo.toml` and a `src/` directory, and no
/// component from the visited ancestor down is a symbolic link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenRuntime {
    krate: PathBuf,
    tree: PathBuf,
}

impl ProvenRuntime {
    /// The proven module tree (`src/runtime/rust/src`).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.tree
    }

    /// The proven module tree, owned.
    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.tree
    }

    /// The proven crate root, the directory holding the runtime's `Cargo.toml`.
    #[must_use]
    pub fn crate_root(&self) -> &Path {
        &self.krate
    }
}

impl AsRef<Path> for ProvenRuntime {
    fn as_ref(&self) -> &Path {
        &self.tree
    }
}

/// Why the checkout walk resolved no runtime tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeLookupError {
    /// No visited directory holds the tree.
    Missing {
        /// The directory the walk started at.
        anchor: PathBuf,
    },
    /// A component of a candidate tree is a symbolic link.
    Linked {
        /// The link.
        path: PathBuf,
    },
    /// A candidate component's metadata could not be read.
    Unreadable {
        /// The offending path.
        path: PathBuf,
        /// The metadata error kind.
        kind: io::ErrorKind,
    },
}

impl fmt::Display for RuntimeLookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { anchor } => write!(
                f,
                "no runtime tree (src/runtime/rust/src beside its Cargo.toml) at or above {} \
                 within {RUNTIME_LOOKUP_CEILING} directories",
                anchor.display()
            ),
            Self::Linked { path } => write!(
                f,
                "runtime tree component {} is a symbolic link; the checkout walk follows none",
                path.display()
            ),
            Self::Unreadable { path, kind } => write!(
                f,
                "runtime tree component {} is unreadable: {kind}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for RuntimeLookupError {}

/// What one path's own metadata, never a link's target, says it is.
enum Entry {
    Absent,
    Dir,
    File,
    Other,
}

/// Probe `path` without following it, refusing a link or an unreadable entry.
fn entry(path: &Path) -> Result<Entry, RuntimeLookupError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(RuntimeLookupError::Linked {
            path: path.to_path_buf(),
        }),
        Ok(meta) if meta.is_dir() => Ok(Entry::Dir),
        Ok(meta) if meta.is_file() => Ok(Entry::File),
        Ok(_) => Ok(Entry::Other),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Entry::Absent),
        Err(e) => Err(RuntimeLookupError::Unreadable {
            path: path.to_path_buf(),
            kind: e.kind(),
        }),
    }
}

/// The runtime crate `dir` holds, every component below `dir` probed unfollowed.
///
/// `Ok(None)` when an expected component is absent or of another kind.
fn runtime_crate_in(dir: &Path) -> Result<Option<ProvenRuntime>, RuntimeLookupError> {
    let mut krate = dir.to_path_buf();
    for part in ["src", "runtime", "rust"] {
        krate.push(part);
        if !matches!(entry(&krate)?, Entry::Dir) {
            return Ok(None);
        }
    }
    let tree = krate.join("src");
    let manifest_is_file = matches!(entry(&krate.join("Cargo.toml"))?, Entry::File);
    let tree_is_dir = matches!(entry(&tree)?, Entry::Dir);
    Ok((manifest_is_file && tree_is_dir).then_some(ProvenRuntime { krate, tree }))
}

/// The checkout's runtime crate at or above `anchor`.
///
/// Visits at most [`RUNTIME_LOOKUP_CEILING`] directories, `anchor` first, and
/// accepts one layout: `src/runtime/rust/src` whose parent holds `Cargo.toml`.
/// Every component from a visited directory down is probed with
/// `symlink_metadata`, so no link is followed. Reads no variable and never the
/// current directory, so only the anchor the caller names decides the tree.
///
/// # Errors
///
/// [`RuntimeLookupError::Linked`] / [`RuntimeLookupError::Unreadable`] on the
/// first linked or unreadable component, never passed over for a directory
/// further up; [`RuntimeLookupError::Missing`] when no visited directory holds
/// the tree.
pub fn in_repo_runtime_src(anchor: &Path) -> Result<ProvenRuntime, RuntimeLookupError> {
    for dir in anchor.ancestors().take(RUNTIME_LOOKUP_CEILING) {
        if let Some(found) = runtime_crate_in(dir)? {
            return Ok(found);
        }
    }
    Err(RuntimeLookupError::Missing {
        anchor: anchor.to_path_buf(),
    })
}

/// Resolve the checkout's runtime module tree (`src/runtime/rust/src`).
///
/// Anchored at the manifest directory [`require_manifest_dir`] proves (the
/// run-time value first, so the anchor holds under an archive's workspace
/// remap) and found by [`in_repo_runtime_src`]. No variable and no current
/// directory names another tree: the tests of a checkout run on its runtime.
///
/// # Panics
///
/// With the [`RuntimeLookupError`] when no runtime tree resolves.
#[must_use]
pub fn require_runtime() -> ProvenRuntime {
    let anchor = require_manifest_dir(env!("CARGO_MANIFEST_DIR"));
    in_repo_runtime_src(&anchor).unwrap_or_else(|e| fail(format_args!("{e}")))
}

/// Resolve the runtime crate root, the directory holding its `Cargo.toml`.
///
/// # Panics
///
/// With the [`RuntimeLookupError`] when no runtime tree resolves.
#[must_use]
pub fn require_runtime_crate() -> PathBuf {
    require_runtime().crate_root().to_path_buf()
}

/// Resolve the calling crate's manifest directory; the body of [`manifest_dir!`](crate::manifest_dir).
///
/// Reads the run-time `CARGO_MANIFEST_DIR` (set by cargo and nextest, correct
/// under an archive's workspace remap) before the compile-time `baked` path;
/// the winner must be an existing directory.
///
/// # Panics
///
/// With the [`ResolveError`] when neither path is an existing directory.
#[must_use]
pub fn require_manifest_dir(baked: &str) -> PathBuf {
    let runtime = ipe_env::var_os("CARGO_MANIFEST_DIR")
        .filter(|v| !v.is_empty())
        .map(|v| (Source::RuntimeEnv("CARGO_MANIFEST_DIR"), PathBuf::from(v)));
    let candidates = runtime.into_iter().chain(std::iter::once((
        Source::CompileTimeBaked,
        PathBuf::from(baked),
    )));
    let mut tried = Tried::new();
    for (source, path) in candidates {
        if path.is_dir() {
            return path;
        }
        tried.push((source, path));
    }
    let e = ResolveError::Missing {
        name: "CARGO_MANIFEST_DIR",
        tried,
    };
    fail(format_args!("{e}"))
}

/// Resolve cargo bin target `$name` of the calling test crate into a [`ProvenBin`].
///
/// A macro because `CARGO_BIN_EXE_<name>` is only defined at compile time in
/// the integration-test crate that calls it. Never falls back to a `PATH`
/// lookup.
#[macro_export]
macro_rules! cargo_bin {
    ($name:literal) => {
        $crate::bin::require_bin(
            $name,
            ::core::env!(::core::concat!("CARGO_BIN_EXE_", $name)),
        )
    };
}

/// The calling crate's manifest directory as a proven-existing `PathBuf`.
///
/// A macro so the compile-time fallback is the CALLING crate's
/// `CARGO_MANIFEST_DIR`, not this crate's.
#[macro_export]
macro_rules! manifest_dir {
    () => {
        $crate::bin::require_manifest_dir(::core::env!("CARGO_MANIFEST_DIR"))
    };
}
