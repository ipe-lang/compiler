//! Existence-proven resolution of a cargo bin target.
//!
//! A resolver here either returns a proof type ([`ProvenBin`]) whose
//! constructor is private to this module, or a typed [`ResolveError`]
//! naming every location it tried. No resolver falls through to a `PATH` lookup,
//! and an explicit override that does not hold the artifact is refused rather
//! than silently replaced by a later candidate. No resolver reads the current
//! directory: a lookup starts at an anchor its caller names.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// The most directories a runtime lookup visits, its start included.
pub const RUNTIME_LOOKUP_CEILING: usize = 64;

/// Where a candidate artifact path came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The `CARGO_BIN_EXE_<name>` value the test runner exports at run time.
    NextestRuntime,
    /// The `CARGO_BIN_EXE_<name>` path cargo baked in at compile time.
    CompileTimeBaked,
    /// An explicit override variable.
    RuntimeEnv(&'static str),
    /// The running executable itself.
    CurrentExe,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NextestRuntime => f.write_str("run-time CARGO_BIN_EXE"),
            Self::CompileTimeBaked => f.write_str("compile-time CARGO_BIN_EXE"),
            Self::RuntimeEnv(var) => write!(f, "${var}"),
            Self::CurrentExe => f.write_str("current executable"),
        }
    }
}

/// Every location a resolver tried, in order.
pub type Tried = Vec<(Source, PathBuf)>;

/// Why an artifact could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// No candidate location exists.
    Missing {
        /// The artifact name.
        name: &'static str,
        /// Every location tried, in order.
        tried: Tried,
    },
    /// A binary candidate exists but is not a regular file (a directory or a symlink).
    NotAFile {
        /// The artifact name.
        name: &'static str,
        /// The offending path.
        path: PathBuf,
    },
    /// A candidate's metadata could not be read.
    Unreadable {
        /// The artifact name.
        name: &'static str,
        /// The offending path.
        path: PathBuf,
        /// The metadata error kind.
        kind: io::ErrorKind,
    },
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { name, tried } => {
                write!(f, "artifact `{name}` not found; tried:")?;
                for (source, path) in tried {
                    write!(f, " [{source} {}]", path.display())?;
                }
                Ok(())
            }
            Self::NotAFile { name, path } => write!(
                f,
                "artifact `{name}` at {} is not a regular file",
                path.display()
            ),
            Self::Unreadable { name, path, kind } => write!(
                f,
                "artifact `{name}` at {} is unreadable: {kind}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ResolveError {}

/// A cargo bin target whose path was proven to be a regular file when resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenBin(PathBuf);

impl ProvenBin {
    /// The proven path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// The proven path, owned.
    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

impl AsRef<Path> for ProvenBin {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<OsStr> for ProvenBin {
    fn as_ref(&self) -> &OsStr {
        self.0.as_os_str()
    }
}

/// What a path's own metadata (not its symlink target) says it is.
enum Probe {
    Absent,
    File,
    Dir,
    Other,
    Unreadable(io::ErrorKind),
}

fn probe(path: &Path) -> Probe {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => Probe::File,
        Ok(meta) if meta.is_dir() => Probe::Dir,
        Ok(_) => Probe::Other,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Probe::Absent,
        Err(e) => Probe::Unreadable(e.kind()),
    }
}

/// Resolve cargo bin target `name`: the run-time path first, then the compile-time one.
///
/// An empty run-time value counts as absent. See [`resolve_bin_from`] for the
/// per-candidate rule.
///
/// # Errors
///
/// As [`resolve_bin_from`].
pub fn resolve_bin(
    name: &'static str,
    runtime: Option<OsString>,
    baked: &Path,
) -> Result<ProvenBin, ResolveError> {
    let runtime = runtime.filter(|v| !v.is_empty()).map(PathBuf::from);
    resolve_bin_from(
        name,
        runtime
            .map(|p| (Source::NextestRuntime, p))
            .into_iter()
            .chain(std::iter::once((
                Source::CompileTimeBaked,
                baked.to_path_buf(),
            ))),
    )
}

/// Resolve bin `name` from ordered `candidates`, proving the winner is a regular file.
///
/// An absent candidate is recorded and the next one is tried; a candidate that
/// exists but is not a regular file (a directory, or a symlink even to a file)
/// is refused on the spot rather than skipped.
///
/// # Errors
///
/// [`ResolveError::Missing`] listing every candidate when none exists;
/// [`ResolveError::NotAFile`] / [`ResolveError::Unreadable`] for a candidate
/// that exists but cannot be proven a regular file.
pub fn resolve_bin_from(
    name: &'static str,
    candidates: impl IntoIterator<Item = (Source, PathBuf)>,
) -> Result<ProvenBin, ResolveError> {
    let mut tried = Tried::new();
    for (source, path) in candidates {
        match probe(&path) {
            Probe::File => return Ok(ProvenBin(path)),
            Probe::Absent => tried.push((source, path)),
            Probe::Dir | Probe::Other => return Err(ResolveError::NotAFile { name, path }),
            Probe::Unreadable(kind) => return Err(ResolveError::Unreadable { name, path, kind }),
        }
    }
    Err(ResolveError::Missing { name, tried })
}
