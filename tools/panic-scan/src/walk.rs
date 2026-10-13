//! The one directory walker every source scan lists its files through.
//!
//! A scan over a tree certifies only the files the walk hands it, so the walk
//! skips nothing and drops nothing: every entry is listed, descended into, or
//! refused with a typed [`WalkError`]. A missing root, an entry that cannot be
//! read, a symlinked directory (not followed, so its contents cannot be
//! vouched for), a wanted name that is not a regular file (a FIFO or device a
//! read would block on), and a tree past [`EntryCeiling`] or [`DirDepth`] are each a
//! refusal, never a shorter list. The walk is iterative, so its depth costs no
//! stack, and it counts entries as it reads them, so no directory listing is
//! held past the ceiling.

use std::fmt;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

/// Largest number of directory entries one walk reads.
const ENTRY_CEILING: usize = 200_000;

/// Deepest directory, counted in components below the root, one walk enters.
const DIR_DEPTH: usize = 64;

/// File name of a crate manifest.
const MANIFEST_FILE: &str = "Cargo.toml";

// IPE-RUST-AUDIT:ACCEPTED — compile-time `const` assertion (not a runtime panic); it fails the build if a walk ceiling is zero
const _: () = assert!(ENTRY_CEILING > 0 && DIR_DEPTH > 0);

/// `n` as a non-zero count; the `const` assertion above proves every ceiling is.
const fn non_zero(n: usize) -> NonZeroUsize {
    match NonZeroUsize::new(n) {
        Some(n) => n,
        None => NonZeroUsize::MIN,
    }
}

/// Largest number of directory entries one walk reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryCeiling(NonZeroUsize);

/// Deepest directory, in components below the root, one walk enters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirDepth(NonZeroUsize);

impl EntryCeiling {
    /// The ceiling every walk enforces.
    pub const CEILING: Self = Self(non_zero(ENTRY_CEILING));

    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

impl DirDepth {
    /// The ceiling every walk enforces.
    pub const CEILING: Self = Self(non_zero(DIR_DEPTH));

    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

impl fmt::Display for EntryCeiling {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for DirDepth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Which files a walk lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    /// Every `.rs` file.
    RustFiles,
    /// Every `.rs` file and every `Cargo.toml`.
    RustAndManifests,
    /// Every `.rs` file and every `.sh` or `.bash` script.
    RustAndShellScripts,
}

impl Want {
    /// Whether a file at `path` is one this walk lists.
    fn admits(self, path: &Path) -> bool {
        let extension = path.extension();
        let rust = extension.is_some_and(|ext| ext == "rs");
        match self {
            Self::RustFiles => rust,
            Self::RustAndManifests => {
                rust || path.file_name().is_some_and(|name| name == MANIFEST_FILE)
            }
            Self::RustAndShellScripts => {
                rust || extension.is_some_and(|ext| ext == "sh" || ext == "bash")
            }
        }
    }
}

/// Why a walk refuses to list a tree.
#[derive(Debug)]
pub enum WalkError {
    /// The root does not exist.
    Missing { root: PathBuf },
    /// A directory, entry, or entry type could not be read.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A symlink to a directory, which the walk does not follow.
    SymlinkedDirectory { path: PathBuf },
    /// A wanted name that is not a regular file once any symlink is resolved.
    NotAFile { path: PathBuf },
    /// The tree holds more entries than the walk reads.
    TooMany {
        root: PathBuf,
        ceiling: EntryCeiling,
    },
    /// A directory lies deeper below the root than the walk enters.
    TooDeep { path: PathBuf, ceiling: DirDepth },
}

impl fmt::Display for WalkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { root } => write!(f, "{}: no such directory", root.display()),
            Self::Io { path, source } => write!(f, "{}: cannot read: {source}", path.display()),
            Self::SymlinkedDirectory { path } => write!(
                f,
                "{}: symlinked directory — the walk does not follow it, so it cannot vouch for its contents",
                path.display()
            ),
            Self::NotAFile { path } => write!(
                f,
                "{}: not a regular file — a scan cannot read it as source",
                path.display()
            ),
            Self::TooMany { root, ceiling } => write!(
                f,
                "{}: holds more than {ceiling} entries, the walk ceiling",
                root.display()
            ),
            Self::TooDeep { path, ceiling } => write!(
                f,
                "{}: lies more than {ceiling} directories below the walk root",
                path.display()
            ),
        }
    }
}

impl std::error::Error for WalkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Missing { .. }
            | Self::SymlinkedDirectory { .. }
            | Self::NotAFile { .. }
            | Self::TooMany { .. }
            | Self::TooDeep { .. } => None,
        }
    }
}

/// Every file under `root` that `want` admits, sorted by path.
///
/// A symlinked file is listed, so a scan reads its target; a symlink whose
/// target cannot be read is refused, and so is a wanted name whose resolved
/// type is not a regular file. Sorting by path orders each directory's
/// entries by name, ahead of the entries of any later sibling.
///
/// # Errors
///
/// A [`WalkError`] when the root is missing, any entry cannot be read, a
/// symlinked directory or a wanted non-regular file is met, or the tree is
/// past [`EntryCeiling::CEILING`] entries or [`DirDepth::CEILING`] levels; no
/// partial list is returned.
pub fn rust_sources(root: &Path, want: Want) -> Result<Vec<PathBuf>, WalkError> {
    let root_type = std::fs::symlink_metadata(root)
        .map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                WalkError::Missing {
                    root: root.to_path_buf(),
                }
            } else {
                WalkError::Io {
                    path: root.to_path_buf(),
                    source,
                }
            }
        })?
        .file_type();
    if root_type.is_symlink() {
        refuse_directory_target(root)?;
    }
    let entries = EntryCeiling::CEILING;
    let depth_ceiling = DirDepth::CEILING;
    let mut read = 0_usize;
    let mut files = Vec::new();
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    while let Some((dir, depth)) = pending.pop() {
        let unreadable = |source| WalkError::Io {
            path: dir.clone(),
            source,
        };
        for entry in std::fs::read_dir(&dir).map_err(unreadable)? {
            let entry = entry.map_err(unreadable)?;
            read = read.saturating_add(1);
            if read > entries.get() {
                return Err(WalkError::TooMany {
                    root: root.to_path_buf(),
                    ceiling: entries,
                });
            }
            let path = entry.path();
            let file_type = entry.file_type().map_err(|source| WalkError::Io {
                path: path.clone(),
                source,
            })?;
            if file_type.is_dir() {
                let below = depth.saturating_add(1);
                if below > depth_ceiling.get() {
                    return Err(WalkError::TooDeep {
                        path,
                        ceiling: depth_ceiling,
                    });
                }
                pending.push((path, below));
            } else {
                let regular = if file_type.is_symlink() {
                    refuse_directory_target(&path)?.is_file()
                } else {
                    file_type.is_file()
                };
                if want.admits(&path) {
                    if !regular {
                        return Err(WalkError::NotAFile { path });
                    }
                    files.push(path);
                }
            }
        }
    }
    files.sort();
    Ok(files)
}

/// The type of the symlink target at `path`, refused when it is a directory or cannot be read.
fn refuse_directory_target(path: &Path) -> Result<std::fs::FileType, WalkError> {
    let target = std::fs::metadata(path).map_err(|source| WalkError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if target.is_dir() {
        Err(WalkError::SymlinkedDirectory {
            path: path.to_path_buf(),
        })
    } else {
        Ok(target.file_type())
    }
}
