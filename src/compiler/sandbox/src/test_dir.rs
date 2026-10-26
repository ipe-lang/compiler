//! A test-only scratch directory, removed when dropped.

use std::path::{Path, PathBuf};

use crate::scratch::ScratchDir;

/// A fresh canonical scratch directory, removed with its contents on drop.
pub struct TestDir {
    /// The canonical path of `_dir`.
    path: PathBuf,
    /// The private directory, removed on drop.
    _dir: ScratchDir,
}

impl TestDir {
    /// A fresh private directory named after `label`.
    ///
    /// # Errors
    /// The I/O error when the directory cannot be created or resolved.
    pub fn new(label: &str) -> std::io::Result<Self> {
        let dir = ScratchDir::new(&format!("ipe-sandbox-{label}"))?;
        let path = std::fs::canonicalize(dir.path())?;
        Ok(Self { path, _dir: dir })
    }

    /// The canonical directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// `abs` spelled relative to the working directory, so a resolver that joined a
/// relative `PATH` entry onto that directory would reach it.
#[cfg(unix)]
#[must_use]
pub fn relative_spelling(abs: &Path) -> PathBuf {
    let depth = std::env::current_dir().map_or(0, |cwd| {
        cwd.components()
            .filter(|c| matches!(c, std::path::Component::Normal(_)))
            .count()
    });
    let mut rel: PathBuf = std::iter::repeat_n("..", depth).collect();
    rel.push(abs.strip_prefix("/").unwrap_or(abs));
    rel
}
