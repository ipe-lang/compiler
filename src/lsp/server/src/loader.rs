//! The project-resolution seam between the server loop and the CLI driver.
//!
//! Discovering a project (manifest walk-up, sibling discovery, stdlib
//! injection) is driver logic that reads the filesystem — it lives in the
//! `ipe` crate, which depends on this one. The server therefore receives it
//! as a [`ProjectLoader`] implementation; the query layer below stays free
//! of hidden inputs, and tests substitute a fixture loader with no
//! filesystem at all.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

pub use ipe_db::ModuleOrigin;

/// One resolved module of a loaded project.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LoadedFile {
    /// The module's on-disk source path (absolute on the real driver path).
    pub path: PathBuf,
    /// The module's source text as the loader resolved it (disk bytes,
    /// except the anchor file when an overlay was supplied).
    pub text: String,
    /// The driver-vouched trust tag ([`ipe_db::SourceFile`]'s `origin`).
    pub origin: ModuleOrigin,
}

/// A fully resolved project: every in-scope module plus the entry module.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LoadedProject {
    /// Module path → resolved file, for every module in the build
    /// (user sources plus the injected stdlib closure).
    pub files: BTreeMap<Vec<String>, LoadedFile>,
    /// The entry module's path segments (e.g. `["Main"]`).
    pub entry_module: Vec<String>,
    /// The directory `lint.ipe` is read from.
    ///
    /// The driver names it exactly as `ipe lint` does for the same project,
    /// so the editor and the batch linter configure one set of rules.
    pub lint_config_dir: PathBuf,
}

/// A project-resolution failure, typed by how the server must answer it.
///
/// Each variant carries the driver's rendered, user-facing detail, which
/// [`fmt::Display`] writes unchanged. [`LoadError::disposition`] tells a
/// failure the server degrades around from one it refuses to serve.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LoadError {
    /// The sources or manifest failed a pipeline stage; an edit may fix it.
    Pipeline(String),
    /// A read or directory walk failed at the filesystem.
    Io(String),
    /// The driver refused to open a source file.
    ///
    /// The refused file (not a regular file, access denied) is one the user
    /// can fix or stop importing, so the server degrades around it.
    Refused(String),
    /// A bounded read or walk hit its ceiling.
    Limit {
        /// What the ceiling counted, and so what can bring the load back under it.
        lifted_by: LimitSource,
        /// The driver's rendered detail.
        detail: String,
    },
    /// The FFI artifact cache failed its trust check.
    FfiUntrusted(String),
    /// The installed FFI catalog is inconsistent; no buffer edit fixes it.
    FfiCatalogRefused(String),
    /// The discovered package manifest failed its trust check.
    ManifestUntrusted(String),
}

/// What a load ceiling counted, which decides whether an edit can lift it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LimitSource {
    /// The ceiling counted the open buffer (a loose file's import closure).
    ///
    /// Editing the buffer (dropping imports, shrinking it) can bring the
    /// load back under the ceiling.
    Buffer,
    /// The ceiling counted the filesystem alone (the manifest walk, a package's tree).
    ///
    /// No edit to the buffer changes what the ceiling counted.
    Filesystem,
}

/// How the server answers a [`LoadError`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LoadDisposition {
    /// Serve the open buffer as a single-file fallback layout.
    Degrade,
    /// Serve no layout at all, withdrawing any trusted or fallback one.
    ///
    /// The failure is one no edit to the buffer can lift (a filesystem
    /// ceiling, a trust refusal), so any layout kept would show analysis the
    /// compiler refuses to give.
    Refuse,
}

impl LoadError {
    /// Whether the server degrades around this failure or refuses to serve it.
    #[must_use]
    pub const fn disposition(&self) -> LoadDisposition {
        match self {
            Self::Pipeline(_)
            | Self::Io(_)
            | Self::Refused(_)
            | Self::Limit {
                lifted_by: LimitSource::Buffer,
                ..
            } => LoadDisposition::Degrade,
            Self::Limit {
                lifted_by: LimitSource::Filesystem,
                ..
            }
            | Self::FfiUntrusted(_)
            | Self::FfiCatalogRefused(_)
            | Self::ManifestUntrusted(_) => LoadDisposition::Refuse,
        }
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pipeline(detail)
            | Self::Io(detail)
            | Self::Refused(detail)
            | Self::Limit { detail, .. }
            | Self::FfiUntrusted(detail)
            | Self::FfiCatalogRefused(detail)
            | Self::ManifestUntrusted(detail) => f.write_str(detail),
        }
    }
}

/// Resolves the project that contains an opened document.
pub trait ProjectLoader {
    /// Resolve the project containing `open_file`.
    ///
    /// `workspace_root` is the editor's workspace folder (used when it holds
    /// a manifest); `open_text`, when present, is the editor's current
    /// buffer for `open_file` and shadows its disk bytes during resolution
    /// (the VFS overlay applied at the discovery step).
    ///
    /// # Errors
    /// [`LoadError`] when no project shape can be resolved around
    /// `open_file`; its [`LoadError::disposition`] says whether the server
    /// degrades to single-file service or refuses the load.
    fn load(
        &self,
        workspace_root: Option<&Path>,
        open_file: &Path,
        open_text: Option<&str>,
    ) -> Result<LoadedProject, LoadError>;
}
