//! The `ipe_wrapper` crate source a native-bearing release builds.
//!
//! The source is the compiler workspace this `ipe` binary was compiled from.
//! Its root is fixed when `ipe` itself is built (`CARGO_MANIFEST_DIR`), never
//! derived from the current directory or a path a project supplies, so a
//! `Cargo.toml` planted above a project cannot become the build a release
//! jails behind. The root is held through [`ProvenDir`] (every ancestor proven
//! owner-trusted), each manifest is read through the bounded reader from the
//! held handle, and the tree must parse as the workspace that declares the
//! wrapper: a `[workspace]` table whose `members` name [`WRAPPER_MEMBER`], a
//! committed `Cargo.lock` beside it, and a member manifest whose package is
//! [`WRAPPER_PACKAGE`]. An `ipe` running away from that source refuses a
//! native-bearing release with [`crate::CliError::WrapperSourceRefused`].

use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::io_bounded::{MANIFEST_CAP, prove_regular, read_proven};
use crate::proven_dir::{EntryName, ProvenDir, ProvenDirError};
use crate::text;

/// The Cargo package name of the jail wrapper crate.
pub const WRAPPER_PACKAGE: &str = "ipe_wrapper";

/// The wrapper crate's path inside the workspace, as `members` lists it.
pub const WRAPPER_MEMBER: &str = "src/ipe-wrapper";

/// The verified root of the workspace that holds the `ipe_wrapper` crate.
///
/// Built only by [`WrapperSource::resolve`] and [`WrapperSource::resolve_at`],
/// so holding one is proof that every check ran.
#[derive(Debug)]
pub struct WrapperSource {
    root: PathBuf,
}

/// Why a candidate wrapper source was refused.
#[derive(Debug)]
pub enum WrapperSourceDefect {
    /// The build-time crate path has no workspace root above it.
    NoBuildRoot,
    /// A directory or file on the way is absent or not proven owner-trusted.
    Unproven(ProvenDirError),
    /// A manifest could not be read within [`MANIFEST_CAP`] as UTF-8.
    Unreadable(PathBuf),
    /// A manifest is not valid TOML.
    Unparsable(PathBuf),
    /// The root manifest has no `[workspace]` table.
    NotAWorkspace,
    /// The workspace `members` do not name [`WRAPPER_MEMBER`].
    MemberUndeclared,
    /// The member manifest's package is not [`WRAPPER_PACKAGE`].
    PackageMismatch,
}

/// A refused wrapper source: the root that was tried, and why.
#[derive(Debug)]
pub struct WrapperSourceRefusal {
    /// The candidate workspace root.
    pub root: PathBuf,
    /// The check it failed.
    pub defect: WrapperSourceDefect,
}

impl WrapperSource {
    /// The workspace root fixed when this `ipe` binary was compiled.
    ///
    /// `None` when the build-time crate path has no grandparent.
    #[must_use]
    pub fn build_root() -> Option<&'static Path> {
        Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2)
    }

    /// Verify the build-time workspace root as the wrapper source.
    ///
    /// # Errors
    ///
    /// [`WrapperSourceRefusal`] naming the failed check.
    pub fn resolve() -> Result<Self, WrapperSourceRefusal> {
        let root = Self::build_root().ok_or_else(|| WrapperSourceRefusal {
            root: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
            defect: WrapperSourceDefect::NoBuildRoot,
        })?;
        Self::resolve_at(root)
    }

    /// Verify `root` as the workspace holding the wrapper crate.
    ///
    /// # Errors
    ///
    /// [`WrapperSourceRefusal`] naming the failed check.
    pub fn resolve_at(root: &Path) -> Result<Self, WrapperSourceRefusal> {
        let refuse = |defect| WrapperSourceRefusal {
            root: root.to_path_buf(),
            defect,
        };
        let held = ProvenDir::open(root).map_err(|e| refuse(WrapperSourceDefect::Unproven(e)))?;
        let workspace = read_manifest(&held).map_err(refuse)?;
        let declared = workspace
            .get("workspace")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| refuse(WrapperSourceDefect::NotAWorkspace))?
            .get("members")
            .and_then(toml::Value::as_array)
            .is_some_and(|members| {
                members
                    .iter()
                    .any(|m| m.as_str().is_some_and(|m| m == WRAPPER_MEMBER))
            });
        if !declared {
            return Err(refuse(WrapperSourceDefect::MemberUndeclared));
        }
        let lock = entry(&held, "Cargo.lock").map_err(refuse)?;
        held.open_file(&lock)
            .map_err(|e| refuse(WrapperSourceDefect::Unproven(e)))?;

        let member = ProvenDir::open(&root.join(WRAPPER_MEMBER))
            .map_err(|e| refuse(WrapperSourceDefect::Unproven(e)))?;
        let package = read_manifest(&member).map_err(refuse)?;
        let named = package
            .get("package")
            .and_then(toml::Value::as_table)
            .and_then(|p| p.get("name"))
            .and_then(toml::Value::as_str)
            .is_some_and(|name| name == WRAPPER_PACKAGE);
        if !named {
            return Err(refuse(WrapperSourceDefect::PackageMismatch));
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// A source over `root` that skips every check, for the build-command unit
    /// tests only.
    #[cfg(test)]
    pub(crate) fn unverified_for_test(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    /// The verified workspace root: the directory `cargo` builds the wrapper in.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// The one-component entry `name` inside `dir`.
fn entry(dir: &ProvenDir, name: &'static str) -> Result<EntryName, WrapperSourceDefect> {
    EntryName::new(OsStr::new(name)).ok_or_else(|| {
        WrapperSourceDefect::Unproven(ProvenDirError::Io {
            path: dir.path().join(name),
            source: std::io::ErrorKind::InvalidInput.into(),
        })
    })
}

/// Read and parse the `Cargo.toml` inside `dir` from the held handle.
fn read_manifest(dir: &ProvenDir) -> Result<toml::Table, WrapperSourceDefect> {
    let name = entry(dir, "Cargo.toml")?;
    let path = dir.path_of(&name);
    let file = dir
        .open_file(&name)
        .map_err(WrapperSourceDefect::Unproven)?;
    let text = prove_regular(file, &path)
        .and_then(|file| read_proven(file, &path, MANIFEST_CAP))
        .map_err(|_| WrapperSourceDefect::Unreadable(path.clone()))?;
    text.parse::<toml::Table>()
        .map_err(|_| WrapperSourceDefect::Unparsable(path))
}

impl fmt::Display for WrapperSourceDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBuildRoot => f.write_str(text::wrapper_source_no_build_root()),
            Self::Unproven(ProvenDirError::Unsupported) => {
                f.write_str(text::wrapper_source_unsupported())
            }
            Self::Unproven(e) => {
                let path = e
                    .path()
                    .map_or_else(String::new, |p| p.display().to_string());
                f.write_str(&text::wrapper_source_unproven(&path))
            }
            Self::Unreadable(path) => {
                f.write_str(&text::wrapper_source_unreadable(&path.display()))
            }
            Self::Unparsable(path) => {
                f.write_str(&text::wrapper_source_unparsable(&path.display()))
            }
            Self::NotAWorkspace => f.write_str(text::wrapper_source_not_workspace()),
            Self::MemberUndeclared => {
                f.write_str(&text::wrapper_source_member_undeclared(&WRAPPER_MEMBER))
            }
            Self::PackageMismatch => {
                f.write_str(&text::wrapper_source_package_mismatch(&WRAPPER_PACKAGE))
            }
        }
    }
}
