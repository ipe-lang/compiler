//! The one proof that turns a requested output path into an absolute one.
//!
//! [`ProvenOutPath`] has a private field and [`prove_parent_steps_from`] is its
//! only constructor, so no path reaches a claim without every `..` and `.`
//! resolved out of a proven plain directory first.

use std::path::{Component, Path, PathBuf};

use super::{OutputRefusal, held};
use crate::{CliError, io_err};

/// An absolute output path with no `..` or `.` component.
///
/// Built only by [`prove_parent_steps_from`], the one place a requested path is
/// made absolute: a relative request is walked on from the working directory,
/// component by component, and each `..` is resolved there, lexically, once
/// the level it climbs out of is proven an existing directory that is not a
/// link. No `Path::join`/`push` ever sees a requested `..` or `.` (onto a
/// Windows verbatim `\\?\` base it collapses them unproven), and no later walk
/// meets a `..` for a platform to interpret its own way (Windows collapses
/// `..` lexically, POSIX follows the real parent).
#[derive(Debug, Clone)]
pub struct ProvenOutPath(PathBuf);

impl ProvenOutPath {
    /// The proven absolute path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// The proven absolute path, owned.
    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }

    /// The parent directory, itself proven.
    ///
    /// Dropping the last plain name keeps the path absolute with no `..` or
    /// `.`. `None` at the root.
    #[cfg(test)]
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        self.0
            .file_name()
            .and_then(|_| self.0.parent())
            .map(|parent| Self(parent.to_path_buf()))
    }
}

/// Make `raw` absolute against the working directory, resolving every `..`.
///
/// As [`prove_parent_steps_from`] with the working directory, read only for a
/// relative `raw`.
///
/// # Errors
/// As [`prove_parent_steps_from`]; [`CliError::Io`] when the working
/// directory cannot be read.
pub fn prove_parent_steps(raw: &Path) -> Result<ProvenOutPath, CliError> {
    if raw.is_absolute() {
        return prove_parent_steps_from(raw, Path::new(""));
    }
    let cwd = std::env::current_dir().map_err(|e| io_err(Path::new("."), e))?;
    prove_parent_steps_from(raw, &cwd)
}

/// Make `raw` absolute against `cwd`, resolving every `..` out of a proven plain directory.
///
/// The components of `cwd` (all of it for a relative `raw`, only its drive
/// for a Windows rooted `\x`, none for an absolute `raw`) and of `raw` are
/// walked as one sequence; nothing is joined before the walk, so every `..`
/// the user wrote reaches the proof whatever form `cwd` takes. A `..` is
/// honoured only when the level it climbs out of exists as a directory that
/// is not a link, reached through the already resolved levels above it; the
/// level is then popped. Out of such a level the lexical and the real parent
/// are the same directory, so the result names on every platform what POSIX
/// would. A `..` over a missing level, a file, a link, or the root is
/// refused. Bounded by the component count.
///
/// # Errors
/// [`OutputRefusal::ParentTraversal`] for an unproven `..`;
/// [`OutputRefusal::Unplaceable`] for a path that does not name one absolute
/// place: a Windows drive-relative `C:x`, a rooted `\x` against a working
/// directory with no drive, or a component that is not one plain name where
/// it lands (a `/` inside a verbatim `\\?\` component, an `a:b` that Windows
/// reads as a drive); [`CliError::Io`] when a level cannot be inspected.
pub fn prove_parent_steps_from(raw: &Path, cwd: &Path) -> Result<ProvenOutPath, CliError> {
    let traversal = || -> CliError { OutputRefusal::ParentTraversal(raw.to_path_buf()).into() };
    let unplaceable = || -> CliError { OutputRefusal::Unplaceable(raw.to_path_buf()).into() };
    let base = if raw.is_absolute() {
        Path::new("")
    } else {
        match raw.components().next() {
            Some(Component::Prefix(_)) => return Err(unplaceable()),
            Some(Component::RootDir) => drive_of(cwd).ok_or_else(unplaceable)?,
            Some(Component::CurDir | Component::ParentDir | Component::Normal(_)) | None => cwd,
        }
    };
    let mut proven = PathBuf::new();
    for component in base.components().chain(raw.components()) {
        match component {
            Component::Prefix(_) | Component::RootDir => proven.push(component),
            Component::CurDir => {}
            Component::Normal(name) => {
                if !is_one_name(name) {
                    return Err(unplaceable());
                }
                proven.push(name);
            }
            Component::ParentDir => {
                if proven.file_name().is_none() {
                    return Err(traversal());
                }
                match held::HeldDir::open(&proven) {
                    Ok(Some(_)) => {}
                    Ok(None) | Err(CliError::OutputRefused(_)) => return Err(traversal()),
                    Err(e) => return Err(e),
                }
                if !proven.pop() {
                    return Err(traversal());
                }
            }
        }
    }
    if !proven.is_absolute() {
        return Err(unplaceable());
    }
    Ok(ProvenOutPath(proven))
}

/// The drive prefix of `cwd`, the base of a Windows rooted `\x`.
#[must_use]
pub fn drive_of(cwd: &Path) -> Option<&Path> {
    match cwd.components().next() {
        Some(prefix @ Component::Prefix(_)) => Some(Path::new(prefix.as_os_str())),
        Some(
            Component::RootDir | Component::CurDir | Component::ParentDir | Component::Normal(_),
        )
        | None => None,
    }
}

/// Whether `name` reads back as exactly itself, one plain component.
///
/// A name that reads as more — a `/` split by a non-verbatim parse, an `a:b`
/// Windows takes for a drive prefix that would replace the path it is pushed
/// onto — does not extend that path by one level.
fn is_one_name(name: &std::ffi::OsStr) -> bool {
    let mut parts = Path::new(name).components();
    match (parts.next(), parts.next()) {
        (Some(Component::Normal(only)), None) => only == name,
        _ => false,
    }
}
