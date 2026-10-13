//! The one proof that turns a requested output path into an absolute one.
//!
//! [`ProvenOutPath`] has a private field and the walk behind
//! [`prove_parent_steps`] is its only constructor, so no path reaches a claim
//! without every `..` and `.` resolved out of a proven plain directory first,
//! its prefix one that names a place on a disk or share, and every name in it
//! one that the platform opens as spelled. The base a relative request is
//! walked on from is a [`Cwd`], which only the process working directory
//! supplies.

use std::path::{Component, Path, PathBuf, Prefix};

use ipe_fs_open::PlaceablePrefix;

use super::{OutputRefusal, held};
use crate::{CliError, io_err};

/// An absolute output path with no `..` or `.` component.
///
/// Built only by `prove_walk`, the one place a requested path is
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

/// The process working directory, the only base a relative request is proven against.
///
/// The field is private and [`Cwd::current`] reads it from the process, so no
/// caller can hand the prover a base of its own choosing.
#[derive(Debug)]
pub struct Cwd(PathBuf);

impl Cwd {
    /// The process working directory.
    ///
    /// # Errors
    /// [`CliError::Io`] when the working directory cannot be read.
    pub fn current() -> Result<Self, CliError> {
        std::env::current_dir()
            .map(Self)
            .map_err(|e| io_err(Path::new("."), e))
    }

    /// `path` taken as the working directory, so a test can place one.
    #[cfg(test)]
    #[must_use]
    pub const fn assumed(path: PathBuf) -> Self {
        Self(path)
    }

    /// The working directory's path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
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
        return prove_walk(raw, Path::new(""), Path::new(""));
    }
    prove_parent_steps_from(raw, &Cwd::current()?)
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
/// [`OutputRefusal::Unplaceable`] for a request that does not name one
/// absolute place: a Windows drive-relative `C:x`, a `.` or `..` inside a
/// verbatim `\\?\` path (a literal name there, not a step), a prefix that is
/// no [`PlaceablePrefix`], or a component that is not one plain name opened as
/// spelled (`ipe_fs_open::is_one_spelled_name`);
/// [`OutputRefusal::UnplaceableCwd`] when the part of the walk the working
/// directory supplies fails the same rules, or a rooted `\x` meets a working
/// directory with no drive; [`CliError::Io`] when a level cannot be inspected.
pub fn prove_parent_steps_from(raw: &Path, cwd: &Cwd) -> Result<ProvenOutPath, CliError> {
    let cwd = cwd.as_path();
    let base = if raw.is_absolute() {
        Path::new("")
    } else {
        match raw.components().next() {
            Some(Component::Prefix(_)) => return Err(unplaceable(raw)),
            Some(Component::RootDir) => drive_of(cwd).ok_or_else(|| unplaceable_cwd(cwd, raw))?,
            Some(Component::CurDir | Component::ParentDir | Component::Normal(_)) | None => cwd,
        }
    };
    prove_walk(raw, base, cwd)
}

/// The refusal of `raw` as naming no single place.
fn unplaceable(raw: &Path) -> CliError {
    OutputRefusal::Unplaceable(raw.to_path_buf()).into()
}

/// The refusal of `raw` because the working directory it is walked on from names no single place.
fn unplaceable_cwd(cwd: &Path, raw: &Path) -> CliError {
    OutputRefusal::UnplaceableCwd {
        cwd: cwd.to_path_buf(),
        request: raw.to_path_buf(),
    }
    .into()
}

/// The part of the invoker's input a walked component came from.
#[derive(Debug, Clone, Copy)]
enum Origin<'a> {
    /// The request itself.
    Request,
    /// The working directory the request is walked on from.
    Cwd(&'a Path),
}

impl Origin<'_> {
    /// The refusal of `raw` for a component of this origin that names no single place.
    fn unplaceable(self, raw: &Path) -> CliError {
        match self {
            Self::Request => unplaceable(raw),
            Self::Cwd(cwd) => unplaceable_cwd(cwd, raw),
        }
    }
}

/// Accept `prefix` only as a [`PlaceablePrefix`], refused under the part of the input it came from.
fn accept_prefix(prefix: Prefix<'_>, origin: Origin<'_>, raw: &Path) -> Result<(), CliError> {
    PlaceablePrefix::parse(prefix)
        .map(|_| ())
        .map_err(|_| origin.unplaceable(raw))
}

/// Walk `base` then `raw` as one component sequence into a proven absolute path.
///
/// `base` is the already chosen start of the walk: empty for an absolute
/// `raw`, else the working directory `cwd` or its drive. A refusal of a
/// component of `base` names `cwd`, the part the invoker must change.
fn prove_walk(raw: &Path, base: &Path, cwd: &Path) -> Result<ProvenOutPath, CliError> {
    let traversal = || -> CliError { OutputRefusal::ParentTraversal(raw.to_path_buf()).into() };
    if has_verbatim_dot_component(base) {
        return Err(unplaceable_cwd(cwd, raw));
    }
    if has_verbatim_dot_component(raw) {
        return Err(unplaceable(raw));
    }
    let mut proven = PathBuf::new();
    let walked = base
        .components()
        .map(|component| (component, Origin::Cwd(cwd)))
        .chain(
            raw.components()
                .map(|component| (component, Origin::Request)),
        );
    for (component, origin) in walked {
        match component {
            Component::Prefix(prefix) => {
                accept_prefix(prefix.kind(), origin, raw)?;
                proven.push(component);
            }
            Component::RootDir => proven.push(component),
            Component::CurDir => {}
            Component::Normal(name) => {
                if !ipe_fs_open::is_one_spelled_name(name) {
                    return Err(origin.unplaceable(raw));
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
        return Err(unplaceable(raw));
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

/// Whether `path` is verbatim (`\\?\`) and holds a `.` or `..` component.
///
/// Under a verbatim prefix neither `.` nor `..` is a step: the OS passes each
/// through as a literal name, so dropping a `.` or popping a level for a `..`
/// would prove a path other than the one spelled.
fn has_verbatim_dot_component(path: &Path) -> bool {
    let mut components = path.components();
    let verbatim = matches!(
        components.next(),
        Some(Component::Prefix(prefix)) if prefix.kind().is_verbatim()
    );
    verbatim
        && components.any(|component| matches!(component, Component::CurDir | Component::ParentDir))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::path::{Path, Prefix};

    use super::{Cwd, Origin, OutputRefusal, accept_prefix, prove_parent_steps_from};
    use crate::CliError;

    /// A prefix that is no `PlaceablePrefix` is refused under the part of the input it came from.
    #[test]
    fn prove_walk_refuses_a_bad_share() {
        let cwd = Cwd::assumed(r"\\srv\con\x".into());
        let request = Path::new("out");
        let bad = [
            Prefix::UNC(OsStr::new("srv"), OsStr::new("con")),
            Prefix::UNC(OsStr::new("srv"), OsStr::new("")),
            Prefix::UNC(OsStr::new("-srv"), OsStr::new("share")),
            Prefix::VerbatimUNC(OsStr::new(".."), OsStr::new("x")),
            Prefix::DeviceNS(OsStr::new("pipe")),
            Prefix::Verbatim(OsStr::new("Volume{00000000-0000-0000-0000-000000000000}")),
        ];
        for prefix in bad {
            let from_cwd = accept_prefix(prefix, Origin::Cwd(cwd.as_path()), request);
            assert!(
                matches!(
                    &from_cwd,
                    Err(CliError::OutputRefused(OutputRefusal::UnplaceableCwd { cwd: named, request: asked }))
                        if named == cwd.as_path() && asked == request
                ),
                "{prefix:?} from the working directory must name it, got {from_cwd:?}"
            );
            let from_request = accept_prefix(prefix, Origin::Request, request);
            assert!(
                matches!(
                    &from_request,
                    Err(CliError::OutputRefused(OutputRefusal::Unplaceable(asked))) if asked == request
                ),
                "{prefix:?} in the request must name it, got {from_request:?}"
            );
        }
        let share = Prefix::UNC(OsStr::new("localhost"), OsStr::new("C$"));
        let kept = accept_prefix(share, Origin::Request, request);
        assert!(
            kept.is_ok(),
            "an admin share on a host name is placeable, got {kept:?}"
        );
    }

    /// A requested name holding NUL is unplaceable, never handed to an open.
    #[test]
    fn a_name_holding_nul_is_unplaceable() {
        let cwd = Cwd::assumed(ipe_test_temp::temp_root());
        for raw in ["out\0", "a/out\0dir", "\0"] {
            let result = prove_parent_steps_from(Path::new(raw), &cwd);
            assert!(
                matches!(
                    result,
                    Err(CliError::OutputRefused(OutputRefusal::Unplaceable(_)))
                ),
                "--out {raw:?} must be unplaceable, got {result:?}"
            );
        }
        let kept = prove_parent_steps_from(Path::new("a/out"), &cwd).expect("a plain name");
        assert_eq!(
            kept.as_path(),
            ipe_test_temp::temp_root().join("a").join("out"),
            "a plain relative name is proven onto the working directory"
        );
    }
}
