//! Whether a jail bind would expose the cargo home.
//!
//! The cargo home holds `credentials.toml`; a jail may bind its `bin`,
//! `registry`, and `git` subdirectories but never the home itself nor any
//! directory at or above it. [`JailMounts`] is the only bind set the build and
//! run jails accept, and only its checker builds one.

use std::path::{Path, PathBuf};

use crate::{CanonicalPath, HomeMasks, JailPathError};

/// Every host path a build or run jail exposes, none at or above the cargo home.
///
/// The one always-writable scratch, the working tree (writable only when the
/// profile grants the filesystem axis), and the read-only binds, with the home
/// masks resolved alongside them. Only [`Self::of_invoker`] builds one, after
/// checking every path, whatever its source, against the invoker's cargo home;
/// [`Self::recheck`] repeats that check when the jail is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JailMounts {
    scoped_tmp: CanonicalPath,
    working_tree: CanonicalPath,
    read_only: Vec<CanonicalPath>,
    homes: HomeMasks,
    cargo_home: PathBuf,
}

impl JailMounts {
    /// The jail mounts of the invoking process, checked against its cargo home.
    ///
    /// The cargo home is `CARGO_HOME`, else `$HOME/.cargo`; the home masks are
    /// the invoker's.
    ///
    /// # Errors
    /// - [`JailPathError::UserHomeUnresolved`] when the user home, and so the
    ///   cargo home, is unknown.
    /// - [`JailPathError::ToolHomeRelative`] when `CARGO_HOME` is relative.
    /// - [`JailPathError::ExposesCargoHome`] when a path equals or contains the
    ///   cargo home.
    pub fn of_invoker(
        scoped_tmp: CanonicalPath,
        working_tree: CanonicalPath,
        read_only: Vec<CanonicalPath>,
    ) -> Result<Self, JailPathError> {
        let home = crate::home::home_dir();
        let cargo_home = crate::home::tool_home("CARGO_HOME", home.as_ref().ok(), ".cargo")
            .map_err(JailPathError::ToolHomeRelative)?;
        let user_home = home.map_err(JailPathError::UserHomeUnresolved)?;
        let homes = HomeMasks::resolve(Ok(&user_home), cargo_home.as_ref())?;
        let cargo_home =
            cargo_home.unwrap_or_else(|| crate::home::ToolHome::under(&user_home, ".cargo"));
        Self::checked(
            scoped_tmp,
            working_tree,
            read_only,
            homes,
            cargo_home.as_path().to_path_buf(),
        )
    }

    /// `scoped_tmp`, `working_tree`, and `read_only` checked against
    /// `cargo_home`.
    ///
    /// # Errors
    /// [`JailPathError::ExposesCargoHome`] when a path equals or contains
    /// `cargo_home`.
    fn checked(
        scoped_tmp: CanonicalPath,
        working_tree: CanonicalPath,
        read_only: Vec<CanonicalPath>,
        homes: HomeMasks,
        cargo_home: PathBuf,
    ) -> Result<Self, JailPathError> {
        let mounts = Self {
            scoped_tmp,
            working_tree,
            read_only,
            homes,
            cargo_home,
        };
        mounts.refuse_exposing()?;
        Ok(mounts)
    }

    /// Test-only: the check against a stand-in `cargo_home` under stand-in
    /// `homes`, for pure argv tests over paths that need not exist.
    ///
    /// # Errors
    /// As the checker: [`JailPathError::ExposesCargoHome`].
    #[cfg(test)]
    pub fn checked_against(
        scoped_tmp: CanonicalPath,
        working_tree: CanonicalPath,
        read_only: Vec<CanonicalPath>,
        homes: HomeMasks,
        cargo_home: &Path,
    ) -> Result<Self, JailPathError> {
        Self::checked(
            scoped_tmp,
            working_tree,
            read_only,
            homes,
            cargo_home.to_path_buf(),
        )
    }

    /// Confirm every path still resolves to itself and still exposes no cargo
    /// home.
    ///
    /// # Errors
    /// [`JailPathError::Moved`] when a path changed since it was resolved;
    /// [`JailPathError::ExposesCargoHome`] when one now covers the cargo home.
    pub fn recheck(&self) -> Result<(), JailPathError> {
        for path in self.all() {
            path.recheck()?;
        }
        self.refuse_exposing()
    }

    /// Refuse when a fixed path a platform profile grants on top of these
    /// mounts equals or contains the cargo home.
    ///
    /// A profile with no masks (Seatbelt) exposes whatever its fixed roots
    /// cover, so those roots answer to the same check as the mounts.
    ///
    /// # Errors
    /// [`JailPathError::ExposesCargoHome`] naming the first such path.
    pub fn refuse_fixed_exposing(&self, fixed: &[&str]) -> Result<(), JailPathError> {
        fixed
            .iter()
            .map(Path::new)
            .find(|root| path_covers(root, &self.cargo_home))
            .map_or(Ok(()), |root| {
                Err(JailPathError::ExposesCargoHome {
                    bind: root.to_path_buf(),
                    cargo_home: self.cargo_home.clone(),
                })
            })
    }

    fn refuse_exposing(&self) -> Result<(), JailPathError> {
        self.all()
            .find(|path| path_covers(path.as_path(), &self.cargo_home))
            .map_or(Ok(()), |bind| {
                Err(JailPathError::ExposesCargoHome {
                    bind: bind.as_path().to_path_buf(),
                    cargo_home: self.cargo_home.clone(),
                })
            })
    }

    fn all(&self) -> impl Iterator<Item = &CanonicalPath> {
        [&self.scoped_tmp, &self.working_tree]
            .into_iter()
            .chain(&self.read_only)
    }

    /// The one always-writable scratch.
    #[must_use]
    pub const fn scoped_tmp(&self) -> &CanonicalPath {
        &self.scoped_tmp
    }

    /// The working tree, writable only when the filesystem axis is granted.
    #[must_use]
    pub const fn working_tree(&self) -> &CanonicalPath {
        &self.working_tree
    }

    /// The read-only binds.
    #[must_use]
    pub fn read_only(&self) -> &[CanonicalPath] {
        &self.read_only
    }

    /// The home masks resolved with the paths.
    #[must_use]
    pub const fn homes(&self) -> &HomeMasks {
        &self.homes
    }
}

/// The first of `binds` that would make `cargo_home` visible inside the jail.
///
/// Binding such a path exposes `credentials.toml`; [`JailMounts`] refuses every
/// bind set for which this returns `Some`.
#[must_use]
pub fn bind_exposing<'a>(
    binds: &'a [CanonicalPath],
    cargo_home: &Path,
) -> Option<&'a CanonicalPath> {
    binds
        .iter()
        .find(|bind| path_covers(bind.as_path(), cargo_home))
}

/// Whether binding `outer` makes `inner` visible.
///
/// `inner` equals or lies under `outer`, judged lexically, with symlinks
/// resolved, and by directory identity. Any judgement finding containment is
/// enough.
#[must_use]
pub fn path_covers(outer: &Path, inner: &Path) -> bool {
    lexical_normal(inner).starts_with(lexical_normal(outer))
        || resolved(inner).starts_with(resolved(outer))
        || covers_by_identity(outer, inner)
}

/// Whether some ancestor of `inner` (itself included) is the directory
/// `outer`, compared by `(dev, ino)`.
///
/// This also catches a bind-mount alias no path comparison sees. `link(2)`
/// refuses directories, so one `(dev, ino)` names exactly one directory and no
/// hardlinked alias exists. An `outer` that does not exist exposes nothing; a
/// missing ancestor of `inner` cannot be `outer`. Any other metadata error
/// counts as covered.
#[cfg(unix)]
fn covers_by_identity(outer: &Path, inner: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let identity = |path: &Path| std::fs::metadata(path).map(|meta| (meta.dev(), meta.ino()));
    let outer_id = match identity(outer) {
        Ok(id) => id,
        Err(e) => return e.kind() != std::io::ErrorKind::NotFound,
    };
    inner
        .ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .any(|ancestor| match identity(ancestor) {
            Ok(id) => id == outer_id,
            Err(e) => e.kind() != std::io::ErrorKind::NotFound,
        })
}

/// Directory identity has no portable form off unix; the lexical and resolved
/// judgements of [`path_covers`] stand alone there.
#[cfg(not(unix))]
const fn covers_by_identity(_outer: &Path, _inner: &Path) -> bool {
    false
}

/// `path` without `.` components, each `..` removing the component before it
/// (never above the root); trailing separators vanish with the components.
fn lexical_normal(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                out.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
        }
    }
    out
}

/// `path` with symlinks resolved as the kernel resolves them.
///
/// A `..` after a symlink climbs from the link's target. A path that does not
/// exist yet resolves through its longest existing ancestor, with the missing
/// tail appended and the whole normalized lexically.
fn resolved(path: &Path) -> PathBuf {
    for ancestor in path.ancestors() {
        if let Ok(real) = std::fs::canonicalize(ancestor) {
            return path.strip_prefix(ancestor).map_or_else(
                |_| lexical_normal(path),
                |tail| lexical_normal(&real.join(tail)),
            );
        }
    }
    lexical_normal(path)
}

#[cfg(test)]
#[allow(clippy::expect_used)] // test fixtures: the scratch dirs must exist
mod tests {
    use super::*;
    use crate::test_dir::TestDir;

    fn make_dir(path: &Path) {
        std::fs::create_dir_all(path).expect("create dir");
    }

    #[cfg(unix)]
    #[test]
    fn identity_sees_an_equal_or_enclosing_dir_and_nothing_else() {
        let tmp_dir = TestDir::new("covers-identity").expect("test dir");
        let tmp = tmp_dir.path();
        let cargo_home = tmp.join(".cargo");
        let other = tmp.join("other");
        make_dir(&cargo_home.join("bin"));
        make_dir(&other);
        assert!(
            covers_by_identity(&cargo_home, &cargo_home),
            "the directory itself is covered"
        );
        assert!(
            covers_by_identity(tmp, &cargo_home),
            "an enclosing directory covers it"
        );
        assert!(
            !covers_by_identity(&cargo_home.join("bin"), &cargo_home),
            "a directory below does not cover it"
        );
        assert!(
            !covers_by_identity(&other, &cargo_home),
            "a disjoint directory does not cover it"
        );
        assert!(
            !covers_by_identity(&tmp.join("absent"), &cargo_home),
            "a missing bind exposes nothing"
        );
        assert!(
            !covers_by_identity(&other, &cargo_home.join("absent")),
            "a missing tail cannot be the bind"
        );
    }

    #[test]
    fn a_bind_at_or_above_the_cargo_home_exposes_it() {
        let tmp_dir = TestDir::new("covers-exposing").expect("test dir");
        let tmp = tmp_dir.path();
        let cargo_home = tmp.join(".cargo");
        make_dir(&cargo_home.join("bin"));
        let canonical = |path: &Path| CanonicalPath::resolve(path).expect("canonical");
        let bin = canonical(&cargo_home.join("bin"));
        for exposing in [canonical(&cargo_home), canonical(tmp)] {
            let binds = [bin.clone(), exposing.clone()];
            assert_eq!(bind_exposing(&binds, &cargo_home), Some(&exposing));
        }
        assert_eq!(bind_exposing(std::slice::from_ref(&bin), &cargo_home), None);
    }

    #[test]
    fn jail_mounts_refuse_a_crate_or_workspace_root_at_or_above_the_cargo_home() {
        let tmp_dir = TestDir::new("covers-mounts").expect("test dir");
        let tmp = tmp_dir.path();
        let cargo_home = tmp.join("home").join(".cargo");
        let scratch = tmp.join("scratch");
        let crate_root = tmp.join("crate");
        make_dir(&cargo_home.join("bin"));
        make_dir(&scratch);
        make_dir(&crate_root);
        let canonical = |path: &Path| CanonicalPath::resolve(path).expect("canonical");
        let mounts = |scoped: &Path, working: &Path, read_only: Vec<CanonicalPath>| {
            JailMounts::checked_against(
                canonical(scoped),
                canonical(working),
                read_only,
                HomeMasks::unmasked(),
                &cargo_home,
            )
        };
        let safe = vec![canonical(&cargo_home.join("bin")), canonical(&crate_root)];
        assert!(mounts(&scratch, &scratch, safe).is_ok());
        for exposing in [cargo_home.clone(), tmp.join("home"), tmp.to_path_buf()] {
            let read_only = vec![canonical(&crate_root), canonical(&exposing)];
            assert!(
                matches!(
                    mounts(&scratch, &scratch, read_only),
                    Err(JailPathError::ExposesCargoHome { bind, .. }) if bind == canonical(&exposing).as_path()
                ),
                "a read-only crate or workspace root at or above the cargo home is refused"
            );
            assert!(
                matches!(
                    mounts(&scratch, &exposing, Vec::new()),
                    Err(JailPathError::ExposesCargoHome { .. })
                ),
                "a working tree at or above the cargo home is refused"
            );
            assert!(
                matches!(
                    mounts(&exposing, &scratch, Vec::new()),
                    Err(JailPathError::ExposesCargoHome { .. })
                ),
                "a scratch at or above the cargo home is refused"
            );
        }
    }

    #[test]
    fn jail_mounts_recheck_refuses_a_path_moved_after_the_check() {
        let tmp_dir = TestDir::new("covers-recheck").expect("test dir");
        let tmp = tmp_dir.path();
        let cargo_home = tmp.join(".cargo");
        let scratch = tmp.join("scratch");
        let crate_root = tmp.join("crate");
        make_dir(&scratch);
        make_dir(&crate_root);
        let canonical = |path: &Path| CanonicalPath::resolve(path).expect("canonical");
        let mounts = JailMounts::checked_against(
            canonical(&scratch),
            canonical(&scratch),
            vec![canonical(&crate_root)],
            HomeMasks::unmasked(),
            &cargo_home,
        )
        .expect("disjoint mounts");
        assert!(mounts.recheck().is_ok());
        std::fs::remove_dir_all(&crate_root).expect("remove crate root");
        assert!(matches!(mounts.recheck(), Err(JailPathError::Moved { .. })));
    }

    #[test]
    fn lexical_dot_dot_cannot_hide_the_cargo_home() {
        assert!(path_covers(
            Path::new("/opt/tools/../home"),
            Path::new("/opt/home/.cargo")
        ));
        assert!(!path_covers(
            Path::new("/opt/home/.cargo/bin"),
            Path::new("/opt/home/.cargo")
        ));
    }
}
