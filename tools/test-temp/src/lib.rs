//! The OS temp root for test code.
//!
//! Production code never names the shared temp base: it creates every
//! temporary entry through the scratch primitive (`ipe_sandbox::scratch`, or
//! the runtime's `scratch_core`), which verifies the base and creates entries
//! exclusively under it. Clippy bans the standard library's and `tempfile`'s
//! temp-root lookups everywhere else, so a test that needs the root reads it
//! here. This crate is a dev-dependency only; the scratch text gate refuses a
//! manifest that lists it under `[dependencies]` or `[build-dependencies]`.
//!
//! The root is handed out only once it is proven to sit outside every Ipê
//! project: a project marker at the base or above it would make the compiler's
//! upward manifest and cache walks see a host project, and flip any test rooted
//! there.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

/// The entries whose presence at a directory makes it an Ipê project root, component by component.
///
/// The `ipe` CLI owns these names; its test build fails unless this list
/// equals its package manifest, project manifest and FFI cache components.
pub const PROJECT_MARKERS: [&[&str]; 3] = [
    &["package.ipe"],
    &["ipe.toml"],
    &[".ipe", "cache", "ffi", "rust"],
];

/// The directory names the `ipe` CLI reserves, refusing build output inside them.
///
/// The `ipe` CLI owns these names; its test build fails unless this list
/// equals its reserved-name set, in order.
pub const RESERVED_COMPONENTS: [&str; 5] = [".git", ".hg", ".jj", "_darcs", ".ipe"];

/// Why a temp base is unfit to root tests.
#[derive(Debug)]
pub enum HostUnfit {
    /// A project marker exists at this path, at the base or one of its ancestors.
    MarkerAt(PathBuf),
    /// A component of the base is a reserved directory name; the path ends at it.
    ReservedComponent(PathBuf),
    /// The base, or a marker path the proof must inspect, could not be resolved
    /// or inspected, so its absence is unproven.
    Unresolvable(PathBuf, std::io::Error),
}

/// Prove that `base` sits outside every Ipê project.
///
/// Both the spelled path and its canonical form are checked: no component may
/// be a reserved directory name (ASCII case ignored), and neither the base nor
/// any ancestor may hold a project marker. A marker counts whenever an entry of
/// that name exists, whatever its type, so a directory or a dangling link
/// refuses too.
///
/// # Errors
///
/// The first [`HostUnfit`] found; an unresolvable base, or a marker path whose
/// absence cannot be established, is never a pass.
pub fn prove_outside_projects(base: &Path) -> Result<(), HostUnfit> {
    let canonical = std::fs::canonicalize(base)
        .map_err(|error| HostUnfit::Unresolvable(base.to_path_buf(), error))?;
    for form in [base, canonical.as_path()] {
        refuse_reserved_component(form)?;
    }
    for form in [base, canonical.as_path()] {
        refuse_marker(form)?;
    }
    Ok(())
}

/// Refuse a path one of whose components is a reserved directory name.
fn refuse_reserved_component(path: &Path) -> Result<(), HostUnfit> {
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        if let Component::Normal(name) = component
            && is_reserved(name)
        {
            return Err(HostUnfit::ReservedComponent(prefix));
        }
    }
    Ok(())
}

/// Whether `name` is a reserved directory name, ASCII case ignored.
fn is_reserved(name: &OsStr) -> bool {
    RESERVED_COMPONENTS.iter().any(|reserved| {
        name.as_encoded_bytes()
            .eq_ignore_ascii_case(reserved.as_bytes())
    })
}

/// Refuse a path where it or an ancestor holds a project marker.
///
/// The empty ancestor of a relative path names the working directory, not an
/// ancestor of the base, so it is skipped; the canonical form covers the real
/// ancestry.
fn refuse_marker(path: &Path) -> Result<(), HostUnfit> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        for marker in PROJECT_MARKERS {
            let mut at = ancestor.to_path_buf();
            at.extend(marker);
            match at.symlink_metadata() {
                Ok(_) => return Err(HostUnfit::MarkerAt(at)),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) => {}
                Err(error) => return Err(HostUnfit::Unresolvable(at, error)),
            }
        }
    }
    Ok(())
}

/// The OS temp root, as `std::env::temp_dir`, once proven outside every project.
///
/// The proof runs on every call, so a marker planted mid-run is caught at the
/// next one.
///
/// # Panics
///
/// When [`prove_outside_projects`] refuses the root: an unfit host stops the
/// test rather than flipping its outcome.
#[must_use]
#[allow(clippy::disallowed_methods)] // the sanctioned test-support reader of the temp root
pub fn temp_root() -> PathBuf {
    let root = std::env::temp_dir();
    match prove_outside_projects(&root) {
        Ok(()) => root,
        Err(unfit) => unfit_host(&unfit),
    }
}

/// Stop the calling test on a host whose temp root fails the proof.
#[allow(clippy::panic)] // test support: an unfit host must stop the test, never flip it
fn unfit_host(unfit: &HostUnfit) -> ! {
    // IPE-RUST-AUDIT:ACCEPTED — test-support failure path; an unfit host fails the calling test
    panic!("the OS temp root cannot root tests: {unfit:?}");
}

#[cfg(test)]
mod tests {
    use super::{HostUnfit, PROJECT_MARKERS, RESERVED_COMPONENTS, prove_outside_projects};
    use std::fs;
    use std::path::{Path, PathBuf};

    /// A fresh fixture directory `<temp>/ipe-test-temp-<tag>-<pid>`.
    #[allow(clippy::disallowed_methods)] // the fixture sits beside the root under proof
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ipe-test-temp-{tag}-{}", std::process::id()));
        if dir.symlink_metadata().is_ok() {
            fs::remove_dir_all(&dir).expect("clear stale fixture");
        }
        fs::create_dir_all(&dir).expect("create fixture");
        dir
    }

    fn mkdir(path: &Path) {
        fs::create_dir_all(path).expect("create fixture dir");
    }

    fn touch(path: &Path) {
        if let Some(parent) = path.parent() {
            mkdir(parent);
        }
        fs::write(path, "").expect("plant fixture file");
    }

    fn cleanup(dir: &Path) {
        fs::remove_dir_all(dir).expect("remove fixture");
    }

    /// Assert the proof refuses `base` with a marker at exactly `at`.
    fn assert_marker(base: &Path, at: &Path) {
        let result = prove_outside_projects(base);
        assert!(
            matches!(result, Err(HostUnfit::MarkerAt(ref found)) if found == at),
            "expected a marker at {}, got {result:?}",
            at.display()
        );
    }

    /// Assert the proof admits `base`.
    fn assert_admits(base: &Path) {
        let result = prove_outside_projects(base);
        assert!(
            result.is_ok(),
            "expected {} admitted, got {result:?}",
            base.display()
        );
    }

    #[test]
    fn layout_names_pin() {
        assert_eq!(
            PROJECT_MARKERS,
            [
                &["package.ipe"][..],
                &["ipe.toml"][..],
                &[".ipe", "cache", "ffi", "rust"][..],
            ]
        );
        assert_eq!(
            RESERVED_COMPONENTS,
            [".git", ".hg", ".jj", "_darcs", ".ipe"]
        );
    }

    #[test]
    fn ancestor_manifest_refuses() {
        let dir = scratch("ancestor-manifest");
        let base = dir.join("a").join("b");
        mkdir(&base);
        let marker = dir.join("a").join("package.ipe");
        touch(&marker);
        assert_marker(&base, &marker);
        fs::remove_file(&marker).expect("remove marker");
        assert_admits(&base);
        cleanup(&dir);
    }

    #[test]
    fn marker_at_base_refuses() {
        let dir = scratch("marker-at-base");
        let marker = dir.join("package.ipe");
        touch(&marker);
        assert_marker(&dir, &marker);
        fs::remove_file(&marker).expect("remove marker");
        assert_admits(&dir);
        cleanup(&dir);
    }

    #[test]
    fn ipe_toml_ancestor_refuses() {
        let dir = scratch("ipe-toml-ancestor");
        let base = dir.join("a").join("b");
        mkdir(&base);
        let marker = dir.join("ipe.toml");
        touch(&marker);
        assert_marker(&base, &marker);
        fs::remove_file(&marker).expect("remove marker");
        assert_admits(&base);
        cleanup(&dir);
    }

    #[test]
    fn ffi_cache_ancestor_refuses() {
        let dir = scratch("ffi-cache-ancestor");
        let base = dir.join("a").join("b");
        mkdir(&base);
        let marker = dir
            .join("a")
            .join(".ipe")
            .join("cache")
            .join("ffi")
            .join("rust");
        mkdir(&marker);
        assert_marker(&base, &marker);
        fs::remove_dir(&marker).expect("remove marker");
        assert_admits(&base);
        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn dangling_link_marker_refuses() {
        let dir = scratch("dangling-link");
        let base = dir.join("a");
        mkdir(&base);
        let marker = dir.join("package.ipe");
        std::os::unix::fs::symlink(dir.join("absent"), &marker).expect("plant dangling link");
        assert_marker(&base, &marker);
        fs::remove_file(&marker).expect("remove marker");
        assert_admits(&base);
        cleanup(&dir);
    }

    #[test]
    fn directory_named_manifest_refuses() {
        let dir = scratch("directory-manifest");
        let base = dir.join("a");
        mkdir(&base);
        let marker = dir.join("package.ipe");
        mkdir(&marker);
        assert_marker(&base, &marker);
        fs::remove_dir(&marker).expect("remove marker");
        assert_admits(&base);
        cleanup(&dir);
    }

    #[test]
    fn reserved_component_refuses() {
        let dir = scratch("reserved-component");
        let reserved = dir.join(".GIT");
        let base = reserved.join("x");
        mkdir(&base);
        let result = prove_outside_projects(&base);
        assert!(
            matches!(result, Err(HostUnfit::ReservedComponent(ref at)) if *at == reserved),
            "expected {} refused as reserved, got {result:?}",
            reserved.display()
        );
        let renamed = dir.join("GIT");
        fs::rename(&reserved, &renamed).expect("rename reserved dir");
        assert_admits(&renamed.join("x"));
        cleanup(&dir);
    }

    #[test]
    fn missing_base_is_unresolvable() {
        let dir = scratch("missing-base");
        let base = dir.join("absent");
        let result = prove_outside_projects(&base);
        assert!(
            matches!(result, Err(HostUnfit::Unresolvable(ref at, _)) if *at == base),
            "expected {} unresolvable, got {result:?}",
            base.display()
        );
        mkdir(&base);
        assert_admits(&base);
        cleanup(&dir);
    }

    #[test]
    fn bare_namespace_dir_admits() {
        let dir = scratch("bare-namespace");
        let base = dir.join("a").join("b");
        mkdir(&base);
        mkdir(&dir.join("a").join(".ipe"));
        assert_admits(&base);
        cleanup(&dir);
    }

    #[test]
    fn clean_base_admits() {
        let dir = scratch("clean-base");
        assert_admits(&dir);
        cleanup(&dir);
    }
}
