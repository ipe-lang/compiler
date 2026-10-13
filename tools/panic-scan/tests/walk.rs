//! The one walker lists every file under a root, or refuses the whole tree by type.
//!
//! Each refusal is driven with the input one step past what the walk accepts,
//! next to a control at the ceiling, so a walk that drops an entry or stops
//! early reads as a red here, never as a shorter list a scan then certifies.

use std::path::{Path, PathBuf};

use panic_scan::{DirDepth, EntryCeiling, WalkError, Want, rust_sources};

/// A fresh, empty scratch directory named `name`.
#[allow(clippy::expect_used)] // a test that cannot build its tree has nothing to assert
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("panic-scan-walk")
        .join(name);
    // A leftover from an earlier run may be absent; the fresh contents written
    // afterwards are what the test relies on.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch directory");
    dir
}

/// Write an empty file at `root/rel`, creating its parent directories.
#[allow(clippy::expect_used)] // a test that cannot build its tree has nothing to assert
fn put(root: &Path, rel: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create fixture directory");
    }
    std::fs::write(path, "").expect("write fixture file");
}

/// `levels` nested directories below `root`, the deepest holding `deep.rs`.
#[allow(clippy::expect_used)] // a test that cannot build its tree has nothing to assert
fn nest(root: &Path, levels: usize) -> PathBuf {
    let mut dir = root.to_path_buf();
    for _ in 0..levels {
        dir.push("d");
    }
    std::fs::create_dir_all(&dir).expect("create nested directories");
    std::fs::write(dir.join("deep.rs"), "").expect("write nested file");
    dir
}

#[test]
fn lists_every_wanted_file_sorted_and_skips_no_directory() {
    let root = scratch("lists");
    for rel in [
        "b.rs",
        "a/z.rs",
        "a/Cargo.toml",
        "a/notes.txt",
        ".hidden/h.rs",
        "target/t.rs",
        "a.rs",
    ] {
        put(&root, rel);
    }
    let rust = rust_sources(&root, Want::RustFiles).expect("walk the tree");
    let expected: Vec<PathBuf> = ["a/z.rs", "a.rs", ".hidden/h.rs", "b.rs", "target/t.rs"]
        .iter()
        .map(|rel| root.join(rel))
        .collect();
    let mut sorted = expected.clone();
    sorted.sort();
    assert_eq!(
        rust, sorted,
        "every `.rs` file, hidden and `target` included"
    );
    let with_manifests = rust_sources(&root, Want::RustAndManifests).expect("walk the tree");
    assert!(with_manifests.contains(&root.join("a/Cargo.toml")));
    assert_eq!(with_manifests.len(), rust.len() + 1, "{with_manifests:?}");
}

#[test]
fn a_missing_root_is_refused() {
    let root = scratch("missing").join("absent");
    let walked = rust_sources(&root, Want::RustFiles);
    assert!(
        matches!(&walked, Err(WalkError::Missing { root: named }) if *named == root),
        "{walked:?}"
    );
}

#[cfg(unix)]
#[test]
fn an_unreadable_directory_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let root = scratch("unreadable");
    put(&root, "lib.rs");
    put(&root, "locked/prod.rs");
    let locked = root.join("locked");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
        .expect("lock directory");
    // A privileged user reads the locked directory anyway: nothing to refuse.
    let readable = std::fs::read_dir(&locked).is_ok();
    let walked = rust_sources(&root, Want::RustFiles);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755))
        .expect("unlock directory");
    if readable {
        return;
    }
    assert!(
        matches!(&walked, Err(WalkError::Io { path, .. }) if *path == locked),
        "{walked:?}"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_directory_is_refused_and_a_symlinked_file_is_listed() {
    let root = scratch("symlinks");
    put(&root, "outside/prod.rs");
    put(&root, "tree/lib.rs");
    std::os::unix::fs::symlink("../outside/prod.rs", root.join("tree/linked.rs"))
        .expect("create file symlink");
    let tree = root.join("tree");
    let listed = rust_sources(&tree, Want::RustFiles).expect("walk the tree");
    assert_eq!(listed, vec![tree.join("lib.rs"), tree.join("linked.rs")]);

    std::os::unix::fs::symlink("../outside", tree.join("linked")).expect("create dir symlink");
    let walked = rust_sources(&tree, Want::RustFiles);
    assert!(
        matches!(&walked, Err(WalkError::SymlinkedDirectory { path }) if *path == tree.join("linked")),
        "{walked:?}"
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_root_directory_is_refused() {
    let root = scratch("symlinked_root");
    put(&root, "real/lib.rs");
    let link = root.join("link");
    std::os::unix::fs::symlink("real", &link).expect("create dir symlink");
    let walked = rust_sources(&link, Want::RustFiles);
    assert!(
        matches!(&walked, Err(WalkError::SymlinkedDirectory { path }) if *path == link),
        "{walked:?}"
    );
}

#[cfg(unix)]
#[test]
fn a_dangling_symlink_is_refused() {
    let root = scratch("dangling");
    put(&root, "lib.rs");
    let link = root.join("gone.rs");
    std::os::unix::fs::symlink("no-such-target.rs", &link).expect("create symlink");
    let walked = rust_sources(&root, Want::RustFiles);
    assert!(
        matches!(&walked, Err(WalkError::Io { path, .. }) if *path == link),
        "{walked:?}"
    );
}

#[test]
fn a_directory_past_the_depth_ceiling_is_refused() {
    let ceiling = DirDepth::CEILING.get();
    let at = scratch("depth_at");
    let deepest = nest(&at, ceiling);
    let listed = rust_sources(&at, Want::RustFiles).expect("walk at the depth ceiling");
    assert_eq!(listed, vec![deepest.join("deep.rs")]);

    let past = scratch("depth_past");
    let too_deep = nest(&past, ceiling + 1);
    let walked = rust_sources(&past, Want::RustFiles);
    assert!(
        matches!(&walked, Err(WalkError::TooDeep { path, ceiling: named })
            if *path == too_deep && *named == DirDepth::CEILING),
        "{walked:?}"
    );
}

#[test]
fn a_tree_past_the_entry_ceiling_is_refused() {
    let ceiling = EntryCeiling::CEILING.get();
    let root = scratch("entries");
    // One directory holds the ceiling: `ceiling - 1` plain files beside it.
    put(&root, "sub/lib.rs");
    for n in 0..ceiling - 2 {
        std::fs::write(root.join(n.to_string()), "").expect("write filler entry");
    }
    let listed = rust_sources(&root, Want::RustFiles).expect("walk at the entry ceiling");
    assert_eq!(listed, vec![root.join("sub/lib.rs")]);

    put(&root, "one-more");
    let walked = rust_sources(&root, Want::RustFiles);
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        matches!(&walked, Err(WalkError::TooMany { root: named, ceiling: limit })
            if *named == root && *limit == EntryCeiling::CEILING),
        "{walked:?}"
    );
}
