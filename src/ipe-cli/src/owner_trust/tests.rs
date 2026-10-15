use std::path::{Path, PathBuf};

use super::*;

/// The FFI cache below `root`, spelled out component by component, as the loader discovers it.
fn cache_at(root: &Path) -> PathBuf {
    root.join(".ipe").join("cache").join("ffi").join("rust")
}

/// A fresh, empty scratch directory unique to `name` and this process.
fn scratch(name: &str) -> PathBuf {
    let dir =
        ipe_test_temp::temp_root().join(format!("ipe-owner-trust-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

const ME: Invoker = Invoker {
    uid: 1000,
    gid: 1000,
};

const fn stamp(uid: u32, gid: u32, mode: u32) -> Stamp {
    Stamp { uid, gid, mode }
}

#[test]
fn breach_refuses_a_foreign_owner() {
    assert_eq!(
        breach(stamp(1001, 1000, 0o700), ME),
        Some(Breach::ForeignOwner)
    );
}

#[test]
fn breach_refuses_world_write() {
    assert_eq!(
        breach(stamp(1000, 1000, 0o702), ME),
        Some(Breach::WorldWritable)
    );
}

#[test]
fn breach_refuses_write_by_a_foreign_group() {
    assert_eq!(
        breach(stamp(1000, 50, 0o770), ME),
        Some(Breach::ForeignGroupWritable)
    );
}

#[test]
fn breach_admits_a_private_entry_and_the_invokers_own_group() {
    assert_eq!(breach(stamp(1000, 50, 0o755), ME), None);
    assert_eq!(breach(stamp(1000, 1000, 0o775), ME), None);
}

#[test]
fn breach_refuses_a_root_owned_entry() {
    assert_eq!(breach(stamp(0, 0, 0o755), ME), Some(Breach::ForeignOwner));
}

#[test]
fn only_a_link_root_or_the_invoker_owns_is_admitted() {
    assert!(link_owner_admitted(0, ME), "root-owned link");
    assert!(link_owner_admitted(1000, ME), "invoker-owned link");
    assert!(!link_owner_admitted(1001, ME), "foreign-owned link");
}

#[test]
fn container_breach_admits_root_and_sticky_directories() {
    assert_eq!(container_breach(stamp(0, 0, 0o755), ME), None);
    assert_eq!(container_breach(stamp(0, 0, 0o1777), ME), None);
    assert_eq!(container_breach(stamp(1000, 1000, 0o1777), ME), None);
}

#[test]
fn container_breach_refuses_shared_write_without_the_sticky_bit() {
    assert_eq!(
        container_breach(stamp(1001, 1001, 0o755), ME),
        Some(Breach::ForeignOwner)
    );
    assert_eq!(
        container_breach(stamp(0, 0, 0o777), ME),
        Some(Breach::WorldWritable)
    );
    assert_eq!(
        container_breach(stamp(1000, 50, 0o775), ME),
        Some(Breach::ForeignGroupWritable)
    );
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use ipe_ffi::driver::CacheSource as _;

    use super::*;

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    /// Create every component of the cache below `root` as a private directory; return the cache path.
    fn private_chain(root: &Path) -> PathBuf {
        let mut dir = root.to_path_buf();
        for segment in ipe_ffi::driver::FFI_CACHE_COMPONENTS {
            dir.push(segment);
            std::fs::create_dir_all(&dir).expect("create cache component");
            chmod(&dir, 0o700);
        }
        dir
    }

    fn usage(result: Result<Option<TrustedCache>, CliError>) -> Option<text::Message> {
        match result {
            Err(CliError::TrustRefused(refusal)) => Some(refusal.message()),
            _ => None,
        }
    }

    fn artifact_usage(result: Result<Option<String>, CacheLoadError>) -> Option<text::Message> {
        match result {
            Err(CacheLoadError::Cli(CliError::TrustRefused(refusal))) => Some(refusal.message()),
            _ => None,
        }
    }

    #[test]
    fn a_private_owned_cache_is_held() {
        let root = scratch("control");
        let cache = private_chain(&root);
        let held = open_cache(&root).expect("owned cache is trusted");
        assert_eq!(held.as_ref().map(TrustedCache::path), Some(cache.as_path()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_absent_component_finds_no_cache() {
        let root = scratch("absent");
        std::fs::create_dir_all(root.join(".ipe/cache")).expect("create partial chain");
        let held = open_cache(&root).expect("absent cache is not an error");
        assert!(held.is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_symlinked_cache_root_is_refused() {
        let root = scratch("symlink-root");
        let cache = private_chain(&root);
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("create link target");
        chmod(&elsewhere, 0o700);
        std::fs::remove_dir(&cache).expect("remove real cache dir");
        symlink(&elsewhere, &cache).expect("plant symlink");
        let refused = usage(open_cache(&root));
        assert_eq!(
            refused,
            Some(text::msg::ffi_cache_symlink(&cache.display()))
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_symlinked_intermediate_component_is_refused() {
        let root = scratch("symlink-component");
        let real = scratch("symlink-component-target");
        private_chain(&real);
        let link = root.join(".ipe");
        symlink(real.join(".ipe"), &link).expect("plant symlink");
        let refused = usage(open_cache(&root));
        assert_eq!(refused, Some(text::msg::ffi_cache_symlink(&link.display())));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&real);
    }

    #[test]
    fn a_world_writable_component_is_refused() {
        let root = scratch("world-writable");
        let cache = private_chain(&root);
        let shared = root.join(".ipe/cache");
        chmod(&shared, 0o777);
        let refused = usage(open_cache(&root));
        assert_eq!(
            refused,
            Some(text::msg::ffi_cache_untrusted(&shared.display()))
        );
        chmod(&shared, 0o700);
        assert!(cache.is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_world_writable_component_above_an_absent_cache_is_not_refused() {
        let root = scratch("world-writable-no-cache");
        let shared = root.join(".ipe");
        std::fs::create_dir_all(&shared).expect("create .ipe");
        chmod(&shared, 0o777);
        let held = open_cache(&root).expect("no cache below, nothing to refuse");
        assert!(held.is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_regular_private_artifact_is_read_through_the_held_handle() {
        let root = scratch("artifact-ok");
        let cache = private_chain(&root);
        std::fs::write(cache.join("demo.pkg.json"), "{}").expect("write artifact");
        chmod(&cache.join("demo.pkg.json"), 0o600);
        let held = open_cache(&root)
            .expect("owned cache is trusted")
            .expect("cache exists");
        let names = held.entry_names().map_err(CliError::from).expect("list");
        assert_eq!(names, vec!["demo.pkg.json".to_owned()]);
        let body = held
            .read_artifact("demo.pkg.json")
            .map_err(CliError::from)
            .expect("read");
        assert_eq!(body.as_deref(), Some("{}"));
        let missing = held
            .read_artifact("absent.pkg.json")
            .map_err(CliError::from)
            .expect("absent artifact is not an error");
        assert!(missing.is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_symlinked_artifact_is_refused() {
        let root = scratch("artifact-symlink");
        let cache = private_chain(&root);
        let target = root.join("planted.json");
        std::fs::write(&target, "{}").expect("write link target");
        let link = cache.join("demo.pkg.json");
        symlink(&target, &link).expect("plant symlink");
        let held = open_cache(&root)
            .expect("owned cache is trusted")
            .expect("cache exists");
        let refused = artifact_usage(held.read_artifact("demo.pkg.json"));
        assert_eq!(refused, Some(text::msg::ffi_cache_symlink(&link.display())));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_directory_artifact_is_refused_as_not_regular() {
        let root = scratch("artifact-dir");
        let cache = private_chain(&root);
        let odd = cache.join("demo.pkg.json");
        std::fs::create_dir_all(&odd).expect("create directory artifact");
        chmod(&odd, 0o700);
        let held = open_cache(&root)
            .expect("owned cache is trusted")
            .expect("cache exists");
        let refused = artifact_usage(held.read_artifact("demo.pkg.json"));
        assert_eq!(
            refused,
            Some(text::msg::ffi_cache_not_regular(&odd.display()))
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_world_writable_artifact_is_refused() {
        let root = scratch("artifact-world-writable");
        let cache = private_chain(&root);
        let artifact = cache.join("demo.pkg.json");
        std::fs::write(&artifact, "{}").expect("write artifact");
        chmod(&artifact, 0o666);
        let held = open_cache(&root)
            .expect("owned cache is trusted")
            .expect("cache exists");
        let refused = artifact_usage(held.read_artifact("demo.pkg.json"));
        assert_eq!(
            refused,
            Some(text::msg::ffi_cache_untrusted(&artifact.display()))
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_artifact_name_escaping_the_cache_is_refused() {
        let root = scratch("artifact-escape");
        private_chain(&root);
        let held = open_cache(&root)
            .expect("owned cache is trusted")
            .expect("cache exists");
        for name in ["", ".", "..", "../x", "a/b"] {
            let result = held.read_artifact(name);
            assert!(
                matches!(result, Err(CacheLoadError::Cli(CliError::Io { .. }))),
                "{name:?}: {result:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_listing_past_the_cap_is_refused() {
        let root = scratch("listing-cap");
        let cache = private_chain(&root);
        std::fs::write(cache.join("a"), "").expect("write a");
        std::fs::write(cache.join("b"), "").expect("write b");
        let dir = std::fs::File::open(&cache).expect("open cache dir");
        let refused = crate::owner_trust::held::list_capped(&dir, &cache, 1);
        assert!(
            matches!(&refused, Err(CliError::TrustRefused(t)) if t.message() == text::msg::ffi_cache_too_many_entries(&cache.display(), &1_usize)),
            "{refused:?}"
        );
        let admitted = crate::owner_trust::held::list_capped(&dir, &cache, 2)
            .expect("two entries fit a cap of two");
        assert_eq!(admitted.len(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Linux filesystems store arbitrary name bytes; APFS refuses non-UTF-8 names.
    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_names_count_toward_the_listing_cap() {
        use std::os::unix::ffi::OsStrExt as _;
        let root = scratch("listing-cap-non-utf8");
        let cache = private_chain(&root);
        for name in [b"\xffa".as_slice(), b"\xffb".as_slice()] {
            std::fs::write(cache.join(std::ffi::OsStr::from_bytes(name)), "")
                .expect("write non-UTF-8 entry");
        }
        let dir = std::fs::File::open(&cache).expect("open cache dir");
        let refused = crate::owner_trust::held::list_capped(&dir, &cache, 1);
        assert!(
            matches!(&refused, Err(CliError::TrustRefused(t)) if t.message() == text::msg::ffi_cache_too_many_entries(&cache.display(), &1_usize)),
            "{refused:?}"
        );
        let admitted = crate::owner_trust::held::list_capped(&dir, &cache, 2)
            .expect("two entries fit a cap of two");
        assert!(admitted.is_empty(), "a non-UTF-8 name is never an artifact");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A project dir holding an owned `package.ipe` with the given modes.
    fn project(name: &str, dir_mode: u32, manifest_mode: u32) -> (PathBuf, PathBuf) {
        let root = scratch(name);
        let manifest = root.join("package.ipe");
        std::fs::write(&manifest, "module Package exposing (package)\n").expect("write manifest");
        chmod(&manifest, manifest_mode);
        chmod(&root, dir_mode);
        (root, manifest)
    }

    #[test]
    fn an_owned_manifest_in_a_private_dir_is_admitted() {
        let (root, manifest) = project("manifest-ok", 0o755, 0o644);
        let admitted = admit_discovered_manifest(&manifest);
        assert!(admitted.is_ok(), "{admitted:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_owned_manifest_in_a_sticky_shared_dir_is_admitted() {
        let (root, manifest) = project("manifest-sticky", 0o1777, 0o644);
        let admitted = admit_discovered_manifest(&manifest);
        assert!(admitted.is_ok(), "{admitted:?}");
        chmod(&root, 0o755);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_world_writable_manifest_is_refused() {
        let (root, manifest) = project("manifest-world-writable", 0o755, 0o666);
        let refused = admit_discovered_manifest(&manifest);
        assert!(
            matches!(&refused, Err(CliError::TrustRefused(t)) if t.message() == text::msg::manifest_untrusted(&manifest.display())),
            "{refused:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_manifest_in_a_shared_non_sticky_dir_is_refused() {
        let (root, manifest) = project("manifest-shared-dir", 0o777, 0o644);
        let refused = admit_discovered_manifest(&manifest);
        assert!(
            matches!(&refused, Err(CliError::TrustRefused(t)) if t.message() == text::msg::manifest_untrusted(&manifest.display())),
            "{refused:?}"
        );
        chmod(&root, 0o755);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_symlinked_manifest_is_refused() {
        let root = scratch("manifest-symlink");
        chmod(&root, 0o755);
        let target = root.join("elsewhere.ipe");
        std::fs::write(&target, "module Package exposing (package)\n").expect("write target");
        let manifest = root.join("package.ipe");
        symlink(&target, &manifest).expect("plant symlink");
        let refused = admit_discovered_manifest(&manifest);
        assert!(
            matches!(&refused, Err(CliError::TrustRefused(t)) if t.message() == text::msg::manifest_symlink(&manifest.display())),
            "{refused:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_untrusted_ancestor_manifest_stops_the_entry_walk() {
        let (root, manifest) = project("manifest-ancestor", 0o755, 0o666);
        let src = root.join("src");
        std::fs::create_dir_all(&src).expect("create src");
        let entry = src.join("Main.ipe");
        std::fs::write(&entry, "module Main exposing (main)\nmain = 0\n").expect("write entry");
        let refused = crate::find_manifest_for_ipe_file(&entry);
        assert!(
            matches!(&refused, Err(CliError::TrustRefused(t)) if t.message() == text::msg::manifest_untrusted(&manifest.display())),
            "{refused:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_untrusted_ancestor_manifest_refuses_the_project_root() {
        let (root, manifest) = project("manifest-project-root", 0o755, 0o666);
        let src = root.join("src");
        std::fs::create_dir_all(&src).expect("create src");
        let entry = src.join("Main.ipe");
        std::fs::write(&entry, "module Main exposing (main)\nmain = 0\n").expect("write entry");
        let refused = crate::loose_file::ProjectRoot::of(None, &entry);
        assert!(
            matches!(&refused, Err(CliError::TrustRefused(t)) if t.message() == text::msg::manifest_untrusted(&manifest.display())),
            "{refused:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// The unverifiable-host refusals, driven on every platform.
mod unverifiable_policy {
    use super::*;

    #[test]
    fn an_existing_cache_directory_is_refused() {
        let root = scratch("unverifiable-policy-dir");
        let cache = cache_at(&root);
        std::fs::create_dir_all(&cache).expect("create cache");
        let refused = refuse_unverifiable_cache(&root);
        assert!(
            matches!(&refused, Err(CliError::TrustRefused(t)) if t.message() == text::msg::ffi_cache_unverifiable(&cache.display())),
            "{refused:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_existing_cache_file_is_refused() {
        let root = scratch("unverifiable-policy-file");
        let cache = cache_at(&root);
        let parent = cache.parent().expect("cache has a parent");
        std::fs::create_dir_all(parent).expect("create cache parent");
        std::fs::write(&cache, "").expect("plant a file at the cache path");
        let refused = refuse_unverifiable_cache(&root);
        assert!(
            matches!(&refused, Err(CliError::TrustRefused(t)) if t.message() == text::msg::ffi_cache_unverifiable(&cache.display())),
            "{refused:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_absent_cache_is_no_cache() {
        let root = scratch("unverifiable-policy-absent");
        assert!(refuse_unverifiable_cache(&root).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_path_through_a_file_is_no_cache() {
        let root = scratch("unverifiable-policy-through-file");
        std::fs::write(root.join(".ipe"), "").expect("plant a file where a directory belongs");
        let admitted = refuse_unverifiable_cache(&root);
        assert!(admitted.is_ok(), "{admitted:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_discovered_manifest_is_refused_naming_the_fix() {
        let manifest = Path::new("proj").join("package.ipe");
        let refused = refuse_unverifiable_manifest(&manifest);
        assert!(
            matches!(&refused, Err(CliError::TrustRefused(t)) if t.message() == text::msg::manifest_unverifiable(&manifest.display())),
            "{refused:?}"
        );
    }
}

/// The non-Unix discovery entry points route to the unverifiable-host refusals.
#[cfg(not(unix))]
mod unverifiable_host {
    use super::*;

    #[test]
    fn every_existing_cache_is_refused_as_unverifiable() {
        let root = scratch("unverifiable-cache");
        let cache = cache_at(&root);
        std::fs::create_dir_all(&cache).expect("create cache");
        let refused = open_cache(&root);
        assert!(
            matches!(&refused, Err(CliError::TrustRefused(t)) if t.message() == text::msg::ffi_cache_unverifiable(&cache.display())),
            "{refused:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn every_discovered_manifest_is_refused_as_unverifiable() {
        let manifest = Path::new("package.ipe");
        let refused = admit_discovered_manifest(manifest);
        assert!(
            matches!(&refused, Err(CliError::TrustRefused(t)) if t.message() == text::msg::manifest_unverifiable(&manifest.display())),
            "{refused:?}"
        );
    }
}
