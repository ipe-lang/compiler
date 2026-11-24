use std::ffi::OsStr;
#[cfg(unix)] // only `scratch`, unix-only below, returns a `PathBuf`
use std::path::PathBuf;

use super::*;

/// A fresh, empty scratch directory unique to `name`, this process and this thread.
#[cfg(unix)] // every caller lives in the unix-only `mod unix` below
fn scratch(name: &str) -> PathBuf {
    let base = ipe_test_temp::temp_root()
        .canonicalize()
        .expect("canonical temp dir");
    let dir = base.join(format!(
        "ipe-proven-dir-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// The entry name `text`, which the test knows to be one plain component.
#[cfg(unix)] // every caller lives in the unix-only `mod unix` below
fn name(text: &str) -> EntryName {
    EntryName::new(OsStr::new(text)).expect("a plain component")
}

#[test]
fn only_a_single_plain_component_is_an_entry_name() {
    assert!(EntryName::new(OsStr::new("token")).is_some());
    assert!(EntryName::new(OsStr::new(".token.1.ab.tmp")).is_some());
    for refused in ["", ".", "..", "a/b", "/", "a\0b"] {
        assert!(
            EntryName::new(OsStr::new(refused)).is_none(),
            "{refused:?} must not be an entry name"
        );
    }
}

#[cfg(not(unix))]
#[test]
fn a_host_without_unix_ownership_proves_no_directory() {
    let dir = ipe_test_temp::temp_root();
    assert!(matches!(
        ProvenDir::open(&dir),
        Err(ProvenDirError::Unsupported)
    ));
    assert!(matches!(
        ProvenDir::create(&dir.join("ipe-proven-dir-unsupported")),
        Err(ProvenDirError::Unsupported)
    ));
    assert!(
        !dir.join("ipe-proven-dir-unsupported").exists(),
        "a refusal creates nothing"
    );
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use super::*;

    /// Set the permission bits of `path` to `mode`.
    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    /// The permission bits of `path`, file type excluded.
    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o7777
    }

    #[test]
    fn a_created_dir_is_0700_and_a_file_inside_it_is_0600() {
        let base = scratch("happy");
        let path = base.join("a").join("b");
        let dir = ProvenDir::create(&path);
        assert!(dir.is_ok(), "a fresh dir must be proven: {dir:?}");
        let Ok(dir) = dir else { return };
        assert_eq!(dir.path(), path);
        assert_eq!(mode_of(&path), 0o700, "a created dir must be 0700");
        assert_eq!(
            mode_of(&base.join("a")),
            0o700,
            "a created parent must be 0700"
        );
        let created = dir.create_file(&name("secret"), NewFileMode::OwnerOnly);
        assert!(created.is_ok(), "create inside the proven dir: {created:?}");
        assert_eq!(mode_of(&path.join("secret")), 0o600);
        assert!(ProvenDir::open(&path).is_ok(), "the dir reopens");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn an_existing_entry_is_refused_by_the_exclusive_create() {
        let base = scratch("excl");
        std::fs::write(base.join("secret"), "kept").expect("seed");
        let dir = ProvenDir::open(&base).expect("the scratch dir is proven");
        let created = dir.create_file(&name("secret"), NewFileMode::OwnerOnly);
        assert!(
            matches!(&created, Err(e) if e.kind() == io::ErrorKind::AlreadyExists),
            "an existing name must be refused, got {created:?}"
        );
        assert_eq!(
            std::fs::read_to_string(base.join("secret")).expect("read"),
            "kept"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_symlink_at_the_final_component_is_refused() {
        let base = scratch("leaf-link");
        let real = base.join("real");
        std::fs::create_dir(&real).expect("mkdir");
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        for walked in [ProvenDir::open(&link), ProvenDir::create(&link)] {
            assert!(
                matches!(&walked, Err(ProvenDirError::SymlinkLeaf(p)) if *p == link),
                "a final symlink must be refused, got {walked:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_symlinked_ancestor_into_an_untrusted_dir_is_refused() {
        let base = scratch("ancestor-link");
        let exposed = base.join("exposed");
        std::fs::create_dir_all(exposed.join("inner")).expect("mkdir");
        chmod(&exposed, 0o777);
        let link = base.join("link");
        std::os::unix::fs::symlink(&exposed, &link).expect("symlink");
        let walked = ProvenDir::create(&link.join("inner"));
        assert!(
            matches!(
                &walked,
                Err(ProvenDirError::Untrusted { path, breach: Breach::WorldWritable }) if *path == exposed
            ),
            "a link must not lead the walk past an untrusted target, got {walked:?}"
        );
        chmod(&exposed, 0o700);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_symlinked_ancestor_the_invoker_owns_is_walked_to_its_proven_target() {
        let base = scratch("ancestor-link-ok");
        let real = base.join("real");
        std::fs::create_dir_all(real.join("inner")).expect("mkdir");
        let link = base.join("link");
        std::os::unix::fs::symlink("real", &link).expect("relative symlink");
        let walked = ProvenDir::open(&link.join("inner"));
        assert!(walked.is_ok(), "an owned link to a proven dir: {walked:?}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_world_writable_ancestor_without_the_sticky_bit_is_refused() {
        let base = scratch("world-writable");
        let shared = base.join("shared");
        std::fs::create_dir_all(shared.join("mine")).expect("mkdir");
        chmod(&shared, 0o777);
        let walked = ProvenDir::open(&shared.join("mine"));
        assert!(
            matches!(
                &walked,
                Err(ProvenDirError::Untrusted { path, breach: Breach::WorldWritable }) if *path == shared
            ),
            "a world-writable ancestor must be refused, got {walked:?}"
        );
        assert!(
            !shared.join("mine").join("new").exists(),
            "the refusal creates nothing below it"
        );
        chmod(&shared, 0o700);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_sticky_world_writable_ancestor_is_admitted() {
        let base = scratch("sticky");
        let shared = base.join("shared");
        std::fs::create_dir_all(shared.join("mine")).expect("mkdir");
        chmod(&shared, 0o1777);
        let walked = ProvenDir::open(&shared.join("mine"));
        assert!(
            walked.is_ok(),
            "a sticky shared ancestor passes: {walked:?}"
        );
        chmod(&shared, 0o700);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_foreign_owned_ancestor_is_refused_by_the_ancestor_rule() {
        use crate::owner_trust::{Invoker, Stamp, container_breach};
        let me = Invoker::current();
        let foreign = Stamp {
            uid: me.uid.wrapping_add(1),
            gid: me.gid,
            mode: 0o040_755,
        };
        assert_eq!(container_breach(foreign, me), Some(Breach::ForeignOwner));
        let foreign_sticky = Stamp {
            mode: 0o041_777,
            ..foreign
        };
        assert_eq!(
            container_breach(foreign_sticky, me),
            Some(Breach::ForeignOwner),
            "the sticky bit never excuses a foreign owner"
        );
    }

    #[test]
    fn a_world_writable_final_dir_is_refused() {
        let base = scratch("leaf-writable");
        let exposed = base.join("exposed");
        std::fs::create_dir(&exposed).expect("mkdir");
        chmod(&exposed, 0o1777);
        let walked = ProvenDir::open(&exposed);
        assert!(
            matches!(
                &walked,
                Err(ProvenDirError::Untrusted { path, breach: Breach::WorldWritable }) if *path == exposed
            ),
            "the final dir must be the invoker's alone, got {walked:?}"
        );
        chmod(&exposed, 0o700);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_relative_absent_or_non_directory_path_is_refused() {
        let base = scratch("refusals");
        std::fs::write(base.join("file"), "x").expect("seed");
        assert!(matches!(
            ProvenDir::create(Path::new("relative/dir")),
            Err(ProvenDirError::NotAbsolute(_))
        ));
        let absent = base.join("absent");
        assert!(matches!(
            ProvenDir::open(&absent),
            Err(ProvenDirError::Absent(p)) if p == absent
        ));
        assert!(!absent.exists(), "an open walk creates nothing");
        let file = base.join("file");
        assert!(matches!(
            ProvenDir::create(&file.join("sub")),
            Err(ProvenDirError::NotADirectory(p)) if p == file
        ));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_link_another_user_owns_is_refused_and_never_followed() {
        let me = crate::owner_trust::Invoker {
            uid: 1000,
            gid: 1000,
        };
        assert_eq!(link_step(1001, me, false), LinkStep::RefuseUntrusted);
        assert_eq!(link_step(1001, me, true), LinkStep::RefuseLeaf);
        assert_eq!(link_step(1000, me, false), LinkStep::Follow);
        assert_eq!(link_step(0, me, false), LinkStep::Follow);
        assert_eq!(link_step(1000, me, true), LinkStep::RefuseLeaf);
    }

    #[test]
    fn a_path_deeper_than_the_depth_limit_is_refused() {
        let base = scratch("too-deep");
        let deep = (0..=MAX_DEPTH).fold(base.clone(), |path, _| path.join("d"));
        let walked = ProvenDir::create(&deep);
        assert!(
            matches!(walked, Err(ProvenDirError::TooDeep(_))),
            "a walk past the depth limit must be refused, got {walked:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_link_cycle_is_refused_after_the_hop_limit() {
        let base = scratch("cycle");
        std::os::unix::fs::symlink("two", base.join("one")).expect("symlink");
        std::os::unix::fs::symlink("one", base.join("two")).expect("symlink");
        let walked = ProvenDir::open(&base.join("one").join("x"));
        assert!(
            matches!(walked, Err(ProvenDirError::TooManyLinks(_))),
            "a link cycle must be refused, got {walked:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn entries_are_renamed_linked_and_removed_through_the_handle() {
        let base = scratch("entries");
        let dir = ProvenDir::open(&base).expect("the scratch dir is proven");
        let created = dir.create_file(&name("a"), NewFileMode::WorldReadable);
        assert!(created.is_ok(), "{created:?}");
        assert_eq!(
            mode_of(&base.join("a")) & 0o022,
            0,
            "never group/world-writable"
        );
        assert!(matches!(dir.is_vacant(&name("b")), Ok(true)));
        assert!(dir.rename(&name("a"), &name("b")).is_ok());
        assert!(matches!(dir.is_vacant(&name("a")), Ok(true)));
        assert!(dir.hard_link(&name("b"), &name("c")).is_ok());
        assert!(
            dir.hard_link(&name("b"), &name("c")).is_err(),
            "a link never replaces an existing name"
        );
        assert!(dir.open_file(&name("c")).is_ok());
        assert!(dir.remove_file(&name("b")).is_ok());
        assert!(matches!(dir.is_vacant(&name("b")), Ok(true)));
        assert_eq!(dir.path_of(&name("c")), base.join("c"));
        let _ = std::fs::remove_dir_all(&base);
    }
}
