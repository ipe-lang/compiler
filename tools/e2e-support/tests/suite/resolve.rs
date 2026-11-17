//! Refusal paths of the test-artifact resolvers.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Command;

use e2e_support::bin::{
    RUNTIME_LOOKUP_CEILING, ResolveError, RuntimeLookupError, Source, in_repo_runtime_src,
    parse_tier, resolve_bin,
};
use e2e_support::{Tier, require_runtime};

#[allow(clippy::expect_used)] // unwritable test scratch is an environment failure, not a case under test
fn scratch(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("resolve-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create test scratch dir");
    dir
}

#[test]
fn a_missing_runtime_and_baked_path_lists_both_sources() {
    let root = scratch("missing");
    let runtime = root.join("runtime-ipe");
    let baked = root.join("baked-ipe");
    let got = resolve_bin("ipe", Some(runtime.clone().into_os_string()), &baked);
    assert_eq!(
        got,
        Err(ResolveError::Missing {
            name: "ipe",
            tried: vec![
                (Source::NextestRuntime, runtime),
                (Source::CompileTimeBaked, baked),
            ],
        })
    );
}

#[test]
fn an_empty_runtime_value_counts_as_absent() {
    let root = scratch("empty");
    let baked = root.join("baked-ipe");
    let got = resolve_bin("ipe", Some(OsStr::new("").to_os_string()), &baked);
    assert_eq!(
        got,
        Err(ResolveError::Missing {
            name: "ipe",
            tried: vec![(Source::CompileTimeBaked, baked)],
        })
    );
}

#[test]
fn a_directory_is_not_a_file() {
    let root = scratch("dir");
    let got = resolve_bin("ipe", Some(root.clone().into_os_string()), &root.join("x"));
    assert_eq!(
        got,
        Err(ResolveError::NotAFile {
            name: "ipe",
            path: root,
        })
    );
}

#[cfg(unix)]
#[test]
fn a_dangling_symlink_is_not_a_file() {
    let root = scratch("dangling");
    let link = root.join("ipe");
    std::os::unix::fs::symlink(root.join("gone"), &link).unwrap();
    let got = resolve_bin("ipe", None, &link);
    assert_eq!(
        got,
        Err(ResolveError::NotAFile {
            name: "ipe",
            path: link,
        })
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_to_a_file_is_not_a_file() {
    let root = scratch("symlink-file");
    let real = root.join("real");
    std::fs::write(&real, b"").unwrap();
    let link = root.join("ipe");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let got = resolve_bin("ipe", Some(link.clone().into_os_string()), &real);
    assert_eq!(
        got,
        Err(ResolveError::NotAFile {
            name: "ipe",
            path: link,
        })
    );
}

#[test]
fn the_runtime_path_wins_over_a_valid_baked_path() {
    let root = scratch("wins");
    let runtime = root.join("runtime-ipe");
    let baked = root.join("baked-ipe");
    std::fs::write(&runtime, b"").unwrap();
    std::fs::write(&baked, b"").unwrap();
    let got = resolve_bin("ipe", Some(runtime.clone().into_os_string()), &baked).unwrap();
    assert_eq!(got.path(), runtime.as_path());
}

#[test]
fn an_absent_runtime_path_falls_back_to_the_baked_one() {
    let root = scratch("fallback");
    let baked = root.join("baked-ipe");
    std::fs::write(&baked, b"").unwrap();
    let got = resolve_bin("ipe", Some(root.join("gone").into_os_string()), &baked).unwrap();
    assert_eq!(got.path(), baked.as_path());
}

#[test]
fn a_runtime_tree_without_its_crate_manifest_is_not_taken() {
    let root = outside_scratch("no-manifest");
    std::fs::create_dir_all(root.join("src/runtime/rust/src")).unwrap();
    let got = in_repo_runtime_src(&root);
    assert_eq!(
        got,
        Err(RuntimeLookupError::Missing { anchor: root }),
        "a tree whose crate holds no Cargo.toml is not the runtime"
    );
}

/// A checkout root holding the runtime crate (manifest and module tree), outside every checkout.
fn outside_checkout(tag: &str) -> (PathBuf, PathBuf) {
    let root = outside_scratch(tag);
    let tree = root.join("src/runtime/rust/src");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(root.join("src/runtime/rust/Cargo.toml"), b"").unwrap();
    (root, tree)
}

#[test]
fn the_in_repo_tree_is_found_from_a_descendant() {
    let (root, tree) = outside_checkout("walk");
    let deep = root.join("a/b");
    std::fs::create_dir_all(&deep).unwrap();
    let got = in_repo_runtime_src(&deep).unwrap();
    assert_eq!(got.path(), tree.as_path());
    assert_eq!(got.crate_root(), root.join("src/runtime/rust").as_path());
}

/// The lookup visits the anchor and its next ancestors up to the ceiling:
/// a tree the last visited directory holds is found, one a directory
/// further up holds is not.
#[test]
fn the_lookup_stops_at_the_ceiling() {
    let (root, tree) = outside_checkout("ceiling");
    let below = |levels: usize| {
        let dir = (0..levels).fold(root.clone(), |dir, _| dir.join("d"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    };
    let last_visited = below(RUNTIME_LOOKUP_CEILING - 1);
    let past_ceiling = below(RUNTIME_LOOKUP_CEILING);
    assert_eq!(
        in_repo_runtime_src(&last_visited).map(e2e_support::ProvenRuntime::into_path_buf),
        Ok(tree)
    );
    assert_eq!(
        in_repo_runtime_src(&past_ceiling),
        Err(RuntimeLookupError::Missing {
            anchor: past_ceiling
        })
    );
}

/// A symlinked `src/runtime/rust` is refused on the spot, never followed to
/// the crate it names nor passed over for a real tree further up.
#[cfg(unix)]
#[test]
fn a_symlinked_runtime_crate_is_refused() {
    let (outer, _) = outside_checkout("linked-crate");
    let (elsewhere, _) = outside_checkout("linked-crate-target");
    let inner = outer.join("inner");
    std::fs::create_dir_all(inner.join("src/runtime")).unwrap();
    let link = inner.join("src/runtime/rust");
    std::os::unix::fs::symlink(elsewhere.join("src/runtime/rust"), &link).unwrap();
    assert_eq!(
        in_repo_runtime_src(&inner),
        Err(RuntimeLookupError::Linked { path: link })
    );
}

/// A link at any component of the tree (an intermediate directory, the
/// manifest, the module tree) is refused, never followed.
#[cfg(unix)]
#[test]
fn a_link_at_any_tree_component_is_refused() {
    let (target, _) = outside_checkout("linked-part-target");
    for part in [
        "src",
        "src/runtime",
        "src/runtime/rust/Cargo.toml",
        "src/runtime/rust/src",
    ] {
        let (root, _) = outside_checkout(&format!("linked-part-{}", part.replace('/', "-")));
        let link = root.join(part);
        if std::fs::symlink_metadata(&link).unwrap().is_dir() {
            std::fs::remove_dir_all(&link).unwrap();
        } else {
            std::fs::remove_file(&link).unwrap();
        }
        std::os::unix::fs::symlink(target.join(part), &link).unwrap();
        assert_eq!(
            in_repo_runtime_src(&root),
            Err(RuntimeLookupError::Linked { path: link }),
            "{part}"
        );
    }
}

#[test]
fn the_harness_runtime_is_the_checkouts_own_tree() {
    let tree = require_runtime().into_path_buf();
    assert!(
        tree.ends_with("src/runtime/rust/src") && tree.join("../Cargo.toml").is_file(),
        "{}",
        tree.display()
    );
}

/// The line prefix the probe prints its resolved tree under.
const PROBE_PREFIX: &str = "resolved runtime: ";

/// The probe half of the override test: prints the harness runtime, which the
/// parent reads back from a re-spawned run of this binary.
#[test]
fn harness_runtime_probe() {
    println!("{PROBE_PREFIX}{}", require_runtime().path().display());
}

/// A runtime override never reaches the harness: with `IPE_RUNTIME_DIR`
/// naming a directory that holds no runtime, the harness still resolves the
/// checkout's own tree.
#[test]
#[allow(clippy::expect_used)] // an unspawnable test binary is an environment failure, not a case under test
fn the_harness_runtime_ignores_a_runtime_override() {
    let bogus = outside_scratch("override");
    let exe = std::env::current_exe().expect("the running test binary");
    let out = Command::new(exe)
        .args(["--exact", "resolve::harness_runtime_probe", "--nocapture"])
        .env("IPE_RUNTIME_DIR", &bogus)
        .output()
        .expect("re-spawn the test binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let expected = format!("{PROBE_PREFIX}{}", require_runtime().path().display());
    assert!(
        out.status.success() && stdout.lines().any(|line| line == expected),
        "status {:?}; stdout:\n{stdout}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A scratch dir under the OS temp root, outside every checkout.
///
/// `CARGO_TARGET_TMPDIR` lives under the target dir, which defaults to the
/// checkout's own `target/`, so an upward walk from it reaches the checkout's
/// runtime tree; an absence proof must start where no ancestor holds one.
#[allow(clippy::expect_used)] // unwritable test scratch is an environment failure, not a case under test
fn outside_scratch(tag: &str) -> PathBuf {
    let dir = ipe_test_temp::temp_root().join(format!(
        "ipe-e2e-support-resolve-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create test scratch dir");
    dir
}

#[test]
fn a_walk_with_no_runtime_tree_fails() {
    let root = outside_scratch("no-runtime");
    let got = in_repo_runtime_src(&root);
    assert_eq!(
        got,
        Err(RuntimeLookupError::Missing { anchor: root }),
        "a walk above a scratch dir must find no runtime tree"
    );
}

#[test]
fn the_tier_is_unit_when_unset_and_e2e_only_for_one() {
    assert_eq!(parse_tier(None), Ok(Tier::Unit));
    assert_eq!(parse_tier(Some(OsStr::new("1"))), Ok(Tier::E2e));
}

#[test]
fn a_malformed_tier_value_is_refused() {
    for raw in ["", "0", "true", "yes", " 1", "1 "] {
        assert_eq!(
            parse_tier(Some(OsStr::new(raw))),
            Err(OsStr::new(raw).to_os_string()),
            "{raw:?}"
        );
    }
}
