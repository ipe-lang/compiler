//! Refusal paths of the test-artifact resolvers.

use std::ffi::OsStr;
use std::path::PathBuf;

use e2e_support::Tier;
use e2e_support::bin::{ResolveError, Source, parse_tier, resolve_bin, resolve_runtime_src};

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
fn a_runtime_override_naming_a_missing_dir_fails() {
    let root = scratch("runtime-override");
    std::fs::create_dir_all(root.join("src/runtime/rust/src")).unwrap();
    let missing = root.join("absent");
    let got = resolve_runtime_src(Some(missing.clone().into_os_string()), &root);
    assert_eq!(
        got,
        Err(ResolveError::Missing {
            name: "ipe runtime",
            tried: vec![(Source::RuntimeEnv("IPE_RUNTIME_DIR"), missing)],
        })
    );
}

#[test]
fn a_walk_with_no_runtime_tree_fails() {
    let root = scratch("no-runtime");
    let got = resolve_runtime_src(None, &root);
    assert!(
        matches!(got, Err(ResolveError::Missing { .. })),
        "a walk above a scratch dir must find no runtime tree: {got:?}"
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
