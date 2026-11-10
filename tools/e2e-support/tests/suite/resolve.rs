//! Refusal paths of the test-artifact resolvers.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Command;

use e2e_support::bin::{ResolveError, Source, in_repo_runtime_src, parse_tier, resolve_bin};
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
    assert!(
        matches!(got, Err(ResolveError::Missing { .. })),
        "a tree whose crate holds no Cargo.toml is not the runtime: {got:?}"
    );
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
