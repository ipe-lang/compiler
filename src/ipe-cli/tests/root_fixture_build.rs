//! `ipe::build_fixture` emits a project reached through the typed project root.

use std::path::PathBuf;

use ipe::project_root::SourceTree;
use ipe::{CliError, RootFixture, build_fixture};

const MAIN: &str =
    "module Main exposing (main)\n\nimport Ipe.Io\n\nmain =\n    Io.println \"ok\"\n";

const MULTI_MAIN: &str = "module Main exposing (main)\n\nimport Ipe.Io\nimport Lib\n\nmain =\n    Io.println Lib.greeting\n";

const LIB: &str = "module Lib exposing (greeting)\n\ngreeting : String\ngreeting =\n    \"ok\"\n";

fn out_dir(tag: &str) -> PathBuf {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("root_fixture_{tag}"));
    let _ = std::fs::remove_dir_all(&out);
    out
}

#[test]
fn a_fixture_builds_under_the_default_package_name() {
    let fixture = RootFixture::main(MAIN).expect("a project with a Main module resolves");
    let out = out_dir("default");
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = build_fixture(&fixture, &out, &runtime).expect("the fixture builds");
    let dir = fixture
        .path()
        .canonicalize()
        .expect("canonical fixture dir");
    let identity = ipe_backend_rust::crate_identity(ipe::project_root::DEFAULT_NAME, &dir);
    assert!(identity.starts_with("ipe-app_"), "{identity}");
    assert_eq!(
        built
            .crate_name()
            .expect("the emitted manifest names its crate"),
        identity,
        "the crate is named by the fixture's package name and directory"
    );
    let profile = out.join("target").join("debug");
    assert_eq!(
        built.binary_in(&profile).expect("the binary is located"),
        profile.join(format!("{identity}{}", std::env::consts::EXE_SUFFIX))
    );
    assert!(out.join("src/main.rs").is_file());
}

#[test]
fn a_multi_module_fixture_builds_through_its_manifest() {
    let tree = SourceTree::main(MULTI_MAIN).module("Lib", LIB);
    let fixture = RootFixture::from_tree(&tree).expect("a two-module project resolves");
    let out = out_dir("multi");
    let runtime = e2e_support::require_runtime().into_path_buf();
    build_fixture(&fixture, &out, &runtime).expect("the fixture builds");
    assert!(out.join("src/main.rs").is_file());
    assert!(out.join("src/ipe_mods/ipe_mod_lib.rs").is_file());
}

#[test]
fn a_project_the_resolver_refuses_has_no_fixture_to_build() {
    let err = RootFixture::from_tree(&SourceTree::new()).expect_err("no entry module");
    assert!(matches!(err, CliError::NoDefaultEntry { .. }), "{err}");
}
