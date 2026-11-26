//! THE SEAL for an installed crate's module slug.
//!
//! A crate's `_bindings.rs` module is named by its slug, the fold of its
//! package name, while its Rust calls name its lib identifier. The default gate
//! proves a crate whose fold is escaped (`Match` folds to the keyword-escaped
//! `match_`) emits under that slug and is called by its lib identifier; the
//! refusal tests prove two crates folding to one slug are refused with
//! IPE-F4416, the first kept, and that a package spelling the reserved
//! asserted-shim namespace is refused before anything is cached. Under
//! `IPE_E2E=1` the emitted crate builds against the real `Match` crate and runs.
//!
//! ```text
//! cargo test -p ipe --test g_misc golden_ffi_slug_seal
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use ipe::RootFixture;
use ipe::project_root::SourceTree;
use ipe_ffi::driver::{FfiCache, install_from_inspection};

/// An inspection document for package `name` with one free function `f: i64 -> i64`.
fn inspection(name: &str) -> String {
    serde_json::json!({
        "pkg": name,
        "name": name,
        "version": "0.1.0",
        "functions": [{
            "name": "f",
            "params": [{"name": "n", "type": "Int", "ipeType": "Int", "rustType": "i64"}],
            "results": [{"name": "", "type": "Int", "rustType": "i64"}],
            "effect": "pure"
        }],
        "errors": [],
        "transitiveDeps": [{"ident": name, "name": name, "version": "0.1.0"}]
    })
    .to_string()
}

/// The program calling `Match`'s `f` through its lib identifier.
const MAIN_IPE: &str = "module Main exposing (main)\n\
    import Ipe.Io as Io\n\
    import Ipe.String as String\n\
    import Ipe.Ffi.Rust as Rust\n\n\
    bumped : Int -> Result Error Int\n\
    bumped =\n\
    \x20   Rust.fn \"Match\" \"f\"\n\n\
    main =\n\
    \x20   case bumped 41 of\n\
    \x20       Ok n -> Io.println (\"bumped \" ++ String.fromInt n)\n\
    \x20       Err _ -> Io.println \"err\"\n";

/// A project declaring `Match`, its FFI cache seeded with `Match`'s inspection.
#[allow(clippy::expect_used)] // test fixture: a failed write IS the failure
fn match_fixture() -> RootFixture {
    let fixture = RootFixture::from_tree(
        &SourceTree::main(MAIN_IPE).field("rustDependencies = [ rustDep \"Match\" \"=0.1.0\" ]"),
    )
    .expect("the fixture project must be written and resolved");
    let cache = FfiCache::at_project_root(fixture.path());
    install_from_inspection(&cache, &inspection("Match")).expect("`Match` installs");
    fixture
}

/// The cached file names under the project's FFI cache.
fn cached_names(project_root: &Path) -> Vec<String> {
    let dir = project_root.join(ipe_ffi::driver::FFI_CACHE_REL);
    fs::read_dir(dir).map_or_else(
        |_| Vec::new(),
        |entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        },
    )
}

/// `Match` folds to the escaped slug `match_`: its bindings module is `match_`,
/// and its asserted call names the lib identifier `Match`, never the slug.
#[test]
#[allow(clippy::expect_used)] // test fixture: a failed build or read IS the failure
fn an_escaped_slug_names_the_module_and_the_lib_ident_names_the_call() {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let fixture = match_fixture();
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_slug_seal_out");
    e2e_support::scratch::fresh(&out);
    let built = ipe::build_fixture(&fixture, &out, &runtime);
    assert!(built.is_ok(), "the `Match` fixture must build: {built:?}");

    let ffi_rs = fs::read_to_string(out.join("src/ffi.rs")).expect("emitted src/ffi.rs");
    assert!(
        ffi_rs.contains("pub mod match_ {"),
        "the bindings module is the escaped slug:\n{ffi_rs}"
    );
    assert!(
        ffi_rs.contains("::Match::f(arg0)"),
        "the asserted shim calls the lib identifier:\n{ffi_rs}"
    );
    assert!(
        !ffi_rs.contains("::match_::"),
        "no call names the slug as a crate:\n{ffi_rs}"
    );

    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_ffi_slug_seal_e2e");
    e2e_support::scratch::fresh(&tmp);
    let crate_dir = tmp.join("Match");
    fs::create_dir_all(crate_dir.join("src")).expect("mkdir Match");
    fs::write(
        crate_dir.join("Cargo.toml"),
        "[package]\nname = \"Match\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("Match Cargo.toml");
    fs::write(
        crate_dir.join("src/lib.rs"),
        "pub fn f(n: i64) -> i64 { n + 1 }\n",
    )
    .expect("Match lib.rs");
    let manifest_path = out.join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path).expect("emitted Cargo.toml");
    assert!(
        manifest.contains("Match = \"=0.1.0\""),
        "the emitted manifest pins `Match`:\n{manifest}"
    );
    let patched = manifest.replace(
        "Match = \"=0.1.0\"",
        &format!("Match = {{ path = {:?} }}", crate_dir.display().to_string()),
    );
    fs::write(&manifest_path, patched).expect("patched Cargo.toml");

    let ran = e2e_support::build_and_run_rust("ffi_slug_seal", &out);
    assert!(
        ran.is_ok(),
        "{}",
        ran.as_ref().err().map_or("", String::as_str)
    );
    let run = ran.expect("asserted Ok above");
    assert_eq!(run.exit_code, Some(0), "stdout: {}", run.stdout);
    assert!(run.stdout.contains("bumped 42"), "stdout: {}", run.stdout);
    let _ = fs::remove_dir_all(&tmp);
}

/// `a-b` and `a_b` both fold to `a_b`: the second install is refused with
/// IPE-F4416 naming both, and the first stays the slug's occupant.
#[test]
#[allow(clippy::expect_used)] // test fixture: a failed write IS the failure
fn a_second_crate_on_a_held_slug_is_refused_and_the_first_kept() {
    let fixture = RootFixture::main(MAIN_IPE).expect("the fixture project resolves");
    let cache = FfiCache::at_project_root(fixture.path());
    install_from_inspection(&cache, &inspection("a-b")).expect("`a-b` installs");
    let second = install_from_inspection(&cache, &inspection("a_b"));
    let text = second
        .as_ref()
        .err()
        .map(ToString::to_string)
        .unwrap_or_default();
    assert!(
        text.contains("IPE-F4416") && text.contains("a-b") && text.contains("a_b"),
        "the second crate on one slug is refused with IPE-F4416: {second:?}"
    );
    let loaded =
        ipe_ffi::driver::load_catalog(&fixture.path().join(ipe_ffi::driver::FFI_CACHE_REL))
            .expect("the catalog loads");
    let occupants: Vec<String> = loaded
        .iter()
        .filter_map(|c| c.package_name.as_ref().map(|n| n.as_str().to_owned()))
        .collect();
    assert_eq!(occupants, ["a-b"], "the first crate stays the occupant");
}

/// A package spelling the reserved asserted-shim namespace is refused before
/// any artifact is cached.
#[test]
#[allow(clippy::expect_used)] // test fixture: a failed write IS the failure
fn a_package_in_the_asserted_shim_namespace_is_refused_before_caching() {
    let fixture = RootFixture::main(MAIN_IPE).expect("the fixture project resolves");
    let cache = FfiCache::at_project_root(fixture.path());
    let refused = install_from_inspection(&cache, &inspection("ipe-asserted-x"));
    assert!(
        refused.is_err(),
        "the reserved namespace is refused: {refused:?}"
    );
    let cached = cached_names(fixture.path());
    assert!(
        cached.iter().all(|name| !name.starts_with("ipe_asserted")),
        "nothing is cached under the reserved namespace: {cached:?}"
    );
}
