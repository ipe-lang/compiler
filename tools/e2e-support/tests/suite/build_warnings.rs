//! The emitted-build warning refusal, proven on a real `cargo build`.
//!
//! A stand-in runtime crate (package `ipe-runtime-rust`) carries one dead `fn`
//! under the feature the stand-in app selects, so the warning exists only in
//! the emitted feature set. The checked build must refuse it, naming the dead
//! `fn`; the same pair without the dead `fn` must build, so the refusal comes
//! from the warning and not from an earlier exit.

use std::path::{Path, PathBuf};

use e2e_support::target::{BuildTarget, IsolationReason, isolated};
use e2e_support::{Tier, build_project_checked, e2e_tier};

/// The stand-in app's package name.
const APP: &str = "ipe-app-warning-probe";

/// The stand-in runtime's library: a dead `fn` under the emitted feature
/// `json` when `dead` is set.
fn runtime_lib(dead: bool) -> String {
    let dead_fn = if dead {
        "#[cfg(feature = \"json\")]\nfn dead_under_json() {}\n"
    } else {
        ""
    };
    format!("{dead_fn}pub fn greeting() -> &'static str {{ \"hi\" }}\n")
}

/// Write the stand-in runtime and app under `root`, returning the app dir.
#[allow(clippy::expect_used)] // unwritable test scratch is an environment failure, not a case under test
fn write_pair(root: &Path, dead: bool) -> PathBuf {
    let _ = std::fs::remove_dir_all(root);
    let runtime = root.join("runtime");
    let app = root.join("app");
    std::fs::create_dir_all(runtime.join("src")).expect("create the runtime dir");
    std::fs::create_dir_all(app.join("src")).expect("create the app dir");
    std::fs::write(
        runtime.join("Cargo.toml"),
        "[package]\nname = \"ipe-runtime-rust\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\
         publish = false\n\n[features]\njson = []\n",
    )
    .expect("write the runtime manifest");
    std::fs::write(runtime.join("src/lib.rs"), runtime_lib(dead)).expect("write the runtime lib");
    std::fs::write(
        app.join("Cargo.toml"),
        format!(
            "[package]\nname = \"{APP}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\
             publish = false\n\n[workspace]\n\n[dependencies]\n\
             ipe-runtime-rust = {{ path = \"../runtime\", features = [\"json\"] }}\n"
        ),
    )
    .expect("write the app manifest");
    std::fs::write(
        app.join("src/main.rs"),
        "fn main() { println!(\"{}\", ipe_runtime_rust::greeting()); }\n",
    )
    .expect("write the app main");
    app
}

/// Build the stand-in pair, with or without the dead `fn`, in a private tree.
#[allow(clippy::expect_used)] // an unavailable build tree is an environment failure, not a case under test
fn build_pair(tag: &str, dead: bool) -> Result<(), String> {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("build-warnings-{tag}"));
    let app = write_pair(&root, dead);
    let tree = isolated(IsolationReason::ColdBuildUnderTest).expect("a private build tree");
    build_project_checked(tag, &app, &BuildTarget::Isolated(tree), APP)
}

#[test]
fn a_runtime_warning_under_an_emitted_feature_fails_the_build() {
    if e2e_tier() == Tier::Unit {
        return;
    }
    let got = build_pair("dead-fn", true);
    assert!(
        matches!(&got, Err(msg) if msg.contains("without warnings")
            && msg.contains("dead_under_json")
            && msg.contains("ipe-runtime-rust")),
        "a dead runtime fn under the emitted feature must fail the build: {got:?}"
    );
}

#[test]
fn the_same_pair_without_the_dead_fn_builds() {
    if e2e_tier() == Tier::Unit {
        return;
    }
    let got = build_pair("clean", false);
    assert_eq!(got, Ok(()));
}
