//! Every build path emits with the settings its project declares.
//!
//! A split (multi-home) project, a dependency-model desktop build and a shared
//! build cache each once dropped a setting the single-file emit applied: the
//! debugger codec, the desktop window title, or the per-project crate identity.
//! Each test here builds the way production does and reads the emitted text.

use std::error::Error;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

type BoxError = Box<dyn Error>;

/// A console program whose `main` sits in `Main` and whose view text sits in
/// `Lib`, so the program has two homes and is emitted split.
const CLI_MAIN: &str = r"module Main exposing (main)

import Lib exposing (label)
import Ipe.Tea.Cli as Cli
import Ipe.Tea.Cli.Cmd
import Ipe.Tea.Cli.Sub
import Ipe.Ui.Cli as Ui
import Ipe.Ui.Cli exposing (Lines)

type Msg = Line String

type alias Model = { lines : List String }

init : () -> ( Model, Cmd Msg )
init _unit =
    ( { lines = [] }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( model, Cmd.none )

view : Model -> Lines Msg
view _model =
    Ui.text label

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.onLine Line

main =
    Cli.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
        }
";

const LIB: &str = "module Lib exposing (label)\n\nlabel : String\nlabel = \"ok\"\n";

/// A minimal `Web.tea` program.
const WEB_MAIN: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub

type Msg
    = Increment

type alias Model =
    { count : Int }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( { model | count = model.count + 1 }, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.el [ Ui.onClick Increment ] (Ui.text "+")

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = Increment
        }
"#;

/// The package name every fixture here is given.
const NAME: &str = "settings-app";

/// The ceilings a spawned `ipe` runs under: a wedged or flooding child is
/// killed rather than hanging the suite.
const BOUNDS: e2e_support::BoundedRun = e2e_support::BoundedRun {
    max_total: std::time::Duration::from_mins(20),
    idle_window: std::time::Duration::from_mins(10),
    out_cap: 64 * 1024 * 1024,
};

/// A fresh scratch directory for `test_name`, removed first if present.
fn scratch(test_name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("emit_settings_{test_name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The split console project, named [`NAME`].
fn split_tree() -> ipe::project_root::SourceTree {
    ipe::project_root::SourceTree::main(CLI_MAIN)
        .named(NAME)
        .module("Lib", LIB)
}

/// The crate identity the build derives for a project named [`NAME`] at `dir`.
fn identity_of(dir: &Path) -> Result<String, BoxError> {
    let canonical = std::fs::canonicalize(dir)?;
    Ok(
        ipe_backend_rust::crate_identity(&ipe_backend_rust::sanitize_cargo_name(NAME), &canonical)
            .as_str()
            .to_owned(),
    )
}

/// The `[package] name` line of the emitted `Cargo.toml` under `out`.
fn package_name_line(out: &Path) -> Result<String, BoxError> {
    let cargo = std::fs::read_to_string(out.join("Cargo.toml"))?;
    cargo
        .lines()
        .find(|line| line.starts_with("name = "))
        .map(str::to_owned)
        .ok_or_else(|| -> BoxError { format!("{}: no package name", out.display()).into() })
}

/// The number of emitted-project cache entries under `cache`.
fn cache_entries(cache: &Path) -> usize {
    let mut count = 0;
    let mut work = vec![cache.to_path_buf()];
    while let Some(dir) = work.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                work.push(path);
            } else if path.to_string_lossy().ends_with(".json")
                && !path.to_string_lossy().ends_with(".ir.json")
            {
                count += 1;
            }
        }
    }
    count
}

/// The emitted program under `out`: `src/main.rs` and every module file, since
/// `ipe_main` sits in the entry's module file when the program has more than
/// one home.
fn program_text(out: &Path) -> Result<String, BoxError> {
    let mut text = std::fs::read_to_string(out.join("src/main.rs"))?;
    if let Ok(mods) = std::fs::read_dir(out.join("src/ipe_mods")) {
        for entry in mods {
            text.push_str(&std::fs::read_to_string(entry?.path())?);
        }
    }
    Ok(text)
}

/// Run the `ipe` binary with `args`, returning its stderr on a failed exit.
fn run_ipe(args: &[&OsStr], envs: &[(&str, &OsStr)]) -> Result<(), BoxError> {
    let mut cmd = std::process::Command::new(e2e_support::cargo_bin!("ipe").into_path_buf());
    cmd.args(args)
        .env(
            "IPE_RUNTIME_DIR",
            e2e_support::require_runtime().into_path_buf(),
        )
        .env("NO_COLOR", "1")
        .env_remove("IPE_BUILD_CACHE")
        .stdin(std::process::Stdio::null());
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let out = e2e_support::run_bounded(cmd, BOUNDS)?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "ipe {args:?} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
        .into())
    }
}

/// A split console project built by `ipe dev build --debugger` passes the
/// session codec to every `console_app` call, so the crate builds under cargo
/// with the runtime's `debugger` feature.
#[test]
fn split_debugger_builds() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let fixture = ipe::RootFixture::from_tree(&split_tree())?;
    let out = scratch("split_debugger_builds");
    run_ipe(
        &[
            OsStr::new("dev"),
            OsStr::new("build"),
            fixture.manifest_path().as_os_str(),
            OsStr::new("--out"),
            out.as_os_str(),
            OsStr::new("--debugger"),
        ],
        &[],
    )?;
    let _ = std::fs::remove_dir_all(&out);
    Ok(())
}

/// A dependency-model build of a project with a `delivery.desktop` window,
/// asked for the host a resolved `web desktop` delivery names, emits the
/// webview app titled and sized by that window.
#[test]
fn cold_desktop_title() -> Result<(), BoxError> {
    let tree = ipe::project_root::SourceTree::main(WEB_MAIN)
        .named(NAME)
        .field("delivery = { desktop = { title = \"Cold\", width = 500, height = 350 } }");
    let fixture = ipe::RootFixture::from_tree(&tree)?;
    let host = ipe::delivery::Delivery::resolve(
        ipe::delivery::Shape::Web,
        None,
        ipe::delivery::Host::Desktop,
    )
    .map(ipe::delivery::Delivery::host_intent)
    .map_err(|e| -> BoxError { format!("web desktop does not resolve: {e}").into() })?;
    let out = scratch("cold_desktop_title");
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build_fixture_for(
        &fixture,
        &out,
        &runtime,
        &ipe::BuildOptions::default(),
        host,
    )?;
    let program = program_text(&out)?;
    let _ = std::fs::remove_dir_all(&out);
    assert!(
        program.contains(
            "ipe_runtime::webview::WebViewWindowCfg { title: \"Cold\".to_string(), size: (500, 350) }"
        ),
        "the emit does not carry the manifest's desktop window"
    );
    Ok(())
}

/// A split project's emitted crate is named by the project's identity, the
/// name the build derives from the package name and the canonical directory.
#[test]
fn split_name_is_identity() -> Result<(), BoxError> {
    let fixture = ipe::RootFixture::from_tree(&split_tree())?;
    let out = scratch("split_name_is_identity");
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built =
        ipe::build_fixture_with_options(&fixture, &out, &runtime, &ipe::BuildOptions::default())?;
    let name = built.crate_name()?;
    let _ = std::fs::remove_dir_all(&out);
    assert_eq!(name, identity_of(fixture.path())?);
    Ok(())
}

/// Two copies of one project, ejected through one shared build cache, each
/// emit their own crate identity: the second is a cache miss, never the first
/// copy's entry under the wrong name.
#[test]
fn shared_cache_keeps_identity() -> Result<(), BoxError> {
    let first = ipe::RootFixture::from_tree(&split_tree())?;
    let second = ipe::RootFixture::from_tree(&split_tree())?;
    let base = scratch("shared_cache_keeps_identity");
    let cache = base.join("cache");
    std::fs::create_dir_all(&cache)?;
    let envs: [(&str, &OsStr); 2] = [
        ("IPE_RUNTIME_VENDORED", OsStr::new("1")),
        ("IPE_BUILD_CACHE_DIR", cache.as_os_str()),
    ];
    let mut names = Vec::new();
    for (index, fixture) in [&first, &second].into_iter().enumerate() {
        let out = base.join(format!("eject{index}"));
        run_ipe(
            &[
                OsStr::new("release"),
                OsStr::new("eject"),
                fixture.manifest_path().as_os_str(),
                OsStr::new("--out"),
                out.as_os_str(),
            ],
            &envs,
        )?;
        names.push((package_name_line(&out)?, identity_of(fixture.path())?));
    }
    let entries = cache_entries(&cache);
    let _ = std::fs::remove_dir_all(&base);
    for (line, identity) in &names {
        assert_eq!(line, &format!("name = \"{identity}\""));
    }
    assert_ne!(names.first(), names.get(1), "two copies share one identity");
    assert_eq!(entries, 2, "the second copy reused the first copy's entry");
    Ok(())
}
