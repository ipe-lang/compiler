//! Tests for the `ipe release build` subcommand — argument parsing and dispatch
//! checks. The full end-to-end release (compile + cargo build + bundle layout)
//! requires the musl target installed and is gated on `IPE_E2E=1`.

mod support;

use ipe::cli_args::{ReleaseMode, StaticTriple, parse_release_build};

// ── Argument parsing ─────────────────────────────────────────────────────────

/// No arguments: entry defaults to None (project-aware default) and the mode
/// is the single self-jailing binary.
#[test]
fn release_no_args_defaults() {
    let args: Vec<String> = vec![];
    let parsed = parse_release_build(&args).expect("no-arg parse must succeed");
    assert!(parsed.entry.is_none());
    assert!(parsed.out.is_none());
    assert_eq!(parsed.target, None);
    assert!(parsed.runtime.is_none());
    assert_eq!(parsed.mode, ReleaseMode::Embed);
}

/// `--embed` is the default single-file mode.
#[test]
fn release_embed_flag() {
    let args: Vec<String> = vec!["--embed".into()];
    let parsed = parse_release_build(&args).expect("--embed parse must succeed");
    assert_eq!(parsed.mode, ReleaseMode::Embed);
}

/// `--bundle` selects the multi-file opt-out.
#[test]
fn release_bundle_flag() {
    let args: Vec<String> = vec!["--bundle".into()];
    let parsed = parse_release_build(&args).expect("--bundle parse must succeed");
    assert_eq!(parsed.mode, ReleaseMode::Bundle);
}

/// `--embed` and `--bundle` together is a usage error.
#[test]
fn release_embed_and_bundle_mutually_exclusive() {
    let args: Vec<String> = vec!["--embed".into(), "--bundle".into()];
    assert!(
        parse_release_build(&args).is_err(),
        "--embed with --bundle must be rejected"
    );
}

/// `--static` names the posture a native release build already has, so it
/// parses to the default target; `--capabilities` is no flag of
/// `release build` and refuses.
#[test]
fn release_build_accepts_static_and_refuses_capabilities() {
    let args: Vec<String> = vec!["--static".into()];
    let parsed = parse_release_build(&args).expect("--static parse must succeed");
    assert_eq!(parsed.target, None);
    let caps: Vec<String> = vec!["--capabilities".into()];
    assert!(
        parse_release_build(&caps).is_err(),
        "`release build --capabilities` must be refused as an unknown flag"
    );
}

/// `--out <dir>` is accepted.
#[test]
fn release_out_flag() {
    let args: Vec<String> = vec!["--out".into(), "dist/".into()];
    let parsed = parse_release_build(&args).expect("--out parse must succeed");
    assert_eq!(parsed.out.as_deref(), Some("dist/"));
}

/// `--target <triple>` is accepted (native triple).
#[test]
fn release_target_flag_native() {
    let args: Vec<String> = vec!["--target".into(), "x86_64-unknown-linux-musl".into()];
    let parsed = parse_release_build(&args).expect("--target parse must succeed");
    assert_eq!(parsed.target, Some(StaticTriple::X8664LinuxMusl));
}

/// `--target wasm` is refused: the browser bundle is the `web client` delivery.
#[test]
fn release_target_flag_wasm_is_refused() {
    let args: Vec<String> = vec!["--target".into(), "wasm".into()];
    assert!(
        parse_release_build(&args).is_err(),
        "`release build --target wasm` must be refused"
    );
}

/// A positional entry is captured.
#[test]
fn release_positional_entry() {
    let args: Vec<String> = vec!["src/Main.ipe".into()];
    let parsed = parse_release_build(&args).expect("entry parse must succeed");
    assert_eq!(parsed.entry.as_deref(), Some("src/Main.ipe"));
}

/// An unknown flag returns a usage error.
#[test]
fn release_unknown_flag_is_usage_error() {
    let args: Vec<String> = vec!["--no-such-flag".into()];
    let result = parse_release_build(&args);
    assert!(
        result.is_err(),
        "unknown flag must yield a parse error, got: {result:?}"
    );
}

/// `--optimize` is gone — it is no longer a recognised flag.
#[test]
fn release_optimize_flag_removed() {
    let args: Vec<String> = vec!["--optimize".into()];
    assert!(
        parse_release_build(&args).is_err(),
        "--optimize must be rejected (it has been removed)"
    );
}

/// `--out` given twice is a usage error.
#[test]
fn release_out_twice_is_usage_error() {
    let args: Vec<String> = vec!["--out".into(), "a/".into(), "--out".into(), "b/".into()];
    let result = parse_release_build(&args);
    assert!(
        result.is_err(),
        "--out twice must yield a parse error, got: {result:?}"
    );
}

/// `--target` given twice is a usage error.
#[test]
fn release_target_twice_is_usage_error() {
    let args: Vec<String> = vec![
        "--target".into(),
        "x86_64-unknown-linux-musl".into(),
        "--target".into(),
        "aarch64-unknown-linux-musl".into(),
    ];
    let result = parse_release_build(&args);
    assert!(
        result.is_err(),
        "--target twice must yield a parse error, got: {result:?}"
    );
}

/// `ipe release build` in a directory with no package.ipe is refused as
/// `NoManifest` (not a panic or a silent wrong result).
#[test]
fn release_no_project_is_refused_as_no_manifest() {
    let dir = {
        let d =
            std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipe_release_test_empty");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    };
    let prev = std::env::current_dir().unwrap();
    std::env::set_current_dir(&dir).unwrap();

    let result = ipe::run_cli(&["release".to_owned(), "build".to_owned()]);

    std::env::set_current_dir(&prev).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        matches!(result, Err(ipe::CliError::NoManifest { .. })),
        "bare `ipe release build` in an empty dir must yield NoManifest, got: {result:?}"
    );
}

/// `ipe release` on a pure Ipê app (no native/FFI content) must succeed at the
/// dispatch level — it now produces a plain optimised binary instead of refusing.
/// The parse is accepted; the actual build is exercised only under `IPE_E2E=1`.
#[test]
fn release_pure_app_parse_is_accepted() {
    // The pure-app refusal has been removed: parse_release accepts any entry.
    let args: Vec<String> = vec!["src/Main.ipe".into()];
    let parsed = parse_release_build(&args).expect("pure-app entry must parse without error");
    assert_eq!(parsed.entry.as_deref(), Some("src/Main.ipe"));
}

/// An unsupported `--target` triple (not "wasm" and not a known musl triple)
/// surfaces as a usage error at dispatch time.
#[test]
fn release_unsupported_native_target_is_usage_error() {
    let dir = {
        let d = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("ipe_release_test_bad_triple");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("package.ipe"),
            "module Package exposing (package)\n\n\npackage =\n    { name = \"test\" }\n",
        )
        .unwrap();
        std::fs::create_dir_all(d.join("src")).unwrap();
        std::fs::write(
            d.join("src").join("Main.ipe"),
            "main : Task Error ()\nmain = Task.succeed ()\n",
        )
        .unwrap();
        d
    };
    let prev = std::env::current_dir().unwrap();
    std::env::set_current_dir(&dir).unwrap();

    let result = ipe::run_cli(&[
        "release".to_owned(),
        "build".to_owned(),
        "--target".to_owned(),
        "totally-bogus-triple".to_owned(),
    ]);

    std::env::set_current_dir(&prev).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        result.is_err(),
        "release with a bogus target triple must error, got Ok"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("unsupported target") || msg.contains("bogus"),
        "error must mention the unsupported target, got: {msg}"
    );
}

// ── Environment target ───────────────────────────────────────────────────────

/// A served `Web.tea` app: a delivery with no wasm client form.
const SERVED_APP: &str = "module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub

type Msg
    = Noop

type alias Model =
    { count : Int }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( model, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.text \"ok\"

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
        , notFound = Noop
        }
";

/// `IPE_TARGET=wasm` is refused by `release build`, naming the variable.
///
/// The variable is seeded at spawn time on the child `ipe`, the one place a
/// test sets the environment the compiler's reader sees. A release that
/// ignored it would build a native binary silently; the refusal fires before
/// any emit, so no output is written.
#[test]
fn release_env_wasm_is_refused_end_to_end() {
    const NAME: &str = "release_env_wasm_refused";
    let root = support::scratch_root().join(NAME);
    let _ = std::fs::remove_dir_all(&root);
    support::expect_scratch_step(NAME, std::fs::create_dir_all(root.join("src")));
    support::expect_scratch_step(
        NAME,
        std::fs::write(root.join("package.ipe"), support::package_ipe("env-wasm")),
    );
    support::expect_scratch_step(
        NAME,
        std::fs::write(root.join("src").join("Main.ipe"), SERVED_APP),
    );
    let out = root.join("out");
    let output = std::process::Command::new(support::ipe_bin())
        .arg("release")
        .arg("build")
        .arg(&root)
        .arg("--out")
        .arg(&out)
        .env("IPE_TARGET", "wasm")
        .env("NO_COLOR", "1")
        .output();
    let wrote = out.exists();
    let _ = std::fs::remove_dir_all(&root);
    let output = match output {
        Ok(output) => output,
        Err(e) => panic!("spawn `ipe release build`: {e}"),
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "`IPE_TARGET=wasm ipe release build` must refuse: {stderr}"
    );
    assert!(
        stderr.contains("IPE_TARGET") && stderr.contains("ipe release build web client"),
        "the refusal names `IPE_TARGET` and the client delivery: {stderr}"
    );
    assert!(!wrote, "a refused release writes no output");
}
