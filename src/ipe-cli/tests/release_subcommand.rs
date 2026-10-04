//! Tests for the `ipe release build` subcommand — argument parsing and dispatch
//! checks. The full end-to-end release (compile + cargo build + bundle layout)
//! requires the musl target installed and is gated on `IPE_E2E=1`.

use ipe::cli_args::{ReleaseMode, ReleaseTarget, StaticTriple, parse_release_build};

// ── Argument parsing ─────────────────────────────────────────────────────────

/// No arguments: entry defaults to None (project-aware default) and the mode
/// is the single self-jailing binary.
#[test]
fn release_no_args_defaults() {
    let args: Vec<String> = vec![];
    let parsed = parse_release_build(&args).expect("no-arg parse must succeed");
    assert!(parsed.entry.is_none());
    assert!(parsed.out.is_none());
    assert_eq!(
        parsed.target,
        ReleaseTarget::Native(StaticTriple::X8664LinuxMusl)
    );
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
/// parses to the default static musl target; `--capabilities` is no flag of
/// `release build` and refuses.
#[test]
fn release_build_accepts_static_and_refuses_capabilities() {
    let args: Vec<String> = vec!["--static".into()];
    let parsed = parse_release_build(&args).expect("--static parse must succeed");
    assert_eq!(
        parsed.target,
        ReleaseTarget::Native(StaticTriple::X8664LinuxMusl)
    );
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
    assert_eq!(
        parsed.target,
        ReleaseTarget::Native(StaticTriple::X8664LinuxMusl)
    );
}

/// `--target wasm` is accepted (browser bundle path).
#[test]
fn release_target_flag_wasm() {
    let args: Vec<String> = vec!["--target".into(), "wasm".into()];
    let parsed = parse_release_build(&args).expect("--target wasm parse must succeed");
    assert_eq!(parsed.target, ReleaseTarget::Wasm);
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

/// `ipe release` in an empty directory with no package.ipe or src/Main.ipe
/// returns a usage error (not a panic or a silent wrong result).
#[test]
fn release_no_project_returns_usage_error() {
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
        matches!(
            result,
            Err(ipe::CliError::CommandUsage { command, .. }) if command == "release build"
        ),
        "bare `ipe release build` in an empty dir must yield a release build command-usage error, got: {result:?}"
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
