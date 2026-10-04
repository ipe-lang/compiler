//! Exhaustive optional-argument combination coverage for the `ipe` CLI, driven
//! through the real dispatch (`ipe::run_cli`) and the typed parse layer
//! (`ipe::cli_args::*`).
//!
//! Every subcommand is checked on two axes:
//!   (a) each VALID optional-flag combination parses / dispatches without a
//!       usage error (the parse layer returns `Ok`, or dispatch proceeds past
//!       parsing into the build/analysis it would run);
//!   (b) each INVALID / contradictory combination is rejected with a specific
//!       `CliError` and never a panic or a silently-accepted flag.
//!
//! The parse-only assertions use the `pub` `cli_args` functions so a full build
//! is never spawned; the dispatch assertions use `run_cli` for the commands
//! whose parsing lives in their own module (diff / rust / add / remove / fix /
//! init), asserting the usage-error contract without needing a project on disk.

use ipe::CliError;
use ipe::cli_args::{
    BuildMode, SessionMode, parse_build, parse_fix, parse_fmt, parse_run, parse_watch,
};

/// `&[&str]` → `Vec<String>`, the shape every parse/dispatch entry point takes.
fn v(args: &[&str]) -> Vec<String> {
    args.iter().map(|a| (*a).to_owned()).collect()
}

/// Assert a `run_cli` invocation fails with SOME `CliError` (a usage/typed
/// rejection), never `Ok` and never a panic. Used for the invalid combinations
/// whose commands parse in their own module.
fn dispatch_rejects(args: &[&str]) {
    let result = ipe::run_cli(&v(args));
    assert!(
        result.is_err(),
        "expected `ipe {}` to be rejected, got Ok",
        args.join(" ")
    );
}

// ===========================================================================
// build
// ===========================================================================

#[test]
fn build_valid_combinations_parse() {
    // Empty / default.
    assert!(parse_build(&v(&[])).is_ok());
    // Entry only.
    assert!(parse_build(&v(&["Main.ipe"])).is_ok());
    // Each single emit flag.
    assert!(parse_build(&v(&["--out", "o"])).is_ok());
    assert!(parse_build(&v(&["--runtime", "r"])).is_ok());
    assert!(parse_build(&v(&["--fix"])).is_ok());
    assert!(parse_build(&v(&["--emit-ir"])).is_ok());
    assert!(parse_build(&v(&["--static"])).is_ok());
    assert!(parse_build(&v(&["--target", "x86_64-unknown-linux-musl"])).is_ok());
    assert!(parse_build(&v(&["--target", "wasm"])).is_ok());
    // Valid multi-flag native static combination.
    assert!(
        parse_build(&v(&[
            "Main.ipe",
            "--static",
            "--target",
            "x86_64-unknown-linux-musl",
            "--allocator",
            "system",
            "--out",
            "o",
        ]))
        .is_ok()
    );
    // `--fix` composes with `--emit-ir` (fix is a source pre-pass).
    let a = parse_build(&v(&["Main.ipe", "--emit-ir", "--fix"])).expect("emit-ir + fix");
    assert!(a.fix);
    assert!(matches!(a.mode, BuildMode::EmitIr));
}

#[test]
fn build_invalid_combinations_rejected() {
    // --emit-ir vs every emit-affecting flag.
    for extra in [
        vec!["--emit-ir", "--out", "o"],
        vec!["--emit-ir", "--static"],
        vec!["--emit-ir", "--target", "wasm"],
        vec!["--emit-ir", "--target", "x86_64-unknown-linux-musl"],
        vec!["--emit-ir", "--allocator", "dlmalloc"],
    ] {
        assert!(
            parse_build(&v(&extra)).is_err(),
            "expected {extra:?} to be rejected"
        );
    }
    // --target wasm vs native-only static flags.
    assert!(parse_build(&v(&["--target", "wasm", "--static"])).is_err());
    assert!(parse_build(&v(&["--target", "wasm", "--allocator", "dlmalloc"])).is_err());
    // Duplicate value flags.
    assert!(parse_build(&v(&["--out", "a", "--out", "b"])).is_err());
    assert!(parse_build(&v(&["--target", "a", "--target", "b"])).is_err());
    assert!(parse_build(&v(&["--runtime", "a", "--runtime", "b"])).is_err());
    assert!(parse_build(&v(&["--allocator", "auto", "--allocator", "system"])).is_err());
    // Allocator outside the closed set.
    assert!(parse_build(&v(&["--static", "--allocator", "jemalloc"])).is_err());
    assert!(parse_build(&v(&["--static", "--allocator", ""])).is_err());
    // Missing value.
    assert!(parse_build(&v(&["--out"])).is_err());
    assert!(parse_build(&v(&["--allocator"])).is_err());
    // Unknown flag.
    assert!(parse_build(&v(&["--bogus"])).is_err());
    assert!(parse_build(&v(&["Main.ipe", "--nope"])).is_err());
}

// ===========================================================================
// run
// ===========================================================================

#[test]
fn run_valid_combinations_parse() {
    assert!(parse_run(&v(&[])).is_ok());
    assert!(parse_run(&v(&["Main.ipe"])).is_ok());
    assert!(parse_run(&v(&["--out", "o"])).is_ok());
    assert!(parse_run(&v(&["--runtime", "r"])).is_ok());
    assert!(parse_run(&v(&["--static"])).is_ok());
    assert!(parse_run(&v(&["--static", "--target", "x86_64-unknown-linux-musl"])).is_ok());
    // `--` boundary: everything after is forwarded verbatim.
    let a = parse_run(&v(&[
        "Main.ipe", "--out", "o", "--", "--target", "wasm", "x",
    ]))
    .expect("dash-dash");
    assert_eq!(a.bin_args, v(&["--target", "wasm", "x"]));
    assert_eq!(a.out.as_deref(), Some("o"));
    // Trailing `--` forwards nothing.
    assert!(
        parse_run(&v(&["Main.ipe", "--"]))
            .expect("trailing")
            .bin_args
            .is_empty()
    );
}

#[test]
fn run_invalid_combinations_rejected() {
    // `--target wasm` has no native artifact to run.
    assert!(matches!(
        parse_run(&v(&["--target", "wasm"])),
        Err(CliError::Usage(_))
    ));
    // Duplicates + missing value + unknown flag.
    assert!(parse_run(&v(&["--out", "a", "--out", "b"])).is_err());
    assert!(parse_run(&v(&["--runtime"])).is_err());
    assert!(parse_run(&v(&["Main.ipe", "--bogus"])).is_err());
    assert!(parse_run(&v(&["--static", "--allocator", "nope"])).is_err());
}

// ===========================================================================
// watch
// ===========================================================================

#[test]
fn watch_valid_combinations_parse() {
    assert_eq!(parse_watch(&v(&[])).expect("empty").port, 8000);
    assert!(parse_watch(&v(&["Main.ipe"])).is_ok());
    assert!(parse_watch(&v(&["--out", "o"])).is_ok());
    assert!(parse_watch(&v(&["--runtime", "r"])).is_ok());
    assert_eq!(
        parse_watch(&v(&["Main.ipe", "--out", "o", "--port", "9090"]))
            .expect("all")
            .port,
        9090
    );
}

#[test]
fn watch_invalid_combinations_rejected() {
    // Non-numeric / out-of-range port.
    assert!(parse_watch(&v(&["--port", "abc"])).is_err());
    assert!(parse_watch(&v(&["--port", "70000"])).is_err());
    // Duplicate / missing value.
    assert!(parse_watch(&v(&["--port", "1", "--port", "2"])).is_err());
    assert!(parse_watch(&v(&["--port"])).is_err());
    // A build/run flag does not belong to watch.
    assert!(parse_watch(&v(&["--static"])).is_err());
    assert!(parse_watch(&v(&["--target", "wasm"])).is_err());
}

// ===========================================================================
// fix
// ===========================================================================

#[test]
fn fix_valid_combinations_parse() {
    assert!(parse_fix(&v(&["Main.ipe"])).is_ok());
    let a = parse_fix(&v(&["Main.ipe", "--yes"])).expect("yes");
    assert!(a.auto);
}

#[test]
fn fix_invalid_combinations_rejected() {
    // Missing required path.
    assert!(matches!(parse_fix(&v(&[])), Err(CliError::Usage(_))));
    assert!(matches!(parse_fix(&v(&["--yes"])), Err(CliError::Usage(_))));
    // Second positional / unknown flag.
    assert!(parse_fix(&v(&["a.ipe", "b.ipe"])).is_err());
    assert!(parse_fix(&v(&["Main.ipe", "--bogus"])).is_err());
}

// ===========================================================================
// fmt
// ===========================================================================

#[test]
fn fmt_valid_combinations_parse() {
    use ipe::cli_args::FmtMode;

    assert!(parse_fmt(&v(&[])).is_ok());
    assert!(parse_fmt(&v(&["src"])).is_ok());
    assert!(parse_fmt(&v(&["--check"])).is_ok());
    assert!(parse_fmt(&v(&["src", "--check"])).is_ok());

    // --stdin
    let m = parse_fmt(&v(&["--stdin"])).expect("stdin");
    assert!(matches!(m, FmtMode::Stdin));
    let m = parse_fmt(&v(&["--stdin", "--check"])).expect("stdin check");
    assert!(matches!(m, FmtMode::StdinCheck));
}

#[test]
fn fmt_invalid_combinations_rejected() {
    assert!(parse_fmt(&v(&["a", "b"])).is_err());
    assert!(parse_fmt(&v(&["--bogus"])).is_err());
    // --stdin + path is mutually exclusive
    assert!(parse_fmt(&v(&["--stdin", "src"])).is_err());
}

// ===========================================================================
// Commands whose parsing lives in their own module — dispatch-level contract.
// These assert the usage-error boundary without needing a project on disk.
// ===========================================================================

#[test]
fn diff_invalid_combinations_rejected() {
    // Too few positionals.
    dispatch_rejects(&["diff"]);
    dispatch_rejects(&["diff", "only-one"]);
    // The deprecated `--check` alias needs two version arguments.
    dispatch_rejects(&["diff", "old", "new", "--check", "1.0.0"]);
    // A malformed version under `--check`.
    dispatch_rejects(&["diff", "old", "new", "--check", "notaversion", "1.0.0"]);
    // The bare `check` mode needs two paths and two versions.
    dispatch_rejects(&["diff", "check", "old", "new", "1.0.0"]);
    // A malformed version under bare `check`.
    dispatch_rejects(&["diff", "check", "old", "new", "notaversion", "1.0.0"]);
}

#[test]
fn rust_group_invalid_combinations_rejected() {
    // Unknown subcommand.
    dispatch_rejects(&["rust", "frobnicate"]);
    // `add` with no crate.
    dispatch_rejects(&["rust", "add", "--yes"]);
    // `add` with a second positional.
    dispatch_rejects(&["rust", "add", "serde", "extra"]);
    // `add --features` with no value.
    dispatch_rejects(&["rust", "add", "serde", "--features"]);
    // `remove` with no crate / too many.
    dispatch_rejects(&["rust", "remove"]);
    dispatch_rejects(&["rust", "remove", "a", "b"]);
    // `install` with an unknown flag.
    dispatch_rejects(&["rust", "install", "--bogus"]);
}

#[test]
fn add_remove_invalid_combinations_rejected() {
    // No package named (these fail before touching the filesystem).
    dispatch_rejects(&["add"]);
    dispatch_rejects(&["add", "a", "b"]);
    dispatch_rejects(&["remove"]);
    dispatch_rejects(&["remove", "a", "b"]);
}

#[test]
fn init_unknown_flag_rejected() {
    dispatch_rejects(&["init", "--bogus"]);
}

#[test]
fn top_level_unknown_command_rejected() {
    assert!(matches!(
        ipe::run_cli(&v(&["frobnicate"])),
        Err(CliError::UnknownCommand { .. })
    ));
}

// ===========================================================================
// --debugger flag: accepted by build/run, rejected by release
// ===========================================================================

/// `ipe build --debugger` parses and sets the flag.
#[test]
fn build_debugger_flag_accepted() {
    let a = parse_build(&v(&["--debugger"])).expect("--debugger must parse");
    assert!(a.debugger, "--debugger must set the field");
}

/// `ipe build --debugger` composes with other flags.
#[test]
fn build_debugger_flag_composes() {
    let a = parse_build(&v(&["Main.ipe", "--debugger", "--out", "o"]))
        .expect("--debugger + --out must parse");
    assert!(a.debugger);
    assert_eq!(a.entry.as_deref(), Some("Main.ipe"));
}

/// Without `--debugger`, the field is `false`.
#[test]
fn build_no_debugger_flag_is_false() {
    let a = parse_build(&v(&[])).expect("empty must parse");
    assert!(!a.debugger, "debugger must default to false");
}

/// `ipe run --debugger` parses and sets the flag.
#[test]
fn run_debugger_flag_accepted() {
    let a = parse_run(&v(&["--debugger"])).expect("--debugger must parse");
    assert!(a.debugger, "--debugger must set the field");
}

/// Without `--debugger` on `ipe run`, the field is `false`.
#[test]
fn run_no_debugger_flag_is_false() {
    let a = parse_run(&v(&[])).expect("empty must parse");
    assert!(!a.debugger, "debugger must default to false");
}

/// `ipe release --debugger` must be rejected (unknown flag on release).
#[test]
fn release_debugger_flag_rejected() {
    use ipe::cli_args::parse_release_build;
    let result = parse_release_build(&v(&["--debugger"]));
    assert!(
        result.is_err(),
        "`ipe release --debugger` must be rejected as unknown flag, got: {result:?}"
    );
}

// ===========================================================================
// run --record — session recording lives on `ipe run`, not a top-level verb.
// ===========================================================================

/// `ipe run --record` parses, and a plain `ipe run` does not record.
#[test]
fn run_record_flag_accepted() {
    let a = parse_run(&v(&["Main.ipe", "--record"])).expect("--record must parse");
    assert_eq!(a.session, SessionMode::Record, "--record must set the mode");
    let plain = parse_run(&v(&["Main.ipe"])).expect("plain run must parse");
    assert_eq!(plain.session, SessionMode::Live, "a plain run is live");
}

/// `ipe run --replay` reads the default log; `--replay <log>` names one.
#[test]
fn run_replay_flag_accepted_with_optional_log() {
    let a = parse_run(&v(&["Main.ipe", "--replay"])).expect("--replay must parse");
    assert_eq!(a.session, SessionMode::Replay(None));
    let b = parse_run(&v(&["Main.ipe", "--replay", "bug.ipemsgs", "--quiet"]))
        .expect("--replay <log> must parse");
    assert_eq!(
        b.session,
        SessionMode::Replay(Some("bug.ipemsgs".to_owned()))
    );
    assert!(b.quiet, "a flag after the log is still parsed");
    let c = parse_run(&v(&["Main.ipe", "--replay", "--quiet"]))
        .expect("--replay before a flag must parse");
    assert_eq!(
        c.session,
        SessionMode::Replay(None),
        "a flag is never the log"
    );
}

/// `--record` and `--replay` are exclusive, and neither may repeat.
#[test]
fn run_record_and_replay_are_exclusive() {
    for args in [
        &["Main.ipe", "--record", "--replay"][..],
        &["Main.ipe", "--replay", "--record"][..],
        &["Main.ipe", "--record", "--record"][..],
        &["Main.ipe", "--replay", "a.ipemsgs", "--replay"][..],
    ] {
        let result = parse_run(&v(args));
        assert!(
            result.is_err(),
            "{args:?} must be rejected, got: {:?}",
            result.map(|a| a.session)
        );
    }
}

/// `--record` takes no value.
///
/// The log always lands in the ipe-owned output root, so a stray path argument
/// can never name a user file to overwrite.
#[test]
fn run_record_takes_no_path() {
    let result = parse_run(&v(&["Main.ipe", "--record", "notes.txt"]));
    assert!(
        result.is_err(),
        "a path after --record must be rejected, got: {:?}",
        result.map(|a| a.session)
    );
}

/// `debugger` is not a top-level command (recording is `ipe run --record`).
#[test]
fn debugger_is_not_a_top_level_command() {
    dispatch_rejects(&["debugger", "record", "Main.ipe"]);
}
