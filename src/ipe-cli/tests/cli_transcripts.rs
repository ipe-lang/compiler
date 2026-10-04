#![forbid(unsafe_code)]
//! Byte-exact CLI transcript goldens for the deterministic (hermetic) command
//! surface.
//!
//! The four-quadrant conformance gate (`cli_output_conformance.rs`) pins the
//! *structure* of every command's output (exit code, machine-stream
//! cleanliness, JSON well-formedness) but not the *bytes*: a command's help
//! wording, layout, or an error phrase can drift silently. This gate closes
//! that. For a table of hermetic invocations driven from the `help::COMMANDS`
//! SSOT it runs the built binary, redacts the volatile tokens, and compares the
//! transcript to a committed golden under `tests/golden/cli/<name>.txt`.
//!
//! The catalog (which invocations are hermetic, the redaction rule, the
//! per-command classification, and the golden envelope) lives in the shared
//! `ipe::cli_transcript` module, so the test and the `regen-cli-transcripts`
//! tool read one source and cannot drift. This file is the *consumer*: it spawns
//! the binary and diffs against the committed goldens (which the regen tool,
//! run by the orchestrator, produces).
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ipe::cli_transcript::{self, Hermetic};

mod support;

/// The workspace root (two levels up from this crate's manifest).
fn repo_root() -> PathBuf {
    support::manifest_dir().join("../..")
}

/// Run `ipe <args>` with `NO_COLOR=1` (so a captured non-terminal stream is
/// deterministic plain text) and return `(exit_code, stdout)`.
fn run(args: &[&str]) -> (Option<i32>, String) {
    let output = Command::new(support::ipe_bin())
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn ipe");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

/// Read a committed golden by basename, or `None` when it does not exist yet.
/// Read at runtime (not `include_str!`) so a missing golden is a clean test
/// failure the regen tool fixes, never a compile error.
fn read_golden(basename: &str) -> Option<String> {
    let path = cli_transcript::golden_dir(&repo_root()).join(format!("{basename}.txt"));
    std::fs::read_to_string(&path).ok()
}

/// Compare a live transcript to its committed golden.
fn assert_matches_golden(basename: &str, exit_code: Option<i32>, stdout: &str) {
    let redacted = cli_transcript::redact(stdout, &repo_root());
    let actual = cli_transcript::golden_envelope(exit_code, &redacted);
    // A missing golden fails via `assert!` (not a bare `panic!`, which the
    // production clippy set denies even in test targets); the message names the
    // regen tool.
    let expected = read_golden(basename);
    assert!(
        expected.is_some(),
        "missing CLI transcript golden `{basename}.txt`.\n\
         Regenerate with: cargo run -p regen-cli-transcripts\n\
         (the golden is generated output — do not hand-write it)"
    );
    assert_eq!(
        expected.unwrap_or_default(),
        actual,
        "CLI transcript `{basename}` drifted from its golden.\n\
         If the change is intended, regenerate: cargo run -p regen-cli-transcripts"
    );
}

/// The classification must cover exactly the `help::COMMANDS` set — no
/// unclassified fallback — so a new command is forced into a transcript decision.
#[test]
fn every_command_is_classified() {
    for name in ipe::help::command_names() {
        if let Hermetic::Excluded(reason) = cli_transcript::classify(name) {
            assert!(
                !reason.contains(cli_transcript::UNCLASSIFIED_SENTINEL),
                "command `{name}` is not classified in cli_transcript::classify — \
                 add it (Snapshot for a deterministic body, or Excluded with a reason)",
            );
            assert!(
                !reason.trim().is_empty(),
                "excluded command `{name}` must carry a non-empty reason",
            );
        }
    }
}

/// Every advertised (non-hidden) command's `--help` page is byte-exact against
/// its committed golden. Help is a pure render of the `COMMANDS` entry, so it is
/// hermetic for every command regardless of the command body's hermeticity.
#[test]
fn every_command_help_page_matches_its_golden() {
    for spec in ipe::help::all_command_specs() {
        if spec.hidden {
            continue; // hidden commands are not part of the advertised surface
        }
        let argv: Vec<&str> = spec.name.split(' ').chain(["--help"]).collect();
        let (code, stdout) = run(&argv);
        assert_matches_golden(&cli_transcript::help_golden_name(spec.name), code, &stdout);
    }
}

/// The extra hermetic invocations (top-level help, group help, `version`, and
/// the deterministic command bodies over committed fixtures) are byte-exact.
#[test]
fn hermetic_invocations_match_their_goldens() {
    let root = repo_root();
    for inv in cli_transcript::INVOCATIONS {
        let Some(args) = (inv.args)(&root as &Path) else {
            continue; // sparse checkout without a fixture — skip, never a false red
        };
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let (code, stdout) = run(&arg_refs);
        assert_matches_golden(inv.golden, code, &stdout);
    }
}
