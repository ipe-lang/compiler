//! Regenerate the byte-exact CLI transcript goldens under
//! `src/ipe-cli/tests/golden/cli/`.
//!
//! For every advertised (non-hidden) command it records the `--help` page, and
//! for every extra hermetic invocation in the shared catalog it records the
//! transcript — each redacted through [`ipe::cli_transcript::redact`] and stored
//! in the [`ipe::cli_transcript::golden_envelope`] shape the integration test
//! reads back. The command list, classification, redaction, and envelope all
//! come from `ipe::cli_transcript`, so the tool and the test cannot drift.
//!
//! The binary is invoked as `cargo run --quiet -p ipe --bin ipe -- <args>` — the
//! SAME `ipe` the test spawns — so a regenerated golden is faithful by
//! construction: on an unchanged CLI surface it is a no-op (`git status` stays
//! clean), which is exactly what the CI drift gate asserts.
//!
//! Usage:
//!   regen-cli-transcripts                 # regenerate every transcript golden
//!   regen-cli-transcripts --repo-root DIR # anchor at DIR instead of walking up

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use ipe::cli_transcript;

fn main() -> ExitCode {
    match run() {
        Ok(count) => {
            println!("regen-cli-transcripts: {count} transcript golden(s) written");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("regen-cli-transcripts: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<usize, String> {
    let repo_root = find_repo_root()?;
    let dir = cli_transcript::golden_dir(&repo_root);
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;

    let mut written = 0usize;

    // One golden per advertised command's `--help` page.
    for spec in ipe::help::all_command_specs() {
        if spec.hidden {
            continue;
        }
        let name = cli_transcript::help_golden_name(spec.name);
        let content = capture(&repo_root, &[spec.name, "--help"])?;
        write_golden(&dir, &name, &content)?;
        written += 1;
    }

    // One golden per extra hermetic invocation.
    for inv in cli_transcript::INVOCATIONS {
        let Some(args) = (inv.args)(&repo_root) else {
            eprintln!(
                "regen-cli-transcripts: skipping `{}` — fixture absent",
                inv.golden
            );
            continue;
        };
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let content = capture(&repo_root, &arg_refs)?;
        write_golden(&dir, inv.golden, &content)?;
        written += 1;
    }

    Ok(written)
}

/// Run the `ipe` binary with `<args>` under `NO_COLOR=1`, then wrap the redacted
/// stdout in the golden envelope.
fn capture(repo_root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("cargo")
        .args(["run", "--quiet", "-p", "ipe", "--bin", "ipe", "--"])
        .args(args)
        .current_dir(repo_root)
        .env("NO_COLOR", "1")
        .output()
        .map_err(|e| format!("cannot spawn `ipe {args:?}`: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let redacted = cli_transcript::redact(&stdout, repo_root);
    Ok(cli_transcript::golden_envelope(
        output.status.code(),
        &redacted,
    ))
}

/// Write a golden file, creating or overwriting it.
fn write_golden(dir: &Path, basename: &str, content: &str) -> Result<(), String> {
    let path = dir.join(format!("{basename}.txt"));
    std::fs::write(&path, content).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn find_repo_root() -> Result<PathBuf, String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--repo-root" {
            let path = args
                .next()
                .ok_or_else(|| "--repo-root requires a path argument".to_owned())?;
            return Ok(PathBuf::from(path));
        }
    }
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    find_workspace_root(Path::new(manifest_dir))
}

fn find_workspace_root(start: &Path) -> Result<PathBuf, String> {
    let mut current = start;
    loop {
        let candidate = current.join("Cargo.toml");
        if candidate.exists() {
            let content = std::fs::read_to_string(&candidate)
                .map_err(|e| format!("cannot read {}: {e}", candidate.display()))?;
            if content.contains("[workspace]") {
                return Ok(current.to_owned());
            }
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => return Err("workspace root not found — pass --repo-root".to_owned()),
        }
    }
}
