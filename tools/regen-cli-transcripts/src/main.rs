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
//! Transcripts are recorded from one `ipe` binary: the one given by `--ipe-bin`,
//! or else the one `cargo build -p ipe --bin ipe` reports building — the SAME
//! `ipe` the test spawns — so a regenerated golden is faithful by construction:
//! on an unchanged CLI surface it is a no-op (`git status` stays clean), which is
//! exactly what the CI drift gate asserts.
//!
//! Only a transcript `ipe` actually produced is ever written. When `ipe` cannot
//! be built or spawned, or is killed by a signal, the tool exits non-zero before
//! writing any golden, so a tool failure never surfaces as golden drift.
//!
//! Usage:
//!   regen-cli-transcripts                   # regenerate every transcript golden
//!   regen-cli-transcripts --repo-root DIR   # anchor at DIR instead of walking up
//!   regen-cli-transcripts --ipe-bin PATH    # record from a prebuilt `ipe`

#![forbid(unsafe_code)]

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus, Stdio};

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

/// Why the tool could not record the goldens. Every variant is a failure of the
/// tool or its environment — never a transcript, which is only a [`Transcript`].
#[derive(Debug)]
enum RegenError {
    /// A command-line argument is not valid UTF-8.
    NonUtf8Arg(ipe_docs::argv::NonUtf8Argument),
    /// A command-line argument is not a known flag.
    UnknownArg(String),
    /// A flag was given without its path value.
    MissingValue(&'static str),
    /// The `--ipe-bin` path does not resolve to an existing file.
    IpeBin {
        path: PathBuf,
        error: std::io::Error,
    },
    /// A candidate workspace `Cargo.toml` could not be read.
    RepoRootRead {
        path: PathBuf,
        error: std::io::Error,
    },
    /// No ancestor directory holds a workspace `Cargo.toml`.
    RepoRootNotFound,
    /// `cargo` could not be spawned to build `ipe`.
    CargoSpawn(std::io::Error),
    /// `cargo build -p ipe --bin ipe` exited unsuccessfully.
    CargoFailed(ExitStatus),
    /// `cargo build` succeeded but reported no executable for the `ipe` bin.
    NoIpeExecutable,
    /// The `ipe` binary could not be spawned.
    Spawn {
        args: Vec<String>,
        error: std::io::Error,
    },
    /// `ipe` was killed by a signal instead of exiting with a code.
    Signal { args: Vec<String> },
    /// A golden (or its directory) could not be written.
    Write {
        path: PathBuf,
        error: std::io::Error,
    },
}

impl fmt::Display for RegenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonUtf8Arg(refused) => write!(f, "{refused}"),
            Self::UnknownArg(arg) => write!(f, "unknown argument `{arg}`"),
            Self::MissingValue(flag) => write!(f, "{flag} requires a path argument"),
            Self::IpeBin { path, error } => write!(f, "--ipe-bin {}: {error}", path.display()),
            Self::RepoRootRead { path, error } => {
                write!(f, "cannot read {}: {error}", path.display())
            }
            Self::RepoRootNotFound => f.write_str("workspace root not found — pass --repo-root"),
            Self::CargoSpawn(error) => {
                write!(f, "cannot build `ipe`: cannot spawn `cargo`: {error}")
            }
            Self::CargoFailed(status) => write!(
                f,
                "cannot build `ipe`: `cargo build -p ipe --bin ipe` failed ({status})"
            ),
            Self::NoIpeExecutable => {
                f.write_str("cannot build `ipe`: cargo reported no executable for the `ipe` binary")
            }
            Self::Spawn { args, error } => {
                write!(f, "cannot spawn `ipe {}`: {error}", args.join(" "))
            }
            Self::Signal { args } => write!(
                f,
                "`ipe {}` was killed by a signal; no golden written",
                args.join(" ")
            ),
            Self::Write { path, error } => write!(f, "cannot write {}: {error}", path.display()),
        }
    }
}

/// What one `ipe` invocation produced: its exit code and its raw stdout.
struct Transcript {
    exit_code: i32,
    stdout: String,
}

struct Options {
    repo_root: PathBuf,
    ipe_bin: Option<PathBuf>,
}

fn run() -> Result<usize, RegenError> {
    let opts = parse_args()?;
    let repo_root = opts.repo_root;
    // Absolute, so the spawn resolves the same file whatever `current_dir` is.
    let ipe_bin = match opts.ipe_bin {
        Some(path) => {
            std::fs::canonicalize(&path).map_err(|error| RegenError::IpeBin { path, error })?
        }
        None => build_ipe(&repo_root)?,
    };

    // Record every golden before writing any, so a failure leaves the committed
    // goldens untouched.
    let mut goldens: Vec<(String, String)> = Vec::new();

    // One golden per advertised command's `--help` page.
    for spec in ipe::help::all_command_specs() {
        if spec.hidden {
            continue;
        }
        let args: Vec<String> = spec
            .name
            .split(' ')
            .chain(["--help"])
            .map(str::to_owned)
            .collect();
        let transcript = capture(&ipe_bin, &repo_root, &args)?;
        goldens.push((
            cli_transcript::help_golden_name(spec.name),
            envelope(&transcript, &repo_root),
        ));
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
        let transcript = capture(&ipe_bin, &repo_root, &args)?;
        goldens.push((inv.golden.to_owned(), envelope(&transcript, &repo_root)));
    }

    let dir = cli_transcript::golden_dir(&repo_root);
    std::fs::create_dir_all(&dir).map_err(|error| RegenError::Write {
        path: dir.clone(),
        error,
    })?;
    for (name, content) in &goldens {
        write_golden(&dir, name, content)?;
    }
    Ok(goldens.len())
}

/// Run `ipe <args>` under `NO_COLOR=1` from the repository root.
fn capture(ipe_bin: &Path, repo_root: &Path, args: &[String]) -> Result<Transcript, RegenError> {
    let output = Command::new(ipe_bin)
        .args(args)
        .current_dir(repo_root)
        .env("NO_COLOR", "1")
        .output()
        .map_err(|error| RegenError::Spawn {
            args: args.to_vec(),
            error,
        })?;
    let exit_code = output.status.code().ok_or_else(|| RegenError::Signal {
        args: args.to_vec(),
    })?;
    Ok(Transcript {
        exit_code,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
    })
}

/// The redacted transcript in the golden envelope the test reads back.
fn envelope(transcript: &Transcript, repo_root: &Path) -> String {
    let redacted = cli_transcript::redact(&transcript.stdout, repo_root);
    cli_transcript::golden_envelope(Some(transcript.exit_code), &redacted)
}

/// Build `ipe` and return the executable cargo reports, so the transcripts come
/// from exactly the binary just built wherever the target directory lives.
/// Cargo's rendered diagnostics go to the inherited stderr, so a failed build
/// shows its compiler errors.
fn build_ipe(repo_root: &Path) -> Result<PathBuf, RegenError> {
    let output = Command::new("cargo")
        .args(["build", "--quiet", "-p", "ipe", "--bin", "ipe"])
        .arg("--message-format=json-render-diagnostics")
        .current_dir(repo_root)
        .stderr(Stdio::inherit())
        .output()
        .map_err(RegenError::CargoSpawn)?;
    if !output.status.success() {
        return Err(RegenError::CargoFailed(output.status));
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find_map(|msg| ipe_executable(&msg))
        .ok_or(RegenError::NoIpeExecutable)
}

/// The `executable` of a cargo `compiler-artifact` message for the `ipe` bin.
fn ipe_executable(msg: &serde_json::Value) -> Option<PathBuf> {
    let target = msg.get("target")?;
    let is_ipe_bin = msg.get("reason")?.as_str()? == "compiler-artifact"
        && target.get("name")?.as_str()? == "ipe"
        && target
            .get("kind")?
            .as_array()?
            .iter()
            .any(|k| k.as_str() == Some("bin"));
    if !is_ipe_bin {
        return None;
    }
    msg.get("executable")?.as_str().map(PathBuf::from)
}

/// Write a golden file, creating or overwriting it.
fn write_golden(dir: &Path, basename: &str, content: &str) -> Result<(), RegenError> {
    let path = dir.join(format!("{basename}.txt"));
    std::fs::write(&path, content).map_err(|error| RegenError::Write { path, error })
}

fn parse_args() -> Result<Options, RegenError> {
    let mut repo_root = None;
    let mut ipe_bin = None;
    let mut args = ipe_docs::argv::host_args()
        .map_err(RegenError::NonUtf8Arg)?
        .into_iter();
    while let Some(arg) = args.next() {
        let (flag, slot) = match arg.as_str() {
            "--repo-root" => ("--repo-root", &mut repo_root),
            "--ipe-bin" => ("--ipe-bin", &mut ipe_bin),
            other => return Err(RegenError::UnknownArg(other.to_owned())),
        };
        let value = args.next().ok_or(RegenError::MissingValue(flag))?;
        *slot = Some(PathBuf::from(value));
    }
    let repo_root = match repo_root {
        Some(path) => path,
        None => find_workspace_root(Path::new(env!("CARGO_MANIFEST_DIR")))?,
    };
    Ok(Options { repo_root, ipe_bin })
}

fn find_workspace_root(start: &Path) -> Result<PathBuf, RegenError> {
    let mut current = start;
    loop {
        let candidate = current.join("Cargo.toml");
        if candidate.exists() {
            let content =
                std::fs::read_to_string(&candidate).map_err(|error| RegenError::RepoRootRead {
                    path: candidate.clone(),
                    error,
                })?;
            if content.contains("[workspace]") {
                return Ok(current.to_owned());
            }
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => return Err(RegenError::RepoRootNotFound),
        }
    }
}
