//! `jail-runner` — jailed build+run harness for the Ipê playground `/run` surface.
//!
//! Process boundary: argv in, JSON out. The Ipê server stages a Rust crate
//! (Cargo.toml + src/main.rs, split from the client's banner-delimited
//! emitted Rust) under a scratch dir and execs this binary with the project
//! dir as the single positional argument. Every outcome is printed as one
//! JSON document on stdout; the exit code is `0` whenever JSON was printed,
//! `1` only when JSON could not be printed (crash), and `2` on usage errors
//! or harness wall-clock expiry.
//!
//! Security posture (IPE-F4410 fail-closed): the build and run phases run in
//! a bubblewrap jail (network denied, filesystem jailed, rlimits, wall-clock)
//! via `ipe_sandbox`. If the jail cannot be assembled, the harness refuses —
//! it never runs unjailed unless `IPE_FFI_ALLOW_UNSANDBOXED=1` is set, which
//! the runtime only honours on the driver's loud trust warning.
#![allow(clippy::module_name_repetitions)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use serde::Serialize;

use ipe_sandbox::unsandboxed_override_set;
use playground_jail_runner::run_jailed::{
    self, app_binary_path, jailed_build, jailed_run, probe_or_refuse, seed_cargo_home,
    seed_target_dir,
};

const HARNESS_WALL_DEFAULT_SECS: u64 = 60;
const UNSANDBOXED_OUTPUT_CAP_BYTES: u64 = 64 * 1024;
const WARM_DIR_ENV: &str = "IPE_PLAYGROUND_WARM_DIR";
const DEFAULT_WARM_DIR: &str = ".cache/ipe/playground-warm";

/// Serializable mirror of `run_jailed::PhaseOutcome`.
#[derive(Serialize)]
struct PhaseJson {
    status: Option<i32>,
    stdout: String,
    stderr: String,
    killed: bool,
}

impl From<run_jailed::PhaseOutcome> for PhaseJson {
    fn from(phase: run_jailed::PhaseOutcome) -> Self {
        Self {
            status: phase.status,
            stdout: phase.stdout,
            stderr: phase.stderr,
            killed: phase.killed,
        }
    }
}

/// The single wire shape the server understands.
#[derive(Serialize)]
struct Outcome {
    ok: bool,
    unsandboxed: bool,
    build: Option<PhaseJson>,
    run: Option<PhaseJson>,
    exit: Option<i32>,
    error: Option<String>,
}

impl Outcome {
    fn failure(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            unsandboxed: false,
            build: None,
            run: None,
            exit: None,
            error: Some(error.into()),
        }
    }
}

fn main() -> ExitCode {
    // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — playground binary `main`
    // process-boundary entry: argv in, JSON out, no other surface.
    let Ok(args) = std::env::args_os()
        .skip(1)
        .map(std::ffi::OsString::into_string)
        .collect::<Result<Vec<String>, _>>()
    else {
        eprintln!("jail-runner: every argument must be valid UTF-8");
        usage();
        return ExitCode::from(2);
    };
    let rest = args.get(1..).unwrap_or_default();
    let code = match args.first().map(String::as_str) {
        Some("run") => cmd_run(rest),
        Some("prewarm") => cmd_prewarm(rest),
        Some("help" | "--help" | "-h") => {
            usage();
            0
        }
        _ => {
            usage();
            2
        }
    };
    ExitCode::from(code)
}

fn usage() {
    eprintln!(
        "jail-runner: jailed build+run harness for the Ipê playground /run surface\n\
         \n\
         USAGE:\n\
         \x20   jail-runner run <project-dir> [--wall N] [--warm <dir>]\n\
         \x20   jail-runner prewarm [--warm <dir>]\n\
         \n\
         \x20   run      Build (cargo build --offline) and run the staged Rust project\n\
         \x20            inside a bubblewrap jail; prints one JSON document to stdout.\n\
         \x20   prewarm  Build the embedded hello project into the warm cache so jailed\n\
         \x20            builds can resolve dependencies with --offline.\n\
         \n\
         The warm cache defaults to $IPE_PLAYGROUND_WARM_DIR or ~/.cache/ipe/playground-warm."
    );
}

fn cmd_run(args: &[String]) -> u8 {
    cmd_run_with(args, &OUTCOME_CLAIM, start_watchdog)
}

/// [`cmd_run`] with the stdout claim and the watchdog start supplied by the
/// caller; the watchdog must write through the same `claim`.
fn cmd_run_with(
    args: &[String],
    claim: &'static OutcomeClaim,
    start_watchdog: impl FnOnce(u64, &Path, &'static OutcomeClaim) -> std::io::Result<()>,
) -> u8 {
    let parsed = match parse_run_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("{message}");
            usage();
            return 2;
        }
    };
    // Fail closed: without the watchdog thread, a submitted program could run
    // unbounded (no wall-clock cap), so a refused watchdog spawn must stop
    // the harness BEFORE any build or run starts, not just log and continue.
    if let Err(e) = start_watchdog(parsed.wall_secs, &parsed.project_dir, claim) {
        let outcome = Outcome::failure(format!(
            "failed to start the harness wall-clock watchdog: {:?}",
            e.kind()
        ));
        let printed = emit_outcome(claim, &outcome);
        cleanup_project(&parsed.project_dir);
        return if printed { 2 } else { 1 };
    }
    let outcome = run_project(&parsed.project_dir, &parsed.warm_dir);
    let printed = emit_outcome(claim, &outcome);
    cleanup_project(&parsed.project_dir);
    exit_code_after_print(printed)
}

/// `0` once the outcome document was printed, `1` when it could not be.
const fn exit_code_after_print(printed: bool) -> u8 {
    if printed { 0 } else { 1 }
}

struct RunArgs {
    project_dir: PathBuf,
    wall_secs: u64,
    warm_dir: PathBuf,
}

fn parse_run_args(args: &[String]) -> Result<RunArgs, String> {
    let mut project_dir: Option<PathBuf> = None;
    let mut wall_secs = HARNESS_WALL_DEFAULT_SECS;
    let mut warm_dir: Option<PathBuf> = None;
    let mut positionals = 0;
    let mut index = 0;
    while index < args.len() {
        let arg = args.get(index).map(String::as_str);
        match arg {
            Some("--wall") => {
                index += 1;
                let raw = args.get(index).ok_or("--wall requires a value")?;
                wall_secs = raw
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --wall value: {raw}"))?;
            }
            Some("--warm") => {
                index += 1;
                warm_dir = Some(PathBuf::from(
                    args.get(index).ok_or("--warm requires a value")?,
                ));
            }
            Some(flag) if flag.starts_with('-') => return Err(format!("unknown flag: {flag}")),
            Some(value) => {
                positionals += 1;
                if positionals > 1 {
                    return Err(format!("unexpected extra argument: {value}"));
                }
                project_dir = Some(PathBuf::from(value));
            }
            None => break,
        }
        index += 1;
    }
    let project_dir = project_dir.ok_or_else(|| "missing <project-dir> argument".to_owned())?;
    let warm_dir = match warm_dir {
        Some(dir) => dir,
        None => resolve_warm_dir().map_err(|e| e.to_string())?,
    };
    Ok(RunArgs {
        project_dir,
        wall_secs,
        warm_dir,
    })
}

fn cmd_prewarm(args: &[String]) -> u8 {
    let mut warm_dir: Option<PathBuf> = None;
    let mut index = 0;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--warm") => {
                index += 1;
                let Some(value) = args.get(index) else {
                    eprintln!("--warm requires a value");
                    usage();
                    return 2;
                };
                warm_dir = Some(PathBuf::from(value));
            }
            Some(flag) if flag.starts_with('-') => {
                eprintln!("unknown flag: {flag}");
                usage();
                return 2;
            }
            Some(value) => {
                eprintln!("unexpected argument: {value}");
                usage();
                return 2;
            }
            None => break,
        }
        index += 1;
    }
    let warm_dir = match warm_dir.map_or_else(resolve_warm_dir, Ok) {
        Ok(dir) => dir,
        Err(error) => {
            eprintln!("{error}");
            return 2;
        }
    };
    let outcome = prewarm(&warm_dir);
    exit_code_after_print(emit_outcome(&OUTCOME_CLAIM, &outcome))
}

/// Harness-level wall-clock: after `wall_secs` the watchdog prints a timeout
/// JSON document and exits hard. The jail wrapper runs with
/// `--die-with-parent`, so the whole bwrap tree dies with the harness.
///
/// When the run's own outcome has already claimed stdout, the watchdog does
/// nothing: the run is past its jailed phases and `main` is about to exit.
///
/// # Errors
/// The OS refused the watchdog thread; the caller must not start the run.
fn start_watchdog(
    wall_secs: u64,
    project_dir: &Path,
    claim: &'static OutcomeClaim,
) -> std::io::Result<()> {
    let project_dir = project_dir.to_path_buf();
    thread::Builder::new()
        .name("jail-runner-watchdog".to_owned())
        .spawn(move || {
            thread::sleep(Duration::from_secs(wall_secs));
            if !claim.claim() {
                return;
            }
            let outcome =
                Outcome::failure(format!("timed out after {wall_secs}s (harness wall-clock)"));
            let printed = write_claimed_outcome(&outcome);
            // Best-effort: remove the staged project (compiled artifacts can be
            // large). Children may still hold cwd entries; leftover files in that
            // race are bounded by the wall budget and harmless.
            cleanup_project(&project_dir);
            let code = if printed { 2 } else { 1 };
            // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — watchdog expiry: process
            // exit kills all threads; --die-with-parent reaps the bwrap tree.
            std::process::exit(code);
        })?;
    Ok(())
}

/// Best-effort removal of a staged project tree. The harness owns the
/// project-dir lifecycle: the server stages it, this binary runs it, and
/// nothing else touches it afterwards (the server never reuses project
/// dirs). Failures are ignored — a leftover tree is a bounded disk cost,
/// never a correctness issue.
fn cleanup_project(project_dir: &Path) {
    let _ = std::fs::remove_dir_all(project_dir);
}

/// Why no absolute warm-cache directory could be derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WarmDirError {
    /// `IPE_PLAYGROUND_WARM_DIR` is set to a relative path.
    RelativeOverride,
    /// No override is set and the invoking user's home is unset or relative.
    HomeUnresolved,
}

impl std::fmt::Display for WarmDirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RelativeOverride => write!(
                f,
                "{WARM_DIR_ENV} must be an absolute path; pass --warm <dir> or set it absolute"
            ),
            Self::HomeUnresolved => write!(
                f,
                "cannot locate the warm cache: HOME is unset or relative and {WARM_DIR_ENV} \
                 is unset; pass --warm <dir> or set {WARM_DIR_ENV}"
            ),
        }
    }
}

fn resolve_warm_dir() -> Result<PathBuf, WarmDirError> {
    resolve_warm_dir_from(
        ipe_env::var_os(WARM_DIR_ENV),
        ipe_sandbox::home::home_dir().ok().as_ref(),
    )
}

/// Resolve the warm-cache directory, refusing any cwd-relative spelling.
///
/// An empty override counts as unset.
fn resolve_warm_dir_from(
    raw: Option<std::ffi::OsString>,
    home: Option<&ipe_sandbox::home::HomeDir>,
) -> Result<PathBuf, WarmDirError> {
    if let Some(value) = raw.filter(|value| !value.is_empty()) {
        let path = PathBuf::from(value);
        return if path.is_absolute() {
            Ok(path)
        } else {
            Err(WarmDirError::RelativeOverride)
        };
    }
    home.map(|home| home.join(DEFAULT_WARM_DIR))
        .ok_or(WarmDirError::HomeUnresolved)
}

/// The jailed pipeline. Returns the JSON outcome; never panics.
/// Pin the dependency graph before building: with `Cargo.lock` present,
/// `cargo build --offline` never re-resolves from the registry index, so the
/// jail's cargo cannot prune sparse-index cache entries (hard-linked from the
/// warm cache during seeding — observed: entries for the direct dependencies
/// vanished from the project's seeded index after a jailed build, leaving
/// later runs with "no matching package named `X` found" resolution errors).
/// The lock is the warm template's own lock: the emitted `Cargo.toml` is a
/// fixed template, so the graph is identical for every submitted program.
fn provision_lock(project_dir: &Path, warm_dir: &Path) -> Option<Outcome> {
    if project_dir.join("Cargo.lock").is_file() {
        return None;
    }
    let warm_lock = warm_dir.join("Cargo.lock");
    if !warm_lock.is_file() {
        return Some(Outcome::failure(format!(
            "warm cache has no Cargo.lock at {} — re-run `jail-runner prewarm`",
            warm_lock.display()
        )));
    }
    if let Err(error) = std::fs::copy(&warm_lock, project_dir.join("Cargo.lock")) {
        return Some(Outcome::failure(format!(
            "failed to copy warm Cargo.lock: {error}"
        )));
    }
    None
}

fn run_project(project_dir: &Path, warm_dir: &Path) -> Outcome {
    let manifest = project_dir.join("Cargo.toml");
    let entry = project_dir.join("src/main.rs");
    if !manifest.is_file() || !entry.is_file() {
        return Outcome::failure("project dir is missing Cargo.toml or src/main.rs");
    }
    let warm_cargo_home = warm_dir.join("cargo-home");
    let warm_target = warm_dir.join("crate-target");
    if !warm_cargo_home.is_dir() || !warm_target.is_dir() {
        return Outcome::failure(format!(
            "warm cache missing at {} — run `jail-runner prewarm` first",
            warm_dir.display()
        ));
    }
    if let Some(outcome) = provision_lock(project_dir, warm_dir) {
        return outcome;
    }

    let caps = match probe_or_refuse() {
        Ok(caps) => caps,
        Err(refusal) => {
            if unsandboxed_override_set() {
                eprintln!(
                    "[jail-runner] WARNING: IPE_FFI_ALLOW_UNSANDBOXED=1 — running the \
                     submitted program WITHOUT a jail. This is a trust boundary breach; \
                     only use it on a throwaway host."
                );
                return run_unsandboxed(project_dir);
            }
            return Outcome::failure(format!("sandbox unavailable: {}", refusal.reason));
        }
    };

    if let Err(defect) = seed_cargo_home(project_dir, &warm_cargo_home) {
        return Outcome::failure(format!("failed to seed cargo home: {defect}"));
    }
    if let Err(defect) = seed_target_dir(project_dir, &warm_target) {
        return Outcome::failure(format!("failed to seed target dir: {defect}"));
    }

    let build = match jailed_build(&caps, project_dir) {
        Ok(build) => build,
        Err(defect) => return Outcome::failure(format!("jail build failed: {defect}")),
    };
    let build_json = PhaseJson::from(build.clone());
    if build.killed {
        return Outcome {
            ok: false,
            unsandboxed: false,
            build: Some(build_json),
            run: None,
            exit: None,
            error: Some("build phase hit its wall-clock limit".to_owned()),
        };
    }
    if build.status != Some(0) {
        return Outcome {
            ok: false,
            unsandboxed: false,
            build: Some(build_json),
            run: None,
            exit: None,
            error: Some("build phase failed (non-zero exit)".to_owned()),
        };
    }

    let binary = app_binary_path(project_dir);
    if !binary.is_file() {
        return Outcome {
            ok: false,
            unsandboxed: false,
            build: Some(build_json),
            run: None,
            exit: None,
            error: Some("build reported success but produced no `ipe-app` binary".to_owned()),
        };
    }

    let run = match jailed_run(&caps, project_dir, &binary) {
        Ok(run) => run,
        Err(defect) => return Outcome::failure(format!("jail run failed: {defect}")),
    };
    Outcome {
        ok: true,
        unsandboxed: false,
        build: Some(build_json),
        run: Some(PhaseJson::from(run.clone())),
        exit: run.status,
        error: None,
    }
}

/// The `IPE_FFI_ALLOW_UNSANDBOXED=1` escape hatch: same phases, plain
/// subprocesses, output capped, wall-clock still enforced by the watchdog.
fn run_unsandboxed(project_dir: &Path) -> Outcome {
    let build = match run_captured(
        &mut cargo_build_cmd(project_dir),
        UNSANDBOXED_OUTPUT_CAP_BYTES,
    ) {
        Ok(build) => build,
        Err(message) => return Outcome::failure(message),
    };
    let build_json = PhaseJson {
        status: build.status,
        stdout: build.stdout.clone(),
        stderr: build.stderr.clone(),
        killed: false,
    };
    if build.status != Some(0) {
        return Outcome {
            ok: false,
            unsandboxed: true,
            build: Some(build_json),
            run: None,
            exit: None,
            error: Some("build phase failed (non-zero exit)".to_owned()),
        };
    }

    let binary = app_binary_path(project_dir);
    let run = match run_captured(&mut Command::new(&binary), UNSANDBOXED_OUTPUT_CAP_BYTES) {
        Ok(run) => run,
        Err(message) => return Outcome::failure(message),
    };
    Outcome {
        ok: true,
        unsandboxed: true,
        build: Some(build_json),
        run: Some(PhaseJson {
            status: run.status,
            stdout: run.stdout,
            stderr: run.stderr,
            killed: false,
        }),
        exit: run.status,
        error: None,
    }
}

struct Captured {
    status: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Bounded capture: each stream is kept up to `cap_bytes + 1` so oversize
/// output is truncated but still distinguishable from an exact fit.
///
/// The rest of the stream is read and discarded, so a child writing past the
/// cap never blocks on a full pipe.
fn read_capped<R: std::io::Read>(mut stream: R, cap_bytes: u64) -> String {
    let mut buf = Vec::new();
    let _ = stream
        .by_ref()
        .take(cap_bytes.saturating_add(1))
        .read_to_end(&mut buf);
    let _ = std::io::copy(&mut stream, &mut std::io::sink());
    String::from_utf8_lossy(&buf).into_owned()
}

fn run_captured(cmd: &mut Command, cap_bytes: u64) -> Result<Captured, String> {
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null());
    let mut child = cmd.spawn().map_err(|error| {
        format!(
            "failed to spawn {}: {error}",
            cmd.get_program().to_string_lossy()
        )
    })?;
    // stderr drains on its own thread while stdout drains here: reading one
    // stream to EOF before the other deadlocks a child that fills the second
    // stream's pipe first.
    let stderr_drain = match child.stderr.take() {
        Some(stream) => {
            match thread::Builder::new()
                .name("jail-runner-stderr".to_owned())
                .spawn(move || read_capped(stream, cap_bytes))
            {
                Ok(handle) => Some(handle),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "failed to start the stderr drain for {}: {:?}",
                        cmd.get_program().to_string_lossy(),
                        error.kind()
                    ));
                }
            }
        }
        None => None,
    };
    let stdout = child
        .stdout
        .take()
        .map_or_else(String::new, |stream| read_capped(stream, cap_bytes));
    let stderr = stderr_drain
        .map(|handle| handle.join().unwrap_or_default())
        .unwrap_or_default();
    let status = child.wait().map_err(|error| {
        format!(
            "failed to wait on {}: {error}",
            cmd.get_program().to_string_lossy()
        )
    })?;
    Ok(Captured {
        status: status.code(),
        stdout,
        stderr,
    })
}

fn cargo_build_cmd(project_dir: &Path) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(project_dir.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(project_dir.join("crate-target"))
        .env("CARGO_TERM_PROGRESS_WHEN", "never");
    cmd
}

/// Build the embedded hello project into the warm cache so `--offline`
/// jailed builds can resolve the crate template's dependency closure.
fn prewarm(warm_dir: &Path) -> Outcome {
    let warm_cargo_home = warm_dir.join("cargo-home");
    let warm_target = warm_dir.join("crate-target");
    if let Err(error) = std::fs::create_dir_all(&warm_cargo_home) {
        return Outcome::failure(format!(
            "failed to create warm cargo home {}: {error}",
            warm_cargo_home.display()
        ));
    }
    if let Err(error) = std::fs::create_dir_all(&warm_target) {
        return Outcome::failure(format!(
            "failed to create warm target {}: {error}",
            warm_target.display()
        ));
    }

    let scratch = match ipe_sandbox::scratch::ScratchDir::new("ipe-playground-prewarm") {
        Ok(scratch) => scratch,
        Err(error) => return Outcome::failure(format!("failed to create scratch dir: {error}")),
    };
    let src_dir = scratch.path().join("src");
    if let Err(error) = std::fs::create_dir_all(&src_dir) {
        return Outcome::failure(format!("failed to create scratch src dir: {error}"));
    }
    let manifest = include_str!("crate_template/Cargo.toml");
    let hello = include_str!("crate_template/main.rs");
    if let Err(error) = std::fs::write(scratch.path().join("Cargo.toml"), manifest) {
        return Outcome::failure(format!("failed to stage template Cargo.toml: {error}"));
    }
    if let Err(error) = std::fs::write(src_dir.join("main.rs"), hello) {
        return Outcome::failure(format!("failed to stage template main.rs: {error}"));
    }

    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("--manifest-path")
        .arg(scratch.path().join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&warm_target)
        .env("CARGO_HOME", &warm_cargo_home)
        .env("CARGO_TERM_PROGRESS_WHEN", "never");
    match run_captured(&mut cmd, UNSANDBOXED_OUTPUT_CAP_BYTES) {
        Ok(captured) if captured.status == Some(0) => {
            // Save the resolved lockfile: `run` copies it into each project so
            // the jailed cargo never re-resolves from the registry index.
            let lock_src = scratch.path().join("Cargo.lock");
            let lock_dst = warm_dir.join("Cargo.lock");
            if !lock_src.is_file() {
                return Outcome::failure("prewarm build produced no Cargo.lock");
            }
            if let Err(error) = std::fs::copy(&lock_src, &lock_dst) {
                return Outcome::failure(format!(
                    "failed to save warm Cargo.lock to {}: {error}",
                    lock_dst.display()
                ));
            }
            Outcome {
                ok: true,
                unsandboxed: false,
                build: None,
                run: None,
                exit: None,
                error: None,
            }
        }
        Ok(captured) => Outcome::failure(format!(
            "prewarm build failed: {}",
            tail(&captured.stderr, 2000)
        )),
        Err(message) => Outcome::failure(format!("prewarm build error: {message}")),
    }
}

/// The last `max_bytes` of `text` at most, cut forward to a char boundary.
fn tail(text: &str, max_bytes: usize) -> String {
    let Some(cut) = text.len().checked_sub(max_bytes).filter(|cut| *cut > 0) else {
        return text.to_owned();
    };
    let kept = (cut..=text.len())
        .find(|at| text.is_char_boundary(*at))
        .and_then(|at| text.get(at..))
        .unwrap_or_default();
    format!("…{kept}")
}

/// Which writer owns stdout: the run's own outcome or the watchdog's timeout.
///
/// Exactly one document reaches stdout per process, whichever side claims
/// first, so the server never reads two outcomes or one cut short by the
/// other's exit.
struct OutcomeClaim(AtomicBool);

impl OutcomeClaim {
    const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Whether this caller is the first, and so the one that writes.
    fn claim(&self) -> bool {
        !self.0.swap(true, Ordering::SeqCst)
    }
}

static OUTCOME_CLAIM: OutcomeClaim = OutcomeClaim::new();

/// Print `outcome` under `claim`; `true` once the whole document is written.
///
/// When the watchdog has claimed stdout first, this thread waits for the
/// watchdog's exit rather than return and end the process mid-document.
#[must_use]
fn emit_outcome(claim: &OutcomeClaim, outcome: &Outcome) -> bool {
    if !claim.claim() {
        loop {
            thread::park();
        }
    }
    write_claimed_outcome(outcome)
}

/// Write `outcome` to stdout; the caller holds the claim. `false` when the
/// document could not be written, so the caller never exits `0` without one.
#[must_use]
fn write_claimed_outcome(outcome: &Outcome) -> bool {
    match write_outcome(&mut std::io::stdout().lock(), outcome) {
        Ok(()) => true,
        Err(error) => {
            eprintln!("[jail-runner] fatal: failed to write the outcome: {error}");
            false
        }
    }
}

/// `outcome` as one JSON line on `out`, flushed.
///
/// # Errors
/// The serialization or I/O error, e.g. a closed stdout pipe.
fn write_outcome(out: &mut impl Write, outcome: &Outcome) -> std::io::Result<()> {
    serde_json::to_writer(&mut *out, outcome)?;
    out.write_all(b"\n")?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_WARM_DIR, Outcome, OutcomeClaim, WarmDirError, cmd_run_with, resolve_warm_dir_from,
        run_captured, tail, write_outcome,
    };
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::mpsc;
    use std::time::Duration;

    /// Runs `cmd` through `run_captured` on a helper thread, failing the test
    /// rather than hanging when the capture does not return.
    fn capture_within(mut cmd: Command, cap_bytes: u64) -> super::Captured {
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("capture-test".to_owned())
            .spawn(move || {
                let _ = tx.send(run_captured(&mut cmd, cap_bytes));
            })
            .expect("test thread starts");
        rx.recv_timeout(Duration::from_secs(60))
            .expect("run_captured must return, not deadlock on a full pipe")
            .expect("the child runs")
    }

    #[test]
    fn a_child_filling_stderr_first_is_captured_without_deadlock() {
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg("head -c 300000 /dev/zero | tr '\\0' e 1>&2; echo done");
        let captured = capture_within(cmd, 1024 * 1024);
        assert_eq!(captured.stdout, "done\n");
        assert_eq!(captured.stderr.len(), 300_000);
    }

    #[test]
    fn a_child_writing_past_the_cap_still_runs_to_exit() {
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg("head -c 300000 /dev/zero | tr '\\0' o; exit 3");
        let captured = capture_within(cmd, 1000);
        assert_eq!(captured.stdout.len(), 1001);
        assert_eq!(captured.status, Some(3));
    }

    #[test]
    fn a_tail_cut_inside_a_char_moves_to_its_boundary() {
        // Each `é` is two bytes, so a 3-byte tail starts inside one.
        assert_eq!(tail("éééé", 3), "…é");
        assert_eq!(tail("éé", 4), "éé");
        assert_eq!(tail("abc", 2), "…bc");
    }

    #[test]
    fn a_refused_watchdog_stops_the_run_before_any_build() {
        static CLAIM: OutcomeClaim = OutcomeClaim::new();
        let staged = tempfile::tempdir_in(ipe_test_temp::temp_root()).expect("tempdir");
        let project = staged.path().join("project");
        std::fs::create_dir(&project).expect("project dir");
        let args = vec![
            project.display().to_string(),
            "--warm".to_owned(),
            staged.path().join("warm").display().to_string(),
        ];
        let code = cmd_run_with(&args, &CLAIM, |_, _, _| {
            Err(std::io::Error::other("refused"))
        });
        assert_eq!(code, 2, "a refused watchdog must fail the run closed");
        assert!(
            !project.exists(),
            "the staged project is cleaned up when the run is refused"
        );
        assert!(
            !CLAIM.claim(),
            "the refusal document is written through the stdout claim"
        );
    }

    /// With stdout already claimed (the watchdog's timeout document), the
    /// refusal neither writes a second document nor returns an exit code.
    #[test]
    fn a_refusal_after_the_watchdog_claimed_stdout_never_writes_or_returns() {
        static CLAIM: OutcomeClaim = OutcomeClaim::new();
        assert!(CLAIM.claim());
        let staged = tempfile::tempdir_in(ipe_test_temp::temp_root()).expect("tempdir");
        let project = staged.path().join("project");
        std::fs::create_dir(&project).expect("project dir");
        let args = vec![
            project.display().to_string(),
            "--warm".to_owned(),
            staged.path().join("warm").display().to_string(),
        ];
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("claimed-refusal-test".to_owned())
            .spawn(move || {
                let code = cmd_run_with(&args, &CLAIM, |_, _, _| {
                    Err(std::io::Error::other("refused"))
                });
                let _ = tx.send(code);
            })
            .expect("test thread starts");
        assert!(
            rx.recv_timeout(Duration::from_millis(500)).is_err(),
            "a run that lost the claim must park, not return an exit code"
        );
        assert!(
            project.exists(),
            "the losing side leaves cleanup to the watchdog that owns the exit"
        );
    }

    /// A cut inside a multi-byte char moves forward to the next boundary
    /// instead of splitting the char.
    #[test]
    fn tail_cuts_on_a_char_boundary() {
        assert_eq!(tail("abc", 3), "abc");
        assert_eq!(tail("aé", 1), "…");
        assert_eq!(tail("aéb", 2), "…b");
        assert_eq!(tail("aéb", 3), "…éb");
        assert_eq!(tail("ab", 0), "…");
    }

    /// A stdout that refuses the write is an error, never a panic.
    #[test]
    fn a_closed_stdout_is_a_write_error() {
        struct Closed;
        impl std::io::Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let outcome = Outcome::failure("x");
        assert!(write_outcome(&mut Closed, &outcome).is_err());
        let mut out = Vec::new();
        assert!(write_outcome(&mut out, &outcome).is_ok());
        let body = out.strip_suffix(b"\n");
        assert!(
            body.is_some_and(|body| !body.contains(&b'\n')),
            "one newline-terminated line: {out:?}"
        );
    }

    /// Only the first claimant writes the outcome.
    #[test]
    fn the_outcome_is_claimed_once() {
        let claim = OutcomeClaim::new();
        assert!(claim.claim());
        assert!(!claim.claim());
    }

    /// The home the parser makes of the raw value `raw`, when it accepts one.
    fn parsed(raw: &str) -> Option<ipe_sandbox::home::HomeDir> {
        ipe_sandbox::home::HomeDir::try_parse(Some(raw.into())).ok()
    }

    #[test]
    fn a_missing_home_without_an_override_is_refused() {
        assert_eq!(
            resolve_warm_dir_from(None, None),
            Err(WarmDirError::HomeUnresolved)
        );
        assert_eq!(
            resolve_warm_dir_from(Some(OsString::new()), None),
            Err(WarmDirError::HomeUnresolved)
        );
        assert_eq!(
            resolve_warm_dir_from(None, parsed("relative/home").as_ref()),
            Err(WarmDirError::HomeUnresolved)
        );
    }

    #[test]
    fn a_relative_override_is_refused() {
        assert_eq!(
            resolve_warm_dir_from(Some(OsString::from("warm")), parsed("/home/u").as_ref()),
            Err(WarmDirError::RelativeOverride)
        );
    }

    #[test]
    fn an_absolute_override_or_home_resolves() {
        assert_eq!(
            resolve_warm_dir_from(Some(OsString::from("/srv/warm")), None),
            Ok(PathBuf::from("/srv/warm"))
        );
        assert_eq!(
            resolve_warm_dir_from(None, parsed("/home/u").as_ref()),
            Ok(PathBuf::from("/home/u").join(DEFAULT_WARM_DIR))
        );
    }
}
