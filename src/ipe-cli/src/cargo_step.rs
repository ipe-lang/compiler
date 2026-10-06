//! The one owner of every `cargo` child the CLI spawns to build a crate,
//! resolve its lock, or read its target directory.
//!
//! A cargo build is described as a typed value — the crate it builds, its
//! profile, its target and its output mode — and this module alone turns that
//! value into a `Command`: the `build` subcommand, the flags, the environment,
//! the lockfile policy, the pipe drains and the reap. No other module builds
//! a cargo `build` command (`tests/cargo_step_scan.rs` holds the inventory), so
//! every command path gets the same environment, the same drains and the same
//! lifetime for its cargo child.
//!
//! Both pipes of a child are drained on threads scoped to the call that spawned
//! it, so no drain outlives the build and the child is always reaped before the
//! call returns, on success and on every error. Every captured pipe has a
//! declared byte ceiling: a drain keeps reading to the end of the stream (so
//! cargo never stalls on a full pipe) but stops storing at the ceiling.
//!
//! Every cargo child starts through `spawn_cargo`, so a build script never
//! inherits a descriptor the CLI holds open and, on Linux, never outlives the
//! CLI. A `cargo build` carries no wall: it runs as long as the user's build
//! takes.

use std::io::{BufReader, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};

use ipe_backend_rust::static_build::StaticTriple;

use crate::output_dir::OwnedDir;
use crate::remote_ingest::{
    LOCK_FETCH_LIMITS, LOCK_RESOLVE_LIMITS, LocalCeiling, LocalRefusal, LocalSource,
    METADATA_LIMITS, RunError, run_local,
};
use crate::style::TerminalSafe;
use crate::toolchain::CargoBin;
use crate::watch::{BuildAccel, apply_build_accel_env};
use crate::{CliError, RuntimeContext, text};

/// Bytes of a build's `--message-format=json` stdout kept; a longer stream
/// fails the build, since the stream is the record of the artifacts cargo wrote.
pub const ARTIFACT_STREAM_CAP: usize = 64 * 1024 * 1024;

/// Bytes of cargo's stderr kept for a failure diagnostic. The live relay of a
/// build forwards every byte; only the kept copy stops here, at a chunk
/// boundary, so the diagnostic shows the first errors cargo reported.
pub const STDERR_KEEP_CAP: usize = 1024 * 1024;

/// The cargo build profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CargoProfile {
    /// cargo's default `dev` profile (a debug binary).
    Dev,
    /// `--release`.
    Release,
}

/// The target a cargo build compiles for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CargoTarget {
    /// The host triple: no `--target` flag.
    Host,
    /// A statically linked target triple (`--target <triple>`).
    Static(StaticTriple),
    /// The browser bundle, `wasm32-unknown-unknown`.
    WasmBrowser,
    /// A WASI module, `wasm32-wasip1`.
    ///
    /// The emitted crate ships its own `.cargo/config.toml` linker override for
    /// this target, which an ambient `RUSTFLAGS`/`CARGO_ENCODED_RUSTFLAGS`
    /// would outrank, so both are cleared from the child.
    Wasip1,
}

impl CargoTarget {
    /// The `--target` triple, or `None` for the host.
    const fn triple(self) -> Option<&'static str> {
        match self {
            Self::Host => None,
            Self::Static(triple) => Some(triple.as_str()),
            Self::WasmBrowser => Some("wasm32-unknown-unknown"),
            Self::Wasip1 => Some("wasm32-wasip1"),
        }
    }
}

/// How much of cargo's own progress a build shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
    /// cargo's terminal UI (colour and the progress bar when stderr is a
    /// terminal), plus the dependency-resolve stage.
    Progress,
    /// cargo's `-q`; no dependency-resolve stage.
    Quiet,
}

impl Verbosity {
    /// [`Self::Quiet`] when a command's `--quiet` is set, else [`Self::Progress`].
    #[must_use]
    pub const fn of_quiet(quiet: bool) -> Self {
        if quiet { Self::Quiet } else { Self::Progress }
    }
}

/// Where a build's stdout goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CargoOutput {
    /// stdout inherited; a `cargo build` writes only status, to stderr.
    Human(Verbosity),
    /// `--message-format=json`: stdout is captured (up to
    /// [`ARTIFACT_STREAM_CAP`]) and handed back, the one authoritative record
    /// of the artifacts cargo wrote.
    JsonStream(Verbosity),
}

impl CargoOutput {
    /// The verbosity of either mode.
    const fn verbosity(self) -> Verbosity {
        match self {
            Self::Human(verbosity) | Self::JsonStream(verbosity) => verbosity,
        }
    }
}

/// The app binary and profile a release wrapper embeds.
#[derive(Debug, Clone, Copy)]
pub struct EmbeddedApp<'a> {
    /// The built app binary.
    pub binary: &'a Path,
    /// The app's `ipe.profile`.
    pub profile: &'a Path,
}

/// The crate a blocking cargo build compiles.
#[derive(Debug, Clone, Copy)]
pub enum CargoCrate<'a> {
    /// A crate ipe emitted into a claimed directory, proven that directory
    /// before cargo starts and again after it succeeds: cargo reaches it by
    /// path, so a swap while it runs is detected, never trusted.
    Emitted(&'a OwnedDir),
    /// The `ipe_wrapper` package of the verified compiler workspace `source`,
    /// a tree ipe does not own, so no output claim is proven.
    ReleaseWrapper {
        /// The verified workspace holding the `ipe_wrapper` package.
        source: &'a crate::wrapper_source::WrapperSource,
        /// The app the wrapper embeds, when the release is a single file.
        embed: Option<EmbeddedApp<'a>>,
    },
}

/// Which `Cargo.lock` a blocking build replays with `--locked`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockPolicy {
    /// Resolve the graph once into the crate's own fresh lock, then replay it:
    /// an emitted crate has no lock of its own.
    Regenerate,
    /// Replay the lock the tree already commits; never rewrite it, since ipe
    /// does not own that tree.
    Committed,
}

impl CargoCrate<'_> {
    /// The lock this crate's build replays.
    const fn lock_policy(&self) -> LockPolicy {
        match self {
            Self::Emitted(_) => LockPolicy::Regenerate,
            Self::ReleaseWrapper { .. } => LockPolicy::Committed,
        }
    }
}

/// One blocking `cargo build`: [`CargoBuild::run`] spawns it and returns once
/// cargo has exited and both pipes are drained.
#[derive(Debug, Clone)]
pub struct CargoBuild<'a> {
    /// The resolved `cargo`.
    pub cargo: &'a CargoBin,
    /// The crate to build; cargo runs with it as its working directory.
    pub krate: CargoCrate<'a>,
    /// The build profile.
    pub profile: CargoProfile,
    /// The compile target.
    pub target: CargoTarget,
    /// Where stdout goes, and how much progress shows.
    pub output: CargoOutput,
    /// What is built, named in the failure diagnostic.
    pub what: &'static str,
    /// The runtime crate the build links against, when resolved.
    pub runtime: Option<RuntimeContext>,
}

impl CargoBuild<'_> {
    /// The directory cargo runs in.
    fn dir(&self) -> &Path {
        match self.krate {
            CargoCrate::Emitted(dir) => dir.path(),
            CargoCrate::ReleaseWrapper { source, .. } => source.root(),
        }
    }

    /// The `cargo build` command, before the lockfile flag and the pipes.
    fn command(&self) -> Command {
        let mut cmd = build_command(
            self.cargo.path(),
            self.dir(),
            self.profile,
            self.target,
            self.output,
        );
        if let CargoCrate::ReleaseWrapper { embed, .. } = self.krate {
            cmd.args(["--package", "ipe_wrapper"]);
            if let Some(app) = embed {
                // The wrapper's `build.rs` copies these into `OUT_DIR` and
                // enables its `embed_mode` cfg.
                cmd.env("IPE_EMBED_APP", app.binary)
                    .env("IPE_EMBED_PROFILE", app.profile);
            }
        }
        cmd
    }

    /// Build against a pinned dependency graph and return the captured stdout
    /// (empty for [`CargoOutput::Human`]).
    ///
    /// Every build passes `--locked`, so a transitive point release cannot
    /// change a build with no source change, and any lock-to-manifest drift
    /// fails at `ipe` time. An emitted crate first resolves once into its own
    /// `Cargo.lock`; the release wrapper replays the workspace's committed
    /// lock and never rewrites it. stderr is relayed live, indented one shared
    /// column, and kept unindented (up to [`STDERR_KEEP_CAP`]) for the failure
    /// diagnostic.
    ///
    /// # Errors
    /// - [`CliError::Io`] if cargo cannot be spawned, waited on, or read, or
    ///   its artifact stream passes [`ARTIFACT_STREAM_CAP`].
    /// - [`CliError::EmittedBuildFailed`] if the resolve or the build exits
    ///   non-zero.
    /// - [`CliError::OutputRefused`] if an [`CargoCrate::Emitted`] directory
    ///   was replaced before or while cargo ran.
    pub fn run(&self) -> Result<String, CliError> {
        if let CargoCrate::Emitted(dir) = self.krate {
            dir.verify()?;
        }
        let dir = self.dir();
        let io_err = |source: std::io::Error| CliError::Io {
            path: dir.to_path_buf(),
            source,
        };
        let mut cmd = self.command();
        if self.krate.lock_policy() == LockPolicy::Regenerate {
            lock_dependencies(&cmd, dir, self.output.verbosity())?;
        }
        cmd.arg("--locked");
        let drained = run_to_exit(cmd, ARTIFACT_STREAM_CAP).map_err(io_err)?;
        let stdout = self.verdict(drained)?;
        if let CargoCrate::Emitted(dir) = self.krate {
            dir.verify()?;
        }
        Ok(stdout)
    }

    /// The build's captured stdout, or why the drained build failed.
    ///
    /// A stderr that could not be read outranks a non-zero exit, so a partial
    /// stderr is never rendered as the build's diagnostic.
    fn verdict(&self, drained: Drained<ExitStatus>) -> Result<String, CliError> {
        let io_err = |source: std::io::Error| CliError::Io {
            path: self.dir().to_path_buf(),
            source,
        };
        if let Some(e) = drained.stderr.error {
            return Err(io_err(e));
        }
        let status = drained.waited;
        if !status.success() {
            return Err(CliError::EmittedBuildFailed {
                what: self.what,
                code: status.code().unwrap_or(1),
                stderr: TerminalSafe::sanitize(&drained.stderr.text),
                runtime: self.runtime.clone(),
            });
        }
        if let Some(e) = drained.stdout.error {
            return Err(io_err(e));
        }
        Ok(drained.stdout.text)
    }
}

/// The directory cargo writes `crate_dir`'s build output to, read from
/// `cargo metadata --no-deps` (it honours `CARGO_TARGET_DIR` and any config
/// relocation).
///
/// The child runs under [`METADATA_LIMITS`] with stdin closed.
///
/// # Errors
/// - [`CliError::LocalLimitExceeded`] if cargo crosses a ceiling (its document
///   is refused whole, never parsed truncated); its process group is killed.
/// - [`CliError::Io`] if cargo cannot be spawned or waited on.
/// - [`CliError::ChildPipeHeld`] if a process cargo started holds a pipe open.
/// - [`CliError::Usage`] if it exits non-zero or its document is not JSON or
///   carries no target directory.
pub fn target_directory(cargo: &CargoBin, crate_dir: &Path) -> Result<PathBuf, CliError> {
    target_directory_within(cargo, crate_dir, METADATA_LIMITS)
}

/// [`target_directory`] held to `ceiling`.
fn target_directory_within(
    cargo: &CargoBin,
    crate_dir: &Path,
    ceiling: LocalCeiling,
) -> Result<PathBuf, CliError> {
    let mut cmd = Command::new(cargo.path());
    cmd.args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(crate_dir);
    let captured = run_local(cmd, ceiling, LocalSource::CargoMetadata)
        .map_err(|e| local_run_error(crate_dir, e))?;
    if !captured.status.success() {
        return Err(CliError::Usage(text::msg::cargo_metadata_failed(
            &crate_dir.display(),
            &captured.stderr.to_terminal(),
        )));
    }
    let meta: serde_json::Value = serde_json::from_slice(&captured.stdout)
        .map_err(|e| CliError::Usage(text::msg::cargo_metadata_unparsable(&e)))?;
    meta.get("target_directory")
        .and_then(serde_json::Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| CliError::Usage(text::msg::cargo_metadata_no_target_dir()))
}

/// One `ipe dev watch` rebuild: [`WatchBuild::spawn`] starts it and returns at
/// once, so the watch loop can kill a superseded build.
///
/// A watch rebuild passes no `--locked`: the emitted crate's dependencies
/// change with the program's imports between rebuilds, so cargo keeps the
/// session's `Cargo.lock` and extends it only when the manifest asks for a
/// crate it does not pin, rather than re-resolving on every rebuild.
pub struct WatchBuild<'a> {
    /// The `cargo` to run ([`crate::watch::WatchOptions::cargo_path`]).
    pub cargo: &'a Path,
    /// The emitted crate, proven to carry the development marker; cargo runs
    /// with it as its working directory.
    pub krate: crate::DevMarkedCrate<'a>,
    /// A target directory overriding the inherited `CARGO_TARGET_DIR`.
    pub target_dir: Option<&'a Path>,
    /// The compiler acceleration for this rebuild.
    pub accel: &'a BuildAccel,
    /// How much of cargo's progress shows.
    pub verbosity: Verbosity,
}

impl WatchBuild<'_> {
    /// The rebuild's `cargo build --message-format=json` command.
    fn command(&self) -> Command {
        let mut cmd = build_command(
            self.cargo,
            self.krate.path(),
            CargoProfile::Dev,
            CargoTarget::Host,
            CargoOutput::JsonStream(self.verbosity),
        );
        if let Some(target) = self.target_dir {
            cmd.env("CARGO_TARGET_DIR", target);
        }
        apply_build_accel_env(&mut cmd, self.accel);
        cmd
    }

    /// Spawn the rebuild, its pipes taken for [`CargoPipes::drain_while`].
    ///
    /// # Errors
    /// The spawn error when cargo cannot be started, or the refusal of
    /// `spawn_cargo`.
    pub fn spawn(&self) -> std::io::Result<(Child, CargoPipes)> {
        let mut child = spawn_cargo(self.command())?;
        let pipes = CargoPipes::take(&mut child, ARTIFACT_STREAM_CAP);
        Ok((child, pipes))
    }
}

/// The `cargo build` every build kind shares: program, subcommand, working
/// directory, profile, target, output mode and terminal UI.
fn build_command(
    cargo: &Path,
    dir: &Path,
    profile: CargoProfile,
    target: CargoTarget,
    output: CargoOutput,
) -> Command {
    let mut cmd = Command::new(cargo);
    cmd.arg("build").current_dir(dir);
    if profile == CargoProfile::Release {
        cmd.arg("--release");
    }
    if let Some(triple) = target.triple() {
        cmd.args(["--target", triple]);
    }
    if target == CargoTarget::Wasip1 {
        cmd.env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS");
    }
    match output {
        CargoOutput::Human(_) => {
            cmd.stdout(Stdio::inherit());
        }
        CargoOutput::JsonStream(_) => {
            cmd.arg("--message-format=json").stdout(Stdio::piped());
        }
    }
    cmd.stderr(Stdio::piped());
    match output.verbosity() {
        Verbosity::Quiet => {
            cmd.arg("-q");
        }
        Verbosity::Progress => crate::force_cargo_terminal_ui(&mut cmd),
    }
    cmd
}

/// Start a `cargo build` child through the runtime's hardened spawner.
///
/// The child inherits no descriptor beyond its three standard streams and, on
/// Linux, dies with the CLI. No wall is set.
///
/// # Errors
/// The spawn refusal, as an I/O error, when the spawner is unavailable, this
/// host does not list its open descriptors, or cargo cannot be started.
fn spawn_cargo(cmd: Command) -> std::io::Result<Child> {
    ipe_runtime_rust::system::spawn_hardened(cmd).map_err(std::io::Error::from)
}

/// Spawn `cmd`, drain its pipes while waiting on it, and return its exit
/// status with both drains; the child is reaped before this returns.
fn run_to_exit(cmd: Command, stdout_cap: usize) -> std::io::Result<Drained<ExitStatus>> {
    let mut child = spawn_cargo(cmd)?;
    let pipes = CargoPipes::take(&mut child, stdout_cap);
    let Drained {
        waited,
        stdout,
        stderr,
    } = pipes.drain_while(|| child.wait());
    Ok(Drained {
        waited: waited?,
        stdout,
        stderr,
    })
}

/// Resolve the crate's dependency graph once into its own `Cargo.lock`, with
/// the build command's program, directory and environment, so the lock comes
/// from the toolchain that consumes it.
///
/// The resolve may fetch the registry index, so it runs under
/// [`LOCK_FETCH_LIMITS`]. It is the one silent gap before cargo's own progress
/// starts, so a [`Verbosity::Progress`] build covers it with a stage, settled
/// before the relay starts. Its stderr is kept for the failure diagnostic,
/// never relayed.
///
/// # Errors
/// - [`CliError::LocalLimitExceeded`] if the resolve crosses a ceiling.
/// - [`CliError::Io`] if the resolve cannot be spawned or waited on.
/// - [`CliError::ChildPipeHeld`] if a process it started holds a pipe open.
/// - [`CliError::EmittedBuildFailed`] if it exits non-zero (the registry
///   unreachable, for one).
fn lock_dependencies(build: &Command, dir: &Path, verbosity: Verbosity) -> Result<(), CliError> {
    lock_dependencies_within(build, dir, verbosity, LOCK_FETCH_LIMITS)
}

/// [`lock_dependencies`] held to `ceiling`.
fn lock_dependencies_within(
    build: &Command,
    dir: &Path,
    verbosity: Verbosity,
    ceiling: LocalCeiling,
) -> Result<(), CliError> {
    let stage = (verbosity == Verbosity::Progress).then(|| {
        crate::progress::Stage::start(
            std::io::stderr(),
            "resolving the emitted crate's dependencies…",
        )
    });
    let mut lock = Command::new(build.get_program());
    lock.arg("generate-lockfile").current_dir(dir);
    for (key, val) in build.get_envs() {
        match val {
            Some(v) => lock.env(key, v),
            None => lock.env_remove(key),
        };
    }
    let resolved = match run_local(lock, ceiling, LocalSource::LockFetch) {
        Ok(captured) if captured.status.success() => Ok(()),
        Ok(captured) => Err(CliError::EmittedBuildFailed {
            what: "the emitted crate's dependency lockfile",
            code: captured.status.code().unwrap_or(1),
            stderr: captured.stderr.to_terminal(),
            runtime: None,
        }),
        Err(e) => Err(local_run_error(dir, e)),
    };
    if let Some(stage) = stage {
        if resolved.is_ok() {
            stage.success("dependencies resolved");
        } else {
            stage.failure("dependency resolution failed");
        }
    }
    resolved
}

/// How an offline `cargo generate-lockfile` that ran within its ceilings ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockOutcome {
    /// cargo exited zero: the lock is written.
    Resolved,
    /// cargo exited non-zero, or was ended by a signal (`code` is `None`).
    Unresolved {
        /// cargo's exit code, when it exited.
        code: Option<i32>,
    },
}

/// Resolve `manifest`'s dependency graph into its `Cargo.lock` offline, from the local registry cache.
///
/// The child runs under [`LOCK_RESOLVE_LIMITS`] with stdin closed. A
/// non-zero exit is a [`LockOutcome::Unresolved`], not an error: the caller
/// decides whether an unresolved lock is fatal.
///
/// # Errors
/// - [`CliError::LocalLimitExceeded`] if cargo crosses a ceiling; its process
///   group is killed.
/// - [`CliError::Io`] (naming `manifest`) if cargo cannot be spawned or waited on.
/// - [`CliError::ChildPipeHeld`] if a process cargo started holds a pipe open.
pub fn lock_offline(cargo: &Path, manifest: &Path) -> Result<LockOutcome, CliError> {
    lock_offline_within(cargo, manifest, LOCK_RESOLVE_LIMITS)
}

/// [`lock_offline`] held to `ceiling`.
fn lock_offline_within(
    cargo: &Path,
    manifest: &Path,
    ceiling: LocalCeiling,
) -> Result<LockOutcome, CliError> {
    let mut lock = Command::new(cargo);
    lock.arg("generate-lockfile")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(manifest);
    let captured = run_local(lock, ceiling, LocalSource::LockResolve)
        .map_err(|e| local_run_error(manifest, e))?;
    Ok(if captured.status.success() {
        LockOutcome::Resolved
    } else {
        LockOutcome::Unresolved {
            code: captured.status.code(),
        }
    })
}

/// The CLI error of a local cargo child that produced no result, naming `path` on an I/O failure.
fn local_run_error(path: &Path, e: RunError<LocalRefusal>) -> CliError {
    match e {
        RunError::Exceeded(refusal) => CliError::LocalLimitExceeded(refusal),
        RunError::Spawn(source) | RunError::Wait(source) => CliError::Io {
            path: path.to_path_buf(),
            source,
        },
        RunError::Measure(path, source) => CliError::Io { path, source },
        RunError::PipeDrainTimeout(stream) => CliError::ChildPipeHeld(stream),
        RunError::PipeRead(stream, kind) => CliError::ChildPipeUnread(stream, kind),
    }
}

/// The stdout and stderr pipes of a spawned cargo child; stderr is relayed live and a copy kept.
#[derive(Debug)]
pub struct CargoPipes {
    /// stdout, when piped.
    stdout: Option<ChildStdout>,
    /// The bytes of stdout kept before the stream is refused.
    stdout_cap: usize,
    /// stderr, when piped.
    stderr: Option<ChildStderr>,
}

/// The text a pipe drain kept, and the error that ended or refused it.
#[derive(Debug, Default)]
pub struct Drain {
    /// Everything kept before the end of the stream, the error, or the ceiling.
    pub text: String,
    /// The read error that stopped the drain, or the refusal of a stdout that
    /// passed its ceiling or was not UTF-8.
    pub error: Option<std::io::Error>,
}

/// What [`CargoPipes::drain_while`] returns: the waiter's value and both drains.
#[derive(Debug)]
pub struct Drained<T> {
    /// What the waiter returned.
    pub waited: T,
    /// The captured stdout (empty when stdout was not piped).
    pub stdout: Drain,
    /// The captured stderr, unindented, cut at [`STDERR_KEEP_CAP`].
    pub stderr: Drain,
}

/// A pipe that passed its byte ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeOverflow {
    /// The pipe's name.
    pub pipe: &'static str,
    /// The ceiling it passed, in bytes.
    pub cap: usize,
}

impl std::fmt::Display for PipeOverflow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cargo {} passed its {}-byte ceiling",
            self.pipe, self.cap
        )
    }
}

impl std::error::Error for PipeOverflow {}

impl CargoPipes {
    /// Take both pipes off `child`.
    const fn take(child: &mut Child, stdout_cap: usize) -> Self {
        Self {
            stdout: child.stdout.take(),
            stdout_cap,
            stderr: child.stderr.take(),
        }
    }

    /// Drain both pipes on threads scoped to this call while `wait` runs on
    /// the calling thread, and return once all three are done.
    ///
    /// Draining both pipes at once keeps a full, unread pipe buffer from
    /// stalling cargo. The drains end at end-of-stream, which cargo's exit
    /// (or its kill) brings, so none outlives the build.
    pub fn drain_while<T>(self, wait: impl FnOnce() -> T) -> Drained<T> {
        let Self {
            stdout,
            stdout_cap,
            stderr,
        } = self;
        std::thread::scope(|scope| {
            let stdout = std::thread::Builder::new().spawn_scoped(scope, move || {
                stdout
                    .map(|pipe| stdout_drain(read_capped(pipe, stdout_cap), stdout_cap))
                    .unwrap_or_default()
            });
            let stderr = std::thread::Builder::new().spawn_scoped(scope, move || {
                stderr
                    .map(|pipe| relay_stderr(pipe, STDERR_KEEP_CAP))
                    .unwrap_or_default()
            });
            let waited = wait();
            Drained {
                waited,
                stdout: joined(stdout, "stdout"),
                stderr: joined(stderr, "stderr"),
            }
        })
    }
}

/// A drain thread's result: a thread that could not start, or that panicked,
/// is reported as a read error.
///
/// A drain that never started dropped its pipe with its closure, so cargo's
/// next write to it fails rather than stalling on a pipe nobody reads.
fn joined(spawned: std::io::Result<std::thread::ScopedJoinHandle<'_, Drain>>, pipe: &str) -> Drain {
    match spawned {
        Ok(handle) => handle.join().unwrap_or_else(|_| Drain {
            text: String::new(),
            error: Some(std::io::Error::other(format!(
                "cargo {pipe} drain panicked"
            ))),
        }),
        Err(error) => Drain {
            text: String::new(),
            error: Some(error),
        },
    }
}

/// The bytes a capped read kept.
#[derive(Debug, Default)]
struct Kept {
    /// At most the cap's worth of the stream's first bytes.
    bytes: Vec<u8>,
    /// Whether the stream held more than the cap.
    overflowed: bool,
    /// The read error that ended the stream early.
    error: Option<std::io::Error>,
}

/// Read `pipe` to its end, keeping at most `cap` bytes; the rest is read and
/// dropped so the writer never blocks.
fn read_capped(mut pipe: impl Read, cap: usize) -> Kept {
    let mut kept = Kept::default();
    let mut buf = [0u8; 8 * 1024];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) => return kept,
            Ok(n) => {
                let got = buf.get(..n).unwrap_or_default();
                let room = cap.saturating_sub(kept.bytes.len());
                let take = got.get(..room.min(got.len())).unwrap_or_default();
                kept.bytes.extend_from_slice(take);
                if take.len() < got.len() {
                    kept.overflowed = true;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => {
                kept.error = Some(e);
                return kept;
            }
        }
    }
}

/// A stdout drain: the kept text, refused when the stream passed `cap` or is
/// not UTF-8.
fn stdout_drain(kept: Kept, cap: usize) -> Drain {
    if kept.overflowed {
        return Drain {
            text: String::new(),
            error: Some(std::io::Error::new(
                ErrorKind::FileTooLarge,
                PipeOverflow {
                    pipe: "stdout",
                    cap,
                },
            )),
        };
    }
    match String::from_utf8(kept.bytes) {
        Ok(text) => Drain {
            text,
            error: kept.error,
        },
        Err(e) => Drain {
            text: String::new(),
            error: Some(std::io::Error::new(ErrorKind::InvalidData, e)),
        },
    }
}

/// Relay `pipe` live to our stderr, one shared column off the edge, and keep
/// the unindented text up to `keep` bytes.
///
/// Chunks end at a newline or a carriage return
/// ([`crate::read_progress_chunk`]), so cargo's in-place progress bar flows
/// without waiting for the next newline. The kept copy stops at the first
/// chunk that would pass `keep`; the relay goes on to the end of the stream.
fn relay_stderr(pipe: impl Read, keep: usize) -> Drain {
    let mut reader = BufReader::new(pipe);
    let mut drain = Drain::default();
    let mut keeping = true;
    let mut chunk = String::new();
    loop {
        chunk.clear();
        match crate::read_progress_chunk(&mut reader, &mut chunk) {
            Ok(0) => break,
            Ok(_) => {
                crate::screen::emit_machine(
                    crate::screen::Stream::Stderr,
                    &crate::screen::indent_relay_chunk(&chunk),
                );
                keeping = keeping && drain.text.len().saturating_add(chunk.len()) <= keep;
                if keeping {
                    drain.text.push_str(&chunk);
                }
            }
            Err(e) => {
                drain.error = Some(e);
                break;
            }
        }
    }
    drain
}

#[cfg(test)]
mod tests {
    use super::{
        CargoBuild, CargoCrate, CargoOutput, CargoProfile, CargoTarget, EmbeddedApp, Verbosity,
        WatchBuild,
    };
    use crate::toolchain::CargoBin;
    use crate::watch::BuildAccel;
    use crate::wrapper_source::WrapperSource;
    use ipe_backend_rust::static_build::StaticTriple;
    use std::ffi::OsStr;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::LazyLock;

    /// A `cargo` the command-shape tests never spawn.
    static CARGO: LazyLock<CargoBin> = LazyLock::new(|| CargoBin::stub(PathBuf::from("cargo")));

    /// The arguments of `cmd`, as text.
    fn args(cmd: &Command) -> Vec<String> {
        cmd.get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// What a `Command` does with one environment variable.
    #[derive(Debug, PartialEq, Eq)]
    enum Env<'c> {
        /// Inherited untouched.
        Inherited,
        /// Removed from the child.
        Removed,
        /// Set to a value.
        Set(&'c OsStr),
    }

    /// What `cmd` does with `key`.
    fn env<'c>(cmd: &'c Command, key: &str) -> Env<'c> {
        cmd.get_envs()
            .find(|(k, _)| *k == OsStr::new(key))
            .map_or(Env::Inherited, |(_, v)| v.map_or(Env::Removed, Env::Set))
    }

    /// A release wrapper build over `root`.
    fn wrapper<'a>(source: &'a WrapperSource, embed: Option<EmbeddedApp<'a>>) -> CargoBuild<'a> {
        CargoBuild {
            cargo: &CARGO,
            krate: CargoCrate::ReleaseWrapper { source, embed },
            profile: CargoProfile::Release,
            target: CargoTarget::Static(StaticTriple::X8664LinuxMusl),
            output: CargoOutput::Human(Verbosity::Quiet),
            what: "the release wrapper",
            runtime: None,
        }
    }

    #[test]
    fn every_build_runs_the_build_subcommand_in_its_crate() {
        let root = Path::new("/ws");
        let source = WrapperSource::unverified_for_test(root);
        let cmd = wrapper(&source, None).command();
        assert_eq!(args(&cmd).first().map(String::as_str), Some("build"));
        assert_eq!(cmd.get_current_dir(), Some(root));
        let accel = BuildAccel::MachineDefault;
        let watch = WatchBuild {
            cargo: Path::new("cargo"),
            krate: crate::DevMarkedCrate::assume(Path::new("/crate")),
            target_dir: None,
            accel: &accel,
            verbosity: Verbosity::Progress,
        }
        .command();
        assert_eq!(args(&watch).first().map(String::as_str), Some("build"));
        assert_eq!(watch.get_current_dir(), Some(Path::new("/crate")));
    }

    #[test]
    fn the_wrapper_build_names_its_package_profile_target_and_quiet_flag() {
        let source = WrapperSource::unverified_for_test(Path::new("/ws"));
        let a = args(&wrapper(&source, None).command());
        for want in [
            "--release",
            "--package",
            "ipe_wrapper",
            "--target",
            "x86_64-unknown-linux-musl",
            "-q",
        ] {
            assert!(a.iter().any(|x| x == want), "{want} missing from {a:?}");
        }
        assert!(!a.iter().any(|x| x == "--message-format=json"), "{a:?}");
    }

    #[test]
    fn only_an_embedding_wrapper_carries_the_embed_env() {
        let source = WrapperSource::unverified_for_test(Path::new("/ws"));
        let plain = wrapper(&source, None).command();
        assert_eq!(env(&plain, "IPE_EMBED_APP"), Env::Inherited);
        let app = EmbeddedApp {
            binary: Path::new("/app"),
            profile: Path::new("/app.profile"),
        };
        let embedding = wrapper(&source, Some(app)).command();
        assert_eq!(
            env(&embedding, "IPE_EMBED_APP"),
            Env::Set(OsStr::new("/app"))
        );
        assert_eq!(
            env(&embedding, "IPE_EMBED_PROFILE"),
            Env::Set(OsStr::new("/app.profile"))
        );
    }

    #[test]
    fn only_a_wasip1_build_clears_the_ambient_rustflags() {
        let wasi = super::build_command(
            Path::new("cargo"),
            Path::new("/c"),
            CargoProfile::Release,
            CargoTarget::Wasip1,
            CargoOutput::JsonStream(Verbosity::Quiet),
        );
        assert_eq!(env(&wasi, "RUSTFLAGS"), Env::Removed);
        assert_eq!(env(&wasi, "CARGO_ENCODED_RUSTFLAGS"), Env::Removed);
        assert!(args(&wasi).iter().any(|a| a == "wasm32-wasip1"));
        assert!(args(&wasi).iter().any(|a| a == "--message-format=json"));
        for target in [CargoTarget::Host, CargoTarget::WasmBrowser] {
            let other = super::build_command(
                Path::new("cargo"),
                Path::new("/c"),
                CargoProfile::Dev,
                target,
                CargoOutput::Human(Verbosity::Quiet),
            );
            assert_eq!(env(&other, "RUSTFLAGS"), Env::Inherited, "{target:?}");
        }
    }

    #[test]
    fn a_host_dev_build_carries_no_target_and_no_release_flag() {
        let cmd = super::build_command(
            Path::new("cargo"),
            Path::new("/c"),
            CargoProfile::Dev,
            CargoTarget::Host,
            CargoOutput::Human(Verbosity::Quiet),
        );
        assert_eq!(args(&cmd), ["build", "-q"]);
    }

    #[test]
    fn a_watch_build_pins_its_target_dir_and_acceleration() {
        let accel = BuildAccel::WarmIncremental;
        let cmd = WatchBuild {
            cargo: Path::new("cargo"),
            krate: crate::DevMarkedCrate::assume(Path::new("/crate")),
            target_dir: Some(Path::new("/t")),
            accel: &accel,
            verbosity: Verbosity::Quiet,
        }
        .command();
        assert_eq!(env(&cmd, "CARGO_TARGET_DIR"), Env::Set(OsStr::new("/t")));
        assert_eq!(env(&cmd, "CARGO_INCREMENTAL"), Env::Set(OsStr::new("1")));
        assert_eq!(args(&cmd), ["build", "--message-format=json", "-q"]);
    }

    #[test]
    fn a_drain_thread_that_cannot_start_is_a_read_error_not_a_panic() {
        let drain = std::thread::scope(|_| {
            super::joined(
                Err(std::io::Error::from(std::io::ErrorKind::OutOfMemory)),
                "stdout",
            )
        });
        assert!(drain.text.is_empty());
        assert_eq!(
            drain.error.map(|e| e.kind()),
            Some(std::io::ErrorKind::OutOfMemory)
        );
    }

    #[test]
    fn a_drain_thread_that_panics_is_a_read_error() {
        let drain = std::thread::scope(|scope| {
            let handle = std::thread::Builder::new().spawn_scoped(scope, || -> super::Drain {
                std::panic::resume_unwind(Box::new("drain"))
            });
            super::joined(handle, "stderr")
        });
        assert!(
            drain
                .error
                .is_some_and(|e| e.to_string().contains("stderr drain panicked"))
        );
    }

    #[test]
    fn a_capped_read_keeps_exactly_its_ceiling() {
        let at = super::read_capped(&[b'a'; 10][..], 10);
        assert_eq!((at.bytes.len(), at.overflowed), (10, false));
        let past = super::read_capped(&[b'a'; 11][..], 10);
        assert_eq!((past.bytes.len(), past.overflowed), (10, true));
    }

    #[test]
    fn a_stdout_past_its_ceiling_is_refused_whole() {
        let drain = super::stdout_drain(super::read_capped(&[b'a'; 11][..], 10), 10);
        assert!(
            drain.text.is_empty(),
            "no prefix of a refused stream is kept"
        );
        let refusal = drain.error.expect("an overflowing stdout is refused");
        assert_eq!(refusal.kind(), std::io::ErrorKind::FileTooLarge);
        assert!(
            refusal
                .get_ref()
                .and_then(|e| e.downcast_ref::<super::PipeOverflow>())
                .is_some_and(|o| o.cap == 10),
            "the refusal names its ceiling, got {refusal:?}"
        );
    }

    #[test]
    fn a_stdout_that_is_not_utf8_is_refused() {
        let drain = super::stdout_drain(super::read_capped(&[0xff, 0xfe][..], 10), 10);
        assert_eq!(
            drain.error.map(|e| e.kind()),
            Some(std::io::ErrorKind::InvalidData)
        );
    }

    #[test]
    fn a_relayed_stderr_keeps_whole_chunks_up_to_its_ceiling() {
        let drain = super::relay_stderr(&b"aaaa\nbbbb\ncccc\n"[..], 10);
        assert_eq!(drain.text, "aaaa\nbbbb\n");
        assert!(drain.error.is_none());
    }

    #[test]
    fn a_progress_chunk_with_no_terminator_ends_at_its_ceiling() {
        let line = vec![b'a'; crate::driver::RELAY_CHUNK_CAP * 3];
        let mut reader = &line[..];
        let mut chunk = String::new();
        let n = crate::read_progress_chunk(&mut reader, &mut chunk).expect("read");
        assert_eq!(n, crate::driver::RELAY_CHUNK_CAP);
        assert_eq!(chunk.len(), crate::driver::RELAY_CHUNK_CAP);
    }

    #[test]
    fn a_progress_chunk_never_splits_a_character_at_its_ceiling() {
        let mut line = vec![b'a'; crate::driver::RELAY_CHUNK_CAP - 1];
        line.extend_from_slice("éé".as_bytes());
        let mut reader = &line[..];
        let mut chunk = String::new();
        crate::read_progress_chunk(&mut reader, &mut chunk).expect("read");
        assert!(
            !chunk.contains('\u{fffd}'),
            "a chunk ends on a character boundary"
        );
    }

    #[cfg(unix)]
    mod stubbed {
        //! Builds driven through a stub `cargo` that logs every invocation.

        use super::super::{
            CargoBuild, CargoCrate, CargoOutput, CargoProfile, CargoTarget, LockOutcome, Verbosity,
            WatchBuild, lock_dependencies_within, lock_offline, lock_offline_within,
            target_directory, target_directory_within,
        };
        use crate::CliError;
        use crate::output_dir::OwnedDir;
        use crate::remote_ingest::{
            IngestLimit, LOCK_FETCH_LIMITS, LOCK_RESOLVE_LIMITS, LocalRefusal, LocalSource,
            LocalWall, METADATA_LIMITS,
        };
        use crate::toolchain::CargoBin;
        use std::os::unix::fs::PermissionsExt as _;
        use std::path::{Path, PathBuf};
        use std::time::Duration;

        /// A fresh scratch base for `tag`.
        fn scratch(tag: &str) -> PathBuf {
            let base = ipe_test_temp::temp_root()
                .join(format!("ipe-cargo-step-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&base).expect("scratch base");
            base
        }

        /// A stub `cargo` under `base` that logs its arguments to `base/log`, then runs `body`.
        fn stub(base: &Path, body: &str) -> CargoBin {
            let path = base.join("cargo");
            let log = base.join("log");
            std::fs::write(
                &path,
                format!("#!/bin/sh\necho \"$@\" >> '{}'\n{body}\n", log.display()),
            )
            .expect("write stub");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("stub executable");
            CargoBin::stub(path)
        }

        /// Every logged invocation, one per line.
        fn invocations(base: &Path) -> Vec<String> {
            std::fs::read_to_string(base.join("log"))
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }

        /// A quiet build of `krate` through `cargo`.
        fn build(cargo: &CargoBin, krate: CargoCrate<'_>) -> Result<String, CliError> {
            CargoBuild {
                cargo,
                krate,
                profile: CargoProfile::Dev,
                target: CargoTarget::Host,
                output: CargoOutput::JsonStream(Verbosity::Quiet),
                what: "the stub build",
                runtime: None,
            }
            .run()
        }

        /// Whether the process whose pid is written to `file`, or any process of its group, still exists.
        fn alive(file: &Path) -> bool {
            let raw: i32 = std::fs::read_to_string(file)
                .expect("pid file")
                .trim()
                .parse()
                .expect("pid");
            let pid = rustix::process::Pid::from_raw(raw).expect("non-zero pid");
            let gone = Err(rustix::io::Errno::SRCH);
            rustix::process::test_kill_process(pid) != gone
                || rustix::process::test_kill_process_group(pid) != gone
        }

        /// Whether the process whose pid is written to `file` is gone within a few seconds.
        ///
        /// A killed process outside the caller's reach is reaped by its new
        /// parent, so its pid lingers briefly as a zombie.
        fn gone_soon(file: &Path) -> bool {
            let waited = std::time::Instant::now();
            while alive(file) {
                if waited.elapsed() > Duration::from_secs(10) {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            true
        }

        /// A stub cargo that starts a background `sleep` (its pid in `base/grandchild`),
        /// records its own pid in `base/pid`, then sleeps far past any test wall.
        fn sleeping_stub(base: &Path) -> CargoBin {
            stub(
                base,
                &format!(
                    "sleep 30 &\necho $! > '{}'\necho $$ > '{}'\nexec sleep 30",
                    base.join("grandchild").display(),
                    base.join("pid").display()
                ),
            )
        }

        #[test]
        fn an_offline_lock_past_its_wall_is_refused_and_killed() {
            let base = scratch("lock-wall");
            let cargo = sleeping_stub(&base);
            let started = std::time::Instant::now();
            let locked = lock_offline_within(
                cargo.path(),
                &base.join("Cargo.toml"),
                LOCK_RESOLVE_LIMITS.with_wall(LocalWall::of_secs::<1>()),
            );
            assert!(
                matches!(
                    &locked,
                    Err(CliError::LocalLimitExceeded(LocalRefusal {
                        source: LocalSource::LockResolve,
                        limit: IngestLimit::Time(_),
                        ..
                    }))
                ),
                "a resolve past its wall is a typed refusal, got {locked:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "the refusal lands at the wall, not at the child's exit"
            );
            assert!(
                gone_soon(&base.join("pid")),
                "the refused cargo is killed and reaped"
            );
            assert!(
                gone_soon(&base.join("grandchild")),
                "a process the refused cargo started is killed with its group"
            );
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn an_offline_lock_flooding_stdout_is_refused() {
            let base = scratch("lock-stdout");
            let cargo = stub(&base, "head -c 1048576 /dev/zero");
            let locked = lock_offline(cargo.path(), &base.join("Cargo.toml"));
            assert!(
                matches!(
                    &locked,
                    Err(CliError::LocalLimitExceeded(LocalRefusal {
                        source: LocalSource::LockResolve,
                        limit: IngestLimit::Bytes(_),
                        ..
                    }))
                ),
                "a resolve past its stdout ceiling is a typed refusal, got {locked:?}"
            );
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn an_offline_lock_that_fails_is_unresolved_not_an_error() {
            let base = scratch("lock-fail");
            let cargo = stub(&base, "exit 101");
            let manifest = base.join("Cargo.toml");
            let locked = lock_offline(cargo.path(), &manifest);
            assert_eq!(
                locked.ok(),
                Some(LockOutcome::Unresolved { code: Some(101) })
            );
            assert_eq!(
                invocations(&base).first().map(String::as_str),
                Some(
                    format!(
                        "generate-lockfile --offline --manifest-path {}",
                        manifest.display()
                    )
                    .as_str()
                )
            );
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn an_offline_lock_that_succeeds_is_resolved() {
            let base = scratch("lock-ok");
            let cargo = stub(&base, "true");
            let locked = lock_offline(cargo.path(), &base.join("Cargo.toml"));
            assert_eq!(locked.ok(), Some(LockOutcome::Resolved));
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn an_emitted_crate_lock_past_its_wall_is_refused_and_killed() {
            let base = scratch("fetch-wall");
            let cargo = sleeping_stub(&base);
            let build = std::process::Command::new(cargo.path());
            let started = std::time::Instant::now();
            let locked = lock_dependencies_within(
                &build,
                &base,
                Verbosity::Quiet,
                LOCK_FETCH_LIMITS.with_wall(LocalWall::of_secs::<1>()),
            );
            assert!(
                matches!(
                    &locked,
                    Err(CliError::LocalLimitExceeded(LocalRefusal {
                        source: LocalSource::LockFetch,
                        limit: IngestLimit::Time(_),
                        ..
                    }))
                ),
                "a networked resolve past its wall is a typed refusal, got {locked:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "the refusal lands at the wall, not at the child's exit"
            );
            assert!(
                gone_soon(&base.join("pid")),
                "the refused cargo is killed and reaped"
            );
            assert!(
                gone_soon(&base.join("grandchild")),
                "a process the refused cargo started is killed with its group"
            );
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn the_wrapper_build_replays_the_committed_lock_and_never_rewrites_it() {
            let base = scratch("wrapper");
            let cargo = stub(&base, "true");
            let source = crate::wrapper_source::WrapperSource::unverified_for_test(&base);
            let built = build(
                &cargo,
                CargoCrate::ReleaseWrapper {
                    source: &source,
                    embed: None,
                },
            );
            assert!(built.is_ok(), "{built:?}");
            let calls = invocations(&base);
            assert!(
                calls.iter().all(|c| !c.contains("generate-lockfile")),
                "the wrapper's committed lock is never regenerated, got {calls:?}"
            );
            assert!(
                calls
                    .iter()
                    .any(|c| c.starts_with("build ") && c.contains("--locked")),
                "the wrapper build replays the lock, got {calls:?}"
            );
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn an_emitted_build_resolves_its_own_lock_then_replays_it() {
            let base = scratch("emitted");
            let cargo = stub(&base, "true");
            let crate_dir = OwnedDir::claim(&base.join("crate")).expect("claim crate");
            let built = build(&cargo, CargoCrate::Emitted(&crate_dir));
            assert!(built.is_ok(), "{built:?}");
            let calls = invocations(&base);
            assert_eq!(calls.first().map(String::as_str), Some("generate-lockfile"));
            assert!(
                calls
                    .get(1)
                    .is_some_and(|c| c.starts_with("build ") && c.contains("--locked")),
                "the build replays the fresh lock, got {calls:?}"
            );
            let _ = std::fs::remove_dir_all(&base);
        }

        /// An inheritable descriptor open in the test process.
        fn inheritable_marker() -> rustix::fd::OwnedFd {
            let held = rustix::fs::open(
                "/dev/null",
                rustix::fs::OFlags::RDONLY,
                rustix::fs::Mode::empty(),
            )
            .expect("open /dev/null");
            assert!(
                rustix::io::fcntl_getfd(&held)
                    .is_ok_and(|flags| !flags.contains(rustix::io::FdFlags::CLOEXEC)),
                "the marker descriptor must be inheritable"
            );
            held
        }

        /// A stub whose `build` records under `base/seen` whether `marker` is open in it.
        fn descriptor_probe_stub(base: &Path, marker: &rustix::fd::OwnedFd) -> CargoBin {
            use std::os::fd::AsRawFd as _;
            let seen = base.join("seen");
            stub(
                base,
                &format!(
                    "[ \"$1\" = build ] || exit 0\nif [ -e /dev/fd/{fd} ]; then echo inherited > '{seen}'; else echo closed > '{seen}'; fi\nexit 0",
                    fd = marker.as_raw_fd(),
                    seen = seen.display()
                ),
            )
        }

        /// What the descriptor probe stub recorded under `base`.
        fn seen(base: &Path) -> String {
            std::fs::read_to_string(base.join("seen"))
                .unwrap_or_default()
                .trim()
                .to_owned()
        }

        #[test]
        fn a_build_child_inherits_no_marker_descriptor() {
            let base = scratch("build-fd");
            let marker = inheritable_marker();
            let cargo = descriptor_probe_stub(&base, &marker);
            let crate_dir = OwnedDir::claim(&base.join("crate")).expect("claim crate");
            let built = build(&cargo, CargoCrate::Emitted(&crate_dir));
            assert!(built.is_ok(), "{built:?}");
            assert_eq!(
                seen(&base),
                "closed",
                "a cargo build child must not inherit the CLI's descriptors"
            );
            drop(marker);
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn a_watch_build_child_inherits_no_marker_descriptor() {
            let base = scratch("watch-fd");
            let marker = inheritable_marker();
            let cargo = descriptor_probe_stub(&base, &marker);
            let crate_dir = base.join("crate");
            std::fs::create_dir_all(&crate_dir).expect("crate dir");
            let accel = crate::watch::BuildAccel::MachineDefault;
            let watch = WatchBuild {
                cargo: cargo.path(),
                krate: crate::DevMarkedCrate::assume(&crate_dir),
                target_dir: None,
                accel: &accel,
                verbosity: Verbosity::Quiet,
            };
            let (mut child, pipes) = watch.spawn().expect("spawn the watch build");
            let drained = pipes.drain_while(|| child.wait());
            assert!(
                drained
                    .waited
                    .as_ref()
                    .is_ok_and(std::process::ExitStatus::success),
                "{:?}",
                drained.waited
            );
            assert_eq!(
                seen(&base),
                "closed",
                "a watch rebuild child must not inherit the CLI's descriptors"
            );
            drop(marker);
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn a_failed_stderr_read_outranks_a_non_zero_exit() {
            use std::os::unix::process::ExitStatusExt as _;
            let base = scratch("stderr-read");
            let cargo = stub(&base, "exit 0");
            let crate_dir = OwnedDir::claim(&base.join("crate")).expect("claim crate");
            let drained = super::super::Drained {
                waited: std::process::ExitStatus::from_raw(7 << 8),
                stdout: super::super::Drain::default(),
                stderr: super::super::Drain {
                    text: "partial".to_owned(),
                    error: Some(std::io::Error::other("stderr read failed")),
                },
            };
            let verdict = CargoBuild {
                cargo: &cargo,
                krate: CargoCrate::Emitted(&crate_dir),
                profile: CargoProfile::Dev,
                target: CargoTarget::Host,
                output: CargoOutput::JsonStream(Verbosity::Quiet),
                what: "the stub build",
                runtime: None,
            }
            .verdict(drained);
            assert!(
                matches!(&verdict, Err(CliError::Io { .. })),
                "an unread stderr is an I/O failure, never a partial build diagnostic, got {verdict:?}"
            );
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn an_artifact_stream_past_its_ceiling_fails_the_build() {
            let base = scratch("artifact-cap");
            let cargo = stub(
                &base,
                &format!(
                    "[ \"$1\" = build ] && head -c {} /dev/zero; exit 0",
                    super::super::ARTIFACT_STREAM_CAP + 1
                ),
            );
            let crate_dir = OwnedDir::claim(&base.join("crate")).expect("claim crate");
            let built = build(&cargo, CargoCrate::Emitted(&crate_dir));
            assert!(
                matches!(&built, Err(CliError::Io { source, .. })
                    if source.kind() == std::io::ErrorKind::FileTooLarge),
                "an oversized artifact stream is refused, got {built:?}"
            );
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn the_target_directory_is_read_from_cargo_metadata() {
            let base = scratch("metadata");
            let cargo = stub(&base, "echo '{\"target_directory\":\"/t\"}'");
            let dir = target_directory(&cargo, &base);
            assert_eq!(dir.ok(), Some(PathBuf::from("/t")));
            let calls = invocations(&base);
            assert_eq!(
                calls.first().map(String::as_str),
                Some("metadata --format-version 1 --no-deps")
            );
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn a_failing_cargo_metadata_is_refused() {
            let base = scratch("metadata-fail");
            let cargo = stub(&base, "echo boom >&2; exit 3");
            let dir = target_directory(&cargo, &base);
            assert!(matches!(dir, Err(CliError::Usage(_))), "{dir:?}");
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn a_metadata_document_past_its_ceiling_is_refused() {
            let base = scratch("metadata-cap");
            let cargo = stub(&base, "head -c 16777217 /dev/zero");
            let dir = target_directory(&cargo, &base);
            assert!(
                matches!(
                    &dir,
                    Err(CliError::LocalLimitExceeded(LocalRefusal {
                        source: LocalSource::CargoMetadata,
                        limit: IngestLimit::Bytes(_),
                        ..
                    }))
                ),
                "an oversized metadata document is a typed refusal, got {dir:?}"
            );
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn a_metadata_query_past_its_wall_is_refused_and_killed() {
            let base = scratch("metadata-wall");
            let cargo = sleeping_stub(&base);
            let started = std::time::Instant::now();
            let dir = target_directory_within(
                &cargo,
                &base,
                METADATA_LIMITS.with_wall(LocalWall::of_secs::<1>()),
            );
            assert!(
                matches!(
                    &dir,
                    Err(CliError::LocalLimitExceeded(LocalRefusal {
                        source: LocalSource::CargoMetadata,
                        limit: IngestLimit::Time(_),
                        ..
                    }))
                ),
                "a metadata query past its wall is a typed refusal, got {dir:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "the refusal lands at the wall, not at the child's exit"
            );
            assert!(
                gone_soon(&base.join("pid")),
                "the refused cargo is killed and reaped"
            );
            assert!(
                gone_soon(&base.join("grandchild")),
                "a process the refused cargo started is killed with its group"
            );
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn a_stdout_flood_is_refused_before_the_child_exits() {
            let base = scratch("lock-flood-early");
            let cargo = stub(
                &base,
                &format!(
                    "echo $$ > '{}'\nhead -c 1048576 /dev/zero\nexec sleep 30",
                    base.join("pid").display()
                ),
            );
            let started = std::time::Instant::now();
            let locked = lock_offline(cargo.path(), &base.join("Cargo.toml"));
            assert!(
                matches!(
                    &locked,
                    Err(CliError::LocalLimitExceeded(LocalRefusal {
                        source: LocalSource::LockResolve,
                        limit: IngestLimit::Bytes(_),
                        ..
                    }))
                ),
                "a resolve past its stdout ceiling is a typed refusal, got {locked:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "the refusal lands at the overflow, not at the child's exit or its wall"
            );
            assert!(
                gone_soon(&base.join("pid")),
                "the flooding cargo is killed and reaped"
            );
            let _ = std::fs::remove_dir_all(&base);
        }
    }
}
