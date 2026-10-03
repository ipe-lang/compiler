//! Build + run plumbing for the golden E2E gate.
//!
//! Provides the core routines the golden test harness and E2E tests share:
//! build the emitted Rust project, locate the produced binary, and run it.
//! There is no Go-oracle format here — the expected output is captured once
//! (as `tests/golden/<name>/expected.txt`) and compared directly by the test.
//!
//! Two entry points:
//!   * [`build_and_run_rust`] — build + run; returns stdout + exit code.
//!   * [`build_rust_binary`]  — build only; returns the binary path.

#![forbid(unsafe_code)]

pub mod bin;

pub use bin::{
    ProvenBin, ProvenRuntime, ResolveError, Tier, e2e_tier, require_manifest_dir, require_runtime,
    require_runtime_crate,
};

use std::io::{BufRead, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// The expected-output file name inside a golden directory.
pub const EXPECTED_FILE: &str = "expected.txt";
/// The Ipê entry point inside every golden directory.
pub const MAIN_IPE: &str = "Main.ipe";

/// Absolute liveness backstop for the emitted-crate `cargo build`, in seconds.
///
/// NOT a performance assertion: a *progressing* build (cargo still emitting
/// compile messages) is never killed by this ceiling — the inactivity watchdog
/// below is what fails a genuine wedge fast. This exists only so a pathological
/// build that emits a trickle of output forever cannot run unbounded. It is set
/// wide because the SEAL verdict — "does the emitted crate build?" — must not
/// depend on how many seconds a cold, contended runner needs; a slow-but-healthy
/// build under a missing dep cache legitimately runs many minutes. Overridable
/// via `IPE_E2E_BUILD_TIMEOUT_SECS`.
const DEFAULT_EMITTED_BUILD_TIMEOUT_SECS: u64 = 1800;

/// No-forward-progress window for the emitted-crate `cargo build`, in seconds.
///
/// `cargo build` streams a compile message as each unit finishes, so a healthy
/// build — however slow the runner — keeps that stream alive. Silence for this
/// long means the build has wedged (a deadlock, a lock it will never get, a spun
/// rustc), not merely that the runner is loaded, so the child is killed and the
/// test fails fast. This is what makes the SEAL verdict load-INDEPENDENT: the
/// build's own progress decides it, never wall-clock. Overridable via
/// `IPE_E2E_BUILD_IDLE_SECS`.
const DEFAULT_EMITTED_BUILD_IDLE_SECS: u64 = 180;

/// Resolve a positive-seconds duration from `var`, falling back to `default`.
///
/// A non-empty, parseable positive value wins; anything else (absent, empty,
/// non-numeric, zero) uses the default — an unreadable override must never
/// silently disable the guard.
fn duration_env_or(var: &str, default_secs: u64) -> Duration {
    let secs = ipe_env::var(var)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(default_secs);
    Duration::from_secs(secs)
}

/// Resolve the emitted-build absolute backstop from the environment.
fn emitted_build_timeout() -> Duration {
    duration_env_or(
        "IPE_E2E_BUILD_TIMEOUT_SECS",
        DEFAULT_EMITTED_BUILD_TIMEOUT_SECS,
    )
}

/// Resolve the emitted-build inactivity window from the environment.
fn emitted_build_idle() -> Duration {
    duration_env_or("IPE_E2E_BUILD_IDLE_SECS", DEFAULT_EMITTED_BUILD_IDLE_SECS)
}

/// Stable token stored in a portable golden `Cargo.toml` instead of the
/// machine-specific `ipe-runtime-rust` crate path.
///
/// The real emit writes a live, resolvable absolute path so `cargo build`
/// works in any environment; only the golden fixture stores this placeholder
/// so the byte-compare is machine-independent. The comparison and bless paths
/// both normalise the emitted path to this value before touching the golden.
pub const RUNTIME_PATH_PLACEHOLDER: &str = "__IPE_RUNTIME_PATH__";

/// Replace the `ipe-runtime-rust` dependency's `path = "<abs>"` value in a
/// `Cargo.toml` text with [`RUNTIME_PATH_PLACEHOLDER`], leaving every other
/// byte untouched.
///
/// Only the one `ipe_runtime = { … package = "ipe-runtime-rust" … path = "…"
/// … }` dependency line carries a machine-specific value; the rewrite is
/// scoped to `path = "…"` on that line, so a manifest with no such line (e.g.
/// the vendored / wasm shape) passes through unchanged, and any real manifest
/// drift still surfaces as a diff.
#[must_use]
pub fn normalize_runtime_dep_path(manifest: &str) -> String {
    let path_normalized = manifest
        .lines()
        .map(|line| {
            if line.contains("package = \"ipe-runtime-rust\"")
                && let Some(start) = line.find("path = \"")
            {
                let val_start = start + "path = \"".len();
                if let Some(rel_end) = line[val_start..].find('"') {
                    let end = val_start + rel_end;
                    return format!(
                        "{}{}{}",
                        &line[..val_start],
                        RUNTIME_PATH_PLACEHOLDER,
                        &line[end..]
                    );
                }
            }
            line.to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
        + if manifest.ends_with('\n') { "\n" } else { "" };
    normalize_crate_identity_hash(&path_normalized)
}

/// Stable token stored in a portable golden `Cargo.toml` in place of the
/// machine-specific per-project crate-identity hash.
///
/// The emitted `[package] name` is `"<friendly>_<hash>"`, where `<hash>` is a
/// fixed-width digest of the CANONICAL project directory — a value that differs
/// per machine (the golden is emitted from a host-local temp/checkout path). The
/// friendly base is host-independent and stays in the golden verbatim (so the
/// golden still pins it); only the volatile hash is replaced with this placeholder
/// on both the comparison and bless paths, so the committed golden is portable and
/// a regen is idempotent across machines.
pub const CRATE_IDENTITY_HASH_PLACEHOLDER: &str = "__IPE_CRATE_HASH__";

/// Replace the `[package] name` crate-identity hash suffix (`_<8 lowercase-hex>`)
/// with [`CRATE_IDENTITY_HASH_PLACEHOLDER`], leaving the friendly base and every
/// other byte untouched.
///
/// Scoped to the `[package]` table's first `name = "…"` line. A name with no
/// hash suffix (the single-file `ipe-app` default) and any non-`[package]` `name`
/// (a dependency) pass through unchanged. The suffix shape — a trailing `_`
/// followed by EXACTLY the fixed-width lowercase-hex digest — is matched
/// precisely so a friendly base that itself ends in `_<hex-looking>` is not
/// mangled beyond that exact trailing token.
#[must_use]
fn normalize_crate_identity_hash(manifest: &str) -> String {
    // Mirrors `ipe_backend_rust::crate_identity`'s fixed suffix width; a shell/
    // tool cannot import that const, so the expected width is asserted by the
    // determinism/host-independence tests that drive both sides.
    const HEX_LEN: usize = 8;
    let mut in_package = false;
    let mut done = false;
    manifest
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with('[') {
                in_package = trimmed.starts_with("[package]");
                return line.to_owned();
            }
            if in_package
                && !done
                && trimmed.starts_with("name")
                && let Some((lhs, rhs)) = line.split_once('=')
                && lhs.trim() == "name"
            {
                let raw = rhs.trim();
                if let Some(inner) = raw.strip_prefix('"').and_then(|s| s.strip_suffix('"'))
                    && let Some((base, hash)) = inner.rsplit_once('_')
                    && hash.len() == HEX_LEN
                    && hash
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                {
                    done = true;
                    return format!("{lhs}= \"{base}_{CRATE_IDENTITY_HASH_PLACEHOLDER}\"");
                }
                done = true;
            }
            line.to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
        + if manifest.ends_with('\n') { "\n" } else { "" }
}

/// Captured stdout + exit code from running a built program.
#[derive(Clone, Debug)]
pub struct RunResult {
    /// The program's standard output, decoded lossily from UTF-8.
    pub stdout: String,
    /// The process exit code (`None` if killed by a signal).
    pub exit_code: Option<i32>,
}

/// Turn an arbitrary golden name into a cargo-package-safe suffix.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Rewrite the emitted `Cargo.toml` so its package — and hence its binary — is
/// unique to this golden, letting every golden's binary coexist in the one
/// shared cargo target. Returns the unique package name.
///
/// The emitted package name is `ipe-app` for a single-file build but the slug
/// from `package.ipe` for a project build, so the rewrite targets the first
/// `name = "..."` line inside the `[package]` section (whatever its value)
/// rather than a fixed anchor string.
fn rewrite_package_name(emitted_dir: &Path, golden_name: &str) -> Result<String, String> {
    let manifest = emitted_dir.join("Cargo.toml");
    let original = std::fs::read_to_string(&manifest)
        .map_err(|e| format!("cannot read {}: {e}", manifest.display()))?;
    let unique = format!("ipe-app-e2e-{}", sanitize(golden_name));
    let rewritten = replace_package_name(&original, &unique).ok_or_else(|| {
        format!(
            "emitted manifest {} has no `name = \"...\"` line in its `[package]` section",
            manifest.display()
        )
    })?;
    std::fs::write(&manifest, rewritten)
        .map_err(|e| format!("cannot write {}: {e}", manifest.display()))?;
    Ok(unique)
}

/// Replace the package name in a `Cargo.toml` text with `unique`, returning the
/// rewritten text (or `None` if no `[package]` `name = "..."` line is present).
///
/// The `[package]` table is the first section of every emitted manifest, so the
/// first `name = "..."` line at or after a `[package]` header is the package
/// name; a `name = ` under `[dependencies]`/`[features]` never precedes it.
fn replace_package_name(manifest: &str, unique: &str) -> Option<String> {
    let mut in_package = false;
    let mut done = false;
    let out = manifest
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with('[') {
                in_package = trimmed.starts_with("[package]");
            } else if in_package
                && !done
                && trimmed.starts_with("name")
                && let Some((lhs, _)) = line.split_once('=')
                && lhs.trim() == "name"
            {
                done = true;
                return format!("name = \"{unique}\"");
            }
            line.to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
        + if manifest.ends_with('\n') { "\n" } else { "" };
    done.then_some(out)
}

/// Parse `cargo build --message-format=json` stdout for the produced binary.
fn find_executable(json_stdout: &str, unique_pkg: &str) -> Option<String> {
    let mut found: Option<String> = None;
    for line in json_stdout.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact") {
            continue;
        }
        let Some(exe) = value.get("executable").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let pkg_id = value
            .get("package_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if pkg_id.contains(unique_pkg) {
            found = Some(exe.to_owned());
        }
    }
    found
}

/// Decide the emitted-project cargo target, decoupling it from the ambient
/// `CARGO_TARGET_DIR` set by the outer build lane.
///
/// `shared` is the raw `IPE_ORACLE_SHARED_TARGET` value. Returns `Some(path)`
/// only when it is a non-empty absolute path — anything else (absent, relative,
/// whitespace) returns `None` (inherit the ambient env = isolate). This
/// fail-safe prevents a runtime-editing lane that vendors a different
/// `ipe_runtime` from accidentally reusing a stale shared target and producing
/// a false green.
fn resolve_emitted_target(shared: Option<&str>) -> Option<String> {
    let trimmed = shared?.trim();
    if trimmed.is_empty() {
        return None;
    }
    if !Path::new(trimmed).is_absolute() {
        eprintln!(
            "e2e-support: ignoring IPE_ORACLE_SHARED_TARGET={trimmed:?} \
             (not an absolute path); isolating emitted build in ambient CARGO_TARGET_DIR"
        );
        return None;
    }
    Some(trimmed.to_owned())
}

/// The `CARGO_TARGET_DIR` a child `ipe`/`cargo` process should inherit so its
/// emitted build links against the warm shared dependency target.
///
/// A test spawning the `ipe` subprocess (`ipe run|build|watch`) forwards this on
/// the child's environment. The resolution order:
///   * `IPE_ORACLE_SHARED_TARGET`, when it is an absolute path — CI's e2e/seal
///     jobs export ONLY this variable, and production `ipe` never reads it, so
///     the harness must translate it into the child's `CARGO_TARGET_DIR` or the
///     child cold-builds the full tokio/axum/runtime tree.
///   * else the ambient `CARGO_TARGET_DIR`, when a local run set one — the child
///     inherits it untouched, so agent-lane target isolation is preserved.
///   * else `None` (nothing to forward; cargo's default per-crate target).
///
/// Returning `None` when neither is set keeps a bare local run hermetic and
/// unchanged; a non-absolute `IPE_ORACLE_SHARED_TARGET` fails safe exactly as
/// [`resolve_emitted_target`] does (isolate rather than reuse a stale target).
#[must_use]
pub fn child_shared_target(
    shared: Option<&str>,
    ambient_cargo_target: Option<&str>,
) -> Option<String> {
    resolve_emitted_target(shared).or_else(|| {
        ambient_cargo_target
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

/// Resolve [`child_shared_target`] from the current process environment.
///
/// Convenience wrapper reading `IPE_ORACLE_SHARED_TARGET` and `CARGO_TARGET_DIR`
/// from the ambient environment for the common call site that forwards the warm
/// target onto a spawned `ipe`/`cargo` child.
#[must_use]
pub fn child_shared_target_from_env() -> Option<String> {
    let shared = ipe_env::var("IPE_ORACLE_SHARED_TARGET").ok();
    let ambient = ipe_env::var("CARGO_TARGET_DIR").ok();
    child_shared_target(shared.as_deref(), ambient.as_deref())
}

/// Build the emitted project at `emitted_dir` for `golden_name`, returning the
/// located binary path. The shared core of [`build_and_run_rust`] and
/// [`build_rust_binary`], so both drive `cargo build` identically.
///
/// The emitted build's cargo target is chosen by [`resolve_emitted_target`] from
/// `IPE_ORACLE_SHARED_TARGET`: when the harness opts in with an absolute path the
/// build is pinned to that shared target (runtime deps compiled once, reused);
/// otherwise the ambient env is inherited untouched (isolate — the fail-safe
/// default).
///
/// The compiler wrapper (sccache) is disabled for this build. Each emitted crate
/// lives in a per-golden scratch directory the golden removes on its next run, so
/// pinning rustc to a cwd-sensitive shared sccache server is unsound under
/// parallelism: one golden's scratch teardown unlinks the very cwd the shared
/// sccache server inherited, after which every sibling compile fails
/// `sccache rustc -vV` with "couldn't determine current working directory".
/// Running the emitted builds without the wrapper removes that shared, racy
/// resource; the shared cargo target already caches the heavy runtime dep tree.
///
/// An EMPTY `CARGO_BUILD_RUSTC_WRAPPER` (not `env_remove`) is required: the
/// wrapper is commonly configured in `~/.cargo/config.toml`'s `[build]
/// rustc-wrapper`, which `env_remove` cannot override — only an empty env var,
/// which takes precedence over the config value, actually disables it.
fn build_emitted_binary(golden_name: &str, emitted_dir: &Path) -> Result<String, String> {
    let unique_pkg = rewrite_package_name(emitted_dir, golden_name)?;

    let shared = ipe_env::var("IPE_ORACLE_SHARED_TARGET").ok();
    let target = resolve_emitted_target(shared.as_deref());

    // Hermetic resolve: pin the emitted crate's whole dependency graph into a
    // per-emit `Cargo.lock` ONCE, then build against exactly that lock with
    // `--locked`. Without the lock the build resolves "latest-compatible" live on
    // every run, so a transitive point-release (e.g. a chrono patch pulling a
    // wasm-bindgen bump against the runtime's exact pin) can red the SEAL with no
    // source change. `--locked` makes the build refuse to re-resolve: any
    // lock↔manifest drift fails closed here, never as a silent divergence.
    lock_emitted_dependencies(emitted_dir, target.as_deref(), golden_name)?;

    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("--locked")
        .arg("--message-format=json")
        .current_dir(emitted_dir)
        .env("CARGO_BUILD_RUSTC_WRAPPER", "")
        .env("RUSTC_WRAPPER", "");
    if let Some(p) = &target {
        cmd.env("CARGO_TARGET_DIR", p);
    }
    let build = run_bounded_build(
        cmd,
        golden_name,
        emitted_build_timeout(),
        emitted_build_idle(),
    )?;
    if !build.status.success() {
        return Err(format!(
            "{golden_name}: emitted project must build\n--- cargo stderr ---\n{}",
            String::from_utf8_lossy(&build.stderr)
        ));
    }

    let json_stdout = String::from_utf8_lossy(&build.stdout);
    find_executable(&json_stdout, &unique_pkg).ok_or_else(|| {
        format!("{golden_name}: no `executable` artifact for package `{unique_pkg}` in cargo JSON")
    })
}

/// Resolve the emitted crate's dependency graph ONCE into a per-emit
/// `Cargo.lock` under `emitted_dir`, so the subsequent `--locked` build replays
/// exactly that resolution instead of resolving "latest-compatible" afresh. The
/// environment mirrors the build below (cleared `RUSTC_WRAPPER`, the shared
/// `CARGO_TARGET_DIR` when set) so the same toolchain that consumes the lock
/// produces it.
fn lock_emitted_dependencies(
    emitted_dir: &Path,
    target: Option<&str>,
    golden_name: &str,
) -> Result<(), String> {
    let mut cmd = Command::new("cargo");
    cmd.arg("generate-lockfile")
        .current_dir(emitted_dir)
        .env("CARGO_BUILD_RUSTC_WRAPPER", "")
        .env("RUSTC_WRAPPER", "");
    if let Some(p) = target {
        cmd.env("CARGO_TARGET_DIR", p);
    }
    let out = run_bounded_build(
        cmd,
        golden_name,
        emitted_build_timeout(),
        emitted_build_idle(),
    )?;
    if out.status.success() {
        return Ok(());
    }
    Err(format!(
        "{golden_name}: emitted project must resolve a Cargo.lock\n--- cargo stderr ---\n{}",
        String::from_utf8_lossy(&out.stderr)
    ))
}

/// The ceilings a [`run_bounded`] child runs under.
#[derive(Clone, Copy, Debug)]
pub struct BoundedRun {
    /// The absolute wall-clock ceiling, a backstop for a trickle-forever child.
    pub max_total: Duration,
    /// How long both streams may stay silent before the child counts as wedged.
    pub idle_window: Duration,
    /// The most bytes each of stdout and stderr may carry.
    pub out_cap: usize,
}

/// A [`run_bounded`] child that finished inside its ceilings.
#[derive(Debug)]
pub struct BoundedOutput {
    /// The child's exit status.
    pub status: std::process::ExitStatus,
    /// Everything the child wrote to stdout.
    pub stdout: Vec<u8>,
    /// Everything the child wrote to stderr.
    pub stderr: Vec<u8>,
}

/// One of a child's two output streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

impl std::fmt::Display for OutStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        })
    }
}

/// Why a [`run_bounded`] child gave no [`BoundedOutput`].
///
/// Every variant past [`BoundedRunError::Spawn`] means the child was killed
/// and reaped before the error came back.
#[derive(Debug)]
pub enum BoundedRunError {
    /// The child could not be started.
    Spawn(std::io::Error),
    /// The OS refused a thread to drain one of the child's streams.
    Drain(std::io::Error),
    /// Waiting on the child failed.
    Wait(std::io::Error),
    /// Both streams stayed silent for the idle window.
    Idle(Duration),
    /// The child outlived the absolute ceiling.
    Wall(Duration),
    /// A stream carried more than the output cap.
    OutputCap {
        /// The stream that overflowed.
        stream: OutStream,
        /// The cap it crossed.
        cap: usize,
    },
}

impl std::fmt::Display for BoundedRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(e) => write!(f, "could not start: {e}"),
            Self::Drain(e) => write!(f, "could not start an output drain thread: {e}"),
            Self::Wait(e) => write!(f, "waiting on the child failed: {e}"),
            Self::Idle(window) => write!(f, "produced no output for {window:?} and was killed"),
            Self::Wall(ceiling) => write!(f, "exceeded the {ceiling:?} ceiling and was killed"),
            Self::OutputCap { stream, cap } => {
                write!(f, "wrote more than {cap} bytes to {stream} and was killed")
            }
        }
    }
}

impl std::error::Error for BoundedRunError {}

/// The most bytes each stream of an emitted `cargo build` may carry.
///
/// Far above what a real build's `--message-format=json` writes, so only a
/// runaway child reaches it.
const EMITTED_BUILD_OUTPUT_CAP: usize = 256 * 1024 * 1024;

/// A stream's drain: the thread reading it and the flag it raises past the cap.
struct Drain {
    handle: std::thread::JoinHandle<Vec<u8>>,
    over_cap: Arc<AtomicBool>,
    stream: OutStream,
}

/// Kill and reap `child`, then hand back `err`.
fn stop_child(child: &mut std::process::Child, err: BoundedRunError) -> BoundedRunError {
    let _ = child.kill();
    let _ = child.wait();
    err
}

/// Run `cmd` to completion under `bounds`, draining stdout and stderr on reader threads.
///
/// The child is killed, reaped and an `Err` returned when any ceiling trips:
///   * `idle_window` — the streams have been silent this long: a wedged
///     child, killed fast. A *progressing* child resets the window on every
///     line, so a slow-but-healthy one is never killed — that is what makes
///     the SEAL verdict load-independent.
///   * `max_total` — an absolute liveness backstop for a trickle-forever child.
///   * `out_cap` — a stream carried more bytes than the cap.
///
/// A child that exits returns its status at once through `try_wait`, so no
/// ceiling can mask a real non-zero exit — they only govern killing a *live*
/// child.
///
/// The streams are drained on dedicated threads because a child's output can
/// exceed the OS pipe buffer; polling `try_wait` while the child blocks on a
/// full pipe would otherwise deadlock.
///
/// # Errors
///
/// [`BoundedRunError`] when the child cannot be started or drained, waiting
/// on it fails, or a ceiling trips.
pub fn run_bounded(mut cmd: Command, bounds: BoundedRun) -> Result<BoundedOutput, BoundedRunError> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(BoundedRunError::Spawn)?;

    let start = Instant::now();
    // Millis-since-`start` of the most recent byte read from either stream. A
    // progressing child keeps bumping this; a wedged one leaves it frozen, so
    // `elapsed - last_activity` is the child's current idle time. Seeded at 0
    // (= `start`), so a child that emits nothing at all is idle from the
    // outset and trips `idle_window` on schedule.
    let last_activity = Arc::new(AtomicU64::new(0));

    let mut drains = Vec::with_capacity(2);
    let streams: [(OutStream, Option<Box<dyn Read + Send>>); 2] = [
        (
            OutStream::Stdout,
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>),
        ),
        (
            OutStream::Stderr,
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>),
        ),
    ];
    for (stream, pipe) in streams {
        let Some(pipe) = pipe else { continue };
        match drain_stream(
            pipe,
            stream,
            start,
            Arc::clone(&last_activity),
            bounds.out_cap,
        ) {
            Ok(drain) => drains.push(drain),
            Err(e) => return Err(stop_child(&mut child, BoundedRunError::Drain(e))),
        }
    }

    let status = loop {
        if let Some(drain) = drains.iter().find(|d| d.over_cap.load(Ordering::Relaxed)) {
            let err = BoundedRunError::OutputCap {
                stream: drain.stream,
                cap: bounds.out_cap,
            };
            return Err(stop_child(&mut child, err));
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                let elapsed = start.elapsed();
                let idle = elapsed
                    .saturating_sub(Duration::from_millis(last_activity.load(Ordering::Relaxed)));
                if idle >= bounds.idle_window {
                    let err = BoundedRunError::Idle(bounds.idle_window);
                    return Err(stop_child(&mut child, err));
                }
                if elapsed >= bounds.max_total {
                    let err = BoundedRunError::Wall(bounds.max_total);
                    return Err(stop_child(&mut child, err));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(stop_child(&mut child, BoundedRunError::Wait(e))),
        }
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    for drain in drains {
        let stream = drain.stream;
        let bytes = drain.handle.join().unwrap_or_default();
        // A child that exits right after flooding a stream ends the poll
        // before the flag is seen; the cap holds all the same.
        if drain.over_cap.load(Ordering::Relaxed) {
            return Err(BoundedRunError::OutputCap {
                stream,
                cap: bounds.out_cap,
            });
        }
        match stream {
            OutStream::Stdout => stdout = bytes,
            OutStream::Stderr => stderr = bytes,
        }
    }
    Ok(BoundedOutput {
        status,
        stdout,
        stderr,
    })
}

/// Run an emitted-project `cargo build` under the build ceilings, naming the golden in any error.
fn run_bounded_build(
    cmd: Command,
    golden_name: &str,
    max_total: Duration,
    idle_window: Duration,
) -> Result<BoundedOutput, String> {
    let bounds = BoundedRun {
        max_total,
        idle_window,
        out_cap: EMITTED_BUILD_OUTPUT_CAP,
    };
    run_bounded(cmd, bounds).map_err(|e| match e {
        BoundedRunError::Spawn(e) => format!("{golden_name}: failed to spawn `cargo build`: {e}"),
        BoundedRunError::Wait(e) => {
            format!("{golden_name}: waiting on `cargo build` failed: {e}")
        }
        BoundedRunError::Idle(window) => format!(
            "{golden_name}: emitted `cargo build` produced no output for {window:?} \
             and was killed (inactivity watchdog: a wedged build, not a slow one — a \
             progressing build resets the window on every compile message; \
             raise IPE_E2E_BUILD_IDLE_SECS if a single unit legitimately compiles \
             longer in silence)"
        ),
        BoundedRunError::Wall(ceiling) => format!(
            "{golden_name}: emitted `cargo build` exceeded the {ceiling:?} absolute \
             ceiling and was killed (liveness backstop; raise \
             IPE_E2E_BUILD_TIMEOUT_SECS)"
        ),
        other @ (BoundedRunError::Drain(_) | BoundedRunError::OutputCap { .. }) => {
            format!("{golden_name}: emitted `cargo build` {other}")
        }
    })
}

/// Start a thread that reads a child stream to EOF, stopping past `cap` bytes.
///
/// Every line stamps `last_activity` (millis since `start`) so the parent can
/// tell a progressing child (bytes still arriving) from a wedged one (stream
/// gone silent). Each read is bounded by what is left of `cap`, so a flood
/// with no line break cannot grow the buffer past it; crossing the cap raises
/// the drain's `over_cap` flag and ends the read.
fn drain_stream(
    stream: Box<dyn Read + Send>,
    which: OutStream,
    start: Instant,
    last_activity: Arc<AtomicU64>,
    cap: usize,
) -> std::io::Result<Drain> {
    let over_cap = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&over_cap);
    let handle = std::thread::Builder::new()
        .name(format!("e2e-drain-{which}"))
        .spawn(move || {
            let mut reader = std::io::BufReader::new(stream);
            let mut buf = Vec::new();
            loop {
                let left = cap.saturating_sub(buf.len());
                let budget = u64::try_from(left).unwrap_or(u64::MAX).saturating_add(1);
                let mut line = Vec::new();
                match reader.by_ref().take(budget).read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        buf.extend_from_slice(&line);
                        let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                        last_activity.store(ms, Ordering::Relaxed);
                        if buf.len() > cap {
                            flag.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                }
            }
            buf
        })?;
    Ok(Drain {
        handle,
        over_cap,
        stream: which,
    })
}

/// Build the emitted Rust project at `emitted_dir` and run the resulting binary,
/// returning its stdout + exit code.
///
/// # Errors
/// Returns a message if the manifest cannot be retargeted, `cargo build` fails
/// (the message carries cargo's stderr), the binary cannot be located in the
/// JSON output, or the binary cannot be executed.
pub fn build_and_run_rust(golden_name: &str, emitted_dir: &Path) -> Result<RunResult, String> {
    let exe = build_emitted_binary(golden_name, emitted_dir)?;

    let run = Command::new(&exe)
        .output()
        .map_err(|e| format!("{golden_name}: emitted binary `{exe}` must run: {e}"))?;
    Ok(RunResult {
        stdout: String::from_utf8_lossy(&run.stdout).into_owned(),
        exit_code: run.status.code(),
    })
}

/// Build the emitted Rust project at `emitted_dir` and return the path of the
/// resulting binary WITHOUT running it.
///
/// Used by E2E tests that need to control binary launch (custom env vars,
/// pre-started fixture servers, stack-limit wrappers, …).
///
/// # Errors
/// Returns a message if the manifest cannot be retargeted, `cargo build` fails
/// (carrying cargo's stderr), or the binary cannot be located in the JSON
/// output.
pub fn build_rust_binary(golden_name: &str, emitted_dir: &Path) -> Result<String, String> {
    build_emitted_binary(golden_name, emitted_dir)
}

/// Read the expected output for a golden from its `expected.txt` file.
///
/// Returns `Ok(text)` on success, `Err` when the file is missing or unreadable
/// — a hard failure (never a skip) so a golden without an expected file cannot
/// pass silently. `expected.txt` is the self-regression anchor: captured from
/// ipe's own output and only changed when behaviour intentionally changes.
///
/// # Errors
/// Returns a human-readable message when the file is absent or cannot be read.
pub fn read_expected(golden_dir: &Path) -> Result<String, String> {
    let path = golden_dir.join(EXPECTED_FILE);
    std::fs::read_to_string(&path)
        .map_err(|e| format!("missing or unreadable {}: {e}", path.display()))
}

/// Poll `pred` on a fixed tick until it returns `true`, or `false` once
/// `deadline` has elapsed since the call started.
///
/// The one shared bounded event-poll for tests that must wait on an observed
/// condition (a process event, an HTTP response, a file's contents): a fixed
/// `thread::sleep` used as a synchronisation point races the same scheduler
/// contention a loaded CI runner introduces, splitting or missing events a
/// deterministic poll-until-true always catches. Never panics — a timeout is
/// reported as `false`, leaving it to the caller (usually an `assert!` naming
/// what never became true) to fail; `deadline` is held as a whole `Duration`
/// throughout; no site truncates it to seconds.
pub fn wait_for(deadline: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    loop {
        if pred() {
            return true;
        }
        if start.elapsed() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Why a re-exec of the current test binary did not prove its one test passed.
#[derive(Debug)]
pub enum RerunError {
    /// The running test binary's own path could not be read.
    Locate(std::io::Error),
    /// The re-exec could not be spawned.
    Spawn(std::io::Error),
    /// The re-exec ran and failed.
    Failed {
        status: std::process::ExitStatus,
        stdout: String,
        stderr: String,
    },
    /// The re-exec exited 0 without running exactly one passing test: libtest
    /// exits 0 when `--exact` matches nothing, so a success alone proves
    /// nothing.
    DidNotRun { stdout: String },
}

/// Re-exec the current test binary and require it ran and passed only `test`.
///
/// `test` is the full path under the crate root (e.g. `tests::name`);
/// `configure` adds the spawn-time environment and any extra harness flags.
///
/// The one shared re-exec for tests whose body needs a process environment
/// fixed at spawn: a success exit alone is vacuous, since a `test` name that
/// matches nothing (a renamed test, a wrong module path) also exits 0.
///
/// # Errors
///
/// [`RerunError`] when the binary cannot be located or spawned, the child
/// fails, or the child's libtest summary does not show one passed test.
pub fn rerun_this_test_exact(
    test: &str,
    configure: impl FnOnce(&mut Command),
) -> Result<(), RerunError> {
    let exe = std::env::current_exe().map_err(RerunError::Locate)?;
    let mut cmd = Command::new(exe);
    cmd.args(["--exact", test]);
    configure(&mut cmd);
    let out = cmd.output().map_err(RerunError::Spawn)?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        return Err(RerunError::Failed {
            status: out.status,
            stdout,
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    if ran_exactly_one_passing_test(&stdout) {
        Ok(())
    } else {
        Err(RerunError::DidNotRun { stdout })
    }
}

/// Whether a libtest run's `stdout` carries the summary of exactly one test
/// run and passed.
fn ran_exactly_one_passing_test(stdout: &str) -> bool {
    stdout
        .lines()
        .any(|line| line.starts_with("test result: ok. 1 passed; 0 failed;"))
}

#[cfg(test)]
mod tests {
    use super::{
        BoundedRun, BoundedRunError, CRATE_IDENTITY_HASH_PLACEHOLDER,
        DEFAULT_EMITTED_BUILD_IDLE_SECS, DEFAULT_EMITTED_BUILD_TIMEOUT_SECS, OutStream,
        emitted_build_idle, emitted_build_timeout, normalize_crate_identity_hash,
        ran_exactly_one_passing_test, replace_package_name, rerun_this_test_exact,
        resolve_emitted_target, run_bounded, run_bounded_build, wait_for,
    };
    use std::process::Command;
    use std::time::{Duration, Instant};

    #[test]
    fn bounded_build_kills_a_silent_wedged_process() {
        // A process that sleeps silently stands in for a wedged `cargo build`
        // (a deadlock, a lock it never gets). It emits NO output, so the
        // inactivity watchdog must kill it one idle-window after start — well
        // before the sleep finishes and well under the wide absolute backstop.
        let mut cmd = Command::new("sleep");
        cmd.arg("120");
        let started = Instant::now();
        let result = run_bounded_build(
            cmd,
            "hung_build_probe",
            Duration::from_secs(3600), // absolute backstop — must NOT be what fires
            Duration::from_millis(300), // idle window — this is what fires
        );
        let elapsed = started.elapsed();

        let err = result.expect_err("a silent 120s sleep must be killed by the idle watchdog");
        assert!(
            err.contains("no output") && err.contains("inactivity watchdog"),
            "the error must name the inactivity watchdog, not the backstop, got: {err}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the idle watchdog must fire promptly (killed the child), took {elapsed:?}"
        );
    }

    #[test]
    fn bounded_build_does_not_kill_a_slow_but_progressing_process() {
        // THE load-independence property: a build that runs FAR longer than the
        // idle window is NOT killed as long as it keeps emitting output. This is
        // exactly the slow-cold-runner case the old total-wall-clock cap
        // false-killed. Forty ticks 100ms apart run ~4s total against a 3s idle
        // window — a 30x margin between tick and window, generous enough that a
        // loaded runner's scheduler stall (shell startup, a delayed `sleep`
        // fork) cannot exceed it — yet each tick resets the window, so the
        // process completes rather than being false-killed as wedged.
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg("i=0; while [ $i -lt 40 ]; do echo tick; sleep 0.1; i=$((i+1)); done");
        let started = Instant::now();
        let idle_window = Duration::from_secs(3);
        let capture = run_bounded_build(
            cmd,
            "slow_progress_probe",
            Duration::from_secs(3600), // absolute backstop — far away
            idle_window,
        )
        .expect("a progressing process must never be killed by the idle window");
        assert!(capture.status.success());
        assert!(
            started.elapsed() >= idle_window,
            "the probe must have outlived the idle window to prove the point"
        );
        // Counting newlines across a few bytes of captured probe output; a SIMD
        // `bytecount` dependency is unwarranted for a test probe.
        #[allow(clippy::naive_bytecount)]
        let newline_count = capture.stdout.iter().filter(|&&b| b == b'\n').count();
        assert_eq!(newline_count, 40);
    }

    #[test]
    fn bounded_run_caps_a_flooding_process() {
        // `yes` writes one line after another forever, well inside the idle
        // window and the wall, so only the output cap can stop it.
        let started = Instant::now();
        let result = run_bounded(
            Command::new("yes"),
            BoundedRun {
                max_total: Duration::from_secs(3600),
                idle_window: Duration::from_secs(3600),
                out_cap: 64 * 1024,
            },
        );
        assert!(
            matches!(
                result,
                Err(BoundedRunError::OutputCap {
                    stream: OutStream::Stdout,
                    cap: 65_536,
                })
            ),
            "a flooding stdout must trip the output cap, got: {result:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the cap must stop the flood promptly, took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn bounded_run_caps_a_flood_with_no_line_break() {
        // One unbroken line past the cap is refused the same as many lines.
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg("head -c 200000 /dev/zero | tr '\\0' a 1>&2");
        let result = run_bounded(
            cmd,
            BoundedRun {
                max_total: Duration::from_secs(60),
                idle_window: Duration::from_secs(60),
                out_cap: 1024,
            },
        );
        assert!(
            matches!(
                result,
                Err(BoundedRunError::OutputCap {
                    stream: OutStream::Stderr,
                    ..
                })
            ),
            "an unbroken stderr flood must trip the output cap, got: {result:?}"
        );
    }

    #[test]
    fn bounded_build_returns_a_fast_process_output() {
        // A process that finishes inside both guards must return its captured
        // output normally.
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("printf hello; printf oops 1>&2");
        let capture = run_bounded_build(
            cmd,
            "fast_build_probe",
            Duration::from_secs(30),
            Duration::from_secs(30),
        )
        .expect("a fast process must return its output");
        assert!(capture.status.success());
        assert_eq!(capture.stdout, b"hello");
        assert_eq!(capture.stderr, b"oops");
    }

    #[test]
    fn build_timeout_defaults_when_env_absent_or_invalid() {
        // The helper reads a process-global env var; assert only the default
        // path (env unset in the test harness) so the test needs no env mutation.
        // A parse guard in the helper covers empty/zero/non-numeric overrides.
        assert_eq!(
            emitted_build_timeout(),
            Duration::from_secs(DEFAULT_EMITTED_BUILD_TIMEOUT_SECS)
        );
    }

    #[test]
    fn build_idle_defaults_when_env_absent_or_invalid() {
        // Same default-path assertion for the inactivity window.
        assert_eq!(
            emitted_build_idle(),
            Duration::from_secs(DEFAULT_EMITTED_BUILD_IDLE_SECS)
        );
    }

    #[test]
    fn rewrites_single_file_ipe_app_name() {
        let manifest = "[package]\nname = \"ipe-app\"\nversion = \"0.1.0\"\n\n[dependencies]\n";
        let out = replace_package_name(manifest, "uniq").expect("has a package name");
        assert!(out.contains("name = \"uniq\""));
        assert!(!out.contains("name = \"ipe-app\""));
    }

    #[test]
    fn rewrites_project_named_crate() {
        let manifest = "[package]\nname = \"connroseal\"\nedition = \"2024\"\n\n[dependencies]\n";
        let out = replace_package_name(manifest, "uniq").expect("has a package name");
        assert!(out.contains("name = \"uniq\""));
        assert!(!out.contains("name = \"connroseal\""));
    }

    #[test]
    fn leaves_non_package_name_lines_untouched() {
        // A `name = ` under a later section must not be mistaken for the package name.
        let manifest =
            "[package]\nname = \"app\"\n\n[[bin]]\nname = \"other\"\npath = \"src/main.rs\"\n";
        let out = replace_package_name(manifest, "uniq").expect("has a package name");
        assert!(out.contains("name = \"uniq\""));
        assert!(out.contains("name = \"other\""));
    }

    #[test]
    fn no_package_name_yields_none() {
        assert!(replace_package_name("[dependencies]\nfoo = \"1\"\n", "uniq").is_none());
    }

    // Host-independence of goldens: the per-machine crate-identity hash suffix is
    // replaced with a stable placeholder, so a golden regenerated on any machine
    // is byte-identical (the friendly base is preserved verbatim).
    #[test]
    fn crate_identity_hash_suffix_is_normalized_to_placeholder() {
        let manifest = "[package]\nname = \"mm-diamond_1a2b3c4d\"\nedition = \"2024\"\n";
        let out = normalize_crate_identity_hash(manifest);
        assert!(
            out.contains(&format!(
                "name = \"mm-diamond_{CRATE_IDENTITY_HASH_PLACEHOLDER}\""
            )),
            "hash suffix must normalize to the placeholder, got:\n{out}"
        );
        assert!(!out.contains("1a2b3c4d"), "no per-machine hash may survive");
    }

    // Two different real project paths yield different hashes; after
    // normalization BOTH collapse to the identical placeholder text — the
    // property that makes the committed golden host-independent.
    #[test]
    fn distinct_hashes_normalize_to_the_same_text() {
        let a = normalize_crate_identity_hash("[package]\nname = \"app_00112233\"\n");
        let b = normalize_crate_identity_hash("[package]\nname = \"app_deadbeef\"\n");
        assert_eq!(a, b);
    }

    // The single-file default carries no hash suffix and must pass through
    // untouched, and a `name` under a later table is never mistaken for the
    // package name.
    #[test]
    fn unhashed_and_non_package_names_pass_through() {
        let single = "[package]\nname = \"ipe-app\"\nedition = \"2024\"\n";
        assert_eq!(normalize_crate_identity_hash(single), single);

        // A dependency `name` whose value merely looks hash-shaped is untouched.
        let dep = "[package]\nname = \"app_00112233\"\n\n[[bin]]\nname = \"other_00112233\"\n";
        let out = normalize_crate_identity_hash(dep);
        assert!(out.contains(&format!("name = \"app_{CRATE_IDENTITY_HASH_PLACEHOLDER}\"")));
        assert!(
            out.contains("name = \"other_00112233\""),
            "a non-[package] name must be left alone, got:\n{out}"
        );
    }

    // A friendly base that is NOT hash-shaped (wrong width) is not mangled.
    #[test]
    fn wrong_width_suffix_is_not_treated_as_a_hash() {
        let manifest = "[package]\nname = \"my_app\"\nedition = \"2024\"\n";
        assert_eq!(normalize_crate_identity_hash(manifest), manifest);
    }

    // These lock the fail-safe semantics of `resolve_emitted_target` without
    // touching the ambient env — the function signature takes an `Option<&str>`
    // so tests pass the value directly.

    #[test]
    fn shared_absolute_path_overrides_ambient() {
        assert_eq!(
            resolve_emitted_target(Some("/home/x/.cache/ipe-lang-target")),
            Some("/home/x/.cache/ipe-lang-target".to_owned())
        );
    }

    #[test]
    fn unset_inherits_ambient_isolate() {
        assert_eq!(resolve_emitted_target(None), None);
    }

    #[test]
    fn empty_or_whitespace_fails_safe() {
        assert_eq!(resolve_emitted_target(Some("")), None);
        assert_eq!(resolve_emitted_target(Some("   ")), None);
    }

    #[test]
    fn relative_path_fails_safe() {
        assert_eq!(resolve_emitted_target(Some("relative/target")), None);
        assert_eq!(resolve_emitted_target(Some("./target")), None);
    }

    // `child_shared_target` layers the ambient-CARGO_TARGET_DIR fallback over the
    // same fail-safe resolution, so an `ipe`-subprocess site can forward the warm
    // target whether CI exports IPE_ORACLE_SHARED_TARGET or a local lane exports
    // CARGO_TARGET_DIR.
    use super::child_shared_target;

    #[test]
    fn child_prefers_absolute_shared_over_ambient() {
        assert_eq!(
            child_shared_target(Some("/warm/shared"), Some("/lane/target")),
            Some("/warm/shared".to_owned())
        );
    }

    #[test]
    fn child_falls_back_to_ambient_when_shared_absent() {
        assert_eq!(
            child_shared_target(None, Some("/lane/target")),
            Some("/lane/target".to_owned())
        );
    }

    #[test]
    fn child_falls_back_to_ambient_when_shared_non_absolute() {
        // A non-absolute shared value fails safe; a valid ambient value still wins.
        assert_eq!(
            child_shared_target(Some("relative/target"), Some("/lane/target")),
            Some("/lane/target".to_owned())
        );
    }

    #[test]
    fn child_is_none_when_neither_set() {
        assert_eq!(child_shared_target(None, None), None);
        assert_eq!(child_shared_target(Some("  "), Some("")), None);
    }

    /// The load-bearing soundness guarantee of the warm-deps/cold-app dep cache:
    /// a shared cargo target reuses only DEPENDENCY artifacts, never masking a
    /// broken app crate. Two crates build into ONE shared `CARGO_TARGET_DIR`;
    /// the first is well-typed and warms the target, the second carries a
    /// deliberate type error. cargo fingerprints each crate on its own source
    /// hash, so the second must FAIL to compile even though the target is warm —
    /// proving the SEAL cannot be greened by cache reuse.
    #[test]
    fn shared_target_never_masks_a_broken_crate() {
        use std::process::Command;

        let root = ipe_test_temp::temp_root().join(format!(
            "e2e_support_soundness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let shared_target = root.join("shared-target");

        // Minimal, dependency-free crates so the proof is fast and hermetic —
        // the fingerprint mechanism under test is cargo's, independent of the
        // dependency set. Each gets a UNIQUE package name (the same rule the
        // real harness applies), so both coexist in the one shared target.
        let write_crate = |name: &str, main_rs: &str| -> std::path::PathBuf {
            let dir = root.join(name);
            std::fs::create_dir_all(dir.join("src")).expect("create crate dir");
            std::fs::write(
                dir.join("Cargo.toml"),
                format!(
                    "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n"
                ),
            )
            .expect("write Cargo.toml");
            std::fs::write(dir.join("src").join("main.rs"), main_rs).expect("write main.rs");
            dir
        };

        let build_into_shared = |dir: &std::path::Path| -> std::process::Output {
            Command::new("cargo")
                .arg("build")
                .current_dir(dir)
                .env("CARGO_TARGET_DIR", &shared_target)
                .env("CARGO_BUILD_RUSTC_WRAPPER", "")
                .env("RUSTC_WRAPPER", "")
                .output()
                .expect("cargo must spawn")
        };

        // 1. Well-typed crate → warms the shared target and succeeds.
        let good = write_crate("e2e_soundness_good", "fn main() { println!(\"ok\"); }");
        let good_out = build_into_shared(&good);
        assert!(
            good_out.status.success(),
            "the well-typed crate must build into the shared target\n{}",
            String::from_utf8_lossy(&good_out.stderr)
        );

        // 2. Broken crate (E0308) → the warm target MUST NOT mask it.
        let bad = write_crate(
            "e2e_soundness_bad",
            "fn main() { let _x: u32 = \"not a number\"; }",
        );
        let bad_out = build_into_shared(&bad);
        assert!(
            !bad_out.status.success(),
            "SOUNDNESS BREACH: a crate with a deliberate type error built \
             successfully into the warm shared target — the dep cache masked a \
             broken app. The SEAL is only sound if this build FAILS."
        );
        assert!(
            String::from_utf8_lossy(&bad_out.stderr).contains("E0308"),
            "the broken crate must fail with the injected type mismatch (E0308)\n{}",
            String::from_utf8_lossy(&bad_out.stderr)
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The re-exec target of the positive rerun test: passes trivially.
    #[test]
    fn a_rerun_target_that_passes() {}

    #[test]
    fn a_rerun_of_a_real_test_proves_it_ran() {
        let rerun = rerun_this_test_exact("tests::a_rerun_target_that_passes", |_| {});
        assert!(
            rerun.is_ok(),
            "the real test must be re-run and pass: {rerun:?}"
        );
    }

    #[test]
    fn a_rerun_of_a_test_name_that_matches_nothing_is_refused() {
        let rerun = rerun_this_test_exact("tests::no_test_has_this_name", |_| {});
        assert!(
            matches!(rerun, Err(super::RerunError::DidNotRun { .. })),
            "a zero-match re-exec exits 0 yet must be refused: {rerun:?}"
        );
    }

    #[test]
    fn only_a_one_passed_summary_counts_as_a_run() {
        assert!(ran_exactly_one_passing_test(
            "running 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s\n"
        ));
        assert!(!ran_exactly_one_passing_test(
            "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 0.00s\n"
        ));
        assert!(!ran_exactly_one_passing_test(
            "running 1 test\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 9 filtered out; finished in 0.00s\n"
        ));
        assert!(!ran_exactly_one_passing_test(""));
    }

    #[test]
    fn wait_for_returns_true_as_soon_as_the_predicate_holds() {
        let mut calls = 0;
        assert!(wait_for(Duration::from_secs(2), || {
            calls += 1;
            calls >= 3
        }));
        assert_eq!(
            calls, 3,
            "must stop polling the instant the predicate holds"
        );
    }

    #[test]
    fn wait_for_times_out_instead_of_blocking_forever_on_a_predicate_that_never_holds() {
        let started = Instant::now();
        let deadline = Duration::from_millis(200);
        assert!(
            !wait_for(deadline, || false),
            "a predicate that never holds must yield false, never panic or hang"
        );
        assert!(
            started.elapsed() >= deadline,
            "must have actually waited out the deadline, not returned early"
        );
    }
}
