//! `ipe watch`.
//!
//! The salsa-aware orchestrator that wires [`ipe_watch`]'s salsa-agnostic
//! primitives (confined watcher, debounce, process supervisor) to THIS
//! crate's warm compile pipeline. This is the first real CONSUMER of
//! incremental compilation's speed benefit — a naive "re-run `ipe build`
//! from scratch on every save" watch mode would defeat the entire point of
//! the salsa port.
//!
//! Decision record: `docs/adr/0007-build-incrementality-and-release-infra.md`.
//!
//! ## Architecture
//!
//! Three threads plus the orchestrator (this module's `run`):
//!
//! 1. **notify watcher thread** (owned by the `notify::Watcher` handle) —
//!    pushes every IN-SCOPE raw path change onto an `mpsc` channel. The
//!    [`ipe_watch::WatchScope::is_relevant`] filter runs INSIDE the event
//!    callback, so an excluded-dir storm never reaches the channel at all.
//!    The callback ALSO rejects `EventKind::Access` (open/read)
//!    and `EventKind::Other` before that filter even runs — load-bearing,
//!    not an optimisation: `resolve_project_sources` opens every in-scope
//!    file on every rebuild, and without this exclusion that OPEN is
//!    itself an observable event that would queue another rebuild forever.
//!    One Access sub-variant, `Close(Write)`, is deliberately EXEMPTED from
//!    that rejection — it is the write-completion proof a debounce window
//!    alone cannot substitute for; see the callback's own doc comment for
//!    why.
//! 2. **coalesce thread** — [`ipe_watch::coalesce_loop`] turns that raw
//!    stream into settled batches (the debounce half).
//! 3. **compile worker thread** (spawned fresh per rebuild cycle) — holds a
//!    CLONED [`ipe_db::IpeDatabase`] handle and runs [`compile_prepared`]
//!    inside [`salsa::Cancelled::catch`]. The orchestrator thread never runs
//!    a salsa query itself; it only mutates inputs (which is what makes a
//!    superseding edit cancel the in-flight worker — see the cancellation
//!    section below).
//!
//! The orchestrator drains one unified `mpsc::Receiver<OrchestratorEvent>`
//! that both the coalesce thread and every worker/cargo-wait thread feed —
//! a single blocking `recv()` with **no busy-polling**, and no risk of two
//! event sources racing on separate wakeups.
//!
//! ## Cancellation, and why it needs no extra machinery
//!
//! Salsa's `#[salsa::input]` setters require `&mut IpeDatabase` (routed
//! through `zalsa_mut()`), which — per `salsa::Storage`'s own documented
//! contract (verified against the pinned `salsa=0.27.2` source,
//! `src/storage.rs`'s `cancel_others`) — sets a cancellation flag and BLOCKS
//! until every other `Storage` handle (a `.clone()` of the database, exactly
//! what a compile worker holds) has been dropped. A query running on a
//! cancelled snapshot unwinds via `panic::resume_unwind(Cancelled)` the next
//! time it checks (every tracked-function boundary — the `WillCheckCancellation`
//! event salsa's own test suite pins). So:
//!
//! - the orchestrator NEVER calls `sync_source_root` while ALSO holding a
//!   worker's clone alive on its own thread — it hands the clone to the
//!   worker THREAD and keeps only the original `db_main` on the orchestrator
//!   thread;
//! - when a new settled batch arrives mid-build, `sync_source_root(&mut
//!   db_main, …)` is called immediately — this call blocks (invisibly, from
//!   the orchestrator's point of view) until the worker thread's query
//!   unwinds and drops its cloned `Storage`, then returns; the worker thread
//!   observes `Cancelled` via `salsa::Cancelled::catch`, reports it, and
//!   exits;
//! - the orchestrator then spawns a FRESH worker against the just-synced
//!   (latest) state.
//!
//! This is exactly rust-analyzer's own cancellation pattern, and it needs
//! zero new synchronisation primitives beyond what salsa already provides.
//!
//! `cargo build` cancellation (never overlapping cargo builds) uses the
//! portable equivalent for a plain OS process: the
//! orchestrator holds the `Child` handle directly and supersedes it (records
//! the kill, then `.kill()`s) on a superseding batch; a dedicated per-build
//! "waiter" thread polls for exit and reports completion (or, when the
//! orchestrator recorded the kill, "superseded, not a real failure") through the
//! SAME unified event channel, tagged with a generation counter so a stale
//! completion from an already-superseded cycle is silently ignored rather
//! than raced against the new one.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::output_dir::{EmitTarget, OutputRefusal, OwnedDir, ProjectPaths};
use crate::project;
use crate::text;
use crate::{CliError, write_emitted_project};

/// A lifecycle notification from a running watch session.
///
/// Delivered synchronously (before the orchestrator moves on) through
/// [`WatchOptions::on_event`]. This is the seam integration tests use to
/// observe internal state transitions (exactly-once coalescing, red-build
/// preservation, cancellation) without racing wall-clock timing or
/// capturing stderr — and, incidentally, a reusable hook for a future
/// structured/`--json` watch log. The CLI path leaves `on_event` unset
/// (`None`), so it costs nothing there.
#[derive(Debug, Clone)]
pub enum WatchEvent {
    /// A settled batch triggered a NEW rebuild cycle. Exactly one of these
    /// fires per coalesced batch, never per raw filesystem event.
    RebuildStarted { generation: u64 },
    /// `generation`'s compile finished with a compiler diagnostic — the
    /// running process (if any) is untouched (INV-3).
    CompileFailed { generation: u64 },
    /// `generation`'s compile was cancelled by a superseding edit
    /// — never reported to the end user, but observable here for tests.
    CompileCancelled { generation: u64 },
    /// `generation`'s `cargo build` failed — the running process (if any)
    /// is untouched (INV-3).
    CargoFailed { generation: u64 },
    /// `generation`'s `cargo build` was killed because a newer batch
    /// superseded it ("never overlapping cargo builds").
    CargoKilled { generation: u64 },
    /// `generation` reached [`ipe_watch::SupervisorState::apply_green`] and
    /// this was the outcome.
    Restarted {
        generation: u64,
        outcome: RestartOutcomeKind,
    },
    /// `generation`'s edit was classified appearance-only and hot-swapped into
    /// the running app via a `LiteralTable` patch — no cargo rebuild, no restart.
    /// `views` is the number of edited views patched. Only fires under
    /// [`WatchOptions::hot_appearance`].
    AppearanceHotSwapped { generation: u64, views: usize },
}

/// A test/observability-friendly mirror of [`ipe_watch::RestartOutcome`].
///
/// That type intentionally isn't `Clone` — it can carry a live [`Child`]
/// via [`ipe_watch::SupervisorState`] elsewhere in this module — so
/// [`WatchEvent`] carries this small `Clone`-able summary instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartOutcomeKind {
    Spawned,
    UnchangedBinary,
    Restarted,
    RespawnedLastGood,
    NothingRunning,
}

/// Configuration for one `ipe watch` session. Every field has a sound
/// default via [`WatchOptions::new`]; the CLI layer (`run_watch` in
/// `lib.rs`) is the only place that overrides them from flags.
// The flags are independent dev toggles (quiet / blue-green / reset-state /
// debugger), not the axes of a state machine — a two-variant enum per flag would
// obscure, not clarify, so the bool-per-toggle shape is the honest one.
#[allow(clippy::struct_excessive_bools)]
pub struct WatchOptions {
    pub entry: PathBuf,
    pub out_dir: PathBuf,
    pub runtime_dir: PathBuf,
    /// The port injected as `IPE_WEB_PORT` for the spawned child and probed
    /// for `/_ipe/readyz` when the emitted project is detected as a
    /// Ipe.Web app. Harmless (ignored) for every other app shape.
    pub port: u16,
    pub debounce: ipe_watch::DebounceConfig,
    pub restart_timeouts: ipe_watch::RestartTimeouts,
    /// The resolved `cargo` executable each rebuild spawns. The CLI layer
    /// resolves it once (fail-closed) before the loop starts and stores the
    /// path here; the default is the bare name `cargo`, deferring to `PATH`
    /// resolution for callers that do not pre-resolve.
    pub cargo_path: PathBuf,
    /// Optional lifecycle observer — see [`WatchEvent`]. `None` on the CLI
    /// path.
    pub on_event: Option<Arc<dyn Fn(WatchEvent) + Send + Sync>>,
    /// Suppress progress chatter — only warnings and errors are printed.
    /// Passes `-q` to cargo and skips the lifecycle status lines.
    pub quiet: bool,
    /// DEV-ONLY blue-green cutover. When set, `ipe watch` puts a persistent
    /// front proxy on `port` and runs each rebuilt binary behind it on a fresh
    /// internal loopback port, cutting traffic over once the new binary passes
    /// readiness — so a rebuild never drops the browser's connection. The CLI
    /// path sets this on by default (see [`crate::bluegreen_enabled`]; opt out
    /// with `IPE_WATCH_NO_BLUEGREEN`); the raw [`WatchOptions::new`] default is
    /// off (the direct-bind, kill-old-then-spawn-new path) for a library caller
    /// that has not chosen. Never compiled into a release binary or an emitted
    /// app.
    pub bluegreen: bool,
    /// DEV-ONLY state-reset escape hatch. When set, the next spawned child
    /// receives `IPE_WEB_RESET_STATE=1`, which makes the runtime skip the
    /// session-checkpoint hydration and force every returning session to a fresh
    /// `init` for the lifetime of that process. The flag is off by default (the
    /// additive-preserve algorithm runs normally). Exposed as `ipe watch
    /// --reset-state`. Never compiled into a release binary.
    pub reset_state: bool,
    /// DEV-ONLY debugger. When set, each rebuild emits with the `debugger`
    /// runtime feature so the served app carries the in-app time-travelling
    /// debugger overlay. Exposed as `ipe watch --debugger`; off by default (the
    /// recorder adds runtime weight). Never compiled into a release binary.
    pub debugger: bool,
    /// DEV-ONLY appearance hot-swap. When set, each rebuild emits with a
    /// `LiteralTable` overlay and an appearance-only edit is patched into the
    /// running app instead of rebuilt. [`WatchOptions::new`] reads the default
    /// once from the environment (see [`crate::hot_appearance_enabled`]).
    pub hot_appearance: bool,
    /// Optional cargo target directory the rebuild's `cargo build` is pinned to.
    /// `None` (the CLI default) leaves the build to honour an inherited
    /// `CARGO_TARGET_DIR`, exactly as before. An embedder sets it to pin the
    /// build to a specific — typically warm — target so a rebuild links against
    /// a pre-compiled dependency tree instead of cold-building it; the E2E watch
    /// suite uses it to forward the CI shard's warm shared target.
    pub target_dir: Option<PathBuf>,
    /// The proven target `out_dir` names, when the caller holds one.
    ///
    /// Each rebuild claims it through its proof; `None` proves `out_dir`
    /// disjoint from the watched project before the session starts.
    pub out_target: Option<EmitTarget>,
}

impl WatchOptions {
    #[must_use]
    pub fn new(entry: PathBuf, out_dir: PathBuf, runtime_dir: PathBuf) -> Self {
        Self {
            entry,
            out_dir,
            runtime_dir,
            port: 8000,
            debounce: ipe_watch::DebounceConfig::default(),
            restart_timeouts: ipe_watch::RestartTimeouts::for_dev_watch(),
            cargo_path: PathBuf::from("cargo"),
            on_event: None,
            quiet: false,
            bluegreen: false,
            reset_state: false,
            debugger: false,
            hot_appearance: crate::hot_appearance_enabled(),
            target_dir: None,
            out_target: None,
        }
    }
}

fn emit(opts: &WatchOptions, event: WatchEvent) {
    if let Some(cb) = &opts.on_event {
        cb(event);
    }
}

/// Render a watch lifecycle line with a deterministic 4-space gutter (two
/// [`crate::style::GUTTER`] widths — one level deeper than the CLI's own
/// top-level banner/status indent, matching the runtime child's own
/// `[ipe.http.server]`/`[ipe.live]` startup-line indent) and optional colour.
/// `role` selects the semantic colour: `Info`, `Success`, or `Failure`.
#[derive(Clone, Copy)]
enum WatchRole {
    /// Informational status: building, watching, change detected.
    Info,
    /// A successful outcome: app started, app reloaded.
    Success,
    /// A failure outcome: build failed, readiness failed.
    Failure,
}

/// The single source of truth for the "first SIGTERM consumed" ack.
///
/// The forwarder emits this text once, through [`watch_line`] (so the printed
/// line wraps it in gutter/colour escapes — match it as a substring, never for
/// byte-equality), the moment it consumes the first SIGTERM and begins the
/// orderly teardown. Any supervisor or test that must observe consumption waits
/// for this line rather than a timing guess: a second SIGTERM sent only after
/// it appears is provably after the forwarder spent its one registration, so it
/// is guaranteed absorbed.
pub const SIGTERM_TEARDOWN_MARKER: &str = "[ipe watch] SIGTERM received; shutting down";

/// `text` is already-sanitised [`TerminalSafe`], mirroring [`crate::screen::error_screen`]:
/// the line's own gutter/colour escapes are the only control bytes the output may
/// carry. Callers construct it via [`crate::style::TerminalSafe::sanitize`] at the
/// message boundary, so an unsanitised watch message is unrepresentable here.
fn watch_line(text: &crate::style::TerminalSafe, role: WatchRole) -> String {
    let p = crate::style::Palette::for_stream(&std::io::stderr());
    let (colour, glyph, reset) = match role {
        WatchRole::Info => (p.dim, "", p.reset),
        WatchRole::Success => (p.green, "", p.reset),
        // A failed rebuild leaves the last-good binary running, so it is a soft
        // warning, not a hard stop — a calm light yellow, never alarming red.
        WatchRole::Failure => (
            // Failure glyph from the SSOT; the tint is the soft warning amber,
            // not red — a failed rebuild leaves the last-good binary running.
            p.bright_yellow,
            crate::style::outcome_glyph(crate::style::Outcome::Failure),
            p.reset,
        ),
    };
    // The indent is literal GUTTER text placed BEFORE any colour escape, on
    // every role alike, so it is deterministic regardless of colour state and
    // so `screen::guttered_once`'s `starts_with(GUTTER)` check recognises it
    // and never adds a second gutter on top (the prior colour-first
    // construction on the `Info`/`Success` arms defeated that check, so those
    // two roles rendered at 4 spaces with colour on but only 2 with colour
    // off — this makes all three roles a fixed 4 spaces either way).
    let indent = format!("{}{}", crate::style::GUTTER, crate::style::GUTTER);
    let prefix = if glyph.is_empty() {
        format!("{indent}{colour}{reset}")
    } else {
        format!("{indent}{colour}{glyph}{reset} ")
    };
    format!("{prefix}{text}")
}

/// Write one [`watch_line`] to stderr as progress chatter.
fn emit_watch_line(text: &crate::style::TerminalSafe, role: WatchRole) {
    crate::screen::chatter_styled(
        crate::screen::Stream::Stderr,
        &format!("{}\n", watch_line(text, role)),
    );
}

/// Per-phase wall-clock timing for ONE rebuild cycle, printed to stderr as a
/// guttered breakdown when `IPE_WATCH_TIMING=1` — a diagnostic for locating
/// where a rebuild's wall-clock goes.
///
/// Off by default: [`RebuildTimings::enabled`] reads the env gate ONCE at
/// cycle start; when unset, the `report` is a no-op and the per-phase
/// `Instant` reads it guards cost nothing, so the normal `ipe watch` path is
/// unaffected.
///
/// Each field is the wall-clock of a real phase boundary in the orchestrator
/// (measured with [`Instant`], never a fabricated split). Phases that run on a
/// helper thread (compile, cargo) measure their own span there and hand the
/// measured [`Duration`] back through the event channel, so the orchestrator
/// records a real elapsed time rather than inferring one from event arrival.
#[derive(Debug, Default, Clone, Copy)]
struct RebuildTimings {
    enabled: bool,
    /// When this cycle's `FsBatch` was received — the anchor the total is
    /// measured against.
    cycle_start: Option<Instant>,
    /// edit → settled batch (the coalescer's quiescence window). `None` for
    /// the initial kickoff cycle and resolve-retry cycles, which carry no
    /// first-event timestamp.
    settle: Option<Duration>,
    /// `resolve_project_sources` + FFI-catalog prep + `sync_source_root`
    /// (input mutation into the warm salsa db) — the orchestrator-thread work
    /// of the `FsBatch` arm before the compile worker is spawned.
    resolve: Option<Duration>,
    /// `compile_prepared`: canon + link + typecheck + lower + emit-IR, the
    /// salsa warm-compile. Measured on the worker thread.
    compile: Option<Duration>,
    /// `write_emitted_project`: serialise the in-memory emitted project to the
    /// out-dir (`src/*.rs`, `Cargo.toml`, prune).
    write: Option<Duration>,
    /// `cargo build`: compile + link the emitted crate. One number — the JSON
    /// stream does not separate rustc codegen from the final link step, so it
    /// is reported whole (see the report's own note).
    cargo: Option<Duration>,
    /// Kill the old child + spawn the new one + readiness probe
    /// (`SupervisorState::apply_green`).
    restart: Option<Duration>,
}

impl RebuildTimings {
    /// Start a cycle's timing. Reads the `IPE_WATCH_TIMING` gate once; a value
    /// of exactly `1` enables the breakdown, anything else (unset included)
    /// leaves it off.
    fn start(settle: Option<Duration>) -> Self {
        let enabled = ipe_env::var("IPE_WATCH_TIMING").as_deref() == Ok("1");
        Self {
            enabled,
            cycle_start: enabled.then(Instant::now),
            settle,
            ..Self::default()
        }
    }

    /// The sum of every recorded phase — the accounted-for wall-clock. The
    /// residual against the observed total is everything the phase splits miss
    /// (channel hops between the orchestrator and its worker/waiter threads,
    /// scheduling latency).
    fn summed(&self) -> Duration {
        [
            self.settle,
            self.resolve,
            self.compile,
            self.write,
            self.cargo,
            self.restart,
        ]
        .into_iter()
        .flatten()
        .sum()
    }

    /// Render the breakdown to stderr, guttered, one phase per line in ms plus
    /// the observed total and the residual (total − Σ phases), so a reader can
    /// see how much wall-clock the phase splits fail to account for (channel
    /// hops, scheduling). A no-op when the gate is off.
    fn report(&self, generation: u64) {
        if !self.enabled {
            return;
        }
        let Some(start) = self.cycle_start else {
            return;
        };
        let total = start.elapsed();
        let ms = |d: Option<Duration>| {
            d.map_or_else(
                || "     —".to_owned(),
                |d| format!("{:6.1}", d.as_secs_f64() * 1000.0),
            )
        };
        let residual = total.saturating_sub(self.summed());
        let body = format!(
            "[ipe watch timing] generation {generation}\n\
             settle    {} ms   (edit -> settled batch)\n\
             resolve   {} ms   (read sources + ffi + salsa sync)\n\
             compile   {} ms   (canon+link+typecheck+lower+emit-IR)\n\
             write     {} ms   (emit Rust project to disk)\n\
             cargo     {} ms   (cargo build: compile + link)\n\
             restart   {} ms   (kill old + spawn new + readiness)\n\
             --------\n\
             total     {:6.1} ms   (observed, FsBatch -> restart done)\n\
             residual  {:6.1} ms   (total - sum of phases)",
            ms(self.settle),
            ms(self.resolve),
            ms(self.compile),
            ms(self.write),
            ms(self.cargo),
            ms(self.restart),
            total.as_secs_f64() * 1000.0,
            residual.as_secs_f64() * 1000.0,
        );
        crate::screen::Screen::new(crate::screen::Stream::Stderr)
            .line(crate::screen::Tone::Aux, &body)
            .emit();
    }
}

/// One resolved project snapshot — the ingredients [`compile_modules`]
/// (the one-shot driver) would consume, but returned to the CALLER instead
/// of immediately compiled, so `ipe watch` can re-resolve on every settled
/// batch and feed the result through a WARM, reused database via
/// `ipe_db::sync_source_root` rather than constructing a fresh one per
/// build. Deliberately mirrors `run_build`'s own manifest-resolution
/// dispatch (`crates/ipe/src/lib.rs`) without touching that code — the
/// one-shot entry points stay exactly as tested by the golden suite; this
/// is an independent, read-only duplicate of the RESOLUTION step only (no
/// compiler stage runs here).
pub(crate) struct ResolvedProject {
    pub(crate) sources: BTreeMap<Vec<String>, (PathBuf, String)>,
    pub(crate) discovered: Vec<project::DiscoveredModule>,
    pub(crate) entry_path: Vec<String>,
    pub(crate) blame_path: PathBuf,
    pub(crate) db_driver: ipe_backend_rust::DbDriver,
    /// The `[wasm] publicEnv` allowlist (empty for the no-manifest loose-file
    /// path — there is no manifest to declare one).
    pub(crate) wasm_public_env: Vec<String>,
    /// The sanitized Cargo package name for the emitted crate (from `package.ipe`
    /// name via [`ipe_backend_rust::sanitize_cargo_name`]). Empty string
    /// when no manifest is present (sibling-discovery path uses `"ipe-app"`).
    pub(crate) cargo_name: String,
    /// What the confined watcher observes for this snapshot.
    pub(crate) scope: ScopeSpec,
}

/// The inputs a [`ipe_watch::WatchScope`] is built from, per project shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScopeSpec {
    /// A manifest project: the manifest's directory, watched recursively.
    Package {
        /// The manifest's directory.
        root: PathBuf,
        /// Every module file the bounded module discovery found.
        source_files: Vec<PathBuf>,
    },
    /// A loose file: the entry and the sibling module files its import closure probes.
    LooseFile {
        /// The entry `.ipe` file as given on the command line.
        entry: PathBuf,
        /// Every probed module file, relative to the entry's directory.
        module_files: Vec<PathBuf>,
        /// Every module file the build loaded, relative to the entry's directory.
        loaded_files: Vec<PathBuf>,
    },
}

impl ScopeSpec {
    /// Build the confined scope this spec describes.
    ///
    /// # Errors
    /// [`ipe_watch::ScopeError`] when the root is missing or the scope is too large.
    fn build(&self) -> Result<ipe_watch::WatchScope, ipe_watch::ScopeError> {
        match self {
            Self::Package { root, source_files } => {
                ipe_watch::WatchScope::build(root, root, source_files)
            }
            Self::LooseFile {
                entry,
                module_files,
                loaded_files,
            } => ipe_watch::WatchScope::loose_file(entry, module_files, loaded_files),
        }
    }
}

/// Resolve `entry` (a `.ipe` file or a project directory) into a fresh
/// [`ResolvedProject`] by re-reading every relevant file from disk. Mirrors
/// `run_build`'s dispatch: directory → `package.ipe` inside it; `.ipe` → walk
/// up for a manifest, else the loose-file import closure
/// ([`crate::loose_file::resolve_loose_file`]).
///
/// `entry_text_override`, when given, shadows the entry `.ipe` file's disk
/// bytes in the no-manifest branch. `ipe watch` always passes `None` (disk
/// is its truth).
///
/// # Errors
/// [`CliError::Io`] on any filesystem failure; [`CliError::Pipeline`] if the
/// entry file itself fails to parse (needed only to learn its imports in the
/// no-manifest case); [`CliError::DiscoveryLimitReached`] when a loose
/// file's import closure is too large.
pub(crate) fn resolve_project_sources(
    entry: &Path,
    entry_text_override: Option<&str>,
) -> Result<ResolvedProject, CliError> {
    let manifest_path = if entry.is_dir() {
        match project::manifest_in_dir(entry) {
            Some(manifest) => Some(manifest),
            None if project::has_only_legacy_toml(entry) => {
                return Err(CliError::Usage(text::msg::legacy_toml_hint()));
            }
            None => {
                return Err(CliError::Usage(text::msg::watch_dir_no_manifest()));
            }
        }
    } else {
        crate::find_manifest_for_ipe_file(entry)?
    };

    if let Some(manifest_path) = manifest_path {
        let manifest = project::parse_manifest(&manifest_path)?;
        let discovered = project::discover_modules(&manifest.src_root)?;
        let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
        for m in &discovered {
            let src = crate::io_bounded::read_walked_source(m.path())?;
            sources.insert(m.module_path().to_vec(), (m.path().to_path_buf(), src));
        }
        let cargo_name = ipe_backend_rust::sanitize_cargo_name(&manifest.name);
        // The entry defaults to `["Main"]`; a `programs` manifest routes its
        // (default) program's declared entry file through instead. Named
        // multi-program selection is a reported residual — see
        // `misc/docs/package-programs-design.md`.
        let entry_path = manifest.resolved_entry()?;
        let package_root = manifest_path
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        let source_files = discovered.iter().map(|m| m.path().to_path_buf()).collect();
        return Ok(ResolvedProject {
            sources,
            discovered,
            entry_path,
            blame_path: manifest_path,
            db_driver: manifest.driver,
            wasm_public_env: manifest.wasm.public_env,
            cargo_name,
            scope: ScopeSpec::Package {
                root: package_root,
                source_files,
            },
        });
    }

    // No manifest: the loose-file closure, the same one `ipe build` compiles.
    let loaded = crate::loose_file::resolve_loose_file(
        entry,
        entry_text_override,
        crate::loose_file::LooseFileLimits::DEFAULT,
    )?;
    Ok(ResolvedProject {
        sources: loaded.sources,
        discovered: loaded.discovered,
        entry_path: loaded.entry_module,
        blame_path: entry.to_path_buf(),
        db_driver: ipe_backend_rust::DbDriver::Sqlite,
        wasm_public_env: Vec::new(),
        cargo_name: String::new(),
        scope: ScopeSpec::LooseFile {
            entry: entry.to_path_buf(),
            module_files: loaded.probed_files,
            loaded_files: loaded.loaded_files,
        },
    })
}

/// The directories a scope hands the OS-level watcher.
fn watched_roots(scope: &ipe_watch::WatchScope) -> BTreeSet<PathBuf> {
    scope
        .roots_to_watch()
        .iter()
        .map(|watched| watched.as_path().to_path_buf())
        .collect()
}

/// Rebuild a loose-file scope from a fresh snapshot so the watcher follows the current import closure.
///
/// Directories the new closure needs are watched before the swap and
/// directories it dropped are unwatched after it; a package scope is
/// recursive and never changes. A scope that fails to build keeps the
/// previous one in force, and a directory that fails to watch is logged.
/// Returns whether a directory was added: an event inside it between the
/// snapshot's read and the watch taking effect went unobserved, so the
/// caller resolves once more.
///
/// The scope lock is never held across a watcher call, since the watcher's
/// event thread takes the same lock.
fn rescope(
    watcher: &mut notify::RecommendedWatcher,
    shared: &RwLock<ipe_watch::WatchScope>,
    spec: &ScopeSpec,
) -> bool {
    if matches!(spec, ScopeSpec::Package { .. }) {
        return false;
    }
    let next = match spec.build() {
        Ok(next) => next,
        Err(e) => {
            emit_watch_line(
                &crate::style::TerminalSafe::sanitize(text::Message::relay(&e).as_str()),
                WatchRole::Failure,
            );
            return false;
        }
    };
    let previous = watched_roots(&shared.read().unwrap_or_else(PoisonError::into_inner));
    let current = watched_roots(&next);
    let mode = next.recursive_mode();
    let mut added = false;
    for dir in current.difference(&previous) {
        match notify::Watcher::watch(watcher, dir, mode) {
            Ok(()) => added = true,
            Err(e) => emit_watch_line(
                &crate::style::TerminalSafe::sanitize(
                    text::msg::watch_path_failed(&dir.display(), &e).as_str(),
                ),
                WatchRole::Failure,
            ),
        }
    }
    *shared.write().unwrap_or_else(PoisonError::into_inner) = next;
    for dir in previous.difference(&current) {
        let _ = notify::Watcher::unwatch(watcher, dir);
    }
    added
}

/// One event on the orchestrator's unified channel. Carries a `generation`
/// on every variant whose completion could race a superseding cycle, so a
/// STALE completion (from a cycle the orchestrator has already moved past)
/// is recognisable and silently dropped rather than raced against the
/// current one.
enum OrchestratorEvent {
    /// A settled batch of filesystem changes — the coalescer's output.
    /// Carries no paths: `ipe watch` re-resolves the WHOLE project on every
    /// cycle (cheap — a directory walk over a bounded file set) and lets
    /// `sync_source_root`'s own byte-equal no-op boundary do the real
    /// dirty-vs-clean filtering, so there is no need to thread individual
    /// changed paths through the recompute step. `settle` carries the
    /// coalescer's edit→settled latency for `IPE_WATCH_TIMING` (`None` for the
    /// initial kickoff and resolve-retry cycles, which have no batch).
    FsBatch { settle: Option<Duration> },
    /// The compile worker for `generation` finished (successfully, with a
    /// compiler diagnostic, or cancelled). `compile` is the worker-measured
    /// wall-clock of `compile_prepared` (only meaningful for a Green/Red
    /// outcome; a cancelled cycle's time is not reported).
    CompileDone {
        generation: u64,
        outcome: CompileOutcome,
        compile: Duration,
    },
    /// The `cargo build` for `generation` finished (successfully, with a
    /// build failure, or was killed because it was superseded). `cargo` is the
    /// waiter-measured wall-clock from spawn to exit.
    CargoDone {
        generation: u64,
        outcome: CargoOutcome,
        cargo: Duration,
    },
    /// An external caller requested a clean shutdown (see [`WatchHandle`]).
    /// Used by tests and any future embedder that needs to stop a watch
    /// session programmatically rather than only on Ctrl-C.
    Shutdown,
}

/// Upper bound on how long [`WatchHandle::stop`] (and, transitively,
/// [`WatchHandle`]'s `Drop` safety net) will block waiting for the
/// orchestrator thread to confirm it has actually finished tearing down
/// (child process killed/reaped, watcher + coalesce threads joined) —
/// never an unbounded wait (the "every long-running command is timeout-bounded"
/// rule: every long-running command is timeout-bounded). Generously above the realistic worst case: a
/// `graceful_stop` of [`ipe_watch::RestartTimeouts::default`]'s 3 s, plus
/// slack for the cargo-kill waiter's poll loop, the compile worker's salsa
/// unwind, and the coalesce thread's join — all of which are themselves
/// individually bounded and normally complete in well under a second once
/// shutdown starts (the dev-watch `graceful_stop`,
/// [`ipe_watch::RestartTimeouts::for_dev_watch`], is a fraction of a second).
const SHUTDOWN_WAIT_BUDGET: Duration = Duration::from_secs(20);

/// Delay before retrying a cycle whose `resolve_project_sources` call
/// failed. A transient resolve failure (mid-save partial write, a file
/// momentarily unreadable during an editor's atomic rename) has no
/// guarantee of a follow-up filesystem event to retry it, so the cycle
/// schedules its own retry rather than losing the save until the next
/// unrelated edit.
const RESOLVE_RETRY_DELAY: Duration = Duration::from_millis(250);

/// Schedule one follow-up [`OrchestratorEvent::FsBatch`] after
/// [`RESOLVE_RETRY_DELAY`] — the recovery path for a `resolve_project_sources`
/// failure. Without this, a transient failure has no other route back into
/// the orchestrator's event loop: the triggering save is lost until an
/// unrelated future filesystem event happens to arrive.
fn schedule_resolve_retry(evt_tx: &mpsc::Sender<OrchestratorEvent>) {
    let retry_tx = evt_tx.clone();
    thread::spawn(move || {
        thread::sleep(RESOLVE_RETRY_DELAY);
        let _ = retry_tx.send(OrchestratorEvent::FsBatch { settle: None });
    });
}

/// A handle to a running [`spawn`]ed watch session.
///
/// Lets the caller request a clean shutdown from another thread — the seam
/// integration tests use to stop `ipe watch` deterministically instead of
/// relying on a process signal.
///
/// `Drop` is a genuine safety net, not merely `stop()` called for you: an
/// embedder that lets a `WatchHandle` fall out of scope WITHOUT calling
/// `stop()` first — a bug in the embedder's own code, a panic unwinding
/// through a scope that holds one, an early `return`/`?` — must never leak
/// the supervised child process (a whole spawned `ipe-app` server binding a
/// real port) as an orphan. `stop()` and `Drop::drop` therefore share one
/// synchronous, bounded implementation: signal the orchestrator, then block
/// (up to [`SHUTDOWN_WAIT_BUDGET`]) until it confirms teardown is done —
/// not merely requested.
pub struct WatchHandle {
    stop_tx: mpsc::Sender<()>,
    /// Signalled by the orchestrator thread's own wrapper (see [`spawn`])
    /// once `run_inner` has returned — i.e. AFTER `SupervisorState::shutdown`
    /// has killed/reaped the supervised child and every helper thread has
    /// been joined. `Mutex<Option<..>>` rather than a bare `Receiver` so
    /// `stop()` can take `&self` (matching its pre-existing public
    /// signature) while still being able to drain the receiver exactly
    /// once; a second `stop()`/`Drop` call after the first successful wait
    /// finds `None` and is a harmless no-op, matching `stop()`'s existing
    /// idempotency contract.
    done_rx: Mutex<Option<mpsc::Receiver<()>>>,
}

impl WatchHandle {
    /// Request a clean shutdown and BLOCK (bounded by
    /// [`SHUTDOWN_WAIT_BUDGET`]) until the orchestrator thread confirms it
    /// has actually finished — not merely until the request was sent.
    /// Idempotent: a second call, or a call after `Drop` already waited
    /// (impossible through the public API, since `Drop` consumes `self`,
    /// but relevant to `Drop`'s own internal reuse of this method) is a
    /// harmless no-op.
    pub fn stop(&self) {
        let _ = self.stop_tx.send(());
        self.wait_for_shutdown();
    }

    /// Block until the orchestrator's done-signal arrives, or
    /// [`SHUTDOWN_WAIT_BUDGET`] elapses — whichever comes first. Draining
    /// (`Option::take`) the receiver makes this safe to call more than
    /// once: every call after the first successful wait (or a prior
    /// `Drop`) is a no-op.
    fn wait_for_shutdown(&self) {
        let mut guard = self
            .done_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(rx) = guard.take() {
            let _ = rx.recv_timeout(SHUTDOWN_WAIT_BUDGET);
        }
    }
}

impl Drop for WatchHandle {
    /// The safety net described on the type itself: guarantees the
    /// supervised child process is torn down even when the embedder never
    /// called `stop()` — including when a panic unwinds through a scope
    /// holding a `WatchHandle`. Rust always runs `Drop` during ordinary
    /// unwinding (this is not the `abort` panic strategy), so this fires on
    /// both the "forgot to call `stop()`" and the "panicked while holding
    /// one" cases the review flagged. `stop_tx.send` and
    /// `recv_timeout` are both plain, synchronous, non-blocking-by-default
    /// calls (no `.await`, nothing that needs an async runtime), so this is
    /// sound to run directly from `drop`.
    fn drop(&mut self) {
        let _ = self.stop_tx.send(());
        self.wait_for_shutdown();
    }
}

/// Spawn `ipe watch` on its own thread, returning a join handle plus a
/// [`WatchHandle`] the caller can use to stop it.
///
/// Identical behaviour to [`run`], with one addition: an external `stop()`
/// call is delivered
/// through the SAME unified event channel `run`'s own loop already drains
/// (as an [`OrchestratorEvent::Shutdown`]), so shutdown ordering is
/// serialised with every other event exactly like a real Ctrl-C would be —
/// no separate code path to keep in sync.
#[must_use]
pub fn spawn(opts: WatchOptions) -> (thread::JoinHandle<Result<(), CliError>>, WatchHandle) {
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    // `done_tx` is moved into the spawned thread's own closure (never handed
    // to `run_inner` itself) and is unconditionally dropped the instant that
    // closure returns — on EVERY exit path (the clean `Ok(())` after full
    // shutdown, or an early setup-failure `Err`), not just the happy path.
    // `WatchHandle::wait_for_shutdown` therefore unblocks promptly even if
    // `run_inner` fails before ever reaching its main loop.
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let handle = thread::spawn(move || {
        let result = run_inner(&opts, Some(stop_rx));
        let _ = done_tx.send(());
        result
    });
    (
        handle,
        WatchHandle {
            stop_tx,
            done_rx: Mutex::new(Some(done_rx)),
        },
    )
}

enum CompileOutcome {
    Green(Arc<ipe_backend::EmittedProject>),
    Red(String),
    /// Cancelled via salsa (a newer generation superseded it) — never
    /// reported to the user; the newer cycle already took over.
    Cancelled,
}

enum CargoOutcome {
    Green(PathBuf),
    Red(String),
    Killed,
}

/// An in-flight `cargo build` child plus whether the orchestrator killed it.
///
/// "Killed by us" is recorded at the kill site rather than inferred from the
/// exit status: an exit status cannot tell our kill apart from a crash, an
/// out-of-memory kill, or (off unix) an ordinary compile error, and treating
/// any of those as superseded would silently drop a real failure.
struct CargoChild {
    child: Child,
    superseded: bool,
}

impl CargoChild {
    /// Record that the orchestrator is ending this build, then kill it.
    fn supersede(&mut self) {
        self.superseded = true;
        let _ = self.child.kill();
    }
}

/// Run `ipe watch` until the process receives a shutdown signal (Ctrl-C) or
/// every event source disconnects.
///
/// Never returns an `Err` for a build failure — INV-3 means a red build is
/// a LOGGED event, not a fatal one; this only returns `Err` for a genuine
/// setup failure (scope refused, watcher couldn't start).
///
/// # Errors
/// [`CliError`] if the confined scope cannot be built, or the filesystem
/// watcher cannot be started.
pub fn run(opts: &WatchOptions) -> Result<(), CliError> {
    run_inner(opts, None)
}

/// The full implementation behind both [`run`] (CLI-facing, no external stop
/// channel) and [`spawn`] (embedder/test-facing, stoppable via
/// [`WatchHandle`]).
///
/// # Errors
/// [`CliError`] if the confined scope cannot be built, or the filesystem
/// watcher cannot be started.
#[allow(clippy::too_many_lines)]
fn run_inner(
    opts: &WatchOptions,
    external_stop: Option<mpsc::Receiver<()>>,
) -> Result<(), CliError> {
    let initial = resolve_project_sources(&opts.entry, None)?;
    let out_target = EmitTarget::for_path(
        &opts.out_dir,
        opts.out_target.clone(),
        &ProjectPaths::discover(&opts.entry)?,
    )?;

    let scope = initial
        .scope
        .build()
        .map_err(|e| CliError::Usage(crate::text::Message::relay(&e)))?;
    if !opts.quiet {
        emit_watch_line(
            &crate::style::TerminalSafe::sanitize(&format!(
                "[ipe watch] watching {} ({} source files)",
                scope.root().display(),
                scope.file_count()
            )),
            WatchRole::Info,
        );
    }

    let (raw_tx, raw_rx) = mpsc::channel::<PathBuf>();
    let recursive_mode = scope.recursive_mode();
    let initial_roots = watched_roots(&scope);
    let shared_scope = Arc::new(RwLock::new(scope));
    let mut watcher = {
        let scope = Arc::clone(&shared_scope);
        notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            let Ok(event) = res else { return };
            // Reject non-mutating ACCESS events (open/read/execute) and the
            // watch-internal `Other` kind — EXCEPT `Access(Close(Write))`,
            // which is deliberately let through (see below). This is
            // load-bearing, not an optimisation: the orchestrator's own
            // `resolve_project_sources` OPENS every in-scope `.ipe` file
            // (and reads the watched directory) on EVERY rebuild cycle.
            // Some backends (Linux inotify, by default) report that
            // open/read as an `Access(Open)`/`Access(Close(Read))` event —
            // without this filter, the watcher would observe its own read,
            // queue another rebuild, read again to service it, and so on
            // forever (a self-triggering rebuild storm this was caught by,
            // not merely guarded against speculatively). `resolve_project_
            // sources` only ever opens `.ipe` files for READING, so it can
            // never itself produce the one Access variant this filter
            // exempts (`Close(Write)` — see below); the exemption cannot
            // reopen the self-trigger hole.
            //
            // `Close(Write)` exemption (coalescing race):
            // `std::fs::write` — and most editors' "atomic-ish"
            // save path — is `open(O_TRUNC) → write() → close()`, which is
            // NOT one atomic filesystem operation. `open(O_TRUNC)` alone
            // can fire `Modify(Data)` (truncating IS a data change) the
            // instant the file is EMPTIED, strictly BEFORE the writer's own
            // `write()` call actually lands the new bytes. Under enough
            // scheduling pressure on the WRITING process/thread (verified:
            // 8-way CPU saturation + a concurrent real `cargo build`
            // reproduces this reliably; a quiet system does not), the gap
            // between that `open(O_TRUNC)` and the following `write()` can
            // exceed the debounce quiescence window — the coalescer, having
            // received only the truncate's `Modify(Data)` and nothing more
            // within its window, correctly (by ITS OWN local contract)
            // considers the batch settled and fires a rebuild that reads a
            // GENUINELY EMPTY file on disk (`IPE-P0020` "malformed module
            // header"), followed shortly by a second, correct rebuild once
            // the writer finally catches up and closes the file.
            // `Close(Write)` is the one signal that is only ever
            // emitted once a write-mode file handle is actually `close()`d
            // — which, by the writing process's own fd lifecycle, can only
            // happen AFTER its `write()` call returns. Letting that specific
            // event back through means the coalescer's quiescence timer
            // resets on it exactly like any other mutating event, so a
            // truncate-then-write sequence that spans MORE than the nominal
            // debounce window still gets folded into the SAME batch — closed
            // by construction (keyed off the syscall that is a
            // write-completion PROOF), not by widening a timing margin and
            // hoping it's wide enough. `Create`/`Modify`/`Remove`/`Any` (the
            // "imprecise backend" catch-all) all pass through
            // unconditionally, unaffected by this exemption.
            let is_write_close = matches!(
                event.kind,
                notify::EventKind::Access(notify::event::AccessKind::Close(
                    notify::event::AccessMode::Write
                ))
            );
            if !is_write_close
                && (event.kind.is_access() || matches!(event.kind, notify::EventKind::Other))
            {
                return;
            }
            let scope = scope.read().unwrap_or_else(PoisonError::into_inner);
            for path in event.paths {
                if scope.is_relevant(&path) {
                    let _ = raw_tx.send(path);
                }
            }
        })
        .map_err(|e| CliError::Usage(text::msg::watch_start_failed(&e)))?
    };
    for dir in &initial_roots {
        notify::Watcher::watch(&mut watcher, dir, recursive_mode)
            .map_err(|e| CliError::Usage(text::msg::watch_path_failed(&dir.display(), &e)))?;
    }

    warn_if_memory_store();

    let (batch_tx, batch_rx) = mpsc::channel::<ipe_watch::Batch>();
    let debounce_cfg = opts.debounce;
    let coalesce_handle =
        thread::spawn(move || ipe_watch::coalesce_loop(&raw_rx, &batch_tx, debounce_cfg));

    let (evt_tx, evt_rx) = mpsc::channel::<OrchestratorEvent>();
    {
        let evt_tx = evt_tx.clone();
        thread::spawn(move || {
            for batch in batch_rx {
                // The settle window is the batch's arrival now minus when its
                // first raw event opened the window — the true edit→settled
                // latency, measured only when timing is on (the field is unused
                // otherwise).
                let settle = batch.first_event_at.map(|t| t.elapsed());
                if evt_tx.send(OrchestratorEvent::FsBatch { settle }).is_err() {
                    return;
                }
            }
        });
    }
    // SIGTERM → orderly shutdown, for the CLI `run()` path ONLY (`external_stop`
    // is `None` exactly there). A supervisor's `kill -TERM <ipe-pid>` (systemd's
    // default, PID-only — not the foreground process group Ctrl-C signals) would
    // otherwise hard-kill this process before ANY teardown code runs, orphaning
    // the supervised child on its port forever. The forwarder is a third instance
    // of the existing "send into the unified event channel" pattern; the
    // `Shutdown => break` arm below then runs the full, already-tested teardown.
    //
    // NEVER installed for `spawn()` (`external_stop` is `Some`): `spawn()` runs
    // on a same-process background thread inside an EMBEDDING HOST — installing a
    // process-wide SIGTERM handler there would silently and permanently change
    // the HOST's signal disposition (signal-hook does not restore the previous
    // disposition once its action is gone). `spawn()` keeps relying exclusively
    // on `WatchHandle`'s stop channel + `Drop` safety net.
    if external_stop.is_none() {
        #[cfg(unix)]
        {
            let evt_tx = evt_tx.clone();
            // Errors are logged, never fatal — a platform where signal
            // registration fails degrades to the pre-existing behaviour (no
            // PID-only-SIGTERM handling), never a hard failure of `ipe watch`.
            if let Err(e) = ipe_watch::install_sigterm_forwarder(move || {
                // Announce, on the forwarder thread, that the FIRST SIGTERM has
                // been consumed and the orderly teardown is starting — the one
                // registration `signal-hook` holds is now spent, so every later
                // SIGTERM is absorbed (a stuck `ipe watch` needs SIGKILL). This
                // notice is emitted BEFORE the `Shutdown` event is sent, so its
                // appearance is a happens-before proof that the forwarder has
                // consumed the signal: a supervisor (or the double-SIGTERM proof
                // test) can wait for this line as an explicit ack rather than
                // guessing a delay. Not `--quiet`-gated: a shutdown-on-signal
                // notice is a load-bearing operational fact, not chatter.
                emit_watch_line(
                    &crate::style::TerminalSafe::sanitize(SIGTERM_TEARDOWN_MARKER),
                    WatchRole::Info,
                );
                let _ = evt_tx.send(OrchestratorEvent::Shutdown);
            }) {
                emit_watch_line(
                    &crate::style::TerminalSafe::sanitize(&format!(
                        "[ipe watch] warning: could not install SIGTERM handler: {e}"
                    )),
                    WatchRole::Info,
                );
            }
        }
    }
    if let Some(stop_rx) = external_stop {
        let evt_tx = evt_tx.clone();
        thread::spawn(move || {
            if stop_rx.recv().is_ok() {
                let _ = evt_tx.send(OrchestratorEvent::Shutdown);
            }
        });
    }

    // Resolve the runtime crate root once, fail-closed, before the event loop
    // starts. The path-dependency emit needs the CRATE ROOT (the directory
    // holding the runtime `Cargo.toml`), not the source sub-tree. This
    // mirrors how `ipe build` resolves it via `runtime_embed::resolve()`.
    let runtime_dep_root = crate::runtime_embed::resolve()?.root().to_path_buf();

    // The DEV-ONLY blue-green front proxy. When engaged it binds the user's port
    // up front and holds it for the whole session; the app binaries run behind it
    // on internal loopback ports and are cut over on readiness so a rebuild never
    // drops the browser's connection.
    //
    // Engagement is DEFERRED past the first build: the proxy is an HTTP L7 proxy
    // and can only front a crate that binds a first-party HTTP listener
    // (`web_app` / `server_listen`, detected on the emitted `main.rs`). Whether a
    // crate binds one is not knowable before the first emit, so the proxy is
    // bound lazily at the first green build (see `ensure_proxy_bound`) only when
    // `current_binds_http && opts.bluegreen`. A CLI/TUI/worker or a
    // third-party/non-HTTP server never engages it — watch rebuilds and restarts
    // such a crate directly, binding no proxy on the user's port.
    let mut proxy: Option<ipe_watch::DevProxy> = None;

    let mut db_main = ipe_db::IpeDatabase::new();
    let mut source_root: Option<ipe_db::SourceRoot> = None;
    let mut config: Option<ipe_db::BuildConfig> = None;
    let mut supervisor = ipe_watch::SupervisorState::fresh();
    let mut generation: u64 = 0;
    let mut compile_worker: Option<thread::JoinHandle<()>> = None;
    let mut cargo_child: Option<Arc<std::sync::Mutex<CargoChild>>> = None;
    // The crate the in-flight cargo build compiles, proven again once it exits.
    let mut building: Option<OwnedDir> = None;
    // Set at `CompileDone` (Green), consumed at `CargoDone` (Green) — the
    // readiness strategy is a property of the SOURCE (does it call
    // `Web.tea`?), decided once per generation right after emit, not
    // re-derived from the built executable (which carries no such marker).
    let mut current_is_web = false;
    // Set alongside `current_is_web` at each emit: does the built crate bind a
    // first-party HTTP listener (`web_app` OR `server_listen`)? This — not the
    // program's shape — gates blue-green proxy engagement: a CLI/TUI/worker or a
    // third-party/non-HTTP server emits neither and is rebuilt+restarted
    // directly, never fronted by a proxy that cannot discover its port.
    let mut current_binds_http = false;
    // Set alongside `current_is_web` at each emit: is the built crate a Ipe.Tui
    // app? A tui child has no HTTP endpoint, so an appearance-only edit is
    // delivered over the loopback CONTROL SOCKET (`send_control_frame`) rather
    // than the web `/_ipe/hot-appearance` POST — the shape-agnostic control
    // channel's tui delivery path.
    let mut current_is_tui = false;
    // The prominent "open this URL" line is printed once, after the first web
    // app settles into a running state — so the address the user must open is
    // the last thing on screen, not a line that scrolled away above the cargo
    // build. A non-web app (CLI/TUI) has no URL and never sets this.
    let mut url_announced = false;
    // The emit of the currently-RUNNING binary, kept only under the appearance
    // hot-swap flag. The classifier diffs each new emit against this to decide
    // AppearanceOnly (push a table patch, skip cargo) vs Logic (recompile). It is
    // updated ONLY when a recompile is actually launched (Logic path / first
    // build) — never on an appearance push, because the running binary still
    // bakes THESE defaults (they key the runtime overlay), so chained style edits
    // each diff against the same running baseline. `None` until the first emit,
    // or whenever the flag is off.
    let mut running_emitted: Option<Arc<ipe_backend::EmittedProject>> = None;
    // The per-session control token that authenticates a `/_ipe/hot-appearance`
    // POST and a `/_ipe/watch/status` build-status POST. Minted once here and
    // injected into every spawned child via `child_env` as `IPE_WATCH_HOT_TOKEN`,
    // so only this watch process can drive either dev endpoint of the app it
    // launched. Minted when EITHER the appearance hot-swap flag OR the browser
    // build-status banner is on — the failure banner must reach the child even
    // with appearance hot-swap off (the two endpoints gate independently on the
    // server; the shared token arms only whichever route is actually mounted).
    let hot_token: Option<String> = if opts.hot_appearance || crate::watch_banner_enabled() {
        // `None` here (OS CSPRNG unavailable) leaves the control endpoint
        // unarmed rather than falling back to a guessable token.
        mint_hot_token()
    } else {
        None
    };
    // The loopback control-socket port for the tui/cli/worker control channel,
    // allocated once per session like the token above and injected into every
    // spawned child via `child_env` as `IPE_CONTROL_PORT`. Allocated only when a
    // token was minted (the two arm the child's control surface together); if the
    // OS cannot lease an ephemeral loopback port, leave it unset — the child then
    // opens no control socket (fail-closed), never a degraded path.
    let control_port: Option<u16> = if hot_token.is_some() {
        free_loopback_port().ok()
    } else {
        None
    };
    // The appearance hot-swap classifier and its running-emit baseline are armed
    // ONLY by the appearance flag — never merely by the banner. The child's emit
    // carries a `LiteralTable` overlay only under `opts.hot_appearance`
    // (see the emit config), so a patch push against a banner-only build would
    // target a binary with no overlay to patch.
    let appearance_active = opts.hot_appearance;
    // The current live cycle's per-phase timing (`IPE_WATCH_TIMING`). Reset at
    // each `FsBatch`; the resolve/compile/write/cargo phases fill it as their
    // events land, and it is reported at the terminal event (restart done, or
    // a red build). A superseding batch simply overwrites it — the stale
    // cycle's partial timing is discarded exactly like its stale events.
    let mut timings = RebuildTimings::default();

    // Kick off the first build immediately — don't wait for a file event.
    if evt_tx
        .send(OrchestratorEvent::FsBatch { settle: None })
        .is_err()
    {
        return Ok(());
    }

    while let Ok(event) = evt_rx.recv() {
        match event {
            OrchestratorEvent::FsBatch { settle } => {
                generation += 1;
                let this_gen = generation;
                timings = RebuildTimings::start(settle);
                // The orchestrator-thread phase (resolve + ffi + salsa sync)
                // starts here; its span closes just before the compile worker
                // is spawned below.
                let resolve_started = Instant::now();
                emit(
                    opts,
                    WatchEvent::RebuildStarted {
                        generation: this_gen,
                    },
                );

                // Single-flight: a superseding batch kills any in-flight
                // cargo build immediately ("never overlapping cargo
                // builds"). Only a signal is sent here (`kill`, never
                // a blocking `wait`) — the build's own waiter thread (see
                // `spawn_cargo_build`) observes the exit via its own poll
                // and reports `CargoOutcome::Killed`, so this arm never
                // blocks the orchestrator.
                if let Some(child) = cargo_child.take() {
                    // A poisoned lock still guards a live child to kill — the
                    // kill must not be skipped just because some other thread
                    // panicked while briefly holding the lock.
                    child
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .supersede();
                }

                let resolved = match resolve_project_sources(&opts.entry, None) {
                    Ok(r) => r,
                    Err(e) => {
                        emit_watch_line(
                            &crate::style::TerminalSafe::sanitize(&format!("[ipe watch] {e}")),
                            WatchRole::Failure,
                        );
                        // This cycle's `generation` bump and cargo-kill
                        // already happened above, so without a scheduled
                        // retry the save that triggered this cycle is lost
                        // until an unrelated future edit.
                        schedule_resolve_retry(&evt_tx);
                        continue;
                    }
                };
                if rescope(&mut watcher, &shared_scope, &resolved.scope) {
                    schedule_resolve_retry(&evt_tx);
                }

                let mut sources = resolved.sources;
                let mut discovered = resolved.discovered;
                let injected = project::inject_compiled_std_closure(&mut sources, &mut discovered);

                // Load the FFI catalog and inject installed-crate interface
                // modules — the same seam `run_build` uses (CO-INCR-005).
                // An error logs and skips the cycle (same policy as a
                // resolution failure above) rather than tearing down the
                // whole watch session.
                let ffi_prep = match crate::ffi::prepare_ffi(&mut sources, &resolved.blame_path) {
                    Ok(p) => p,
                    Err(e) => {
                        emit_watch_line(
                            &crate::style::TerminalSafe::sanitize(&format!(
                                "[ipe watch] FFI catalog error: {e}"
                            )),
                            WatchRole::Failure,
                        );
                        continue;
                    }
                };

                // Borrow each module's text: `sync_source_root` clones only at
                // the real mutation points (a new input, or an actually-changed
                // set), so a settled batch that touches one file no longer copies
                // every module's source (including the ~130-module injected
                // stdlib closure) into a map that is immediately discarded.
                let desired: BTreeMap<Vec<String>, (&str, ipe_db::ModuleOrigin)> = sources
                    .iter()
                    .map(|(p, (_, text))| {
                        let origin = if injected.contains(p) {
                            ipe_db::ModuleOrigin::EmbeddedStdlib
                        } else if ffi_prep.injected.contains(p) {
                            ipe_db::ModuleOrigin::FfiInterface
                        } else {
                            ipe_db::ModuleOrigin::User
                        };
                        (p.clone(), (text.as_str(), origin))
                    })
                    .collect();

                // This call BLOCKS until any in-flight compile
                // worker's cancelled query unwinds and drops its database
                // clone — see the module doc's cancellation walkthrough.
                let root = if let Some(root) = source_root {
                    ipe_db::sync_source_root(&mut db_main, root, &desired);
                    root
                } else {
                    let root = crate::create_source_root(
                        &db_main,
                        &sources,
                        &injected,
                        &ffi_prep.injected,
                    );
                    source_root = Some(root);
                    root
                };

                let cfg = if let Some(cfg) = config {
                    if *cfg.db_driver(&db_main) != resolved.db_driver {
                        use salsa::Setter as _;
                        cfg.set_db_driver(&mut db_main).to(resolved.db_driver);
                    }
                    if cfg.wasm_public_env(&db_main) != &resolved.wasm_public_env {
                        use salsa::Setter as _;
                        cfg.set_wasm_public_env(&mut db_main)
                            .to(resolved.wasm_public_env.clone());
                    }
                    cfg
                } else {
                    // Pass ffi_prep.emit so the backend can write FFI
                    // bindings (src/ffi.rs) into the emitted project — the
                    // same slot `run_build` fills via BuildConfig (CO-INCR-005).
                    let cfg = ipe_db::BuildConfig::new(
                        &db_main,
                        resolved.db_driver,
                        ffi_prep.emit,
                        ipe_ir::Target::Native,
                        resolved.wasm_public_env.clone(),
                        false,
                        // `ipe watch` is a development loop — Debug.* is allowed.
                        ipe_backend_rust::BuildIntent::Development,
                        // Dependency-model emit: the project links the runtime as a
                        // path dependency (what `ipe build` uses by default), so
                        // no runtime source is vendored into `src/ipe_runtime/`.
                        // `runtime_dep_root` is the verified crate root (holds
                        // `Cargo.toml`), resolved once before the loop via
                        // `runtime_embed::resolve()`, matching `ipe build`'s path.
                        Some(ipe_backend_rust::RuntimeDep {
                            root: runtime_dep_root.clone(),
                        }),
                        // `ipe watch --debugger` compiles the in-app debugger
                        // overlay into the rebuilt runtime loop.
                        opts.debugger,
                        resolved.cargo_name.clone(),
                        opts.hot_appearance,
                        // `ipe watch` reloads the served-live web app; the
                        // webview-native desktop delivery is not a watch target.
                        false,
                    );
                    config = Some(cfg);
                    cfg
                };

                // The prior worker (if any) has already unwound by the time
                // `sync_source_root` returned above; join to reclaim the
                // thread handle (fast — it already finished).
                if let Some(h) = compile_worker.take() {
                    let _ = h.join();
                }

                // Close the orchestrator-thread phase: everything from the
                // start of this arm (resolve + ffi + salsa input mutation) up
                // to handing off to the compile worker.
                timings.resolve = Some(resolve_started.elapsed());

                let db_worker = db_main.clone();
                let entry_path = resolved.entry_path.clone();
                let blame_path = resolved.blame_path.clone();
                let evt_tx = evt_tx.clone();
                compile_worker = Some(thread::spawn(move || {
                    // Measure the salsa warm-compile on the worker thread: the
                    // orchestrator only sees the event, so the span has to be
                    // taken here at the real call boundary.
                    let compile_started = Instant::now();
                    let outcome =
                        match salsa::Cancelled::catch(std::panic::AssertUnwindSafe(|| {
                            crate::compile_prepared(
                                &db_worker,
                                root,
                                &sources,
                                &entry_path,
                                &blame_path,
                                cfg,
                            )
                        })) {
                            Ok(Ok(emitted)) => CompileOutcome::Green(Arc::new(emitted)),
                            Ok(Err(e)) => CompileOutcome::Red(e.to_string()),
                            Err(_cancelled) => CompileOutcome::Cancelled,
                        };
                    let _ = evt_tx.send(OrchestratorEvent::CompileDone {
                        generation: this_gen,
                        outcome,
                        compile: compile_started.elapsed(),
                    });
                }));
            }

            OrchestratorEvent::CompileDone {
                generation: g,
                outcome,
                compile,
            } => {
                if g != generation {
                    continue; // stale — a newer cycle already superseded this one.
                }
                timings.compile = Some(compile);
                match outcome {
                    CompileOutcome::Cancelled => {
                        emit(opts, WatchEvent::CompileCancelled { generation: g });
                    }
                    CompileOutcome::Red(msg) => {
                        // Frame the diagnostic like `ipe run`: a blank line
                        // above, every line guttered two spaces (so the whole
                        // report sits inset, not just the header), a blank line
                        // below to set it off from the next watch line. Light
                        // yellow, not red — the last-good binary stays up.
                        let mut screen = crate::screen::Screen::new(crate::screen::Stream::Stderr);
                        let frame = compile_failed_frame(&msg, screen.palette());
                        screen.guttered(&frame).emit();
                        emit(opts, WatchEvent::CompileFailed { generation: g });
                        if let (Some(tok), Some(app_port)) = (
                            hot_token.as_deref(),
                            app_status_port(proxy.as_ref(), opts.port),
                        ) {
                            post_watch_status(app_port, tok, false, &first_error_line(&msg));
                        }
                        // A red compile is terminal for this cycle (no cargo,
                        // no restart) — report the partial breakdown here.
                        timings.report(g);
                    }
                    CompileOutcome::Green(emitted) => {
                        // Appearance hot-swap: if the flag is on and we already
                        // have a running binary, classify this emit against it.
                        // An AppearanceOnly delta (only hoisted style-literal
                        // VALUES moved) is pushed as a `LiteralTable` patch to the
                        // running app and skips cargo entirely — the sub-second
                        // path. Anything else is Logic and recompiles below. The
                        // classifier is conservative by construction: a logic
                        // change perturbs the emitted Rust outside a defaults
                        // array, forcing Logic (see `hot_classify`).
                        if let (true, Some(tok), Some(running)) = (
                            appearance_active,
                            hot_token.as_deref(),
                            running_emitted.as_ref(),
                        ) {
                            match crate::hot_classify::classify(running, &emitted) {
                                // An EMPTY hot-swap means the two emits were
                                // byte-identical — a no-op re-emit (a duplicate
                                // filesystem event on an already-current source, or
                                // a whitespace-only edit). It applies nothing to the
                                // running app, so it must NOT short-circuit the
                                // rebuild: this cycle already killed any in-flight
                                // cargo build when its batch settled, and taking the
                                // fast path here would `continue` without restarting
                                // it — losing the pending rebuild. Fall through to
                                // the normal build path instead, which re-launches
                                // the (idempotent) rebuild.
                                crate::hot_classify::Classification::HotSwappable(hot)
                                    if !hot.is_empty() =>
                                {
                                    // The running shape decides where — or whether
                                    // — an appearance swap can be delivered out of
                                    // band. Each shape maps to exactly one route;
                                    // the match is exhaustive so a shape can never
                                    // silently skip the edit (see `appearance_route`).
                                    match appearance_route(current_is_tui, current_is_web) {
                                        // A Ipe.Tui child has no HTTP endpoint: its
                                        // appearance hot-swap rides the loopback
                                        // control socket, not the web POST path.
                                        // Only an APPEARANCE-only swap is hot for tui
                                        // (C3) — the logic legs (transitions/msg-sets/
                                        // subs/inits/wirings) each need a rebuilt
                                        // `update`, so a tui swap that carries any of
                                        // them falls through to a full rebuild. On a
                                        // clean delivery (every view Ack'd) skip cargo;
                                        // any miss (no port, bad token, socket error)
                                        // falls back to the rebuild below.
                                        AppearanceRoute::ControlSocket => {
                                            let appearance_only = hot.transitions.is_empty()
                                                && hot.msg_sets.is_empty()
                                                && hot.subs.is_empty()
                                                && hot.inits.is_empty()
                                                && hot.wirings.is_empty();
                                            if appearance_only
                                                && push_control_appearance(
                                                    control_port,
                                                    tok,
                                                    &hot.views,
                                                    opts.quiet,
                                                )
                                            {
                                                emit(
                                                    opts,
                                                    WatchEvent::AppearanceHotSwapped {
                                                        generation: g,
                                                        views: hot.views.len(),
                                                    },
                                                );
                                                timings.report(g);
                                                continue;
                                            }
                                            // Not appearance-only, or delivery missed:
                                            // fall through to the full rebuild below.
                                        }
                                        AppearanceRoute::WebPost => {
                                            // The running binary is unchanged, so
                                            // `running_emitted` stays the baseline. Push
                                            // each edited view's appearance patch AND each
                                            // edited arm's transition patch, then skip
                                            // cargo. Both must reach the app for the swap
                                            // to be complete; a failure of EITHER is a soft
                                            // miss that falls through to a normal recompile
                                            // so the edit still lands.
                                            let views_ok = push_appearance_patches(
                                                opts.port, tok, &hot.views, opts.quiet,
                                            );
                                            let transitions_ok = push_transition_patches(
                                                opts.port,
                                                tok,
                                                &hot.transitions,
                                                opts.quiet,
                                            );
                                            // The additive-`Msg`-set leg: the endpoint
                                            // re-proves the superset and refuses a
                                            // non-additive candidate, so a miss here (like
                                            // a view/transition miss) falls back to a full
                                            // recompile.
                                            let msg_sets_ok = push_msg_set_patches(
                                                opts.port,
                                                tok,
                                                &hot.msg_sets,
                                                opts.quiet,
                                            );
                                            let subs_ok = push_sub_patches(
                                                opts.port, tok, &hot.subs, opts.quiet,
                                            );
                                            let inits_ok = push_init_patches(
                                                opts.port, tok, &hot.inits, opts.quiet,
                                            );
                                            let wirings_ok = push_wiring_patches(
                                                opts.port,
                                                tok,
                                                &hot.wirings,
                                                opts.quiet,
                                            );
                                            if views_ok
                                                && transitions_ok
                                                && msg_sets_ok
                                                && subs_ok
                                                && inits_ok
                                                && wirings_ok
                                            {
                                                emit(
                                                    opts,
                                                    WatchEvent::AppearanceHotSwapped {
                                                        generation: g,
                                                        views: hot.views.len()
                                                            + hot.transitions.len()
                                                            + hot.msg_sets.len()
                                                            + hot.subs.len()
                                                            + hot.inits.len()
                                                            + hot.wirings.len(),
                                                    },
                                                );
                                                if let Some(app_port) =
                                                    app_status_port(proxy.as_ref(), opts.port)
                                                {
                                                    post_watch_status(app_port, tok, true, "");
                                                }
                                                timings.report(g);
                                                continue;
                                            }
                                        }
                                        AppearanceRoute::Rebuild => {
                                            // Every other shape — cli (`console_app`)
                                            // and worker (`worker_app`) — has NO out-of-
                                            // band appearance-apply path: a worker has no
                                            // view surface at all, and a cli renders its
                                            // `LinesView` synchronously on the next line/
                                            // msg fold (its committed transcript is
                                            // already written and its live region is
                                            // bounded), so an out-of-band repaint has no
                                            // meaning and off-TTY must never spray ANSI
                                            // into a pipe. Appearance hot-swap is N/A for
                                            // these shapes; a HotSwappable classification
                                            // here MUST fall to a full rebuild rather than
                                            // silently skip the edit (which would leave the
                                            // app running stale code — a correctness break
                                            // worse than a rebuild). Falling through does
                                            // exactly that.
                                        }
                                    } // end appearance-swap shape routing
                                }
                                // An empty hot-swap (byte-identical re-emit, guarded
                                // out of the fast path above) and a `Logic` edit both
                                // fall through to the normal rebuild below.
                                crate::hot_classify::Classification::HotSwappable(_)
                                | crate::hot_classify::Classification::Logic => {
                                    // Recompile below.
                                }
                            }
                        }
                        // Watch is always a dynamic dev build — no static plan,
                        // no tree-shaking (the full runtime tree keeps rebuilds
                        // incremental across a session's changing reach set).
                        let write_started = Instant::now();
                        let crate_dir = match write_emitted_project(
                            &emitted,
                            &out_target,
                            &opts.runtime_dir,
                            None,
                            false,
                        ) {
                            Ok(dir) => dir,
                            Err(e) => {
                                emit_watch_line(
                                    &crate::style::TerminalSafe::sanitize(&format!(
                                        "[ipe watch] failed to write emitted project: {e}"
                                    )),
                                    WatchRole::Failure,
                                );
                                continue;
                            }
                        };
                        timings.write = Some(write_started.elapsed());
                        // This emit is about to be compiled into the new running
                        // binary, so it becomes the classifier's baseline for the
                        // next edit (only relevant under the appearance flag).
                        if appearance_active {
                            running_emitted = Some(emitted.clone());
                        }
                        current_is_web = emitted_is_web(&emitted);
                        current_binds_http = emitted_binds_http(&emitted);
                        current_is_tui = emitted_is_tui(&emitted);
                        // Design doc "First-run vs warm-run UX": the cold
                        // (first) build pays the full dependency-compile
                        // cost and can take minutes; every subsequent
                        // rebuild is warm (seconds). Distinguishing them
                        // here means "watch is slow" is never misattributed
                        // to the salsa layer, which already ran in
                        // milliseconds by the time this line prints.
                        if !opts.quiet {
                            if generation == 1 {
                                emit_watch_line(
                                    &crate::style::TerminalSafe::sanitize(
                                        "[ipe watch] building (first run — compiling \
                                         dependencies, this is the slow one)…",
                                    ),
                                    WatchRole::Info,
                                );
                            } else {
                                emit_watch_line(
                                    &crate::style::TerminalSafe::sanitize(
                                        "[ipe watch] change detected — rebuilding…",
                                    ),
                                    WatchRole::Info,
                                );
                            }
                        }
                        // A cargo rebuild is a multi-second silent window — tell
                        // the running app to raise its "Recompiling app" banner so
                        // the browser is never left guessing. Only meaningful when
                        // an app is already up (a rebuild, not the first build).
                        if let (Some(tok), Some(app_port)) = (
                            hot_token.as_deref(),
                            app_status_port(proxy.as_ref(), opts.port),
                        ) {
                            post_watch_recompiling(app_port, tok);
                        }
                        match spawn_cargo_build(
                            &opts.cargo_path,
                            crate_dir.path(),
                            opts.target_dir.as_deref(),
                            generation,
                            evt_tx.clone(),
                            opts.quiet,
                        ) {
                            Ok(child) => {
                                cargo_child = Some(child);
                                building = Some(crate_dir);
                            }
                            Err(e) => emit_watch_line(
                                &crate::style::TerminalSafe::sanitize(&format!(
                                    "[ipe watch] cannot start cargo build: {e}"
                                )),
                                WatchRole::Failure,
                            ),
                        }
                    }
                }
            }

            OrchestratorEvent::CargoDone {
                generation: g,
                outcome,
                cargo,
            } => {
                if g != generation {
                    continue;
                }
                cargo_child = None;
                timings.cargo = Some(cargo);
                match outcome {
                    CargoOutcome::Killed => {
                        emit(opts, WatchEvent::CargoKilled { generation: g });
                    }
                    CargoOutcome::Red(msg) => {
                        emit_watch_line(
                            &crate::style::TerminalSafe::sanitize(&format!(
                                "[ipe watch] cargo build failed (last-good binary stays \
                                     up):\n{msg}"
                            )),
                            WatchRole::Failure,
                        );
                        emit(opts, WatchEvent::CargoFailed { generation: g });
                        if let (Some(tok), Some(app_port)) = (
                            hot_token.as_deref(),
                            app_status_port(proxy.as_ref(), opts.port),
                        ) {
                            post_watch_status(app_port, tok, false, &first_error_line(&msg));
                        }
                        // A red cargo build is terminal (no restart) — report
                        // the partial breakdown here.
                        timings.report(g);
                    }
                    CargoOutcome::Green(exe_path) => {
                        let built = match prove_green_crate(building.take(), &opts.out_dir) {
                            Ok(dir) => dir,
                            Err(reason) => {
                                emit_watch_line(
                                    &crate::style::TerminalSafe::sanitize(&format!(
                                        "[ipe watch] refusing the build: {reason}"
                                    )),
                                    WatchRole::Failure,
                                );
                                emit(opts, WatchEvent::CargoFailed { generation: g });
                                timings.report(g);
                                continue;
                            }
                        };
                        let restart_started = Instant::now();
                        // Deferred blue-green engagement: bind the proxy on the
                        // user's port the first time a green build is known to bind
                        // a first-party HTTP listener. A bind failure here is fatal
                        // for the SAME reason a direct port-in-use is — the user
                        // asked for that port and it is unavailable.
                        if proxy.is_none() && opts.bluegreen && current_binds_http {
                            let bound = ipe_watch::DevProxy::bind(opts.port).map_err(|e| {
                                CliError::Usage(text::msg::watch_proxy_bind_failed(&opts.port, &e))
                            })?;
                            if !opts.quiet {
                                emit_watch_line(
                                    &crate::style::TerminalSafe::sanitize(&format!(
                                        "[ipe watch] blue-green proxy holding port {} \
                                             (rebuilds cut over with no dropped connection)",
                                        opts.port
                                    )),
                                    WatchRole::Info,
                                );
                            }
                            proxy = Some(bound);
                        }
                        let outcome = if let Some(proxy) = proxy.as_ref() {
                            // Blue-green: the new binary binds a FRESH internal
                            // port behind the proxy; readiness is probed on
                            // that internal port; on ready, the proxy cuts over
                            // to it and the old binary is drained — the
                            // user-facing port (held by the proxy) never stops
                            // answering. A web app gets the precise
                            // `/_ipe/readyz` probe; every other shape falls
                            // back to a short alive-grace, exactly as the
                            // direct path does.
                            let internal_port = match free_loopback_port() {
                                Ok(p) => p,
                                Err(e) => {
                                    emit_watch_line(
                                        &crate::style::TerminalSafe::sanitize(&format!(
                                            "[ipe watch] cannot allocate an internal port for \
                                                 the blue-green cutover: {e}"
                                        )),
                                        WatchRole::Failure,
                                    );
                                    // The green binary is already built, but the
                                    // cutover can't proceed without an internal
                                    // port. Mirror the resolve-failure recovery:
                                    // clear the browser "Recompiling" banner (it
                                    // would otherwise hang forever) and schedule a
                                    // retry so this build is re-driven rather than
                                    // silently abandoned until an unrelated edit.
                                    if let (Some(tok), Some(app_port)) = (
                                        hot_token.as_deref(),
                                        app_status_port(Some(proxy), opts.port),
                                    ) {
                                        post_watch_status(
                                            app_port,
                                            tok,
                                            false,
                                            &format!("internal-port allocation failed: {e}"),
                                        );
                                    }
                                    schedule_resolve_retry(&evt_tx);
                                    continue;
                                }
                            };
                            let readiness = if current_is_web {
                                ipe_watch::ReadinessCheck::HttpReadyz {
                                    port: internal_port,
                                }
                            } else if current_binds_http {
                                // A first-party HTTP server (Ipe.Http.Server) has
                                // no `/_ipe/readyz`, but it DOES bind a TCP
                                // listener on the internal port — so readiness is
                                // "the port accepts a connection", not merely "the
                                // child is still alive". A bare alive-grace could
                                // cut the proxy over to an upstream that has not
                                // finished binding, yielding a transient 502.
                                ipe_watch::ReadinessCheck::TcpConnect {
                                    port: internal_port,
                                }
                            } else {
                                ipe_watch::ReadinessCheck::AliveGrace {
                                    grace: Duration::from_millis(300),
                                }
                            };
                            let crate_dir = built.path().to_path_buf();
                            let tok = hot_token.clone();
                            let cp = control_port;
                            let reset_state = opts.reset_state;
                            supervisor.apply_green_behind_proxy(
                                &exe_path,
                                internal_port,
                                move |path, port| {
                                    spawn_command(
                                        path,
                                        &child_env(
                                            port,
                                            &crate_dir,
                                            tok.as_deref(),
                                            cp,
                                            true,
                                            reset_state,
                                        ),
                                    )
                                },
                                readiness,
                                opts.restart_timeouts,
                                |ready_port| proxy.set_upstream(ready_port),
                            )
                        } else {
                            let readiness = if current_is_web {
                                ipe_watch::ReadinessCheck::HttpReadyz { port: opts.port }
                            } else if current_binds_http {
                                // Direct-bind HTTP server (blue-green off): the
                                // app owns `opts.port` itself; readiness is the
                                // port accepting a connection.
                                ipe_watch::ReadinessCheck::TcpConnect { port: opts.port }
                            } else {
                                ipe_watch::ReadinessCheck::AliveGrace {
                                    grace: Duration::from_millis(300),
                                }
                            };
                            let env = child_env(
                                opts.port,
                                built.path(),
                                hot_token.as_deref(),
                                control_port,
                                false,
                                opts.reset_state,
                            );
                            supervisor.apply_green(
                                &exe_path,
                                move |path| spawn_command(path, &env),
                                readiness,
                                opts.restart_timeouts,
                            )
                        };
                        timings.restart = Some(restart_started.elapsed());
                        report_restart_outcome(&outcome, opts.quiet);
                        // Clear any "Recompiling app" banner with a soft-green
                        // "Updated!" the moment the rebuilt app is serving. Under
                        // blue-green the client also greets its reconnect with the
                        // swap toast; this covers the direct-bind path and closes
                        // the recompiling banner deterministically either way.
                        if outcome_is_running(&outcome)
                            && let (Some(tok), Some(app_port)) = (
                                hot_token.as_deref(),
                                app_status_port(proxy.as_ref(), opts.port),
                            )
                        {
                            post_watch_status(app_port, tok, true, "");
                        }
                        // Surface the open-URL prominently once the first web
                        // app is up: the address is the one thing the user must
                        // act on, and it would otherwise be buried above the
                        // cargo output. Web shapes only; a running-app outcome
                        // only (a failed readiness keeps the last-good app, so
                        // its URL — already shown — still stands).
                        if !opts.quiet
                            && current_is_web
                            && !url_announced
                            && outcome_is_running(&outcome)
                        {
                            crate::screen::Screen::new(crate::screen::Stream::Stderr)
                                .guttered(&open_url_block(opts.port))
                                .emit();
                            url_announced = true;
                        }
                        emit(
                            opts,
                            WatchEvent::Restarted {
                                generation: g,
                                outcome: restart_outcome_kind(&outcome),
                            },
                        );
                        // The terminal event of a fully-green cycle — the whole
                        // breakdown is now populated.
                        timings.report(g);
                    }
                }
            }

            OrchestratorEvent::Shutdown => break,
        }
    }

    // Explicitly drop the notify watcher — and with it, its owned `raw_tx`
    // clone — BEFORE waiting on `coalesce_handle` below. `raw_tx` is moved
    // (never `.clone()`d — see `mpsc::channel` above) into `watcher`'s own
    // event callback, so `watcher` is the SOLE owner of a live sender.
    // `ipe_watch::coalesce_loop`'s blocking `raw_rx.recv()` only returns
    // once every `raw_tx` sender has been dropped; leaving `watcher` to die
    // via its ordinary end-of-function scope drop (i.e. AFTER
    // `coalesce_handle.join()` below) means that `join()` blocks FOREVER —
    // notify's own internal OS-watch thread stays parked (`epoll_wait`),
    // `raw_rx` never observes a disconnect, and the whole shutdown wedges.
    // Confirmed live via `/proc/<pid>/task/*/wchan` before this fix: the
    // notify thread parked in `ep_poll` while every sibling thread sat in
    // `futex_wait_queue_me`, and both `watch_rebuild_on_save_swaps_…` and
    // `watch_coalesces_a_rapid_double_save_…` hung past their nextest
    // SIGTERM ceiling as a direct result.
    drop(watcher);

    if let Some(child) = cargo_child.take() {
        // A poisoned lock still guards a live child to kill — the kill must
        // not be skipped just because some other thread panicked while
        // briefly holding the lock.
        child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .supersede();
    }
    supervisor.shutdown(opts.restart_timeouts);
    // Stop the front proxy AFTER the supervised child is down: it held the
    // user's port for the whole session, so releasing it last means the port
    // is answered until the very end of teardown rather than flapping.
    if let Some(mut proxy) = proxy.take() {
        proxy.shutdown();
    }
    if let Some(h) = compile_worker {
        let _ = h.join();
    }
    let _ = coalesce_handle.join();
    Ok(())
}

/// Ask the OS for a free loopback TCP port by binding an ephemeral one and
/// immediately dropping the listener, returning the port it chose.
///
/// A tiny race exists between releasing the port here and the spawned child
/// binding it — acceptable for a DEV loop on loopback, and closed in practice
/// because the child binds it within milliseconds and the blue-green readiness
/// probe would catch (and INV-3-preserve against) a bind failure. Kept minimal
/// deliberately: a robust production port lease is out of scope for a dev-only
/// cutover.
///
/// # Errors
/// An I/O error if no ephemeral port can be bound at all.
fn free_loopback_port() -> std::io::Result<u16> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}

/// Where an appearance-only hot-swap is delivered for the running TEA shape —
/// one variant per delivery mechanism, so a shape can never fall between the
/// arms and silently drop an edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppearanceRoute {
    /// Ipe.Tui: the child owns a loopback control socket; the swap rides a
    /// `HotAppearance` control frame.
    ControlSocket,
    /// Ipe.Web: the child serves `/_ipe/hot-appearance`; the swap rides an HTTP
    /// POST on the app port.
    WebPost,
    /// Every viewless-or-line-oriented shape — cli (`console_app`) and worker
    /// (`worker_app`) — has no out-of-band apply path, so an appearance swap is
    /// N/A: the edit takes a full structural rebuild. Never a silent skip.
    Rebuild,
}

/// Route an appearance-only hot-swap by the running shape. Tui and web each have
/// a delivery channel; any other shape (cli, worker, a bare HTTP server) has
/// none, so it rebuilds. Total over the two shape flags by construction — the
/// `Rebuild` fallback is the fail-safe that keeps a `HotSwappable` classification
/// from ever no-op'ing on a shape that cannot apply it.
const fn appearance_route(is_tui: bool, is_web: bool) -> AppearanceRoute {
    if is_tui {
        AppearanceRoute::ControlSocket
    } else if is_web {
        AppearanceRoute::WebPost
    } else {
        AppearanceRoute::Rebuild
    }
}

/// Does any emitted `.rs` file contain `needle` — a FULLY-QUALIFIED runtime
/// entry call (`ipe_runtime::web::web_app`, `…::server::server_listen`,
/// `…::tui::tui_app_ui`) the backend emits ONLY at the app entry?
///
/// Scans the WHOLE emitted source, not just `src/main.rs`: the entry call lands
/// in `src/main.rs` for a single-file app but in a module file
/// (`src/ipe_mods/ipe_mod_main.rs`) for a multi-module project, where `src/main.rs`
/// is only a generic `ipe_main()` shim. Scanning `src/main.rs` alone therefore
/// misclassified every multi-module app as neither-web-nor-tui — routing its
/// appearance hot-swaps to a full rebuild and leaving the blue-green proxy
/// disengaged. The emitted tree is compiler-controlled and the needle is a
/// fully-qualified path (never a bare token a user symbol could shadow — the
/// `unqualified_*` refusal tests pin this), so a substring check across it is
/// sound.
fn emitted_source_contains(emitted: &ipe_backend::EmittedProject, needle: &str) -> bool {
    emitted
        .files
        .iter()
        .filter(|(rel, _)| {
            std::path::Path::new(rel.as_str())
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
        })
        .any(|(_, text)| text.contains(needle))
}

/// The emitted crate is a live Ipe.Web app — its entry emission always contains
/// the literal `ipe_runtime::web::web_app` call
/// (`crates/ipe_backend_rust/src/emit_web.rs`). Ipe.Web apps get the precise
/// `/_ipe/readyz` readiness probe and appearance hot-swap.
fn emitted_is_web(emitted: &ipe_backend::EmittedProject) -> bool {
    emitted_source_contains(emitted, "ipe_runtime::web::web_app")
}

/// The emitted crate is a Ipe.Tui app — its entry emission always contains the
/// literal `ipe_runtime::tui::tui_app_ui` call (`emit_tui.rs`). A tui child has
/// no HTTP endpoint, so its appearance hot-swap rides the loopback CONTROL
/// SOCKET (`send_control_frame`) rather than the web `/_ipe/hot-appearance` POST.
/// A match on the fully-qualified emitted path (not a bare token) so a user
/// symbol or string literal cannot masquerade as the runtime entry.
fn emitted_is_tui(emitted: &ipe_backend::EmittedProject) -> bool {
    emitted_source_contains(emitted, "ipe_runtime::tui::tui_app_ui")
}

/// The emitted crate binds a FIRST-PARTY HTTP listener whose port `ipe`
/// controls via the injected `IPE_*_PORT` env — exactly the two entrypoints an
/// L7 proxy can front: `web_app` (Ipe.Web) or `server_listen` (Ipe.Http.Server).
/// This — not the program's shape — decides whether the blue-green proxy
/// engages: a `Shape::Script` `main = Server.listen …` binds an HTTP port and
/// emits `server_listen`, so it too is proxied; a CLI/TUI/worker or a
/// third-party/non-HTTP server (ftp/irc/raw socket) emits neither, so watch
/// rebuilds and restarts it directly rather than fronting a port it cannot
/// discover or relocate.
fn emitted_binds_http(emitted: &ipe_backend::EmittedProject) -> bool {
    // Match the FULLY-QUALIFIED emitted call path, not a bare token: the kernel
    // emits `ipe_runtime::server::server_listen(` / `ipe_runtime::web::web_app(`.
    // A bare `server_listen` would also match a user function named
    // `serverListen` (emitted `server_listen`) or a string literal in user code
    // — a false positive that would engage the proxy for a program binding no
    // HTTP port, reviving the 502 (proxy holds the port, child never listens).
    emitted_source_contains(emitted, "ipe_runtime::web::web_app")
        || emitted_source_contains(emitted, "ipe_runtime::server::server_listen")
}

/// The crate a green build wrote, proven still the one its rebuild claimed.
///
/// `cargo` writes into the crate by path, so a crate replaced while it ran, or a
/// green build with no claim on record, is refused and its binary is never
/// started. `reported` names the output root in the refusal when no claim
/// exists.
fn prove_green_crate(building: Option<OwnedDir>, reported: &Path) -> Result<OwnedDir, CliError> {
    building.map_or_else(
        || {
            Err(CliError::from(OutputRefusal::Replaced(
                reported.to_path_buf(),
            )))
        },
        |dir| dir.verify().map(|()| dir),
    )
}

/// Build the child process's environment.
///
/// Sets both `IPE_WEB_PORT` and `IPE_SERVER_PORT` to the SAME configured
/// port — harmless (ignored) for whichever app shape didn't ask for it, and
/// what lets a `Ipe.Http.Server` fixture that reads `IPE_SERVER_PORT` (the
/// convention this repo's own `server_e2e.rs` test suite already
/// establishes) be driven by `--port` exactly like a Ipe.Web app is.
///
/// Also provides the watch-scoped half of session continuity —
/// default the dev session store to `file` (persisted beside the claimed
/// `crate_dir` the green build was proven to write,
/// confined to the emit tree's parent so the emit→cargo bridge's
/// `src/`-only prune pass never touches it) unless the caller's OWN
/// environment already configures `IPE_WEB_STORE`, in which case that
/// choice is respected verbatim (and warned about when it is exactly
/// `memory` — see `warn_if_memory_store`, called once at watch startup).
fn child_env(
    port: u16,
    crate_dir: &Path,
    hot_token: Option<&str>,
    control_port: Option<u16>,
    bluegreen: bool,
    reset_state: bool,
) -> Vec<(String, String)> {
    let mut env = vec![
        ("IPE_WEB_PORT".to_owned(), port.to_string()),
        ("IPE_SERVER_PORT".to_owned(), port.to_string()),
    ];
    // The loopback control-socket port for the shape-agnostic control channel
    // (tui/cli/worker hot-swap + time-travel debugger). Allocated by `ipe watch`
    // and injected like the port vars above; the child opens its control listener
    // only when BOTH this and `IPE_WATCH_HOT_TOKEN` are present (fail-closed to no
    // control surface). A release build's runtime never reads it.
    if let Some(cp) = control_port {
        env.push(("IPE_CONTROL_PORT".to_owned(), cp.to_string()));
    }
    // Blue-green cutover: tell the emitted server it runs behind the watch
    // proxy so its client greets a reconnect with the positive "updated ✓"
    // toast instead of the "Reconnecting…" banner. Only the blue-green path
    // sets this; the direct-bind path (and any release build) leaves it unset.
    if bluegreen {
        env.push(("IPE_WEB_SWAP_TOAST".to_owned(), "1".to_owned()));
    }
    // State-reset escape hatch: force every returning session to a fresh `init`
    // for the child's lifetime, bypassing additive-splice. Dev-only; a release
    // binary never receives this — `IPE_WEB_RESET_STATE` is a no-op unless
    // the emitted binary's runtime reads it via `reset_state_from_env`.
    if reset_state {
        env.push(("IPE_WEB_RESET_STATE".to_owned(), "1".to_owned()));
    }
    // Under appearance hot-swap, hand the running app the per-session control
    // token so its `/_ipe/hot-appearance` endpoint accepts patches from THIS
    // watch (and nothing else). Absent ⇒ the endpoint fails closed.
    if let Some(tok) = hot_token {
        env.push(("IPE_WATCH_HOT_TOKEN".to_owned(), tok.to_owned()));
        // The emitted app's runtime reads `IPE_WATCH_HOT_APPEARANCE` to activate
        // its overlay (see the runtime's `literal_table`). A hot token present
        // means this watch built with the hot-swap emit, so tell the child to
        // turn its overlay on — explicitly, so default-on works without the user
        // setting anything.
        env.push(("IPE_WATCH_HOT_APPEARANCE".to_owned(), "1".to_owned()));
    }
    if ipe_env::var("IPE_WEB_STORE").is_err() {
        // `file`, not `sqlite`: a plain `Web.tea` reaches no DB kernel, so the
        // emitted crate carries no `db` feature and the sqlite store compiles
        // out (it would silently degrade to an in-memory store that does NOT
        // survive a rebuild — no Model handoff). The `file` store rides the
        // `web` feature every web build already has, reusing the same
        // schema-tagged checkpoint codec, so the blue-green swap can rehydrate
        // the Model. Confined to the emit tree's parent so the `src/`-only
        // prune pass never touches it.
        env.push(("IPE_WEB_STORE".to_owned(), "file".to_owned()));
        let store_path = crate_dir
            .parent()
            .unwrap_or(crate_dir)
            .join(".ipe-watch-sessions.json");
        env.push((
            "IPE_WEB_STORE_PATH".to_owned(),
            store_path.to_string_lossy().into_owned(),
        ));
    }
    // A dev rebuild is down for seconds (the cargo relink dominates), so widen
    // the browser's fast-reconnect window past its default to cover it: the page
    // reconnects a fast-retry tick after the new server binds instead of waiting
    // out an exponential-backoff interval. The caller's own value wins.
    if ipe_env::var("IPE_WEB_RETRY_FAST_WINDOW_MS").is_err() {
        env.push(("IPE_WEB_RETRY_FAST_WINDOW_MS".to_owned(), "8000".to_owned()));
    }
    env
}

/// Mint a per-session control token for the `/_ipe/hot-appearance` endpoint.
///
/// The token authenticates a live appearance patch: only this watch process
/// knows it (it is injected into the child's env and never printed), so even a
/// dev server bound to `0.0.0.0` cannot be driven by a LAN peer. The 256 bits
/// come from the OS CSPRNG on every target (`getrandom` wraps `getrandom(2)` /
/// `/dev/urandom` on Unix and `BCryptGenRandom` on Windows), rendered as
/// lowercase hex. There is no non-CSPRNG fallback: if the OS CSPRNG cannot be
/// read this returns `None` and the caller leaves the control endpoint unarmed
/// — a fail-closed downgrade to "no hot control", never a guessable token.
fn mint_hot_token() -> Option<String> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).ok()?;
    Some(hex::encode(buf))
}

/// POST every edited view's appearance patch to the running app's
/// `/_ipe/hot-appearance` endpoint, authenticated with the session control
/// token. Returns `true` only if every patch was accepted (HTTP 200), so a
/// caller can fall back to a full recompile on any miss. An empty patch list is
/// a no-op success (a whitespace-only edit the emitter normalised away).
fn push_appearance_patches(
    port: u16,
    token: &str,
    patches: &[crate::hot_classify::ViewPatch],
    quiet: bool,
) -> bool {
    for vp in patches {
        let body = serde_json::json!({
            "defaults": vp.defaults,
            "patch": vp.patch,
        })
        .to_string();
        if !matches!(post_hot_appearance(port, token, &body), Ok(true)) {
            if !quiet {
                emit_watch_line(
                    &crate::style::TerminalSafe::sanitize(
                        "[ipe watch] appearance hot-swap push failed — falling back to a \
                         full rebuild",
                    ),
                    WatchRole::Info,
                );
            }
            return false;
        }
    }
    if !quiet {
        emit_watch_line(
            &crate::style::TerminalSafe::sanitize(
                "[ipe watch] appearance edit hot-swapped (no rebuild)",
            ),
            WatchRole::Info,
        );
    }
    true
}

/// Send one `POST /_ipe/hot-appearance` to loopback `port` over a raw HTTP/1.1
/// connection, returning `Ok(true)` on a `200 OK` status line. Loopback-only and
/// dev-only, so a minimal blocking request (no client crate, no keep-alive) is
/// sufficient; a short connect/read timeout keeps a dead app from stalling the
/// watch loop.
///
/// # Errors
/// An I/O error if the connection cannot be made or the exchange fails.
fn post_hot_appearance(port: u16, token: &str, body: &str) -> std::io::Result<bool> {
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500))?;
    stream.set_read_timeout(Some(Duration::from_millis(1500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(1500)))?;
    let req = format!(
        "POST /_ipe/hot-appearance HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         X-Ipe-Hot-Token: {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        len = body.len(),
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    let mut resp = Vec::new();
    // Read only the status line's worth; the body is empty (`OK`) either way.
    let mut chunk = [0u8; 256];
    if let Ok(n) = stream.read(&mut chunk)
        && let Some(head) = chunk.get(..n)
    {
        resp.extend_from_slice(head);
    }
    let head = String::from_utf8_lossy(&resp);
    Ok(head.starts_with("HTTP/1.1 200"))
}

/// Send one [`ControlFrame`] to the child's loopback control socket, presenting
/// the session token, and read back the child's reply frame.
///
/// The parent end of the tui/cli/worker control transport, mirroring
/// `post_hot_appearance`: a minimal blocking exchange over a raw std socket
/// (loopback-only, dev-only), with a short connect/read timeout so a dead app
/// cannot stall the watch loop. The wire is the runtime's ONE definition
/// (`ipe_runtime_rust::control`) — the token is presented as its own
/// length-delimited record ahead of the `encode_frame` body, exactly as the
/// child's accept-loop expects.
///
/// Returns the decoded reply on success — a caller reads its
/// [`ControlFrame::Ack`] to decide whether to proceed or fall back to a full
/// rebuild.
///
/// # Errors
/// An I/O error if the connection cannot be made, the exchange fails, or the
/// frame cannot be encoded/decoded (a too-large frame or a malformed reply).
fn send_control_frame(
    port: u16,
    token: &str,
    frame: &ipe_runtime_rust::control::ControlFrame,
) -> std::io::Result<ipe_runtime_rust::control::ControlFrame> {
    use ipe_runtime_rust::control::{decode_frame, encode_frame};
    use std::io::{Read as _, Write as _};
    use std::net::{SocketAddr, TcpStream};
    let body = encode_frame(frame).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "control frame exceeds the wire cap",
        )
    })?;
    let token_bytes = token.as_bytes();
    let token_len = u32::try_from(token_bytes.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "control token too long")
    })?;
    let addr = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500))?;
    stream.set_read_timeout(Some(Duration::from_millis(1500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(1500)))?;
    // The token record precedes the frame record: a 4-byte big-endian length
    // prefix over the raw token bytes, matching the child's `read_record`.
    stream.write_all(&token_len.to_be_bytes())?;
    stream.write_all(token_bytes)?;
    stream.write_all(&body)?;
    stream.flush()?;
    // The reply is a single length-delimited frame; read the whole (small) record
    // to EOF — the child closes after one reply. The cap bounds what a compromised
    // child could make the parent buffer.
    let mut resp = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if let Some(head) = chunk.get(..n) {
                    resp.extend_from_slice(head);
                }
                if resp.len() > ipe_runtime_rust::control::MAX_FRAME_LEN + 4 {
                    break;
                }
            }
            Err(e) => return Err(e),
        }
    }
    let (reply, _consumed) = decode_frame(&resp)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(reply)
}

/// Deliver each edited view's appearance patch to a running Ipe.Tui child over
/// the loopback control socket as a [`ControlFrame::HotAppearance`], the tui
/// analogue of [`push_appearance_patches`] (which uses the web HTTP endpoint).
///
/// Returns `true` only when EVERY patch was delivered AND the child replied with
/// a positive [`ControlFrame::Ack`] — so any miss (no control port, a socket
/// error, a rejecting ack, or an unexpected reply variant) falls the caller back
/// to a full rebuild, never a silent partial apply. An empty patch list is a
/// no-op success. `control_port` absent ⇒ `false` (no channel ⇒ full rebuild).
fn push_control_appearance(
    control_port: Option<u16>,
    token: &str,
    patches: &[crate::hot_classify::ViewPatch],
    quiet: bool,
) -> bool {
    use ipe_runtime_rust::control::{AppearancePatch, ControlFrame};
    // An empty patch list is a no-op success: nothing to deliver means nothing
    // to rebuild for, independent of whether a control port was leased.
    if patches.is_empty() {
        return true;
    }
    let Some(port) = control_port else {
        return false;
    };
    for vp in patches {
        let frame = ControlFrame::HotAppearance(AppearancePatch {
            defaults: vp.defaults.clone(),
            patch: vp.patch.clone(),
        });
        // Fail closed on ANYTHING other than an explicit positive Ack: an I/O
        // error, a rejecting Ack, or a non-Ack reply all fall back to a rebuild.
        let applied = matches!(
            send_control_frame(port, token, &frame),
            Ok(ControlFrame::Ack { ok: true, .. })
        );
        if !applied {
            if !quiet {
                emit_watch_line(
                    &crate::style::TerminalSafe::sanitize(
                        "[ipe watch] tui appearance hot-swap failed — falling back to a \
                             full rebuild",
                    ),
                    WatchRole::Info,
                );
            }
            return false;
        }
    }
    if !quiet && !patches.is_empty() {
        emit_watch_line(
            &crate::style::TerminalSafe::sanitize(
                "[ipe watch] tui appearance edit hot-swapped (no rebuild)",
            ),
            WatchRole::Info,
        );
    }
    true
}

/// POST every edited `update` arm's transition patch to the running app's
/// `/_ipe/hot-transition` endpoint, authenticated with the same session control
/// token as the appearance channel. Returns `true` only if every patch was
/// accepted (HTTP 200), so a caller can fall back to a full recompile on any
/// miss. An empty patch list is a no-op success.
fn push_transition_patches(
    port: u16,
    token: &str,
    patches: &[crate::hot_classify::TransitionPatch],
    quiet: bool,
) -> bool {
    for tp in patches {
        let body = serde_json::json!({
            "old_json": tp.old_json,
            "new_json": tp.new_json,
        })
        .to_string();
        if !matches!(post_hot_transition(port, token, &body), Ok(true)) {
            if !quiet {
                emit_watch_line(
                    &crate::style::TerminalSafe::sanitize(
                        "[ipe watch] transition hot-swap push failed — falling back to a \
                         full rebuild",
                    ),
                    WatchRole::Info,
                );
            }
            return false;
        }
    }
    if !quiet && !patches.is_empty() {
        emit_watch_line(
            &crate::style::TerminalSafe::sanitize(
                "[ipe watch] update-arm edit hot-swapped (no rebuild)",
            ),
            WatchRole::Info,
        );
    }
    true
}

/// Send one `POST /_ipe/hot-transition` to loopback `port`, returning `Ok(true)`
/// on a `200 OK` status line. Same minimal blocking-request shape and timeouts
/// as [`post_hot_appearance`] — loopback + dev-only, so no client crate needed.
///
/// # Errors
/// An I/O error if the connection cannot be made or the exchange fails.
fn post_hot_transition(port: u16, token: &str, body: &str) -> std::io::Result<bool> {
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500))?;
    stream.set_read_timeout(Some(Duration::from_millis(1500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(1500)))?;
    let req = format!(
        "POST /_ipe/hot-transition HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         X-Ipe-Hot-Token: {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        len = body.len(),
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    let mut resp = Vec::new();
    let mut chunk = [0u8; 256];
    if let Ok(n) = stream.read(&mut chunk)
        && let Some(head) = chunk.get(..n)
    {
        resp.extend_from_slice(head);
    }
    let head = String::from_utf8_lossy(&resp);
    Ok(head.starts_with("HTTP/1.1 200"))
}

fn push_msg_set_patches(
    port: u16,
    token: &str,
    patches: &[crate::hot_classify::MsgSetPatch],
    quiet: bool,
) -> bool {
    for mp in patches {
        let body = serde_json::json!({
            "live_json": mp.live_json,
            "candidate_json": mp.candidate_json,
        })
        .to_string();
        if !matches!(post_hot_msg(port, token, &body), Ok(true)) {
            if !quiet {
                emit_watch_line(
                    &crate::style::TerminalSafe::sanitize(
                        "[ipe watch] Msg-set hot-swap push failed — falling back to a \
                         full rebuild",
                    ),
                    WatchRole::Info,
                );
            }
            return false;
        }
    }
    if !quiet && !patches.is_empty() {
        emit_watch_line(
            &crate::style::TerminalSafe::sanitize(
                "[ipe watch] added Msg variant hot-swapped (no rebuild)",
            ),
            WatchRole::Info,
        );
    }
    true
}

/// POST every edited `subscriptions` entry's sub-description patch to the running
/// app's `/_ipe/hot-subs` endpoint, authenticated with the same session control
/// token as the appearance/transition channels. Returns `true` only if every patch
/// was accepted (HTTP 200), so a caller can fall back to a full recompile on any
/// miss. An empty patch list is a no-op success.
fn push_sub_patches(
    port: u16,
    token: &str,
    patches: &[crate::hot_classify::SubPatch],
    quiet: bool,
) -> bool {
    for sp in patches {
        let body = serde_json::json!({
            "old_json": sp.old_json,
            "new_json": sp.new_json,
        })
        .to_string();
        if !matches!(post_hot_subs(port, token, &body), Ok(true)) {
            if !quiet {
                emit_watch_line(
                    &crate::style::TerminalSafe::sanitize(
                        "[ipe watch] subscription hot-swap push failed — falling back to a \
                         full rebuild",
                    ),
                    WatchRole::Info,
                );
            }
            return false;
        }
    }
    if !quiet && !patches.is_empty() {
        emit_watch_line(
            &crate::style::TerminalSafe::sanitize(
                "[ipe watch] subscriptions edit hot-swapped (no rebuild)",
            ),
            WatchRole::Info,
        );
    }
    true
}

/// Send one `POST /_ipe/hot-msg` to loopback `port`, returning `Ok(true)` on a
/// `200 OK` status line. Same minimal blocking-request shape and timeouts as
/// [`post_hot_transition`] — loopback + dev-only, so no client crate needed.
///
/// # Errors
/// An I/O error if the connection cannot be made or the exchange fails.
fn post_hot_msg(port: u16, token: &str, body: &str) -> std::io::Result<bool> {
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500))?;
    stream.set_read_timeout(Some(Duration::from_millis(1500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(1500)))?;
    let req = format!(
        "POST /_ipe/hot-msg HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         X-Ipe-Hot-Token: {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        len = body.len(),
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    let mut resp = Vec::new();
    let mut chunk = [0u8; 256];
    if let Ok(n) = stream.read(&mut chunk)
        && let Some(head) = chunk.get(..n)
    {
        resp.extend_from_slice(head);
    }
    let head = String::from_utf8_lossy(&resp);
    Ok(head.starts_with("HTTP/1.1 200"))
}

/// Send one `POST /_ipe/hot-subs` to loopback `port`, returning `Ok(true)` on a
/// `200 OK` status line. Same minimal blocking-request shape and timeouts as
/// [`post_hot_transition`] — loopback + dev-only, so no client crate needed.
///
/// # Errors
/// An I/O error if the connection cannot be made or the exchange fails.
fn post_hot_subs(port: u16, token: &str, body: &str) -> std::io::Result<bool> {
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500))?;
    stream.set_read_timeout(Some(Duration::from_millis(1500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(1500)))?;
    let req = format!(
        "POST /_ipe/hot-subs HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         X-Ipe-Hot-Token: {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        len = body.len(),
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    let mut resp = Vec::new();
    let mut chunk = [0u8; 256];
    if let Ok(n) = stream.read(&mut chunk)
        && let Some(head) = chunk.get(..n)
    {
        resp.extend_from_slice(head);
    }
    let head = String::from_utf8_lossy(&resp);
    Ok(head.starts_with("HTTP/1.1 200"))
}

fn push_init_patches(
    port: u16,
    token: &str,
    patches: &[crate::hot_classify::InitPatch],
    quiet: bool,
) -> bool {
    for ip in patches {
        let body = serde_json::json!({
            "old_json": ip.old_json,
            "new_json": ip.new_json,
        })
        .to_string();
        if !matches!(post_hot_init(port, token, &body), Ok(true)) {
            if !quiet {
                emit_watch_line(
                    &crate::style::TerminalSafe::sanitize(
                        "[ipe watch] init hot-swap push failed — falling back to a \
                         full rebuild",
                    ),
                    WatchRole::Info,
                );
            }
            return false;
        }
    }
    if !quiet && !patches.is_empty() {
        emit_watch_line(
            &crate::style::TerminalSafe::sanitize(
                "[ipe watch] init edit hot-swapped for new sessions (no rebuild)",
            ),
            WatchRole::Info,
        );
    }
    true
}

/// Send one `POST /_ipe/hot-init` to loopback `port`, returning `Ok(true)` on a
/// `200 OK` status line. Same minimal blocking-request shape and timeouts as
/// [`post_hot_appearance`] — loopback + dev-only, so no client crate needed.
///
/// # Errors
/// An I/O error if the connection cannot be made or the exchange fails.
fn post_hot_init(port: u16, token: &str, body: &str) -> std::io::Result<bool> {
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500))?;
    stream.set_read_timeout(Some(Duration::from_millis(1500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(1500)))?;
    let req = format!(
        "POST /_ipe/hot-init HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         X-Ipe-Hot-Token: {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        len = body.len(),
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    let mut resp = Vec::new();
    let mut chunk = [0u8; 256];
    if let Ok(n) = stream.read(&mut chunk)
        && let Some(head) = chunk.get(..n)
    {
        resp.extend_from_slice(head);
    }
    let head = String::from_utf8_lossy(&resp);
    Ok(head.starts_with("HTTP/1.1 200"))
}

/// POST every edited `update` arm's Cmd-wiring patch to the running app's
/// `/_ipe/hot-wiring` endpoint, authenticated with the same session control
/// token. Returns `true` only if every patch was accepted (HTTP 200), so a caller
/// can fall back to a full recompile on any miss. An empty patch list is a no-op
/// success. A wiring edit swaps which already-compiled effect an arm fires; the
/// effect body is unchanged.
fn push_wiring_patches(
    port: u16,
    token: &str,
    patches: &[crate::hot_classify::WiringPatch],
    quiet: bool,
) -> bool {
    for wp in patches {
        let body = serde_json::json!({
            "old_json": wp.old_json,
            "new_json": wp.new_json,
        })
        .to_string();
        if !matches!(post_hot_wiring(port, token, &body), Ok(true)) {
            if !quiet {
                emit_watch_line(
                    &crate::style::TerminalSafe::sanitize(
                        "[ipe watch] wiring hot-swap push failed — falling back to a \
                         full rebuild",
                    ),
                    WatchRole::Info,
                );
            }
            return false;
        }
    }
    if !quiet && !patches.is_empty() {
        emit_watch_line(
            &crate::style::TerminalSafe::sanitize(
                "[ipe watch] update-arm Cmd wiring hot-swapped (no rebuild)",
            ),
            WatchRole::Info,
        );
    }
    true
}

/// Send one `POST /_ipe/hot-wiring` to loopback `port`, returning `Ok(true)` on a
/// `200 OK` status line. Same minimal blocking-request shape and timeouts as
/// [`post_hot_appearance`] — loopback + dev-only, so no client crate needed.
///
/// # Errors
/// An I/O error if the connection cannot be made or the exchange fails.
fn post_hot_wiring(port: u16, token: &str, body: &str) -> std::io::Result<bool> {
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500))?;
    stream.set_read_timeout(Some(Duration::from_millis(1500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(1500)))?;
    let req = format!(
        "POST /_ipe/hot-wiring HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         X-Ipe-Hot-Token: {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        len = body.len(),
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    let mut resp = Vec::new();
    let mut chunk = [0u8; 256];
    if let Ok(n) = stream.read(&mut chunk)
        && let Some(head) = chunk.get(..n)
    {
        resp.extend_from_slice(head);
    }
    let head = String::from_utf8_lossy(&resp);
    Ok(head.starts_with("HTTP/1.1 200"))
}

/// The dev child's launch `Command`: `exe_path` with `env` applied and stdin closed.
fn child_command(exe_path: &Path, env: &[(String, String)]) -> Command {
    let mut cmd = Command::new(exe_path);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdin(std::process::Stdio::null());
    cmd
}

/// Spawn the dev child through the runtime's parent-death floor.
///
/// The supervisor reaps this child on every GRACEFUL path (shutdown /
/// SIGTERM-forwarder / Drop), but a SIGKILL/OOM/panic-abort of `ipe watch`
/// would otherwise orphan it holding the dev port. `spawn_hardened` forks it
/// from the runtime's process-lifetime spawner thread, so on Linux the kernel
/// SIGTERMs it when `ipe watch` dies by ANY means, and never earlier (the
/// signal is bound to the forking thread, which lives as long as the process).
/// A refused hardened spawn surfaces as a spawn error; it never degrades to an
/// unhardened spawn.
fn spawn_command(exe_path: &Path, env: &[(String, String)]) -> std::io::Result<Child> {
    ipe_runtime_rust::system::spawn_hardened(child_command(exe_path, env))
        .map_err(std::io::Error::from)
}

/// Frame a compiler diagnostic for the watch stderr build-failed report: the
/// guttered, soft-yellow block `ipe watch` prints when a compile fails while the
/// last-good binary stays up.
///
/// The diagnostic carries `.ipe` source-span snippets — untrusted text that
/// could smuggle raw control/ANSI bytes able to move the cursor, recolour, or
/// hide output on our stderr. It is sanitised through [`crate::style::TerminalSafe`]
/// FIRST; the palette escapes are our own, added only after the untrusted text is
/// neutralised, so the frame's sole control bytes are the ones we put there.
fn compile_failed_frame(msg: &str, p: &crate::style::Palette) -> String {
    let safe_msg = crate::style::TerminalSafe::sanitize(msg.trim_end());
    // The failure glyph comes from the style SSOT; the tint is deliberately the
    // soft warning amber, not the red a hard failure wears — the last-good binary
    // stays up.
    let body = format!(
        "{}{} [ipe watch] build failed (last-good binary stays up):{}\n{}",
        p.bright_yellow,
        crate::style::outcome_glyph(crate::style::Outcome::Failure),
        p.reset,
        safe_msg.as_str()
    );
    crate::style::gutter(&body)
}

/// Extract the first non-blank line from a compiler diagnostic, capped at
/// 120 characters, for inclusion in the build-failed banner.
fn first_error_line(msg: &str) -> String {
    let stripped = strip_ansi(msg);
    stripped
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .chars()
        .take(120)
        .collect()
}

/// Remove ANSI escape sequences from `s`. Cargo forces coloured, progress-bar
/// stderr when the watch's terminal is a TTY, so a build-failure excerpt arrives
/// laced with CSI sequences (`ESC [ … m`) and other escapes. Dropping them keeps
/// the browser build-status banner readable and free of terminal control codes.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        // An escape introduces a control sequence. A CSI (`ESC [`) runs until a
        // final byte in 0x40..=0x7e; any other escape consumes just its single
        // following byte. Either way the escape itself is dropped.
        if chars.next() == Some('[') {
            for seq in chars.by_ref() {
                if ('\u{40}'..='\u{7e}').contains(&seq) {
                    break;
                }
            }
        }
    }
    out
}

/// POST `{ok, error}` to the child's dev-only `/_ipe/watch/status` endpoint.
///
/// Best-effort: silently ignores all errors. The child may not be running yet,
/// or the endpoint may not be mounted (non-web app, banner disabled, etc.) —
/// all of those are fine. A short connect+read timeout keeps a dead app from
/// stalling the watch loop.
/// The port the app that actually serves the browser is listening on — the
/// target for a build-status POST.
///
/// Under blue-green (default) the user-facing `port` is held by the front proxy
/// and the live app runs behind it on an internal loopback port, so a status
/// POST to `port` would hit the proxy (which 502s when no upstream is ready yet,
/// so the in-app banner never appears). Route to the proxy's current upstream
/// instead. `None` when no app is up (no upstream, or the internal port is not
/// yet known) — there is then no browser to notify. Direct-bind (no proxy) keeps
/// the app on `port` itself.
fn app_status_port(proxy: Option<&ipe_watch::DevProxy>, port: u16) -> Option<u16> {
    proxy.map_or(Some(port), |p| match p.current_upstream() {
        0 => None,
        up => Some(up),
    })
}

fn post_watch_status(port: u16, token: &str, ok: bool, error: &str) {
    let _ = post_to_watch_status(port, token, &watch_status_body(ok, error));
}

/// Serialise the `{ok, error}` watch-status body. `serde_json` escapes every
/// control char below 0x20 as `\u00XX`, so a compiler excerpt carrying carriage
/// returns or ANSI escapes still yields RFC 8259-valid JSON the server can
/// parse — hand-rolled backslash/quote escaping alone left those unescaped and
/// the server rejected the body.
fn watch_status_body(ok: bool, error: &str) -> String {
    let value = if ok {
        serde_json::json!({ "ok": true })
    } else {
        serde_json::json!({ "ok": false, "error": error })
    };
    value.to_string()
}

/// Tell the running app a rebuild has started, so it shows a soft-yellow
/// "Recompiling app" banner during the otherwise-silent cargo build (the ok /
/// error result follows when the build settles). Best-effort, like every other
/// dev-endpoint POST.
fn post_watch_recompiling(port: u16, token: &str) {
    let _ = post_to_watch_status(port, token, r#"{"ok":false,"phase":"recompiling"}"#);
}

/// Send one raw HTTP/1.1 POST to `/_ipe/watch/status`. Returns `Ok(())` when
/// the server replied (any status); any I/O failure is silently discarded by
/// the caller. Mirrors the structure of `post_hot_appearance`.
fn post_to_watch_status(port: u16, token: &str, body: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::net::TcpStream;
    let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500))?;
    stream.set_write_timeout(Some(Duration::from_millis(1500)))?;
    let req = format!(
        "POST /_ipe/watch/status HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         X-Ipe-Hot-Token: {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        len = body.len(),
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    Ok(())
}

/// The `memory`-store warning: called once, at watch startup, so it is
/// printed exactly once per session rather than on every rebuild.
///
/// # Errors
/// Never — this only ever prints; it returns nothing failable, kept as a
/// plain function (not `Result`) so call sites don't need to thread an
/// unused error channel.
fn warn_if_memory_store() {
    if ipe_env::var("IPE_WEB_STORE").as_deref() == Ok("memory") {
        emit_watch_line(
            &crate::style::TerminalSafe::sanitize(
                "[ipe watch] warning: IPE_WEB_STORE=memory is set — session state will NOT \
                 survive a watch-triggered restart. Unset it (watch defaults to a file-backed \
                 store) or set IPE_WEB_STORE=file explicitly to keep your session across rebuilds.",
            ),
            WatchRole::Info,
        );
    }
}

/// Whether a restart outcome left an app actually serving — the two outcomes
/// that bring a binary up (a fresh spawn, a reload). The last-good-fallback and
/// nothing-running outcomes did NOT start the new binary, so they must not
/// trigger the first-run URL announcement.
const fn outcome_is_running(outcome: &ipe_watch::RestartOutcome) -> bool {
    matches!(
        outcome,
        ipe_watch::RestartOutcome::Spawned
            | ipe_watch::RestartOutcome::Restarted
            | ipe_watch::RestartOutcome::UnchangedBinary
    )
}

/// The prominent open-URL block shown once the first web app is up: a framed,
/// guttered, soft-green line naming the address to open. Coloured when stderr is
/// a colour terminal, plain otherwise.
fn open_url_block(port: u16) -> String {
    let p = crate::style::Palette::for_stream(&std::io::stderr());
    let body = format!(
        "{g}➜  Open{r}   {g}http://localhost:{port}{r}",
        g = p.green,
        r = p.reset,
    );
    crate::style::frame(&crate::style::gutter(&body))
}

fn report_restart_outcome(outcome: &ipe_watch::RestartOutcome, quiet: bool) {
    match outcome {
        ipe_watch::RestartOutcome::Spawned => {
            if !quiet {
                emit_watch_line(
                    &crate::style::TerminalSafe::sanitize("[ipe watch] app started"),
                    WatchRole::Success,
                );
            }
        }
        ipe_watch::RestartOutcome::UnchangedBinary => {}
        ipe_watch::RestartOutcome::Restarted => {
            if !quiet {
                emit_watch_line(
                    &crate::style::TerminalSafe::sanitize("[ipe watch] app reloaded"),
                    WatchRole::Success,
                );
            }
        }
        ipe_watch::RestartOutcome::RespawnedLastGood { broken } => emit_watch_line(
            &crate::style::TerminalSafe::sanitize(&format!(
                "[ipe watch] new binary failed its readiness probe ({}); kept the previous \
                     last-good binary running instead",
                broken.display()
            )),
            WatchRole::Failure,
        ),
        ipe_watch::RestartOutcome::NothingRunning {
            broken,
            last_good_error,
        } => {
            emit_watch_line(
                &crate::style::TerminalSafe::sanitize(&format!(
                    "[ipe watch] new binary failed its readiness probe ({}); no previous \
                         last-good binary could be brought up{}",
                    broken.display(),
                    last_good_error
                        .as_ref()
                        .map_or_else(String::new, |e| format!(" ({e})"))
                )),
                WatchRole::Failure,
            );
        }
    }
}

/// Project a [`ipe_watch::RestartOutcome`] down to the `Clone`-able
/// [`RestartOutcomeKind`] tests observe via [`WatchEvent::Restarted`].
const fn restart_outcome_kind(outcome: &ipe_watch::RestartOutcome) -> RestartOutcomeKind {
    match outcome {
        ipe_watch::RestartOutcome::Spawned => RestartOutcomeKind::Spawned,
        ipe_watch::RestartOutcome::UnchangedBinary => RestartOutcomeKind::UnchangedBinary,
        ipe_watch::RestartOutcome::Restarted => RestartOutcomeKind::Restarted,
        ipe_watch::RestartOutcome::RespawnedLastGood { .. } => {
            RestartOutcomeKind::RespawnedLastGood
        }
        ipe_watch::RestartOutcome::NothingRunning { .. } => RestartOutcomeKind::NothingRunning,
    }
}

/// Spawn `cargo build --message-format=json` in `out_dir` and a companion
/// Opt-out env gate for the dev-loop incremental rebuild path. When set to any
/// value other than `0`, `ipe watch` keeps the machine's normal build
/// configuration (sccache wrapper, non-incremental) for the emitted-app rebuild
/// instead of the fast incremental path.
const NO_INCREMENTAL_ENV: &str = "IPE_WATCH_NO_INCREMENTAL";

/// The build-acceleration strategy for one watch-mode `cargo build`, chosen from
/// the target's warmth.
///
/// sccache and rustc-incremental are mutually exclusive (sccache refuses to cache
/// an incremental crate) and they accelerate opposite halves of the loop: sccache
/// caches whole *dependency* crates in a shared store — its win is the one-time
/// cold compile of the registry deps the emitted app links; incremental caches at
/// codegen-unit granularity within one warm target — its win is the per-edit
/// rebuild of the app crate (the vendored runtime module tree compiled inside it).
/// So the split that matters is *cold deps vs warm app*, not first-run vs later: a
/// target whose deps are not yet built compiles under sccache, and every warm
/// rebuild after that uses incremental. A machine-level
/// `build.rustc-wrapper = "sccache"` + `build.incremental = false` would otherwise
/// force every rebuild to re-codegen the whole app from scratch; the warm path
/// overrides it in THIS child only.
///
/// Behaviour-identical either way — incremental changes codegen partitioning, not
/// program semantics (enforced by the clean-vs-incremental parity gate) — and
/// scoped to the watch child: `ipe build` (release / clean / CI) never calls this.
enum BuildAccel {
    /// Explicit opt-out ([`NO_INCREMENTAL_ENV`]): leave the machine's build
    /// configuration untouched for the emitted-app rebuild.
    MachineDefault,
    /// Cold target — an `sccache` wrapper for a fast one-time dependency compile.
    /// Incremental is off (the two cannot coexist); the payoff is bounded to the
    /// first build on a fresh target.
    ColdSccache(PathBuf),
    /// Warm target — per-crate incremental codegen, sccache taken out of the
    /// picture for this child.
    WarmIncremental,
}

/// The target directory this watch build will use: an explicit
/// [`WatchOptions::target_dir`] override wins, else an inherited
/// `CARGO_TARGET_DIR`, else cargo's default of `<out_dir>/target`.
fn watch_target_dir(out_dir: &Path, override_dir: Option<&Path>) -> PathBuf {
    override_dir.map_or_else(
        || {
            ipe_env::var_os("CARGO_TARGET_DIR")
                .map_or_else(|| out_dir.join("target"), PathBuf::from)
        },
        Path::to_path_buf,
    )
}

/// Whether a resolved target directory already holds a compiled dependency
/// library (a single `.rlib` under `debug/deps` — the registry crates the emitted
/// app links). Fail-safe: any I/O error reads as no-rlib, so the worst case is one
/// extra sccache-mode build, never a wrong-but-fast one. Pure in its argument —
/// the ambient-env resolution lives in [`target_is_warm`].
fn dir_has_dep_rlib(target_dir: &Path) -> bool {
    let deps = target_dir.join("debug").join("deps");
    let Ok(entries) = std::fs::read_dir(&deps) else {
        return false;
    };
    entries
        .flatten()
        .any(|e| e.path().extension().is_some_and(|x| x == "rlib"))
}

/// A target is *warm* once it already holds compiled dependency libraries; a
/// fresh (or pruned) target holds none. Resolves the target directory cargo will
/// actually use (honouring an inherited `CARGO_TARGET_DIR`, exactly as the watch
/// build will) and checks it for a dependency `.rlib`.
fn target_is_warm(out_dir: &Path, override_dir: Option<&Path>) -> bool {
    dir_has_dep_rlib(&watch_target_dir(out_dir, override_dir))
}

/// Locate an `sccache` executable on `PATH`, if the machine has one. sccache is
/// optional: absent, a cold build simply falls back to the warm/incremental path
/// — correct, only slower for the first compile.
fn find_sccache() -> Option<PathBuf> {
    let path = ipe_env::var_os("PATH")?;
    std::env::split_paths(&path)
        .flat_map(|dir| [dir.join("sccache"), dir.join("sccache.exe")])
        .find(|p| p.is_file())
}

/// Pick the acceleration strategy for the next watch build from the opt-out gate
/// and the target's warmth. A cold target with sccache available builds its deps
/// under sccache; a warm target (or no sccache) uses incremental. Re-evaluated
/// per build, so the cold sccache build's deps make the very next build warm and
/// incremental — the one-time cold→warm transition the design intends.
///
/// The decision is computed at the call site and passed to
/// [`apply_build_accel_env`], keeping the env-to-`Command` mapping a pure function.
fn choose_build_accel(out_dir: &Path, override_dir: Option<&Path>, opt_out: bool) -> BuildAccel {
    if opt_out {
        return BuildAccel::MachineDefault;
    }
    match (target_is_warm(out_dir, override_dir), find_sccache()) {
        (false, Some(sccache)) => BuildAccel::ColdSccache(sccache),
        _ => BuildAccel::WarmIncremental,
    }
}

/// Map a [`BuildAccel`] onto a watch child's `cargo build` environment. Pure: the
/// only inputs are the chosen strategy and the command.
fn apply_build_accel_env(cmd: &mut Command, accel: &BuildAccel) {
    match accel {
        BuildAccel::MachineDefault => {}
        BuildAccel::ColdSccache(sccache) => {
            // sccache cannot cache an incremental crate, so incremental is off for
            // this cold build. Wire the wrapper explicitly rather than trust the
            // machine config, so the cold path works with or without a global
            // sccache setting.
            cmd.env("CARGO_INCREMENTAL", "0");
            cmd.env("RUSTC_WRAPPER", sccache);
            cmd.env("RUSTC_WORKSPACE_WRAPPER", "");
        }
        BuildAccel::WarmIncremental => {
            cmd.env("CARGO_INCREMENTAL", "1");
            // Clear BOTH wrapper hooks so a machine-level `rustc-wrapper = "sccache"`
            // (which forces non-incremental) does not defeat the incremental
            // request. Empty string, not `remove_env`: cargo reads the wrapper from
            // its resolved config, so an empty override in the child env is what
            // actually disables it — removing the var alone would let the config win.
            cmd.env("RUSTC_WRAPPER", "");
            cmd.env("RUSTC_WORKSPACE_WRAPPER", "");
        }
    }
}

/// Read a boolean opt-out/opt-in env gate: true when the variable is set to any
/// value other than empty or `0`.
fn env_flag_on(name: &str) -> bool {
    ipe_env::var(name).is_ok_and(|v| !v.is_empty() && v != "0")
}

/// waiter thread that reports completion (or "killed — superseded")
/// through `evt_tx`, tagged with `generation`. Returns a shared handle the
/// orchestrator can `.kill()` from a DIFFERENT thread while the waiter is
/// concurrently polling it — see the module doc's cancellation section.
///
/// The returned handle is wrapped in `Arc<Mutex<..>>` rather than handed
/// out as a bare `Child` because BOTH the orchestrator (kill-on-supersede)
/// and this function's own waiter thread (exit detection) need independent
/// access; the waiter deliberately uses `try_wait` in a short poll loop
/// rather than a blocking `wait()` so it never holds the lock across a
/// call that could block for the build's entire duration — holding the
/// lock there would make the orchestrator's `.kill()` block on the very
/// wait it's trying to interrupt (a real deadlock this design avoids by
/// construction, not by convention).
///
/// # Errors
/// An I/O error if the `cargo` process itself cannot be spawned.
fn spawn_cargo_build(
    cargo_path: &Path,
    out_dir: &Path,
    target_dir: Option<&Path>,
    generation: u64,
    evt_tx: mpsc::Sender<OrchestratorEvent>,
    quiet: bool,
) -> std::io::Result<Arc<std::sync::Mutex<CargoChild>>> {
    let mut cmd = Command::new(cargo_path);
    cmd.arg("build")
        .arg("--message-format=json")
        .current_dir(out_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // An explicit override pins the build's target dir; without one cargo honours
    // the inherited `CARGO_TARGET_DIR` (or its `<out_dir>/target` default).
    if let Some(target) = target_dir {
        cmd.env("CARGO_TARGET_DIR", target);
    }
    let accel = choose_build_accel(out_dir, target_dir, env_flag_on(NO_INCREMENTAL_ENV));
    apply_build_accel_env(&mut cmd, &accel);
    if quiet {
        cmd.arg("-q");
    } else {
        // Force colour + the progress bar through the pipe when our stderr is a terminal.
        crate::force_cargo_terminal_ui(&mut cmd);
    }
    // Anchor the cargo phase at spawn — the waiter thread reports the elapsed
    // time back through `CargoDone` for `IPE_WATCH_TIMING`.
    let cargo_started = Instant::now();
    let mut child = cmd.spawn()?;

    // Take the pipes now, before the `Child` moves behind the shared lock —
    // reading them on their own threads (rather than after exit) avoids the
    // classic `Command`-pipe deadlock where a full OS pipe buffer blocks the
    // child before it can exit.
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let shared = Arc::new(std::sync::Mutex::new(CargoChild {
        child,
        superseded: false,
    }));
    let shared_for_waiter = Arc::clone(&shared);

    let stdout_reader = thread::spawn(move || read_all(stdout));
    // Relay stderr live so the user sees cargo's progress bar and compiler
    // messages as they arrive, while still capturing the full text for the
    // failure diagnostic (CargoOutcome::Red carries it).
    let stderr_reader = thread::spawn(move || relay_and_capture_stderr(stderr));

    thread::spawn(move || {
        let status = loop {
            match shared_for_waiter.lock() {
                // A poisoned lock means the orchestrator thread panicked while
                // holding it; the exit status can no longer be observed, so
                // stop polling rather than spin forever.
                Err(_) => break None,
                Ok(mut guard) => {
                    let superseded = guard.superseded;
                    let polled = guard.child.try_wait();
                    drop(guard);
                    match polled {
                        Ok(Some(status)) => break Some((status, superseded)),
                        Ok(None) => {}
                        // A persistent `try_wait` error can never resolve by
                        // retrying, so stop rather than poll forever.
                        Err(_) => break None,
                    }
                }
            }
            thread::sleep(Duration::from_millis(30));
        };
        let out_buf = stdout_reader.join().unwrap_or_default();
        let err_buf = stderr_reader.join().unwrap_or_default();
        let outcome = match status {
            None => CargoOutcome::Red("cargo build: could not observe exit status".to_owned()),
            Some((status, _)) if status.success() => find_executable_path(&out_buf).map_or_else(
                || {
                    CargoOutcome::Red(
                        "cargo build succeeded but produced no executable artifact".to_owned(),
                    )
                },
                CargoOutcome::Green,
            ),
            Some((_, true)) => CargoOutcome::Killed,
            Some((_, false)) => CargoOutcome::Red(err_buf),
        };
        let _ = evt_tx.send(OrchestratorEvent::CargoDone {
            generation,
            outcome,
            cargo: cargo_started.elapsed(),
        });
    });

    Ok(shared)
}

/// Drain an optional pipe to a `String`, best-effort (a read failure yields
/// whatever was read so far — never a panic, never lost build output on a
/// transient short read).
fn read_all(pipe: Option<impl std::io::Read>) -> String {
    let mut buf = String::new();
    if let Some(mut s) = pipe {
        let _ = s.read_to_string(&mut buf);
    }
    buf
}

/// Relay `cargo`'s stderr live to our own stderr (so the user sees the progress
/// bar and compiler messages as they arrive) and simultaneously accumulate the
/// full text for the failure diagnostic. Uses the same chunk boundary as
/// [`crate::read_progress_chunk`] so carriage-return progress-bar frames flow
/// through without buffering until the next newline.
fn relay_and_capture_stderr(pipe: Option<impl std::io::Read>) -> String {
    use std::io::BufReader;
    let mut captured = String::new();
    let Some(reader) = pipe else { return captured };
    let mut reader = BufReader::new(reader);
    let mut chunk = String::new();
    loop {
        chunk.clear();
        match crate::read_progress_chunk(&mut reader, &mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                // Indented one shared column off the edge (see
                // `screen::indent_relay_chunk`, the same routine `commands.rs`
                // uses for `ipe build`'s identical relay) — `captured` keeps
                // the raw, unindented chunk for the failure diagnostic.
                crate::screen::emit_machine(
                    crate::screen::Stream::Stderr,
                    &crate::screen::indent_relay_chunk(&chunk),
                );
                captured.push_str(&chunk);
            }
        }
    }
    captured
}

/// Parse `cargo build --message-format=json`'s stdout for the produced
/// `executable` artifact path. Mirrors `oracle::build_rust_binary`'s own
/// parsing (that crate stays a dev-dependency only — see `Cargo.toml`'s own
/// note — so this is a small, independent re-implementation rather than a
/// production dependency on a test-utility crate).
fn find_executable_path(cargo_json_stdout: &str) -> Option<PathBuf> {
    for line in cargo_json_stdout.lines() {
        let value: serde_json::Value = serde_json::from_str(line).ok()?;
        if value.get("reason").and_then(serde_json::Value::as_str) == Some("compiler-artifact")
            && let Some(exe) = value.get("executable").and_then(serde_json::Value::as_str)
        {
            return Some(PathBuf::from(exe));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        AppearanceRoute, BuildAccel, Command, Duration, OrchestratorEvent, RESOLVE_RETRY_DELAY,
        RebuildTimings, ResolvedProject, ScopeSpec, WatchRole, appearance_route,
        apply_build_accel_env, child_command, child_env, choose_build_accel, compile_failed_frame,
        dir_has_dep_rlib, emitted_binds_http, emitted_is_tui, emitted_is_web, env_flag_on,
        first_error_line, mint_hot_token, mpsc, prove_green_crate, push_control_appearance,
        resolve_project_sources, schedule_resolve_retry, send_control_frame, spawn_command,
        strip_ansi, watch_line, watch_status_body,
    };
    use std::ffi::OsStr;
    use std::path::{Path, PathBuf};

    /// Build an `EmittedProject` whose `src/main.rs` carries `main_rs`, so the
    /// HTTP-detection predicates can be tested on their real scan surface without
    /// running the emitter.
    fn emitted_with_main(main_rs: &str) -> ipe_backend::EmittedProject {
        let mut files = std::collections::BTreeMap::new();
        let rel = ipe_backend::RelPath::new("src/main.rs").expect("valid rel path");
        files.insert(rel, main_rs.to_owned());
        ipe_backend::EmittedProject {
            files,
            cargo_toml: String::new(),
            uses_webview: false,
        }
    }

    /// Build a MULTI-MODULE `EmittedProject`: `src/main.rs` is only the generic
    /// `ipe_main()` shim (no runtime entry call) and the real entry call lives in
    /// a module file, exactly as the emitter lays out a multi-file project.
    fn emitted_with_module_entry(module_rs: &str) -> ipe_backend::EmittedProject {
        let mut files = std::collections::BTreeMap::new();
        files.insert(
            ipe_backend::RelPath::new("src/main.rs").expect("valid rel path"),
            "fn main() { ipe_main().run_blocking(); }".to_owned(),
        );
        files.insert(
            ipe_backend::RelPath::new("src/ipe_mods/ipe_mod_main.rs").expect("valid rel path"),
            module_rs.to_owned(),
        );
        ipe_backend::EmittedProject {
            files,
            cargo_toml: String::new(),
            uses_webview: false,
        }
    }

    /// A live web app emits `web_app`: it is BOTH a web project and an HTTP binder.
    #[test]
    fn web_app_emit_is_web_and_binds_http() {
        let p = emitted_with_main("fn main() { ipe_runtime::web::web_app(a, b, c, d, e); }");
        assert!(emitted_is_web(&p), "web_app must classify as web");
        assert!(emitted_binds_http(&p), "web_app must be an HTTP binder");
    }

    /// Prove the regression fix: a MULTI-MODULE web app emits its `web_app` entry
    /// into `src/ipe_mods/ipe_mod_main.rs`, not `src/main.rs` (a bare shim). The
    /// shape detectors must scan the whole emitted surface, not just `src/main.rs`
    /// — otherwise every multi-module web app is misclassified as neither-web-nor-
    /// tui, routing its appearance edits to a full rebuild (not `AppearanceHotSwapped`)
    /// and leaving the blue-green proxy disengaged (the client socket dropped on
    /// rebuild).
    #[test]
    fn multi_module_web_entry_is_detected_outside_main_rs() {
        let p = emitted_with_module_entry(
            "pub fn ipe_main() -> _ { ipe_runtime::tea::WebApp(ipe_runtime::web::web_app(a,b,c,d,e)) }",
        );
        assert!(
            emitted_is_web(&p),
            "a web_app entry in a module file must still classify as web"
        );
        assert!(
            emitted_binds_http(&p),
            "a web_app entry in a module file must still engage the blue-green proxy"
        );
        assert_eq!(
            appearance_route(emitted_is_tui(&p), emitted_is_web(&p)),
            AppearanceRoute::WebPost,
            "a multi-module web app must route appearance edits to the hot POST, not a rebuild"
        );
    }

    /// The tui counterpart: a multi-module tui app's `tui_app_ui` entry also lives
    /// in a module file and must still be detected (control-socket route, not rebuild).
    #[test]
    fn multi_module_tui_entry_is_detected_outside_main_rs() {
        let p = emitted_with_module_entry(
            "pub fn ipe_main() -> _ { ipe_runtime::tea::TuiApp(ipe_runtime::tui::tui_app_ui(a,b,c,d)) }",
        );
        assert!(
            emitted_is_tui(&p),
            "a tui entry in a module file must classify as tui"
        );
        assert!(!emitted_is_web(&p), "a tui app is not a web project");
        assert_eq!(
            appearance_route(emitted_is_tui(&p), emitted_is_web(&p)),
            AppearanceRoute::ControlSocket,
            "a multi-module tui app must route over the control socket, not a rebuild"
        );
    }

    /// An `Ipe.Http.Server` emits `server_listen`: an HTTP binder, but NOT web —
    /// so the proxy engages (T2) while readiness uses `TcpConnect`, not readyz (T3).
    /// This holds regardless of program shape: a `Shape::Script main = Server.listen`
    /// emits `server_listen` and is detected by the emitted symbol, not the shape.
    #[test]
    fn server_listen_emit_binds_http_but_is_not_web() {
        let p = emitted_with_main("fn main() { ipe_runtime::server::server_listen(8000i64, rs); }");
        assert!(!emitted_is_web(&p), "a bare server is not a web project");
        assert!(
            emitted_binds_http(&p),
            "server_listen must engage the HTTP proxy"
        );
    }

    /// Prove the refusal: detection matches the FULLY-QUALIFIED emitted call, so
    /// a user-defined `serverListen` function (emitted `server_listen`) or the
    /// bare token in a string literal is NOT mistaken for a first-party HTTP
    /// bind — no spurious proxy engagement (which would revive the 502).
    #[test]
    fn unqualified_server_listen_token_does_not_engage_proxy() {
        let user_fn = emitted_with_main(
            "fn server_listen(x: i64) -> i64 { x } fn main() { let _ = server_listen(1i64); }",
        );
        assert!(
            !emitted_binds_http(&user_fn),
            "a user function named server_listen (no ipe_runtime::server:: path) must NOT engage \
             the proxy"
        );
        let string_literal =
            emitted_with_main("fn main() { let _ = \"server_listen is just text here\"; }");
        assert!(
            !emitted_binds_http(&string_literal),
            "the bare token in a string literal must NOT engage the proxy"
        );
    }

    /// A CLI/TUI/worker or a third-party/non-HTTP server emits neither
    /// entrypoint: no proxy engages and watch takes the direct-restart path.
    #[test]
    fn non_http_emit_binds_no_first_party_listener() {
        let p = emitted_with_main("fn main() { ipe_runtime::cli::run(update, view); }");
        assert!(!emitted_is_web(&p));
        assert!(
            !emitted_binds_http(&p),
            "a non-HTTP program must NOT engage the proxy — no spurious port bind"
        );
    }

    /// A Ipe.Tui app emits `tui_app_ui`: it is a tui child (control-socket
    /// hot-swap) and NOT a web project nor an HTTP binder.
    #[test]
    fn tui_app_emit_is_tui_not_web_or_http() {
        let p = emitted_with_main(
            "fn main() { ipe_runtime::tea::TuiApp(ipe_runtime::tui::tui_app_ui(a,b,c,d)); }",
        );
        assert!(emitted_is_tui(&p), "tui_app_ui must classify as tui");
        assert!(!emitted_is_web(&p), "a tui app is not a web project");
        assert!(!emitted_binds_http(&p), "a tui app binds no HTTP listener");
    }

    /// A cli (`console_app`) app is neither tui nor web, so an appearance-only
    /// edit routes to a full structural REBUILD, never an out-of-band swap: a cli
    /// renders its `LinesView` synchronously on the next fold and has no control
    /// socket or `/_ipe/hot-appearance` endpoint to deliver a patch to.
    #[test]
    fn cli_app_emit_is_neither_tui_nor_web() {
        let p = emitted_with_main(
            "fn main() { ipe_runtime::tea::CliApp(ipe_runtime::console_app(a,b,c,d)); }",
        );
        let (is_tui, is_web) = (emitted_is_tui(&p), emitted_is_web(&p));
        assert!(!is_tui, "a cli app is not a tui app");
        assert!(!is_web, "a cli app is not a web app");
        assert_eq!(
            appearance_route(is_tui, is_web),
            AppearanceRoute::Rebuild,
            "a cli appearance edit must rebuild — no out-of-band apply path exists"
        );
    }

    /// A worker (`worker_app`) app has NO view surface at all, so appearance
    /// hot-swap is genuinely N/A: every edit — appearance-classified or not —
    /// routes to a full structural rebuild.
    #[test]
    fn worker_app_emit_is_neither_tui_nor_web() {
        let p = emitted_with_main(
            "fn main() { ipe_runtime::tea::WorkerApp(ipe_runtime::worker_app(a,b,c)); }",
        );
        let (is_tui, is_web) = (emitted_is_tui(&p), emitted_is_web(&p));
        assert!(!is_tui, "a worker app is not a tui app");
        assert!(!is_web, "a worker app is not a web app");
        assert_eq!(
            appearance_route(is_tui, is_web),
            AppearanceRoute::Rebuild,
            "a worker has no view surface — every edit rebuilds, never hot-swaps"
        );
    }

    /// The full shape→route table, pinned exhaustively: only tui takes the
    /// control socket, only web takes the HTTP POST, and every viewless/
    /// line-oriented shape (the `false, false` case cli and worker both land on)
    /// falls to a rebuild. This is the fail-safe: no shape silently skips an edit.
    #[test]
    fn appearance_route_covers_every_shape() {
        assert_eq!(
            appearance_route(true, false),
            AppearanceRoute::ControlSocket,
            "tui delivers over the loopback control socket"
        );
        assert_eq!(
            appearance_route(false, true),
            AppearanceRoute::WebPost,
            "web delivers over the /_ipe/hot-appearance POST"
        );
        assert_eq!(
            appearance_route(false, false),
            AppearanceRoute::Rebuild,
            "cli/worker/other rebuild — the fail-safe against a silent skip"
        );
    }

    /// Prove the refusal: tui detection matches the FULLY-QUALIFIED emitted call,
    /// so a user function or a string literal carrying the bare token is not
    /// mistaken for the runtime tui entry (no spurious control-socket delivery).
    #[test]
    fn unqualified_tui_token_is_not_a_tui_app() {
        let user_fn =
            emitted_with_main("fn tui_app_ui() {} fn main() { let _ = \"tui_app_ui text\"; }");
        assert!(
            !emitted_is_tui(&user_fn),
            "a user symbol / string literal is not the runtime tui entry"
        );
        let web = emitted_with_main("fn main() { ipe_runtime::web::web_app(a,b,c,d,e); }");
        assert!(!emitted_is_tui(&web), "a web app is not a tui app");
    }

    /// Fail-closed: with NO control port allocated (the child opened no control
    /// socket, or the OS could not lease a loopback port), a tui appearance
    /// delivery reports failure so the caller falls back to a full rebuild —
    /// never a silent "applied". A non-empty patch list makes the miss meaningful.
    #[test]
    fn control_appearance_without_a_port_fails_closed() {
        let patches = vec![crate::hot_classify::ViewPatch {
            defaults: vec!["padding: 12px".to_owned()],
            patch: vec![(0, "padding: 16px".to_owned())],
        }];
        assert!(
            !push_control_appearance(None, "session-secret", &patches, true),
            "no control port must fall back to a full rebuild, never report applied"
        );
    }

    /// An EMPTY patch list is a no-op success even with no port — nothing to
    /// deliver means nothing to rebuild for.
    #[test]
    fn control_appearance_empty_is_a_noop_success() {
        assert!(
            push_control_appearance(None, "session-secret", &[], true),
            "an empty patch list applies nothing and needs no rebuild"
        );
    }

    /// Collect a `Command`'s env overrides as owned strings, resolving the
    /// override VALUE (`None` means "remove from the child env"). Lets a test
    /// assert exactly which vars `apply_dev_incremental_env` set and to what.
    fn env_overrides(cmd: &Command) -> Vec<(String, Option<String>)> {
        cmd.get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect()
    }

    fn override_for<'a>(
        env: &'a [(String, Option<String>)],
        key: &str,
    ) -> Option<&'a Option<String>> {
        env.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// The warm path requests incremental codegen AND clears both rustc wrapper
    /// hooks in the child env, so a machine-level `rustc-wrapper = "sccache"`
    /// (which forces non-incremental) cannot defeat the incremental build. The
    /// clear is an EMPTY override, not a removal — cargo reads the wrapper from
    /// its resolved config, so only an empty value in the child env disables it.
    #[test]
    fn warm_accel_enables_incremental_and_clears_wrapper() {
        let mut cmd = Command::new(OsStr::new("cargo"));
        apply_build_accel_env(&mut cmd, &BuildAccel::WarmIncremental);
        let env = env_overrides(&cmd);
        assert_eq!(
            override_for(&env, "CARGO_INCREMENTAL"),
            Some(&Some("1".to_owned())),
            "the warm path must request incremental codegen"
        );
        assert_eq!(
            override_for(&env, "RUSTC_WRAPPER"),
            Some(&Some(String::new())),
            "the warm path must clear RUSTC_WRAPPER to an empty value (disables sccache)"
        );
        assert_eq!(
            override_for(&env, "RUSTC_WORKSPACE_WRAPPER"),
            Some(&Some(String::new())),
            "the warm path must clear RUSTC_WORKSPACE_WRAPPER too"
        );
    }

    /// The cold path wires the `sccache` wrapper for a fast one-time dependency
    /// compile and turns incremental OFF (the two are mutually exclusive).
    #[test]
    fn cold_accel_wires_sccache_and_disables_incremental() {
        let sccache = PathBuf::from("/usr/bin/sccache");
        let mut cmd = Command::new(OsStr::new("cargo"));
        apply_build_accel_env(&mut cmd, &BuildAccel::ColdSccache(sccache.clone()));
        let env = env_overrides(&cmd);
        assert_eq!(
            override_for(&env, "CARGO_INCREMENTAL"),
            Some(&Some("0".to_owned())),
            "the cold path must disable incremental (sccache cannot cache it)"
        );
        assert_eq!(
            override_for(&env, "RUSTC_WRAPPER"),
            Some(&Some(sccache.to_string_lossy().into_owned())),
            "the cold path must wire the sccache wrapper explicitly"
        );
    }

    /// With the opt-out on, the watch build inherits the machine's normal build
    /// configuration: no incremental request, no wrapper override.
    #[test]
    fn machine_default_accel_leaves_env_untouched() {
        let mut cmd = Command::new(OsStr::new("cargo"));
        apply_build_accel_env(&mut cmd, &BuildAccel::MachineDefault);
        let env = env_overrides(&cmd);
        assert!(
            override_for(&env, "CARGO_INCREMENTAL").is_none(),
            "opt-out must not request incremental"
        );
        assert!(
            override_for(&env, "RUSTC_WRAPPER").is_none(),
            "opt-out must not touch the rustc wrapper"
        );
    }

    /// A present hot token means the watch built the hot-swap emit, so the child
    /// env must carry BOTH the control token and `IPE_WATCH_HOT_APPEARANCE=1` —
    /// the flag the emitted app's runtime reads to activate its overlay, set
    /// explicitly so default-on hot-swap works without the user setting anything.
    #[test]
    fn child_env_activates_hot_appearance_when_token_present() {
        let env = child_env(
            3000,
            Path::new("/tmp/ipe-out"),
            Some("deadbeef"),
            Some(4567),
            false,
            false,
        );
        assert!(
            env.iter()
                .any(|(k, v)| k == "IPE_WATCH_HOT_TOKEN" && v == "deadbeef"),
            "the control token must be handed to the child"
        );
        assert!(
            env.iter()
                .any(|(k, v)| k == "IPE_WATCH_HOT_APPEARANCE" && v == "1"),
            "a hot token present must activate the child's overlay via IPE_WATCH_HOT_APPEARANCE=1"
        );
        assert!(
            env.iter()
                .any(|(k, v)| k == "IPE_CONTROL_PORT" && v == "4567"),
            "an allocated control port must be handed to the child as IPE_CONTROL_PORT"
        );
    }

    /// No hot token (hot-swap off) means no overlay-activating flag reaches the
    /// child — the emitted app stays inert.
    #[test]
    fn child_env_omits_hot_appearance_without_token() {
        let env = child_env(3000, Path::new("/tmp/ipe-out"), None, None, false, false);
        assert!(
            !env.iter().any(|(k, _)| k == "IPE_WATCH_HOT_APPEARANCE"),
            "without a hot token the child must not be told to activate the overlay"
        );
        assert!(
            !env.iter().any(|(k, _)| k == "IPE_WATCH_HOT_TOKEN"),
            "without a hot token no control token is handed to the child"
        );
        assert!(
            !env.iter().any(|(k, _)| k == "IPE_CONTROL_PORT"),
            "without an allocated control port the child opens no control socket"
        );
    }

    /// The opt-out short-circuits to `MachineDefault` regardless of warmth, so a
    /// user who opts out always gets the machine's normal build configuration.
    #[test]
    fn opt_out_chooses_machine_default() {
        let dir = ipe_test_temp::temp_root();
        assert!(
            matches!(
                choose_build_accel(&dir, None, true),
                BuildAccel::MachineDefault
            ),
            "opt-out must choose MachineDefault"
        );
    }

    /// Warmth detection over a resolved target directory: empty reads cold, a
    /// `debug/deps` holding an `.rlib` reads warm. Drives the cold-sccache →
    /// warm-incremental transition across a session. Tests the ambient-env-free
    /// core so it is independent of the `CARGO_TARGET_DIR` the test harness sets.
    #[test]
    fn target_warmth_tracks_dep_rlibs() {
        let target = ipe_test_temp::temp_root().join(format!(
            "ipe_warmth_{}_{}",
            std::process::id(),
            RESOLVE_RETRY_DELAY.as_nanos()
        ));
        let deps = target.join("debug").join("deps");
        // No target yet ⇒ cold.
        assert!(!dir_has_dep_rlib(&target), "a fresh target must read cold");
        std::fs::create_dir_all(&deps).expect("create deps dir");
        // Deps dir exists but holds no rlib ⇒ still cold.
        assert!(
            !dir_has_dep_rlib(&target),
            "an empty deps dir must still read cold"
        );
        std::fs::write(deps.join("libfoo-0000.rlib"), b"x").expect("write rlib");
        // A compiled dependency library is present ⇒ warm.
        assert!(
            dir_has_dep_rlib(&target),
            "a target with a dep rlib must read warm"
        );
        let _ = std::fs::remove_dir_all(&target);
    }

    /// The env flag reader treats an unset variable as off — the safe default
    /// for the incremental opt-out. (Set/`0`/non-empty branches are exercised
    /// without mutating process env, which the workspace lints forbid.)
    #[test]
    fn env_flag_reader_treats_unset_as_off() {
        // A non-`IPE_`-prefixed name no other code sets (so it is reliably
        // unset in the test process, and the env-docs scanner does not treat it
        // as an undocumented `IPE_*` variable).
        assert!(
            !env_flag_on("WATCH_FLAG_READER_DEFINITELY_UNSET_PROBE"),
            "an unset flag must read as off"
        );
    }

    /// The summed phases must equal the total when the total IS the sum plus a
    /// small unaccounted residual — the invariant the `report` residual line
    /// surfaces. Built with fixed durations so it is deterministic (no
    /// wall-clock): the residual a real cycle prints is `total − summed`, and
    /// this pins that `summed()` adds every recorded phase (a dropped phase
    /// would inflate the residual and silently mis-attribute cost).
    #[test]
    fn summed_phases_account_for_the_whole_when_no_residual() {
        let ms = Duration::from_millis;
        let t = RebuildTimings {
            settle: Some(ms(10)),
            resolve: Some(ms(5)),
            compile: Some(ms(20)),
            write: Some(ms(3)),
            cargo: Some(ms(4000)),
            restart: Some(ms(120)),
            ..RebuildTimings::default()
        };
        // A fabricated "observed total" equal to the sum: residual is zero,
        // i.e. the phases account for the whole cycle within tolerance.
        let total = t.summed();
        let residual = total.saturating_sub(t.summed());
        assert_eq!(
            t.summed(),
            ms(10 + 5 + 20 + 3 + 4000 + 120),
            "summed() must add every recorded phase"
        );
        assert!(
            residual <= Duration::from_millis(1),
            "phase sum must equal a total that IS the sum, within 1ms: residual {residual:?}"
        );
    }

    /// A missing phase (e.g. `settle` on the kickoff cycle) is simply omitted
    /// from the sum — never counted as zero-that-inflates, never a panic.
    #[test]
    fn summed_skips_unrecorded_phases() {
        let ms = Duration::from_millis;
        let t = RebuildTimings {
            resolve: Some(ms(5)),
            compile: Some(ms(20)),
            ..RebuildTimings::default()
        };
        assert_eq!(t.summed(), ms(25));
    }

    /// CO-INCR-008: a `resolve_project_sources` failure must not lose the
    /// rebuild cycle silently. `schedule_resolve_retry` is the orchestrator's
    /// ONLY route back into its event loop after such a failure (no
    /// filesystem event is guaranteed to follow), so this pins that a
    /// `FsBatch` retry actually lands on the channel.
    #[test]
    fn schedule_resolve_retry_sends_a_follow_up_fs_batch() {
        let (evt_tx, evt_rx) = mpsc::channel::<OrchestratorEvent>();
        schedule_resolve_retry(&evt_tx);
        let event = evt_rx
            .recv_timeout(RESOLVE_RETRY_DELAY * 4)
            .expect("a retry FsBatch must arrive — the save must not be lost");
        assert!(
            matches!(event, OrchestratorEvent::FsBatch { .. }),
            "the retry must be a FsBatch, not some other orchestrator event"
        );
    }

    /// The retry is delayed, not immediate — an instant re-send would defeat
    /// the point of a "short delay" retry (hammering a still-broken
    /// filesystem state) and would also mask a resolve failure that
    /// self-heals within one debounce window.
    #[test]
    fn schedule_resolve_retry_waits_before_sending() {
        let (evt_tx, evt_rx) = mpsc::channel::<OrchestratorEvent>();
        let started = std::time::Instant::now();
        schedule_resolve_retry(&evt_tx);
        // The retry rides a real `RESOLVE_RETRY_DELAY` `thread::sleep`, which can
        // never wake early — so the send is bounded BELOW by that delay. Assert
        // that lower bound was honoured (measured at arrival) rather than probing
        // a fixed short wall-clock window: under CPU contention the test thread
        // itself can be starved past the delay before it observes the channel,
        // which made the old 10ms-empty probe flake. Load can only make the
        // observed delay longer, never shorter, so this stays deterministic.
        evt_rx
            .recv_timeout(RESOLVE_RETRY_DELAY * 4)
            .expect("the retry must still arrive after the short delay");
        assert!(
            started.elapsed() >= RESOLVE_RETRY_DELAY / 2,
            "the retry must be delayed by ~RESOLVE_RETRY_DELAY, not fire immediately"
        );
    }

    /// A build-failure excerpt laced with carriage returns, ANSI escapes, and a
    /// double-quote must still serialise to JSON the server can parse. The
    /// former hand-rolled escaper left control chars raw, producing invalid
    /// JSON that the endpoint rejected — silently blanking the banner exactly
    /// when a build failed.
    #[test]
    fn watch_status_body_is_valid_json_for_hostile_input() {
        let hostile = "error\r\n\u{1b}[31m\"broke\"out\u{1b}[0m\ttab\u{7}bell";
        let body = watch_status_body(false, hostile);
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("the body must be RFC 8259-valid JSON");
        assert_eq!(parsed.get("ok"), Some(&serde_json::Value::Bool(false)));
        assert_eq!(
            parsed.get("error"),
            Some(&serde_json::Value::String(hostile.to_string())),
            "the error round-trips byte-for-byte, so no field is injected"
        );
    }

    /// A crafted excerpt cannot inject sibling JSON fields: the closing quote,
    /// braces, and a spoofed `"ok":true` all survive as string content.
    #[test]
    fn watch_status_body_resists_field_injection() {
        let attack = r#"","ok":true,"injected":"x"#;
        let body = watch_status_body(false, attack);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed.get("ok"), Some(&serde_json::Value::Bool(false)));
        assert!(
            parsed.get("injected").is_none(),
            "a crafted excerpt must not add fields to the object"
        );
    }

    #[test]
    fn watch_status_body_ok_omits_error() {
        let parsed: serde_json::Value =
            serde_json::from_str(&watch_status_body(true, "")).expect("valid JSON");
        assert_eq!(parsed.get("ok"), Some(&serde_json::Value::Bool(true)));
        assert!(parsed.get("error").is_none());
    }

    /// The parent sender presents its token as a length-delimited record ahead of
    /// the `encode_frame` body, then reads back one reply frame. Stand up a std
    /// loopback listener that reflects the child's accept-loop contract (token
    /// record, then frame record) and replies with an `Ack`; assert the round-trip
    /// yields that `Ack` and that the token bytes arrived verbatim.
    #[test]
    fn send_control_frame_presents_token_then_reads_ack() {
        use ipe_runtime_rust::control::{ControlFrame, decode_frame, encode_frame};
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("bind an ephemeral loopback listener");
        let port = listener.local_addr().expect("local addr").port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept the sender");
            // Read the token record: 4-byte length prefix then the token bytes.
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).expect("read token length");
            let token_len = u32::from_be_bytes(len_buf) as usize;
            let mut token = vec![0u8; token_len];
            stream.read_exact(&mut token).expect("read token body");
            // Drain the frame record (prefix + body) so the sender's write completes.
            stream.read_exact(&mut len_buf).expect("read frame length");
            let frame_len = u32::from_be_bytes(len_buf) as usize;
            let mut frame = vec![0u8; frame_len];
            stream.read_exact(&mut frame).expect("read frame body");
            // Reply with a positive Ack, mirroring the child's ack stub.
            let ack = ControlFrame::Ack {
                ok: true,
                detail: "ack".to_string(),
            };
            let out = encode_frame(&ack).expect("encode the ack");
            stream.write_all(&out).expect("write the ack");
            stream.flush().expect("flush the ack");
            String::from_utf8(token).expect("token is utf8")
        });

        let frame = ControlFrame::Ack {
            ok: true,
            detail: "ping".to_string(),
        };
        let reply = send_control_frame(port, "session-secret", &frame)
            .expect("the sender completes the exchange");
        assert!(
            matches!(reply, ControlFrame::Ack { ok: true, .. }),
            "the sender reads back the child's positive Ack, got {reply:?}"
        );
        let seen_token = server.join().expect("server thread joins");
        assert_eq!(
            seen_token, "session-secret",
            "the token record carried the presented token verbatim"
        );
        // Sanity: the reply bytes decode as the same frame the sender parsed.
        let out = encode_frame(&reply).expect("re-encode the reply");
        let (again, _) = decode_frame(&out).expect("the reply round-trips");
        assert_eq!(again, reply);
    }

    /// ANSI colour and CSI sequences are removed while the surrounding text is
    /// preserved intact.
    #[test]
    fn strip_ansi_removes_escape_sequences() {
        assert_eq!(strip_ansi("\u{1b}[31mred\u{1b}[0m text"), "red text");
        assert_eq!(strip_ansi("no escapes here"), "no escapes here");
        assert_eq!(strip_ansi("\u{1b}[2K\u{1b}[1G   Compiling"), "   Compiling");
    }

    /// The excerpt handed to the banner is the first non-blank line, stripped of
    /// ANSI codes and capped at 120 chars.
    #[test]
    fn first_error_line_strips_ansi_and_picks_first_nonblank() {
        let raw = "\r\n\u{1b}[1m\u{1b}[38;5;9merror[E0308]\u{1b}[0m: mismatched types\nnext line";
        assert_eq!(first_error_line(raw), "error[E0308]: mismatched types");
    }

    /// Prove the refusal: a compiler diagnostic carrying a `.ipe` source snippet
    /// laced with a raw `ESC`, a CSI sequence, and a bare control byte must reach
    /// the watch stderr frame SANITISED — no raw escape survives to move the
    /// cursor, recolour, or hide text — while the visible diagnostic text stays
    /// intact. The frame's only escapes are our own palette codes (empty under a
    /// no-colour palette, which is what the test uses).
    #[test]
    fn compile_failed_frame_sanitizes_untrusted_diagnostic() {
        // A no-colour palette so the ONLY escapes that could appear are ones the
        // untrusted message smuggles in — none may survive.
        let p = crate::style::Palette::select(false);
        let hostile =
            "type error near:\n\u{1b}[31m  x = \u{1b}]0;pwned\u{7}evil\u{1b}[0m\r\n\u{7}bell";
        let frame = compile_failed_frame(hostile, p);
        assert!(
            !frame.contains('\u{1b}'),
            "no raw ESC may reach stderr: {frame:?}"
        );
        assert!(
            !frame.contains('\u{7}'),
            "no raw BEL/control byte may reach stderr: {frame:?}"
        );
        // The human-readable content still comes through.
        assert!(
            frame.contains("type error near:"),
            "diagnostic text preserved"
        );
        assert!(
            frame.contains("evil"),
            "the snippet body survives sanitising"
        );
        assert!(frame.contains("bell"), "text after a control byte survives");
    }

    /// The dev child's `Command` carries the requested env into the running
    /// child when launched through the runtime's hardened spawner: the child
    /// (`/usr/bin/env`) prints its environment and it contains the port.
    #[cfg(unix)]
    #[test]
    fn child_command_env_reaches_the_hardened_child() {
        let env = vec![("IPE_WEB_PORT".to_string(), "4321".to_string())];
        let mut cmd = child_command(Path::new("/usr/bin/env"), &env);
        cmd.stdout(std::process::Stdio::piped());
        let child = ipe_runtime_rust::system::spawn_hardened(cmd)
            .map_err(std::io::Error::from)
            .expect("hardened /usr/bin/env must spawn");
        let out = child.wait_with_output().expect("reap /usr/bin/env");
        assert!(out.status.success(), "/usr/bin/env must exit 0");
        let printed = String::from_utf8_lossy(&out.stdout);
        assert!(
            printed.lines().any(|l| l == "IPE_WEB_PORT=4321"),
            "child env must carry the requested port: {printed}"
        );
    }

    /// `spawn_command` launches the requested binary through the hardened
    /// spawner and hands back a live, reapable `Child`.
    #[cfg(unix)]
    #[test]
    fn spawn_command_launches_through_the_hardened_spawner() {
        let mut child =
            spawn_command(Path::new("/bin/true"), &[]).expect("hardened /bin/true must spawn");
        let status = child.wait().expect("reap /bin/true");
        assert!(status.success(), "hardened /bin/true must exit 0");
    }

    /// The hot-control token is 256 bits of OS-CSPRNG output rendered as 64 hex
    /// chars, and two mints differ — there is no fixed or predictable fallback.
    #[test]
    fn mint_hot_token_is_csprng_hex() {
        let a = mint_hot_token().expect("OS CSPRNG must be available under test");
        let b = mint_hot_token().expect("OS CSPRNG must be available under test");
        assert_eq!(a.len(), 64, "32 random bytes render to 64 hex chars");
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "token must be lowercase hex"
        );
        assert_ne!(a, b, "two mints must not collide");
    }

    /// A fresh scratch directory unique to this test run.
    fn loose_scratch(tag: &str) -> PathBuf {
        let dir = ipe_test_temp::temp_root().join(format!(
            "ipe_loose_watch_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    /// Watch resolves a loose file to its import closure, beside an unreadable directory.
    ///
    /// A rebuild re-resolves from disk, so an import added to the entry pulls
    /// the newly named sibling in, while an unimported sibling stays out.
    #[cfg(unix)]
    #[test]
    fn watch_loose_file_resolves_the_import_closure_and_follows_a_new_import() {
        use std::os::unix::fs::PermissionsExt;
        let dir = loose_scratch("closure");
        let entry = dir.join("Main.ipe");
        std::fs::write(&entry, "module Main exposing (main)\n\nmain = 1\n").expect("write entry");
        std::fs::write(
            dir.join("Helper.ipe"),
            "module Helper exposing (h)\n\nh = 1\n",
        )
        .expect("write helper");
        std::fs::write(
            dir.join("Stray.ipe"),
            "module Stray exposing (s)\n\ns = ???\n",
        )
        .expect("write stray");
        let locked = dir.join("locked");
        std::fs::create_dir_all(&locked).expect("create locked dir");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .expect("chmod 000");

        let before = resolve_project_sources(&entry, None);
        std::fs::write(
            &entry,
            "module Main exposing (main)\n\nimport Helper\n\nmain = Helper.h\n",
        )
        .expect("rewrite entry");
        let after = resolve_project_sources(&entry, None);
        let after_scope = after.as_ref().map(|resolved| resolved.scope.build());
        let canon_dir = std::fs::canonicalize(&dir);
        let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&dir);

        let canon_dir = canon_dir.expect("scratch dir canonicalises");
        let after_scope = after_scope
            .expect("loose file re-resolves")
            .expect("the watch scope builds beside an unreadable directory");
        let watched: Vec<&Path> = after_scope
            .roots_to_watch()
            .iter()
            .map(ipe_watch::WatchedPath::as_path)
            .collect();
        assert_eq!(watched, vec![canon_dir.as_path()], "no directory is walked");
        assert!(matches!(
            after_scope.recursive_mode(),
            notify::RecursiveMode::NonRecursive
        ));
        assert!(after_scope.is_relevant(&canon_dir.join("Helper.ipe")));
        assert!(!after_scope.is_relevant(&canon_dir.join("Stray.ipe")));

        let modules = |resolved: &ResolvedProject| -> Vec<Vec<String>> {
            resolved.sources.keys().cloned().collect()
        };
        let before = before.expect("loose file resolves");
        let after = after.expect("loose file re-resolves");
        assert_eq!(
            after_scope.file_count(),
            after.sources.len(),
            "the watch count is the build's read set"
        );
        assert_eq!(modules(&before), vec![vec!["Main".to_owned()]]);
        assert_eq!(
            modules(&after),
            vec![vec!["Helper".to_owned()], vec!["Main".to_owned()]],
            "the re-resolve picks up the newly imported sibling only"
        );
        assert_eq!(after.entry_path, vec!["Main".to_owned()]);
        assert_eq!(
            after.scope,
            ScopeSpec::LooseFile {
                entry: entry.clone(),
                module_files: vec![PathBuf::from("Helper.ipe")],
                loaded_files: vec![PathBuf::from("Helper.ipe")],
            }
        );
        assert_eq!(after.blame_path, entry);
    }

    /// Write an executable fake `cargo` running `body` into a fresh directory
    /// named after `name`, returning the script path.
    #[cfg(unix)]
    fn fake_cargo(name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = ipe_test_temp::temp_root().join(format!(
            "ipe_watch_fake_cargo_{name}_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create fake cargo dir");
        let path = dir.join("cargo");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write fake cargo");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("make fake cargo executable");
        path
    }

    /// Spawn `cargo` through the watch build path and return the outcome its
    /// waiter reports, after `before_exit` has run against the live child.
    #[cfg(unix)]
    fn cargo_outcome(
        cargo: &Path,
        before_exit: impl FnOnce(&std::sync::Mutex<super::CargoChild>),
    ) -> Option<super::CargoOutcome> {
        let out_dir = cargo.parent().expect("fake cargo has a parent dir");
        let (tx, rx) = mpsc::channel();
        let child =
            super::spawn_cargo_build(cargo, out_dir, Some(&out_dir.join("target")), 1, tx, true)
                .expect("spawn fake cargo");
        before_exit(child.as_ref());
        let event = rx.recv_timeout(Duration::from_secs(30));
        let _ = std::fs::remove_dir_all(out_dir);
        match event {
            Ok(OrchestratorEvent::CargoDone { outcome, .. }) => Some(outcome),
            _ => None,
        }
    }

    /// A build that dies by a signal nobody in the orchestrator sent (a crash,
    /// an out-of-memory kill) is a real failure, never a silent supersede.
    #[cfg(unix)]
    #[test]
    fn unrequested_signal_death_is_a_failure() {
        let cargo = fake_cargo("signal", "kill -9 $$");
        let outcome = cargo_outcome(&cargo, |_| {});
        assert!(
            matches!(outcome, Some(super::CargoOutcome::Red(_))),
            "a signal death the orchestrator did not request must report Red"
        );
    }

    /// A build the orchestrator supersedes reports `Killed`, so the stale
    /// cycle is dropped rather than shown as a failure.
    #[cfg(unix)]
    #[test]
    fn superseded_build_reports_killed() {
        let cargo = fake_cargo("supersede", "exec sleep 30");
        let outcome = cargo_outcome(&cargo, |child| {
            child.lock().expect("cargo child lock").supersede();
        });
        assert!(
            matches!(outcome, Some(super::CargoOutcome::Killed)),
            "a superseded build must report Killed"
        );
    }

    /// `watch_line` must render every role at a fixed 4-space indent (two
    /// `GUTTER` widths) regardless of colour state. Before this fix, `Info`
    /// and `Success` placed the colour escape BEFORE the literal gutter text,
    /// which defeated `screen::guttered_once`'s `starts_with(GUTTER)` check
    /// and caused it to add a second gutter on top — 4 spaces with colour on,
    /// only 2 with colour off. Stripping ANSI here isolates the indent from
    /// that downstream (and separately-tested) double-gutter guard.
    #[test]
    fn watch_line_indent_is_four_spaces_regardless_of_role_or_colour() {
        let text = crate::style::TerminalSafe::sanitize("app started");
        for role in [WatchRole::Info, WatchRole::Success, WatchRole::Failure] {
            let rendered = strip_ansi(&watch_line(&text, role));
            assert!(
                rendered.starts_with("    "),
                "watch_line must start with a 4-space gutter for every role; got {rendered:?}"
            );
            assert!(
                !rendered.starts_with("     "),
                "watch_line must not double-gutter past 4 spaces; got {rendered:?}"
            );
        }
    }

    /// Whether `refused` is a replaced-crate refusal.
    fn refused_as_replaced(refused: &Result<crate::output_dir::OwnedDir, crate::CliError>) -> bool {
        refused.as_ref().is_err_and(|r| {
            matches!(
                r,
                crate::CliError::OutputRefused(crate::output_dir::OutputRefusal::Replaced(_))
            )
        })
    }

    /// A green build with no claimed crate on record fails, its binary unstarted.
    #[test]
    fn a_green_build_without_a_claimed_crate_is_refused() {
        let refused = prove_green_crate(None, Path::new("/tmp/ipe-out"));
        assert!(refused_as_replaced(&refused), "got {refused:?}");
    }

    /// A crate swapped while cargo built it fails the build, its binary unstarted.
    #[test]
    fn a_green_build_whose_crate_was_replaced_is_refused() {
        let base =
            ipe_test_temp::temp_root().join(format!("ipe-watch-green-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("scratch base");
        let crate_path = base.join("crate");
        let claimed = crate::output_dir::OwnedDir::claim(&crate_path).expect("claim crate");
        std::fs::rename(&crate_path, base.join("aside")).expect("move crate aside");
        std::fs::create_dir(&crate_path).expect("replacement at the same path");
        let refused = prove_green_crate(Some(claimed), &crate_path);
        assert!(refused_as_replaced(&refused), "got {refused:?}");

        let fresh = base.join("fresh");
        let held = crate::output_dir::OwnedDir::claim(&fresh).expect("claim fresh crate");
        let proven = prove_green_crate(Some(held), &fresh);
        assert!(
            proven.as_ref().is_ok_and(|dir| dir.path() == fresh),
            "an untouched crate is handed back to run, got {proven:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
