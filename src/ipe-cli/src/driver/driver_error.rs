use super::{nearest_command, nearest_group_member};
use crate::style::TerminalSafe;
use crate::{
    Diagnostic, Path, PathBuf, Write, api_surface, audit, build_plan, contained_path, delivery,
    help, io_bounded, machine_output, output_dir, publish, remote_ingest, render, render_json,
    style, text, toolchain,
};

/// The runtime crate an emitted project linked against: its root and declared
/// version.
///
/// Carried into [`CliError::EmittedBuildFailed`] so a `cargo` failure that names
/// a missing runtime feature can point at the exact stale crate. Both parts come
/// from outside ipe (an `IPE_RUNTIME_DIR` path, a `Cargo.toml` field), so they
/// are held as [`TerminalSafe`] text: the self-rendering error cannot
/// interpolate them raw.
#[derive(Debug, Clone)]
pub struct RuntimeContext {
    /// The resolved runtime crate root, as display text.
    pub root: TerminalSafe,
    /// The version that crate declares.
    pub version: TerminalSafe,
}

/// The payload of [`CliError::AdvisoryVulnerable`], boxed to keep `CliError`
/// within its 128-byte size ceiling while still carrying the full diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvisoryVulnerablePayload {
    /// The affected dependency name.
    pub package: String,
    /// The exact locked version that matched.
    pub version: String,
    /// The advisory identifier (e.g. `IPE-2024-0001`).
    pub id: String,
    /// The severity string (`"high"` or `"critical"`).
    pub severity: &'static str,
    /// The advisory's short description.
    pub description: String,
    /// The first fixed version, if recorded.
    pub fixed_in: Option<String>,
}

/// A driver-level error. Distinct from a compiler [`Diagnostic`]: it also covers
/// filesystem failures and command-line misuse, neither of which is a property
/// of the Ipê program being compiled.
#[derive(Debug)]
pub enum CliError {
    /// Command-line or manifest misuse; carries the catalog message saying what
    /// was wrong and how to fix it.
    Usage(text::Message),
    /// No command, or an unrecognised one: the top-level help is shown and the
    /// process exits non-zero. Distinct from [`Self::Usage`] because it renders
    /// the full sectioned screen (coloured for a terminal) rather than a hint.
    ///
    /// `attempted` is the token the user typed (empty when no command was
    /// given); a near-miss to a known command is offered as a `maybe` hint.
    UnknownCommand { attempted: TerminalSafe },
    /// A filesystem operation failed at `path`.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A private scratch directory could not be created under the OS temp
    /// root. The root itself is never named: only the scratch primitive holds
    /// it, and it may carry bytes unsafe for a terminal.
    ScratchUnavailable { source: std::io::Error },
    /// The compiler rejected the program. Carries the entry path and full
    /// source text alongside the diagnostic so [`fmt::Display`] can render a
    /// rustc/Elm-style report (caret snippet + help + `ipe explain` pointer)
    /// rather than a debug dump.
    ///
    /// `diag` is boxed: a bare [`Diagnostic`] is the widest field of the
    /// widest variant, and every one of the ~200 functions returning
    /// `Result<_, CliError>` pays the enum's size in its `Err` slot. Boxing
    /// this one field keeps `CliError` small — the compile-failure path (the
    /// exceptional one) is the only place that pays for the diagnostic — while
    /// leaving the `file`/`src` field names intact so existing pattern matches
    /// on this variant are unaffected.
    Pipeline {
        file: PathBuf,
        src: String,
        diag: Box<Diagnostic>,
    },
    /// The Ipê runtime module tree could not be located.
    RuntimeNotFound,
    /// `$IPE_RUNTIME_DIR` was set but does not name a runtime crate root (a
    /// directory whose `Cargo.toml` declares the `ipe-runtime-rust` package).
    /// The override is a trust decision — an unverified directory is a hard,
    /// typed refusal, never a silent fall-through to a different runtime.
    RuntimeDirInvalid {
        /// The path the override named.
        path: PathBuf,
        /// The named path is the inner runtime module directory
        /// (`…/src/ipe_runtime` or `…/rust/src`) rather than the crate root — a
        /// common misconfiguration worth calling out explicitly.
        points_at_inner: bool,
    },
    /// No directory could be resolved to materialize the embedded runtime into
    /// (no `IPE_HOME`, `XDG_DATA_HOME`, or `HOME`). Without a home there is
    /// nowhere to write the runtime the emitted project links against.
    RuntimeHomeUnknown,
    /// No per-user cache directory could be resolved: neither `XDG_CACHE_HOME`
    /// nor the home (`HOME`, or `USERPROFILE` on Windows) names an absolute path. Refused rather than falling back to a
    /// directory relative to the current working directory.
    CacheHomeUnknown,
    /// An explicit directory override (`IPE_INDEX_DIR`, `IPE_HOME`) is set but is
    /// not an absolute path. Refused rather than resolved against the current
    /// working directory or silently replaced by the default location.
    EnvDirNotAbsolute {
        /// The environment variable carrying the refused value.
        var: &'static str,
    },
    /// Writing the embedded runtime source to `<IPE_HOME>/runtime/<version>/rust`
    /// failed (disk full, permission denied, or a drifted embed). This is a
    /// fail-closed refusal — the build stops rather than link a wrong or empty
    /// runtime. Carries a specific detail.
    RuntimeMaterializeFailed {
        /// What specifically failed.
        detail: String,
    },
    /// The resolved runtime crate declares a version different from the
    /// compiler's own. The emitted project pins features and shapes against the
    /// compiler's runtime; a crate at a different version lacks those, so linking
    /// it fails deep inside `cargo` with an opaque feature error. This is a hard,
    /// typed refusal at resolution time — a stale `out/`, a walked-up old crate
    /// root, or a mismatched `IPE_RUNTIME_DIR` is caught before emit, never
    /// linked. Carries the resolved root, the version found there, and the
    /// compiler's expected version.
    RuntimeVersionMismatch {
        /// The resolved runtime crate root whose version disagrees.
        path: PathBuf,
        /// The version that crate's `Cargo.toml` declares.
        found: String,
        /// The compiler's own version, which the runtime must equal.
        expected: String,
    },
    /// Building the emitted Rust project failed — `cargo` exited non-zero while
    /// compiling the program this compiler emitted. This is neither a
    /// command-line misuse (so it never shows the command's `--help` page) nor a
    /// fault in the user's Ipê source (the compile already succeeded). Carries
    /// `cargo`'s exit code and its captured stderr so `Display` can surface a
    /// targeted cause (a runtime-feature gap) or the trimmed `cargo` error under
    /// a clean header.
    EmittedBuildFailed {
        /// What the build step compiled (e.g. `the emitted program`).
        what: &'static str,
        /// `cargo`'s exit code.
        code: i32,
        /// `cargo`'s captured stderr, presented after trimming.
        stderr: TerminalSafe,
        /// The runtime crate root the emitted project linked against, when the
        /// caller resolved one — named in a runtime-feature-gap message.
        runtime: Option<RuntimeContext>,
    },
    /// `ipe explain <CODE>` was given a string that is not a taxonomy code.
    /// Carries the (trimmed) input and a deterministic did-you-mean list over
    /// the known codes, ranked by `(Levenshtein, code)`.
    UnknownCode {
        input: String,
        suggestions: Vec<&'static str>,
    },
    /// `ipe doc <query>` named no documentation entry.
    ///
    /// Carries the query and the closest entries of any kind (ranked, bounded, never empty while
    /// any documentation exists), so a miss always points somewhere.
    DocNotFound {
        query: String,
        suggestions: Vec<crate::doc_bundle::DocSuggestion>,
    },
    /// A static-build request was refused (typed reason — see
    /// [`build_plan::Refusal`]). Refusal means NO artifact: the build asked
    /// to be static is never silently degraded to a dynamic one.
    StaticRefusal(build_plan::Refusal),
    /// A declared capability set did not equal the set inferred from the
    /// program. Carries the capabilities the program uses but did not declare
    /// (`missing`) and the ones declared but never used (`extra`), each a stable
    /// sorted list of wire names. Consumed by SP2/SP4 to reject a drifted
    /// manifest.
    CapabilityMismatch {
        missing: Vec<&'static str>,
        extra: Vec<&'static str>,
    },
    /// Package resolution failed for a non-security reason: an index entry could
    /// not be found or parsed, no published version satisfied the requirement, or
    /// a `git` fetch of the source failed. Carries a message naming the package.
    Resolve(text::Message),
    /// `ipe.lock` cannot record or admit a dependency: a missing field, an
    /// unrecognised `kind`, an impossible `source`/`rev`/`kind` pairing, or a
    /// path dependency that cannot be written into the lockfile. Boxed to keep
    /// `CliError` within its size ceiling.
    LockRefused(Box<crate::lockfile::LockRefusal>),
    /// A fetched package's content hash did not equal the hash the index pinned.
    /// This is the verify-before-trust boundary: a mismatch is always a hard,
    /// typed error — never a warning — because the source that was fetched is not
    /// the source the publisher registered. Carries the package name, the
    /// expected hash, and the hash actually computed over the fetched tree.
    HashMismatch {
        package: String,
        expected: String,
        actual: String,
    },
    /// `ipe diff` could not compute the public-API delta — a tree could not be
    /// read, did not typecheck, or exposed an open interface. Carries the typed
    /// [`api_surface::DiffError`] cause.
    Diff(api_surface::DiffError),
    /// The verify mode found the proposed new version does not clear the
    /// required semver floor. Carries the required floor version and the
    /// human-readable required bump so the message is actionable.
    SemverRejected {
        required: String,
        floor: String,
        proposed: String,
    },
    /// A `ipe package audit` Tier-1 check rejected the package. Carries the
    /// typed [`audit::Rejection`] naming the failing check and its one
    /// diagnostic. This is the package gate's hard reject — a check that would
    /// let an unsafe or dishonest version through is a security hole, so it is
    /// always a typed error, never a warning.
    PackageAudit(audit::Rejection),
    /// `ipe package publish` declined to proceed. Carries the typed
    /// [`publish::Refusal`] naming the precondition that failed (a dirty working
    /// tree, an unpushed HEAD, or an already-published version).
    /// A publish precondition is a hard, typed refusal — never a warning — because
    /// a merged index entry must pin an immutable, reproducible revision.
    Publish(publish::Refusal),
    /// A package version cannot enter the index — malformed, carrying build
    /// metadata, or not above every version already published. Raised at
    /// publish, at admission, and when an index entry is read, so no ambiguous
    /// or regressing version reaches resolution or the enforced-semver check.
    /// The refusal is boxed to keep `CliError` within its size ceiling.
    VersionRefused {
        package: String,
        refusal: Box<crate::published_version::VersionRefusal>,
    },
    /// `ipe doc check` found one or more exposed bindings without a doc-comment.
    /// Carries the ready-to-print coverage report. This is a legitimate gate
    /// result — the check ran correctly and the package is under-documented — not
    /// a command misuse, so it exits non-zero with the report alone and never the
    /// command's `--help` page.
    DocCoverage(TerminalSafe),
    /// `ipe doc --check-examples` found one or more broken doc-string examples.
    /// Carries the ready-to-print failure report. A legitimate gate result — the
    /// extraction ran correctly and an example does not compile or produce the
    /// expected result — not a command misuse, so it exits non-zero with the
    /// report alone and never the command's `--help` page.
    DocExamplesFailed(TerminalSafe),
    /// A known command was misused (bad or missing arguments, an unknown flag).
    /// Carries the specific reason and the command name; [`fmt::Display`] renders
    /// the reason followed by that command's full, indented `--help` page — the
    /// uniform "misuse shows help" output every command shares, printed to stderr
    /// by [`crate::run_cli`]'s caller. The command name is always a known command
    /// (the dispatcher wraps a raw [`Self::Usage`] into
    /// this only for a command it recognised).
    CommandUsage {
        /// The command whose help page to show (a known command or grouped verb).
        command: crate::verb::CommandName,
        /// The specific reason for the misuse (e.g. an unknown flag).
        reason: TerminalSafe,
    },
    /// A command group (e.g. `dev`) was followed by a token that is not one of
    /// its verbs. [`fmt::Display`] renders an "unknown verb" line — with a
    /// near-miss suggestion drawn from the group's own members — then that
    /// group's subpage. Progressive help: the group teaches its verbs at the
    /// point the user reached for one. `group` is always a known group name.
    UnknownGroupSub {
        /// The group whose subpage to show (a known group name, e.g. `dev`).
        group: &'static str,
        /// The token the user typed after the group name.
        attempted: TerminalSafe,
    },
    /// A verb name typed without the umbrella group it lives under (`ipe
    /// build`), or a group typed with no member verb (`ipe release`).
    ///
    /// The legacy names have no handler: this refusal is their one
    /// representation. [`fmt::Display`] names what was typed, then one hint
    /// per grouped form.
    GroupRequired {
        /// What the user typed: the legacy verb or the bare group word.
        attempted: TerminalSafe,
        /// The grouped forms the hint offers; empty for a group with no page.
        forms: &'static [crate::verb::Verb],
        /// The arguments that followed `attempted`, carried onto each hinted
        /// form; empty when there were none.
        tail: TerminalSafe,
    },
    /// `ipe release run` was given a target whose artifact has no run form.
    ///
    /// [`fmt::Display`] names the target, then hints the `ipe release build`
    /// form that produces its artifact.
    NoRunForm {
        /// The target with no run form.
        target: crate::cli_args::NoRunTarget,
    },
    /// A native-bearing release refused the `ipe_wrapper` source it builds.
    ///
    /// Nothing was built: the wrapper builds only from the verified compiler
    /// workspace this binary was compiled from.
    WrapperSourceRefused(Box<crate::wrapper_source::WrapperSourceRefusal>),
    /// A stage of `ipe verify` failed. Carries the stage name and the stage's
    /// own already-rendered report. Like [`Self::DocCoverage`], this is a
    /// legitimate gate result — the `verify` invocation was valid and the
    /// underlying check ran correctly — so it exits non-zero with the report
    /// alone and never the `verify` command's `--help` page.
    VerifyFailed {
        /// The failing stage (e.g. `format`).
        stage: &'static str,
        /// The stage's rendered failure report, printed as-is.
        report: TerminalSafe,
    },
    /// The project's test runner exited non-zero — one or more `Ipe.Test` cases
    /// failed. The test binary has already printed the per-case failures and the
    /// `N passed, M failed` summary to stdout, so this carries only the exit
    /// code and renders a short trailing line; it is a legitimate gate result
    /// (`ipe test` / `verify`'s test stage ran correctly), never a command-line
    /// misuse, so it exits non-zero with no `--help` page.
    TestFailed {
        /// The test binary's exit code (1 from `Ipe.Test.runMain` on a failing
        /// case, or another non-zero code from a crash).
        code: i32,
    },
    /// `ipe upgrade` could not find a prebuilt binary for the requested version
    /// and platform. This is a transient operational failure — the release was
    /// tagged but the CI build artifacts are still being generated — NOT a
    /// command-line misuse. Exits non-zero with the friendly message alone and
    /// never the `upgrade` command's `--help` page.
    UpgradeNoPrebuilt {
        /// The release version tag (e.g. `v0.1.24`).
        version: TerminalSafe,
        /// The platform–architecture pair (e.g. `linux-x64`).
        platform: TerminalSafe,
    },
    /// A command needed the Rust toolchain (`cargo`/`rustc`) to build, run, or
    /// test a program, but `cargo` was not found. This is an environment
    /// failure, not a command-line misuse — the invocation was valid; the host
    /// is missing a prerequisite — so it exits non-zero with the friendly,
    /// root-cause message alone and never the command's `--help` page. Carries
    /// the typed [`toolchain::ToolchainMissing`] naming what the command was
    /// doing and whether the toolchain is uninstalled or merely off the `PATH`.
    ToolchainMissing(toolchain::ToolchainMissing),
    /// `ipe health` found a critical prerequisite missing (no `rustc`/`cargo`,
    /// or an unresolvable runtime). This is a legitimate diagnostic verdict —
    /// the command ran correctly and reported the environment fully to stdout —
    /// not a command-line misuse, so it exits non-zero after the report and
    /// never shows the `health` command's `--help` page. Carries nothing: the
    /// report is the message; this variant is only the exit-code signal.
    HealthCritical,
    /// `ipe lint` found one or more findings at or above the configured gate
    /// severity. This is a legitimate gate verdict — the linter ran correctly and
    /// already printed every finding to stdout — not a command-line misuse, so it
    /// exits non-zero after the report and never shows the `lint` command's
    /// `--help` page. Carries nothing: the printed findings are the message.
    LintGateFailed,
    /// `ipe release eject` was asked to eject a program it cannot make self-contained.
    /// Eject vendors ONLY the embedded runtime source; a program that binds a
    /// foreign Rust crate (FFI) would need those external crates pulled from a
    /// registry, which the self-contained, source-only eject contract forbids.
    /// This is a hard, typed refusal — never a partial eject that would emit a
    /// tree `cargo build` could not resolve offline. Carries the reason.
    EjectUnsupported {
        /// The specific reason the program cannot be ejected.
        reason: TerminalSafe,
    },
    /// A `Pipeline` diagnostic was already rendered as JSON and written to
    /// stderr by the caller. The process must exit non-zero, but there is
    /// nothing left to print — the JSON line is the complete machine output.
    DiagnosticJsonEmitted,
    /// A file exceeded the per-surface read ceiling in
    /// [`io_bounded::read_to_string_capped`]. The read was stopped at the cap;
    /// no unbounded allocation was made.
    FileTooLarge {
        /// The path of the oversized file.
        path: PathBuf,
        /// The ceiling (bytes) that was enforced.
        max: u64,
    },
    /// `ipe fmt` refused a file whose formatted output would pass its cap.
    ///
    /// The file is left unchanged.
    FmtOutputTooLarge {
        /// The file whose output passed the cap.
        file: PathBuf,
        /// The output ceiling that was enforced.
        cap: ipe_fmt::OutputCap,
    },
    /// A remote transfer crossed its declared ingest budget and was stopped.
    ///
    /// Nothing it staged reached the lock, the manifest or the package cache.
    RemoteIngestExceeded(remote_ingest::IngestRefusal),
    /// Local work (a source-tree walk, a `git` query) crossed its ceiling and was stopped.
    LocalLimitExceeded(remote_ingest::LocalRefusal),
    /// A finished child's output pipe stayed open past the grace.
    ///
    /// A process the child started still held it; that process was stopped.
    ChildPipeHeld(remote_ingest::Stream),
    /// The OS refused a thread the command needs.
    ///
    /// Anything the command had started for that thread was stopped first.
    ThreadRefused {
        role: crate::threads::ThreadRole,
        source: std::io::Error,
    },
    /// Reading a child's output pipe failed, so its output was not used.
    ChildPipeUnread(remote_ingest::Stream, std::io::ErrorKind),
    /// A signal ended a remote transfer before it finished.
    ///
    /// Nothing it staged reached the lock, the manifest or the package cache.
    Interrupted,
    /// A source path was refused before any of it was read.
    ///
    /// It named a non-regular file (a FIFO, device or socket, which could
    /// block the read or never end) or a file or directory the process may
    /// not open. Raised by [`io_bounded::open_regular`] and the no-follow
    /// module walks built on it.
    SourceRefused {
        /// The refused path, as the caller spelled it.
        path: PathBuf,
        /// Why the path was refused.
        reason: io_bounded::SourceRefusal,
    },
    /// A manifest `sourceRoot` (or equivalent dependency path) was rejected by
    /// [`contained_path::ContainedRelPath::parse`] because it escapes the
    /// project directory. Carries the specific [`contained_path::PathEscape`]
    /// reason so the diagnostic names exactly why the path was refused.
    PathEscape {
        /// The raw path string as it appeared in the manifest.
        raw: String,
        /// Why the path was rejected.
        reason: contained_path::PathEscape,
    },
    /// A build-output location was refused because ipe cannot prove it owns it.
    ///
    /// A symlink, a directory holding user files, or a path overlapping the
    /// project's sources. Nothing was written, cleaned, or overwritten.
    OutputRefused(output_dir::OutputRefusal),
    /// The module-discovery walk hit its depth ceiling or detected a symlink
    /// cycle. Carries the maximum depth that was configured and, for a cycle,
    /// the directory path where the cycle was detected.
    DiscoveryLimitReached {
        /// The depth ceiling that was enforced (`MAX_DISCOVERY_DEPTH`), or the
        /// path at which a symlink cycle was detected.
        detail: String,
    },
    /// A discovered manifest or FFI cache failed its trust check and was not used.
    ///
    /// Either one steers or compiles into the build unsandboxed, so one some
    /// other user could have written is refused rather than obeyed.
    TrustRefused(crate::owner_trust::TrustRefusal),
    /// FFI preparation refused the installed catalog or a project's use of it.
    ///
    /// The cause is a variant of [`crate::ffi::FfiPrepError`], never message
    /// text, so a consumer decides how to handle it from its type. It is not
    /// command misuse, so no help page is attached to it.
    FfiPrep(Box<crate::ffi::FfiPrepError>),
    /// A discovered source file's module path uses a Windows reserved device name.
    ///
    /// `Aux.ipe` opens the `AUX` device on Windows, so the same tree would
    /// map to a different module set per platform; it is refused, never
    /// silently skipped.
    DeviceNamedModule {
        /// The refused source file.
        path: PathBuf,
        /// The device-named segment (`Aux`, `Con`, `Com1`, ...).
        segment: String,
    },
    /// `ipe upgrade` (or `ipe health`) could not reach the release feed. This
    /// is a transient, non-zero operational result — not a command misuse — so
    /// it exits with no `--help` page and renders its own message. Carries
    /// nothing: the human or machine output was already printed; this is only
    /// the exit-code signal.
    UpgradeFeedUnreachable,
    /// `ipe upgrade --check --exit-code` resolved the action and must exit
    /// with a numeric code that is neither SUCCESS nor FAILURE (e.g. 10 for
    /// "upgrade available"). Carries the code so `main` can return it as an
    /// `ExitCode` after printing nothing (the status line was already printed
    /// by `run_upgrade`).
    UpgradeCheckExit {
        /// The process exit code (10 = available, 0 = up to date,
        /// 2 = unreachable).
        code: i32,
    },
    /// A locked dependency's version falls within an advisory's affected range
    /// at `high` or `critical` severity.  This is a hard, typed rejection —
    /// never a warning — because the dep is known-vulnerable and the gate
    /// cannot certify the package safe (PRINCIPLES §1 Security, fail-closed).
    ///
    /// The payload is boxed because five `String` fields would exceed the
    /// 128-byte `CliError` size ceiling; the rejection path is exceptional, so
    /// the extra indirection costs nothing on the common path.
    AdvisoryVulnerable(Box<AdvisoryVulnerablePayload>),
    /// An advisory DB file could not be read (I/O error, directory
    /// inaccessible).  Fail-closed: absent proof the dep is safe, refuse.
    AdvisoryDbUnreachable {
        /// What went wrong.
        detail: String,
    },
    /// An advisory DB file was present but malformed (TOML parse error, a
    /// missing required field, or an invalid value).  Fail-closed: a corrupt
    /// advisory cannot be treated as "no advisory".
    AdvisoryDbMalformed {
        /// The path of the malformed advisory file.
        path: std::path::PathBuf,
        /// What was wrong with the file.
        detail: String,
    },
    /// `ipe dev run --target wasi` was invoked on an `ipe` binary built WITHOUT the
    /// `wasi_run` feature, so no embedded wasmtime engine is linked to execute
    /// the emitted `wasm32-wasip1` module. A typed refusal naming the feature —
    /// never a panic, never a silent fall-through to a native run — so the
    /// missing-engine case is fail-closed and self-explaining.
    WasiRunFeatureDisabled,
    /// The embedded wasmtime engine could not load, instantiate, or run the
    /// emitted `wasm32-wasip1` module (a compile/link error in the engine, a
    /// missing WASI export, or a guest trap that is not a clean exit). A WASI
    /// trap maps here to a typed non-zero exit, never a host panic. Carries a
    /// short detail describing what failed.
    WasiRunFailed {
        /// What specifically failed in the embedded run.
        detail: TerminalSafe,
    },
    /// The emitted `wasm32-wasip1` module ran to completion under embedded
    /// wasmtime and returned a non-zero WASI exit code. Propagated as `ipe
    /// dev run`'s own non-zero exit, mirroring how the native run surfaces a child's
    /// non-zero status — the guest's own outcome, not a driver fault.
    WasiRunExited {
        /// The module's WASI exit code (non-zero).
        code: i32,
    },
}

impl From<toolchain::ToolchainMissing> for CliError {
    fn from(missing: toolchain::ToolchainMissing) -> Self {
        Self::ToolchainMissing(missing)
    }
}

impl From<api_surface::DiffError> for CliError {
    fn from(err: api_surface::DiffError) -> Self {
        match err {
            api_surface::DiffError::Source(refusal) => *refusal,
            other => Self::Diff(other),
        }
    }
}

impl From<build_plan::Refusal> for CliError {
    fn from(refusal: build_plan::Refusal) -> Self {
        Self::StaticRefusal(refusal)
    }
}

impl From<ipe_docs::argv::NonUtf8Argument> for CliError {
    /// A command-line argument that is not UTF-8 is command-line misuse; the
    /// refusal names its position, never its bytes.
    fn from(refused: ipe_docs::argv::NonUtf8Argument) -> Self {
        Self::Usage(text::Message::relay(&refused))
    }
}

impl From<delivery::DeliveryError> for CliError {
    /// A delivery refusal is a pedagogical, user-facing message; it surfaces
    /// through the reader's named-error channel.
    fn from(err: delivery::DeliveryError) -> Self {
        Self::Usage(text::Message::relay(&err))
    }
}

/// Emit an error for `command` on a machine (`--json` / `--plain`) stream, then
/// return [`CliError::DiagnosticJsonEmitted`] so the caller exits non-zero with
/// nothing more printed.
///
/// This is the single machine-error routing point for the machine-mode command
/// bodies (`type-check`, `build`, `run`). It closes the disclosure class every
/// one of them shared: under a machine format NO error may fall through to the
/// human [`crate::screen::report_error`] on the top-level path — a framed
/// banner in a `--json` or `--plain` stream is exactly the leak this unification
/// prevents.
///
/// * A `Pipeline` compile diagnostic under `--json` keeps its established rich
///   schema ([`render_json`]) — `code`, `severity`, spans, hints — a shape
///   downstream consumers already parse.
/// * Every other case renders through the shared
///   [`machine_output::machine_error`]: the `--json` error envelope, or the
///   `--plain` flush-left reason. Either way the message is the error's curated
///   `Display` text, ANSI/control-stripped — never a raw internal string and
///   never the human banner.
///
/// The rendering is written to stderr (a machine failure keeps stdout clean) as
/// best-effort — if stderr is closed the process still exits non-zero via the
/// sentinel.
pub fn emit_machine_error(
    format: crate::cli_args::OutputFormat,
    command: &str,
    err: &CliError,
) -> CliError {
    use crate::cli_args::OutputFormat;
    let rendered = match err {
        CliError::Pipeline { file, src, diag } if format == OutputFormat::Json => {
            render_json(diag, &file.to_string_lossy(), src)
        }
        _ => machine_output::machine_error(format, command, err.machine_kind(), &err.to_string()),
    };
    // Best-effort write; if stderr is closed we still exit non-zero.
    let _ = std::io::stderr().write_all(rendered.as_bytes());
    CliError::DiagnosticJsonEmitted
}

impl CliError {
    /// A consent gate's refusal, framed by the shared diagnostic renderer.
    ///
    /// The refusal has no source location, so the entry path and source are empty.
    #[must_use]
    pub fn consent_refused(msg: ipe_diagnostics::ConsentError) -> Self {
        Self::Pipeline {
            file: PathBuf::new(),
            src: String::new(),
            diag: Box::new(Diagnostic::Consent { msg }),
        }
    }

    /// The manifest refusal for a program entry that [`parse_entry`] turned away.
    ///
    /// The entry and the refused segment are author text, so both render through
    /// `{:?}` (escaped) and a control byte cannot reach the terminal raw.
    ///
    /// [`parse_entry`]: crate::project::parse_entry
    #[must_use]
    pub fn manifest_entry_refused(entry: &str, refusal: &crate::project::EntryRefusal) -> Self {
        use crate::project::EntryRefusal;
        let entry = format!("{entry:?}");
        Self::Usage(match refusal {
            EntryRefusal::Empty => text::msg::manifest_entry_no_module(&entry),
            EntryRefusal::NotModuleSegment { segment } => {
                text::msg::manifest_entry_segment_invalid(&entry, &format!("{segment:?}"))
            }
            EntryRefusal::EmptySegment => text::msg::manifest_entry_empty_segment(&entry),
            EntryRefusal::DotSegment => text::msg::manifest_entry_dot_segment(&entry),
            EntryRefusal::Backslash => text::msg::manifest_entry_backslash(&entry),
            EntryRefusal::DrivePrefix => text::msg::manifest_entry_drive_prefix(&entry),
            EntryRefusal::Extension => text::msg::manifest_entry_extension(&entry),
        })
    }

    /// The stable machine `kind` tag for this error — the fixed vocabulary word a
    /// `--json` consumer branches on, carried under `payload.kind` alongside the
    /// prose `message`.
    ///
    /// The match is exhaustive with NO wildcard arm ON PURPOSE: it is the single
    /// place the format→error schema is defined, so a newly-added `CliError`
    /// variant fails the BUILD here until it is given a `kind`, rather than
    /// silently escaping to a generic envelope (or, worse, the human banner) in a
    /// machine stream. This is make-invalid-states-unrepresentable applied to the
    /// machine-output contract.
    ///
    /// A `kind` is a compile-time constant per variant, never user input, so it
    /// leaks nothing: no path, no identifier, no secret rides in it.
    #[must_use]
    pub const fn machine_kind(&self) -> &'static str {
        match self {
            Self::Usage(_) | Self::FfiPrep(_) => "usage",
            Self::UnknownCommand { .. } => "unknown-command",
            Self::Io { .. } => "io",
            Self::ScratchUnavailable { .. } => "scratch-unavailable",
            Self::Pipeline { .. } => "pipeline",
            Self::RuntimeNotFound => "runtime-not-found",
            Self::RuntimeDirInvalid { .. } => "runtime-dir-invalid",
            Self::RuntimeHomeUnknown => "runtime-home-unknown",
            Self::CacheHomeUnknown => "cache-home-unknown",
            Self::EnvDirNotAbsolute { .. } => "env-dir-not-absolute",
            Self::RuntimeMaterializeFailed { .. } => "runtime-materialize-failed",
            Self::RuntimeVersionMismatch { .. } => "runtime-version-mismatch",
            Self::EmittedBuildFailed { .. } => "emitted-build-failed",
            Self::UnknownCode { .. } => "unknown-code",
            Self::DocNotFound { .. } => "doc-not-found",
            Self::StaticRefusal(_) => "static-refusal",
            Self::CapabilityMismatch { .. } => "capability-mismatch",
            Self::Resolve(_) => "resolve",
            Self::LockRefused(_) => "lock-refused",
            Self::HashMismatch { .. } => "hash-mismatch",
            Self::Diff(_) => "diff",
            Self::SemverRejected { .. } => "semver-rejected",
            Self::PackageAudit(_) => "package-audit",
            Self::Publish(_) => "publish",
            Self::VersionRefused { .. } => "version-refused",
            Self::DocCoverage(_) => "doc-coverage",
            Self::DocExamplesFailed(_) => "doc-examples-failed",
            Self::CommandUsage { .. } => "command-usage",
            Self::UnknownGroupSub { .. } => "unknown-group-sub",
            Self::GroupRequired { .. } => "group-required",
            Self::NoRunForm { .. } => "no-run-form",
            Self::WrapperSourceRefused(_) => "wrapper-source-refused",
            Self::VerifyFailed { .. } => "verify-failed",
            Self::TestFailed { .. } => "test-failed",
            Self::UpgradeNoPrebuilt { .. } => "upgrade-no-prebuilt",
            Self::ToolchainMissing(_) => "toolchain-missing",
            Self::HealthCritical => "health-critical",
            Self::LintGateFailed => "lint-gate-failed",
            Self::EjectUnsupported { .. } => "eject-unsupported",
            Self::DiagnosticJsonEmitted => "diagnostic-json-emitted",
            Self::FileTooLarge { .. } => "file-too-large",
            Self::FmtOutputTooLarge { .. } => "fmt-output-too-large",
            Self::RemoteIngestExceeded(_) => "remote-ingest-exceeded",
            Self::LocalLimitExceeded(_) => "local-limit-exceeded",
            Self::ChildPipeHeld(_) => "child-pipe-held",
            Self::ThreadRefused { .. } => "thread-refused",
            Self::ChildPipeUnread(..) => "child-pipe-unread",
            Self::Interrupted => "interrupted",
            Self::SourceRefused { .. } => "source-refused",
            Self::PathEscape { .. } => "path-escape",
            Self::OutputRefused(_) => "output-refused",
            Self::DiscoveryLimitReached { .. } => "discovery-limit-reached",
            Self::TrustRefused(_) => "trust-refused",
            Self::DeviceNamedModule { .. } => "device-named-module",
            Self::UpgradeFeedUnreachable => "upgrade-feed-unreachable",
            Self::UpgradeCheckExit { .. } => "upgrade-check-exit",
            Self::AdvisoryVulnerable(_) => "advisory-vulnerable",
            Self::AdvisoryDbUnreachable { .. } => "advisory-db-unreachable",
            Self::AdvisoryDbMalformed { .. } => "advisory-db-malformed",
            Self::WasiRunFeatureDisabled => "wasi-run-feature-disabled",
            Self::WasiRunFailed { .. } => "wasi-run-failed",
            Self::WasiRunExited { .. } => "wasi-run-exited",
        }
    }

    /// Who this error belongs to, which picks its colour in the human error
    /// frame ([`crate::screen::Fault`]).
    ///
    /// Internal means ipe broke a promise it makes: a program ipe accepted whose
    /// emitted Rust then failed to build (the SEAL), or an installed runtime
    /// that disagrees with the compiler's own version. An emitted build that
    /// failed only because the crate registry was unreachable is the network's
    /// doing, not ipe's. Everything else is actionable by the user. Exhaustive
    /// with no wildcard, like [`Self::machine_kind`], so a new variant must be
    /// classified to build.
    #[must_use]
    pub fn fault(&self) -> crate::screen::Fault {
        use crate::screen::Fault::{Internal, User};
        match self {
            Self::EmittedBuildFailed { stderr, .. } => {
                match EmittedBuildCause::of(stderr.as_str().trim()) {
                    EmittedBuildCause::RegistryUnreachable => User,
                    EmittedBuildCause::MissingRuntimeFeature(_) | EmittedBuildCause::Miscompile => {
                        Internal
                    }
                }
            }
            Self::RuntimeVersionMismatch { .. } => Internal,
            Self::FfiPrep(refusal) => ffi_prep_fault(refusal),
            Self::Usage(_)
            | Self::UnknownCommand { .. }
            | Self::Io { .. }
            | Self::ScratchUnavailable { .. }
            | Self::Pipeline { .. }
            | Self::RuntimeNotFound
            | Self::RuntimeDirInvalid { .. }
            | Self::RuntimeHomeUnknown
            | Self::CacheHomeUnknown
            | Self::EnvDirNotAbsolute { .. }
            | Self::RuntimeMaterializeFailed { .. }
            | Self::UnknownCode { .. }
            | Self::DocNotFound { .. }
            | Self::StaticRefusal(_)
            | Self::CapabilityMismatch { .. }
            | Self::Resolve(_)
            | Self::LockRefused(_)
            | Self::HashMismatch { .. }
            | Self::Diff(_)
            | Self::SemverRejected { .. }
            | Self::PackageAudit(_)
            | Self::Publish(_)
            | Self::VersionRefused { .. }
            | Self::DocCoverage(_)
            | Self::DocExamplesFailed(_)
            | Self::CommandUsage { .. }
            | Self::UnknownGroupSub { .. }
            | Self::GroupRequired { .. }
            | Self::NoRunForm { .. }
            | Self::WrapperSourceRefused(_)
            | Self::VerifyFailed { .. }
            | Self::TestFailed { .. }
            | Self::UpgradeNoPrebuilt { .. }
            | Self::ToolchainMissing(_)
            | Self::HealthCritical
            | Self::LintGateFailed
            | Self::EjectUnsupported { .. }
            | Self::DiagnosticJsonEmitted
            | Self::FileTooLarge { .. }
            | Self::FmtOutputTooLarge { .. }
            | Self::RemoteIngestExceeded(_)
            | Self::LocalLimitExceeded(_)
            | Self::ChildPipeHeld(_)
            | Self::ThreadRefused { .. }
            | Self::ChildPipeUnread(..)
            | Self::Interrupted
            | Self::SourceRefused { .. }
            | Self::PathEscape { .. }
            | Self::OutputRefused(_)
            | Self::DiscoveryLimitReached { .. }
            | Self::TrustRefused(_)
            | Self::DeviceNamedModule { .. }
            | Self::UpgradeFeedUnreachable
            | Self::UpgradeCheckExit { .. }
            | Self::AdvisoryVulnerable(_)
            | Self::AdvisoryDbUnreachable { .. }
            | Self::AdvisoryDbMalformed { .. }
            | Self::WasiRunFeatureDisabled
            | Self::WasiRunFailed { .. }
            | Self::WasiRunExited { .. } => User,
        }
    }

    /// Whether this error's `Display` is a complete screen of its own.
    ///
    /// A help page, a gate report, or a self-guttered environment message: the
    /// error frame shows it as rendered rather than painting it as one message.
    ///
    /// That trust rests on a type invariant: every piece of user or external
    /// text such a variant carries (a typed token, a path, a tool's output, a
    /// report built from source) is a [`TerminalSafe`] field, sanitised where
    /// it entered, so its `Display` cannot interpolate a raw control sequence.
    #[must_use]
    pub const fn renders_own_screen(&self) -> bool {
        matches!(
            self,
            Self::UnknownCommand { .. }
                | Self::CommandUsage { .. }
                | Self::UnknownGroupSub { .. }
                | Self::GroupRequired { .. }
                | Self::NoRunForm { .. }
                | Self::DocCoverage(_)
                | Self::DocExamplesFailed(_)
                | Self::VerifyFailed { .. }
                | Self::TestFailed { .. }
                | Self::UpgradeNoPrebuilt { .. }
                | Self::ToolchainMissing(_)
                | Self::EmittedBuildFailed { .. }
                | Self::HealthCritical
                | Self::LintGateFailed
                | Self::EjectUnsupported { .. }
                | Self::UpgradeFeedUnreachable
                | Self::WasiRunFeatureDisabled
                | Self::WasiRunFailed { .. }
                | Self::WasiRunExited { .. }
                | Self::DiagnosticJsonEmitted
        )
    }
}

/// The one-line stderr verdict for a failed test run, guttered and glyphed so
/// the caller prints it as-is. The per-case failures and the `N passed, M
/// failed` summary already went to stdout from the test binary; this pairs the
/// non-zero exit with a short, human-readable reason.
pub fn test_failed_message(code: i32) -> String {
    format!(
        "{}{} {}",
        style::GUTTER,
        style::outcome_glyph(style::Outcome::Failure),
        text::cli_test_failed_suffix(&code),
    )
}

impl std::fmt::Display for CliError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(hint) => f.write_str(hint),
            Self::UnknownCommand { attempted } => fmt_unknown_command(attempted, f),
            Self::Io { path, source } => fmt_io_error(path, source, f),
            Self::ScratchUnavailable { source } => {
                f.write_str(&text::cli_scratch_unavailable(&source.kind()))
            }
            Self::Pipeline { file, src, diag } => {
                f.write_str(&render(diag, &file.to_string_lossy(), src))
            }
            Self::RuntimeNotFound => f.write_str(text::cli_runtime_not_found()),
            Self::CacheHomeUnknown => f.write_str(text::cli_cache_home_unknown()),
            Self::EnvDirNotAbsolute { var } => f.write_str(&text::cli_env_dir_not_absolute(var)),
            Self::RuntimeDirInvalid { .. }
            | Self::RuntimeHomeUnknown
            | Self::RuntimeMaterializeFailed { .. }
            | Self::RuntimeVersionMismatch { .. } => fmt_runtime_install_error(self, f),
            Self::EmittedBuildFailed { .. } => fmt_emitted_build_failed(self, f),
            Self::StaticRefusal(refusal) => f.write_str(&text::cli_static_refusal(refusal)),
            Self::CapabilityMismatch { missing, extra } => {
                f.write_str(text::cli_capability_mismatch_header())?;
                if !missing.is_empty() {
                    write!(
                        f,
                        "\n{}",
                        text::cli_capability_mismatch_missing(&missing.join(", "))
                    )?;
                }
                if !extra.is_empty() {
                    write!(
                        f,
                        "\n{}",
                        text::cli_capability_mismatch_extra(&extra.join(", "))
                    )?;
                }
                Ok(())
            }
            Self::Resolve(message) => f.write_str(message),
            Self::LockRefused(refusal) => write!(f, "{refusal}"),
            Self::HashMismatch {
                package,
                expected,
                actual,
            } => f.write_str(&text::cli_hash_mismatch(
                &package.escape_debug(),
                expected,
                actual,
            )),
            Self::DocNotFound { query, suggestions } => {
                f.write_str(&text::cli_doc_not_found(query))?;
                if !suggestions.is_empty() {
                    write!(f, "\n{}", text::cli_doc_suggestions_header())?;
                    for line in crate::doc_bundle::suggestion_lines(suggestions) {
                        write!(f, "\n{line}")?;
                    }
                }
                Ok(())
            }
            Self::UnknownCode { input, suggestions } => {
                f.write_str(&text::cli_unknown_code(input))?;
                match suggestions.split_first() {
                    None => Ok(()),
                    Some((first, rest)) => {
                        write!(f, "\n{}", text::cli_unknown_code_did_you_mean(first))?;
                        for s in rest {
                            write!(f, ", {s}")?;
                        }
                        write!(f, "?")
                    }
                }
            }
            Self::Diff(err) => write!(f, "{err}"),
            Self::SemverRejected {
                required,
                floor,
                proposed,
            } => f.write_str(&text::cli_semver_rejected(required, floor, proposed)),
            Self::DocCoverage(report) | Self::DocExamplesFailed(report) => {
                f.write_str(report.as_str())
            }
            Self::PackageAudit(rejection) => write!(f, "{rejection}"),
            Self::Publish(refusal) => f.write_str(&text::cli_publish_refused(refusal)),
            Self::VersionRefused { package, refusal } => {
                f.write_str(&text::cli_version_refused(&package.escape_debug(), refusal))
            }
            // The reason, then the command's full `--help` page (indented,
            // coloured for a terminal). Rendered against stderr because misuse
            // output goes there. A known command always has a help page; the
            // `None` fallback (never taken for a known command) degrades to the
            // top-level screen rather than panicking.
            Self::CommandUsage { command, reason } => {
                writeln!(f, "{}", crate::style::gutter(reason.as_str()))?;
                let page = help::command(command.as_str(), &std::io::stderr())
                    .unwrap_or_else(|| help::top_level(&std::io::stderr()));
                f.write_str(page.trim_end_matches('\n'))
            }
            // The unknown verb, an optional near-miss over the group's own
            // members, then the group's subpage — the git-style
            // "`git remote` shows remote help" behaviour, rendered against
            // stderr because misuse output goes there.
            Self::UnknownGroupSub { group, attempted } => {
                writeln!(
                    f,
                    "{}",
                    crate::style::gutter(&text::cli_unknown_group_verb(group, attempted))
                )?;
                if let Some(sugg) = nearest_group_member(group, attempted.as_str()) {
                    writeln!(
                        f,
                        "{}",
                        crate::style::gutter(&text::cli_unknown_group_suggestion(group, &sugg))
                    )?;
                }
                let page = help::group(group, &std::io::stderr())
                    .unwrap_or_else(|| help::top_level(&std::io::stderr()));
                f.write_str(page.trim_end_matches('\n'))
            }
            // What was typed, then one hint per grouped form. A bare group
            // states it needs a subcommand; its members stay discoverable
            // through `ipe <group> --help`.
            Self::GroupRequired {
                attempted,
                forms,
                tail,
            } => {
                let headline = if help::is_group(attempted.as_str()) {
                    text::cli_subcommand_required(attempted)
                } else {
                    text::cli_group_required(attempted)
                };
                f.write_str(&crate::style::gutter(&headline))?;
                for form in *forms {
                    let shown = if tail.as_str().is_empty() {
                        form.to_string()
                    } else {
                        format!("{form} {tail}")
                    };
                    writeln!(f)?;
                    f.write_str(&crate::style::gutter(&text::cli_group_required_form(
                        &shown,
                    )))?;
                }
                Ok(())
            }
            Self::NoRunForm { target } => {
                f.write_str(&crate::style::gutter(&text::cli_no_run_form(
                    &target.word(),
                )))?;
                writeln!(f)?;
                f.write_str(&crate::style::gutter(&text::cli_no_run_form_hint(
                    &target.build_form(),
                )))
            }
            Self::WrapperSourceRefused(refusal) => f.write_str(&text::cli_wrapper_source_refused(
                &refusal.root.display(),
                &refusal.defect,
            )),
            Self::VerifyFailed { stage, report } => {
                writeln!(f, "{}", text::cli_verify_failed(stage))?;
                f.write_str(report.as_str().trim_end_matches('\n'))
            }
            // The test binary already printed its own per-case failures and the
            // `N passed, M failed` summary to stdout; this is only the one-line
            // verdict that pairs with the non-zero exit, self-guttered so the
            // caller prints it as-is.
            Self::TestFailed { code } => f.write_str(&test_failed_message(*code)),
            Self::UpgradeNoPrebuilt { version, platform } => {
                let glyph = style::outcome_glyph(style::Outcome::Failure);
                f.write_str(&style::gutter(&text::cli_upgrade_no_prebuilt(
                    &glyph, version, platform,
                )))
            }
            // The toolchain-missing message gutters and frames itself; it owns
            // its rendering (see `toolchain::ToolchainMissing`'s `Display`).
            Self::ToolchainMissing(missing) => write!(f, "{missing}"),
            // The full diagnostic report already went to stdout; this stderr
            // line is only the one-line verdict that pairs with the non-zero
            // exit, self-guttered so the caller prints it as-is.
            Self::HealthCritical => {
                write!(f, "{}{}", style::GUTTER, text::cli_health_critical())
            }
            Self::EjectUnsupported { reason } => write!(
                f,
                "{}{}",
                style::GUTTER,
                text::cli_eject_unsupported(reason)
            ),
            // The findings already went to stdout; this stderr line is the
            // one-line verdict paired with the non-zero gate exit.
            Self::LintGateFailed => {
                write!(f, "{}{}", style::GUTTER, text::cli_lint_gate_failed())
            }
            // These already wrote their final output; nothing more to display.
            // `run_upgrade` prints the framed "feed unreachable" line (human) or
            // the machine payload (`--json`/`--plain`) before returning, so the
            // error renders nothing here — otherwise the line prints twice (the
            // duplicate that stderr showed under the stdout frame).
            Self::DiagnosticJsonEmitted
            | Self::UpgradeCheckExit { .. }
            | Self::UpgradeFeedUnreachable => Ok(()),
            Self::FileTooLarge { path, max } => {
                let path = path.display();
                f.write_str(&text::cli_file_too_large(&path, max))
            }
            Self::FmtOutputTooLarge { file, cap } => {
                let file = file.display();
                f.write_str(&text::fmt_output_too_large(&file, cap))
            }
            Self::RemoteIngestExceeded(refusal) => refusal.fmt(f),
            Self::LocalLimitExceeded(refusal) => refusal.fmt(f),
            Self::ChildPipeHeld(stream) => f.write_str(&text::cli_child_pipe_held(stream)),
            Self::ThreadRefused { role, source } => {
                f.write_str(&text::cli_thread_refused(role, &source.kind()))
            }
            Self::ChildPipeUnread(stream, kind) => {
                f.write_str(&text::cli_child_pipe_unread(stream, kind))
            }
            Self::Interrupted => f.write_str(text::cli_transfer_interrupted()),
            Self::SourceRefused { path, reason } => {
                let path = path.display();
                f.write_str(&match reason {
                    io_bounded::SourceRefusal::NotRegularFile => {
                        text::cli_source_not_regular_file(&path)
                    }
                    io_bounded::SourceRefusal::AccessDenied => {
                        text::cli_source_access_denied(&path)
                    }
                    io_bounded::SourceRefusal::Symlink => text::cli_source_symlink(&path),
                })
            }
            Self::PathEscape { raw, reason } => {
                let raw = format!("{raw:?}");
                f.write_str(&text::cli_path_escape(&raw, reason))
            }
            Self::OutputRefused(refusal) => f.write_str(&text::cli_output_refused(refusal)),
            Self::DiscoveryLimitReached { detail } => {
                f.write_str(&text::cli_discovery_limit_reached(detail))
            }
            Self::TrustRefused(refusal) => f.write_str(&refusal.message()),
            Self::FfiPrep(refusal) => std::fmt::Display::fmt(refusal, f),
            Self::DeviceNamedModule { path, segment } => {
                f.write_str(&text::cli_device_named_module(&path.display(), segment))
            }
            Self::AdvisoryVulnerable(p) => {
                let fixed_in = p
                    .fixed_in
                    .as_ref()
                    .map(|v| String::from(text::cli_advisory_fixed_in(v)))
                    .unwrap_or_default();
                f.write_str(&text::cli_advisory_vulnerable(
                    &p.package,
                    &p.version,
                    &p.severity,
                    &p.id,
                    &p.description,
                    &fixed_in,
                ))
            }
            Self::AdvisoryDbUnreachable { detail } => {
                f.write_str(&text::cli_advisory_db_unreachable(detail))
            }
            Self::AdvisoryDbMalformed { path, detail } => {
                let path = path.display();
                f.write_str(&text::cli_advisory_db_malformed(&path, detail))
            }
            Self::WasiRunFeatureDisabled => write!(
                f,
                "{}{}",
                style::GUTTER,
                text::cli_wasi_run_feature_disabled()
            ),
            Self::WasiRunFailed { detail } => {
                write!(f, "{}{}", style::GUTTER, text::cli_wasi_run_failed(detail))
            }
            // The guest ran to completion and returned a non-zero WASI exit; this
            // one-line verdict pairs with `ipe dev run`'s own non-zero exit, mirroring
            // the native run's child-exit surfacing.
            Self::WasiRunExited { code } => {
                write!(f, "{}{}", style::GUTTER, text::cli_wasi_run_exited(code))
            }
        }
    }
}

/// Render [`CliError::UnknownCommand`] for `Display`: an optional "unknown
/// command" line with a near-miss suggestion, then the top-level help screen
/// (coloured for a terminal). Output goes to stderr, where misuse output belongs.
///
/// The whole block is guttered as one unit so the "unknown command" lines and
/// the help header share the same left gutter — the screen reads identically to
/// the plain top-level page, only with the leading advice. The top-level page
/// already carries its own gutter, so an unknown-command entry re-gutters only
/// its own advice lines and leaves the page as-is.
pub fn fmt_unknown_command(
    attempted: &TerminalSafe,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    if !attempted.as_str().is_empty() {
        writeln!(
            f,
            "{}",
            style::gutter(&text::cli_unknown_command_line(attempted))
        )?;
        if let Some(sugg) = nearest_command(attempted.as_str()) {
            writeln!(
                f,
                "{}",
                style::gutter(&text::cli_unknown_command_suggestion(&sugg))
            )?;
        }
    }
    f.write_str(&help::top_level(&std::io::stderr()))
}

/// Render [`CliError::Io`] for `Display`, styled and actionable rather than a
/// raw OS string. A missing file is the common case a first-time user hits, so
/// it gets a plain-language message with no `os error N` tail and no `io error`
/// jargon; every other kind keeps the readable OS description under the same
/// guttered, path-naming frame. Never leaks an errno.
pub fn fmt_io_error(
    path: &Path,
    source: &std::io::Error,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    // The generic error path in the binary already frames and gutters this
    // (`ipe: <message>`); render only the message body, styled and errno-free.
    let path = path.display();
    if source.kind() == std::io::ErrorKind::NotFound {
        f.write_str(&text::cli_io_not_found(&path))
    } else {
        // A readable kind description, never the `(os error N)` tail. `ErrorKind`
        // renders as a short human phrase (e.g. "permission denied").
        f.write_str(&text::cli_io_other(&path, &source.kind()))
    }
}

/// Render the runtime-install error family (`RuntimeDirInvalid`,
/// `RuntimeHomeUnknown`, `RuntimeMaterializeFailed`) for [`CliError`]'s `Display`.
/// Split out so the main `Display` match stays within one screen.
pub fn fmt_runtime_install_error(
    err: &CliError,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    match err {
        CliError::RuntimeDirInvalid {
            path,
            points_at_inner,
        } => {
            let path = path.display();
            f.write_str(&text::cli_runtime_dir_invalid(&path))?;
            if *points_at_inner {
                write!(f, "\n{}", text::cli_runtime_dir_invalid_inner_hint())?;
            }
            Ok(())
        }
        CliError::RuntimeHomeUnknown => f.write_str(text::cli_runtime_home_unknown()),
        CliError::RuntimeMaterializeFailed { detail } => {
            f.write_str(&text::cli_runtime_materialize_failed(detail))
        }
        CliError::RuntimeVersionMismatch {
            path,
            found,
            expected,
        } => {
            let path = path.display();
            f.write_str(&text::cli_runtime_version_mismatch(&path, found, expected))
        }
        // The caller only dispatches the runtime-install variants here.
        _ => Ok(()),
    }
}

/// Render [`CliError::EmittedBuildFailed`] for `Display`.
///
/// Three cases, one per [`EmittedBuildCause`]:
///
/// - **Stale runtime**: `cargo`'s stderr names a missing runtime feature — lead
///   with a targeted line pointing at the stale runtime crate.
/// - **Registry unreachable**: `cargo` could not reach the crate registry — a
///   network problem, rendered with no bug-report invitation.
/// - **Miscompile**: every other `cargo` failure after a successful Ipê
///   compile. The front-end gate ensures only valid programs reach emit, so a
///   `cargo` failure here means the emitted Rust is wrong — a miscompile in Ipê,
///   not the user's source. Render it as a humble `CompilerBug` ICE so the user
///   knows to file a report rather than try to fix their source. The full `cargo`
///   stderr is embedded as the reportable detail.
///
/// No form shows any command's `--help` page.
pub fn fmt_emitted_build_failed(
    err: &CliError,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    let CliError::EmittedBuildFailed {
        what,
        code,
        stderr,
        runtime,
    } = err
    else {
        // The caller only dispatches the one variant here.
        return Ok(());
    };
    let runtime = runtime.as_ref();
    let trimmed = stderr.as_str().trim();
    match EmittedBuildCause::of(trimmed) {
        EmittedBuildCause::MissingRuntimeFeature(feature) => {
            f.write_str(&text::cli_emitted_build_feature_missing(what, &feature))?;
            if let Some(rt) = runtime {
                write!(
                    f,
                    "{}",
                    text::cli_emitted_build_feature_context(&rt.root, &rt.version)
                )?;
            }
            write!(f, ".\n{}", text::cli_emitted_build_stale_runtime_hint())
        }
        // An environment failure (DNS, offline, proxy), not a compiler bug and
        // not the user's source: a calm, actionable message with no bug-report
        // invitation.
        EmittedBuildCause::RegistryUnreachable => {
            let detail = String::from(if trimmed.is_empty() {
                text::cli_cargo_fetch_failed(code, what)
            } else {
                text::cli_cargo_fetch_failed_detail(code, what, &trimmed)
            });
            let d = Diagnostic::RegistryUnreachable { detail };
            f.write_str(&render(&d, "", ""))
        }
        // The front-end gate lets only valid programs reach emit, so this cargo
        // failure is a bug in ipe's own emission: a humble ICE whose detail
        // embeds the full cargo stderr, so a report carries everything needed to
        // reproduce the miscompile.
        EmittedBuildCause::Miscompile => {
            let detail = String::from(if trimmed.is_empty() {
                text::cli_cargo_compile_failed(code, what)
            } else {
                text::cli_cargo_compile_failed_detail(code, what, &trimmed)
            });
            let ice = Diagnostic::CompilerBug {
                where_: "emit.cargo_build",
                detail,
            };
            f.write_str(&render(&ice, "", ""))
        }
    }
}

/// Why an emitted crate's `cargo build` failed, read from `cargo`'s stderr.
///
/// The one classification both the rendered message and the error's
/// [`crate::screen::Fault`] follow, so the two never disagree.
enum EmittedBuildCause {
    /// The runtime crate lacks a feature the emitted crate enables: a stale
    /// runtime install.
    MissingRuntimeFeature(String),
    /// `cargo` could not reach the crate registry: DNS, offline, or a proxy.
    RegistryUnreachable,
    /// Any other failure: the emitted Rust is wrong, a miscompile in ipe.
    Miscompile,
}

impl EmittedBuildCause {
    /// Classify `cargo`'s trimmed stderr.
    fn of(stderr: &str) -> Self {
        missing_runtime_feature(stderr).map_or_else(
            || {
                if is_registry_unreachable(stderr) {
                    Self::RegistryUnreachable
                } else {
                    Self::Miscompile
                }
            },
            Self::MissingRuntimeFeature,
        )
    }
}

/// Detect whether cargo's stderr signals a network-level registry failure
/// (offline, DNS resolution, or a transient fetch error) rather than a compiler
/// miscompile.
///
/// Only genuinely network-level phrases qualify. Broader phrases like "failed to
/// load source for dependency" or "registry index" are deliberately excluded:
/// they also fire when a local path dependency is missing or a manifest is
/// malformed — not connectivity problems, and reporting them as "check your
/// connection" would misdirect the user. The offline case always surfaces one of
/// the network phrases below as its root cause.
pub fn is_registry_unreachable(stderr: &str) -> bool {
    stderr.contains("Could not resolve host")
        || stderr.contains("spurious network error")
        || stderr.contains("failed to fetch")
}

/// Extract the runtime feature name from a `cargo` feature-resolution error of
/// the form ``… depends on ipe-runtime-rust with feature `X` but ipe-runtime-rust
/// does not have that feature``. The name is quoted in backticks or single
/// quotes; both are accepted. `None` when the stderr is some other failure.
pub fn missing_runtime_feature(stderr: &str) -> Option<String> {
    if !stderr.contains("does not have that feature") {
        return None;
    }
    // The name sits between `with feature <q>` and the matching close quote,
    // where the quote is a backtick or a single quote.
    let after = stderr.split_once("with feature ")?.1;
    let mut chars = after.chars();
    let close = match chars.next()? {
        '`' => '`',
        '\'' => '\'',
        _ => return None,
    };
    let rest = chars.as_str();
    let name = rest.split_once(close)?.0;
    if name.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

impl std::error::Error for CliError {}

/// Who an FFI prep refusal belongs to.
///
/// An emit left empty after asserted calls validated breaks a promise ipe
/// makes ([`crate::ffi::FfiPrepError::AssertedWithoutCatalog`]); every other
/// refusal is the user's to fix.
const fn ffi_prep_fault(refusal: &crate::ffi::FfiPrepError) -> crate::screen::Fault {
    use crate::ffi::FfiPrepError;
    match refusal {
        FfiPrepError::AssertedWithoutCatalog => crate::screen::Fault::Internal,
        FfiPrepError::ModuleClaimed { .. }
        | FfiPrepError::ReservedModuleExists
        | FfiPrepError::AssertedRefused(_)
        | FfiPrepError::AssertedShimSeal(_)
        | FfiPrepError::DefineOpaqueCollision { .. }
        | FfiPrepError::DependencyMerge(_)
        | FfiPrepError::CatalogSeal(_)
        | FfiPrepError::TransparentWithoutShape { .. } => crate::screen::Fault::User,
    }
}

// `CliError` is the `Err` type of every driver `Result`, so its size is paid
// in the `Err` slot of ~200 functions. Boxing the wide payloads (the `Pipeline`
// diagnostic) keeps it under clippy's `result_large_err` threshold; the bound
// below IS that threshold, so the assertion and the lint enforce one fact. A
// future variant that carries an unboxed wide payload trips both. The bound is
// the lint's ceiling, not the type's current exact size, so it holds on every
// target ABI (`std::io::Error` is wider on Windows than on Linux, for one).
pub const CLI_ERROR_MAX_BYTES: usize = 128;
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); it fails the build if a future `CliError` variant exceeds the size bound rather than boxing its payload [ledger #boundary]
const _: () = assert!(std::mem::size_of::<CliError>() <= CLI_ERROR_MAX_BYTES);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_args::OutputFormat;

    /// A non-`Pipeline` refusal under `--json` reaches the machine stream as the
    /// documented schema object — a parseable `{status,kind,message}` — never a
    /// raw variant dump and never the human banner. This is the disclosure
    /// contract every failure class now honours, not just `Pipeline`.
    #[test]
    fn non_pipeline_json_renders_the_documented_schema_object() {
        let err = CliError::CapabilityMismatch {
            missing: vec!["net"],
            extra: vec![],
        };
        let line = machine_output::machine_error(
            OutputFormat::Json,
            "build",
            err.machine_kind(),
            &err.to_string(),
        );
        assert!(
            line.starts_with("{\"schema\":\"ipe.cli.error/1\""),
            "the documented error envelope, not a human banner: {line:?}"
        );
        assert!(
            line.contains("\"status\":\"error\""),
            "status=error: {line:?}"
        );
        assert!(
            line.contains("\"kind\":\"capability-mismatch\""),
            "a stable kind per variant: {line:?}"
        );
        assert!(line.contains("\"message\":"), "a message field: {line:?}");
        assert!(
            !line.contains("Ipê lang"),
            "the human banner must never reach a --json stream: {line:?}"
        );
    }

    /// The same non-`Pipeline` refusal under `--plain` renders the terse
    /// flush-left record — the pipe-friendly one-record-per-line form, not a
    /// framed human banner.
    #[test]
    fn non_pipeline_plain_renders_the_terse_flush_left_record() {
        let err = CliError::RuntimeNotFound;
        let line = machine_output::machine_error(
            OutputFormat::Plain,
            "build",
            err.machine_kind(),
            &err.to_string(),
        );
        assert!(
            !line.starts_with(' ') && !line.starts_with('\n'),
            "flush-left, unframed: {line:?}"
        );
        assert!(line.ends_with('\n'), "one record per line: {line:?}");
        assert!(
            !line.starts_with('{'),
            "--plain is the bare reason, not the JSON envelope: {line:?}"
        );
        assert!(
            !line.contains("Ipê lang"),
            "no human banner in a --plain stream: {line:?}"
        );
    }

    /// `Pipeline` keeps its distinct rich diagnostic kind — the boundary still
    /// routes it through the full diagnostic JSON schema (`code`, spans, hints),
    /// never collapsing it into the terse envelope.
    #[test]
    fn pipeline_keeps_its_own_kind() {
        assert_eq!(
            CliError::Pipeline {
                file: PathBuf::from("Main.ipe"),
                src: String::new(),
                diag: Box::new(Diagnostic::CompilerBug {
                    where_: "test",
                    detail: String::new(),
                }),
            }
            .machine_kind(),
            "pipeline"
        );
    }

    /// The `kind` tags are stable, distinct words — a consumer's branch keys.
    #[test]
    fn kinds_are_stable_and_distinct_per_named_refusal() {
        assert_eq!(
            CliError::RuntimeNotFound.machine_kind(),
            "runtime-not-found"
        );
        assert_eq!(
            CliError::CapabilityMismatch {
                missing: vec![],
                extra: vec![]
            }
            .machine_kind(),
            "capability-mismatch"
        );
        assert_eq!(CliError::HealthCritical.machine_kind(), "health-critical");
    }

    /// A scratch failure renders only the error kind: neither the temp root
    /// nor the source error's payload (which may carry a path with terminal
    /// control bytes) reaches the message.
    #[test]
    fn a_scratch_failure_names_no_path() {
        let err = CliError::ScratchUnavailable {
            source: std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "/planted/root\u{1b}[31m",
            ),
        };
        let shown = err.to_string();
        assert!(shown.contains("permission denied"), "{shown:?}");
        assert!(!shown.contains("/planted/root"), "{shown:?}");
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
        assert_eq!(err.machine_kind(), "scratch-unavailable");
    }

    /// An FFI prep refusal keeps the `usage` machine kind, renders inside the
    /// error frame, and is the user's fault except the internal-invariant breach.
    #[test]
    fn ffi_prep_machine_kind_and_fault() {
        use crate::ffi::FfiPrepError;
        use crate::screen::Fault;
        let lift = |refusal| CliError::FfiPrep(Box::new(refusal));
        let internal = lift(FfiPrepError::AssertedWithoutCatalog);
        assert_eq!(internal.fault(), Fault::Internal);
        for user in [
            FfiPrepError::ReservedModuleExists,
            FfiPrepError::DefineOpaqueCollision {
                slug: "a".to_owned(),
                name: "T".to_owned(),
            },
            FfiPrepError::ModuleClaimed {
                module: "Rust.A".to_owned(),
                slug: "a".to_owned(),
            },
        ] {
            assert_eq!(lift(user).fault(), Fault::User);
        }
        assert_eq!(internal.machine_kind(), "usage");
        assert!(!internal.renders_own_screen());
    }
}
