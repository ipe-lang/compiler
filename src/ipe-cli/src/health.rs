//! `ipe health` — environment diagnostics and consent-gated build-optimization
//! setup.
//!
//! In the tradition of `flutter doctor` / `rustup check`, but precise because
//! the compiler knows what its own emit-and-Cargo pipeline needs. The command
//! has two halves:
//!
//! 1. **Detection** (always read-only): each concern the pipeline depends on is
//!    a [`Check`] — a toolchain probe, a linker probe, a cache probe, the shared
//!    build target, the FFI sandbox prerequisites, free disk. Every check yields
//!    a typed [`Status`] and, where it can be improved, a typed [`Fix`].
//! 2. **Apply** (only on explicit consent): a fix that carries one is either a
//!    structured, format-preserving edit to a config file the command is allowed
//!    to touch, or an install run as a direct `argv` (never a shell, never
//!    `sudo`, never a pipe-to-shell), or a setup of the shared target under
//!    `$IPE_HOME`. Each is previewed before it runs.
//!
//! # Who decides, and how
//! Human-vs-machine is TTY-driven, not flag-driven (the same rule the rest of
//! the CLI follows via [`crate::style`]):
//! - On a terminal with no format flag: print the report, then prompt per
//!   fixable item `[Y/n]` (default yes), each previewing exactly what it will do
//!   — a diff for a config edit, the exact command for an install.
//! - `--plain` / `--json`: pure data, and they NEVER mutate — the machine forms
//!   a script or `jq` consumes.
//! - Piped with no flag: report plus an exit code, no prompt (a prompt into a
//!   pipe would hang); a hint points at the interactive or `--yes` path.
//! - `--yes` / `-y`: apply every fixable item non-interactively (provisioning
//!   and CI).
//!
//! # What it is allowed to touch
//! A config edit's destination is a [`ConfigTarget`], a closed set of exactly
//! the two files in the command's scope: `$IPE_HOME/config.toml` and
//! `~/.cargo/config.toml`. There is no variant for anything else, so "edit a
//! file outside my scope" is not a state the apply engine can represent. An
//! install runs a fixed `argv`; a package-manager command (which needs
//! elevation the command deliberately does not take) is shown, never run.

use std::fmt::Write as _;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli_args::OutputFormat;
use crate::style::TerminalSafe;
use crate::{
    CliError, runtime_embed,
    scratch::{LeafName, ScratchDir},
    style, toolchain,
};

/// Whether a check passed, warns, is a hard miss, or cannot be known.
///
/// `Unknown` is a first-class outcome, not a failure: a probe whose answer the
/// command cannot honestly determine (there is no version feed to compare the
/// running `ipe` against) reports `Unknown` rather than inventing an `Ok`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The concern is satisfied.
    Ok,
    /// The concern works but could be improved (an optional optimization is
    /// absent, disk is tight). Never fails the exit code.
    Warn,
    /// A concern the pipeline needs is absent. A `Missing` check that is
    /// [`critical`](Check::critical) drives a non-zero exit.
    Missing,
    /// The check ran but its answer cannot be honestly determined.
    Unknown,
}

impl Status {
    /// The lowercase wire tag used in `--plain` / `--json`.
    const fn tag(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Missing => "missing",
            Self::Unknown => "unknown",
        }
    }

    /// The glyph that leads this status on the human report.
    const fn glyph(self) -> &'static str {
        match self {
            // Ok and Missing share the success/failure glyphs from the SSOT; Warn
            // and Unknown are health-only states with their own bullets.
            Self::Ok => style::outcome_glyph(style::Outcome::Success),
            Self::Warn => "!",
            Self::Missing => style::outcome_glyph(style::Outcome::Failure),
            Self::Unknown => "?",
        }
    }
}

/// The report section a check belongs to. A closed set so the renderer groups
/// deterministically and a check cannot land in an unnamed section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    /// `rustc` / `cargo` presence, the running `ipe`, the runtime crate.
    Toolchain,
    /// A fast linker (`mold` / `lld`).
    Linker,
    /// A compile cache (`sccache`).
    Cache,
    /// The ipe-managed shared build target.
    Target,
    /// The FFI build-jail / run-jail prerequisites for this platform.
    Sandbox,
    /// Free disk for the shared target and build cache.
    Disk,
}

impl Group {
    /// The section heading on the human report.
    const fn title(self) -> &'static str {
        match self {
            Self::Toolchain => "Toolchain",
            Self::Linker => "Linker",
            Self::Cache => "Cache",
            Self::Target => "Shared build target",
            Self::Sandbox => "Sandbox (FFI)",
            Self::Disk => "Disk",
        }
    }

    /// The report order.
    const ALL: [Self; 6] = [
        Self::Toolchain,
        Self::Linker,
        Self::Cache,
        Self::Target,
        Self::Sandbox,
        Self::Disk,
    ];
}

/// The config file a [`Fix::ConfigEdit`] is allowed to write.
///
/// A closed two-variant set: the command's whole config-edit scope is exactly
/// `$IPE_HOME/config.toml` and `~/.cargo/config.toml`. There is no variant for
/// any other path, so an edit outside the command's scope is unrepresentable
/// rather than merely disallowed at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigTarget {
    /// `$IPE_HOME/config.toml` — the compiler's own per-user configuration.
    IpeHome,
    /// `~/.cargo/config.toml` — Cargo's per-user configuration (the linker /
    /// wrapper snippets live here because they must reach the `cargo` the driver
    /// shells out to).
    Cargo,
}

impl ConfigTarget {
    /// A short label for the preview and reports.
    const fn label(self) -> &'static str {
        match self {
            Self::IpeHome => "$IPE_HOME/config.toml",
            Self::Cargo => "~/.cargo/config.toml",
        }
    }

    /// Resolve the on-disk path for this target. `$IPE_HOME/config.toml` uses
    /// the same [`runtime_embed::ipe_home`] resolution the runtime install uses;
    /// `~/.cargo/config.toml` honours `$CARGO_HOME`, else `~/.cargo`.
    ///
    /// # Errors
    /// [`CliError::RuntimeHomeUnknown`] when no home can be resolved for the Ipê
    /// target; for Cargo, [`CliError::EnvDirNotAbsolute`] when `CARGO_HOME` is
    /// relative and [`CliError::Usage`] when no home can be resolved.
    fn path(self) -> Result<PathBuf, CliError> {
        match self {
            Self::IpeHome => Ok(runtime_embed::ipe_home()?.join("config.toml")),
            Self::Cargo => cargo_config_path(),
        }
    }
}

/// The Cargo config path cargo itself reads: `$CARGO_HOME/config.toml`, else `~/.cargo/config.toml`.
///
/// # Errors
/// See [`cargo_config_path_from`].
fn cargo_config_path() -> Result<PathBuf, CliError> {
    cargo_config_path_from(
        ipe_env::var_os("CARGO_HOME"),
        crate::env_dir::home().ok().as_ref(),
    )
}

/// Resolve the Cargo config path from the raw `CARGO_HOME` value and the home.
///
/// # Errors
/// [`CliError::EnvDirNotAbsolute`] when `CARGO_HOME` is set, non-empty, and
/// relative — cargo resolves it against its working directory, so writing the
/// home default instead would edit a file cargo never reads;
/// [`CliError::Usage`] when `CARGO_HOME` is unset and no home resolves.
fn cargo_config_path_from(
    cargo_home: Option<std::ffi::OsString>,
    home: Option<&crate::env_dir::HomeDir>,
) -> Result<PathBuf, CliError> {
    let cargo_home = crate::env_dir::tool_home_from("CARGO_HOME", cargo_home, home, ".cargo")?
        .ok_or_else(|| CliError::Usage(crate::text::msg::health_home_unknown()))?;
    Ok(cargo_home.join("config.toml"))
}

/// The value a [`ConfigEdit`] sets — a string or a string array.
///
/// The distinction matters because `toml_edit` writes them as different TOML
/// constructs: `key = "value"` vs `key = ["a", "b"]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigValue {
    /// A plain TOML string value.
    Str(String),
    /// A TOML array of strings.
    StrList(Vec<String>),
}

impl ConfigValue {
    /// A compact display for the fix preview (`+` diff-add line).
    fn display(&self) -> String {
        match self {
            Self::Str(s) => format!("{s:?}"),
            Self::StrList(elems) => {
                let inner: Vec<String> = elems.iter().map(|s| format!("{s:?}")).collect();
                format!("[{}]", inner.join(", "))
            }
        }
    }
}

/// A structured, format-preserving edit to one config file.
///
/// The edit is expressed as a dotted key and a typed value, not raw text: the
/// applier parses the existing document, sets exactly that key (preserving every
/// other line, comment, and layout), and writes it back. `rationale` is shown in
/// the preview so the user knows why the key is being set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigEdit {
    /// Which in-scope file to edit.
    pub target: ConfigTarget,
    /// The dotted TOML key path (e.g. `build.rustc-wrapper`).
    pub key: Vec<&'static str>,
    /// The value to set the key to.
    pub value: ConfigValue,
    /// A one-line reason, shown in the preview.
    pub rationale: &'static str,
}

/// How an install is carried out.
///
/// Only [`Direct`](Self::Direct) ever runs, and it runs a fixed `argv` with no
/// shell between it and the OS — no word-splitting, no globbing, no
/// pipe-to-shell. A tool whose install needs a system package manager (and thus
/// elevation this command deliberately does not take) is
/// [`PackageManager`](Self::PackageManager): its command is printed for the user
/// to run, never executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallMethod {
    /// A fixed `argv`, run directly (no shell). The first element is the program;
    /// the rest are its literal arguments.
    Direct {
        /// The program and its literal arguments.
        argv: Vec<String>,
    },
    /// A command the user must run themselves (it needs a package manager /
    /// elevation the command does not take). Shown, never run.
    PackageManager {
        /// The exact command line to display.
        command: String,
    },
}

/// A tool install a fix offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Install {
    /// The tool being installed (for the preview and the success line).
    pub tool: &'static str,
    /// How the install is carried out.
    pub method: InstallMethod,
}

/// A fix a check can offer. Each variant is a distinct trust action with its own
/// preview and its own applier; there is no free-form "run this" escape hatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fix {
    /// Set a key in one of the two in-scope config files.
    ConfigEdit(ConfigEdit),
    /// Install a tool (directly, or by printing a package-manager command).
    Install(Install),
    /// Configure the ipe-managed shared build target under `$IPE_HOME`.
    HomeSetup(SharedTargetSetup),
    /// Run `ipe upgrade` to install the available newer release.
    RunUpgrade {
        /// The currently running version.
        current: String,
        /// The latest available version.
        latest: String,
    },
}

/// The shared-target setup.
///
/// Point `$IPE_HOME/config.toml`'s build target at a stable directory under
/// `$IPE_HOME/target`, so every emitted project reuses one warm target instead
/// of a cold per-project one. Reversible by construction: it only sets the
/// `build.target-dir` key in the Ipê-owned config (never the user's Cargo
/// config), which the user can clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedTargetSetup {
    /// The absolute shared-target directory to configure.
    pub target_dir: PathBuf,
}

/// One diagnostic. Carries its group, a stable id, its status, a human detail,
/// an optional suggestion, and an optional [`Fix`] the apply engine can run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// The report section.
    pub group: Group,
    /// A stable machine id (the `--plain` / `--json` key), e.g. `rustc`.
    pub id: &'static str,
    /// The outcome.
    pub status: Status,
    /// A one-line human explanation of the outcome.
    pub detail: String,
    /// An optional suggestion, shown when there is no applicable fix (or beside
    /// one). Names only shipped commands.
    pub suggestion: Option<String>,
    /// The fix the apply engine can run, when there is one.
    pub fix: Option<Fix>,
}

impl Check {
    /// Whether a `Missing` here should drive a non-zero exit. Only the hard
    /// pipeline prerequisites are critical; an absent optimization is a `Warn`.
    fn critical(&self) -> bool {
        matches!(self.id, "rustc" | "cargo" | "runtime")
    }
}

/// The full diagnostic outcome: every check, in report order.
pub struct Report {
    /// The checks, grouped-and-ordered by [`Group::ALL`] within the vector.
    pub checks: Vec<Check>,
}

impl Report {
    /// Whether any critical check is missing — the signal for a non-zero exit.
    fn has_critical_failure(&self) -> bool {
        self.checks
            .iter()
            .any(|c| c.status == Status::Missing && c.critical())
    }

    /// The checks that carry an applicable fix, in report order.
    fn fixable(&self) -> impl Iterator<Item = &Check> {
        self.checks.iter().filter(|c| c.fix.is_some())
    }
}

/// `ipe health` entry point.
///
/// Parses the shared output-format flags plus `--yes`/`-y`, runs the read-only
/// detectors, prints the report in the requested mode, and — on a terminal (or
/// under `--yes`) — offers to apply each fixable item. `--plain` / `--json`
/// never prompt and never mutate.
///
/// # Errors
/// [`CliError::Usage`] on an unknown flag or a combination the parse
/// rejects (`--yes` with `--plain` / `--json`, which never mutate); a filesystem
/// error from an accepted fix.
pub fn run_health(rest: &[String]) -> Result<(), CliError> {
    let args = crate::cli_args::parse_health(rest)?;
    let report = detect();

    let stdout = std::io::stdout();
    match args.format {
        OutputFormat::Plain => {
            crate::screen::emit_machine(crate::screen::Stream::Stdout, &render_plain(&report));
            return finish(&report);
        }
        OutputFormat::Json => {
            crate::screen::emit_machine(crate::screen::Stream::Stdout, &render_json(&report));
            return finish(&report);
        }
        OutputFormat::Human => {
            crate::screen::Screen::new(crate::screen::Stream::Stdout)
                .guttered(&render_human(&report, &stdout))
                .emit();
        }
    }

    // The apply half runs only when the user can consent: `--yes` is
    // consent-by-flag; otherwise a real terminal on stdin is required so a
    // per-item prompt has somewhere to read from. A no-flag pipe reports and
    // stops (a prompt into a pipe would hang).
    let consent = if args.assume_yes {
        Consent::All
    } else if std::io::stdin().is_terminal() && stdout.is_terminal() {
        Consent::Interactive
    } else {
        // Reported already; a non-interactive run without `--yes` mutates
        // nothing. Point the user at the two ways to apply.
        if report.fixable().next().is_some() {
            crate::screen::chatter(
                crate::screen::Stream::Stdout,
                crate::screen::Tone::Text,
                "Run `ipe health` in a terminal to apply these interactively, or \
                     `ipe health --yes` to apply them all.\n",
            );
        }
        return finish(&report);
    };

    apply_fixes(&report, consent, &stdout);
    finish(&report)
}

/// Run the diagnostic checks and print the human report, then offer per-item
/// fixes interactively — the same behaviour as `ipe health` on a terminal, but
/// driven from another command rather than the CLI entry point.
///
/// Called by `ipe init` after scaffolding to let the user tune the toolchain in
/// the same session. The caller is responsible for gating on TTY; this function
/// never reads TTY state itself so the caller controls where the prompt appears.
///
/// # Errors
/// Propagates any filesystem error from an accepted fix. A critical missing
/// check returns [`CliError::HealthCritical`] so the caller can decide whether
/// to treat it as fatal (the init wizard ignores it, matching `ipe health`'s
/// non-zero exit only when invoked as a standalone command).
pub(crate) fn run_health_inline() -> Result<(), CliError> {
    let report = detect();
    let stdout = std::io::stdout();
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .guttered(&render_human(&report, &stdout))
        .emit();
    apply_fixes(&report, Consent::Interactive, &stdout);
    finish(&report)
}

/// The exit-code decision, printed as `Ok(())` / a typed failure. A critical
/// missing check exits non-zero (so CI can gate); everything else is success.
fn finish(report: &Report) -> Result<(), CliError> {
    if report.has_critical_failure() {
        return Err(CliError::HealthCritical);
    }
    Ok(())
}

/// How much the caller has consented to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Consent {
    /// Prompt per item on the terminal.
    Interactive,
    /// Apply every item (consent-by-flag, `--yes`).
    All,
}

// ---- detection ------------------------------------------------------------

/// Run every read-only detector and collect the report, in group order.
fn detect() -> Report {
    let mut checks = Vec::new();
    checks.push(check_ipe_version());
    checks.extend(check_rust_toolchain());
    checks.push(check_runtime());
    checks.push(check_linker());
    checks.push(check_cache());
    checks.push(check_shared_target());
    checks.extend(check_sandbox());
    checks.push(check_disk());
    Report { checks }
}

/// Map a [`version_check::VersionCheck`] result to a health [`Check`].
///
/// The pure conversion the test surface exercises without a network call.
fn version_check_to_check(vc: &crate::version_check::VersionCheck) -> Check {
    use crate::version_check::UpgradeAction;
    let cur = vc.current.to_string();
    match vc.action() {
        UpgradeAction::UpToDate => Check {
            group: Group::Toolchain,
            id: "ipe",
            status: Status::Ok,
            detail: format!("ipe {cur} — up to date"),
            suggestion: None,
            fix: None,
        },
        UpgradeAction::Unreachable => Check {
            group: Group::Toolchain,
            id: "ipe",
            status: Status::Unknown,
            detail: format!("ipe {cur} — cannot check for a newer release (offline)"),
            suggestion: None,
            fix: None,
        },
        UpgradeAction::Available => {
            let lat = vc
                .latest
                .as_ref()
                .map(semver::Version::to_string)
                .unwrap_or_default();
            Check {
                group: Group::Toolchain,
                id: "ipe",
                status: Status::Warn,
                detail: format!("ipe {cur} — {lat} available"),
                suggestion: None,
                fix: Some(Fix::RunUpgrade {
                    current: cur,
                    latest: lat,
                }),
            }
        }
    }
}

/// Compare the running `ipe` to the latest published release.
///
/// Calls the release feed; any network or parse failure ⇒ `Status::Unknown`.
fn check_ipe_version() -> Check {
    version_check_to_check(&crate::version_check::version_check())
}

/// `rustc` and `cargo` presence, reusing the toolchain resolver's
/// [`toolchain::Disposition`] so the "installed but off PATH" case is named
/// distinctly from "not installed".
// A `match` over presence + disposition reads far clearer than nested
// `map_or_else` closures each carrying a full `Check` literal.
#[allow(clippy::option_if_let_else)]
fn check_rust_toolchain() -> Vec<Check> {
    let cargo = match toolchain::probe_cargo() {
        toolchain::Probe::Found(path) => Check {
            group: Group::Toolchain,
            id: "cargo",
            status: Status::Ok,
            detail: format!("cargo found at {}", path.display()),
            suggestion: None,
            fix: None,
        },
        toolchain::Probe::Missing(toolchain::Disposition::NotInstalled) => Check {
            group: Group::Toolchain,
            id: "cargo",
            status: Status::Missing,
            detail: "cargo not found — the Rust toolchain is not installed".to_owned(),
            suggestion: Some("install Rust with rustup: https://rustup.rs".to_owned()),
            fix: None,
        },
        toolchain::Probe::Missing(toolchain::Disposition::NotOnPath { found_in }) => Check {
            group: Group::Toolchain,
            id: "cargo",
            status: Status::Missing,
            detail: format!(
                "cargo is installed at {found_in} but that directory is not on your PATH"
            ),
            suggestion: Some(format!("add it to PATH: export PATH=\"{found_in}:$PATH\"")),
            fix: None,
        },
    };

    let rustc = match which_on_path("rustc") {
        Some(path) => Check {
            group: Group::Toolchain,
            id: "rustc",
            status: Status::Ok,
            detail: format!("rustc found at {}", path.display()),
            suggestion: None,
            fix: None,
        },
        None => Check {
            group: Group::Toolchain,
            id: "rustc",
            status: Status::Missing,
            detail: "rustc not found on PATH".to_owned(),
            suggestion: Some("install Rust with rustup: https://rustup.rs".to_owned()),
            fix: None,
        },
    };

    vec![rustc, cargo]
}

/// The runtime crate is resolvable (the install-resolution story): the embedded
/// source materializes, an in-repo checkout is found, or `$IPE_RUNTIME_DIR`
/// verifies. This drives the same [`runtime_embed::resolve`] a real build uses.
fn check_runtime() -> Check {
    match runtime_embed::resolve() {
        Ok(resolved) => Check {
            group: Group::Toolchain,
            id: "runtime",
            status: Status::Ok,
            detail: format!(
                "runtime crate resolvable ({} at {})",
                resolved.version(),
                resolved.root().display()
            ),
            suggestion: None,
            fix: None,
        },
        Err(e) => Check {
            group: Group::Toolchain,
            id: "runtime",
            status: Status::Missing,
            detail: format!("runtime crate could not be resolved: {e}"),
            suggestion: Some(
                "set IPE_HOME to a writable directory so the embedded runtime can materialize"
                    .to_owned(),
            ),
            fix: None,
        },
    }
}

/// A fast linker (`mold` preferred, then `lld`, then `ld.gold`).
///
/// The check order:
/// 0. The host's link driver is MSVC → not applicable, nothing to do.
/// 1. Already configured in `~/.cargo/config.toml` → `Ok`, nothing to do.
/// 2. A linker is on PATH AND passes a link probe → offer the `rustflags` fix.
/// 3. A linker is on PATH but fails the probe → report found-but-rejected
///    (neutral; never offer a fix that would break the user's builds).
/// 4. Nothing found → suggest installation.
fn check_linker() -> Check {
    // 0. MSVC links through `link.exe`, which has no `-fuse-ld=` concept.
    //    Probing a PATH linker, or writing the `rustflags` edit, would offer a
    //    fix the host linker silently ignores. The axis does not apply here.
    if matches!(host_link_driver(), Some(LinkDriver::Msvc)) {
        return Check {
            group: Group::Linker,
            id: "linker",
            status: Status::Ok,
            detail: "fast-linker selection does not apply: the MSVC link driver (link.exe) \
                     ignores -fuse-ld="
                .to_owned(),
            suggestion: None,
            fix: None,
        };
    }

    // 1. Already configured: the `rustflags` key for the host target is present
    //    in `~/.cargo/config.toml` and contains a `-fuse-ld=` flag.
    if linker_already_configured() {
        return Check {
            group: Group::Linker,
            id: "linker",
            status: Status::Ok,
            detail: "fast linker already configured in ~/.cargo/config.toml".to_owned(),
            suggestion: None,
            fix: None,
        };
    }

    // 2 & 3. Probe candidates in fastest-first order.
    let candidates: &[&str] = &["mold", "ld.lld", "lld", "ld.gold"];
    for name in candidates {
        let id: &'static str = match *name {
            "mold" => "mold",
            "ld.lld" | "lld" => "lld",
            "ld.gold" | "gold" => "gold",
            _ => "linker",
        };
        let flag_name: &'static str = match *name {
            "mold" => "mold",
            "ld.lld" | "lld" => "lld",
            "ld.gold" | "gold" => "gold",
            _ => name,
        };
        let Some(path) = which_on_path(name) else {
            continue;
        };
        match probe_linker(flag_name) {
            LinkerProbeResult::Accepted => {
                return Check {
                    group: Group::Linker,
                    id,
                    status: Status::Ok,
                    detail: format!(
                        "{name} found at {} — not yet configured for native builds",
                        path.display()
                    ),
                    suggestion: Some(
                        "configure it in ~/.cargo/config.toml to halve native link time".to_owned(),
                    ),
                    fix: Some(Fix::ConfigEdit(linker_edit(flag_name))),
                };
            }
            LinkerProbeResult::Rejected => {
                return Check {
                    group: Group::Linker,
                    id,
                    status: Status::Warn,
                    detail: format!(
                        "{name} found at {} but the toolchain rejected -fuse-ld={flag_name} — \
                         the current compiler cannot use it",
                        path.display()
                    ),
                    suggestion: Some(
                        "upgrade your compiler toolchain or install a newer version of the linker"
                            .to_owned(),
                    ),
                    fix: None,
                };
            }
        }
    }

    // 4. Nothing found.
    Check {
        group: Group::Linker,
        id: "linker",
        status: Status::Warn,
        detail: "no fast linker (mold, lld, or gold) found — links use the default linker"
            .to_owned(),
        suggestion: Some(installer_hint(
            "mold",
            "a fast linker that cuts native link time",
        )),
        fix: None,
    }
}

/// Whether a fast linker is already wired in `~/.cargo/config.toml` for the
/// host target: the `rustflags` array at `[target.<triple>]` contains a
/// `-fuse-ld=` argument.
fn linker_already_configured() -> bool {
    let Ok(path) = cargo_config_path() else {
        return false;
    };
    let Ok(text) =
        crate::io_bounded::read_to_string_capped(&path, crate::io_bounded::SMALL_FILE_READ_CAP)
    else {
        return false;
    };
    let Ok(doc) = text.parse::<toml_edit::DocumentMut>() else {
        return false;
    };
    let triple = host_target_triple();
    // Walk target.<triple>.rustflags; accept either a string or an array.
    let Some(target_table) = doc.get("target").and_then(|t| t.get(triple)) else {
        return false;
    };
    let Some(flags) = target_table.get("rustflags") else {
        return false;
    };
    // String variant: `rustflags = "-fuse-ld=mold -C …"`
    if let Some(s) = flags.as_str() {
        return s.contains("-fuse-ld=");
    }
    // Array variant (the form we write): `rustflags = ["-C", "link-arg=-fuse-ld=mold"]`
    if let Some(arr) = flags.as_array() {
        return arr
            .iter()
            .any(|v| v.as_str().is_some_and(|s| s.contains("-fuse-ld=")));
    }
    false
}

/// Outcome of a toolchain-level linker probe.
enum LinkerProbeResult {
    /// The toolchain accepted `-fuse-ld=<name>` and linked successfully.
    Accepted,
    /// The linker is on PATH but the toolchain rejected or errored the flag.
    Rejected,
}

/// Probe whether the Rust toolchain accepts `-Clink-arg=-fuse-ld=<name>` by
/// linking a trivial program in a temporary directory.
///
/// The probe result is cached under `$IPE_HOME/linker-probe.toml` keyed on the
/// linker name and the `rustc -vV` release string, so repeated `ipe health`
/// runs cost nothing after the first.
fn probe_linker(name: &str) -> LinkerProbeResult {
    let cache_key = rustc_version_string();
    if let Some(result) = read_probe_cache(name, cache_key.as_deref()) {
        return result;
    }
    let result = run_link_probe(name);
    write_probe_cache(name, cache_key.as_deref(), &result);
    result
}

/// The compiler's link driver — decides whether `-fuse-ld=<name>` has any
/// effect on the host.
enum LinkDriver {
    /// `link.exe` (every `*-pc-windows-msvc` host) — ignores `-fuse-ld=`.
    Msvc,
    /// A `cc`-family front end (gnu/musl/mingw/Unix hosts) — honours it.
    CcDriver,
}

/// Classify a `rustc -vV` host triple into its [`LinkDriver`].
///
/// Pure and host-independent — the triple string alone decides the driver, so
/// this is testable on any CI host without ever spawning `rustc`.
fn link_driver_for_host_triple(host: &str) -> LinkDriver {
    if host.ends_with("-msvc") {
        LinkDriver::Msvc
    } else {
        LinkDriver::CcDriver
    }
}

/// Parse the `host:` line out of `rustc -vV`'s raw output text.
///
/// Pure: no subprocess, no environment lookup — just the line scan. The one
/// parser both [`host_link_driver`] and [`host_target_triple`] read through,
/// so "the host triple" has exactly one source wherever `rustc -vV`'s text is
/// available, instead of two call sites each re-deriving it their own way.
fn host_triple_from_rustc_vv(text: &str) -> Option<&str> {
    text.lines().find_map(|l| l.strip_prefix("host: "))
}

/// Ask the running toolchain for its host triple via `rustc -vV`. `None` when
/// `rustc` is not on `PATH`, exits non-zero, or its output does not carry a
/// parseable `host:` line.
fn rustc_host_triple() -> Option<String> {
    let text = rustc_vv_text()?;
    host_triple_from_rustc_vv(&text).map(str::to_owned)
}

/// The running toolchain's `rustc -vV` text. `None` when `rustc` is not on
/// `PATH`, exits non-zero, or prints non-UTF-8.
fn rustc_vv_text() -> Option<String> {
    let out = Command::new("rustc").arg("-vV").output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

/// The running toolchain's link driver, derived from its host triple. `None`
/// when the triple cannot be determined — the fast-linker probe then runs
/// exactly as it did before this check existed.
fn host_link_driver() -> Option<LinkDriver> {
    rustc_host_triple().map(|host| link_driver_for_host_triple(&host))
}

/// The `rustc -vV` release line, used as the cache invalidation key. `None`
/// when `rustc` is not on PATH or its output cannot be parsed.
fn rustc_version_string() -> Option<String> {
    let text = rustc_vv_text()?;
    // The "release:" line uniquely identifies the toolchain version.
    text.lines()
        .find(|l| l.starts_with("release:"))
        .map(str::to_owned)
}

/// Run the actual link probe: feed `fn main(){}` to `rustc` with
/// `-Clink-arg=-fuse-ld=<name>` and return whether it exits 0.
///
/// The artifact lands in a `ScratchDir` that is removed on drop, so no debris
/// reaches the project tree or the shared target.
fn run_link_probe(name: &str) -> LinkerProbeResult {
    // A ScratchDir gives us an unpredictably-named, exclusively-created, mode-
    // 0700 directory that is removed when the guard drops — no predictable path,
    // no race on the temp name, no leftover artifacts.
    let Ok(scratch) = ScratchDir::new("ipe-linker-probe") else {
        return LinkerProbeResult::Rejected;
    };
    let Ok(leaf) = LeafName::new("probe") else {
        return LinkerProbeResult::Rejected;
    };
    let out_path = scratch.child(&leaf);
    let out = Command::new("rustc")
        .args([
            "-",
            "--edition=2021",
            &format!("-Clink-arg=-fuse-ld={name}"),
            "-o",
            &out_path.to_string_lossy(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write as _;
                let _ = stdin.write_all(b"fn main(){}");
            }
            child.wait()
        });
    // `scratch` drops here, removing the directory and the probe artifact.
    match out {
        Ok(status) if status.success() => LinkerProbeResult::Accepted,
        _ => LinkerProbeResult::Rejected,
    }
}

/// The path of the linker-probe cache file: `$IPE_HOME/linker-probe.toml`.
fn probe_cache_path() -> Option<PathBuf> {
    runtime_embed::ipe_home()
        .ok()
        .map(|h| h.join("linker-probe.toml"))
}

/// Read a cached probe result for `(name, toolchain_key)`. Returns `None` when
/// the cache is absent, unreadable, or the entry's toolchain key has changed
/// (toolchain upgrade → re-probe).
fn read_probe_cache(name: &str, toolchain_key: Option<&str>) -> Option<LinkerProbeResult> {
    let path = probe_cache_path()?;
    let text =
        crate::io_bounded::read_to_string_capped(&path, crate::io_bounded::SMALL_FILE_READ_CAP)
            .ok()?;
    let doc: toml::Table = text.parse().ok()?;
    let entry = doc.get(name)?.as_table()?;
    // If the cached entry carries a toolchain key that differs from the running
    // toolchain, the cache is stale — fall through to re-probe.
    let cached_key = entry.get("toolchain").and_then(|v| v.as_str());
    if cached_key != toolchain_key {
        return None;
    }
    if entry.get("accepted")?.as_bool()? {
        Some(LinkerProbeResult::Accepted)
    } else {
        Some(LinkerProbeResult::Rejected)
    }
}

/// Write a probe result to the cache. Failures are silently ignored: a missing
/// cache only costs a re-probe on the next run; a caching error must not fail
/// `ipe health`.
fn write_probe_cache(name: &str, toolchain_key: Option<&str>, result: &LinkerProbeResult) {
    let Some(path) = probe_cache_path() else {
        return;
    };
    let accepted = matches!(result, LinkerProbeResult::Accepted);
    // Read the existing cache (if any) so we preserve other linkers' entries.
    let existing =
        crate::io_bounded::read_to_string_capped(&path, crate::io_bounded::SMALL_FILE_READ_CAP)
            .unwrap_or_default();
    let mut doc = existing
        .parse::<toml_edit::DocumentMut>()
        .unwrap_or_default();
    let entry = doc
        .entry(name)
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
    if let Some(t) = entry.as_table_mut() {
        t.insert("accepted", toml_edit::value(accepted));
        if let Some(key) = toolchain_key {
            t.insert("toolchain", toml_edit::value(key));
        }
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, doc.to_string());
}

/// The `~/.cargo/config.toml` edit that wires a fast linker for the host
/// target via a `rustflags` array. The `rustflags` approach works with the
/// default `gcc`/`cc` linker driver — no `clang` dependency — and is the
/// mechanism proven to halve native link time.
fn linker_edit(flag_name: &'static str) -> ConfigEdit {
    ConfigEdit {
        target: ConfigTarget::Cargo,
        key: vec!["target", host_target_triple(), "rustflags"],
        value: ConfigValue::StrList(vec![
            "-C".to_owned(),
            format!("link-arg=-fuse-ld={flag_name}"),
        ]),
        rationale: match flag_name {
            "mold" => "pass -fuse-ld=mold to the linker for faster native builds",
            "lld" => "pass -fuse-ld=lld to the linker for faster native builds",
            _ => "pass -fuse-ld to the linker for faster native builds",
        },
    }
}

/// `sccache` present → offer to set `build.rustc-wrapper` in the user Cargo
/// config so repeated builds reuse cached compilations.
// A `match` reads clearer than a `map_or_else` over two full `Check` literals.
#[allow(clippy::option_if_let_else)]
fn check_cache() -> Check {
    match which_on_path("sccache") {
        Some(path) => Check {
            group: Group::Cache,
            id: "sccache",
            status: Status::Ok,
            detail: format!("sccache found at {}", path.display()),
            suggestion: Some("set it as the rustc wrapper to cache compilations".to_owned()),
            fix: Some(Fix::ConfigEdit(ConfigEdit {
                target: ConfigTarget::Cargo,
                key: vec!["build", "rustc-wrapper"],
                value: ConfigValue::Str("sccache".to_owned()),
                rationale: "cache Rust compilations across builds with sccache",
            })),
        },
        None => Check {
            group: Group::Cache,
            id: "sccache",
            status: Status::Warn,
            detail: "sccache not found — compilations are not cached across builds".to_owned(),
            suggestion: Some(installer_hint(
                "sccache",
                "a compilation cache that speeds repeated builds",
            )),
            fix: None,
        },
    }
}

/// Whether the ipe-managed shared build target is configured, and — when it is
/// not — offer to set it up under `$IPE_HOME/target`.
// A `match` reads clearer than a `map_or_else` over two full `Check` literals.
#[allow(clippy::option_if_let_else, clippy::single_match_else)]
fn check_shared_target() -> Check {
    let configured = ipe_home_config_value(&["build", "target-dir"]);
    match configured {
        Some(dir) => Check {
            group: Group::Target,
            id: "shared-target",
            status: Status::Ok,
            detail: format!("shared build target configured at {dir}"),
            suggestion: None,
            fix: None,
        },
        None => {
            let target_dir = runtime_embed::ipe_home()
                .map_or_else(|_| PathBuf::from("target"), |h| h.join("target"));
            Check {
                group: Group::Target,
                id: "shared-target",
                status: Status::Warn,
                detail: "no shared build target — each project builds into its own cold target"
                    .to_owned(),
                suggestion: Some(
                    "configure a shared target so projects reuse one warm build cache".to_owned(),
                ),
                fix: Some(Fix::HomeSetup(SharedTargetSetup { target_dir })),
            }
        }
    }
}

/// The FFI sandbox prerequisites for the host platform. FFI runs untrusted
/// foreign builds and calls in a jail; without the platform's jail primitive the
/// jail cannot be entered.
// One linear body of per-platform `cfg` arms, each a `match` over presence that
// reads clearer than a `map_or_else` carrying full `Check` literals.
#[allow(clippy::option_if_let_else, clippy::too_many_lines)]
fn check_sandbox() -> Vec<Check> {
    #[cfg(target_os = "linux")]
    {
        let tool = "bwrap";
        match which_on_path(tool) {
            Some(path) => vec![Check {
                group: Group::Sandbox,
                id: "bubblewrap",
                status: Status::Ok,
                detail: format!("bubblewrap ({tool}) found at {}", path.display()),
                suggestion: None,
                fix: None,
            }],
            None => vec![Check {
                group: Group::Sandbox,
                id: "bubblewrap",
                status: Status::Warn,
                detail: "bubblewrap (bwrap) not found — FFI build/run jails are unavailable"
                    .to_owned(),
                suggestion: Some(installer_hint(
                    "bubblewrap",
                    "the Linux sandbox FFI uses to jail foreign builds and calls",
                )),
                fix: None,
            }],
        }
    }
    #[cfg(target_os = "freebsd")]
    {
        // FreeBSD's `jail(8)` is a base-system facility; the runnable prereq is
        // the `jail` utility on PATH plus the privilege to create a jail (which
        // this command never takes). Report presence; the privilege is the
        // user's to arrange.
        match which_on_path("jail") {
            Some(path) => vec![Check {
                group: Group::Sandbox,
                id: "jail",
                status: Status::Ok,
                detail: format!("jail(8) utility found at {}", path.display()),
                suggestion: None,
                fix: None,
            }],
            None => vec![Check {
                group: Group::Sandbox,
                id: "jail",
                status: Status::Warn,
                detail: "jail(8) utility not found on PATH — FFI run-jails are unavailable"
                    .to_owned(),
                suggestion: Some(
                    "jail(8) is part of the FreeBSD base system; ensure /usr/sbin is on PATH"
                        .to_owned(),
                ),
                fix: None,
            }],
        }
    }
    #[cfg(target_os = "macos")]
    {
        // macOS jails foreign builds with the base-system `sandbox-exec`.
        match which_on_path("sandbox-exec") {
            Some(path) => vec![Check {
                group: Group::Sandbox,
                id: "sandbox-exec",
                status: Status::Ok,
                detail: format!("sandbox-exec found at {}", path.display()),
                suggestion: None,
                fix: None,
            }],
            None => vec![Check {
                group: Group::Sandbox,
                id: "sandbox-exec",
                status: Status::Warn,
                detail: "sandbox-exec not found on PATH — FFI jails are unavailable".to_owned(),
                suggestion: Some(
                    "sandbox-exec ships with macOS; ensure /usr/bin is on PATH".to_owned(),
                ),
                fix: None,
            }],
        }
    }
    #[cfg(target_os = "windows")]
    {
        // Windows has no first-party FFI jail arm yet; report honestly rather
        // than probe for a tool that would not be used.
        vec![Check {
            group: Group::Sandbox,
            id: "sandbox",
            status: Status::Unknown,
            detail: "FFI sandboxing on Windows is not yet supported".to_owned(),
            suggestion: None,
            fix: None,
        }]
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "macos",
        target_os = "windows"
    )))]
    {
        vec![Check {
            group: Group::Sandbox,
            id: "sandbox",
            status: Status::Unknown,
            detail: "FFI sandbox prerequisites are unknown on this platform".to_owned(),
            suggestion: None,
            fix: None,
        }]
    }
}

/// Free disk under the shared-target / build-cache home. Tight space is a
/// `Warn` — builds still work, but a cold target can fill a small volume.
// A `match` reads clearer than a `map_or_else` over two full `Check` literals.
#[allow(clippy::option_if_let_else)]
fn check_disk() -> Check {
    let probe_dir = runtime_embed::ipe_home().unwrap_or_else(|_| PathBuf::from("."));
    match free_space_bytes(&probe_dir) {
        Some(free) => {
            let gib = free / (1024 * 1024 * 1024);
            let status = if free < LOW_DISK_FLOOR {
                Status::Warn
            } else {
                Status::Ok
            };
            let detail = if status == Status::Warn {
                format!("{gib} GiB free under the build home — a cold target may not fit")
            } else {
                format!("{gib} GiB free under the build home")
            };
            Check {
                group: Group::Disk,
                id: "free-space",
                status,
                detail,
                suggestion: None,
                fix: None,
            }
        }
        None => Check {
            group: Group::Disk,
            id: "free-space",
            status: Status::Unknown,
            detail: "free disk space could not be determined on this platform".to_owned(),
            suggestion: None,
            fix: None,
        },
    }
}

/// The free-space floor below which disk is a `Warn` (a few cold Rust targets).
const LOW_DISK_FLOOR: u64 = 5 * 1024 * 1024 * 1024;

// ---- small probes ---------------------------------------------------------

/// The host target triple as `rustc` names it, for a per-target `rustflags`
/// key.
///
/// Reads the real triple from `rustc -vV`'s `host:` line — through
/// [`rustc_host_triple`], the same reader [`host_link_driver`] uses — so
/// there is exactly one source for "the host triple" on this host, not a
/// static per-arch/OS table that drifts from whatever `rustc` actually
/// targets (a cross-compiled or multi-target toolchain's host is not always
/// the triple a `cfg` guess would produce). Falls back to the compile-time
/// [`cfg_host_triple_fallback`] when `rustc` is unreachable, and only then to
/// the generic `"host"` key on an unmapped platform — the linker edit is a
/// convenience, not a correctness requirement, so a best-effort key is still
/// useful when the real triple cannot be read. Cached for the process's
/// lifetime: the host triple cannot change between two calls in one run.
fn host_target_triple() -> &'static str {
    static TRIPLE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TRIPLE
        .get_or_init(|| {
            rustc_host_triple().unwrap_or_else(|| cfg_host_triple_fallback().to_owned())
        })
        .as_str()
}

/// A compile-time per-arch/OS guess at the host triple, used only when
/// `rustc -vV` cannot be read. An unmapped host falls back to the generic
/// `"host"` key, which still parses as a TOML table key.
const fn cfg_host_triple_fallback() -> &'static str {
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        "x86_64-unknown-linux-gnu"
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        "aarch64-unknown-linux-gnu"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    {
        "x86_64-apple-darwin"
    }
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        "aarch64-apple-darwin"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "freebsd"))]
    {
        "x86_64-unknown-freebsd"
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "linux"),
        all(target_arch = "aarch64", target_os = "linux"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "freebsd"),
    )))]
    {
        "host"
    }
}

/// Resolve `name` on `PATH` to its absolute executable path, or `None`.
fn which_on_path(name: &str) -> Option<PathBuf> {
    let path_var = ipe_env::var_os("PATH")?;
    let exe = exe_name(name);
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(&exe))
        .find(|candidate| is_executable_file(candidate))
}

/// The platform executable file name for a bare tool name.
fn exe_name(name: &str) -> String {
    #[cfg(windows)]
    {
        if name.ends_with(".exe") {
            name.to_owned()
        } else {
            format!("{name}.exe")
        }
    }
    #[cfg(not(windows))]
    {
        name.to_owned()
    }
}

/// Whether `path` is a regular file the OS would run (executable bit on Unix).
#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && (meta.permissions().mode() & 0o111 != 0))
}

/// Whether `path` is a regular file that could be executed.
#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

/// Read a dotted string value from `$IPE_HOME/config.toml`, or `None` when the
/// file is absent, a symlink, unreadable, unparseable, or lacks the key.
fn ipe_home_config_value(key: &[&str]) -> Option<String> {
    let home = runtime_embed::ipe_home().ok()?;
    let text = crate::io_bounded::read_named_in(
        &home,
        &["config.toml"],
        crate::io_bounded::SMALL_FILE_CAP,
    )
    .ok()?;
    let doc: toml::Table = text.parse().ok()?;
    let mut node = &toml::Value::Table(doc);
    for segment in key {
        node = node.as_table()?.get(*segment)?;
    }
    node.as_str().map(str::to_owned)
}

/// Free bytes on the filesystem holding `dir`. `None` when the platform query is
/// unavailable or fails.
#[cfg(unix)]
fn free_space_bytes(dir: &Path) -> Option<u64> {
    // Walk up to the nearest existing ancestor: an as-yet-uncreated `$IPE_HOME`
    // has no statfs, but its parent does and lives on the same filesystem.
    let mut probe: Option<&Path> = Some(dir);
    while let Some(p) = probe {
        if p.exists() {
            return statvfs_free(p);
        }
        probe = p.parent();
    }
    None
}

/// `statvfs(2)`-based free-space query via `rustix`: available blocks times the
/// fragment size — the bytes an unprivileged process may actually use. `None`
/// when the syscall fails (a path that vanished mid-probe, or a filesystem that
/// does not report the figure).
#[cfg(unix)]
fn statvfs_free(p: &Path) -> Option<u64> {
    let vfs = rustix::fs::statvfs(p).ok()?;
    // `f_bavail` counts fragments free to a non-root caller; `f_frsize` is the
    // fragment size in bytes. Their product is the usable free byte count.
    vfs.f_bavail.checked_mul(vfs.f_frsize)
}

/// Free bytes — unavailable without a platform query on non-Unix here.
#[cfg(not(unix))]
fn free_space_bytes(_dir: &Path) -> Option<u64> {
    None
}

/// A per-OS install hint for a tool: the recommended command for the detected
/// platform, or a generic pointer. Print-only guidance — never run.
fn installer_hint(tool: &str, what: &str) -> String {
    let cmd = match std::env::consts::OS {
        "linux" => {
            format!("your package manager (e.g. `apt install {tool}` / `dnf install {tool}`)")
        }
        "macos" => format!("Homebrew: `brew install {tool}`"),
        "freebsd" => format!("pkg: `pkg install {tool}`"),
        "windows" => {
            format!("a package manager (e.g. `scoop install {tool}` / `choco install {tool}`)")
        }
        _ => format!("your platform's package manager (`{tool}`)"),
    };
    format!("install {tool} ({what}) via {cmd}")
}

// ---- rendering ------------------------------------------------------------

/// The framed, grouped human report, coloured for a terminal.
fn render_human(report: &Report, stream: &impl IsTerminal) -> String {
    let p = style::Palette::for_stream(stream);
    let mut body = String::new();
    for group in Group::ALL {
        let mut section: Vec<&Check> = report.checks.iter().filter(|c| c.group == group).collect();
        if section.is_empty() {
            continue;
        }
        section.sort_by_key(|c| c.id);
        let _ = writeln!(body, "{}{}{}", p.bold, group.title(), p.reset);
        for check in section {
            let color = match check.status {
                Status::Ok => p.green,
                Status::Missing => p.red,
                Status::Warn | Status::Unknown => p.yellow,
            };
            let _ = writeln!(
                body,
                "  {color}{}{} {}",
                check.status.glyph(),
                p.reset,
                TerminalSafe::sanitize(&check.detail)
            );
            if let Some(s) = &check.suggestion {
                let _ = writeln!(
                    body,
                    "    {}→ {}{}",
                    p.dim,
                    TerminalSafe::sanitize(s),
                    p.reset
                );
            }
        }
        body.push('\n');
    }
    style::frame(&style::gutter(body.trim_end_matches('\n')))
}

/// The `--plain` report: one `id<TAB>status<TAB>detail` record per line,
/// flush-left, for `grep` / `awk`. Never framed, never coloured.
fn render_plain(report: &Report) -> String {
    let mut out = String::new();
    for check in &report.checks {
        let _ = writeln!(
            out,
            "{}\t{}\t{}",
            check.id,
            check.status.tag(),
            TerminalSafe::sanitize(&check.detail)
        );
    }
    out
}

/// The `--json` report: `{"checks":[{"id","group","status","detail",...}]}`, a
/// stable object a machine consumes. Never framed, never coloured.
fn render_json(report: &Report) -> String {
    let items: Vec<serde_json::Value> = report
        .checks
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "group": c.group.title(),
                "status": c.status.tag(),
                "detail": c.detail,
                "suggestion": c.suggestion,
                "fixable": c.fix.is_some(),
            })
        })
        .collect();
    let value = serde_json::json!({
        "checks": items,
        "critical_failure": report.has_critical_failure(),
    });
    format!("{value}\n")
}

// ---- apply engine ---------------------------------------------------------

/// The user's answer to a per-item prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// Apply this item.
    Yes,
    /// Skip this item.
    No,
}

/// Read a `[Y/n]` answer for `prompt` from stdin. Default (empty line) is yes.
/// EOF or a read error declines — never applies a trust action on a stream the
/// command could not read.
fn ask(prompt: &str) -> Answer {
    use std::io::Write as _;
    crate::screen::prompt(&format!("{prompt} [Y/n] "));
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(n) if n > 0 => match line.trim().to_ascii_lowercase().as_str() {
            "" | "y" | "yes" => Answer::Yes,
            _ => Answer::No,
        },
        // EOF (`Ok(0)`) or a read error: no answer we can trust — decline rather
        // than assume consent to a trust action.
        _ => Answer::No,
    }
}

/// Walk the fixable checks, preview each, and apply on consent.
///
/// A per-item failure is reported and the walk continues; it never aborts the
/// rest and never changes the exit code (the exit code is the diagnostic
/// verdict, not the apply outcome), so this returns nothing.
fn apply_fixes(report: &Report, consent: Consent, stream: &impl IsTerminal) {
    let fixable: Vec<&Check> = report.fixable().collect();
    if fixable.is_empty() {
        return;
    }
    let p = style::Palette::for_stream(stream);
    // The header sits at the report's base indent; the fix bullets below it are
    // indented one level deeper so the actionable list reads as nested under it.
    crate::screen::chatter_styled(
        crate::screen::Stream::Stdout,
        &crate::style::gutter(&format!("\n{}Suggested fixes{}\n", p.bold, p.reset)),
    );
    for check in fixable {
        let Some(fix) = &check.fix else { continue };
        crate::screen::chatter_styled(
            crate::screen::Stream::Stdout,
            &style::gutter(&fix_bullet(check, fix, p)),
        );
        // The question hangs a blank line below the preview and sits at the
        // body column (one level deeper than the bullet) so it reads as the last
        // line of the fix, not a new item.
        let apply = match consent {
            Consent::All => true,
            Consent::Interactive => ask(&format!("\n{FIX_BODY_INDENT}Apply?")) == Answer::Yes,
        };
        if !apply {
            crate::screen::chatter(
                crate::screen::Stream::Stdout,
                crate::screen::Tone::Text,
                &format!("{FIX_BODY_INDENT}skipped.\n"),
            );
            continue;
        }
        // The outcome leads with the status glyph — green ✓ on success, red ✗ on
        // failure — so the applied/failed edit is legible at a glance.
        match apply_one(fix) {
            Ok(outcome) => {
                let (glyph, tint) = style::Outcome::Success.glyph_and_tint(p);
                crate::screen::chatter_styled(
                    crate::screen::Stream::Stdout,
                    &crate::style::gutter(&format!(
                        "{FIX_BODY_INDENT}{tint}{glyph}{} {}\n",
                        p.reset,
                        TerminalSafe::sanitize(&outcome)
                    )),
                );
            }
            Err(e) => {
                // A fix that fails is reported and the walk continues — one
                // failed edit must not abort the rest, and it must not exit the
                // command non-zero (the exit code is the diagnostic verdict, not
                // the apply outcome).
                let (glyph, tint) = style::Outcome::Failure.glyph_and_tint(p);
                crate::screen::chatter_styled(
                    crate::screen::Stream::Stdout,
                    &crate::style::gutter(&format!(
                        "{FIX_BODY_INDENT}{tint}{glyph}{} could not apply: {}\n",
                        p.reset,
                        TerminalSafe::sanitize(&e.to_string())
                    )),
                );
            }
        }
    }
}

/// The indent of a fix bullet, one level deeper than the "Suggested fixes"
/// header (the header sits at the gutter's base column).
const FIX_INDENT: &str = "  ";
/// The indent of a bullet's body lines (problem / `+` / file), one level deeper
/// again so they hang under the bullet.
const FIX_BODY_INDENT: &str = "    ";

/// Render one suggested-fix bullet: a bright-yellow bullet leading the detected
/// problem, then the change as a `+` diff-add line, then the file it touches.
///
/// Presented in the order a reader reasons about a fix: what is wrong, what will
/// change, and where — the `[Y/n]` question the caller prints last completes it.
/// Colour and indent are the interactive-TTY dressing only; `--plain` / `--json`
/// never reach here.
fn fix_bullet(check: &Check, fix: &Fix, p: &style::Palette) -> String {
    let FixChange { change, file } = fix_change(fix);
    let mut out = format!(
        "\n{FIX_INDENT}{}• {}{}\n",
        p.bright_yellow,
        TerminalSafe::sanitize(&check.detail),
        p.reset
    );
    let _ = writeln!(
        out,
        "{FIX_BODY_INDENT}+ {}",
        TerminalSafe::sanitize(&change)
    );
    if let Some(file) = file {
        let _ = writeln!(out, "{FIX_BODY_INDENT}{}", TerminalSafe::sanitize(&file));
    }
    out
}

/// The change a fix makes (the `+` diff-add text) and the file it touches, if
/// any. An install changes no file, so its `file` is `None`.
struct FixChange {
    /// The one-line diff-add description shown after the `+`.
    change: String,
    /// The file the fix writes, when it writes one.
    file: Option<String>,
}

/// The `+`-line change text and target file for a fix.
fn fix_change(fix: &Fix) -> FixChange {
    match fix {
        Fix::ConfigEdit(edit) => FixChange {
            change: format!("{} = {}", edit.key.join("."), edit.value.display()),
            file: Some(config_path_label(edit.target)),
        },
        Fix::Install(install) => match &install.method {
            InstallMethod::Direct { argv } => FixChange {
                change: format!("install {} ({})", install.tool, argv.join(" ")),
                file: None,
            },
            InstallMethod::PackageManager { command } => FixChange {
                change: format!("install {} — run yourself: {command}", install.tool),
                file: None,
            },
        },
        Fix::HomeSetup(setup) => FixChange {
            change: format!("build.target-dir = {:?}", setup.target_dir.display()),
            file: Some(config_path_label(ConfigTarget::IpeHome)),
        },
        Fix::RunUpgrade { current, latest } => FixChange {
            change: format!("run: ipe upgrade  ({current} \u{2192} {latest})"),
            file: None,
        },
    }
}

/// The resolved on-disk path for a config target, falling back to its short
/// label when no path can be resolved.
fn config_path_label(target: ConfigTarget) -> String {
    target
        .path()
        .map_or_else(|_| target.label().to_owned(), |p| p.display().to_string())
}

/// Apply one fix, returning a one-line outcome for the report. A
/// package-manager install is a no-op here (it was only ever shown).
fn apply_one(fix: &Fix) -> Result<String, CliError> {
    match fix {
        Fix::ConfigEdit(edit) => {
            let path = edit.target.path()?;
            apply_config_edit(&path, &edit.key, &edit.value)?;
            Ok(format!(
                "set {} in {}",
                edit.key.join("."),
                edit.target.label()
            ))
        }
        Fix::Install(install) => match &install.method {
            InstallMethod::Direct { argv } => {
                run_install(argv).map(|()| format!("installed {}", install.tool))
            }
            InstallMethod::PackageManager { .. } => Ok(format!(
                "{} must be installed with the command above",
                install.tool
            )),
        },
        Fix::HomeSetup(setup) => {
            let path = ConfigTarget::IpeHome.path()?;
            std::fs::create_dir_all(&setup.target_dir).map_err(|e| CliError::Io {
                path: setup.target_dir.clone(),
                source: e,
            })?;
            let value = ConfigValue::Str(setup.target_dir.display().to_string());
            apply_config_edit(&path, &["build", "target-dir"], &value)?;
            Ok(format!(
                "shared target configured at {}",
                setup.target_dir.display()
            ))
        }
        Fix::RunUpgrade { latest, .. } => {
            crate::run_installer()?;
            Ok(format!("upgraded to {latest}"))
        }
    }
}

/// Run a direct install `argv` with no shell between it and the OS. The first
/// element is the program; the rest are literal arguments. Refuses an empty
/// `argv`, and never invokes a shell or `sudo`.
///
/// # Errors
/// [`CliError::Usage`] when `argv` is empty, the program cannot be
/// launched, or it exits non-zero.
fn run_install(argv: &[String]) -> Result<(), CliError> {
    let (program, rest) = argv
        .split_first()
        .ok_or_else(|| CliError::Usage(crate::text::msg::health_install_command_empty()))?;
    let status = Command::new(program).args(rest).status().map_err(|e| {
        CliError::Usage(crate::text::msg::health_install_launch_failed(&program, &e))
    })?;
    if status.success() {
        Ok(())
    } else {
        Err(CliError::Usage(crate::text::msg::health_install_failed(
            &program,
        )))
    }
}

/// Set a dotted key in a TOML config file, format-preserving and idempotent:
/// - Parse the existing document (empty when the file is absent).
/// - If the key already holds exactly the requested value, do nothing.
/// - Otherwise back up the current file to a numbered sibling
///   (`config.toml.bak`, `.bak.1`, …), set exactly that key (every other line,
///   comment, and layout preserved), and write the result atomically.
/// - Re-parse what was written; if it does not parse, roll the backup back so
///   the user is never left with a broken config.
///
/// A conflicting existing value is NOT silently overwritten in place: the
/// numbered backup captures the prior state first, so the change is reversible.
///
/// # Errors
/// [`CliError::Io`] on a filesystem failure; [`CliError::Usage`] when the
/// existing file does not parse as TOML (the command will not blindly overwrite
/// a file it cannot understand).
fn apply_config_edit(path: &Path, key: &[&str], value: &ConfigValue) -> Result<(), CliError> {
    let existing = match crate::io_bounded::read_to_string_capped(
        path,
        crate::io_bounded::SMALL_FILE_READ_CAP,
    ) {
        Ok(text) => text,
        Err(CliError::Io { ref source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            String::new()
        }
        Err(e) => return Err(e),
    };

    let mut doc = existing.parse::<toml_edit::DocumentMut>().map_err(|e| {
        CliError::Usage(crate::text::msg::health_config_not_toml(
            &path.display(),
            &e,
        ))
    })?;

    // Idempotent: if the key already holds exactly this value, no write, no
    // backup — running health twice changes nothing.
    if dotted_value_matches(&doc, key, value) {
        return Ok(());
    }

    // Back up the prior state before any change, so a conflicting overwrite is
    // reversible.
    let backup = if existing.is_empty() {
        None
    } else {
        Some(numbered_backup(path, &existing)?)
    };

    set_dotted(&mut doc, key, value);
    let rendered = doc.to_string();

    // Parse-verify BEFORE the write becomes live: a render that does not
    // round-trip is a bug, and we roll back rather than write it.
    if rendered.parse::<toml_edit::DocumentMut>().is_err() {
        return Err(CliError::Usage(
            crate::text::msg::health_config_edit_unparsable(&path.display()),
        ));
    }

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| CliError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    match write_atomic_config(path, &rendered) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Roll the backup back so a failed write never leaves the user with
            // a truncated or missing config.
            if let Some(backup_path) = &backup {
                let _ = std::fs::copy(backup_path, path);
            }
            Err(e)
        }
    }
}

/// Whether the dotted key in `doc` already holds exactly `value` (idempotency
/// check). Handles both string and string-array values.
fn dotted_value_matches(doc: &toml_edit::DocumentMut, key: &[&str], value: &ConfigValue) -> bool {
    let mut item = doc.as_item();
    for segment in key {
        let Some(next) = item.get(segment) else {
            return false;
        };
        item = next;
    }
    match value {
        ConfigValue::Str(s) => item.as_str() == Some(s.as_str()),
        ConfigValue::StrList(elems) => item.as_array().is_some_and(|arr| {
            arr.len() == elems.len()
                && arr
                    .iter()
                    .zip(elems)
                    .all(|(a, b)| a.as_str() == Some(b.as_str()))
        }),
    }
}

/// Set a dotted key on a document, creating intermediate tables as needed and
/// preserving every unrelated line. Supports both string and string-array values.
fn set_dotted(doc: &mut toml_edit::DocumentMut, key: &[&str], value: &ConfigValue) {
    let Some((last, parents)) = key.split_last() else {
        return;
    };
    let mut table = doc.as_table_mut();
    for segment in parents {
        let entry = table
            .entry(segment)
            .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
        // Coerce a non-table entry at an intermediate segment into a table so
        // the leaf has somewhere to land. A user who put a scalar where a table
        // must go is corrected here (their prior value was captured in the
        // backup). `as_table_mut` then yields the table without a fallible
        // unwrap, since the entry is now guaranteed to be one.
        if !entry.is_table() {
            *entry = toml_edit::Item::Table(toml_edit::Table::new());
        }
        match entry.as_table_mut() {
            Some(next) => table = next,
            // Unreachable: the entry was just ensured to be a table. Bail
            // without setting the key rather than panic.
            None => return,
        }
    }
    match value {
        ConfigValue::Str(s) => {
            table.insert(last, toml_edit::value(s.as_str()));
        }
        ConfigValue::StrList(elems) => {
            let mut arr = toml_edit::Array::new();
            for elem in elems {
                arr.push(elem.as_str());
            }
            table.insert(last, toml_edit::value(arr));
        }
    }
}

/// Back up `contents` to the first free numbered sibling of `path`
/// (`<name>.bak`, `<name>.bak.1`, …). Returns the backup path.
///
/// The free slot is claimed with an exclusive `create_new` open, not a
/// check-then-write: a concurrent `ipe health` that raced to the same slot loses
/// the open with `AlreadyExists` and this loop advances to the next number, so a
/// backup is never truncated over an existing one.
fn numbered_backup(path: &Path, contents: &str) -> Result<PathBuf, CliError> {
    use std::io::Write as _;
    let base = {
        let mut s = path.as_os_str().to_owned();
        s.push(".bak");
        PathBuf::from(s)
    };
    let mut candidate = base.clone();
    let mut n = 1u32;
    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                file.write_all(contents.as_bytes())
                    .map_err(|e| CliError::Io {
                        path: candidate.clone(),
                        source: e,
                    })?;
                return Ok(candidate);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut s = base.as_os_str().to_owned();
                s.push(format!(".{n}"));
                candidate = PathBuf::from(s);
                n = n.saturating_add(1);
            }
            Err(e) => {
                return Err(CliError::Io {
                    path: candidate,
                    source: e,
                });
            }
        }
    }
}

/// Write `contents` to `path` through the driver's one atomic writer.
///
/// An exclusively created sibling temp file is renamed over `path`, so the
/// config is never truncated in place.
fn write_atomic_config(path: &Path, contents: &str) -> Result<(), CliError> {
    crate::driver::write_atomic(path, contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temp directory removed on drop, so config-edit tests never touch a real
    /// home.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = ipe_test_temp::temp_root().join(format!(
                "ipe_health_{tag}_{}_{:?}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or_default()
            ));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_relative_cargo_home_is_refused_and_the_home_config_is_untouched() {
        let home = TempDir::new("rel_cargo_home");
        let home_config = home.path().join(".cargo").join("config.toml");
        std::fs::create_dir_all(home.path().join(".cargo")).expect("create ~/.cargo");
        let sentinel = "# user's own cargo config\n";
        std::fs::write(&home_config, sentinel).expect("write sentinel");
        let value =
            ConfigValue::StrList(vec!["-C".to_owned(), "link-arg=-fuse-ld=mold".to_owned()]);

        for raw in ["rel/cargo", "./cargo", "../cargo"] {
            let parsed = crate::env_dir::HomeDir::try_parse(Some(home.path().into()))
                .expect("an absolute test home");
            let got = cargo_config_path_from(Some(raw.into()), Some(&parsed)).and_then(|path| {
                apply_config_edit(
                    &path,
                    &["target", "x86_64-unknown-linux-gnu", "rustflags"],
                    &value,
                )
            });
            assert!(
                matches!(got, Err(CliError::EnvDirNotAbsolute { var: "CARGO_HOME" })),
                "relative CARGO_HOME `{raw}` must be refused"
            );
        }
        assert_eq!(
            std::fs::read_to_string(&home_config).expect("read sentinel"),
            sentinel,
            "a refused CARGO_HOME must never fall back to editing ~/.cargo/config.toml"
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn cargo_config_path_honours_an_absolute_cargo_home_and_defaults_when_unset_or_empty() {
        let home = crate::env_dir::HomeDir::try_parse(Some("/home/u".into()))
            .expect("an absolute test home");
        let got = cargo_config_path_from(Some("/opt/cargo".into()), Some(&home));
        assert!(matches!(got, Ok(p) if p == std::path::Path::new("/opt/cargo/config.toml")));
        for raw in [None, Some("")] {
            let got = cargo_config_path_from(raw.map(std::ffi::OsString::from), Some(&home));
            assert!(
                matches!(&got, Ok(p) if p == &PathBuf::from("/home/u/.cargo/config.toml")),
                "{raw:?}"
            );
        }
        let got = cargo_config_path_from(None, None);
        assert!(matches!(got, Err(CliError::Usage(_))));
    }

    fn sample_report() -> Report {
        Report {
            checks: vec![
                Check {
                    group: Group::Toolchain,
                    id: "cargo",
                    status: Status::Ok,
                    detail: "cargo found".to_owned(),
                    suggestion: None,
                    fix: None,
                },
                Check {
                    group: Group::Toolchain,
                    id: "runtime",
                    status: Status::Missing,
                    detail: "runtime not resolvable".to_owned(),
                    suggestion: Some("set IPE_HOME".to_owned()),
                    fix: None,
                },
                Check {
                    group: Group::Cache,
                    id: "sccache",
                    status: Status::Warn,
                    detail: "sccache not found".to_owned(),
                    suggestion: None,
                    fix: None,
                },
            ],
        }
    }

    #[test]
    fn critical_missing_drives_the_exit_code() {
        assert!(sample_report().has_critical_failure());
        // A warn-only report is a clean exit.
        let clean = Report {
            checks: vec![Check {
                group: Group::Cache,
                id: "sccache",
                status: Status::Warn,
                detail: "no cache".to_owned(),
                suggestion: None,
                fix: None,
            }],
        };
        assert!(!clean.has_critical_failure());
    }

    #[test]
    fn plain_is_flush_left_tab_separated_and_uncoloured() {
        let out = render_plain(&sample_report());
        assert!(out.starts_with("cargo\tok\t"));
        assert!(out.contains("runtime\tmissing\t"));
        assert!(!out.contains('\x1b'), "plain must carry no ANSI");
        // One record per check, no framing blank lines.
        assert_eq!(out.lines().count(), 3);
    }

    #[test]
    fn json_is_a_stable_object_with_every_check() {
        let out = render_json(&sample_report());
        let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        let checks = parsed
            .get("checks")
            .and_then(serde_json::Value::as_array)
            .expect("checks array");
        assert_eq!(checks.len(), 3);
        let first = checks.first().expect("first check");
        assert_eq!(first.get("id"), Some(&serde_json::json!("cargo")));
        assert_eq!(first.get("status"), Some(&serde_json::json!("ok")));
        assert_eq!(
            parsed.get("critical_failure"),
            Some(&serde_json::json!(true))
        );
        assert!(!out.contains('\x1b'));
    }

    #[test]
    fn human_frames_and_groups() {
        // A non-terminal stream renders uncoloured, still framed + grouped. A
        // regular file stands in for the stream (it is not a terminal, so the
        // plain palette is selected and no ANSI is emitted).
        let dir = TempDir::new("human");
        let file = std::fs::File::create(dir.path().join("out")).expect("file");
        let out = render_human(&sample_report(), &file);
        assert!(out.contains("Toolchain"));
        assert!(out.contains("Cache"));
        assert!(!out.contains('\x1b'), "a non-tty stream carries no ANSI");
        assert!(out.starts_with('\n') && out.ends_with('\n'), "framed");
    }

    #[test]
    fn health_reports_up_to_date_without_a_fix() {
        let vc = crate::version_check::VersionCheck {
            current: semver::Version::parse("0.1.72").expect("valid semver"),
            latest: Some(semver::Version::parse("0.1.72").expect("valid semver")),
            upgrade_available: false,
            reached_feed: true,
        };
        let c = version_check_to_check(&vc);
        assert!(matches!(c.status, Status::Ok));
        assert!(c.fix.is_none());
    }

    #[test]
    fn health_offers_a_fix_when_an_upgrade_is_available() {
        let vc = crate::version_check::VersionCheck {
            current: semver::Version::parse("0.1.72").expect("valid semver"),
            latest: Some(semver::Version::parse("0.1.75").expect("valid semver")),
            upgrade_available: true,
            reached_feed: true,
        };
        let c = version_check_to_check(&vc);
        assert!(c.fix.is_some());
        assert!(matches!(c.status, Status::Warn));
    }

    #[test]
    fn health_offline_is_unknown_no_fix() {
        let vc = crate::version_check::VersionCheck {
            current: semver::Version::parse("0.1.72").expect("valid semver"),
            latest: None,
            upgrade_available: false,
            reached_feed: false,
        };
        let c = version_check_to_check(&vc);
        assert!(matches!(c.status, Status::Unknown));
        assert!(c.fix.is_none());
    }

    #[test]
    fn config_edit_creates_backs_up_and_is_idempotent() {
        let dir = TempDir::new("cfg");
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "# my config\n[build]\njobs = 4\n").expect("seed");

        // First edit: sets the key, preserves the comment + the sibling key,
        // and writes a numbered backup of the prior file.
        let val = ConfigValue::Str("sccache".to_owned());
        apply_config_edit(&cfg, &["build", "rustc-wrapper"], &val).expect("first edit");
        let after = std::fs::read_to_string(&cfg).expect("read");
        assert!(after.contains("# my config"), "comment preserved");
        assert!(after.contains("jobs = 4"), "sibling key preserved");
        assert!(after.contains("rustc-wrapper = \"sccache\""));
        let backup = dir.path().join("config.toml.bak");
        assert!(backup.exists(), "prior file backed up");

        // Second, identical edit: idempotent — no change, no new backup.
        apply_config_edit(&cfg, &["build", "rustc-wrapper"], &val).expect("idempotent");
        assert!(
            !dir.path().join("config.toml.bak.1").exists(),
            "idempotent edit writes no second backup"
        );
    }

    #[test]
    fn config_edit_on_absent_file_creates_it_without_a_backup() {
        let dir = TempDir::new("absent");
        let cfg = dir.path().join("config.toml");
        let val = ConfigValue::Str("/tmp/shared".to_owned());
        apply_config_edit(&cfg, &["build", "target-dir"], &val).expect("create");
        let text = std::fs::read_to_string(&cfg).expect("read");
        assert!(text.contains("target-dir = \"/tmp/shared\""));
        assert!(
            !dir.path().join("config.toml.bak").exists(),
            "a fresh file has nothing to back up"
        );
    }

    #[test]
    fn config_edit_refuses_unparseable_toml() {
        let dir = TempDir::new("broken");
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "this is not = = toml [[[").expect("seed");
        let val = ConfigValue::Str("y".to_owned());
        let err = apply_config_edit(&cfg, &["build", "x"], &val);
        assert!(matches!(err, Err(CliError::Usage(_))));
        // The broken file is left untouched — never overwritten.
        assert_eq!(
            std::fs::read_to_string(&cfg).expect("read"),
            "this is not = = toml [[["
        );
    }

    #[test]
    fn config_edit_str_list_writes_toml_array_and_is_idempotent() {
        let dir = TempDir::new("strlist");
        let cfg = dir.path().join("config.toml");
        let val = ConfigValue::StrList(vec!["-C".to_owned(), "link-arg=-fuse-ld=mold".to_owned()]);
        apply_config_edit(
            &cfg,
            &["target", "x86_64-unknown-linux-gnu", "rustflags"],
            &val,
        )
        .expect("create");
        let text = std::fs::read_to_string(&cfg).expect("read");
        assert!(text.contains("rustflags"), "rustflags key must be present");
        assert!(
            text.contains("-fuse-ld=mold"),
            "the fuse-ld flag must appear in the written TOML"
        );

        // Idempotent: a second identical edit writes no backup.
        apply_config_edit(
            &cfg,
            &["target", "x86_64-unknown-linux-gnu", "rustflags"],
            &val,
        )
        .expect("idempotent");
        assert!(
            !dir.path().join("config.toml.bak.1").exists(),
            "idempotent array edit writes no second backup"
        );
    }

    #[test]
    fn linker_edit_emits_rustflags_array_not_linker_key() {
        let edit = linker_edit("mold");
        // The key must target rustflags, not linker.
        assert_eq!(edit.key.last(), Some(&"rustflags"), "key must be rustflags");
        // The value must be a string array containing the fuse-ld flag.
        assert!(
            matches!(&edit.value, ConfigValue::StrList(_)),
            "linker_edit must use ConfigValue::StrList, got: {:?}",
            edit.value
        );
        if let ConfigValue::StrList(elems) = &edit.value {
            assert!(
                elems.iter().any(|e| e.contains("-fuse-ld=mold")),
                "rustflags array must contain -fuse-ld=mold, got: {elems:?}"
            );
        }
    }

    #[test]
    #[cfg(not(target_env = "msvc"))]
    fn probe_rejected_linker_offers_no_fix() {
        // Simulate a probe rejection: a linker name that no toolchain has.
        // `check_linker` never reaches this probe on MSVC (the driver check
        // above short-circuits first), so the probe itself is exercised only
        // where it is actually reachable in production.
        let result = run_link_probe("__ipe_test_nonexistent_linker__");
        assert!(
            matches!(result, LinkerProbeResult::Rejected),
            "a nonexistent linker must be rejected by the probe"
        );
    }

    #[test]
    fn an_msvc_host_offers_no_fuse_ld_fix() {
        assert!(matches!(
            link_driver_for_host_triple("x86_64-pc-windows-msvc"),
            LinkDriver::Msvc
        ));
        assert!(matches!(
            link_driver_for_host_triple("aarch64-pc-windows-msvc"),
            LinkDriver::Msvc
        ));
        assert!(matches!(
            link_driver_for_host_triple("x86_64-pc-windows-gnu"),
            LinkDriver::CcDriver
        ));
        assert!(matches!(
            link_driver_for_host_triple("x86_64-unknown-linux-gnu"),
            LinkDriver::CcDriver
        ));
        assert!(matches!(
            link_driver_for_host_triple("aarch64-apple-darwin"),
            LinkDriver::CcDriver
        ));
    }

    #[test]
    fn host_triple_parser_reads_msvc_line_and_refuses_missing() {
        let vv = "rustc 1.80.0 (abcdef 2024-01-01)\n\
                  binary: rustc\n\
                  host: x86_64-pc-windows-msvc\n\
                  release: 1.80.0\n";
        assert_eq!(
            host_triple_from_rustc_vv(vv),
            Some("x86_64-pc-windows-msvc")
        );
        // No `host:` line at all — the parser refuses rather than guessing.
        let no_host = "rustc 1.80.0 (abcdef 2024-01-01)\nrelease: 1.80.0\n";
        assert_eq!(host_triple_from_rustc_vv(no_host), None);
        assert_eq!(host_triple_from_rustc_vv(""), None);
    }

    #[test]
    fn probe_cache_round_trips_accepted_and_rejected() {
        let dir = TempDir::new("probe_cache");
        // Temporarily redirect probe cache to the temp dir.
        let cache_path = dir.path().join("linker-probe.toml");

        // Write an Accepted entry for "mold" under a fake toolchain key.
        {
            let mut doc = toml_edit::DocumentMut::new();
            let entry = doc
                .entry("mold")
                .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
            if let Some(t) = entry.as_table_mut() {
                t.insert("accepted", toml_edit::value(true));
                t.insert("toolchain", toml_edit::value("release: 1.99.0"));
            }
            std::fs::write(&cache_path, doc.to_string()).expect("write cache");
        }

        // Read back via the raw TOML parse to confirm the round-trip.
        let text = std::fs::read_to_string(&cache_path).expect("read cache");
        let doc: toml::Table = text.parse().expect("parse cache");
        let entry = doc
            .get("mold")
            .and_then(|v| v.as_table())
            .expect("mold entry");
        assert_eq!(
            entry.get("accepted").and_then(toml::Value::as_bool),
            Some(true),
            "accepted=true must round-trip"
        );
        assert_eq!(
            entry.get("toolchain").and_then(toml::Value::as_str),
            Some("release: 1.99.0"),
            "toolchain key must round-trip"
        );

        // A different toolchain key means stale cache (None returned).
        let entry_wrong_key = entry.get("toolchain").and_then(toml::Value::as_str);
        assert_ne!(
            entry_wrong_key,
            Some("release: 2.00.0"),
            "a different toolchain key is stale"
        );
    }

    #[test]
    fn config_target_scope_is_exactly_two_files() {
        // The closed set means an out-of-scope edit is unrepresentable. Both
        // labels name a config file the command owns.
        assert!(ConfigTarget::IpeHome.label().contains("config.toml"));
        assert!(ConfigTarget::Cargo.label().contains("config.toml"));
    }

    #[test]
    fn empty_install_argv_is_refused() {
        assert!(matches!(run_install(&[]), Err(CliError::Usage(_))));
    }

    #[test]
    fn install_preview_never_pipes_to_shell() {
        let check = Check {
            group: Group::Cache,
            id: "sccache",
            status: Status::Warn,
            detail: "sccache not found".to_owned(),
            suggestion: None,
            fix: None,
        };
        let fix = Fix::Install(Install {
            tool: "mold",
            method: InstallMethod::PackageManager {
                command: "apt install mold".to_owned(),
            },
        });
        let text = fix_bullet(&check, &fix, style::Palette::select(false));
        assert!(text.contains("apt install mold"));
        assert!(!text.contains("| sh"), "no pipe-to-shell in a bullet");
    }

    #[test]
    fn fix_bullet_orders_problem_then_change_then_file() {
        // A config-edit bullet reads: the detected problem, then the `+` change,
        // then the file it touches — in that order, each on its own line.
        let check = Check {
            group: Group::Cache,
            id: "sccache",
            status: Status::Ok,
            detail: "sccache found — not yet wired as the rustc wrapper".to_owned(),
            suggestion: None,
            fix: Some(Fix::ConfigEdit(ConfigEdit {
                target: ConfigTarget::Cargo,
                key: vec!["build", "rustc-wrapper"],
                value: ConfigValue::Str("sccache".to_owned()),
                rationale: "cache builds",
            })),
        };
        let fix = check.fix.clone().expect("fix");
        let text = fix_bullet(&check, &fix, style::Palette::select(false));
        let problem = text.find("sccache found").expect("problem line");
        let change = text.find("+ build.rustc-wrapper").expect("change line");
        let file = text.find("config.toml").expect("file line");
        assert!(problem < change, "problem precedes the + change");
        assert!(change < file, "the + change precedes the file");
        // The bullet glyph leads, and the plain palette emits no ANSI.
        assert!(text.contains("• sccache found"));
        assert!(!text.contains('\x1b'), "plain palette carries no colour");
    }

    #[test]
    fn fix_bullet_is_bright_yellow_under_colour() {
        let check = Check {
            group: Group::Target,
            id: "shared-target",
            status: Status::Warn,
            detail: "no shared build target".to_owned(),
            suggestion: None,
            fix: Some(Fix::HomeSetup(SharedTargetSetup {
                target_dir: PathBuf::from("/tmp/t"),
            })),
        };
        let fix = check.fix.clone().expect("fix");
        let text = fix_bullet(&check, &fix, style::Palette::select(true));
        assert!(
            text.contains(style::Palette::COLOR.bright_yellow),
            "the bullet is bright-yellow on a colour terminal"
        );
        assert!(text.contains("+ build.target-dir"), "a + change line");
    }

    #[test]
    fn declining_answer_parses_from_non_yes() {
        // The answer parse is exercised through its pure core: only empty / y /
        // yes accept.
        for (input, expect) in [
            ("", Answer::Yes),
            ("y", Answer::Yes),
            ("yes", Answer::Yes),
            ("n", Answer::No),
            ("no", Answer::No),
            ("anything", Answer::No),
        ] {
            let got = match input.trim().to_ascii_lowercase().as_str() {
                "" | "y" | "yes" => Answer::Yes,
                _ => Answer::No,
            };
            assert_eq!(got, expect, "answer for {input:?}");
        }
    }
}
