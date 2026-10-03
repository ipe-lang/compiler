//! `ipe package audit` — the SP4 universal Tier-1 package gate.
//!
//! The gate answers one question: is this package version safe and honest enough
//! for the curated index to serve it? It runs four checks over the working
//! package and is a hard **accept** or **reject with a diagnostic** — never a
//! warning that lets an unsafe version through. The author runs it locally as a
//! pre-flight; the index CI re-runs the SAME [`run_audit`] path as the
//! authoritative gate, so the two verdicts cannot diverge.
//!
//! The four Tier-1 checks (see
//! `docs/adr/0007-build-incrementality-and-release-infra.md`), each wired to existing machinery:
//!
//! 1. **Provenance panic-scan** — author-supplied FFI wrapper Rust
//!    (`*_bindings.rs` in the project's FFI cache) is scanned with the SAME token
//!    scanner the repo's abrupt-failure hook runs ([`panic_scan`]); an authored
//!    abrupt-failure construct there is a user error the package is rejected for,
//!    because that Rust compiles unsandboxed into the shipped artifact. Our
//!    EMITTED Rust is NOT the author's concern (plan §1a routes emitted-Rust hits
//!    to our CI, not the author's) and is already gated by the compiler's own
//!    `tools/panic-scan` CI over the backend `src/` templates — the backend even
//!    emits one deliberate, guarded polyfill `panic!` into every project — so the
//!    author gate scans ONLY author Rust, keeping the provenance boundary exact
//!    by construction.
//! 2. **Capability consistency** — the inferred capability set (the call-graph
//!    union that backs `ipe capabilities`) must EQUAL the manifest's declared
//!    `[capabilities]`. A used-but-undeclared capability is a hidden effect; a
//!    declared-but-unused one is an over-broad, misleading claim. Either rejects.
//! 3. **Enforced semver** — `ipe diff` / [`crate::diff::check_semver_bump`]
//!    between this version's public API and the previous published STABLE
//!    version; an under-bump rejects. A prerelease submission, and a first
//!    stable version (no stable predecessor), skip this check.
//! 4. **Supply chain** — `cargo-deny` over the emitted project's dependency
//!    graph, plus the resolver's content-hash re-assertion over any Ipê package
//!    dependencies (verify-before-trust, re-checked at publish).
//!
//! For a native-bearing package (one declaring the `native-ffi` axis or binding
//! a `[rust.dependencies]` crate) a fifth check, [`crate::audit_native::native_tier2`],
//! runs after the four Tier-1 checks: it builds and exercises the package's
//! native code inside a jail scoped to its declared capability set and
//! reconciles observed-vs-declared, fail-closed (ADR 0004). It genuinely
//! certifies only the wired-and-proven platforms (`linux-x64` under
//! bwrap+seccomp, `macos-arm64` under `sandbox-exec` Seatbelt, `freebsd-x64`
//! under `jail(8)`); other platforms remain a documented refuse-to-certify and
//! the surface never claims Tier-2 for them.
//!
//! Deferred (not this layer): Tier-2 on Windows. Its returning build jail landed,
//! but the audit's Tier-2 probe wrapper is a POSIX shell fixture driven through a
//! `/bin/sh` invocation prefix, and the Windows jail runs `payload[0]` directly
//! through `CreateProcessW` (no shell), so a Windows-native probe wrapper is
//! needed before the audit can certify there — a design change beyond a
//! `cfg`-gate promotion. Also deferred: run-time sandbox isolation hardening.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use ipe_ir::Capability;

use crate::CliError;
use crate::cli_args::OutputFormat;
use crate::project::{self, ProjectManifest};
use crate::published_version::PublishedVersion;
use crate::publisher::{BlessedPublisher, BlessingRefusal, SelfDeclaredPublisher};
use crate::scratch::ScratchDir;
use crate::text;

/// The package-gate checks, in the fixed order [`run_audit`] runs them. Naming
/// the check that rejected lets the diagnostic say exactly which gate failed.
///
/// The first four are the universal Tier-1 checks; [`Self::NativeTier2`] is the
/// native-code capability-enforcement check, appended only for native-bearing
/// packages (ADR 0004). [`Self::NativeBindingRegen`] is the prerequisite step
/// that runs before Tier-1 for native-bearing packages: it regenerates the FFI
/// bindings from the pinned `[rust.dependencies]` inside the sandbox so the
/// gate never trusts committed or absent bindings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// 0 — sandboxed FFI binding regeneration for native packages: runs the
    /// same jailed generator as `ipe rust install` does against the pinned
    /// `[rust.dependencies]`, writing gate-owned bindings the Tier-1 checks
    /// then read. Absent or committed bindings are never trusted.
    ///
    /// Also fires when a manifest declares `[rust.wrapper]` bindings: wrapper
    /// bindings are author-asserted (a local path with no registry pin, rev, or
    /// content hash), so the gate has no independent source to regenerate from
    /// and rejects the package at admission.
    NativeBindingRegen,
    /// 1a — abrupt-failure token scan over author-supplied FFI wrapper Rust.
    Provenance,
    /// 1b — inferred vs declared capability set.
    Capability,
    /// 1c — enforced semver bump vs the previous published version.
    Semver,
    /// 1d — `cargo-deny` + content-hash integrity over the dependency graph.
    SupplyChain,
    /// 1e — reserved-namespace ownership: a package whose module set claims a
    /// reserved prefix (`Ipe.*`, `Rust.*`) is refused unless it is the blessed
    /// first-party publisher's, so a third party cannot squat the trusted stdlib
    /// namespace.
    ReservedNamespace,
    /// Tier-2 — differential-confinement enforcement of a native package's
    /// declared capability set against what its built+exercised native code
    /// actually demands.
    NativeTier2,
}

impl Check {
    /// A short label for the check, shown in a passing line and a reject header.
    const fn label(self) -> &'static str {
        match self {
            Self::NativeBindingRegen => "native FFI binding regeneration",
            Self::Provenance => "provenance panic-scan",
            Self::Capability => "capability consistency",
            Self::Semver => "enforced semver",
            Self::SupplyChain => "supply chain",
            Self::ReservedNamespace => "reserved-namespace ownership",
            Self::NativeTier2 => "native Tier-2 capability enforcement",
        }
    }
}

/// A rejection from one check: the check that failed and a one-diagnostic
/// message naming exactly what is wrong and (where applicable) where.
///
/// A closed value — every reject the gate can emit is one of these, carrying its
/// own already-rendered message — so the CLI boundary need only print it and
/// exit non-zero. Making the reject a typed value rather than a bare string keeps
/// the check that failed inspectable by tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejection {
    /// Which Tier-1 check rejected the package.
    pub check: Check,
    /// The human-readable diagnostic: what is wrong, and where.
    pub message: String,
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "package audit rejected by the {} check:\n{}",
            self.check.label(),
            self.message
        )
    }
}

/// The compiler-derived facts a consumer needs to consent to a package: how its
/// entry program drives itself (the control model) and the effect axes it can
/// exercise (the capability set). Both are read from the compiler's own
/// derivation, never a second source — the control model projects the shape the
/// compiler pinned for `main`, and the capability set is the whole-tree inferred
/// union the capability-consistency check already computes.
///
/// A closed value: a package either exposes a runnable entry (whose control model
/// is one of the closed [`crate::delivery::ControlModel`] variants) or is a
/// library with no self-driving entry ([`ControlModelDisclosure::NotApplicable`]).
/// An entry that exists but cannot be classified is never represented here — it is
/// a fail-closed rejection before a [`Disclosure`] is ever built, so no permissive
/// default can be disclosed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Disclosure {
    /// The entry program's control model, or the library marker.
    control_model: ControlModelDisclosure,
    /// The capability axes the whole package can exercise — the same inferred
    /// union the capability-consistency check reconciles against the manifest.
    capabilities: BTreeSet<Capability>,
}

impl Disclosure {
    /// The disclosed control-model word — a closed-set model's own word, or
    /// `"library"` for a package with no runnable entry. The exact vocabulary the
    /// `ipe audit` JSON verdict discloses, so `ipe doc` speaks the same words.
    pub(crate) const fn control_model_word(&self) -> &'static str {
        self.control_model.word()
    }

    /// The disclosed capability axes, in the audit's canonical order — the same
    /// inferred union `ipe audit` discloses.
    pub(crate) const fn capabilities(&self) -> &BTreeSet<Capability> {
        &self.capabilities
    }
}

/// The control model disclosed for a package: the entry program's model, or the
/// marker for a library that exposes modules but runs no entry of its own.
///
/// There is deliberately no "unknown" variant. A runnable entry that cannot be
/// classified fails the audit closed (a program whose self-driving model we
/// cannot state must not be certified as safe), so the only representable states
/// are a known model or a genuine absence of one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlModelDisclosure {
    /// The entry program's compiler-pinned control model.
    Entry(crate::delivery::ControlModel),
    /// A library: it exposes modules but defines no runnable `main`, so it has no
    /// control model of its own. Honest absence, not a permissive default.
    NotApplicable,
}

impl ControlModelDisclosure {
    /// The word disclosed for this control model — a closed-set model's own word,
    /// or `"library"` for a package with no runnable entry.
    const fn word(self) -> &'static str {
        match self {
            Self::Entry(model) => model.word(),
            Self::NotApplicable => "library",
        }
    }
}

/// The already-built package the four checks read from: its parsed manifest, its
/// `package.ipe` path, and the directory it was emitted into. Preparing these once
/// keeps each check a pure function of a ready package rather than re-deriving
/// paths and re-building.
#[derive(Debug)]
struct Prepared {
    /// The parsed manifest (name, version, declared capabilities, deps).
    manifest: ProjectManifest,
    /// The `package.ipe` path (the semver check's public-API extraction root is
    /// its parent; the build's blame path).
    manifest_path: PathBuf,
    /// The directory the package was emitted into (the `cargo-deny` target for
    /// the supply-chain check).
    emitted_dir: PathBuf,
}

/// `ipe package audit [<path>]` — run the full Tier-1 gate on the working
/// package and exit non-zero with the failing check's diagnostic.
///
/// `<path>` is a project directory or a `package.ipe` (defaults to the current
/// directory). The package MUST be a project (have a `package.ipe`): the gate
/// checks a publishable package, and the manifest carries the declared
/// capabilities, version, and dependency graph every check reads.
///
/// # Errors
/// [`CliError::Usage`] / [`CliError::Usage`] on argument misuse or a
/// package with no manifest; [`CliError::Pipeline`] / [`CliError::Io`] when the
/// package cannot be built or read; [`CliError::PackageAudit`] when a Tier-1
/// check rejects the package (the gate's hard reject).
pub fn run_audit(rest: &[String]) -> Result<(), CliError> {
    let unproven = BlessingRefusal::NoProvenIdentity;
    run_audit_as(rest, Err(&unproven))
}

/// [`run_audit`] under a proven publisher standing.
///
/// `blessing` is the [`BlessedPublisher`] an authenticated (`ipe package publish`) or attested
/// (`ipe package audit-entry`) identity established for the claimed
/// `--publisher`, or the [`BlessingRefusal`] saying why none was. Only a
/// blessing covering the claimed publisher exempts a reserved-namespace package;
/// a bare `--publisher` never does.
///
/// # Errors
/// As [`run_audit`].
pub fn run_audit_as(
    rest: &[String],
    blessing: Result<&BlessedPublisher, &BlessingRefusal>,
) -> Result<(), CliError> {
    let (path, index_root, advisory_db_override, no_advisory_db, claimed, format) =
        parse_audit_args(rest)?;
    let prepared = prepare(&path)?;
    let name = prepared.manifest.name.clone();
    let version = prepared
        .manifest
        .version
        .as_ref()
        .map_or_else(|| "(unversioned)".to_owned(), ToString::to_string);

    // Resolve the effective advisory DB.
    // Priority: explicit --advisory-db > default registry checkout > --no-advisory-db (None).
    // Absence of --advisory-db uses the registry index checkout the resolver already has.
    // --no-advisory-db is the ONLY way to skip; omitting --advisory-db does NOT skip.
    let effective_advisory_db: Option<PathBuf> = if no_advisory_db {
        None
    } else {
        Some(advisory_db_override.map_or_else(crate::resolve::index_root, Ok)?)
    };

    let outcome = audit_gate(
        &prepared,
        index_root.as_deref(),
        effective_advisory_db.as_deref(),
        PublisherStanding {
            claimed: claimed.as_ref(),
            blessing,
        },
    );

    match format {
        OutputFormat::Json => emit_audit_json(&name, &version, &outcome),
        // `--plain` and the default share the human renderer; the audit verdict
        // has no separate flush-left line form, so `--plain` is the human report
        // (the format parse already rejected `--plain --json` together).
        OutputFormat::Human | OutputFormat::Plain => match outcome {
            Ok((tier2, disclosure)) => {
                crate::screen::Screen::new(crate::screen::Stream::Stdout)
                    .line(
                        crate::screen::Tone::Text,
                        &passing_summary(&name, &version, &tier2, &disclosure),
                    )
                    .emit();
                Ok(())
            }
            Err(err) => Err(err),
        },
    }
}

/// Run the full Tier-1 gate, then Tier-2 for native-bearing packages, returning
/// the first rejection or the Tier-2 outcome on a clean pass.
///
/// The checks run Security-first: the reserved-namespace ownership check (a
/// third party squatting the trusted `Ipe.*` stdlib namespace is a trust-boundary
/// breach) runs first, then the provenance scan (an authored abrupt-failure
/// construct in author Rust is a soundness hole in the SHIPPED artifact) and the
/// capability honesty check, before the semver and supply-chain checks; the
/// FIRST rejection is the verdict. A pure Ipê package skips Tier-2 (Tier-1 already
/// gated it exactly); a native package builds and exercises its native code under
/// a declared-scoped jail and reconciles observed-vs-declared, fail-closed
/// (ADR 0004).
///
/// `standing` is the claimed publisher plus the proof (or refusal) of its
/// blessed first-party identity: only a proven blessed publisher owns the
/// reserved namespace; a plain `ipe package audit`, or any unproven claim, has
/// every reserved-namespace module rejected fail-closed.
fn audit_gate(
    prepared: &Prepared,
    index_root: Option<&Path>,
    advisory_db: Option<&Path>,
    standing: PublisherStanding<'_>,
) -> Result<(crate::audit_native::Tier2Outcome, Disclosure), CliError> {
    reserved_namespace_ownership(prepared, standing)?;
    provenance_panic_scan(prepared)?;

    // The whole-tree inferred capability union — computed once and shared by the
    // consistency check (reconcile against the manifest) and the disclosure
    // (surface to the consumer), so the two can never disagree about the effects.
    let inferred = crate::infer_package_capabilities(&prepared.manifest_path)?;
    capability_consistency(prepared, &inferred)?;

    enforced_semver(prepared, index_root)?;
    supply_chain(prepared)?;
    advisory_check(prepared, advisory_db)?;

    let disclosure = derive_disclosure(prepared, inferred)?;

    let tier2 = crate::audit_native::native_tier2(&crate::audit_native::NativeAudit {
        declared: &prepared.manifest.capabilities,
        has_rust_deps: !prepared.manifest.rust_dependencies.is_empty(),
        root: &prepared.manifest.root,
        emitted_dir: &prepared.emitted_dir,
    })?;

    // Control-model consent (defence-in-depth boundary, sibling of the build-time
    // gate): a package whose runnable entry runs an elevated (`Direct`) control
    // model its own manifest does not accept is a fail-closed audit rejection. A
    // managed model or a library (`NotApplicable`) needs no accept and passes
    // silently. It runs LAST — after the native-bearing fail-closed checks
    // (binding regeneration, provenance, Tier-2) — so the consent decision is the
    // final gate on an otherwise-certifiable package and never preempts a
    // native-surface refusal.
    if let ControlModelDisclosure::Entry(model) = disclosure.control_model {
        crate::control_model_consent::gate(
            model,
            &prepared.manifest.control_models_accept,
            &prepared.manifest.name,
        )?;
    }

    Ok((tier2, disclosure))
}

/// Emit the compact JSON audit verdict to stdout, then map a rejection to the
/// already-emitted sentinel so the process still exits non-zero without printing
/// a second human message. On a pass, the object records the certified verdict
/// and the Tier-2 disposition; on a reject, `certified` is `false` and `reason`
/// carries the failing check's one-line message.
fn emit_audit_json(
    name: &str,
    version: &str,
    outcome: &Result<(crate::audit_native::Tier2Outcome, Disclosure), CliError>,
) -> Result<(), CliError> {
    crate::screen::emit_machine(
        crate::screen::Stream::Stdout,
        &format!("{}\n", audit_verdict_json(name, version, outcome)),
    );

    match outcome {
        Ok(_) => Ok(()),
        // The verdict object was already written to stdout; return the sentinel
        // so the exit is non-zero with nothing more printed.
        Err(_) => Err(CliError::DiagnosticJsonEmitted),
    }
}

/// Build the compact JSON audit verdict object (the pure core of
/// [`emit_audit_json`]): a certified pass with its Tier-2 disposition, or a
/// `certified:false` object carrying the failing check's one-line reason.
fn audit_verdict_json(
    name: &str,
    version: &str,
    outcome: &Result<(crate::audit_native::Tier2Outcome, Disclosure), CliError>,
) -> String {
    use crate::audit_native::Tier2Outcome;
    use crate::cli_args::json;

    match outcome {
        Ok((Tier2Outcome::SkippedPureIpe, disclosure)) => json::object(&[
            ("package", json::string(name)),
            ("version", json::string(version)),
            ("tier1", json::string("pass")),
            ("tier2", json::string("skipped")),
            (
                "controlModel",
                json::string(disclosure.control_model.word()),
            ),
            ("capabilities", disclosure_capabilities_json(disclosure)),
            ("certified", "true".to_owned()),
        ]),
        Ok((Tier2Outcome::Certified { platform }, disclosure)) => json::object(&[
            ("package", json::string(name)),
            ("version", json::string(version)),
            ("tier1", json::string("pass")),
            ("tier2", json::string("pass")),
            ("platform", json::string(platform)),
            (
                "controlModel",
                json::string(disclosure.control_model.word()),
            ),
            ("capabilities", disclosure_capabilities_json(disclosure)),
            ("certified", "true".to_owned()),
        ]),
        Err(err) => json::object(&[
            ("package", json::string(name)),
            ("version", json::string(version)),
            ("certified", "false".to_owned()),
            ("reason", json::string(&err.to_string())),
        ]),
    }
}

/// The capability set as a compact JSON array of the axes' canonical words, in
/// the set's deterministic order.
fn disclosure_capabilities_json(disclosure: &Disclosure) -> String {
    let words: Vec<&'static str> = disclosure.capabilities.iter().map(|c| c.as_str()).collect();
    crate::cli_args::json::string_array(&words)
}

/// Compose the passing summary, advertising Tier-2 ONLY for what genuinely ran
/// (the honest surface, ADR 0004). A pure Ipê package's summary is Tier-1 only,
/// with the standing note that Tier-2 does not apply. A native package certified
/// on a wired platform (`linux-x64`, `macos-arm64`, or `freebsd-x64`) names that
/// platform and states that a Tier-2 certification is per-host — vouching only
/// for the platform whose jail actually ran, never claimed cross-host.
fn passing_summary(
    name: &str,
    version: &str,
    tier2: &crate::audit_native::Tier2Outcome,
    disclosure: &Disclosure,
) -> String {
    use crate::audit_native::Tier2Outcome;
    let tier_line = match tier2 {
        Tier2Outcome::SkippedPureIpe => format!(
            "package audit: {name} {version} — all Tier-1 checks passed. (Pure Ipê package: \
             native Tier-2 does not apply.)"
        ),
        Tier2Outcome::Certified { platform } => format!(
            "package audit: {name} {version} — all Tier-1 checks passed; native Tier-2 capability \
             enforcement (build+link reachability of the package's FFI bindings under a \
             declared-scoped jail) passed on: {platform}. A Tier-2 certification is per-host — it \
             vouches only for the platform whose jail actually ran; running the audit on another \
             wired platform certifies that platform in turn."
        ),
    };
    format!("{tier_line}\n{}", disclosure_summary(name, disclosure))
}

/// The six-field result of [`parse_audit_args`]: `(project_path, index_root,
/// advisory_db_override, no_advisory_db, publisher, format)`.
///
/// `advisory_db_override` is a custom DB path from `--advisory-db <path>`.
/// `no_advisory_db` is `true` when `--no-advisory-db` was passed (explicit opt-out).
/// Absence of both means the check runs against the default registry checkout.
type AuditArgs = (
    PathBuf,
    Option<PathBuf>,
    Option<PathBuf>,
    bool,
    Option<SelfDeclaredPublisher>,
    OutputFormat,
);

/// Parse `ipe package audit`'s tail: an optional positional `<path>`, an
/// optional `--index <dir>` (the curated index checkout the semver check reads
/// the previous published version from; defaults to the resolver's index root),
/// and the shared `--plain` / `--json` output-format flags.
///
/// Advisory-DB flags:
/// - `--advisory-db <path>`: use a custom DB root (overrides the default registry checkout).
/// - `--no-advisory-db`: explicit opt-out; skips the advisory check with a loud warning.
/// - Neither: the check runs against the default registry index checkout (fail-closed default).
///
/// # Errors
/// [`CliError::Usage`] on an unknown flag, a missing flag value, a second
/// positional, `--plain --json` together, or `--advisory-db` and `--no-advisory-db` together.
fn parse_audit_args(rest: &[String]) -> Result<AuditArgs, CliError> {
    let mut path: Option<PathBuf> = None;
    let mut index: Option<PathBuf> = None;
    let mut advisory_db: Option<PathBuf> = None;
    let mut no_advisory_db = false;
    let mut publisher: Option<SelfDeclaredPublisher> = None;
    let mut format: Option<OutputFormat> = None;
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--index" => {
                let value = it.next().ok_or_else(|| {
                    CliError::Usage(text::msg::flag_needs_value(&"package audit", &"--index"))
                })?;
                if index.is_some() {
                    return Err(CliError::Usage(text::msg::flag_repeated(
                        &"package audit",
                        &"--index",
                    )));
                }
                index = Some(PathBuf::from(value));
            }
            "--advisory-db" => {
                let value = it.next().ok_or_else(|| {
                    CliError::Usage(text::msg::flag_needs_value(
                        &"package audit",
                        &"--advisory-db",
                    ))
                })?;
                if advisory_db.is_some() {
                    return Err(CliError::Usage(text::msg::flag_repeated(
                        &"package audit",
                        &"--advisory-db",
                    )));
                }
                if no_advisory_db {
                    return Err(CliError::Usage(text::msg::audit_advisory_db_exclusive()));
                }
                advisory_db = Some(PathBuf::from(value));
            }
            "--no-advisory-db" => {
                if no_advisory_db {
                    return Err(CliError::Usage(text::msg::flag_repeated(
                        &"package audit",
                        &"--no-advisory-db",
                    )));
                }
                if advisory_db.is_some() {
                    return Err(CliError::Usage(text::msg::audit_advisory_db_exclusive()));
                }
                no_advisory_db = true;
            }
            "--publisher" => {
                let value = it.next().ok_or_else(|| {
                    CliError::Usage(text::msg::flag_needs_value(
                        &"package audit",
                        &"--publisher",
                    ))
                })?;
                if publisher.is_some() {
                    return Err(CliError::Usage(text::msg::flag_repeated(
                        &"package audit",
                        &"--publisher",
                    )));
                }
                publisher = Some(SelfDeclaredPublisher::parse(value).map_err(|refusal| {
                    CliError::Usage(text::msg::audit_publisher_not_login(
                        &format!("{value:?}"),
                        &refusal,
                    ))
                })?);
            }
            "--plain" => set_format(&mut format, OutputFormat::Plain)?,
            "--json" => set_format(&mut format, OutputFormat::Json)?,
            flag if flag.starts_with('-') => {
                return Err(crate::cli_args::usage_unknown_flag("package audit", flag));
            }
            positional => {
                if path.is_some() {
                    return Err(CliError::Usage(text::msg::audit_single_path()));
                }
                path = Some(PathBuf::from(positional));
            }
        }
    }
    Ok((
        path.unwrap_or_else(|| PathBuf::from(".")),
        index,
        advisory_db,
        no_advisory_db,
        publisher,
        format.unwrap_or_default(),
    ))
}

/// Fold a requested output format into `slot`, rejecting `--plain --json`
/// together (or a repeat) so a machine consumer never gets a silently-chosen
/// winner — the same mutual-exclusion the shared format parse enforces.
fn set_format(slot: &mut Option<OutputFormat>, requested: OutputFormat) -> Result<(), CliError> {
    match slot {
        None => {
            *slot = Some(requested);
            Ok(())
        }
        Some(existing) if *existing == requested => {
            Err(CliError::Usage(text::msg::audit_format_repeated()))
        }
        Some(_) => Err(CliError::Usage(text::msg::plain_json_exclusive(
            &"package audit",
        ))),
    }
}

/// Locate the package's `package.ipe`, parse the manifest, and build the package to
/// its emitted Rust in a fresh temp directory (never the project's own `out/`, so
/// the audit leaves no artifact behind and cannot race a concurrent build).
///
/// For native-bearing packages (those with `[rust.dependencies]`), the FFI
/// bindings are regenerated from the pinned crates before the build. Any
/// committed `.ipe/cache/ffi/rust` in the fetched tree is removed first so the
/// audit never reads publisher-supplied bindings — only the gate-owned,
/// freshly-generated ones pass the ownership check that follows.
///
/// A `wrapper`-only package is rejected before the build: wrapper
/// bindings are author-asserted (a local source path, no registry pin, rev, or
/// hash), so the gate has no independent pinned source to regenerate from. The
/// only fail-closed option is rejection — committing author-written wrapper
/// `_bindings.rs` that the gate cannot re-derive must never reach a certified
/// build.
///
/// # Errors
/// [`CliError::Usage`] when `path` names no `package.ipe`;
/// [`CliError::PackageAudit`] with [`Check::NativeBindingRegen`] when the
/// manifest declares a `wrapper` field; the build errors
/// ([`CliError::Pipeline`] / [`CliError::Io`] / [`CliError::StaticRefusal`])
/// otherwise.
fn prepare(path: &Path) -> Result<Prepared, CliError> {
    let manifest_path = locate_manifest(path)?;
    let manifest = project::parse_manifest(&manifest_path)?;

    // Reject wrapper-only packages: the gate cannot regenerate wrapper bindings
    // from an independent pinned source, so a committed `_bindings.rs` must
    // never be trusted. Fail closed here rather than reading author-supplied
    // wrapper Rust that was never gate-owned.
    if manifest.has_rust_wrapper {
        return Err(reject(
            Check::NativeBindingRegen,
            "this package declares a `wrapper` field whose bindings are \
             author-asserted (a local source path with no registry pin, rev, or \
             content hash). The audit gate has no independent pinned source to \
             regenerate wrapper bindings from, so it cannot vouch for them. \
             A wrapper-bearing package cannot be certified until the gate gains a \
             regenerable, pinned wrapper source."
                .to_owned(),
        ));
    }

    // Regenerate FFI bindings for native-bearing packages before the build so
    // the compiler finds `Rust.<Crate>` interface modules.
    if !manifest.rust_dependencies.is_empty() {
        regenerate_ffi_bindings(&manifest_path)?;
    }

    // `audit_scratch_dir` creates the directory exclusively with 128-bit OS
    // entropy — no stale-dir removal needed; a fresh exclusive dir is always empty.
    let emitted_dir = audit_scratch_dir(&manifest.name)?;
    // Resolve the runtime exactly as `ipe build` does — one resolver for every
    // command. Under the default dependency model the emitted project names the
    // runtime as a path dependency, which the build materializes from the
    // embedded source under `IPE_HOME`; no vendored module tree is needed, so an
    // empty sentinel is passed and `build_project` never reads it. Only the
    // vendored/wasm shape needs a concrete module tree. Resolving here through a
    // separate walk-up (that never materialized) is what made `audit` fail on a
    // clean machine while `build` succeeded.
    let runtime_dir = crate::resolve_vendored_runtime_dir(None, !crate::runtime_dep_from_env())?;
    crate::build_project(&manifest_path, &emitted_dir, &runtime_dir)?;

    Ok(Prepared {
        manifest,
        manifest_path,
        emitted_dir,
    })
}

/// Regenerate FFI bindings for a native-bearing package into the project's own
/// `.ipe/cache/ffi/rust`, so the gate audits bindings it derived from the pinned
/// crate rather than any the publisher may have committed.
///
/// Any committed cache in the fetched source tree is removed first — the gate
/// never reads publisher-supplied bindings. The freshly generated cache is
/// owned by the invoking process's uid and no other user can write it, so the
/// `ffi::find_cache_root` ownership check passes for all subsequent reads.
///
/// Build scripts are always enabled here (equivalent to `--allow-build-scripts`)
/// because the bwrap jail (network-denied) is the sole confinement boundary;
/// skipping build scripts would silently omit crates that require them to
/// generate their API surface.
///
/// Failure is fail-closed: a regeneration error maps to a typed
/// [`Check::NativeBindingRegen`] rejection rather than letting the audit
/// continue with an absent or incomplete cache.
///
/// # Errors
/// [`CliError::PackageAudit`] with [`Check::NativeBindingRegen`] when the
/// jailed regeneration fails or the cache path escapes the project root via a
/// symlinked component; [`CliError::Io`] when the existing committed cache
/// cannot be removed.
fn regenerate_ffi_bindings(manifest_path: &Path) -> Result<(), CliError> {
    let project_root = manifest_path.parent().unwrap_or_else(|| Path::new("."));

    // Resolve the cache path once and assert it stays inside the project root.
    // An attacker-authored package tree can ship `.ipe/cache/ffi` as a symlink
    // to an out-of-tree target (committed via `git add -f`). `remove_dir_all`
    // traverses intermediate symlinks and would delete the target; the
    // subsequent write would go through the surviving symlink. We walk every
    // path component between `project_root` and the intended cache dir with
    // `symlink_metadata` (no-follow) and reject on the first symlink found,
    // before any delete or write occurs.
    let safe_cache = ffi_cache_path_or_reject(project_root)?;

    if safe_cache.exists() {
        std::fs::remove_dir_all(&safe_cache).map_err(|e| CliError::Io {
            path: safe_cache.clone(),
            source: e,
        })?;
    }
    crate::ffi::install_registry_deps_for_project(manifest_path, true).map_err(|e| {
        reject(
            Check::NativeBindingRegen,
            format!(
                "failed to regenerate FFI bindings from the package's \
                 `[rust.dependencies]` inside the sandbox: {e}\n\
                 The audit requires a clean, gate-owned binding generation; \
                 a failure here means the native package cannot be certified."
            ),
        )
    })
}

/// Resolve the `.ipe/cache/ffi/rust` path under `project_root` and verify that
/// no component of the relative suffix is a symlink (no-follow check).
///
/// Returns the resolved path on success, or a [`Check::NativeBindingRegen`]
/// rejection when any component is a symlink or the resolved path escapes the
/// canonical project root. The check uses [`std::fs::symlink_metadata`] so it
/// never follows symlinks.
fn ffi_cache_path_or_reject(project_root: &Path) -> Result<PathBuf, CliError> {
    // The relative components we walk: `.ipe`, `cache`, `ffi`, `rust`.
    const CACHE_COMPONENTS: &[&str] = &[".ipe", "cache", "ffi", "rust"];

    let mut current = project_root.to_path_buf();
    for component in CACHE_COMPONENTS {
        current.push(component);
        // Check this component without following the symlink.
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(reject(
                    Check::NativeBindingRegen,
                    format!(
                        "the package's cache path `{}` contains a symlink at `{}`; \
                         the audit rejects this to prevent out-of-tree writes through \
                         a symlinked intermediate path component",
                        project_root.join(".ipe/cache/ffi/rust").display(),
                        current.display(),
                    ),
                ));
            }
            // Not present yet — the delete is a no-op and the write will create it.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // Exists and is a real directory or file — continue walking.
            Ok(_) => {}
            Err(e) => {
                return Err(CliError::Io {
                    path: current,
                    source: e,
                });
            }
        }
    }
    Ok(current)
}

/// Resolve `path` (a directory or a `package.ipe`) to its manifest file.
///
/// # Errors
/// [`CliError::Usage`] when the directory holds no `package.ipe`, or `path`
/// is neither a directory nor a `package.ipe`.
fn locate_manifest(path: &Path) -> Result<PathBuf, CliError> {
    if path.is_dir() {
        if let Some(manifest) = crate::project::manifest_in_dir(path) {
            return Ok(manifest);
        }
        if crate::project::has_only_legacy_toml(path) {
            return Err(CliError::Usage(text::msg::legacy_toml_hint()));
        }
        return Err(CliError::Usage(text::msg::audit_no_manifest(
            &path.display(),
        )));
    }
    if path.file_name().and_then(|n| n.to_str()) == Some(crate::package_manifest::PACKAGE_IPE)
        && path.is_file()
    {
        return Ok(path.to_path_buf());
    }
    Err(CliError::Usage(text::msg::audit_not_a_package(
        &path.display(),
    )))
}

/// Create and return an exclusive per-package audit scratch directory under the
/// OS temp root. The name is unpredictable (128-bit OS entropy) so a same-user
/// attacker cannot pre-seed or symlink it.
fn audit_scratch_dir(package: &str) -> Result<PathBuf, CliError> {
    let prefix = format!("ipe-audit-{package}");
    let scratch = ScratchDir::new(&prefix).map_err(|e| CliError::Io {
        path: PathBuf::from(&prefix),
        source: e,
    })?;
    // The caller removes the directory with a best-effort `remove_dir_all`.
    Ok(scratch.into_path())
}

// ===========================================================================
// 1a. Provenance panic-scan
// ===========================================================================

/// Scan the package's Rust for authored abrupt-failure constructs, attributing
/// each hit to its provenance.
///
/// - a hit in author-supplied FFI wrapper Rust (`_bindings.rs` in the project's
///   FFI cache) is a **user error**: the gate rejects the package, pointing at
///   the file and line. This is the security boundary the check exists to close —
///   author Rust compiles unsandboxed into the shipped artifact, so an authored
///   `panic!`/`unwrap` there is a soundness hole the package must not ship with.
/// - a hit in our EMITTED Rust is attributed to the COMPILER, not the author. Per
///   the plan (§1a) an emitted-Rust hit is OUR CI's concern, never the author's,
///   so the author-facing package gate does not scan it here: the emitted surface
///   is already covered by the compiler's own `tools/panic-scan` CI over the
///   backend's `src/` templates (the `panic-scan` job in
///   `.github/workflows/ci.yml`). That separation is not incidental — the backend's FIXED epilogue emits one
///   deliberate, `#[allow(unreachable_code)]`-guarded polyfill `panic!` into
///   every project's `main.rs`, so scanning emitted output as an author gate
///   would reject every package for a construct that is neither the author's nor
///   accidental codegen. The provenance boundary is therefore exact by
///   construction: the gate rejects ONLY the author-supplied FFI wrapper Rust.
///
/// # Errors
/// [`CliError::PackageAudit`] when an author FFI Rust file contains an abrupt-
/// failure construct; [`CliError::Io`] on a read failure.
fn provenance_panic_scan(prepared: &Prepared) -> Result<(), CliError> {
    // Author FFI wrapper Rust is the one surface this check gates: it compiles
    // unsandboxed into the shipped artifact, so an authored abrupt-failure
    // construct there is a soundness hole the package must not ship with.
    if let Some(hit) = scan_author_ffi_rust(prepared)? {
        return Err(reject(
            Check::Provenance,
            format!(
                "author-supplied FFI Rust contains an abrupt-failure construct — a package \
                 that can `{}` at runtime is not safe to publish.\n  {}:{}: `{}`\n\
                 replace it with a `Result`/error return; the gate forbids authored \
                 panic/unwrap/expect/assert in shipped Rust.",
                hit.tok,
                hit.file.display(),
                hit.line,
                hit.tok
            ),
        ));
    }
    Ok(())
}

/// One flagged construct with its provenance file — a [`panic_scan::Hit`]
/// (line + token) paired with the file it was found in.
struct LocatedHit {
    file: PathBuf,
    line: usize,
    tok: String,
}

/// Scan the project's author-supplied FFI wrapper Rust (`*_bindings.rs` under the
/// FFI cache) for the first abrupt-failure construct, if any. Returns `None` when
/// the package carries no FFI cache or no author Rust hit.
///
/// This is the exact author-Rust surface the `_bindings.rs` naming marks: the FFI
/// cache stores one `<slug>_bindings.rs` per installed crate, the hand-written
/// wrapper the inspection produced from the author's `[rust.define.*]` decls.
/// The interface `.ipe` modules (origin [`ipe_canon::ModuleOrigin::FfiInterface`])
/// are Ipê, not Rust; the `_bindings.rs` files are the author Rust the scan
/// attributes to the user.
///
/// # Errors
/// [`CliError::Io`] on a read failure.
fn scan_author_ffi_rust(prepared: &Prepared) -> Result<Option<LocatedHit>, CliError> {
    let cache_root = prepared.manifest.root.join(".ipe/cache/ffi/rust");
    if !cache_root.is_dir() {
        return Ok(None);
    }
    let mut files: Vec<PathBuf> = Vec::new();
    collect_rust_files(&cache_root, &mut files)?;
    files.sort();
    for file in files {
        // Only the `_bindings.rs` wrapper is author-authored Rust that compiles
        // into the crate; the other cache artifacts (`.ipei`, `consumer.json`,
        // `<slug>.ipe`) are interface metadata, not Rust.
        let is_bindings = file
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with("_bindings.rs"));
        if !is_bindings {
            continue;
        }
        if let Some(hit) = first_hit(&file)? {
            return Ok(Some(hit));
        }
    }
    Ok(None)
}

/// Run the shared [`panic_scan`] token scanner over one file, returning its first
/// hit (lowest line) if any.
///
/// Fail closed on a non-lexing file: a `_bindings.rs` the scanner cannot
/// tokenise is opaque — the no-panic audit cannot attest its content. The
/// scanner refuses rather than admits (the same posture `capability_scan`
/// takes for a non-lexing source). A `cargo build` of a non-lexing file would
/// fail, but that is a separate later step; this gate must refuse eagerly,
/// before the file reaches `cargo`.
///
/// # Errors
/// [`CliError::Io`] on a file-read failure; [`CliError::PackageAudit`] when
/// the file does not parse as Rust.
fn first_hit(file: &Path) -> Result<Option<LocatedHit>, CliError> {
    let src =
        crate::io_bounded::read_to_string_capped(file, crate::io_bounded::FFI_CACHE_READ_CAP)?;
    let hits = panic_scan::scan_str(&src).map_err(|_| {
        reject(
            Check::Provenance,
            format!(
                "emitted `{}` does not parse as Rust — the no-panic audit cannot attest \
                 its content; the file is refused rather than admitted",
                file.display()
            ),
        )
    })?;
    Ok(hits.into_iter().next().map(|h| LocatedHit {
        file: file.to_path_buf(),
        line: h.line,
        tok: h.tok,
    }))
}

/// Recursively collect every `.rs` file under `dir` into `out`.
///
/// # Errors
/// [`CliError::Io`] on a directory-read failure.
fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), CliError> {
    let entries = std::fs::read_dir(dir).map_err(|e| CliError::Io {
        path: dir.to_path_buf(),
        source: e,
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| CliError::Io {
            path: dir.to_path_buf(),
            source: e,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| CliError::Io {
            path: path.clone(),
            source: e,
        })?;
        if file_type.is_dir() {
            collect_rust_files(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    Ok(())
}

// ===========================================================================
// 1b. Capability consistency
// ===========================================================================

/// Verify the manifest's declared `[capabilities]` set EQUALS the set inferred
/// over the WHOLE package — no hidden effect, no over-broad claim.
///
/// Uses [`crate::infer_package_capabilities`] (the union over every shipped
/// module, not just `Main`'s reachability closure) so a sibling module a consumer
/// could `import` cannot smuggle in an undeclared effect. This is the same
/// whole-tree posture the enforced-semver check takes over the public API — the
/// declared set the index records is the consumer's consent surface, so it must
/// cover the whole shipped module set. `native-ffi` is inferred like any other
/// axis (it enters the set when a module crosses into `Rust.` code) and, when
/// present and consistent, is surfaced loudly per §1b.
///
/// The `inferred` set is computed once by the caller (the same whole-tree union
/// the disclosure surfaces) and reconciled here against the manifest, so the two
/// surfaces can never disagree about the package's effects.
///
/// # Errors
/// [`CliError::PackageAudit`] when the declared and inferred sets differ.
fn capability_consistency(
    prepared: &Prepared,
    inferred: &BTreeSet<Capability>,
) -> Result<(), CliError> {
    use std::fmt::Write as _;

    let declared: BTreeSet<Capability> = prepared.manifest.capabilities.clone();

    if declared == *inferred {
        if declared.contains(&Capability::NativeFfi) {
            // Surfaced loudly per §1b: a package the user consents to as crossing
            // into opaque native code, whose true effect set cannot be inferred
            // from Ipê alone beyond the `native-ffi` marker itself.
            crate::screen::Screen::new(crate::screen::Stream::Stdout)
                .line(
                    crate::screen::Tone::Text,
                    &format!(
                        "package audit: note — `{}` exercises the `native-ffi` capability; its \
                     native effects cannot be inferred from Ipê alone.",
                        prepared.manifest.name
                    ),
                )
                .emit();
        }
        return Ok(());
    }

    let mut message = String::from(
        "the declared `[capabilities]` set does not match the package's inferred effects \
         — the declared set must be exactly the truth the user consents to.",
    );
    let missing: Vec<&'static str> = inferred.difference(&declared).map(|c| c.as_str()).collect();
    let extra: Vec<&'static str> = declared.difference(inferred).map(|c| c.as_str()).collect();
    if !missing.is_empty() {
        let _ = write!(
            message,
            "\n  used but NOT declared (a hidden effect): {}",
            missing.join(", ")
        );
    }
    if !extra.is_empty() {
        let _ = write!(
            message,
            "\n  declared but NOT used (an over-broad claim): {}",
            extra.join(", ")
        );
    }
    Err(reject(Check::Capability, message))
}

// ===========================================================================
// Compiler-derived disclosure (control model + capability set)
// ===========================================================================

/// Derive the consumer-facing disclosure — the entry program's control model and
/// the package's capability set — reusing the compiler's own derivations.
///
/// The capability set is the whole-tree inferred union the caller already
/// computed (the SSOT the capability-consistency check reconciles), so the
/// disclosed effects and the reconciled effects are the same value.
///
/// The control model is a projection of the shape the compiler pins for `main`
/// ([`ipe_canon::shape_source::classify_main_shape`] → [`crate::delivery::Shape`]
/// → [`crate::delivery::ControlModel`]), never a second inspection of `main`.
/// It is derived **fail-closed**:
///
/// - A library that exposes modules but has no runnable entry file discloses
///   [`ControlModelDisclosure::NotApplicable`] — an honest absence, not a
///   permissive default.
/// - A runnable entry that cannot be read or parsed at disclosure time is a hard
///   rejection: a program whose self-driving model we cannot state must never be
///   certified as safe with a permissive-looking default. (The package already
///   built in [`prepare`], so this is a defence-in-depth second boundary, not the
///   only one.)
///
/// # Errors
/// [`CliError::PackageAudit`] with [`Check::Capability`] when a runnable entry
/// exists but its control model cannot be derived.
fn derive_disclosure(
    prepared: &Prepared,
    inferred: BTreeSet<Capability>,
) -> Result<Disclosure, CliError> {
    let entry = crate::driver::analysis_root_of(&prepared.manifest)?;

    // A library ships no runnable `Main.ipe`; `analysis_root_of` then points at
    // the first exposed module (or a non-existent default). Absent an entry file,
    // the package drives nothing of its own — an honest absence, not a fail-open
    // default.
    if !entry.is_file() {
        return Ok(Disclosure {
            control_model: ControlModelDisclosure::NotApplicable,
            capabilities: inferred,
        });
    }

    // The entry file exists. Read + parse it. A read or parse failure fails the
    // audit closed rather than disclosing a permissive default for a source we
    // cannot classify.
    let source =
        crate::io_bounded::read_to_string_capped(&entry, crate::io_bounded::SOURCE_READ_CAP)
            .map_err(|_| {
                reject(
                    Check::Capability,
                    format!(
                        "the package's entry source (`{}`) could not be read, so its control model \
                     cannot be derived. A program whose self-driving model the audit cannot state \
                     is refused rather than certified with an assumed model.",
                        entry.display()
                    ),
                )
            })?;
    let mut interner = ipe_intern::Interner::new();
    let module = ipe_parse::parse_module(&source, &mut interner).map_err(|_| {
        reject(
            Check::Capability,
            format!(
                "the package's entry source (`{}`) does not parse, so its control model cannot be \
                 derived. A program whose self-driving model the audit cannot state is refused \
                 rather than certified with an assumed model.",
                entry.display()
            ),
        )
    })?;

    // A module that defines no `main` is not a runnable program — it is a library
    // module the package exposes. It drives nothing of its own, so the control
    // model is a genuine absence, distinct from a plain-`Task` Direct `main`.
    let defines_main = interner
        .lookup("main")
        .is_some_and(|main_sym| module.values.iter().any(|v| v.value.name.value == main_sym));
    if !defines_main {
        return Ok(Disclosure {
            control_model: ControlModelDisclosure::NotApplicable,
            capabilities: inferred,
        });
    }

    let shape = crate::delivery::Shape::from_main(ipe_canon::shape_source::classify_main_shape(
        &module, &interner,
    ));
    Ok(Disclosure {
        control_model: ControlModelDisclosure::Entry(shape.control_model()),
        capabilities: inferred,
    })
}

/// The package disclosure a non-audit surface (`ipe doc`) reads — the SAME
/// compiler-derived control model and whole-tree capability union `ipe audit`
/// discloses, reusing [`derive_disclosure`] and
/// [`crate::infer_package_capabilities`] rather than a second derivation that
/// could disagree with the audit's answer.
///
/// Fail-closed identically to the audit: a runnable entry whose source cannot be
/// read or parsed is a hard rejection ([`Check::Capability`]), never a permissive
/// default; a package with no runnable `main` discloses an honest
/// [`ControlModelDisclosure::NotApplicable`] ("library").
///
/// This does NOT build the package (no emit): the disclosure needs only the
/// manifest (for the capability union) and the entry source (for the control
/// model), so `ipe doc` stays a read-only documentation surface.
///
/// # Errors
/// [`CliError`] when the manifest cannot be located or parsed, the capability
/// inference fails, or the entry source cannot be read or parsed (fail-closed).
pub(crate) fn disclose_package(path: &Path) -> Result<Disclosure, CliError> {
    let manifest_path = locate_manifest(path)?;
    let manifest = project::parse_manifest(&manifest_path)?;
    let inferred = crate::infer_package_capabilities(&manifest_path)?;
    let prepared = Prepared {
        manifest,
        manifest_path,
        // The disclosure never reads the emitted directory (only the native
        // Tier-2 check does), so no build is performed for a doc-side disclosure.
        emitted_dir: PathBuf::new(),
    };
    derive_disclosure(&prepared, inferred)
}

/// Render the disclosure as a human-readable frame — the control model and the
/// (possibly empty) capability set the package can exercise.
fn disclosure_summary(name: &str, disclosure: &Disclosure) -> String {
    let caps: Vec<&'static str> = disclosure.capabilities.iter().map(|c| c.as_str()).collect();
    let caps_line = if caps.is_empty() {
        "none".to_owned()
    } else {
        caps.join(", ")
    };
    format!(
        "package audit: `{name}` control model: {}; capabilities: {caps_line}.",
        disclosure.control_model.word()
    )
}

// ===========================================================================
// 1c. Enforced semver
// ===========================================================================

/// Enforce the semver bump between this version's public API and the previous
/// published version fetched from the index.
///
/// Looks up the package in the index; the baseline is [`stable_baseline`] — the
/// highest published RELEASE version strictly below the manifest's declared
/// version. Prereleases are never the baseline: they carry no compatibility
/// promise and a stable requirement never resolves them, so the promise a stable
/// release must keep is to the previous stable release. Diffing against a
/// prerelease instead would let a breaking change ride in through an exempt
/// prerelease and reach stable ranges as a patch. When the package is not in the
/// index, or has no release below this one, this is a FIRST stable version — the
/// check has no baseline to diff against and skips (per §1c). Otherwise it runs
/// [`crate::diff::check_semver_bump`] and rejects an under-bump.
///
/// The predecessor's public API is rebuilt from its pinned source (fetched +
/// hash-verified through the resolver), so the baseline is exactly the bytes the
/// index registered — the plan's §7 "rebuild from pinned source" resolution of
/// the baseline-availability open question.
///
/// # Errors
/// [`CliError::PackageAudit`] on an under-bump or a missing manifest version;
/// [`CliError::VersionRefused`] when the manifest version carries build metadata;
/// [`CliError::Diff`] when a tree cannot be diffed; resolution errors otherwise.
fn enforced_semver(prepared: &Prepared, index_root: Option<&Path>) -> Result<(), CliError> {
    let Some(manifest_version) = prepared.manifest.version.clone() else {
        return Err(reject(
            Check::Semver,
            "the manifest declares no `version = \"…\"` — the enforced-semver check needs a \
             version to compare against the previous published one."
                .to_owned(),
        ));
    };
    let new_version = PublishedVersion::from_semver(manifest_version)
        .map_err(|refusal| refusal.for_package(&prepared.manifest.name))?;

    // A prerelease (`X.Y.Z-<pre>`) is, by semver §9, explicitly unstable and
    // exempt from the compatibility guarantee a release version carries. Range
    // resolution (`index::resolve_version` via `VersionReq::matches`, Cargo
    // semantics) never resolves a prerelease for a non-prerelease requirement, so
    // no consumer on a stable range can even see one — enforcing an API-bump on it
    // would only reject a normal iteration (`X.Y.Z-a` → `X.Y.Z-b`) that harms no
    // one. Monotonicity is still guaranteed independently: `admission_precheck`
    // forbids rewriting a published version and refuses a successor that does not
    // exceed every published one (prereleases included). So a prerelease clears
    // this check by being a prerelease, never by an API delta.
    if new_version.is_prerelease() {
        crate::screen::Screen::new(crate::screen::Stream::Stdout)
            .line(
                crate::screen::Tone::Text,
                &format!(
                    "package audit: `{}` {new_version} is a prerelease — exempt from the \
                 enforced-semver API-compatibility bump (semver §9: a prerelease is unstable \
                 and is not resolved by a stable version requirement).",
                    prepared.manifest.name
                ),
            )
            .emit();
        return Ok(());
    }

    let index_root =
        index_root.map_or_else(crate::resolve::index_root, |root| Ok(root.to_path_buf()))?;
    // Absent ⇒ a first submission; no predecessor to enforce.
    // Unreadable ⇒ fail closed: a corrupt predecessor must not silently pass
    // as "first version" — propagate the error so the gate refuses.
    let Some(entry) =
        crate::index::read_entry_lookup(&index_root, &prepared.manifest.name).absent_or_err()?
    else {
        crate::screen::Screen::new(crate::screen::Stream::Stdout)
            .line(
                crate::screen::Tone::Text,
                &format!(
                    "package audit: `{}` has no previously published version in the index — \
                 skipping the enforced-semver check (first version).",
                    prepared.manifest.name
                ),
            )
            .emit();
        return Ok(());
    };

    let Some(previous) = stable_baseline(&entry.versions, &new_version) else {
        crate::screen::Screen::new(crate::screen::Stream::Stdout)
            .line(
                crate::screen::Tone::Text,
                &format!(
                    "package audit: `{}` has no published stable version below {new_version} — \
                 skipping the enforced-semver check (first stable version; a prerelease \
                 carries no compatibility promise to diff against).",
                    prepared.manifest.name
                ),
            )
            .emit();
        return Ok(());
    };

    // Fetch + hash-verify the predecessor's pinned source, then diff the two
    // public APIs. `fetch_and_verify_baseline` returns the checkout root the
    // predecessor's `src/` lives under.
    let baseline = crate::resolve::fetch_and_verify_index_version(
        &prepared.manifest.root,
        &prepared.manifest.name,
        previous,
    )?;

    let new_tree = prepared
        .manifest_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let report = crate::diff::check_semver_bump(
        &baseline,
        &new_tree,
        previous.version.as_semver(),
        new_version.as_semver(),
    )?;
    if report.satisfied {
        Ok(())
    } else {
        Err(reject(
            Check::Semver,
            format!(
                "version {new_version} does not clear the required {} bump over the previous \
                 published {} — the new version must be at least {}.",
                report.required.as_str(),
                previous.version,
                report.floor
            ),
        ))
    }
}

/// The enforced-semver baseline for a release `new_version`: the highest
/// published release (no prerelease tag) strictly below it, or `None` when there
/// is none (a first stable version).
fn stable_baseline<'a>(
    versions: &'a [crate::index::EntryVersion],
    new_version: &PublishedVersion,
) -> Option<&'a crate::index::EntryVersion> {
    versions
        .iter()
        .filter(|v| !v.version.is_prerelease() && v.version < *new_version)
        .max_by(|a, b| a.version.cmp(&b.version))
}

// ===========================================================================
// 1d. Supply chain
// ===========================================================================

/// Run `cargo-deny` over the emitted project's dependency graph, and re-assert
/// the content-hash integrity of any Ipê package dependencies against their index
/// pins.
///
/// `cargo-deny check` applies the workspace's supply-chain posture (advisories,
/// bans, licenses, sources — see `deny.toml`) to the emitted Cargo project; a
/// non-zero exit is a reject. The Ipê-package hash re-assertion reuses the
/// resolver's lockfile pins so a fetched dependency whose bytes drifted from the
/// registered hash is caught here too (the resolver verifies at install; the gate
/// re-verifies at publish).
///
/// When `cargo-deny` is not installed, the advisory/bans scan is skipped with a
/// loud warning (a missing dev tool is not an unsafe package), while the
/// hash-integrity half still runs. The authoritative index-CI gate always
/// installs cargo-deny, so enforcement is never actually skipped there.
///
/// # Errors
/// [`CliError::PackageAudit`] when `cargo-deny` reports a violation, fails to run
/// for any reason other than not being installed, or a locked dependency's hash
/// no longer verifies.
/// Detect the installed cargo-deny minor version by parsing `cargo-deny --version`.
///
/// Returns the minor component of the version (e.g. `20` for `cargo-deny 0.20.2`).
/// On any parse failure defaults to `20` — the current "latest" release — so
/// absent or unreadable version output uses the newer global-flag placement.
fn detect_cargo_deny_minor() -> u32 {
    let Ok(out) = Command::new("cargo-deny").arg("--version").output() else {
        return 20;
    };
    // Output is `cargo-deny X.Y.Z\n`; split on whitespace, take last token.
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .split_whitespace()
        .last()
        .and_then(|v| v.split('.').nth(1))
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(20)
}

/// Build the cargo-deny argument vector for `advisories bans sources`.
///
/// cargo-deny 0.20 moved `--config` from the `check` subcommand to the global
/// (top-level) position. Placement rule:
///   - minor >= 20: `[--manifest-path <m>] [--config <cfg>] check advisories bans sources`
///   - minor < 20:  `[--manifest-path <m>] check advisories bans sources [--config <cfg>]`
///
/// `--manifest-path` is a global option accepted in both series.
fn deny_args(cargo_deny_minor: u32, manifest: &Path, config: Option<&Path>) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();
    args.push("--manifest-path".into());
    args.push(manifest.into());
    if cargo_deny_minor >= 20
        && let Some(cfg) = config
    {
        args.push("--config".into());
        args.push(cfg.into());
    }
    args.push("check".into());
    // Advisories + bans + sources are the supply-chain axes; licenses are a
    // project-policy axis the workspace's own gate owns, not the package gate.
    args.push("advisories".into());
    args.push("bans".into());
    args.push("sources".into());
    if cargo_deny_minor < 20
        && let Some(cfg) = config
    {
        args.push("--config".into());
        args.push(cfg.into());
    }
    args
}

fn supply_chain(prepared: &Prepared) -> Result<(), CliError> {
    let manifest = prepared.emitted_dir.join("Cargo.toml");
    if !manifest.is_file() {
        // No emitted Cargo project means no Rust dependency graph to vet; the
        // Ipê-package integrity re-check below still applies.
        return verify_locked_dependency_hashes(prepared);
    }

    // Spawn `cargo-deny` directly rather than the `cargo deny` subcommand, so
    // that a machine without cargo-deny yields a `NotFound` spawn error (handled
    // as a skip below) instead of `cargo` running and reporting "no such
    // subcommand", which would masquerade as a supply-chain violation.
    //
    // Apply the SAME advisory/bans/sources posture the workspace uses — its
    // `deny.toml` ledgers advisories the vendored runtime's dependency tree
    // legitimately carries. Without it the check would default-reject every
    // emitted package for a runtime dependency the workspace has already vetted.
    // Absent a resolvable config, cargo-deny falls back to its defaults.
    //
    // `--config` placement is version-dependent: global (before `check`) for
    // cargo-deny >= 0.20, on the `check` subcommand for < 0.20.
    let derived_config = derive_deny_config(&prepared.emitted_dir)?;
    let minor = detect_cargo_deny_minor();
    let args = deny_args(minor, &manifest, derived_config.as_deref());
    let mut command = Command::new("cargo-deny");
    command.args(&args);
    let output = command.output();

    match output {
        Ok(out) if out.status.success() => verify_locked_dependency_hashes(prepared),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(reject(
                Check::SupplyChain,
                format!(
                    "cargo-deny reported a supply-chain violation over the package's Rust \
                     dependency graph:\n{}",
                    stderr.trim()
                ),
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // cargo-deny is not installed. This is a missing dev tool, not an
            // unsafe package: conflating the two would fail every audit run on a
            // machine without cargo-deny. The authoritative gate — the package
            // index CI — always installs it, so advisory/bans enforcement is
            // never actually skipped there. Locally, skip that scan with a loud
            // warning; the lockfile hash-integrity half still runs.
            crate::screen::chatter(
                crate::screen::Stream::Stderr,
                crate::screen::Tone::UserError,
                "warning: supply-chain advisory scan skipped — cargo-deny is not installed \
                     (`cargo install cargo-deny`). The package index enforces it; lockfile hash \
                     integrity is still verified.",
            );
            verify_locked_dependency_hashes(prepared)
        }
        Err(e) => Err(reject(
            Check::SupplyChain,
            format!(
                "could not run `cargo deny` ({e}) — install cargo-deny \
                 (`cargo install cargo-deny`) so the gate can vet the dependency graph."
            ),
        )),
    }
}

/// Re-assert that every locked Ipê package dependency's cached source still
/// hashes to the pin recorded in `ipe.lock` — the resolver's verify-before-trust
/// boundary, re-checked at publish.
///
/// # Errors
/// [`CliError::PackageAudit`] when a locked dependency's cached tree no longer
/// matches its pinned hash.
fn verify_locked_dependency_hashes(prepared: &Prepared) -> Result<(), CliError> {
    match crate::resolve::verify_lockfile_hashes(&prepared.manifest.root) {
        Ok(()) => Ok(()),
        Err(CliError::HashMismatch {
            package,
            expected,
            actual,
        }) => Err(reject(
            Check::SupplyChain,
            format!(
                "the cached source of the locked Ipê dependency `{package}` no longer matches \
                 its pinned hash — the dependency tree drifted from what the index registered.\n\
                 \x20 expected: {expected}\n  actual:   {actual}"
            ),
        )),
        Err(other) => Err(other),
    }
}

/// Cross-check every locked Ipê dependency against the advisory database.
///
/// Reads `<advisory_db_root>/advisories/<pkg>/` for each locked dep and tests
/// its locked version against every advisory's `affected` range.
///
/// `advisory_db` is `None` only when the caller explicitly opted out via
/// `--no-advisory-db`.  The default path (the registry index checkout) is
/// resolved by the caller before this function is called, so an absent
/// `--advisory-db` flag does NOT produce `None` — it produces `Some(default)`.
///
/// When `advisory_db` is `None` (explicit opt-out), the check is skipped with a
/// loud warning naming the flag required to re-enable it.  When `advisory_db`
/// is `Some` but the `advisories/` directory is absent from disk, the check
/// passes cleanly (no advisories published = no risk signal).  An unreadable
/// directory or a malformed advisory file is always an error (fail-closed).
///
/// # Errors
/// [`CliError::AdvisoryVulnerable`] on a `high`/`critical` match.
/// [`CliError::AdvisoryDbMalformed`] on a malformed advisory file.
/// [`CliError::AdvisoryDbUnreachable`] on an unreadable advisory directory.
fn advisory_check(prepared: &Prepared, advisory_db: Option<&Path>) -> Result<(), CliError> {
    let Some(db_root) = advisory_db else {
        // Explicit opt-out via --no-advisory-db.  Warn loudly; the check is
        // on by default and omitting --no-advisory-db is the safe path.
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::UserError,
            "warning: advisory-database check explicitly skipped via --no-advisory-db. \
                 Remove --no-advisory-db to re-enable the default check against the registry \
                 advisory database.",
        );
        return Ok(());
    };

    advisory_check_with_base(prepared, db_root, &crate::registry::registry_base_url())
}

/// The base-URL-injected core of [`advisory_check`]: reads the lockfile and
/// cross-checks every locked dep, using `base_url` as the registry Pages read
/// API. Tests pass an empty `base_url` to disable the HTTP attempt (immediate
/// unreachable → the git-checkout DB is authoritative), keeping them hermetic and
/// off the network.
///
/// # Errors
/// [`CliError::AdvisoryVulnerable`] on a `high`/`critical` match; the advisory-DB
/// errors when the fallback checkout is present but corrupt or unreadable.
fn advisory_check_with_base(
    prepared: &Prepared,
    db_root: &Path,
    base_url: &str,
) -> Result<(), CliError> {
    let lockfile = crate::lockfile::Lockfile::read(&prepared.manifest.root)?;
    for dep in lockfile.packages() {
        // `Lockfile::read` parses each `name` into a `PackageName` — a single
        // non-traversing path component by construction — so a hand-edited
        // `ipe.lock` name never reaches the registry URL segment or the
        // advisory-DB path join raw.
        check_one_dep_advisories(db_root, &dep.name, dep.version.as_semver(), base_url)?;
    }
    Ok(())
}

/// Cross-check one locked dep against the advisory DB, preferring the registry
/// Pages HTTP read-path and falling back to the git-checkout DB at `db_root`.
///
/// The Pages fast-path fetches `/advisories/index.json` + the per-advisory
/// records. A reachable index is authoritative for this run — even an empty
/// result proves the dep clean. When the index (or a named record) is unreachable
/// (offline / air-gapped / an empty `base_url` opt-out), this is a WARN, never a
/// silent all-clear: the check falls back to the git-checkout advisory DB, which
/// is itself fail-closed on a malformed or unreadable file.
///
/// # Errors
/// [`CliError::AdvisoryVulnerable`] on a `high`/`critical` match (from either
/// source); [`CliError::AdvisoryDbMalformed`] / [`CliError::AdvisoryDbUnreachable`]
/// when the fallback DB is present but corrupt or unreadable.
fn check_one_dep_advisories(
    db_root: &Path,
    name: &crate::package_name::PackageName,
    version: &semver::Version,
    base_url: &str,
) -> Result<(), CliError> {
    let name = name.as_str();
    let outcome = crate::registry::fetch_advisories_via_pages_with(
        name,
        base_url,
        &crate::registry::net_fetch,
    )?;
    match outcome {
        crate::registry::PagesAdvisoryOutcome::Fetched(advisories) => {
            crate::advisory::evaluate_advisories(name, version, &advisories)
        }
        crate::registry::PagesAdvisoryOutcome::Unreachable => {
            crate::screen::chatter(
                crate::screen::Stream::Stderr,
                crate::screen::Tone::UserError,
                &format!(
                    "warning: the registry advisory database was unreachable over HTTP for \
                     `{name}` — falling back to the local advisory checkout. Advisory coverage \
                     is only as fresh as that checkout."
                ),
            );
            crate::advisory::check_dep_advisories(db_root, name, version)
        }
    }
}

/// Locate the workspace's `deny.toml` so the supply-chain check applies the same
/// posture the workspace CI does. Walks up from the current directory, then from
/// the resolved runtime tree's ancestry (the runtime lives inside the workspace,
/// so `deny.toml` sits at the workspace root above it). Returns `None` when no
/// `deny.toml` is found.
fn locate_workspace_deny_config() -> Option<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        roots.push(cwd);
    }
    if let Ok(runtime) = crate::resolve_runtime() {
        roots.push(runtime);
    }
    for root in roots {
        let mut here: Option<&Path> = Some(root.as_path());
        while let Some(dir) = here {
            let candidate = dir.join("deny.toml");
            if candidate.is_file() {
                return Some(candidate);
            }
            here = dir.parent();
        }
    }
    None
}

/// Derive a cargo-deny config for the EMITTED project from the workspace's
/// `deny.toml`, dropping its `[graph]` section.
///
/// The workspace config's `[graph] features = ["full"]` names the RUNTIME crate's
/// own feature set, which the emitted `ipe-app` does not have — passing the
/// workspace config verbatim makes `cargo metadata` fail on the unknown feature.
/// The advisory/license/bans/sources POLICY is exactly what the gate must apply,
/// so this copies every section EXCEPT `[graph]` into a derived config written
/// beside the emitted project, and returns its path. Returns `None` when no
/// workspace `deny.toml` is found (cargo-deny then uses its defaults).
///
/// # Errors
/// [`CliError::Io`] on a read/write failure.
fn derive_deny_config(emitted_dir: &Path) -> Result<Option<PathBuf>, CliError> {
    let Some(source) = locate_workspace_deny_config() else {
        return Ok(None);
    };
    let text =
        crate::io_bounded::read_to_string_capped(&source, crate::io_bounded::SMALL_FILE_READ_CAP)?;

    // Line-filter out the `[graph]` table (up to the next top-level `[section]`).
    // The remaining tables (`[advisories]`, `[licenses]`, `[bans]`, `[sources]`)
    // are the emitted-project-independent policy the gate applies.
    let mut out = String::with_capacity(text.len());
    let mut in_graph = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') {
            in_graph = trimmed.starts_with("[graph]");
        }
        if !in_graph {
            out.push_str(line);
            out.push('\n');
        }
    }

    let derived = emitted_dir.join("ipe-audit-deny.toml");
    std::fs::write(&derived, out).map_err(|e| CliError::Io {
        path: derived.clone(),
        source: e,
    })?;
    Ok(Some(derived))
}

/// Refuse a package whose own module set claims a reserved namespace (`Ipe.*`,
/// `Rust.*` — the closed [`ipe_kernels::RESERVED_MODULE_PREFIXES`] set) unless it
/// is published by the blessed first-party identity.
///
/// The trusted `Ipe.*` namespace is the bundled, reviewed stdlib; a third-party
/// package providing an `Ipe.*` module could masquerade as first-party or shadow
/// a stdlib module a consumer trusts. The module set is read from the package's
/// own source tree (`src/`), not from the package NAME — a package named `foo`
/// that declares `module Ipe.Evil` is what this catches.
///
/// Fail-closed default-deny: a reserved-namespace module is rejected unless
/// `standing` carries a [`BlessedPublisher`] proof covering the claimed publisher
/// — a claimed `publisher` alone, however it is spelled, never exempts. The
/// reject NAMES the package and the offending module.
///
/// # Errors
/// [`CliError::PackageAudit`] with [`Check::ReservedNamespace`] when a
/// non-blessed package provides a reserved-namespace module; [`CliError::Io`] /
/// [`CliError::DiscoveryLimitReached`] if the source tree cannot be walked.
fn reserved_namespace_ownership(
    prepared: &Prepared,
    standing: PublisherStanding<'_>,
) -> Result<(), CliError> {
    let modules = crate::project::discover_modules(&prepared.manifest.src_root)?;
    let module_paths: Vec<&[String]> = modules
        .iter()
        .map(crate::project::DiscoveredModule::module_path)
        .collect();
    reserved_namespace_verdict(&prepared.manifest.name, &module_paths, standing)
}

/// The publisher an audit runs under: what the entry claims, and the proof (or
/// the refusal) that the claim is the blessed first-party identity.
#[derive(Clone, Copy, Debug)]
struct PublisherStanding<'a> {
    /// The claimed publisher (`--publisher`), named in a reject; `None` for a
    /// plain local audit with no provenance.
    claimed: Option<&'a SelfDeclaredPublisher>,
    /// The blessing an authenticated or attested identity established, or why
    /// none was.
    blessing: Result<&'a BlessedPublisher, &'a BlessingRefusal>,
}

impl PublisherStanding<'_> {
    /// Whether the proof covers the claim — the only way to the blessed
    /// exemption.
    fn is_proven_blessed(self) -> bool {
        match (self.blessing, self.claimed) {
            (Ok(blessed), Some(claimed)) => blessed.vouches_for(claimed),
            _ => false,
        }
    }

    /// The `(…)` provenance clause a reserved-namespace reject names.
    fn describe(self) -> String {
        let who = self.claimed.map_or_else(
            || "with no first-party provenance".to_owned(),
            |claimed| format!("published by `{claimed}`"),
        );
        let reason = self
            .blessing
            .err()
            .map_or_else(String::new, |refusal| format!("; {refusal}"));
        format!("{who}{reason}")
    }
}

/// The pure core of [`reserved_namespace_ownership`]: over an already-discovered
/// module set, refuse a reserved-namespace module unless the publisher is the
/// blessed first-party identity.
///
/// Fail-closed default-deny: the blessed exemption applies ONLY when `standing`
/// proves the claimed publisher is the blessed identity. An absent claim (a plain
/// local audit), an unproven claim (a forged `publisher`), or any other publisher
/// rejects on a reserved package name, or on the first reserved-namespace module,
/// naming the package, the offending name, and why the exemption was refused.
///
/// Both the package NAME and the module namespaces are reserved: a package whose
/// name lives in a reserved package namespace is refused on the name alone, even
/// when its modules are all ordinary, so a squatted probe name cannot ride the
/// smoke auto-approve path.
///
/// # Errors
/// [`CliError::PackageAudit`] with [`Check::ReservedNamespace`] when a
/// non-blessed package claims a reserved package name or provides a
/// reserved-namespace module.
fn reserved_namespace_verdict(
    package_name: &str,
    module_paths: &[&[String]],
    standing: PublisherStanding<'_>,
) -> Result<(), CliError> {
    let is_blessed = standing.is_proven_blessed();
    if let Some(prefix) = ipe_kernels::reserved_package_prefix_of(package_name)
        && !is_blessed
    {
        let who = standing.describe();
        return Err(reject(
            Check::ReservedNamespace,
            format!(
                "package `{package_name}` ({who}) claims the reserved `{prefix}-*` package \
                 namespace, owned by the first-party publisher `{}`; a third-party package \
                 must not take a name there.",
                ipe_kernels::BLESSED_PUBLISHER,
            ),
        ));
    }
    if is_blessed {
        // The blessed first-party publisher legitimately owns the reserved
        // package namespace and reserved module namespaces; nothing to refuse.
        return Ok(());
    }
    for module_path in module_paths {
        if let Some(prefix) = ipe_kernels::reserved_prefix_of(module_path) {
            let dotted = module_path.join(".");
            let who = standing.describe();
            return Err(reject(
                Check::ReservedNamespace,
                format!(
                    "package `{package_name}` ({who}) provides module `{dotted}`, which claims the \
                     reserved `{prefix}.*` namespace. `{prefix}.*` is owned by the first-party \
                     publisher `{}`; a third-party package must not declare a module there.",
                    ipe_kernels::BLESSED_PUBLISHER,
                ),
            ));
        }
    }
    Ok(())
}

/// Build a [`CliError::PackageAudit`] for `check` carrying `message`.
const fn reject(check: Check, message: String) -> CliError {
    CliError::PackageAudit(Rejection { check, message })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::published_version::VersionRefusal;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn audit_parses_output_format_flags() {
        let (_, _, _, _, _, fmt) = parse_audit_args(&args(&["--json"])).expect("json");
        assert_eq!(fmt, OutputFormat::Json);
        let (_, _, _, _, _, fmt) = parse_audit_args(&args(&["--plain"])).expect("plain");
        assert_eq!(fmt, OutputFormat::Plain);
        let (_, _, _, _, _, fmt) = parse_audit_args(&args(&[])).expect("default");
        assert_eq!(fmt, OutputFormat::Human);
    }

    #[test]
    fn audit_parses_publisher_flag() {
        let (_, _, _, _, publisher, _) =
            parse_audit_args(&args(&["--publisher", "arthurmaciel"])).expect("publisher");
        assert_eq!(
            publisher.as_ref().map(SelfDeclaredPublisher::as_str),
            Some("arthurmaciel")
        );
        // Absent by default.
        let (_, _, _, _, publisher, _) = parse_audit_args(&args(&[])).expect("default");
        assert_eq!(publisher, None);
        // A value is required, and it may not be given twice.
        assert!(parse_audit_args(&args(&["--publisher"])).is_err());
        assert!(parse_audit_args(&args(&["--publisher", "a", "--publisher", "b"])).is_err());
        for hostile in ["", "evil\x1b[2J", "new\nline", "-lead", "sp ace"] {
            assert!(
                matches!(
                    parse_audit_args(&args(&["--publisher", hostile])),
                    Err(CliError::Usage(_))
                ),
                "--publisher {hostile:?} must be refused"
            );
        }
    }

    /// Run the reserved-namespace verdict under `claimed`, with the blessing an
    /// admission-workflow attestation of `attested` establishes for it.
    fn verdict(
        package_name: &str,
        module_paths: &[&[String]],
        claimed: Option<&str>,
        attested: Option<&str>,
    ) -> Result<(), CliError> {
        let claimed = claimed.map(|c| SelfDeclaredPublisher::parse(c).expect("login-shaped claim"));
        let attested = attested
            .map(|a| crate::publisher::AttestedActor::parse(a).expect("login-shaped attestation"));
        let blessing = claimed
            .as_ref()
            .map_or(Err(BlessingRefusal::NoProvenIdentity), |claimed| {
                BlessedPublisher::from_attested(attested.as_ref(), claimed)
            });
        reserved_namespace_verdict(
            package_name,
            module_paths,
            PublisherStanding {
                claimed: claimed.as_ref(),
                blessing: blessing.as_ref(),
            },
        )
    }

    /// Whether `result` is a `ReservedNamespace` audit reject.
    fn is_reserved_reject(result: &Result<(), CliError>) -> bool {
        matches!(
            result,
            Err(CliError::PackageAudit(Rejection {
                check: Check::ReservedNamespace,
                ..
            }))
        )
    }

    #[test]
    fn reserved_namespace_refuses_a_forged_blessed_claim_without_attestation() {
        // A committed entry claiming `publisher = "<blessed>"` with no attested
        // identity is refused on a reserved name AND on a reserved module.
        let blessed = ipe_kernels::BLESSED_PUBLISHER;
        let app_mod: &[String] = &["App".to_owned(), "View".to_owned()];
        let ipe_mod: &[String] = &["Ipe".to_owned(), "Evil".to_owned()];
        let by_name = verdict("ipe-registry-smoke-probe", &[app_mod], Some(blessed), None);
        assert!(is_reserved_reject(&by_name), "{by_name:?}");
        let by_module = verdict("totally-legit", &[ipe_mod], Some(blessed), None);
        assert!(is_reserved_reject(&by_module), "{by_module:?}");
        let message = by_module.expect_err("rejected").to_string();
        assert!(
            message.contains("self-declared"),
            "the reject says why the claim was not trusted: {message}"
        );
    }

    #[test]
    fn reserved_namespace_refuses_an_attestation_not_matching_the_claim() {
        // The attested PR author is someone else: the blessed claim is forged.
        let blessed = ipe_kernels::BLESSED_PUBLISHER;
        let app_mod: &[String] = &["App".to_owned(), "View".to_owned()];
        let forged = verdict(
            "ipe-registry-smoke-probe",
            &[app_mod],
            Some(blessed),
            Some("attacker"),
        );
        assert!(is_reserved_reject(&forged), "{forged:?}");
        // The blessed author attesting an entry that claims someone else is also
        // not a blessed publish.
        let crossed = verdict(
            "ipe-registry-smoke-probe",
            &[app_mod],
            Some("attacker"),
            Some(blessed),
        );
        assert!(is_reserved_reject(&crossed), "{crossed:?}");
    }

    #[test]
    fn reserved_namespace_refuses_a_non_blessed_attestation() {
        // A consistent claim + attestation that is not the blessed identity.
        let ipe_mod: &[String] = &["Ipe".to_owned(), "Palette".to_owned()];
        let result = verdict("ipe-stdlib", &[ipe_mod], Some("someone"), Some("someone"));
        assert!(is_reserved_reject(&result), "{result:?}");
    }

    #[test]
    fn reserved_namespace_rejects_third_party_ipe_module() {
        // A package (whatever its own name) whose source provides `Ipe.Evil`,
        // published by a non-blessed account, is refused fail-closed.
        let ipe_evil: &[String] = &["Ipe".to_owned(), "Evil".to_owned()];
        let err = verdict(
            "totally-legit",
            &[ipe_evil],
            Some("attacker"),
            Some("attacker"),
        )
        .expect_err("third-party Ipe.Evil must be rejected");
        assert!(
            matches!(
                &err,
                CliError::PackageAudit(Rejection {
                    check: Check::ReservedNamespace,
                    ..
                })
            ),
            "expected a ReservedNamespace reject, got {err:?}"
        );
        // The reject names the package and the offending module.
        let message = err.to_string();
        assert!(message.contains("totally-legit"), "message: {message}");
        assert!(message.contains("Ipe.Evil"), "message: {message}");
    }

    #[test]
    fn reserved_namespace_rejects_absent_publisher() {
        // A plain local audit (no index provenance) refuses a reserved-namespace
        // module: the blessed exemption needs an explicit blessed publisher.
        let ipe_mod: &[String] = &["Ipe".to_owned(), "String".to_owned()];
        let err = verdict("squatter", &[ipe_mod], None, None)
            .expect_err("no-provenance Ipe.* must be rejected");
        assert!(matches!(
            err,
            CliError::PackageAudit(Rejection {
                check: Check::ReservedNamespace,
                ..
            })
        ));
    }

    #[test]
    fn reserved_namespace_accepts_blessed_publisher() {
        // The blessed first-party publisher, proven by attestation, legitimately
        // owns `Ipe.*`.
        let ipe_mod: &[String] = &["Ipe".to_owned(), "Palette".to_owned()];
        assert!(
            verdict(
                "ipe-stdlib",
                &[ipe_mod],
                Some(ipe_kernels::BLESSED_PUBLISHER),
                Some(ipe_kernels::BLESSED_PUBLISHER),
            )
            .is_ok()
        );
    }

    #[test]
    fn reserved_namespace_accepts_non_reserved_module_from_any_publisher() {
        // A package in an ordinary namespace is fine from any publisher.
        let app_mod: &[String] = &["App".to_owned(), "View".to_owned()];
        assert!(verdict("cool-lib", &[app_mod], Some("anyone"), Some("anyone")).is_ok());
        assert!(verdict("cool-lib", &[app_mod], None, None).is_ok());
    }

    #[test]
    fn reserved_package_name_rejects_third_party_publisher() {
        // A package NAMED in the reserved smoke namespace, published by a
        // non-blessed account, is refused on the name alone — even though its
        // modules are all ordinary.
        let app_mod: &[String] = &["App".to_owned(), "View".to_owned()];
        let err = verdict(
            "ipe-registry-smoke-probe",
            &[app_mod],
            Some("attacker"),
            Some("attacker"),
        )
        .expect_err("third-party reserved package name must be rejected");
        assert!(
            matches!(
                &err,
                CliError::PackageAudit(Rejection {
                    check: Check::ReservedNamespace,
                    ..
                })
            ),
            "expected a ReservedNamespace reject, got {err:?}"
        );
        // The reject names the package and the reserved package namespace.
        let message = err.to_string();
        assert!(
            message.contains("ipe-registry-smoke-probe"),
            "message: {message}"
        );
        assert!(
            message.contains("ipe-registry-smoke-*"),
            "message: {message}"
        );
    }

    #[test]
    fn reserved_package_name_rejects_absent_publisher() {
        // A plain local audit (no provenance) refuses a reserved package name:
        // the blessed exemption needs an explicit blessed publisher.
        let app_mod: &[String] = &["App".to_owned(), "View".to_owned()];
        let err = verdict("ipe-registry-smoke-probe-bad", &[app_mod], None, None)
            .expect_err("no-provenance reserved package name must be rejected");
        assert!(matches!(
            err,
            CliError::PackageAudit(Rejection {
                check: Check::ReservedNamespace,
                ..
            })
        ));
    }

    #[test]
    fn reserved_package_name_accepts_blessed_publisher() {
        // The blessed first-party publisher, proven by attestation, legitimately
        // owns the reserved package namespace.
        let app_mod: &[String] = &["App".to_owned(), "View".to_owned()];
        assert!(
            verdict(
                "ipe-registry-smoke-probe",
                &[app_mod],
                Some(ipe_kernels::BLESSED_PUBLISHER),
                Some(ipe_kernels::BLESSED_PUBLISHER),
            )
            .is_ok()
        );
    }

    #[test]
    fn non_reserved_package_name_accepts_any_publisher() {
        // A name that merely shares the leading characters without a hyphen
        // segment boundary is not reserved, from any publisher.
        let app_mod: &[String] = &["App".to_owned(), "View".to_owned()];
        assert!(
            verdict(
                "ipe-registry-smokehouse",
                &[app_mod],
                Some("anyone"),
                Some("anyone")
            )
            .is_ok()
        );
        assert!(verdict("ipe-registry-smokehouse", &[app_mod], None, None).is_ok());
    }

    #[test]
    fn audit_rejects_plain_and_json_together() {
        assert!(parse_audit_args(&args(&["--plain", "--json"])).is_err());
        assert!(parse_audit_args(&args(&["--json", "--json"])).is_err());
    }

    #[test]
    fn audit_verdict_json_is_compact_pass_and_fail() {
        use crate::audit_native::Tier2Outcome;

        let disclosure = Disclosure {
            control_model: ControlModelDisclosure::Entry(crate::delivery::ControlModel::Tea),
            capabilities: BTreeSet::from([Capability::Clock, Capability::Network]),
        };
        let pass = audit_verdict_json(
            "http",
            "1.2.0",
            &Ok((Tier2Outcome::SkippedPureIpe, disclosure)),
        );
        // The verdict discloses the compiler-derived control model and the
        // capability set, byte-uniform compact.
        assert!(
            pass.contains("\"controlModel\":\"tea\""),
            "control model: {pass}"
        );
        assert!(
            pass.contains("\"capabilities\":["),
            "capabilities disclosed: {pass}"
        );
        assert!(pass.contains("\"clock\""), "clock axis present: {pass}");
        assert!(pass.contains("\"network\""), "network axis present: {pass}");
        assert!(pass.contains("\"certified\":true"), "pass verdict: {pass}");
        assert!(!pass.contains(", "), "compact pass: {pass}");

        let fail = audit_verdict_json(
            "http",
            "1.2.0",
            &Err(reject(
                Check::Capability,
                "used but not declared".to_owned(),
            )),
        );
        assert!(fail.contains("\"certified\":false"), "fail verdict: {fail}");
        assert!(fail.contains("\"reason\":"), "carries a reason: {fail}");
        // A rejected audit discloses NO control model — a fail-open default is
        // never surfaced.
        assert!(
            !fail.contains("\"controlModel\""),
            "a reject discloses no control model: {fail}"
        );
        // Byte-uniform compact: no space after a comma.
        assert!(!fail.contains(", "), "compact: {fail}");
    }

    #[test]
    fn control_model_disclosure_word_is_the_models_word_or_library() {
        assert_eq!(
            ControlModelDisclosure::Entry(crate::delivery::ControlModel::Tea).word(),
            "tea"
        );
        assert_eq!(
            ControlModelDisclosure::Entry(crate::delivery::ControlModel::Direct).word(),
            "direct"
        );
        assert_eq!(ControlModelDisclosure::NotApplicable.word(), "library");
    }

    #[test]
    fn disclosure_summary_lists_capabilities_or_none() {
        let with_caps = Disclosure {
            control_model: ControlModelDisclosure::Entry(crate::delivery::ControlModel::Direct),
            capabilities: BTreeSet::from([Capability::Clock]),
        };
        let s = disclosure_summary("pkg", &with_caps);
        assert!(s.contains("control model: direct"), "names the model: {s}");
        assert!(s.contains("capabilities: clock"), "lists the axis: {s}");

        let empty = Disclosure {
            control_model: ControlModelDisclosure::NotApplicable,
            capabilities: BTreeSet::new(),
        };
        let s = disclosure_summary("lib", &empty);
        assert!(s.contains("control model: library"), "library marker: {s}");
        assert!(
            s.contains("capabilities: none"),
            "empty set reads none: {s}"
        );
    }

    /// Build a unique throwaway directory under the OS temp root for a test.
    /// Returns the path; the caller must remove it when done.
    fn make_test_dir(tag: &str) -> PathBuf {
        let dir = ipe_test_temp::temp_root().join(format!(
            "ipe-audit-test-{tag}-{}-{}",
            std::process::id(),
            // A per-call counter keeps multiple calls in the same test from
            // colliding.  A static is fine here — tests run in the same process.
            {
                use std::sync::atomic::{AtomicU64, Ordering};
                static N: AtomicU64 = AtomicU64::new(0);
                N.fetch_add(1, Ordering::Relaxed)
            }
        ));
        std::fs::create_dir_all(&dir).expect("create test scratch dir");
        dir
    }

    /// A manifest that carries a `[rust.wrapper]` section is rejected at the
    /// `prepare` step with a [`Check::NativeBindingRegen`] rejection.
    ///
    /// Wrapper bindings are author-asserted (local path, no registry pin, rev, or
    /// hash); the gate has no independent source to regenerate from, so it must
    /// refuse rather than read committed author-written `_bindings.rs`.
    #[test]
    fn prepare_rejects_rust_wrapper_at_admission() {
        use std::io::Write as _;

        let dir = make_test_dir("wrapper-reject");
        let src = dir.join("src");
        std::fs::create_dir(&src).expect("create src/");
        // A minimal main module so the project looks structurally valid.
        std::fs::write(src.join("Main.ipe"), "module Main exposing (..)\n")
            .expect("write Main.ipe");

        let manifest_path = dir.join("package.ipe");
        let mut f = std::fs::File::create(&manifest_path).expect("create package.ipe");
        writeln!(
            f,
            "module Package exposing (package)\n\n\npackage =\n\
             \x20   {{ name = \"wrapper-pkg\"\n\
             \x20   , version = \"0.1.0\"\n\
             \x20   , wrapper = Wrapper {{ path = \"./my-crate\", expose = [ \"some_fn\" ] }}\n\
             \x20   }}\n"
        )
        .expect("write package.ipe");

        let err = prepare(&dir).expect_err("prepare must reject a wrapper-only package");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(err, CliError::PackageAudit(_)),
            "expected PackageAudit, got: {err:?}"
        );
        if let CliError::PackageAudit(ref r) = err {
            assert_eq!(
                r.check,
                Check::NativeBindingRegen,
                "wrong check: must be NativeBindingRegen, got {:?}",
                r.check
            );
            assert!(
                r.message.contains("`wrapper` field"),
                "rejection message must name the wrapper field: {}",
                r.message
            );
        }
    }

    /// A manifest with only `[rust.dependencies]` (no `[rust.wrapper]`) must NOT
    /// be rejected by the wrapper admission guard — the `[rust.dependencies]` path
    /// still proceeds to the regeneration step unchanged.
    ///
    /// This test exercises only the admission predicate through manifest parsing
    /// (not the full `prepare` which requires a sandboxed inspector), confirming
    /// that the new wrapper guard does not perturb the existing
    /// `[rust.dependencies]` path.
    #[test]
    fn prepare_does_not_reject_rust_dependencies_only_manifest() {
        use std::io::Write as _;

        let dir = make_test_dir("dep-only");
        let src = dir.join("src");
        std::fs::create_dir(&src).expect("create src/");
        std::fs::write(src.join("Main.ipe"), "module Main exposing (..)\n")
            .expect("write Main.ipe");

        let manifest_path = dir.join("package.ipe");
        let mut f = std::fs::File::create(&manifest_path).expect("create package.ipe");
        writeln!(
            f,
            "module Package exposing (package)\n\n\npackage =\n\
             \x20   {{ name = \"dep-pkg\"\n\
             \x20   , version = \"0.1.0\"\n\
             \x20   , rustDependencies = [ rustDep \"uuid\" \"1\" ]\n\
             \x20   , capabilities = {{ declares = [ NativeFfi ] }}\n\
             \x20   }}\n"
        )
        .expect("write package.ipe");

        let manifest = crate::project::parse_manifest(&manifest_path)
            .expect("manifest with rust dependencies must parse");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            !manifest.has_rust_wrapper,
            "has_rust_wrapper must be false for a rust-dependencies-only manifest"
        );
    }

    /// A manifest with no FFI sections (pure Ipê) is not affected by the wrapper
    /// guard and must parse with `has_rust_wrapper = false`.
    #[test]
    fn pure_ipe_manifest_has_rust_wrapper_is_false() {
        use std::io::Write as _;

        let dir = make_test_dir("pure-ipe");
        let src = dir.join("src");
        std::fs::create_dir(&src).expect("create src/");
        std::fs::write(src.join("Main.ipe"), "module Main exposing (..)\n")
            .expect("write Main.ipe");

        let manifest_path = dir.join("package.ipe");
        let mut f = std::fs::File::create(&manifest_path).expect("create package.ipe");
        writeln!(
            f,
            "module Package exposing (package)\n\n\npackage =\n\
             \x20   {{ name = \"pure-pkg\", version = \"0.1.0\" }}\n"
        )
        .expect("write package.ipe");

        let manifest =
            crate::project::parse_manifest(&manifest_path).expect("pure manifest must parse");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            !manifest.has_rust_wrapper,
            "has_rust_wrapper must be false for a pure-Ipê manifest"
        );
    }

    /// `ffi_cache_path_or_reject` refuses a cache path whose `.ipe` component
    /// is a symlink, preventing a delete-through-symlink attack — the same
    /// containment that guards `[rust.dependencies]` regeneration.
    #[test]
    #[cfg(unix)]
    fn ffi_cache_path_or_reject_refuses_symlinked_cache_component() {
        use std::os::unix::fs::symlink;

        let dir = make_test_dir("symlink-reject");
        let target = make_test_dir("symlink-target");

        // Plant `.ipe` as a symlink pointing outside the project root.
        let ipe_link = dir.join(".ipe");
        symlink(&target, &ipe_link).expect("create .ipe symlink");

        let err =
            ffi_cache_path_or_reject(&dir).expect_err("must reject a symlinked .ipe component");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&target);
        assert!(
            matches!(err, CliError::PackageAudit(_)),
            "expected PackageAudit, got: {err:?}"
        );
        if let CliError::PackageAudit(ref r) = err {
            assert_eq!(
                r.check,
                Check::NativeBindingRegen,
                "wrong check on symlink reject: {:?}",
                r.check
            );
            assert!(
                r.message.contains("symlink"),
                "rejection message must mention symlink: {}",
                r.message
            );
        }
    }

    // -----------------------------------------------------------------------
    // first_hit — non-lexing source must refuse (instance #3 regression)
    // -----------------------------------------------------------------------

    #[test]
    fn first_hit_non_lexing_source_is_refused_not_admitted() {
        // A `_bindings.rs` that does not lex as Rust tokens must produce Err,
        // not Ok(None). Returning Ok(None) would silently pass the no-panic
        // gate for a file whose content cannot be attested.
        let dir = make_test_dir("first-hit-nonlex");
        let file = dir.join("x_bindings.rs");
        // Unterminated raw string — proc-macro2 cannot tokenise this.
        std::fs::write(&file, r#"fn f() { let x = r##"unterminated"#)
            .expect("write non-lexing fixture");
        let result = super::first_hit(&file);
        assert!(
            result.is_err(),
            "a non-lexing _bindings.rs must return Err (refuse), not Ok(None)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn first_hit_clean_lexing_source_is_ok_none() {
        // A well-formed, panic-free file must still return Ok(None).
        let dir = make_test_dir("first-hit-clean");
        let file = dir.join("x_bindings.rs");
        std::fs::write(&file, "pub fn add(a: i64, b: i64) -> i64 { a + b }")
            .expect("write clean fixture");
        let result = super::first_hit(&file);
        assert!(result.is_ok(), "a clean file must return Ok(_)");
        assert!(
            result.unwrap().is_none(),
            "a panic-free file must return Ok(None)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn first_hit_file_with_panic_is_ok_some() {
        // A file with a panic! must produce Ok(Some(hit)), unchanged.
        let dir = make_test_dir("first-hit-panic");
        let file = dir.join("x_bindings.rs");
        std::fs::write(&file, "pub fn f() { panic!(\"oops\"); }").expect("write panic fixture");
        let result = super::first_hit(&file);
        assert!(result.is_ok(), "a lexing file must return Ok(_)");
        assert!(
            result.unwrap().is_some(),
            "a panic-bearing file must return Ok(Some(_))"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Disclosure derivation (control model + capabilities) ────────────────

    /// Write a project with a single `src/Main.ipe` of `main_src` and return a
    /// `Prepared` pointing at it. Only the manifest's `src_root` and `programs`
    /// matter to [`derive_disclosure`].
    fn prepared_with_main(tag: &str, main_src: &str) -> (PathBuf, Prepared) {
        let dir = make_test_dir(tag);
        let src = dir.join("src");
        std::fs::create_dir_all(&src).expect("create src/");
        std::fs::write(src.join("Main.ipe"), main_src).expect("write Main.ipe");
        let prepared = make_prepared(&dir);
        (dir, prepared)
    }

    #[test]
    fn disclosure_derives_tea_for_a_web_tea_entry() {
        let (dir, prepared) = prepared_with_main(
            "disclosure-tea",
            "module Main exposing (main)\n\
             import Ipe.Tea.Web as Web\n\n\
             main = Web.tea config\n",
        );
        let d = derive_disclosure(&prepared, BTreeSet::new()).expect("derives");
        assert_eq!(
            d.control_model,
            ControlModelDisclosure::Entry(crate::delivery::ControlModel::Tea),
            "a `Web.tea` entry discloses the TEA control model"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disclosure_derives_direct_for_a_plain_task_main() {
        let (dir, prepared) = prepared_with_main(
            "disclosure-direct",
            "module Main exposing (main)\n\n\
             main = doNothing\n",
        );
        let d = derive_disclosure(&prepared, BTreeSet::new()).expect("derives");
        assert_eq!(
            d.control_model,
            ControlModelDisclosure::Entry(crate::delivery::ControlModel::Direct),
            "a plain-`Task` `main` discloses the Direct control model"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disclosure_capabilities_are_the_inferred_set_passed_in() {
        // The disclosure surfaces exactly the SSOT inferred set it is handed —
        // never a re-derivation that could disagree with the consistency check.
        let (dir, prepared) = prepared_with_main(
            "disclosure-caps",
            "module Main exposing (main)\n\nmain = doNothing\n",
        );
        let inferred = BTreeSet::from([Capability::Clock, Capability::Network]);
        let d = derive_disclosure(&prepared, inferred.clone()).expect("derives");
        assert_eq!(d.capabilities, inferred, "discloses the passed-in SSOT set");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disclosure_is_not_applicable_for_a_library_with_no_runnable_entry() {
        // A library exposes modules but ships no runnable `Main.ipe`; it drives
        // nothing, so the disclosure is an honest absence, not a default model.
        let dir = make_test_dir("disclosure-library");
        let src = dir.join("src");
        std::fs::create_dir_all(&src).expect("create src/");
        std::fs::write(
            src.join("MyLib.ipe"),
            "module MyLib exposing (helper)\n\nhelper = 1\n",
        )
        .expect("write MyLib.ipe");
        let mut prepared = make_prepared(&dir);
        prepared.manifest.exposed_modules = vec!["MyLib".to_owned()];
        let d = derive_disclosure(&prepared, BTreeSet::new()).expect("derives");
        assert_eq!(
            d.control_model,
            ControlModelDisclosure::NotApplicable,
            "a library with no runnable entry discloses no control model"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disclosure_fails_closed_when_a_runnable_entry_does_not_parse() {
        // A `Main.ipe` exists (a runnable entry) but does not parse: the audit
        // must REJECT rather than disclose a permissive-looking default. This is
        // the fail-closed branch — a program whose control model we cannot state
        // is refused, never certified as `direct`/library.
        let (dir, prepared) = prepared_with_main(
            "disclosure-unparseable",
            "module Main exposing (main)\n\nmain = = = broken (((\n",
        );
        let err = derive_disclosure(&prepared, BTreeSet::new())
            .expect_err("an unparseable runnable entry must fail closed");
        assert!(
            matches!(err, CliError::PackageAudit(ref r) if r.check == Check::Capability),
            "fail-closed on an underivable control model is a Capability rejection: {err:?}"
        );
        assert!(
            !err.to_string().contains("direct") && !err.to_string().contains("library"),
            "the fail-closed reject discloses no permissive default model: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_refuses_a_direct_entry_a_declared_accept_set_does_not_cover() {
        // The audit-boundary control-model consent (defence-in-depth): a package
        // that opted into control-model consent (a non-empty `acceptsControl`)
        // whose declared set does not cover its actual Direct model is refused —
        // fail-closed, never certified against a stale acceptance.
        let (dir, mut prepared) = prepared_with_main(
            "audit-consent-direct",
            "module Main exposing (main)\n\nmain = doNothing\n",
        );
        prepared.manifest.control_models_accept =
            std::iter::once(crate::delivery::ControlModel::Tea).collect();
        let disclosure = derive_disclosure(&prepared, BTreeSet::new()).expect("derives Direct");
        assert_eq!(
            disclosure.control_model,
            ControlModelDisclosure::Entry(crate::delivery::ControlModel::Direct),
            "a plain-Task entry discloses the Direct model"
        );
        let err = crate::control_model_consent::gate(
            crate::delivery::ControlModel::Direct,
            &prepared.manifest.control_models_accept,
            &prepared.manifest.name,
        )
        .expect_err("a declared accept-set that omits the derived model is refused");
        assert!(err.to_string().contains("IPE-S0004"), "carries the code");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_accepts_a_direct_entry_a_declared_accept_set_covers() {
        let (dir, mut prepared) = prepared_with_main(
            "audit-consent-direct-ok",
            "module Main exposing (main)\n\nmain = doNothing\n",
        );
        prepared.manifest.control_models_accept =
            std::iter::once(crate::delivery::ControlModel::Direct).collect();
        let disclosure = derive_disclosure(&prepared, BTreeSet::new()).expect("derives Direct");
        assert_eq!(
            disclosure.control_model,
            ControlModelDisclosure::Entry(crate::delivery::ControlModel::Direct),
        );
        crate::control_model_consent::gate(
            crate::delivery::ControlModel::Direct,
            &prepared.manifest.control_models_accept,
            &prepared.manifest.name,
        )
        .expect("a Direct entry a declared accept-set covers passes");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_leaves_a_clean_entry_with_no_accept_set_unconstrained() {
        // A clean package with no `acceptsControl` — including a legitimate
        // self-driving Direct script — certifies: the model is disclosed, not
        // gated, until the author opts into control-model consent.
        let (dir, prepared) = prepared_with_main(
            "audit-consent-clean",
            "module Main exposing (main)\n\nmain = doNothing\n",
        );
        let disclosure = derive_disclosure(&prepared, BTreeSet::new()).expect("derives Direct");
        assert_eq!(
            disclosure.control_model,
            ControlModelDisclosure::Entry(crate::delivery::ControlModel::Direct),
        );
        assert!(
            prepared.manifest.control_models_accept.is_empty(),
            "the clean package declares no acceptsControl"
        );
        crate::control_model_consent::gate(
            crate::delivery::ControlModel::Direct,
            &prepared.manifest.control_models_accept,
            &prepared.manifest.name,
        )
        .expect("a clean Direct entry with no acceptsControl certifies unconstrained");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A prerelease submission is EXEMPT from the enforced-semver API-bump, even
    /// with a published predecessor of the same core version. Semver §9 makes a
    /// prerelease unstable and a stable version requirement never resolves it
    /// (`index::resolve_version` via `VersionReq::matches`), so requiring an API
    /// bump would reject a normal `X.Y.Z-a` → `X.Y.Z-b` iteration — the exact shape
    /// the live registry publish-smoke republishes each run. Hermetic: the
    /// exemption returns before any predecessor fetch, so no network is touched
    /// even though a predecessor exists in the baseline. (Release submissions still
    /// engage the bump — see `check_semver_bump` coverage in `diff` and
    /// `tests/diff_cli.rs`.)
    #[test]
    fn enforced_semver_exempts_a_prerelease_over_a_published_predecessor() {
        let index_root = make_test_dir("semver-prerelease-exempt");
        let pkgs = index_root.join("packages");
        std::fs::create_dir_all(&pkgs).expect("create packages/");
        std::fs::write(
            pkgs.join("test-pkg.toml"),
            "name = \"test-pkg\"\n\
             publisher = \"someone\"\n\n\
             [[version]]\n\
             version = \"0.0.0-smoke.1\"\n\
             source = \"https://github.com/example/test-pkg\"\n\
             rev = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\
             sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
        )
        .expect("write baseline entry");

        let mut prepared = make_prepared(&index_root.join("proj"));
        prepared.manifest.name = "test-pkg".to_owned();
        prepared.manifest.version = Some("0.0.0-smoke.2".parse().expect("valid prerelease"));

        let result = enforced_semver(&prepared, Some(&index_root));
        let _ = std::fs::remove_dir_all(&index_root);
        assert!(
            result.is_ok(),
            "a prerelease over a published predecessor is exempt from the bump: {result:?}"
        );
    }

    /// A published version from a literal the test knows is valid.
    #[allow(clippy::expect_used)] // test fixture: the literal is a valid published version
    fn published(raw: &str) -> PublishedVersion {
        PublishedVersion::parse(raw).expect("valid published version")
    }

    /// A manifest version carrying build metadata is refused by the enforced-semver
    /// check before any index read, prerelease or release alike: `+meta` never
    /// names a publishable version.
    #[test]
    fn enforced_semver_refuses_build_metadata() {
        let index_root = make_test_dir("semver-build-metadata");
        for raw in ["1.0.0+b", "0.0.0-smoke.2+sha.abc"] {
            let mut prepared = make_prepared(&index_root.join("proj"));
            prepared.manifest.version = Some(raw.parse().expect("valid semver with build"));
            let result = enforced_semver(&prepared, Some(&index_root));
            assert!(
                matches!(
                    &result,
                    Err(CliError::VersionRefused { refusal, .. })
                        if matches!(**refusal, VersionRefusal::BuildMetadata { .. })
                ),
                "{raw} must be refused for build metadata: {result:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&index_root);
    }

    /// Write a one-package index at `index_root` publishing `versions` of
    /// `test-pkg`.
    fn write_index_versions(index_root: &std::path::Path, versions: &[&str]) {
        use std::fmt::Write as _;
        let pkgs = index_root.join("packages");
        std::fs::create_dir_all(&pkgs).expect("create packages/");
        let mut body = "name = \"test-pkg\"\npublisher = \"someone\"\n".to_owned();
        for version in versions {
            let _ = write!(
                body,
                "\n[[version]]\n\
                 version = \"{version}\"\n\
                 source = \"https://github.com/example/test-pkg\"\n\
                 rev = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\
                 sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n"
            );
        }
        std::fs::write(pkgs.join("test-pkg.toml"), body).expect("write index entry");
    }

    /// A stable release whose only published predecessors are prereleases is a
    /// FIRST stable version: the check skips instead of diffing against the
    /// prerelease. Hermetic — the skip returns before any predecessor fetch.
    #[test]
    fn enforced_semver_skips_a_first_stable_release_over_only_prereleases() {
        let index_root = make_test_dir("semver-first-stable");
        write_index_versions(&index_root, &["0.0.1-rc.1"]);

        let mut prepared = make_prepared(&index_root.join("proj"));
        prepared.manifest.name = "test-pkg".to_owned();
        prepared.manifest.version = Some("0.0.1".parse().expect("valid release"));

        let result = enforced_semver(&prepared, Some(&index_root));
        let _ = std::fs::remove_dir_all(&index_root);
        assert!(
            result.is_ok(),
            "0.0.1-rc.1 -> 0.0.1 graduates as a first stable version: {result:?}"
        );
    }

    /// The baseline skips a prerelease for the release below it, so a breaking
    /// change carried in through an exempt prerelease (`0.1.0` → `0.1.1-rc.1`
    /// removes an export) is measured against `0.1.0` and `0.1.1` is refused.
    #[test]
    fn enforced_semver_baseline_skips_prereleases_so_a_smuggled_break_is_refused() {
        let index_root = make_test_dir("semver-stable-baseline");
        write_index_versions(&index_root, &["0.1.0", "0.1.1-rc.1", "0.2.0-rc.1"]);
        let entry = crate::index::read_entry_lookup(&index_root, "test-pkg")
            .absent_or_err()
            .expect("readable entry")
            .expect("entry present");
        let _ = std::fs::remove_dir_all(&index_root);

        let new_version = published("0.1.1");
        let baseline = stable_baseline(&entry.versions, &new_version).expect("a stable baseline");
        assert_eq!(baseline.version, published("0.1.0"));

        let with_export = |names: &[&str]| {
            let mut module = crate::api_surface::ModuleApi::default();
            for name in names {
                module.values.insert((*name).to_owned(), "Int".to_owned());
            }
            crate::api_surface::PublicApi {
                modules: std::iter::once((vec!["Lib".to_owned()], module)).collect(),
            }
        };
        let stable_api = with_export(&["f", "g"]);
        let rc_api = with_export(&["f"]);
        let report = crate::diff::report(
            &stable_api,
            &rc_api,
            baseline.version.as_semver(),
            new_version.as_semver(),
        )
        .expect("floor does not overflow");
        assert_eq!(report.floor, semver::Version::new(0, 2, 0));
        assert!(
            !report.satisfied,
            "a break smuggled through a prerelease still needs the minor bump"
        );

        assert!(
            stable_baseline(&entry.versions, &published("0.0.9")).is_none(),
            "no release below the new version is a first stable version"
        );
    }

    // ── Advisory-check gate-level tests ─────────────────────────────────────

    /// Build a minimal `Prepared` whose `manifest.root` points at `root`.
    /// Only `manifest.root` is used by `advisory_check` (to read `ipe.lock`).
    fn make_prepared(root: &std::path::Path) -> Prepared {
        use std::collections::{BTreeMap, BTreeSet};
        Prepared {
            manifest: crate::project::ProjectManifest {
                name: "test-pkg".to_owned(),
                version: None,
                root: root.to_path_buf(),
                src_root: root.join("src"),
                icon: None,
                driver: ipe_backend_rust::DbDriver::default(),
                static_request: crate::build_plan::StaticRequestLayer::default(),
                wasm: crate::project::WasmConfig::default(),
                dependencies: BTreeMap::new(),
                rust_dependencies: BTreeMap::new(),
                capabilities: BTreeSet::new(),
                capabilities_accept: BTreeSet::new(),
                control_models_accept: BTreeSet::new(),
                has_rust_wrapper: false,
                programs: Vec::new(),
                exposed_modules: Vec::new(),
                delivery: crate::project::DeliveryConfig::default(),
            },
            manifest_path: root.join("package.ipe"),
            emitted_dir: root.join("emitted"),
        }
    }

    /// Write a minimal `ipe.lock` with one locked dep to `project_root`.
    fn write_lockfile(project_root: &std::path::Path, pkg_name: &str, version: &str) {
        let content = format!(
            "# ipe.lock\n\
             [[package]]\n\
             name = \"{pkg_name}\"\n\
             version = \"{version}\"\n\
             source = \"https://github.com/example/{pkg_name}\"\n\
             rev = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\
             sha256 = \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"\n\
             kind = \"index\"\n"
        );
        std::fs::write(project_root.join("ipe.lock"), content).expect("write ipe.lock");
    }

    /// Write a high-severity advisory for `pkg_name` into `db_root/advisories/<pkg_name>/`.
    fn write_high_advisory(db_root: &std::path::Path, pkg_name: &str, affected: &str) {
        let dir = db_root.join("advisories").join(pkg_name);
        std::fs::create_dir_all(&dir).expect("create advisory dir");
        let content = format!(
            "id          = \"IPE-TEST-0001\"\n\
             package     = \"{pkg_name}\"\n\
             severity    = \"high\"\n\
             affected    = \"{affected}\"\n\
             description = \"Test high-severity vulnerability.\"\n"
        );
        std::fs::write(dir.join("IPE-TEST-0001.toml"), content).expect("write advisory toml");
    }

    /// Default-on gate-level test: planting a high advisory for a locked dep and
    /// passing `Some(db_root)` to `advisory_check` must produce a typed
    /// `AdvisoryVulnerable` rejection. This is the path `run_audit` takes when
    /// `--no-advisory-db` is absent — it resolves the registry checkout and always
    /// passes `Some(effective_db)`.
    #[test]
    fn advisory_check_rejects_high_severity_dep_from_planted_db() {
        let dir = make_test_dir("adv-gate-reject");
        let db = make_test_dir("adv-gate-db");
        write_lockfile(&dir, "vuln-pkg", "1.1.0");
        write_high_advisory(&db, "vuln-pkg", ">=1.0.0, <1.2.0");

        let prepared = make_prepared(&dir);
        // Empty base URL disables the HTTP fast-path (hermetic, off-network); the
        // planted git-checkout DB is authoritative on the fallback path.
        let result = advisory_check_with_base(&prepared, &db, "");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&db);
        assert!(
            matches!(result, Err(CliError::AdvisoryVulnerable(_))),
            "high-severity dep in range must be rejected: {result:?}"
        );
    }

    /// Explicit opt-out gate-level test: `advisory_check(prepared, None)` must
    /// return `Ok(())` — `None` is the explicit `--no-advisory-db` opt-out path.
    #[test]
    fn advisory_check_none_skips_check() {
        let dir = make_test_dir("adv-gate-skip");
        let db = make_test_dir("adv-gate-db-skip");
        write_lockfile(&dir, "vuln-pkg", "1.1.0");
        write_high_advisory(&db, "vuln-pkg", ">=1.0.0, <1.2.0");

        let prepared = make_prepared(&dir);
        let result = advisory_check(&prepared, None);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&db);
        assert!(result.is_ok(), "explicit opt-out must pass: {result:?}");
    }

    /// Defend-in-depth refusal: a hand-edited `ipe.lock` whose dep `name` is a
    /// path-traversing value must be rejected at the audit boundary with a typed
    /// error, before the name can reach a registry URL segment or the advisory-DB
    /// path join. The lockfile is re-read from disk here, so it is untrusted even
    /// though the resolver validates names on write.
    #[test]
    fn advisory_check_rejects_traversing_lockfile_name() {
        for hostile in ["../../x", ".."] {
            let dir = make_test_dir("adv-gate-traversal");
            let db = make_test_dir("adv-gate-traversal-db");
            write_lockfile(&dir, hostile, "1.0.0");
            // Plant an advisory dir OUTSIDE the DB root that the unparsed join
            // would resolve to, proving the parse — not a missing file — is what
            // turns the read back.
            write_high_advisory(db.parent().unwrap_or(&db), "x", ">=0.0.0");

            let prepared = make_prepared(&dir);
            let result = advisory_check_with_base(&prepared, &db, "");
            let _ = std::fs::remove_dir_all(&dir);
            let _ = std::fs::remove_dir_all(&db);
            assert!(
                matches!(result, Err(CliError::Resolve(_))),
                "a traversing lockfile name `{hostile}` must be rejected at the boundary: {result:?}"
            );
        }
    }

    /// The refusal is fail-closed but not over-broad: a legitimate `[a-z0-9-]`
    /// lockfile name with no matching advisory still passes cleanly through the
    /// same boundary.
    #[test]
    fn advisory_check_accepts_legit_lockfile_name() {
        let dir = make_test_dir("adv-gate-legit");
        let db = make_test_dir("adv-gate-legit-db");
        write_lockfile(&dir, "http-extras", "1.0.0");

        let prepared = make_prepared(&dir);
        let result = advisory_check_with_base(&prepared, &db, "");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&db);
        assert!(
            result.is_ok(),
            "a valid package name with no advisory must pass: {result:?}"
        );
    }

    /// `--no-advisory-db` flag is parsed correctly.
    #[test]
    fn parse_audit_args_no_advisory_db_sets_flag() {
        let (_, _, override_db, no_adv, _, _) =
            parse_audit_args(&args(&["--no-advisory-db"])).expect("--no-advisory-db accepted");
        assert!(no_adv, "--no-advisory-db must set the flag");
        assert!(
            override_db.is_none(),
            "no override path when only --no-advisory-db"
        );
    }

    /// `--advisory-db` and `--no-advisory-db` together must be rejected.
    #[test]
    fn parse_audit_args_advisory_db_and_no_advisory_db_are_mutually_exclusive() {
        assert!(
            parse_audit_args(&args(&["--advisory-db", "/some/path", "--no-advisory-db"])).is_err(),
            "--advisory-db then --no-advisory-db must error"
        );
        assert!(
            parse_audit_args(&args(&["--no-advisory-db", "--advisory-db", "/some/path"])).is_err(),
            "--no-advisory-db then --advisory-db must error"
        );
    }

    /// Without either flag, `no_advisory_db` is false and `override_db` is `None`
    /// (caller resolves the default registry checkout).
    #[test]
    fn parse_audit_args_defaults_to_default_on() {
        let (_, _, override_db, no_adv, _, _) =
            parse_audit_args(&args(&[])).expect("empty args accepted");
        assert!(!no_adv, "default must not set --no-advisory-db");
        assert!(
            override_db.is_none(),
            "default must not set an override path"
        );
    }

    // ── Runtime resolution ───────────────────────────────────────────────────

    /// `prepare` resolves the runtime through the SAME path `ipe build` uses — the
    /// materialize-capable resolver — never a separate walk-up that cannot
    /// materialize. Under the default dependency model no vendored module tree is
    /// needed, so with `IPE_RUNTIME_DIR` unset the resolution succeeds with an
    /// empty sentinel (the emitted project names the runtime as a path dependency
    /// the build materializes). This is the property whose absence made `audit`
    /// fail on a clean machine where `build` succeeded; a regression that re-splits
    /// the path (calling `resolve_runtime`, which walks up for an in-repo tree and
    /// errors when none is found) fails here.
    #[test]
    fn audit_runtime_resolution_needs_no_in_repo_tree_under_the_dep_model() {
        // The dependency model is the default. Only the vendored/wasm shape needs a
        // concrete module tree; the default does not, so resolution yields the
        // empty sentinel with no `IPE_RUNTIME_DIR` and no in-repo walk-up.
        let needs_vendored = !crate::runtime_dep_from_env();
        assert!(
            !needs_vendored,
            "the default dependency model must not require a vendored runtime tree"
        );
        let resolved = crate::resolve_vendored_runtime_dir(None, needs_vendored)
            .expect("the dep-model runtime resolution must not require an in-repo tree");
        assert_eq!(
            resolved,
            PathBuf::new(),
            "the dep-model path returns the empty sentinel; the build materializes the runtime"
        );
    }

    // --- deny_args placement tests ---

    /// cargo-deny >= 0.20: `--config` must appear BEFORE `check`, as a global option.
    #[test]
    fn deny_args_modern_places_config_before_check() {
        let manifest = Path::new("/tmp/proj/Cargo.toml");
        let config = Path::new("/ws/deny.toml");
        let args = deny_args(20, manifest, Some(config));
        let strs: Vec<&str> = args.iter().map(|a| a.to_str().unwrap()).collect();
        let check_pos = strs
            .iter()
            .position(|&a| a == "check")
            .expect("check present");
        let config_pos = strs
            .iter()
            .position(|&a| a == "--config")
            .expect("--config present");
        assert!(
            config_pos < check_pos,
            "cargo-deny >= 0.20: --config ({config_pos}) must precede check ({check_pos})"
        );
        // All three scan axes present.
        assert!(strs.contains(&"advisories"), "advisories present");
        assert!(strs.contains(&"bans"), "bans present");
        assert!(strs.contains(&"sources"), "sources present");
    }

    /// cargo-deny < 0.20: `--config` must appear AFTER `check`, as a subcommand option.
    #[test]
    fn deny_args_legacy_places_config_after_check() {
        let manifest = Path::new("/tmp/proj/Cargo.toml");
        let config = Path::new("/ws/deny.toml");
        let args = deny_args(19, manifest, Some(config));
        let strs: Vec<&str> = args.iter().map(|a| a.to_str().unwrap()).collect();
        let check_pos = strs
            .iter()
            .position(|&a| a == "check")
            .expect("check present");
        let config_pos = strs
            .iter()
            .position(|&a| a == "--config")
            .expect("--config present");
        assert!(
            config_pos > check_pos,
            "cargo-deny < 0.20: --config ({config_pos}) must follow check ({check_pos})"
        );
        assert!(strs.contains(&"advisories"), "advisories present");
        assert!(strs.contains(&"bans"), "bans present");
        assert!(strs.contains(&"sources"), "sources present");
    }

    /// No config: neither version emits `--config` at all.
    #[test]
    fn deny_args_no_config_omits_flag() {
        let manifest = Path::new("/tmp/proj/Cargo.toml");
        for minor in [19_u32, 20] {
            let args = deny_args(minor, manifest, None);
            assert!(
                !args.iter().any(|a| a.to_str() == Some("--config")),
                "minor {minor}: --config must not appear when config is None"
            );
        }
    }
}
