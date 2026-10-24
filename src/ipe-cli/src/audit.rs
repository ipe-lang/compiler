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
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

use ipe_ir::Capability;

use crate::CliError;
use crate::cli_args::OutputFormat;
use crate::index::Sha256Hex;
use crate::project::{ModuleSources, PackageSnapshot, ProjectManifest};
use crate::project_root::{EntrySet, Located, NonEmpty, entry_set};
use crate::published_version::PublishedVersion;
use crate::publisher::{BlessedPublisher, BlessingRefusal, SelfDeclaredPublisher};
use crate::remote_ingest::{
    Captured, LocalCeiling, LocalRefusal, LocalSource, RunError, SUPPLY_CHAIN_SCAN_LIMITS,
    TOOL_QUERY_LIMITS, run_local,
};
use crate::scratch::ScratchDir;
use crate::text;
use posture::GatePosture;

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

/// The compiler-derived facts a consumer needs to consent to a package: how each
/// of its programs drives itself (the control model) and the effect axes it can
/// exercise (the capability set). Both are read from the compiler's own
/// derivation, never a second source — the control model projects the shape the
/// compiler pinned for `main`, and the capability set is the whole-tree inferred
/// union the capability-consistency check already computes.
///
/// A closed value: a package either builds programs (each disclosing one of the
/// closed [`crate::delivery::ControlModel`] variants) or is a library with no
/// self-driving entry ([`ControlModelDisclosure::NotApplicable`]).
/// An entry that exists but cannot be classified is never represented here — it is
/// a fail-closed rejection before a [`Disclosure`] is ever built, so no permissive
/// default can be disclosed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Disclosure {
    /// Every program's control model, or the library marker.
    control_model: ControlModelDisclosure,
    /// The capability axes the whole package can exercise — the same inferred
    /// union the capability-consistency check reconciles against the manifest.
    capabilities: BTreeSet<Capability>,
}

impl Disclosure {
    /// The disclosed control-model word — the most elevated model any program
    /// runs, or `"library"` for a package with no runnable entry. The exact
    /// vocabulary the `ipe audit` JSON verdict discloses, so `ipe doc` speaks the
    /// same words.
    pub(crate) fn control_model_word(&self) -> &'static str {
        self.control_model.word()
    }

    /// The disclosed capability axes, in the audit's canonical order — the same
    /// inferred union `ipe audit` discloses.
    pub(crate) const fn capabilities(&self) -> &BTreeSet<Capability> {
        &self.capabilities
    }
}

/// The control model disclosed for a package: every program's model, or the
/// marker for a library that exposes modules but runs no entry of its own.
///
/// There is deliberately no "unknown" variant. A runnable entry that cannot be
/// classified fails the audit closed (a program whose self-driving model we
/// cannot state must not be certified as safe), so the only representable states
/// are a known model for every program or a genuine absence of one.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ControlModelDisclosure {
    /// Each program the package builds, in manifest order, with its compiler-pinned control model.
    Programs(NonEmpty<ProgramModel>),
    /// A library: it exposes modules but builds no program, so it has no
    /// control model of its own. Honest absence, not a permissive default.
    NotApplicable,
}

/// One program of a package and the control model its `main` runs under.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProgramModel {
    /// The program's name.
    program: String,
    /// The program's entry module.
    module: Vec<String>,
    /// The control model the program's `main` pins.
    model: crate::delivery::ControlModel,
}

impl ControlModelDisclosure {
    /// The word disclosed for the package — the most elevated model any of its
    /// programs runs, or `"library"` for a package with no runnable entry.
    ///
    /// A package with one `direct` program among `tea` ones reads `direct`, so
    /// a one-word surface never understates what the package can run.
    fn word(&self) -> &'static str {
        match self {
            Self::Programs(programs) => programs
                .iter()
                .map(|program| program.model)
                .fold(programs.first().model, most_elevated)
                .word(),
            Self::NotApplicable => "library",
        }
    }

    /// The programs disclosed, in manifest order; none for a library.
    fn programs(&self) -> impl Iterator<Item = &ProgramModel> {
        let programs = match self {
            Self::Programs(programs) => Some(programs.iter()),
            Self::NotApplicable => None,
        };
        programs.into_iter().flatten()
    }
}

/// The more elevated of two control models: `Direct` drives itself, `Tea` runs a managed loop.
const fn most_elevated(
    a: crate::delivery::ControlModel,
    b: crate::delivery::ControlModel,
) -> crate::delivery::ControlModel {
    use crate::delivery::ControlModel;
    match (a, b) {
        (ControlModel::Direct, _) | (_, ControlModel::Direct) => ControlModel::Direct,
        (ControlModel::Tea, ControlModel::Tea) => ControlModel::Tea,
    }
}

/// The captured, already-built package the checks judge.
///
/// Every check reads the one [`PackageSnapshot`] (manifest, lockfile, module
/// list, module text) or the [`crate::driver::PackageSourceSet`] assembled from it,
/// which is also exactly what was emitted into `emitted_dir`. No check takes a
/// package path to read from.
struct Prepared {
    /// The one capture of the package tree every verdict is over.
    snapshot: PackageSnapshot,
    /// The snapshot's sources with the stdlib closure and FFI interface modules
    /// injected: the set the build emitted and capability inference judges.
    sources: crate::driver::PackageSourceSet,
    /// The directory the package was emitted into (the `cargo-deny` target for
    /// the supply-chain check).
    emitted_dir: PathBuf,
}

impl Prepared {
    /// The captured, parsed manifest.
    const fn manifest(&self) -> &ProjectManifest {
        self.snapshot.manifest()
    }
}

/// What a passing audit certified: the digest and capability set of the bytes it judged.
///
/// A consumer of the verdict (admission, publish) pins these values, never a
/// fresh hash or inference of the path, so the recorded entry is the audit's
/// own output.
#[derive(Debug)]
pub struct AuditedPackage {
    /// The tree digest of the snapshot, re-proved over the tree after the last check.
    digest: Sha256Hex,
    /// The control model and the inferred capability set, disclosed to consumers.
    disclosure: Disclosure,
    /// The native Tier-2 disposition.
    tier2: crate::audit_native::Tier2Outcome,
}

impl AuditedPackage {
    /// The content digest of the audited tree.
    #[must_use]
    pub const fn digest(&self) -> &Sha256Hex {
        &self.digest
    }

    /// The inferred capability set the audit reconciled with the manifest.
    #[must_use]
    pub const fn capabilities(&self) -> &BTreeSet<Capability> {
        self.disclosure.capabilities()
    }

    /// Refuse an index entry whose recorded `capabilities` are not the audited set.
    ///
    /// The entry's set is the record `ipe add` reports to consumers, so it must
    /// be the audit's output, not a value the submitter wrote.
    ///
    /// # Errors
    /// [`CliError::PackageAudit`] with [`Check::Capability`] when the sets differ.
    pub fn refuse_other_capabilities(
        &self,
        recorded: &BTreeSet<Capability>,
    ) -> Result<(), CliError> {
        if recorded == self.capabilities() {
            return Ok(());
        }
        let words = |set: &BTreeSet<Capability>| {
            let words: Vec<&'static str> = set.iter().map(|c| c.as_str()).collect();
            if words.is_empty() {
                "none".to_owned()
            } else {
                words.join(", ")
            }
        };
        Err(reject(
            Check::Capability,
            format!(
                "the entry's recorded `capabilities` are not the set the audit inferred — the \
                 index records the audit's own output, never a submitted claim.\n  \
                 recorded: {}\n  inferred: {}",
                words(recorded),
                words(self.capabilities())
            ),
        ))
    }

    /// An audited package with the given digest and capabilities, for a consumer's unit test.
    #[cfg(test)]
    #[must_use]
    pub const fn for_test(digest: Sha256Hex, capabilities: BTreeSet<Capability>) -> Self {
        Self {
            digest,
            disclosure: Disclosure {
                control_model: ControlModelDisclosure::NotApplicable,
                capabilities,
            },
            tier2: crate::audit_native::Tier2Outcome::SkippedPureIpe,
        }
    }
}

/// How one audit runs: the index and advisory database it reads, the claimed publisher and the output format.
#[derive(Debug)]
pub struct AuditOptions {
    /// The curated index checkout the semver check reads (`--index`).
    index_root: Option<PathBuf>,
    /// A custom advisory-database root (`--advisory-db`).
    advisory_db_override: Option<PathBuf>,
    /// `--no-advisory-db`: the explicit advisory opt-out.
    no_advisory_db: bool,
    /// The claimed publisher (`--publisher`).
    claimed: Option<SelfDeclaredPublisher>,
    /// The output format.
    format: OutputFormat,
}

impl AuditOptions {
    /// The defaults under a claimed publisher: the resolver's index, the default advisory database, human output.
    #[must_use]
    pub const fn for_publisher(claimed: SelfDeclaredPublisher) -> Self {
        Self {
            index_root: None,
            advisory_db_override: None,
            no_advisory_db: false,
            claimed: Some(claimed),
            format: OutputFormat::Human,
        }
    }

    /// The admission run: the submitted entry's claimed publisher and the
    /// curated `index_root` the semver check reads.
    #[must_use]
    pub const fn for_admission(
        claimed: SelfDeclaredPublisher,
        index_root: Option<PathBuf>,
    ) -> Self {
        Self {
            index_root,
            advisory_db_override: None,
            no_advisory_db: false,
            claimed: Some(claimed),
            format: OutputFormat::Human,
        }
    }

    /// The claimed publisher the audit runs under.
    #[must_use]
    pub const fn claimed(&self) -> Option<&SelfDeclaredPublisher> {
        self.claimed.as_ref()
    }
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
    run_audit_as(rest, Err(&unproven)).map(drop)
}

/// [`run_audit`] under a proven publisher standing, returning what the audit certified.
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
) -> Result<AuditedPackage, CliError> {
    let (path, index_root, advisory_db_override, no_advisory_db, claimed, format) =
        parse_audit_args(rest)?;
    let options = AuditOptions {
        index_root,
        advisory_db_override,
        no_advisory_db,
        claimed,
        format,
    };
    run_audit_over(capture_package(&path)?, &options, blessing)
}

/// Capture the package `path` names (a directory or its `package.ipe`) in one walk.
///
/// # Errors
/// [`CliError::Usage`] when `path` names no `package.ipe`; the
/// [`PackageSnapshot::capture`] refusals otherwise.
pub fn capture_package(path: &Path) -> Result<PackageSnapshot, CliError> {
    capture_manifest_root(&locate_manifest(path)?)
}

/// Capture the package whose `package.ipe` is `manifest_path` in one walk.
///
/// # Errors
/// The [`PackageSnapshot::capture`] refusals.
pub fn capture_manifest_root(manifest_path: &Path) -> Result<PackageSnapshot, CliError> {
    let root = manifest_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    PackageSnapshot::capture(root)
}

/// [`run_audit_as`] over an already-captured `snapshot`.
///
/// # Errors
/// As [`run_audit`].
pub fn run_audit_over(
    snapshot: PackageSnapshot,
    options: &AuditOptions,
    blessing: Result<&BlessedPublisher, &BlessingRefusal>,
) -> Result<AuditedPackage, CliError> {
    let prepared = prepare(snapshot)?;
    let name = prepared.manifest().name.clone();
    let version = prepared
        .manifest()
        .version
        .as_ref()
        .map_or_else(|| "(unversioned)".to_owned(), ToString::to_string);

    // Resolve the effective advisory DB.
    // Priority: explicit --advisory-db > default registry checkout > --no-advisory-db (None).
    // Absence of --advisory-db uses the registry index checkout the resolver already has.
    // --no-advisory-db is the ONLY way to skip; omitting --advisory-db does NOT skip.
    let effective_advisory_db: Option<PathBuf> = if options.no_advisory_db {
        None
    } else {
        Some(
            options
                .advisory_db_override
                .clone()
                .map_or_else(crate::resolve::index_root, Ok)?,
        )
    };

    let outcome = audit_gate(
        &prepared,
        options.index_root.as_deref(),
        effective_advisory_db.as_deref(),
        PublisherStanding {
            claimed: options.claimed.as_ref(),
            blessing,
        },
    );

    match options.format {
        OutputFormat::Json => emit_audit_json(&name, &version, outcome),
        // `--plain` and the default share the human renderer; the audit verdict
        // has no separate flush-left line form, so `--plain` is the human report
        // (the format parse already rejected `--plain --json` together).
        OutputFormat::Human | OutputFormat::Plain => {
            let audited = outcome?;
            crate::screen::Screen::new(crate::screen::Stream::Stdout)
                .line(
                    crate::screen::Tone::Text,
                    &passing_summary(&name, &version, &audited.tier2, &audited.disclosure),
                )
                .emit();
            Ok(audited)
        }
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
) -> Result<AuditedPackage, CliError> {
    let manifest = prepared.manifest();
    reserved_namespace_ownership(&manifest.name, prepared.snapshot.modules(), standing)?;
    provenance_panic_scan(&prepared.sources)?;

    // The whole-tree inferred capability union — computed once and shared by the
    // consistency check (reconcile against the manifest) and the disclosure
    // (surface to the consumer), so the two can never disagree about the effects.
    let inferred = capability_verdict(manifest, &prepared.sources)?;

    enforced_semver(manifest, prepared.snapshot.sources(), index_root)?;
    supply_chain(prepared)?;
    advisory_check(prepared.snapshot.lock(), advisory_db)?;

    let disclosure = derive_disclosure(manifest, prepared.snapshot.sources(), inferred)?;

    let tier2 = crate::audit_native::native_tier2(&crate::audit_native::NativeAudit {
        declared: &manifest.capabilities,
        has_rust_deps: !manifest.rust_dependencies.is_empty(),
        root: &manifest.root,
        emitted_dir: &prepared.emitted_dir,
    })?;

    // Control-model consent (defence-in-depth boundary, sibling of the build-time
    // gate): a package any of whose programs runs a control model its own
    // manifest does not accept is a fail-closed audit rejection. A library
    // (`NotApplicable`) has no program to gate and passes silently. It runs LAST — after the native-bearing fail-closed checks
    // (binding regeneration, provenance, Tier-2) — so the consent decision is the
    // final gate on an otherwise-certifiable package and never preempts a
    // native-surface refusal.
    consent_every_program(&disclosure, manifest)?;

    Ok(AuditedPackage {
        digest: reprove_tree(&prepared.snapshot)?,
        disclosure,
        tier2,
    })
}

/// Re-walk the captured package's tree and require the snapshot's digest: the digest an audit certifies.
///
/// The second, detective boundary behind the single capture: a tree changed
/// while the checks ran (a file swapped after capture, a write by a stage the
/// gate ran) no longer hashes to what was judged, and is refused rather than
/// certified under either digest. Hidden directories (`.ipe/`, `.git/`) are
/// outside the digest stream, so the gate-owned FFI regeneration does not
/// perturb it.
///
/// # Errors
/// [`CliError::HashMismatch`] when the tree's digest is not the snapshot's; the
/// tree-walk refusals otherwise.
fn reprove_tree(snapshot: &PackageSnapshot) -> Result<Sha256Hex, CliError> {
    let judged = Sha256Hex::of_digest(snapshot.tree());
    let now = Sha256Hex::of_tree_within(
        &snapshot.manifest().root,
        crate::remote_ingest::PACKAGE_SOURCE.tree(),
    )?;
    if now == judged {
        Ok(judged)
    } else {
        Err(CliError::HashMismatch {
            package: snapshot.manifest().name.clone(),
            expected: judged.as_str().to_owned(),
            actual: now.as_str().to_owned(),
        })
    }
}

/// Emit the compact JSON audit verdict to stdout, then map a rejection to the
/// already-emitted sentinel so the process still exits non-zero without printing
/// a second human message. On a pass, the object records the certified verdict
/// and the Tier-2 disposition; on a reject, `certified` is `false` and `reason`
/// carries the failing check's one-line message.
fn emit_audit_json(
    name: &str,
    version: &str,
    outcome: Result<AuditedPackage, CliError>,
) -> Result<AuditedPackage, CliError> {
    crate::screen::emit_machine(
        crate::screen::Stream::Stdout,
        &format!("{}\n", audit_verdict_json(name, version, &outcome)),
    );

    // On a reject the verdict object was already written to stdout; the
    // sentinel makes the exit non-zero with nothing more printed.
    outcome.map_err(|_| CliError::DiagnosticJsonEmitted)
}

/// Build the compact JSON audit verdict object (the pure core of
/// [`emit_audit_json`]): a certified pass with its Tier-2 disposition, or a
/// `certified:false` object carrying the failing check's one-line reason.
fn audit_verdict_json(
    name: &str,
    version: &str,
    outcome: &Result<AuditedPackage, CliError>,
) -> String {
    use crate::audit_native::Tier2Outcome;
    use crate::cli_args::json;

    match outcome
        .as_ref()
        .map(|audited| (&audited.tier2, &audited.disclosure))
    {
        Ok((Tier2Outcome::SkippedPureIpe, disclosure)) => json::object(&[
            ("package", json::string(name)),
            ("version", json::string(version)),
            ("tier1", json::string("pass")),
            ("tier2", json::string("skipped")),
            (
                "controlModel",
                json::string(disclosure.control_model.word()),
            ),
            ("programs", disclosure_programs_json(disclosure)),
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
            ("programs", disclosure_programs_json(disclosure)),
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

/// Every disclosed program as a compact JSON array of `{name, controlModel}`
/// objects, in manifest order; empty for a library.
fn disclosure_programs_json(disclosure: &Disclosure) -> String {
    use crate::cli_args::json;
    let programs: Vec<String> = disclosure
        .control_model
        .programs()
        .map(|program| {
            json::object(&[
                ("name", json::string(&program.program)),
                ("controlModel", json::string(program.model.word())),
            ])
        })
        .collect();
    json::array(&programs)
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
    let shown = shown_name(name);
    let tier_line = match tier2 {
        Tier2Outcome::SkippedPureIpe => format!(
            "package audit: {shown} {version} — all Tier-1 checks passed. (Pure Ipê package: \
             native Tier-2 does not apply.)"
        ),
        Tier2Outcome::Certified { platform } => format!(
            "package audit: {shown} {version} — all Tier-1 checks passed; native Tier-2 capability \
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
/// The build emits exactly the source set assembled from `snapshot`, the set
/// every later check judges; no package file is read again.
///
/// # Errors
/// [`CliError::PackageAudit`] with [`Check::NativeBindingRegen`] when the
/// manifest declares a `wrapper` field; the build errors
/// ([`CliError::Pipeline`] / [`CliError::Io`] / [`CliError::StaticRefusal`])
/// otherwise.
fn prepare(snapshot: PackageSnapshot) -> Result<Prepared, CliError> {
    let manifest = snapshot.manifest();
    let manifest_path = crate::driver::snapshot_manifest_path(&snapshot);

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

    // A committed FFI cache is publisher-supplied bindings: remove it whether
    // or not the package declares crates, so the build only ever loads the
    // gate-regenerated catalog (or none).
    purge_committed_ffi_cache(&manifest.root)?;
    // Regenerate FFI bindings for native-bearing packages before the build so
    // the compiler finds `Rust.<Crate>` interface modules. The regeneration runs
    // the package's foreign crates' build scripts, so it is reachable only
    // behind the proof that this process holds a jail and no host-side escape.
    if !manifest.rust_dependencies.is_empty() {
        let posture = GatePosture::establish()?;
        regenerate_ffi_bindings(&posture, &manifest_path)?;
    }

    // `audit_scratch_dir` creates the directory exclusively with 128-bit OS
    // entropy — no stale-dir removal needed; a fresh exclusive dir is always empty.
    let emitted_dir = audit_scratch_dir(&manifest.name)?;
    // Resolve the runtime exactly as `ipe dev build` does — one resolver for every
    // command. Under the default dependency model the emitted project names the
    // runtime as a path dependency, which the build materializes from the
    // embedded source under `IPE_HOME`; no vendored module tree is needed, so an
    // empty sentinel is passed and `build_project` never reads it. Only the
    // vendored/wasm shape needs a concrete module tree. Resolving here through a
    // separate walk-up (that never materialized) is what made `audit` fail on a
    // clean machine while `build` succeeded.
    let runtime_dir = crate::resolve_vendored_runtime_dir(None, !crate::runtime_dep_from_env())?;
    // The FFI interface modules and `src/ffi.rs` text are assembled AFTER the
    // regeneration above, so the set holds the gate-owned bindings.
    let sources = crate::driver::PackageSourceSet::from_snapshot(&snapshot)?;
    crate::driver::build_from_sources(
        manifest,
        &manifest_path,
        sources.clone(),
        crate::driver::OutTarget::Path(&emitted_dir),
        &runtime_dir,
        &crate::driver::BuildOptions::from_env(),
    )?;

    Ok(Prepared {
        snapshot,
        sources,
        emitted_dir,
    })
}

/// The gate's sandbox posture, in its own module so that its proof's field is
/// private to it: only [`GatePosture::from_facts`] can mint one.
mod posture {
    use super::{Check, reject};
    use crate::CliError;
    use crate::text;

    /// Proof that this process runs the audit with no host-side escape from the sandbox.
    ///
    /// Minted once per audit, before any step that runs the package's foreign code
    /// (the FFI binding regeneration); nothing outside this module can construct
    /// it. The step takes the proof as a parameter, so without a jail the step
    /// cannot be called: the developer's unsandboxed inspector override and a
    /// host without bubblewrap are refusals of the gate, never a host run with a
    /// warning.
    pub(super) struct GatePosture(());

    impl GatePosture {
        /// Prove the gate's posture from the host's sandbox facts.
        ///
        /// The only production read of the unsandboxed override in this module;
        /// `audit_source_reads_no_environment_or_cwd` pins that.
        ///
        /// # Errors
        /// As [`Self::from_facts`].
        pub(super) fn establish() -> Result<Self, CliError> {
            let caps = ipe_sandbox::probe();
            Self::from_facts(
                ipe_sandbox::unsandboxed_override_set(),
                &ipe_sandbox::select_mechanism(&caps),
            )
        }

        /// The pure core: refuse the override, refuse a host without a jail.
        ///
        /// # Errors
        /// [`CliError::PackageAudit`] with [`Check::NativeBindingRegen`] when the
        /// unsandboxed inspector override is set, or when the sandbox mechanism is
        /// [`ipe_sandbox::Mechanism::Refused`].
        pub(super) fn from_facts(
            override_set: bool,
            mechanism: &ipe_sandbox::Mechanism,
        ) -> Result<Self, CliError> {
            if override_set {
                return Err(reject(
                    Check::NativeBindingRegen,
                    text::msg::audit_refuses_unsandboxed_override().into(),
                ));
            }
            match mechanism {
                ipe_sandbox::Mechanism::Bwrap(_) => Ok(Self(())),
                ipe_sandbox::Mechanism::Refused => Err(reject(
                    Check::NativeBindingRegen,
                    text::msg::audit_requires_a_jail().into(),
                )),
            }
        }
    }
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
/// generate their API surface. The [`GatePosture`] is the proof that the jail
/// is what runs them: the regeneration is unreachable without it.
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
fn regenerate_ffi_bindings(_posture: &GatePosture, manifest_path: &Path) -> Result<(), CliError> {
    let project_root = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    purge_committed_ffi_cache(project_root)?;
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

/// Remove any `.ipe/cache/ffi/rust` the package tree ships, so the gate never
/// loads publisher-supplied bindings.
///
/// The cache path is resolved once and asserted to stay inside `project_root`:
/// an attacker-authored tree can ship `.ipe/cache/ffi` as a symlink to an
/// out-of-tree target (committed via `git add -f`), and `remove_dir_all`
/// traverses intermediate symlinks, so every component is checked no-follow
/// before any delete.
///
/// # Errors
/// [`CliError::PackageAudit`] with [`Check::NativeBindingRegen`] when a cache
/// path component is a symlink; [`CliError::Io`] when the cache cannot be
/// removed.
fn purge_committed_ffi_cache(project_root: &Path) -> Result<(), CliError> {
    let safe_cache = ffi_cache_path_or_reject(project_root)?;
    if safe_cache.exists() {
        std::fs::remove_dir_all(&safe_cache).map_err(|e| CliError::Io {
            path: safe_cache.clone(),
            source: e,
        })?;
    }
    Ok(())
}

/// Resolve the `.ipe/cache/ffi/rust` path under `project_root` and verify that
/// no component of the relative suffix is a symlink (no-follow check).
///
/// Returns the resolved path on success, or a [`Check::NativeBindingRegen`]
/// rejection when any component is a symlink or the resolved path escapes the
/// canonical project root. The check uses [`std::fs::symlink_metadata`] so it
/// never follows symlinks.
fn ffi_cache_path_or_reject(project_root: &Path) -> Result<PathBuf, CliError> {
    let mut current = project_root.to_path_buf();
    for component in ipe_ffi::driver::FFI_CACHE_COMPONENTS {
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
                        crate::ffi::joined(project_root, &ipe_ffi::driver::FFI_CACHE_COMPONENTS)
                            .display(),
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
/// The scanned text is the `src/ffi.rs` the build emitted from `sources`, so
/// the Rust judged is the Rust shipped, never a second read of the cache.
///
/// # Errors
/// [`CliError::PackageAudit`] when the author FFI Rust contains an abrupt-
/// failure construct or cannot be scanned.
fn provenance_panic_scan(sources: &crate::driver::PackageSourceSet) -> Result<(), CliError> {
    // Author FFI wrapper Rust is the one surface this check gates: it compiles
    // unsandboxed into the shipped artifact, so an authored abrupt-failure
    // construct there is a soundness hole the package must not ship with.
    let Some(bindings) = sources.bindings_source() else {
        return Ok(());
    };
    if let Some(hit) = first_hit_in(Path::new(EMITTED_FFI_RS), bindings)? {
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

/// The emitted file the author FFI wrapper Rust ships in, named in a provenance reject.
///
/// It holds every installed crate's `<slug>_bindings.rs` wrapper, the
/// hand-written Rust the inspection produced from the author's
/// `[rust.define.*]` decls; the interface `.ipe` modules are Ipê, not Rust.
const EMITTED_FFI_RS: &str = "src/ffi.rs";

/// Run the shared [`panic_scan`] token scanner over the Rust text `src` of `file`, returning its
/// first hit (lowest line) if any.
///
/// Fail closed on a non-lexing file: Rust the scanner cannot
/// tokenise is opaque — the no-panic audit cannot attest its content. The
/// scanner refuses rather than admits (the same posture `capability_scan`
/// takes for a non-lexing source). A `cargo build` of a non-lexing file would
/// fail, but that is a separate later step; this gate must refuse eagerly,
/// before the file reaches `cargo`.
///
/// # Errors
/// [`CliError::PackageAudit`] ([`Check::Provenance`]) when the text is over a
/// scan ceiling (too large, too deep, too many tokens) or does not parse as Rust.
fn first_hit_in(file: &Path, src: &str) -> Result<Option<LocatedHit>, CliError> {
    let hits = panic_scan::scan_str(src).map_err(|error| {
        let why = match error {
            panic_scan::ScanError::TooLarge { bytes, ceiling } => format!(
                "is too large to audit (at least {bytes} bytes, over the {ceiling}-byte ceiling)"
            ),
            panic_scan::ScanError::TooDeep {
                line,
                depth,
                ceiling,
            } => format!(
                "nests too deep to audit (line {line} nests {depth} units, over the ceiling of \
                 {ceiling})"
            ),
            panic_scan::ScanError::TooManyTokens { count, ceiling } => {
                format!("holds too many tokens to audit ({count}, over the ceiling of {ceiling})")
            }
            panic_scan::ScanError::Parse { line, source } => {
                format!("does not parse as Rust (line {line}: {source})")
            }
            panic_scan::ScanError::Thread(source) => {
                format!("could not be audited: the parse thread could not start ({source})")
            }
            panic_scan::ScanError::Aborted => {
                "could not be audited: the parse thread aborted".to_owned()
            }
        };
        reject(
            Check::Provenance,
            format!(
                "emitted `{}` {why} — the no-panic audit cannot attest its content; the \
                 file is refused rather than admitted",
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

// ===========================================================================
// 1b. Capability consistency
// ===========================================================================

/// Verify the manifest's declared `[capabilities]` set EQUALS the set inferred
/// over the WHOLE package — no hidden effect, no over-broad claim.
///
/// Uses the whole-package inference over the captured source set (the union over every shipped
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
    manifest: &ProjectManifest,
    inferred: &BTreeSet<Capability>,
) -> Result<(), CliError> {
    use std::fmt::Write as _;

    let declared: BTreeSet<Capability> = manifest.capabilities.clone();

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
                        shown_name(&manifest.name)
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

/// Infer the capability set of exactly the assembled `sources` and reconcile it with `manifest`.
///
/// `sources` is the set the build emitted, so the verdict is over the
/// shipped bytes and never over a re-read of the package path.
///
/// # Errors
/// The inference errors; [`CliError::PackageAudit`] when the declared and
/// inferred sets differ.
fn capability_verdict(
    manifest: &ProjectManifest,
    sources: &crate::driver::PackageSourceSet,
) -> Result<BTreeSet<Capability>, CliError> {
    let inferred = crate::driver::infer_package_capabilities_of(sources)?;
    capability_consistency(manifest, &inferred)?;
    Ok(inferred)
}

// ===========================================================================
// Compiler-derived disclosure (control model + capability set)
// ===========================================================================

/// Derive the consumer-facing disclosure — every program's control model and
/// the package's capability set — reusing the compiler's own derivations.
///
/// The capability set is the whole-tree inferred union the caller already
/// computed (the SSOT the capability-consistency check reconciles), so the
/// disclosed effects and the reconciled effects are the same value.
///
/// Each program's control model is a projection of the shape the compiler pins
/// for its `main` ([`crate::driver::EntryMain`], the reading the build's shape
/// check also projects), never a second inspection of `main`. Every program the
/// package builds ([`captured_programs`]) is disclosed, never one chosen among
/// them. It is derived **fail-closed**:
///
/// - A library that builds no program discloses
///   [`ControlModelDisclosure::NotApplicable`] — an honest absence, not a
///   permissive default.
/// - A program whose entry defines no `main` pins the `script` shape the build
///   checks it as, and so discloses `direct`, the elevated model.
/// - A program whose entry does not parse is a hard rejection: a program whose
///   self-driving model we cannot state must never be certified as safe with a
///   permissive-looking default. (The package already built in [`prepare`], so
///   this is a defence-in-depth second boundary, not the only one.)
///
/// # Errors
/// [`CliError::PackageAudit`] with [`Check::Capability`] when a program's
/// entry does not parse; the [`captured_programs`] refusals.
fn derive_disclosure(
    manifest: &ProjectManifest,
    sources: &ModuleSources,
    inferred: BTreeSet<Capability>,
) -> Result<Disclosure, CliError> {
    let Some(programs) = captured_programs(manifest, sources)? else {
        return Ok(Disclosure {
            control_model: ControlModelDisclosure::NotApplicable,
            capabilities: inferred,
        });
    };
    let mut models = Vec::new();
    for program in programs.iter() {
        let model = match crate::driver::EntryMain::of(program.source) {
            crate::driver::EntryMain::Unparsed => return Err(unparsed(program)),
            entry => entry.delivery_shape().control_model(),
        };
        models.push(ProgramModel {
            program: program.name.clone(),
            module: program.module.clone(),
            model,
        });
    }
    let Some(models) = NonEmpty::from_vec(models) else {
        return Err(reject(
            Check::Capability,
            "the package's program list disclosed no program".to_owned(),
        ));
    };
    Ok(Disclosure {
        control_model: ControlModelDisclosure::Programs(models),
        capabilities: inferred,
    })
}

/// The fail-closed refusal of a program whose entry does not parse.
fn unparsed(program: &CapturedProgram<'_>) -> CliError {
    reject(
        Check::Capability,
        format!(
            "program `{}`'s entry source (`{}`) does not parse, so its control model cannot be \
             derived. A program whose self-driving model the audit cannot state is refused \
             rather than certified with an assumed model.",
            shown_name(&program.name),
            program.path.display()
        ),
    )
}

/// One program of the captured package: its name, entry module and entry text.
#[derive(Debug)]
struct CapturedProgram<'s> {
    /// The program's name.
    name: String,
    /// The program's entry module.
    module: Vec<String>,
    /// The entry file's path, for a refusal to name.
    path: &'s Path,
    /// The entry file's captured text.
    source: &'s str,
}

/// Every program the captured package builds, or `None` for a library.
///
/// [`crate::project_root::entry_set`] over the capture: the one derivation
/// [`crate::project_root::ProjectRoot`] reads over the disk, so the audit and
/// the build can never resolve one manifest to different programs.
///
/// # Errors
/// Every refusal of [`crate::project_root::entry_set`];
/// [`CliError::EntryMissing`] when a resolved entry is not in the capture.
fn captured_programs<'s>(
    manifest: &ProjectManifest,
    sources: &'s ModuleSources,
) -> Result<Option<NonEmpty<CapturedProgram<'s>>>, CliError> {
    let held = |module: &Vec<String>| {
        Ok(if sources.contains_key(module) {
            Located::Found
        } else {
            Located::Missing
        })
    };
    let EntrySet::Programs(entries) = entry_set(manifest, &manifest.root, held)? else {
        return Ok(None);
    };
    let mut programs = Vec::with_capacity(entries.iter().count());
    for entry in entries.iter() {
        let Some((path, source)) = sources.get(entry.module()) else {
            return Err(CliError::EntryMissing {
                entry: format!("{}.ipe", entry.module().join("/")),
            });
        };
        programs.push(CapturedProgram {
            name: entry.name().as_str().to_owned(),
            module: entry.module().to_vec(),
            path,
            source,
        });
    }
    Ok(NonEmpty::from_vec(programs))
}

/// Run the control-model consent gate for every disclosed program.
///
/// Each program is gated on its own model, so a package whose second program
/// alone runs an uncovered model is refused like one whose first program does.
///
/// # Errors
/// The [`crate::control_model_consent::gate`] refusal of the first program whose
/// model the manifest's `acceptsControl` does not cover.
fn consent_every_program(
    disclosure: &Disclosure,
    manifest: &ProjectManifest,
) -> Result<(), CliError> {
    for program in disclosure.control_model.programs() {
        crate::control_model_consent::gate(
            program.model,
            &manifest.control_models_accept,
            &program.module.join("."),
        )?;
    }
    Ok(())
}

/// The package disclosure a non-audit surface (`ipe doc`) reads — the SAME
/// compiler-derived control model and whole-tree capability union `ipe audit`
/// discloses, reusing [`derive_disclosure`] and
/// [`crate::infer_package_capabilities`] rather than a second derivation that
/// could disagree with the audit's answer.
///
/// Fail-closed identically to the audit: a program whose entry cannot be read
/// or parsed is a hard rejection ([`Check::Capability`]), never a permissive
/// default; a library that builds no program discloses an honest
/// [`ControlModelDisclosure::NotApplicable`] ("library").
///
/// This does NOT build the package (no emit): the disclosure needs only the
/// manifest (for the capability union) and each program's entry source (for
/// the control models), so `ipe doc` stays a read-only documentation surface.
///
/// # Errors
/// [`CliError`] when the manifest cannot be located or parsed, the capability
/// inference fails, the entry source cannot be read or parsed (fail-closed), or
/// the package builds nothing ([`CliError::NoDefaultEntry`]).
pub(crate) fn disclose_package(path: &Path) -> Result<Disclosure, CliError> {
    // A working-tree reader, not a capture: `ipe doc` certifies nothing, and a
    // capture would walk the build output under the project root. The modules
    // are read once and both derivations judge that one read.
    let manifest_path = locate_manifest(path)?;
    let manifest = crate::project::parse_manifest(&manifest_path)?;
    let (sources, entries) = crate::driver::read_package_modules(&manifest)?;
    let source_set =
        crate::driver::PackageSourceSet::assemble(sources.clone(), entries, &manifest_path)?;
    let inferred = crate::driver::infer_package_capabilities_of(&source_set)?;
    derive_disclosure(&manifest, &sources, inferred)
}

/// Render the disclosure as a human-readable frame — the control model and the
/// (possibly empty) capability set the package can exercise.
///
/// A package of more than one program also names each program's own model.
/// Every name is shown through [`shown_name`].
fn disclosure_summary(name: &str, disclosure: &Disclosure) -> String {
    let caps: Vec<&'static str> = disclosure.capabilities.iter().map(|c| c.as_str()).collect();
    let caps_line = if caps.is_empty() {
        "none".to_owned()
    } else {
        caps.join(", ")
    };
    let programs: Vec<String> = disclosure
        .control_model
        .programs()
        .map(|program| {
            format!(
                "`{}`: {}",
                shown_name(&program.program),
                program.model.word()
            )
        })
        .collect();
    let per_program = if programs.len() > 1 {
        format!(" ({})", programs.join(", "))
    } else {
        String::new()
    };
    format!(
        "package audit: `{}` control model: {}{per_program}; capabilities: {caps_line}.",
        shown_name(name),
        disclosure.control_model.word()
    )
}

/// A manifest-supplied name (the package's or a program's) as one inert token
/// of a single report line: control characters and line breaks escaped as in
/// [`str::escape_debug`], a backtick escaped so the name cannot close the code
/// span it is shown in, and the result proven a [`crate::style::TerminalLine`].
fn shown_name(raw: &str) -> String {
    let escaped = raw.escape_debug().to_string().replace('`', "\\`");
    crate::style::TerminalLine::sanitize(&escaped)
        .as_str()
        .to_owned()
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
/// [`crate::diff::check_semver_bump_over`] against the captured `sources` and
/// rejects an under-bump.
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
fn enforced_semver(
    manifest: &ProjectManifest,
    sources: &ModuleSources,
    index_root: Option<&Path>,
) -> Result<(), CliError> {
    let Some(manifest_version) = manifest.version.clone() else {
        return Err(reject(
            Check::Semver,
            "the manifest declares no `version = \"…\"` — the enforced-semver check needs a \
             version to compare against the previous published one."
                .to_owned(),
        ));
    };
    let new_version = PublishedVersion::from_semver(manifest_version)
        .map_err(|refusal| refusal.for_package(&manifest.name))?;

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
                    shown_name(&manifest.name)
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
        crate::index::read_entry_lookup(&index_root, &manifest.name).absent_or_err()?
    else {
        crate::screen::Screen::new(crate::screen::Stream::Stdout)
            .line(
                crate::screen::Tone::Text,
                &format!(
                    "package audit: `{}` has no previously published version in the index — \
                 skipping the enforced-semver check (first version).",
                    shown_name(&manifest.name)
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
                    shown_name(&manifest.name)
                ),
            )
            .emit();
        return Ok(());
    };

    // Fetch + hash-verify the predecessor's pinned source, then diff the two
    // public APIs. `fetch_and_verify_baseline` returns the checkout root the
    // predecessor's `src/` lives under.
    let baseline =
        crate::resolve::fetch_and_verify_index_version(&manifest.root, &manifest.name, previous)?;

    let report = crate::diff::check_semver_bump_over(
        &baseline,
        &manifest.root,
        sources,
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

/// The program the supply-chain scan runs: `cargo-deny` itself, never the
/// `cargo deny` subcommand, so a machine without it yields a `NotFound` spawn
/// error instead of cargo reporting "no such subcommand".
const CARGO_DENY: &str = "cargo-deny";

/// Detect the installed cargo-deny minor version by parsing `cargo-deny --version`.
///
/// The probe runs under [`TOOL_QUERY_LIMITS`]. Returns the minor component of
/// the version (e.g. `20` for `cargo-deny 0.20.2`). A probe that fails, crosses
/// a ceiling, or prints no parsable version defaults to `20` — the current
/// "latest" release — so it uses the newer global-flag placement; the scan
/// itself then runs under its own ceilings.
fn detect_cargo_deny_minor(cargo_deny: &OsStr, ceiling: LocalCeiling) -> u32 {
    let mut probe = Command::new(cargo_deny);
    probe.arg("--version");
    let Ok(out) = run_local(probe, ceiling, LocalSource::ToolQuery) else {
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

/// Run `cargo-deny` with `args`, detached in its own process group and held to `ceiling`.
///
/// # Errors
/// See [`RunError`]: a crossed ceiling kills the child's group and is a
/// [`LocalRefusal`] naming [`LocalSource::SupplyChainScan`].
fn run_cargo_deny(
    cargo_deny: &OsStr,
    args: &[OsString],
    ceiling: LocalCeiling,
) -> Result<Captured, RunError<LocalRefusal>> {
    let mut command = Command::new(cargo_deny);
    command.args(args);
    run_local(command, ceiling, LocalSource::SupplyChainScan)
}

/// Build the cargo-deny argument vector for `advisories bans sources`.
///
/// cargo-deny 0.20 moved `--config` from the `check` subcommand to the global
/// (top-level) position. Placement rule:
///   - minor >= 20: `[--manifest-path <m>] [--config <cfg>] check advisories bans sources`
///   - minor < 20:  `[--manifest-path <m>] check advisories bans sources [--config <cfg>]`
///
/// `--manifest-path` is a global option accepted in both series.
fn deny_args(cargo_deny_minor: u32, manifest: &Path, config: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();
    args.push("--manifest-path".into());
    args.push(manifest.into());
    if cargo_deny_minor >= 20 {
        args.push("--config".into());
        args.push(config.into());
    }
    args.push("check".into());
    // Advisories + bans + sources are the supply-chain axes; licenses are a
    // project-policy axis the workspace's own gate owns, not the package gate.
    args.push("advisories".into());
    args.push("bans".into());
    args.push("sources".into());
    if cargo_deny_minor < 20 {
        args.push("--config".into());
        args.push(config.into());
    }
    args
}

/// Run `cargo-deny` over the emitted project's dependency graph, and re-assert
/// the content-hash integrity of any Ipê package dependencies against their index
/// pins.
///
/// `cargo-deny check` applies the workspace's supply-chain posture (advisories,
/// bans, licenses, sources — see `deny.toml`) to the emitted Cargo project; a
/// non-zero exit is a reject. It may fetch the advisory database, so it runs
/// under [`SUPPLY_CHAIN_SCAN_LIMITS`]. The Ipê-package hash re-assertion reuses
/// the resolver's lockfile pins so a fetched dependency whose bytes drifted from
/// the registered hash is caught here too (the resolver verifies at install; the
/// gate re-verifies at publish).
///
/// When `cargo-deny` is not installed, the advisory/bans scan is skipped with a
/// loud warning (a missing dev tool is not an unsafe package), while the
/// hash-integrity half still runs. The authoritative index-CI gate always
/// installs cargo-deny, so enforcement is never actually skipped there.
///
/// # Errors
/// - [`CliError::PackageAudit`] when `cargo-deny` reports a violation, fails to
///   run for any reason other than not being installed, or a locked
///   dependency's hash no longer verifies.
/// - [`CliError::LocalLimitExceeded`] when `cargo-deny` crosses a ceiling; its
///   process group is killed.
/// - [`CliError::ChildPipeHeld`] when a process `cargo-deny` started holds a
///   pipe open.
/// - [`CliError::ChildPipeUnread`] when reading one of its output pipes fails.
fn supply_chain(prepared: &Prepared) -> Result<(), CliError> {
    let manifest = prepared.emitted_dir.join("Cargo.toml");
    if !manifest.is_file() {
        // No emitted Cargo project means no Rust dependency graph to vet; the
        // Ipê-package integrity re-check below still applies.
        return verify_locked_dependency_hashes(prepared);
    }

    // Apply the SAME advisory/bans/sources posture the workspace uses — its
    // `deny.toml` ledgers advisories the vendored runtime's dependency tree
    // legitimately carries. Without it the check would default-reject every
    // emitted package for a runtime dependency the workspace has already vetted.
    // The policy is the gate's embedded one, never a file the audit finds.
    //
    // `--config` placement is version-dependent: global (before `check`) for
    // cargo-deny >= 0.20, on the `check` subcommand for < 0.20.
    let derived_config = derive_deny_config(&prepared.emitted_dir)?;
    let cargo_deny = OsStr::new(CARGO_DENY);
    let minor = detect_cargo_deny_minor(cargo_deny, TOOL_QUERY_LIMITS);
    let args = deny_args(minor, &manifest, &derived_config);

    match run_cargo_deny(cargo_deny, &args, SUPPLY_CHAIN_SCAN_LIMITS) {
        Ok(out) if out.status.success() => verify_locked_dependency_hashes(prepared),
        Ok(out) => {
            let stderr = out.stderr.to_terminal();
            Err(reject(
                Check::SupplyChain,
                format!(
                    "cargo-deny reported a supply-chain violation over the package's Rust \
                     dependency graph:\n{}",
                    stderr.as_str().trim()
                ),
            ))
        }
        Err(RunError::Spawn(e)) if e.kind() == std::io::ErrorKind::NotFound => {
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
        Err(RunError::Exceeded(refusal)) => Err(CliError::LocalLimitExceeded(refusal)),
        Err(RunError::PipeDrainTimeout(stream)) => Err(CliError::ChildPipeHeld(stream)),
        Err(RunError::PipeRead(stream, kind)) => Err(CliError::ChildPipeUnread(stream, kind)),
        Err(RunError::Spawn(e) | RunError::Wait(e) | RunError::Measure(_, e)) => Err(reject(
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
    match crate::resolve::verify_locked_hashes(&prepared.manifest().root, prepared.snapshot.lock())
    {
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
/// [`CliError::Usage`] when `IPE_REGISTRY_URL` is neither empty nor an
/// `https://` base URL.
fn advisory_check(
    lockfile: &crate::lockfile::Lockfile,
    advisory_db: Option<&Path>,
) -> Result<(), CliError> {
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

    advisory_check_with_base(lockfile, db_root, &crate::registry::registry_source()?)
}

/// The registry-source-injected core of [`advisory_check`]: cross-checks every
/// dep of the captured `lockfile`, reading the registry Pages read API from
/// `source`. Tests pass [`crate::registry::RegistrySource::Disabled`] to skip
/// the HTTP attempt (immediate
/// unreachable → the git-checkout DB is authoritative), keeping them hermetic and
/// off the network.
///
/// # Errors
/// [`CliError::AdvisoryVulnerable`] on a `high`/`critical` match; the advisory-DB
/// errors when the fallback checkout is present but corrupt or unreadable.
fn advisory_check_with_base(
    lockfile: &crate::lockfile::Lockfile,
    db_root: &Path,
    source: &crate::registry::RegistrySource,
) -> Result<(), CliError> {
    for dep in lockfile.packages() {
        // The lockfile parse turns each `name` into a `PackageName` — a single
        // non-traversing path component by construction — so a hand-edited
        // `ipe.lock` name never reaches the registry URL segment or the
        // advisory-DB path join raw.
        check_one_dep_advisories(db_root, &dep.name, dep.version.as_semver(), source)?;
    }
    Ok(())
}

/// Cross-check one locked dep against the advisory DB, preferring the registry
/// Pages HTTP read-path and falling back to the git-checkout DB at `db_root`.
///
/// The Pages fast-path fetches `/advisories/index.json` + the per-advisory
/// records. A reachable index is authoritative for this run — even an empty
/// result proves the dep clean. When the index (or a named record) is unreachable
/// (offline / air-gapped / the [`crate::registry::RegistrySource::Disabled`] opt-out), this is a WARN, never a
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
    source: &crate::registry::RegistrySource,
) -> Result<(), CliError> {
    let name = name.as_str();
    let outcome = crate::registry::fetch_advisories_via_pages_with(
        name,
        source,
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

/// The supply-chain policy the gate applies: the compiler workspace's own
/// `deny.toml`, embedded when this binary was built.
///
/// The policy is part of the gate's installation, so no file at audit time can
/// stand in for it: neither the audited package's tree, nor the working
/// directory, nor a runtime tree a cwd walk or `IPE_RUNTIME_DIR` resolves (a
/// package shipping an empty `src/runtime/rust/src/` beside its own
/// `deny.toml` would otherwise name the policy it is judged by). An absent
/// policy has no representation, so cargo-deny never runs on its defaults.
const GATE_DENY_POLICY: &str = include_str!("../../../deny.toml");

/// Derive a cargo-deny config for the EMITTED project from the gate's
/// embedded policy ([`GATE_DENY_POLICY`]), dropping its `[graph]` section.
///
/// The workspace config's `[graph] features = ["full"]` names the RUNTIME crate's
/// own feature set, which the emitted `ipe-app` does not have — passing the
/// workspace config verbatim makes `cargo metadata` fail on the unknown feature.
/// The advisory/license/bans/sources POLICY is exactly what the gate must apply,
/// so this copies every section EXCEPT `[graph]` into a derived config written
/// beside the emitted project, and returns its path.
///
/// # Errors
/// [`CliError::Io`] on a write failure.
fn derive_deny_config(emitted_dir: &Path) -> Result<PathBuf, CliError> {
    let derived = emitted_dir.join("ipe-audit-deny.toml");
    std::fs::write(&derived, emitted_deny_policy(GATE_DENY_POLICY)).map_err(|e| CliError::Io {
        path: derived.clone(),
        source: e,
    })?;
    Ok(derived)
}

/// `policy` without its `[graph]` table (up to the next top-level `[section]`).
///
/// The remaining tables (`[advisories]`, `[licenses]`, `[bans]`, `[sources]`)
/// are the emitted-project-independent policy the gate applies.
fn emitted_deny_policy(policy: &str) -> String {
    let mut out = String::with_capacity(policy.len());
    let mut in_graph = false;
    for line in policy.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') {
            in_graph = trimmed.starts_with("[graph]");
        }
        if !in_graph {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
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
/// non-blessed package provides a reserved-namespace module.
fn reserved_namespace_ownership(
    name: &str,
    modules: &[crate::project::DiscoveredModule],
    standing: PublisherStanding<'_>,
) -> Result<(), CliError> {
    let module_paths: Vec<&[String]> = modules
        .iter()
        .map(crate::project::DiscoveredModule::module_path)
        .collect();
    reserved_namespace_verdict(name, &module_paths, standing)
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
            control_model: single(crate::delivery::ControlModel::Tea),
            capabilities: BTreeSet::from([Capability::Clock, Capability::Network]),
        };
        let pass = audit_verdict_json(
            "http",
            "1.2.0",
            &Ok(AuditedPackage {
                digest: test_digest(),
                disclosure,
                tier2: Tier2Outcome::SkippedPureIpe,
            }),
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
        assert_eq!(single(crate::delivery::ControlModel::Tea).word(), "tea");
        assert_eq!(
            single(crate::delivery::ControlModel::Direct).word(),
            "direct"
        );
        assert_eq!(ControlModelDisclosure::NotApplicable.word(), "library");
    }

    #[test]
    fn disclosure_summary_lists_capabilities_or_none() {
        let with_caps = Disclosure {
            control_model: single(crate::delivery::ControlModel::Direct),
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

        let result = capture_package(&dir).and_then(prepare);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(
                &result,
                Err(CliError::PackageAudit(r))
                    if r.check == Check::NativeBindingRegen && r.message.contains("`wrapper` field")
            ),
            "prepare must reject a wrapper-only package with a NativeBindingRegen reject naming \
             the wrapper field: {:?}",
            result.as_ref().err()
        );
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

    /// A package that declares no crates still has a committed
    /// `.ipe/cache/ffi/rust` removed before the build, so publisher-supplied
    /// bindings never reach the catalog the certified build loads.
    #[test]
    fn prepare_purges_a_committed_ffi_cache_without_rust_dependencies() {
        let dir = make_test_dir("purge-committed-cache");
        let src = dir.join("src");
        std::fs::create_dir(&src).expect("create src/");
        std::fs::write(src.join("Main.ipe"), "module Main exposing (..)\n")
            .expect("write Main.ipe");
        std::fs::write(
            dir.join("package.ipe"),
            "module Package exposing (package)\n\n\npackage =\n\
             \x20   { name = \"cache-pkg\", version = \"0.1.0\" }\n",
        )
        .expect("write package.ipe");
        let cache = dir.join(ipe_ffi::driver::FFI_CACHE_REL);
        std::fs::create_dir_all(&cache).expect("create committed cache");
        std::fs::write(cache.join("evil_bindings.rs"), "pub fn evil() {}\n")
            .expect("plant committed bindings");

        let result = capture_package(&dir).and_then(prepare);
        let survived = cache.exists();
        if let Ok(prepared) = &result {
            let _ = std::fs::remove_dir_all(&prepared.emitted_dir);
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            !survived,
            "a committed FFI cache must be removed before the build: {:?}",
            result.as_ref().err()
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
        let ipe_link = dir.join(ipe_ffi::driver::CACHE_NAMESPACE_DIR);
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
        // Unterminated raw string — proc-macro2 cannot tokenise this.
        let result = first_hit_in(
            Path::new("x_bindings.rs"),
            r#"fn f() { let x = r##"unterminated"#,
        );
        assert!(
            result.is_err(),
            "a non-lexing _bindings.rs must return Err (refuse), not Ok(None)"
        );
    }

    #[test]
    fn first_hit_clean_lexing_source_is_ok_none() {
        // A well-formed, panic-free file must still return Ok(None).
        let result = first_hit_in(
            Path::new("x_bindings.rs"),
            "pub fn add(a: i64, b: i64) -> i64 { a + b }",
        );
        assert!(result.is_ok(), "a clean file must return Ok(_)");
        assert!(
            result.unwrap().is_none(),
            "a panic-free file must return Ok(None)"
        );
    }

    #[test]
    fn first_hit_file_with_panic_is_ok_some() {
        // A file with a panic! must produce Ok(Some(hit)), unchanged.
        let result = first_hit_in(
            Path::new("x_bindings.rs"),
            "pub fn f() { panic!(\"oops\"); }",
        );
        assert!(result.is_ok(), "a lexing file must return Ok(_)");
        assert!(
            result.unwrap().is_some(),
            "a panic-bearing file must return Ok(Some(_))"
        );
    }

    /// A `_bindings.rs` whose body is `n` nested `!` operators.
    fn nested_not_bindings(n: usize) -> String {
        format!("pub fn f() -> bool {{ {}true }}\n", "! ".repeat(n))
    }

    #[test]
    fn first_hit_too_deep_source_is_a_provenance_refusal() {
        // Past the scanner's depth ceiling the parse would overflow its stack;
        // the audit must refuse with a typed reject, never crash or admit.
        let over = panic_scan::NestDepth::CEILING.get().saturating_add(1);
        let result = first_hit_in(Path::new("x_bindings.rs"), &nested_not_bindings(over));
        assert!(
            matches!(
                &result,
                Err(CliError::PackageAudit(Rejection {
                    check: Check::Provenance,
                    message,
                })) if message.contains("too deep")
            ),
            "{:?}",
            result.as_ref().err()
        );
    }

    #[test]
    fn first_hit_source_at_the_depth_ceiling_is_audited() {
        // Each `!` adds one measure unit, so the base depth plus the remaining
        // budget lands exactly on the ceiling.
        let ceiling = panic_scan::NestDepth::CEILING.get();
        let base = panic_scan::measure(&nested_not_bindings(0))
            .expect("the base fixture lexes")
            .depth;
        let at = nested_not_bindings(ceiling.saturating_sub(base));
        let measured = panic_scan::measure(&at).expect("the control lexes").depth;
        assert_eq!(measured, ceiling, "the control must sit at the ceiling");
        let result = first_hit_in(Path::new("x_bindings.rs"), &at);
        assert!(matches!(result, Ok(None)), "{:?}", result.as_ref().err());
    }

    // ── Disclosure derivation (control model + capabilities) ────────────────

    /// The disclosure of a package whose one program `test-pkg` (entry `Main`) runs `model`.
    fn single(model: crate::delivery::ControlModel) -> ControlModelDisclosure {
        ControlModelDisclosure::Programs(
            NonEmpty::from_vec(vec![ProgramModel {
                program: "test-pkg".to_owned(),
                module: vec!["Main".to_owned()],
                model,
            }])
            .expect("one program"),
        )
    }

    /// A TEA web entry module `module`.
    fn tea_entry(module: &str) -> String {
        format!(
            "module {module} exposing (main)\nimport Ipe.Tea.Web as Web\n\nmain = Web.tea config\n"
        )
    }

    /// A plain-`Task` entry module `module` that writes to standard output.
    fn direct_entry(module: &str) -> String {
        format!(
            "module {module} exposing (main)\n\nimport Ipe.Io as Io\n\n\nmain : Task ()\nmain =\n    Io.println \"hi\"\n"
        )
    }

    /// A manifest of two programs, `board` (a TEA `Main`) then `sync` (a Direct `Sync`), and their sources.
    fn two_program_package() -> (ProjectManifest, ModuleSources) {
        let mut manifest = test_manifest(Path::new("/nonexistent/disclosure-two-programs"));
        manifest.programs = vec![
            crate::project::Program {
                name: "board".to_owned(),
                entry: "Main.ipe".to_owned(),
                shape: None,
            },
            crate::project::Program {
                name: "sync".to_owned(),
                entry: "Sync.ipe".to_owned(),
                shape: None,
            },
        ];
        let sources = ModuleSources::from([
            (
                vec!["Main".to_owned()],
                (manifest.src_root.join("Main.ipe"), tea_entry("Main")),
            ),
            (
                vec!["Sync".to_owned()],
                (manifest.src_root.join("Sync.ipe"), direct_entry("Sync")),
            ),
        ]);
        (manifest, sources)
    }

    /// Every program of a two-program package is disclosed, the second's Direct model included.
    #[test]
    fn disclosure_names_every_program_of_a_two_program_package() {
        let (manifest, sources) = two_program_package();
        let disclosure =
            derive_disclosure(&manifest, &sources, BTreeSet::new()).expect("derives both");
        let models: Vec<(&str, crate::delivery::ControlModel)> = disclosure
            .control_model
            .programs()
            .map(|program| (program.program.as_str(), program.model))
            .collect();
        assert_eq!(
            models,
            vec![
                ("board", crate::delivery::ControlModel::Tea),
                ("sync", crate::delivery::ControlModel::Direct),
            ],
            "each program discloses its own model, in manifest order"
        );
        assert_eq!(
            disclosure.control_model_word(),
            "direct",
            "the one-word model is the most elevated any program runs"
        );
        let summary = disclosure_summary("two", &disclosure);
        assert!(
            summary.contains("control model: direct (`board`: tea, `sync`: direct)"),
            "the summary names both programs' models: {summary}"
        );
        let json = audit_verdict_json(
            "two",
            "0.1.0",
            &Ok(AuditedPackage {
                digest: test_digest(),
                disclosure,
                tier2: crate::audit_native::Tier2Outcome::SkippedPureIpe,
            }),
        );
        assert!(
            json.contains(
                "\"programs\":[{\"name\":\"board\",\"controlModel\":\"tea\"},\
                 {\"name\":\"sync\",\"controlModel\":\"direct\"}]"
            ),
            "the verdict lists both programs: {json}"
        );
    }

    /// A program or package name holding a line break and a backtick is shown escaped on one
    /// line, so it cannot forge a second disclosure line or close its code span.
    #[test]
    fn disclosure_summary_shows_hostile_names_escaped_on_one_line() {
        let (mut manifest, sources) = two_program_package();
        let hostile = "sync\n`forged`: tea";
        if let Some(program) = manifest.programs.get_mut(1) {
            hostile.clone_into(&mut program.name);
        }
        let disclosure =
            derive_disclosure(&manifest, &sources, BTreeSet::new()).expect("derives both");
        let summary = disclosure_summary("two\r\n`pkg`", &disclosure);
        assert!(
            !summary.contains('\n') && !summary.contains('\r'),
            "no name breaks the line: {summary:?}"
        );
        assert!(
            summary.contains(r"`sync\n\`forged\`: tea`: direct"),
            "the program name is shown escaped: {summary}"
        );
        assert!(
            summary.contains(r"package audit: `two\r\n\`pkg\`` control model"),
            "the package name is shown escaped: {summary}"
        );
        let passing = passing_summary(
            "two\n`pkg`",
            "0.1.0",
            &crate::audit_native::Tier2Outcome::SkippedPureIpe,
            &disclosure,
        );
        assert_eq!(
            passing.lines().count(),
            2,
            "the tier line and the disclosure line only: {passing:?}"
        );
    }

    /// A package whose second program alone runs a model `acceptsControl` omits is refused.
    #[test]
    fn consent_refuses_a_second_program_the_accept_set_does_not_cover() {
        let (mut manifest, sources) = two_program_package();
        manifest.control_models_accept =
            std::iter::once(crate::delivery::ControlModel::Tea).collect();
        let disclosure =
            derive_disclosure(&manifest, &sources, BTreeSet::new()).expect("derives both");
        let err = consent_every_program(&disclosure, &manifest)
            .expect_err("the second program's Direct model is not accepted");
        let text = err.to_string();
        assert!(text.contains("IPE-S0004"), "carries the code: {text}");
        assert!(
            text.contains("`Sync`"),
            "names the second program's entry: {text}"
        );

        manifest.control_models_accept = [
            crate::delivery::ControlModel::Tea,
            crate::delivery::ControlModel::Direct,
        ]
        .into_iter()
        .collect();
        assert!(
            consent_every_program(&disclosure, &manifest).is_ok(),
            "an accept set covering both programs passes"
        );
    }

    /// A second program whose entry does not parse fails the disclosure closed.
    #[test]
    fn disclosure_fails_closed_when_a_second_program_does_not_parse() {
        let (manifest, mut sources) = two_program_package();
        sources.insert(
            vec!["Sync".to_owned()],
            (
                manifest.src_root.join("Sync.ipe"),
                "module Sync exposing (main)\n\nmain = = = broken (((\n".to_owned(),
            ),
        );
        let err = derive_disclosure(&manifest, &sources, BTreeSet::new())
            .expect_err("an unparseable second program must fail closed");
        assert!(
            matches!(err, CliError::PackageAudit(ref r) if r.check == Check::Capability),
            "a Capability rejection: {err:?}"
        );
        assert!(
            err.to_string().contains("`sync`"),
            "names the program: {err}"
        );
    }

    /// A declared program whose entry the capture does not hold fails the disclosure closed.
    #[test]
    fn disclosure_fails_closed_when_a_declared_program_is_not_captured() {
        let (manifest, mut sources) = two_program_package();
        sources.remove(["Sync".to_owned()].as_slice());
        let err = derive_disclosure(&manifest, &sources, BTreeSet::new())
            .expect_err("a missing second program must fail closed");
        assert!(
            matches!(&err, CliError::EntryMissing { entry } if entry == "Sync.ipe"),
            "the project root's missing-entry refusal: {err:?}"
        );
    }

    /// An entry that defines no `main` discloses the `direct` model the build's script shape runs.
    #[test]
    fn disclosure_of_an_entry_without_main_is_the_script_model() {
        let (manifest, sources) =
            manifest_with_main("module Main exposing (helper)\n\nhelper = 1\n");
        let disclosure = derive_disclosure(&manifest, &sources, BTreeSet::new()).expect("derives");
        assert_eq!(
            disclosure.control_model,
            single(crate::delivery::ControlModel::Direct),
            "no `main` is the script shape, never a library"
        );
    }

    /// A capture case: its tag, its manifest, and its `src/` files.
    type CaptureCase<'a> = (&'a str, &'a str, &'a [(&'a str, String)]);
    /// Each program's name and entry module, `None` for a library, or the refusal's kind.
    type CaptureOutcome = Result<Option<Vec<(String, Vec<String>)>>, String>;

    fn capture_refusal(err: &CliError) -> String {
        match err {
            CliError::NoDefaultEntry { .. } => "no-default-entry".to_owned(),
            other => format!("{other:?}"),
        }
    }

    /// The outcome of the audit's capture reading and of the project root's resolution over the
    /// package `manifest` with `files` under `src/`.
    fn audited_and_resolved(
        tag: &str,
        manifest: &str,
        files: &[(&str, String)],
    ) -> (CaptureOutcome, CaptureOutcome) {
        use crate::project_root::{EntrySet, ProjectRoot, RootArg};
        let dir = make_test_dir(tag);
        assert!(
            std::fs::create_dir_all(dir.join("src/Tools")).is_ok(),
            "create src/"
        );
        assert!(
            std::fs::write(dir.join("package.ipe"), manifest).is_ok(),
            "write package.ipe"
        );
        for (rel, text) in files {
            assert!(
                std::fs::write(dir.join("src").join(rel), text).is_ok(),
                "write {rel}"
            );
        }
        let snapshot = capture_package(&dir).expect("capture");
        let audited: CaptureOutcome = captured_programs(snapshot.manifest(), snapshot.sources())
            .map(|programs| {
                programs.map(|programs| {
                    programs
                        .iter()
                        .map(|program| (program.name.clone(), program.module.clone()))
                        .collect()
                })
            })
            .map_err(|err| capture_refusal(&err));
        let root = ProjectRoot::resolve(RootArg::at(&dir));
        let _ = std::fs::remove_dir_all(&dir);
        let resolved: CaptureOutcome = root
            .map(|root| match root.entries() {
                EntrySet::Programs(programs) => Some(
                    programs
                        .iter()
                        .map(|entry| (entry.name().as_str().to_owned(), entry.module().to_vec()))
                        .collect(),
                ),
                EntrySet::Library(_) => None,
            })
            .map_err(|err| capture_refusal(&err));
        (audited, resolved)
    }

    /// The programs the audit reads from a capture are the programs the project root resolves,
    /// and a package the root refuses is refused by the audit with the same refusal.
    #[test]
    fn captured_programs_are_the_project_roots_programs() {
        let cases: [CaptureCase<'_>; 6] = [
            (
                "agree-two-programs",
                "module Package exposing (package)\n\n\npackage =\n    { name = \"two\"\n    , programs =\n        [ { name = \"board\", entry = \"Main.ipe\" }\n        , { name = \"sync\", entry = \"Tools/Sync.ipe\" }\n        ]\n    }\n",
                &[
                    ("Main.ipe", tea_entry("Main")),
                    ("Tools/Sync.ipe", direct_entry("Tools.Sync")),
                ],
            ),
            (
                "agree-default-main",
                SNAPSHOT_MANIFEST,
                &[("Main.ipe", direct_entry("Main"))],
            ),
            (
                "agree-library",
                "module Package exposing (package)\n\n\npackage =\n    { name = \"lib\", exposedModules = [ \"Lib\" ] }\n",
                &[(
                    "Lib.ipe",
                    "module Lib exposing (one)\n\none = 1\n".to_owned(),
                )],
            ),
            (
                "agree-declared-over-stray-main",
                "module Package exposing (package)\n\n\npackage =\n    { name = \"tools\"\n    , programs = [ { name = \"sync\", entry = \"Tools/Sync.ipe\" } ]\n    }\n",
                &[
                    ("Main.ipe", tea_entry("Main")),
                    ("Tools/Sync.ipe", direct_entry("Tools.Sync")),
                ],
            ),
            (
                "agree-main-over-exposed",
                "module Package exposing (package)\n\n\npackage =\n    { name = \"both\", exposedModules = [ \"Lib\" ] }\n",
                &[
                    ("Main.ipe", direct_entry("Main")),
                    (
                        "Lib.ipe",
                        "module Lib exposing (one)\n\none = 1\n".to_owned(),
                    ),
                ],
            ),
            (
                "agree-no-default-entry",
                "module Package exposing (package)\n\n\npackage =\n    { name = \"none\" }\n",
                &[(
                    "Lib.ipe",
                    "module Lib exposing (one)\n\none = 1\n".to_owned(),
                )],
            ),
        ];
        for (tag, manifest, files) in cases {
            let (audited, resolved) = audited_and_resolved(tag, manifest, files);
            assert_eq!(audited, resolved, "{tag}: the audit and the root agree");
            let expected: CaptureOutcome = match tag {
                "agree-declared-over-stray-main" => Ok(Some(vec![(
                    "sync".to_owned(),
                    vec!["Tools".to_owned(), "Sync".to_owned()],
                )])),
                "agree-main-over-exposed" => {
                    Ok(Some(vec![("both".to_owned(), vec!["Main".to_owned()])]))
                }
                "agree-no-default-entry" => Err("no-default-entry".to_owned()),
                _ => continue,
            };
            assert_eq!(audited, expected, "{tag}: the expected entry set");
        }
    }

    /// A package the project root refuses for an absent exposed module or an absent declared
    /// entry is refused by the audit with that same refusal, never read as a library or as the
    /// programs that are present.
    #[test]
    fn captured_programs_refuse_what_the_project_root_refuses() {
        let lib = || "module Lib exposing (one)\n\none = 1\n".to_owned();
        let cases: [CaptureCase<'_>; 3] = [
            (
                "refuse-exposed-missing-library",
                "module Package exposing (package)\n\n\npackage =\n    { name = \"lib\", exposedModules = [ \"Absent\" ] }\n",
                &[("Lib.ipe", lib())],
            ),
            (
                "refuse-exposed-missing-beside-main",
                "module Package exposing (package)\n\n\npackage =\n    { name = \"both\", exposedModules = [ \"Absent\" ] }\n",
                &[("Main.ipe", direct_entry("Main")), ("Lib.ipe", lib())],
            ),
            (
                "refuse-declared-entry-missing",
                "module Package exposing (package)\n\n\npackage =\n    { name = \"tools\"\n    , programs = [ { name = \"sync\", entry = \"Tools/Sync.ipe\" } ]\n    }\n",
                &[("Main.ipe", tea_entry("Main"))],
            ),
        ];
        for (tag, manifest, files) in cases {
            let (audited, resolved) = audited_and_resolved(tag, manifest, files);
            assert_eq!(audited, resolved, "{tag}: the audit and the root agree");
            assert_eq!(
                audited,
                Err(capture_refusal(&expected_refusal(tag))),
                "{tag}: refused, never a library or a partial program set"
            );
        }
    }

    /// The refusal [`captured_programs_refuse_what_the_project_root_refuses`] expects for `tag`.
    fn expected_refusal(tag: &str) -> CliError {
        if tag == "refuse-declared-entry-missing" {
            CliError::EntryMissing {
                entry: "Tools/Sync.ipe".to_owned(),
            }
        } else {
            CliError::ExposedModuleMissing {
                module: "Absent".to_owned(),
            }
        }
    }

    /// A manifest and captured sources holding a single `Main` module of `main_src`.
    ///
    /// Only the manifest's `programs` and `exposed_modules` matter to [`derive_disclosure`].
    fn manifest_with_main(main_src: &str) -> (ProjectManifest, ModuleSources) {
        let manifest = test_manifest(Path::new("/nonexistent/disclosure"));
        let sources = ModuleSources::from([(
            vec!["Main".to_owned()],
            (manifest.src_root.join("Main.ipe"), main_src.to_owned()),
        )]);
        (manifest, sources)
    }

    #[test]
    fn disclosure_derives_tea_for_a_web_tea_entry() {
        let (manifest, sources) = manifest_with_main(
            "module Main exposing (main)\n\
             import Ipe.Tea.Web as Web\n\n\
             main = Web.tea config\n",
        );
        let d = derive_disclosure(&manifest, &sources, BTreeSet::new()).expect("derives");
        assert_eq!(
            d.control_model,
            single(crate::delivery::ControlModel::Tea),
            "a `Web.tea` entry discloses the TEA control model"
        );
    }

    #[test]
    fn disclosure_derives_direct_for_a_plain_task_main() {
        let (manifest, sources) = manifest_with_main(
            "module Main exposing (main)\n\n\
             main = doNothing\n",
        );
        let d = derive_disclosure(&manifest, &sources, BTreeSet::new()).expect("derives");
        assert_eq!(
            d.control_model,
            single(crate::delivery::ControlModel::Direct),
            "a plain-`Task` `main` discloses the Direct control model"
        );
    }

    #[test]
    fn disclosure_capabilities_are_the_inferred_set_passed_in() {
        // The disclosure surfaces exactly the SSOT inferred set it is handed —
        // never a re-derivation that could disagree with the consistency check.
        let (manifest, sources) =
            manifest_with_main("module Main exposing (main)\n\nmain = doNothing\n");
        let inferred = BTreeSet::from([Capability::Clock, Capability::Network]);
        let d = derive_disclosure(&manifest, &sources, inferred.clone()).expect("derives");
        assert_eq!(d.capabilities, inferred, "discloses the passed-in SSOT set");
    }

    #[test]
    fn disclosure_is_not_applicable_for_a_library_with_no_runnable_entry() {
        // A library exposes modules but ships no runnable `Main.ipe`; it drives
        // nothing, so the disclosure is an honest absence, not a default model.
        let mut manifest = test_manifest(Path::new("/nonexistent/disclosure-library"));
        manifest.exposed_modules = vec!["MyLib".to_owned()];
        let sources = ModuleSources::from([(
            vec!["MyLib".to_owned()],
            (
                manifest.src_root.join("MyLib.ipe"),
                "module MyLib exposing (helper)\n\nhelper = 1\n".to_owned(),
            ),
        )]);
        let d = derive_disclosure(&manifest, &sources, BTreeSet::new()).expect("derives");
        assert_eq!(
            d.control_model,
            ControlModelDisclosure::NotApplicable,
            "a library with no runnable entry discloses no control model"
        );
    }

    /// A package whose entry module is a FIFO is refused at capture, never disclosed as having no entry.
    #[cfg(unix)]
    #[test]
    fn audit_refuses_a_fifo_entry_rather_than_disclosing_absence() {
        let dir = make_test_dir("disclosure-fifo");
        let src = dir.join("src");
        assert!(std::fs::create_dir_all(&src).is_ok(), "create src/");
        assert!(
            std::fs::write(dir.join("package.ipe"), SNAPSHOT_MANIFEST).is_ok(),
            "write package.ipe"
        );
        let made = std::process::Command::new("mkfifo")
            .arg(src.join("MyLib.ipe"))
            .status();
        assert!(
            made.is_ok_and(|status| status.success()),
            "mkfifo creates the fixture"
        );
        let result = capture_package(&dir);
        assert!(
            matches!(&result, Err(CliError::LocalLimitExceeded(_))),
            "a FIFO entry must fail the audit closed at capture: {:?}",
            result.as_ref().err()
        );
    }

    #[test]
    fn disclosure_fails_closed_when_a_runnable_entry_does_not_parse() {
        // A `Main.ipe` exists (a runnable entry) but does not parse: the audit
        // must REJECT rather than disclose a permissive-looking default. This is
        // the fail-closed branch — a program whose control model we cannot state
        // is refused, never certified as `direct`/library.
        let (manifest, sources) =
            manifest_with_main("module Main exposing (main)\n\nmain = = = broken (((\n");
        let err = derive_disclosure(&manifest, &sources, BTreeSet::new())
            .expect_err("an unparseable runnable entry must fail closed");
        assert!(
            matches!(err, CliError::PackageAudit(ref r) if r.check == Check::Capability),
            "fail-closed on an underivable control model is a Capability rejection: {err:?}"
        );
        assert!(
            !err.to_string().contains("direct") && !err.to_string().contains("library"),
            "the fail-closed reject discloses no permissive default model: {err}"
        );
    }

    #[test]
    fn audit_refuses_a_direct_entry_a_declared_accept_set_does_not_cover() {
        // The audit-boundary control-model consent (defence-in-depth): a package
        // that opted into control-model consent (a non-empty `acceptsControl`)
        // whose declared set does not cover its actual Direct model is refused —
        // fail-closed, never certified against a stale acceptance.
        let (mut manifest, sources) =
            manifest_with_main("module Main exposing (main)\n\nmain = doNothing\n");
        manifest.control_models_accept =
            std::iter::once(crate::delivery::ControlModel::Tea).collect();
        let disclosure =
            derive_disclosure(&manifest, &sources, BTreeSet::new()).expect("derives Direct");
        assert_eq!(
            disclosure.control_model,
            single(crate::delivery::ControlModel::Direct),
            "a plain-Task entry discloses the Direct model"
        );
        let err = crate::control_model_consent::gate(
            crate::delivery::ControlModel::Direct,
            &manifest.control_models_accept,
            &manifest.name,
        )
        .expect_err("a declared accept-set that omits the derived model is refused");
        assert!(err.to_string().contains("IPE-S0004"), "carries the code");
    }

    #[test]
    fn audit_accepts_a_direct_entry_a_declared_accept_set_covers() {
        let (mut manifest, sources) =
            manifest_with_main("module Main exposing (main)\n\nmain = doNothing\n");
        manifest.control_models_accept =
            std::iter::once(crate::delivery::ControlModel::Direct).collect();
        let disclosure =
            derive_disclosure(&manifest, &sources, BTreeSet::new()).expect("derives Direct");
        assert_eq!(
            disclosure.control_model,
            single(crate::delivery::ControlModel::Direct),
        );
        crate::control_model_consent::gate(
            crate::delivery::ControlModel::Direct,
            &manifest.control_models_accept,
            &manifest.name,
        )
        .expect("a Direct entry a declared accept-set covers passes");
    }

    #[test]
    fn audit_leaves_a_clean_entry_with_no_accept_set_unconstrained() {
        // A clean package with no `acceptsControl` — including a legitimate
        // self-driving Direct script — certifies: the model is disclosed, not
        // gated, until the author opts into control-model consent.
        let (manifest, sources) =
            manifest_with_main("module Main exposing (main)\n\nmain = doNothing\n");
        let disclosure =
            derive_disclosure(&manifest, &sources, BTreeSet::new()).expect("derives Direct");
        assert_eq!(
            disclosure.control_model,
            single(crate::delivery::ControlModel::Direct),
        );
        assert!(
            manifest.control_models_accept.is_empty(),
            "the clean package declares no acceptsControl"
        );
        crate::control_model_consent::gate(
            crate::delivery::ControlModel::Direct,
            &manifest.control_models_accept,
            &manifest.name,
        )
        .expect("a clean Direct entry with no acceptsControl certifies unconstrained");
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

        let mut manifest = test_manifest(&index_root.join("proj"));
        manifest.name = "test-pkg".to_owned();
        manifest.version = Some("0.0.0-smoke.2".parse().expect("valid prerelease"));

        let result = enforced_semver(&manifest, &ModuleSources::new(), Some(&index_root));
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
            let mut manifest = test_manifest(&index_root.join("proj"));
            manifest.version = Some(raw.parse().expect("valid semver with build"));
            let result = enforced_semver(&manifest, &ModuleSources::new(), Some(&index_root));
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

        let mut manifest = test_manifest(&index_root.join("proj"));
        manifest.name = "test-pkg".to_owned();
        manifest.version = Some("0.0.1".parse().expect("valid release"));

        let result = enforced_semver(&manifest, &ModuleSources::new(), Some(&index_root));
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

    /// A minimal manifest rooted at `root`.
    fn test_manifest(root: &std::path::Path) -> ProjectManifest {
        use std::collections::{BTreeMap, BTreeSet};
        ProjectManifest {
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
        }
    }

    /// The advisory check over the `ipe.lock` written under `dir`, against the DB at `db`.
    fn advisory_over(dir: &Path, db: &Path) -> Result<(), CliError> {
        crate::lockfile::Lockfile::read(dir).and_then(|lock| {
            advisory_check_with_base(&lock, db, &crate::registry::RegistrySource::Disabled)
        })
    }

    /// A digest literal for a verdict that judged no tree.
    #[allow(clippy::expect_used)] // test fixture: the literal is a valid digest
    fn test_digest() -> Sha256Hex {
        let package = crate::package_name::PackageName::parse("p").expect("valid name");
        Sha256Hex::parse(&package, &"0".repeat(64)).expect("valid digest")
    }

    // ── One capture: every verdict is over the snapshot ─────────────────────

    /// A pure package manifest declaring no capabilities.
    const SNAPSHOT_MANIFEST: &str = "module Package exposing (package)\n\n\npackage =\n    \
                                     { name = \"snap-pkg\", version = \"0.1.0\" }\n";

    /// A module whose effects the manifest above does not declare.
    const LEAK_MODULE: &str = "module Leak exposing (leak)\n\
                               import Ipe.Html exposing (render, section)\n\
                               import Ipe.Html.Unsafe exposing (unsafeScript)\n\n\
                               leak = render (section [] [ unsafeScript \"x\" ])\n";

    /// An entry that reaches [`LEAK_MODULE`], so the capability check sees its effects.
    const LEAKING_MAIN: &str = "module Main exposing (main)\n\n\
                                import Ipe.Io as Io\n\
                                import Leak\n\n\n\
                                main : Task ()\n\
                                main =\n    \
                                Io.println (Leak.leak)\n";

    /// A capability-clean package directory (an auditable package has a `Main` entry).
    fn clean_package(tag: &str) -> PathBuf {
        let dir = make_test_dir(tag);
        assert!(
            std::fs::create_dir_all(dir.join("src")).is_ok(),
            "create src/"
        );
        assert!(
            std::fs::write(dir.join("package.ipe"), SNAPSHOT_MANIFEST).is_ok(),
            "write package.ipe"
        );
        assert!(
            std::fs::write(
                dir.join("src/Lib.ipe"),
                "module Lib exposing (one)\n\none = 1\n"
            )
            .is_ok(),
            "write Lib.ipe"
        );
        assert!(
            std::fs::write(
                dir.join("src/Main.ipe"),
                "module Main exposing (main)\n\nimport Ipe.Io as Io\n\n\nmain : Task ()\nmain =\n    Io.println \"hi\"\n"
            )
            .is_ok(),
            "write Main.ipe"
        );
        dir
    }

    /// The capability verdict over a snapshot's assembled sources.
    fn snapshot_capability_verdict(
        snapshot: &PackageSnapshot,
    ) -> Result<BTreeSet<Capability>, CliError> {
        let sources = crate::driver::PackageSourceSet::from_snapshot(snapshot)?;
        capability_verdict(snapshot.manifest(), &sources)
    }

    /// A module added after capture does not change the verdict: the check
    /// judges the captured bytes, and a fresh capture of the swapped tree is
    /// refused.
    #[test]
    fn audit_verdict_is_over_the_snapshot() {
        let dir = clean_package("snapshot-verdict");
        let captured = capture_package(&dir);
        assert!(
            std::fs::write(dir.join("src/Leak.ipe"), LEAK_MODULE).is_ok()
                && std::fs::write(dir.join("src/Main.ipe"), LEAKING_MAIN).is_ok(),
            "swap in a reachable leaking module after capture"
        );
        let judged = captured.and_then(|snapshot| snapshot_capability_verdict(&snapshot));
        let fresh =
            capture_package(&dir).and_then(|snapshot| snapshot_capability_verdict(&snapshot));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(&judged, Ok(set) if set.is_empty()),
            "the verdict is over the captured tree: {:?}",
            judged.as_ref().err()
        );
        assert!(
            matches!(&fresh, Err(CliError::PackageAudit(r)) if r.check == Check::Capability),
            "control: the swapped tree carries an undeclared effect: {:?}",
            fresh
                .as_ref()
                .map(BTreeSet::len)
                .map_err(ToString::to_string)
        );
    }

    /// A tree changed while the audit ran is refused, never certified under either digest.
    #[test]
    fn audit_refuses_a_tree_changed_during_the_audit() {
        let dir = clean_package("snapshot-reprove");
        let unchanged = capture_package(&dir).and_then(|snapshot| {
            reprove_tree(&snapshot).map(|digest| digest == Sha256Hex::of_digest(snapshot.tree()))
        });
        let captured = capture_package(&dir);
        assert!(
            std::fs::write(dir.join("src/Leak.ipe"), LEAK_MODULE).is_ok(),
            "swap in a module after capture"
        );
        let changed = captured.and_then(|snapshot| reprove_tree(&snapshot));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(unchanged, Ok(true)),
            "control: an unchanged tree certifies the snapshot's digest: {:?}",
            unchanged.err()
        );
        assert!(
            matches!(&changed, Err(CliError::HashMismatch { package, .. }) if package == "snap-pkg"),
            "a tree changed after capture is refused: {:?}",
            changed.as_ref().ok()
        );
    }

    /// An entry recording other capabilities than the audited set is refused.
    #[test]
    fn audited_capabilities_refuse_a_different_record() {
        let audited = AuditedPackage::for_test(test_digest(), BTreeSet::from([Capability::Clock]));
        assert!(
            audited
                .refuse_other_capabilities(&BTreeSet::from([Capability::Clock]))
                .is_ok(),
            "control: the audited set is admitted"
        );
        for lie in [
            BTreeSet::new(),
            BTreeSet::from([Capability::Clock, Capability::Network]),
        ] {
            assert!(
                matches!(
                    audited.refuse_other_capabilities(&lie),
                    Err(CliError::PackageAudit(r)) if r.check == Check::Capability
                ),
                "a recorded set {lie:?} other than the audited one is refused"
            );
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

        // Empty base URL disables the HTTP fast-path (hermetic, off-network); the
        // planted git-checkout DB is authoritative on the fallback path.
        let result = advisory_over(&dir, &db);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&db);
        assert!(
            matches!(result, Err(CliError::AdvisoryVulnerable(_))),
            "high-severity dep in range must be rejected: {result:?}"
        );
    }

    /// Explicit opt-out gate-level test: `advisory_check(lock, None)` must
    /// return `Ok(())` — `None` is the explicit `--no-advisory-db` opt-out path.
    #[test]
    fn advisory_check_none_skips_check() {
        let dir = make_test_dir("adv-gate-skip");
        let db = make_test_dir("adv-gate-db-skip");
        write_lockfile(&dir, "vuln-pkg", "1.1.0");
        write_high_advisory(&db, "vuln-pkg", ">=1.0.0, <1.2.0");

        let result =
            crate::lockfile::Lockfile::read(&dir).and_then(|lock| advisory_check(&lock, None));
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

            let result = advisory_over(&dir, &db);
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

        let result = advisory_over(&dir, &db);
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

    /// `prepare` resolves the runtime through the SAME path `ipe dev build` uses — the
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
        let args = deny_args(20, manifest, config);
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
        let args = deny_args(19, manifest, config);
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

    /// A `cargo-deny` driven through a stub that runs a shell `body`.
    #[cfg(unix)]
    mod stubbed_cargo_deny {
        use super::super::{
            LocalRefusal, LocalSource, RunError, SUPPLY_CHAIN_SCAN_LIMITS, TOOL_QUERY_LIMITS,
            detect_cargo_deny_minor, run_cargo_deny,
        };
        use crate::remote_ingest::{IngestLimit, LocalWall};
        use std::os::unix::fs::PermissionsExt as _;
        use std::path::PathBuf;
        use std::time::{Duration, Instant};

        /// A fresh scratch base for `tag` holding a stub `cargo-deny` that runs `body`.
        fn stub(tag: &str, body: &str) -> PathBuf {
            let base = ipe_test_temp::temp_root()
                .join(format!("ipe-audit-deny-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&base).expect("scratch base");
            let path = base.join("cargo-deny");
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write stub");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("stub executable");
            path
        }

        /// Remove the scratch base holding the stub at `path`.
        fn clean(path: &std::path::Path) {
            if let Some(base) = path.parent() {
                let _ = std::fs::remove_dir_all(base);
            }
        }

        #[test]
        fn a_scan_past_its_wall_is_refused() {
            let deny = stub("scan-wall", "exec sleep 30");
            let started = Instant::now();
            let ran = run_cargo_deny(
                deny.as_os_str(),
                &[],
                SUPPLY_CHAIN_SCAN_LIMITS.with_wall(LocalWall::of_secs::<1>()),
            );
            assert!(
                matches!(
                    &ran,
                    Err(RunError::Exceeded(LocalRefusal {
                        source: LocalSource::SupplyChainScan,
                        limit: IngestLimit::Time(_),
                        ..
                    }))
                ),
                "a scan past its wall is a typed refusal, got {ran:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "the refusal lands at the wall, not at the child's exit"
            );
            clean(&deny);
        }

        #[test]
        fn a_scan_flooding_stdout_is_refused() {
            let deny = stub("scan-flood", "head -c 2097152 /dev/zero");
            let ran = run_cargo_deny(deny.as_os_str(), &[], SUPPLY_CHAIN_SCAN_LIMITS);
            assert!(
                matches!(
                    &ran,
                    Err(RunError::Exceeded(LocalRefusal {
                        source: LocalSource::SupplyChainScan,
                        limit: IngestLimit::Bytes(_),
                        ..
                    }))
                ),
                "a scan past its stdout ceiling is a typed refusal, got {ran:?}"
            );
            clean(&deny);
        }

        #[test]
        fn a_version_probe_reads_the_minor() {
            let deny = stub("probe-ok", "echo 'cargo-deny 0.14.3'");
            assert_eq!(
                detect_cargo_deny_minor(deny.as_os_str(), TOOL_QUERY_LIMITS),
                14
            );
            clean(&deny);
        }

        #[test]
        fn a_version_probe_past_its_wall_falls_back_to_the_latest_placement() {
            let deny = stub("probe-wall", "echo 'cargo-deny 0.14.3'\nexec sleep 30");
            let started = Instant::now();
            let minor = detect_cargo_deny_minor(
                deny.as_os_str(),
                TOOL_QUERY_LIMITS.with_wall(LocalWall::of_secs::<1>()),
            );
            assert_eq!(minor, 20, "a probe stopped at its wall reads no version");
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "the probe is stopped at its wall, not at the child's exit"
            );
            clean(&deny);
        }

        #[test]
        fn a_version_probe_flooding_stdout_falls_back_to_the_latest_placement() {
            let deny = stub(
                "probe-flood",
                "head -c 131072 /dev/zero | tr '\\0' ' '\necho 'cargo-deny 0.14.3'",
            );
            assert_eq!(
                detect_cargo_deny_minor(deny.as_os_str(), TOOL_QUERY_LIMITS),
                20,
                "a probe past its stdout ceiling reads no version"
            );
            clean(&deny);
        }
    }

    /// The gate's posture and policy origin: every verdict input is typed by
    /// the gate's own installation, never read from the package or the host's
    /// ambient state at the verdict.
    mod gate_posture_and_policy_origin {
        use std::collections::BTreeMap;
        use std::path::PathBuf;

        use super::super::{
            Check, GATE_DENY_POLICY, GatePosture, Rejection, derive_deny_config,
            emitted_deny_policy,
        };
        use super::make_test_dir;
        use crate::CliError;
        use crate::text;

        fn bwrap() -> ipe_sandbox::Mechanism {
            ipe_sandbox::Mechanism::Bwrap(PathBuf::from("/usr/bin/bwrap"))
        }

        /// The regeneration rejection's message, or `None` for any other outcome.
        fn regen_rejection(result: Result<GatePosture, CliError>) -> Option<String> {
            match result {
                Err(CliError::PackageAudit(Rejection {
                    check: Check::NativeBindingRegen,
                    message,
                })) => Some(message),
                Ok(_) | Err(_) => None,
            }
        }

        #[test]
        fn gate_posture_refuses_the_unsandboxed_override() {
            let message = regen_rejection(GatePosture::from_facts(true, &bwrap()));
            assert_eq!(
                message,
                Some(String::from(text::msg::audit_refuses_unsandboxed_override())),
                "the developer override is a refusal of the gate even with a jail present"
            );
        }

        #[test]
        fn gate_posture_refuses_a_host_without_a_jail() {
            let message = regen_rejection(GatePosture::from_facts(
                false,
                &ipe_sandbox::Mechanism::Refused,
            ));
            assert_eq!(
                message,
                Some(String::from(text::msg::audit_requires_a_jail())),
                "no bubblewrap means no regeneration, never a host run"
            );
        }

        #[test]
        fn gate_posture_holds_under_a_jail_without_the_override() {
            assert!(
                GatePosture::from_facts(false, &bwrap()).is_ok(),
                "a jailed host without the override is the one accepted posture"
            );
        }

        #[test]
        fn the_gate_writes_its_embedded_policy_for_every_audit() {
            let emitted = make_test_dir("policy-embedded");
            let written = derive_deny_config(&emitted)
                .ok()
                .and_then(|path| std::fs::read_to_string(path).ok());
            assert_eq!(
                written.as_deref(),
                Some(emitted_deny_policy(GATE_DENY_POLICY).as_str()),
                "the derived config is the compiler's own policy, whatever the disk holds"
            );
            let policy = written.unwrap_or_default();
            assert!(
                policy.contains("unknown-registry = \"deny\"") && policy.contains("[advisories]"),
                "the embedded policy carries the supply-chain tables, never cargo-deny defaults"
            );
            let _ = std::fs::remove_dir_all(&emitted);
        }

        #[test]
        fn the_emitted_policy_drops_only_the_graph_table() {
            let policy = "[graph]\nfeatures = [\"full\"]\n[advisories]\nignore = []\n[sources]\nunknown-git = \"deny\"\n";
            assert_eq!(
                emitted_deny_policy(policy),
                "[advisories]\nignore = []\n[sources]\nunknown-git = \"deny\"\n",
                "the runtime crate's feature graph is dropped; every policy table is kept"
            );
        }

        /// Names whose qualified mention in production code is an ambient read:
        /// the process environment, the working directory, a runtime tree found
        /// from either, the sandbox facts.
        const AMBIENT_READS: &[&str] = &[
            "current_dir",
            "resolve_runtime",
            "resolve_runtime_src",
            "var",
            "var_os",
            "vars",
            "vars_os",
            "unsandboxed_override_set",
            "probe",
            "select_mechanism",
        ];

        /// Macros that read the build or process environment.
        const AMBIENT_MACROS: &[&str] = &["env", "option_env"];

        /// The one production function allowed to read the sandbox facts.
        const POSTURE_SITE: &str = "establish";

        /// Whether `attrs` carry `#[cfg(test)]`.
        fn is_cfg_test(attrs: &[syn::Attribute]) -> bool {
            attrs.iter().any(|attr| {
                matches!(&attr.meta, syn::Meta::List(list)
                    if list.path.is_ident("cfg") && list.tokens.to_string() == "test")
            })
        }

        /// Ambient reads per production scope: `(enclosing function, name) -> count`.
        ///
        /// A qualified path (`std::env::current_dir`, `ipe_sandbox::probe`), a
        /// `use` of the name (which would let a bare call stand for it), a
        /// macro path (`env!`), and a `::name` token inside any macro's
        /// arguments all count; a bare local named like one does not. Items
        /// under `#[cfg(test)]` are skipped.
        #[derive(Default)]
        struct AmbientReads {
            scope: Vec<String>,
            hits: BTreeMap<(String, String), usize>,
        }

        impl AmbientReads {
            fn hit(&mut self, name: &str) {
                let scope = self
                    .scope
                    .last()
                    .cloned()
                    .unwrap_or_else(|| String::from("<item>"));
                *self.hits.entry((scope, String::from(name))).or_insert(0) += 1;
            }

            fn qualified_path(&mut self, path: &syn::Path) {
                if path.segments.len() < 2 {
                    return;
                }
                if let Some(last) = path.segments.last()
                    && let Some(name) = AMBIENT_READS.iter().find(|n| last.ident == **n)
                {
                    self.hit(name);
                }
            }

            /// Every `::name` ident of a macro's unparsed tokens.
            fn tokens(&mut self, stream: proc_macro2::TokenStream) {
                let mut after_colon = false;
                for tree in stream {
                    match tree {
                        proc_macro2::TokenTree::Ident(ident) => {
                            if after_colon
                                && let Some(name) = AMBIENT_READS.iter().find(|n| ident == **n)
                            {
                                self.hit(name);
                            }
                            after_colon = false;
                        }
                        proc_macro2::TokenTree::Group(group) => {
                            self.tokens(group.stream());
                            after_colon = false;
                        }
                        proc_macro2::TokenTree::Punct(punct) => {
                            after_colon = punct.as_char() == ':';
                        }
                        proc_macro2::TokenTree::Literal(_) => after_colon = false,
                    }
                }
            }
        }

        impl<'ast> syn::visit::Visit<'ast> for AmbientReads {
            fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
                if !is_cfg_test(&m.attrs) {
                    syn::visit::visit_item_mod(self, m);
                }
            }

            fn visit_item_impl(&mut self, imp: &'ast syn::ItemImpl) {
                if !is_cfg_test(&imp.attrs) {
                    syn::visit::visit_item_impl(self, imp);
                }
            }

            fn visit_item_trait(&mut self, tr: &'ast syn::ItemTrait) {
                if !is_cfg_test(&tr.attrs) {
                    syn::visit::visit_item_trait(self, tr);
                }
            }

            fn visit_item_use(&mut self, u: &'ast syn::ItemUse) {
                if !is_cfg_test(&u.attrs) {
                    syn::visit::visit_item_use(self, u);
                }
            }

            fn visit_item_const(&mut self, c: &'ast syn::ItemConst) {
                if !is_cfg_test(&c.attrs) {
                    syn::visit::visit_item_const(self, c);
                }
            }

            fn visit_item_static(&mut self, s: &'ast syn::ItemStatic) {
                if !is_cfg_test(&s.attrs) {
                    syn::visit::visit_item_static(self, s);
                }
            }

            fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
                if is_cfg_test(&f.attrs) {
                    return;
                }
                self.scope.push(f.sig.ident.to_string());
                syn::visit::visit_item_fn(self, f);
                self.scope.pop();
            }

            fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
                if is_cfg_test(&f.attrs) {
                    return;
                }
                self.scope.push(f.sig.ident.to_string());
                syn::visit::visit_impl_item_fn(self, f);
                self.scope.pop();
            }

            fn visit_trait_item_fn(&mut self, f: &'ast syn::TraitItemFn) {
                if is_cfg_test(&f.attrs) {
                    return;
                }
                self.scope.push(f.sig.ident.to_string());
                syn::visit::visit_trait_item_fn(self, f);
                self.scope.pop();
            }

            fn visit_path(&mut self, path: &'ast syn::Path) {
                self.qualified_path(path);
                syn::visit::visit_path(self, path);
            }

            fn visit_use_name(&mut self, name: &'ast syn::UseName) {
                if let Some(found) = AMBIENT_READS.iter().find(|n| name.ident == **n) {
                    self.hit(found);
                }
            }

            fn visit_use_rename(&mut self, rename: &'ast syn::UseRename) {
                if let Some(found) = AMBIENT_READS.iter().find(|n| rename.ident == **n) {
                    self.hit(found);
                }
            }

            fn visit_macro(&mut self, mac: &'ast syn::Macro) {
                if let Some(last) = mac.path.segments.last()
                    && let Some(name) = AMBIENT_MACROS.iter().find(|n| last.ident == **n)
                {
                    self.hit(name);
                }
                self.tokens(mac.tokens.clone());
                syn::visit::visit_macro(self, mac);
            }
        }

        /// The ambient reads of `src`'s production code; `None` when it does not parse.
        fn ambient_reads(src: &str) -> Option<BTreeMap<(String, String), usize>> {
            use syn::visit::Visit as _;
            let file = syn::parse_file(src).ok()?;
            let mut scan = AmbientReads::default();
            scan.visit_file(&file);
            Some(scan.hits)
        }

        const AUDIT_SOURCE: &str = include_str!("audit.rs");

        #[test]
        fn audit_source_reads_no_environment_or_cwd() {
            let hits = ambient_reads(AUDIT_SOURCE);
            assert!(hits.is_some(), "audit.rs parses");
            let Some(hits) = hits else { return };

            let mut expected = BTreeMap::new();
            for name in ["unsandboxed_override_set", "probe", "select_mechanism"] {
                expected.insert((String::from(POSTURE_SITE), String::from(name)), 1);
            }
            assert_eq!(
                hits, expected,
                "the sandbox facts are read once, in `GatePosture::establish`; the \
                 environment and the working directory are read nowhere (a stale \
                 allowlist is red too)"
            );
        }

        #[test]
        fn the_ambient_scan_sees_a_working_directory_read() {
            let mutated = format!(
                "{AUDIT_SOURCE}\nfn smuggled() -> std::io::Result<PathBuf> {{ std::env::current_dir() }}\n"
            );
            let hits = ambient_reads(&mutated).unwrap_or_default();
            assert_eq!(
                hits.get(&(String::from("smuggled"), String::from("current_dir"))),
                Some(&1),
                "a qualified working-directory read in a production function is a hit"
            );
        }

        #[test]
        fn the_ambient_scan_sees_a_runtime_tree_resolution() {
            let mutated = format!(
                "{AUDIT_SOURCE}\nfn policy_beside_runtime() -> bool {{ crate::resolve_runtime().is_ok() }}\n"
            );
            let hits = ambient_reads(&mutated).unwrap_or_default();
            assert_eq!(
                hits.get(&(
                    String::from("policy_beside_runtime"),
                    String::from("resolve_runtime")
                )),
                Some(&1),
                "a runtime tree resolved from the cwd or the environment is an ambient read"
            );
        }

        #[test]
        fn the_ambient_scan_sees_an_imported_environment_reader() {
            let mutated = format!("use std::env::var_os as read_setting;\n{AUDIT_SOURCE}");
            let hits = ambient_reads(&mutated).unwrap_or_default();
            assert_eq!(
                hits.get(&(String::from("<item>"), String::from("var_os"))),
                Some(&1),
                "importing an environment reader under another name is a hit"
            );
        }

        #[test]
        fn the_ambient_scan_sees_a_second_posture_read() {
            let mutated = format!(
                "{AUDIT_SOURCE}\nfn second_look() -> bool {{ ipe_sandbox::unsandboxed_override_set() }}\n"
            );
            let hits = ambient_reads(&mutated).unwrap_or_default();
            assert_eq!(
                hits.get(&(
                    String::from("second_look"),
                    String::from("unsandboxed_override_set")
                )),
                Some(&1),
                "a second read of the override outside the posture site is a hit"
            );
        }

        #[test]
        fn the_ambient_scan_sees_a_read_hidden_in_macro_arguments() {
            let mutated = format!(
                "{AUDIT_SOURCE}\nfn in_macro() -> String {{ format!(\"{{:?}}\", std::env::current_dir()) }}\n"
            );
            let hits = ambient_reads(&mutated).unwrap_or_default();
            assert_eq!(
                hits.get(&(String::from("in_macro"), String::from("current_dir"))),
                Some(&1),
                "a read inside a macro's arguments is a hit"
            );
        }

        #[test]
        fn the_ambient_scan_ignores_a_bare_local_and_test_code() {
            let mutated = format!(
                "{AUDIT_SOURCE}\nfn local_named_probe() -> u8 {{ let probe = 1; probe }}\n\
                 #[cfg(test)]\nfn only_in_tests() -> std::io::Result<PathBuf> {{ std::env::current_dir() }}\n"
            );
            let hits = ambient_reads(&mutated).unwrap_or_default();
            assert!(
                !hits.contains_key(&(String::from("local_named_probe"), String::from("probe"))),
                "a bare local is not a sandbox read"
            );
            assert!(
                !hits.contains_key(&(String::from("only_in_tests"), String::from("current_dir"))),
                "test-only code is outside the scan"
            );
        }
    }
}
