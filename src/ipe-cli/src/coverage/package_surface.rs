//! The package surface: one reconciled enumeration of every declared dependency
//! (Ipê packages and native Rust crates) drawn from a project's manifest and
//! lockfile.
//!
//! Supply-chain coverage drifts the same way a stdlib symbol does: a dependency
//! that is declared but not pinned, or pinned but not hash-verified, or a native
//! crate whose capability set is never declared, is a gap that this surface names
//! at its coordinate. The four columns check the reproducibility and honesty
//! guarantees ADR 0007 mandates for every entry admitted to the package index.
//!
//! A [`PackageItem`] is either an Ipê dependency (`[dependencies]`) or a native
//! Rust crate (`[rust.dependencies]`). Columns that do not apply to one kind
//! return [`Cell::NotApplicable`] for items of the other kind, so the runner
//! never hides a gap behind a column that silently skips it.
//!
//! # Columns
//!
//! - **pinned-and-hashed** (security) — the lockfile entry carries a non-local
//!   revision; its sha256 is a well-formed digest by construction (parsed at
//!   `Lockfile::read`). These are the two integrity anchors the resolver
//!   verifies on every fetch. A path-escape dep has no lockfile pin
//!   ([`Cell::NotApplicable`]); any other dep without a lockfile entry is a hole.
//! - **semver-satisfied** — for an index Ipê dep, the locked version satisfies
//!   the manifest's version requirement. Git-escape and path-escape deps carry no
//!   version requirement; native crates hand their requirement to cargo
//!   verbatim — both are [`Cell::NotApplicable`].
//! - **capability-declared** — for a native Rust crate, the manifest's
//!   `[capabilities] declared` set is non-empty, meaning the author has asserted
//!   what axes of trust the native code exercises. For a pure Ipê dep the
//!   compiler infers the capability set, so this column returns
//!   [`Cell::NotApplicable`]. An empty declaration is a [`Cell::Warn`] (a native
//!   dep whose full capability footprint is undeclared is advisory debt;
//!   Tier-2 enforcement in `ipe package audit` is the authoritative gate).
//! - **provenance-scanned** — the resolved dep's cached source still hashes to
//!   the pin recorded in `ipe.lock`, re-asserting the verify-before-trust
//!   boundary from ADR 0007. Computed once for all index/git-escape deps and
//!   shared across the column's per-item checks. A path-escape dep is
//!   [`Cell::NotApplicable`] (no lockfile hash to re-assert).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::coverage::contract::{AspectCheck, Cell, Surface};
use crate::lockfile::{LockedOrigin, Lockfile};
use crate::project::{IpeDep, ProjectManifest, RustDep};

// ── item type ─────────────────────────────────────────────────────────────────

/// The kind of a package item, carried so columns can dispatch on it without
/// re-examining the dep fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DepKindLabel {
    /// A pure Ipê package from `[dependencies]`.
    Ipe,
    /// A native Rust crate from `[rust.dependencies]`.
    Native,
}

/// One item of the package surface: a declared dependency by name and kind.
#[derive(Clone, Debug)]
pub struct PackageItem {
    /// The dependency name as declared in the manifest.
    pub name: String,
    /// Whether this is a pure Ipê dep or a native Rust crate.
    pub kind: DepKindLabel,
    /// The Ipê dep entry (present iff `kind == Ipe`).
    pub ipe_dep: Option<IpeDep>,
    /// The Rust dep entry (present iff `kind == Native`).
    pub rust_dep: Option<RustDep>,
}

impl PackageItem {
    /// Whether this dep is a local-path escape: `IpeDep::Path` or a native dep
    /// with no lockfile counterpart (native crates are locked by cargo, not
    /// `ipe.lock`).
    const fn is_path_escape(&self) -> bool {
        matches!(self.ipe_dep.as_ref(), Some(IpeDep::Path(_)))
    }
}

// ── surface ───────────────────────────────────────────────────────────────────

/// The package surface for one project. Enumerates the project's declared
/// dependencies from the parsed manifest and lockfile.
///
/// Not zero-sized: it holds the project root so [`Surface::all`] can read both
/// `package.ipe` and `ipe.lock` from the right location.
#[derive(Clone, Debug)]
pub struct PackageSurface {
    /// The project root (directory that contains `package.ipe`).
    pub project_root: PathBuf,
}

impl PackageSurface {
    /// Construct a surface rooted at `project_root`.
    #[must_use]
    pub const fn new(project_root: PathBuf) -> Self {
        Self { project_root }
    }
}

impl Surface for PackageSurface {
    type Item = PackageItem;

    fn name(&self) -> &'static str {
        "package"
    }

    fn all(&self) -> Vec<PackageItem> {
        let Ok(manifest) = load_manifest(&self.project_root) else {
            return Vec::new();
        };

        let mut items: Vec<PackageItem> = Vec::new();

        for (name, dep) in &manifest.dependencies {
            items.push(PackageItem {
                name: name.clone(),
                kind: DepKindLabel::Ipe,
                ipe_dep: Some(dep.clone()),
                rust_dep: None,
            });
        }

        for (name, dep) in &manifest.rust_dependencies {
            items.push(PackageItem {
                name: name.clone(),
                kind: DepKindLabel::Native,
                ipe_dep: None,
                rust_dep: Some(dep.clone()),
            });
        }

        // Deterministic: name-sorted, Ipê before native on a name tie.
        items.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| kind_rank(&a.kind).cmp(&kind_rank(&b.kind)))
        });
        items
    }

    fn label(item: &PackageItem) -> String {
        item.name.clone()
    }
}

/// Sort tie-break: Ipê dep before native dep of the same name.
const fn kind_rank(kind: &DepKindLabel) -> u8 {
    match kind {
        DepKindLabel::Ipe => 0,
        DepKindLabel::Native => 1,
    }
}

// ── lockfile loader ───────────────────────────────────────────────────────────

/// Load and parse the project manifest. Separated so the surface and columns
/// can call it independently without sharing mutable state.
fn load_manifest(project_root: &Path) -> Result<ProjectManifest, crate::CliError> {
    let manifest_path = project_root.join(crate::package_manifest::PACKAGE_IPE);
    crate::package_manifest::parse_package_manifest(&manifest_path)
}

/// Load and parse `ipe.lock` for the project, returning an empty lockfile when
/// the file does not exist (a project with no locked deps yet is valid).
fn load_lockfile(project_root: &Path) -> Lockfile {
    Lockfile::read(project_root).unwrap_or_default()
}

/// Index the lockfile by dep name for O(log n) per-item lookup.
fn lockfile_by_name(lf: &Lockfile) -> BTreeMap<&str, &crate::lockfile::LockedDep> {
    lf.packages().iter().map(|d| (d.name.as_str(), d)).collect()
}

// ── column: pinned-and-hashed ─────────────────────────────────────────────────

/// Column **pinned-and-hashed**: the lockfile entry for this dep carries a
/// non-local revision and a well-formed sha256 — the reproducibility and
/// tamper-detection anchors from ADR 0007.
///
/// - Path-escape Ipê dep → [`Cell::NotApplicable`] (no lockfile pin exists by
///   design; the path dep's integrity is the working-tree content).
/// - Native Rust crate → [`Cell::NotApplicable`] (cargo's own lock owns native
///   crate pins; `ipe.lock` does not track them).
/// - Index or git-escape Ipê dep with a lockfile entry → [`Cell::Ok`]: its
///   [`LockedOrigin`] carries a pinned rev and its sha256 is a parsed digest, so
///   a missing or malformed anchor never reaches this column.
/// - Index or git-escape Ipê dep absent from the lockfile, or locked with a path
///   origin (a `local` rev) → [`Cell::Hole`].
pub struct PinnedAndHashedColumn {
    project_root: PathBuf,
}

impl PinnedAndHashedColumn {
    #[must_use]
    pub const fn new(project_root: PathBuf) -> Self {
        Self { project_root }
    }
}

impl AspectCheck<PackageItem> for PinnedAndHashedColumn {
    fn name(&self) -> &'static str {
        "pinned-and-hashed"
    }

    fn check(&self, item: &PackageItem) -> Cell {
        // Path-escape Ipê deps have no lockfile entry by design.
        if item.is_path_escape() {
            return Cell::not_applicable(
                "a path-escape Ipê dep has no ipe.lock entry by design — no pin to assert",
            );
        }
        // Native Rust crates are locked by cargo, not ipe.lock.
        if item.kind == DepKindLabel::Native {
            return Cell::not_applicable(
                "a native Rust crate is locked by cargo, not ipe.lock — cargo owns its pin",
            );
        }

        let lf = load_lockfile(&self.project_root);
        let index = lockfile_by_name(&lf);

        let Some(locked) = index.get(item.name.as_str()) else {
            return Cell::Hole(format!(
                "`{}` is declared in [dependencies] but absent from ipe.lock — \
                 run `ipe add {}` to resolve and pin it",
                item.name, item.name,
            ));
        };

        match &locked.origin {
            LockedOrigin::Path { .. } => Cell::Hole(format!(
                "`{}` is locked with a `local` rev — a local-path dep cannot \
                 provide the immutable SHA the pinned-and-hashed guarantee requires",
                item.name,
            )),
            LockedOrigin::Index { .. } | LockedOrigin::Git { .. } => Cell::Ok,
        }
    }
}

// ── column: semver-satisfied ──────────────────────────────────────────────────

/// Column **semver-satisfied**: the locked version satisfies the manifest's
/// version requirement.
///
/// Applies only to index Ipê deps (`IpeDep::Index`). Git-escape deps carry a
/// rev pin instead of a version requirement; path-escape deps have neither; and
/// native crates hand their requirement verbatim to cargo. All three return
/// [`Cell::NotApplicable`].
pub struct SemverSatisfiedColumn {
    project_root: PathBuf,
}

impl SemverSatisfiedColumn {
    #[must_use]
    pub const fn new(project_root: PathBuf) -> Self {
        Self { project_root }
    }
}

impl AspectCheck<PackageItem> for SemverSatisfiedColumn {
    fn name(&self) -> &'static str {
        "semver-satisfied"
    }

    fn check(&self, item: &PackageItem) -> Cell {
        let Some(IpeDep::Index(req)) = &item.ipe_dep else {
            return Cell::not_applicable(
                "not an index Ipê dep — a git/path-escape dep or native crate carries no \
                 semver requirement to satisfy",
            );
        };

        let lf = load_lockfile(&self.project_root);
        let index = lockfile_by_name(&lf);

        let Some(locked) = index.get(item.name.as_str()) else {
            // Not in the lockfile yet — pinned-and-hashed already flags this.
            return Cell::not_applicable(
                "not yet in the lockfile — the pinned-and-hashed column already flags this",
            );
        };

        if req.matches(locked.version.as_semver()) {
            Cell::Ok
        } else {
            Cell::Hole(format!(
                "`{}` requires `{}` but the lockfile resolves to `{}` which does \
                 not satisfy the requirement — re-run `ipe add {}` to update the pin",
                item.name, req, locked.version, item.name,
            ))
        }
    }
}

// ── column: capability-declared ───────────────────────────────────────────────

/// Column **capability-declared**: for a native Rust crate, the manifest's
/// `[capabilities] declared` set is non-empty — the author has asserted which
/// trust axes the native code exercises.
///
/// Pure Ipê deps have their capability set inferred by the compiler, so this
/// column returns [`Cell::NotApplicable`] for them. For a native crate, an
/// empty declaration is a [`Cell::Warn`]: a native dep with no declared
/// capabilities is advisory debt (Tier-2 enforcement in `ipe package audit` is
/// the authoritative gate — this column surfaces the gap early).
pub struct CapabilityDeclaredColumn {
    project_root: PathBuf,
}

impl CapabilityDeclaredColumn {
    #[must_use]
    pub const fn new(project_root: PathBuf) -> Self {
        Self { project_root }
    }
}

impl AspectCheck<PackageItem> for CapabilityDeclaredColumn {
    fn name(&self) -> &'static str {
        "capability-declared"
    }

    fn check(&self, item: &PackageItem) -> Cell {
        if item.kind != DepKindLabel::Native {
            return Cell::not_applicable(
                "a pure Ipê dep has its capability set inferred by the compiler — no manual \
                 declaration to check",
            );
        }

        let Ok(manifest) = load_manifest(&self.project_root) else {
            return Cell::Hole(format!(
                "cannot read manifest to check capability declaration for `{}`",
                item.name,
            ));
        };

        if manifest.capabilities.is_empty() {
            Cell::Warn(format!(
                "`{}` is a native Rust crate but `[capabilities] declared` is empty — \
                 declare the capability axes the crate exercises so `ipe package audit` \
                 can enforce them",
                item.name,
            ))
        } else {
            Cell::Ok
        }
    }
}

// ── column: provenance-scanned ────────────────────────────────────────────────

/// Column **provenance-scanned**: the locked dep's cached source still hashes
/// to the sha256 recorded in `ipe.lock`, re-asserting the verify-before-trust
/// boundary from ADR 0007.
///
/// The hash check is computed once (the first call walks the cache for all
/// deps) and shared across every per-item call via [`OnceLock`], so the tree
/// is not re-walked N times.
///
/// - Path-escape Ipê dep → [`Cell::NotApplicable`] (no lockfile hash to assert).
/// - Native Rust crate → [`Cell::NotApplicable`] (cargo owns native integrity).
/// - Index / git-escape dep whose cached tree matches the lockfile pin → [`Cell::Ok`].
/// - A hash mismatch → [`Cell::Hole`].
/// - A dep not yet cached locally → [`Cell::Ok`] (the resolver re-verifies on
///   next fetch; a missing cache is not a tampering signal).
pub struct ProvenanceScannedColumn {
    project_root: PathBuf,
    /// The shared verdict of `resolve::verify_lockfile_hashes`, computed once.
    verdict: OnceLock<Result<(), String>>,
}

impl ProvenanceScannedColumn {
    #[must_use]
    pub const fn new(project_root: PathBuf) -> Self {
        Self {
            project_root,
            verdict: OnceLock::new(),
        }
    }

    /// Run (or return the cached result of) the hash re-assertion.
    fn verdict(&self) -> &Result<(), String> {
        self.verdict.get_or_init(|| {
            crate::resolve::verify_lockfile_hashes(&self.project_root).map_err(|e| e.to_string())
        })
    }
}

impl AspectCheck<PackageItem> for ProvenanceScannedColumn {
    fn name(&self) -> &'static str {
        "provenance-scanned"
    }

    fn check(&self, item: &PackageItem) -> Cell {
        // Path-escape deps have no ipe.lock hash to re-assert.
        if item.is_path_escape() {
            return Cell::not_applicable("a path-escape dep has no ipe.lock hash to re-assert");
        }
        // Native crates are owned by cargo's own integrity chain.
        if item.kind == DepKindLabel::Native {
            return Cell::not_applicable(
                "a native crate is owned by cargo's own integrity chain, not ipe.lock",
            );
        }

        let lf = load_lockfile(&self.project_root);
        let index = lockfile_by_name(&lf);

        // A dep not yet in the lockfile is flagged by pinned-and-hashed; skip here.
        if !index.contains_key(item.name.as_str()) {
            return Cell::not_applicable(
                "not yet in the lockfile — the pinned-and-hashed column already flags this",
            );
        }

        match self.verdict() {
            Ok(()) => Cell::Ok,
            Err(msg) => Cell::Hole(format!(
                "lockfile hash re-assertion failed (at least one cached dep has \
                 drifted from its pin): {msg}"
            )),
        }
    }
}

// ── column factory ────────────────────────────────────────────────────────────

/// Build the registered aspect columns for a `PackageSurface` rooted at
/// `project_root`.
#[must_use]
pub fn package_columns(project_root: PathBuf) -> Vec<Box<dyn AspectCheck<PackageItem>>> {
    vec![
        Box::new(PinnedAndHashedColumn::new(project_root.clone())),
        Box::new(SemverSatisfiedColumn::new(project_root.clone())),
        Box::new(CapabilityDeclaredColumn::new(project_root.clone())),
        Box::new(ProvenanceScannedColumn::new(project_root)),
    ]
}
