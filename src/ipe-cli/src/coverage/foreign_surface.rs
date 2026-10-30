//! The foreign-binding surface: one row per capability axis, judged on five
//! security-weighted columns.
//!
//! "Foreign binding" means any Ipê program step that crosses a trust boundary:
//! a JS-port (inbound untrusted browser data decoded through a seal gate), a
//! native FFI crossing (`NativeFfi` / `FfiRaw`), or an OS-resource capability
//! (`Network`, `Filesystem`, …) that a stdlib kernel exercises under a declared
//! and consent-gated capability grant.
//!
//! The [`Capability`] vocabulary is the closed, compiler-owned SSOT for the
//! foreign-binding surface. One row per axis:
//!
//! - **capability-declared** — the axis appears in [`Capability::ALL`] with a
//!   stable wire name; absence here is a gap in the closed vocabulary.
//! - **boundary-discipline-wired** — the enforcement mechanism exists in the
//!   source tree: a seal-decode gate (`seal_boundary_check` / `seal_decode`) for
//!   JS-port crossings, a jail/sandbox invocation for OS-confinement axes, or a
//!   `StdlibKernel::capability` tag for axes exercised through stdlib kernels.
//! - **within-grant** — the capability passes through a consent gate before a
//!   program can exercise it (the `must_refuse`/`unenforceable` path or, for
//!   axes with no OS isolation surface, a structural non-enforceability
//!   declaration that is never silently skipped).
//! - **documented** — the axis has a prose entry in `docs/reference/capabilities.md`
//!   (or the capability-vocabulary source for axes whose reference IS the code).
//! - **refusal-tested** — a standing test drives the boundary's REJECT path.
//!   This is the security-critical column: a wired gate with no test that proves
//!   it rejects is one edit away from vanishing unnoticed. The detector accepts
//!   BOTH a quoted wire literal (`"js-port:clipboard"`, `"seal decode rejected"`)
//!   AND a typed error-variant assertion (`SealDecodeError::`, `must_refuse`,
//!   `UnknownCapability`) in a test context — it does not under-detect by
//!   restricting to wire strings only.

use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::sync::{Arc, OnceLock};

use ipe_kernels::{Capability, StdlibKernel};

use crate::coverage::contract::{AspectCheck, Cell, Surface};
use crate::coverage::source_tree::{TreeRefusal, for_each_source};

/// One item of the foreign surface: a single capability axis from the closed
/// [`Capability::ALL`] vocabulary, tagged with what boundary class it belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForeignItem {
    /// The capability this row covers.
    pub capability: Capability,
    /// Which broad boundary class the capability belongs to — drives which
    /// discipline check is appropriate.
    pub boundary_class: BoundaryClass,
}

/// The broad enforcement class of a capability axis.
///
/// Different axes have different enforcement mechanisms; this tag lets each
/// column select the right check without re-deriving the class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundaryClass {
    /// A JS-port axis: inbound data is attacker-controlled browser JS and must
    /// pass the fail-closed seal decode gate before reaching any handler.
    JsPort,
    /// A native-FFI disclosure: the program crosses into Rust code opaque to
    /// capability inference. The jail mechanism is the enforcement surface.
    NativeFfi,
    /// An OS-resource axis with a stdlib kernel tag and a runtime jail surface
    /// (`Network`, `Filesystem`, `Database`, `Env`, `Subprocess`).
    OsResource,
    /// An axis with no server-side OS isolation surface: `Clock`, `Random`,
    /// `Unsafe`, `CustomElement`. Structurally non-enforceable; its presence is
    /// a disclosure, not a confinement axis.
    Disclosure,
}

impl ForeignItem {
    /// Determine the boundary class for a capability axis.
    #[must_use]
    pub const fn class_of(cap: Capability) -> BoundaryClass {
        match cap {
            Capability::JsPort(_) => BoundaryClass::JsPort,
            Capability::NativeFfi | Capability::FfiRaw => BoundaryClass::NativeFfi,
            Capability::Network
            | Capability::Filesystem
            | Capability::Database
            | Capability::Env
            | Capability::Subprocess => BoundaryClass::OsResource,
            Capability::Clock
            | Capability::Random
            | Capability::Unsafe
            | Capability::CustomElement => BoundaryClass::Disclosure,
        }
    }
}

/// The foreign-binding surface.
///
/// One row per [`Capability`] axis in the closed vocabulary. Zero-sized: the item
/// list is derived from the compiled-in constant [`Capability::ALL`] on each call
/// to [`Surface::all`].
#[derive(Clone, Copy, Debug, Default)]
pub struct ForeignSurface;

impl Surface for ForeignSurface {
    type Item = ForeignItem;

    fn name(&self) -> &'static str {
        "foreign"
    }

    fn all(&self) -> Result<Vec<ForeignItem>, crate::coverage::error::CoverageError> {
        Ok(Capability::ALL
            .iter()
            .map(|&cap| ForeignItem {
                capability: cap,
                boundary_class: ForeignItem::class_of(cap),
            })
            .collect())
    }

    fn label(item: &ForeignItem) -> String {
        item.capability.as_str().to_owned()
    }
}

// ── column: capability-declared ───────────────────────────────────────────────

/// Column **capability-declared**: every axis in [`Capability::ALL`] has a
/// stable wire name and round-trips through [`Capability::from_str`].
///
/// The surface iterates `Capability::ALL`, so the only way this column fires is
/// if `as_str` returns an empty string or `from_str` fails the round-trip — a
/// structural drift between the wire name and the parser that would let a
/// manifest spell a capability the parser cannot recover.
pub struct CapabilityDeclaredColumn;

impl AspectCheck<ForeignItem> for CapabilityDeclaredColumn {
    fn name(&self) -> &'static str {
        "capability-declared"
    }

    fn check(&self, item: &ForeignItem) -> Cell {
        let wire = item.capability.as_str();
        if wire.is_empty() {
            return Cell::Hole(format!(
                "capability {:?} has an empty wire name — `as_str` must return a \
                 non-empty string",
                item.capability
            ));
        }
        match Capability::from_str(wire) {
            Ok(rt) if rt == item.capability => Cell::Ok,
            Ok(rt) => Cell::Hole(format!(
                "wire name {wire:?} round-trips to a DIFFERENT capability ({rt:?}) — \
                 `as_str` / `from_str` are not mutual inverses for {:?}",
                item.capability
            )),
            Err(_) => Cell::Hole(format!(
                "wire name {wire:?} is not recoverable by `from_str` — the \
                 capability parser is missing an arm for {:?}",
                item.capability
            )),
        }
    }
}

// ── column: boundary-discipline-wired ─────────────────────────────────────────

/// Column **boundary-discipline-wired**: the enforcement mechanism for each
/// capability axis is present in the source tree.
///
/// - **`JsPort`** axes: the seal-decode gate (`seal_boundary_check` /
///   `seal_decode`) exists in the runtime source. A JS-port wired with no seal
///   decode gate means attacker-controlled input can reach handlers unchecked.
/// - **`NativeFfi`** axes: the sandbox jail invocation (`run_in_bwrap_jail` or
///   platform equivalent) exists. An FFI crossing with no jail path means
///   native code runs with the caller's full ambient authority.
/// - **`OsResource`** axes: `StdlibKernel::capability` tags at least one kernel
///   with this axis, so the capability inference is not dead code.
/// - **`Disclosure`** axes: `NotApplicable` — these have no OS isolation surface
///   to wire; their discipline is the presence of the disclosure itself.
pub struct BoundaryDisciplineWiredColumn {
    /// Lazily loaded scan of the source tree for boundary mechanism markers.
    inner: BoundaryWireScan,
}

impl BoundaryDisciplineWiredColumn {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: BoundaryWireScan::load(),
        }
    }
}

impl Default for BoundaryDisciplineWiredColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl AspectCheck<ForeignItem> for BoundaryDisciplineWiredColumn {
    fn name(&self) -> &'static str {
        "boundary-discipline-wired"
    }

    fn check(&self, item: &ForeignItem) -> Cell {
        match item.boundary_class {
            BoundaryClass::JsPort => match &self.inner.seal_gate_present {
                Ok(true) => Cell::Ok,
                Ok(false) => Cell::Hole(
                    "no `seal_boundary_check` or `seal_decode` call found in the \
                     runtime source — the JS-port inbound gate is missing"
                        .to_owned(),
                ),
                Err(refusal) => unscanned("the JS-port inbound gate", refusal),
            },
            BoundaryClass::NativeFfi => match &self.inner.jail_invocation_present {
                Ok(true) => Cell::Ok,
                Ok(false) => Cell::Hole(
                    "no `run_in_bwrap_jail` or `build_jail` invocation found in \
                     the sandbox source — the native-FFI jail path is missing"
                        .to_owned(),
                ),
                Err(refusal) => unscanned("the native-FFI jail path", refusal),
            },
            BoundaryClass::OsResource => {
                // At least one stdlib kernel must be tagged with this capability
                // for the inference to be live code rather than dead tables.
                let cap = item.capability;
                let tagged = StdlibKernel::ALL
                    .iter()
                    .any(|k| k.def().capability == Some(cap));
                if tagged {
                    Cell::Ok
                } else {
                    Cell::Hole(format!(
                        "no `StdlibKernel` is tagged `capability = {cap:?}` — the \
                         capability-inference table has no entry for this OS-resource \
                         axis"
                    ))
                }
            }
            BoundaryClass::Disclosure => {
                // Disclosure axes have no OS isolation surface; the discipline IS
                // the declared-and-documented presence, verified by other columns.
                Cell::not_applicable(
                    "a disclosure axis has no OS-resource isolation surface — its discipline \
                     is declared-and-documented presence, verified by other columns",
                )
            }
        }
    }
}

/// Lazily-scanned source markers for the `boundary-discipline-wired` column.
#[derive(Clone, Debug)]
struct BoundaryWireScan {
    /// Whether `seal_boundary_check` or `seal_decode` appears in the runtime
    /// source tree — the JS-port inbound fail-closed gate.
    seal_gate_present: Marker,
    /// Whether a jail invocation (`run_in_bwrap_jail`, `exec_in_run_jail`,
    /// `build_windows_jailed`, `run_jail_macos`) appears in the sandbox source.
    jail_invocation_present: Marker,
}

impl BoundaryWireScan {
    fn load() -> Self {
        static SCAN: OnceLock<BoundaryWireScan> = OnceLock::new();
        SCAN.get_or_init(Self::compute).clone()
    }

    fn compute() -> Self {
        let runtime_src = workspace_path("src/runtime/rust/src");
        let sandbox_src = workspace_path("src/compiler/sandbox/src");

        let seal_gate_present =
            source_contains(&runtime_src, &["seal_boundary_check", "seal_decode"]);

        let jail_invocation_present = source_contains(
            &sandbox_src,
            &[
                "run_in_bwrap_jail",
                "exec_in_run_jail",
                "build_windows_jailed",
                "run_jail_macos",
            ],
        );

        Self {
            seal_gate_present,
            jail_invocation_present,
        }
    }
}

// ── column: within-grant ──────────────────────────────────────────────────────

/// Column **within-grant**: the capability must pass a consent gate before any
/// program can exercise it.
///
/// - **`JsPort`** / **`NativeFfi`** / **`OsResource`** axes: `ScanOutcome::must_refuse`
///   or the `unenforceable` path is present in the FFI driver, confirming the
///   consent-gate code path exists. The column scans the ffi/src tree for the
///   `must_refuse` marker — a necessary-but-not-sufficient check (the full
///   soundness review is the guardian's domain).
/// - **`Disclosure`** axes: these have no OS isolation surface that a grant gate
///   could confine. Their "grant" is implicit in the language semantics
///   (clock/random are always available; unsafe/custom-element are declared-trust
///   disclosures). `NotApplicable` — not missing, by design.
pub struct WithinGrantColumn {
    grant_gate_present: Marker,
}

impl WithinGrantColumn {
    #[must_use]
    pub fn new() -> Self {
        Self {
            grant_gate_present: scan_grant_gate_present(),
        }
    }
}

impl Default for WithinGrantColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl AspectCheck<ForeignItem> for WithinGrantColumn {
    fn name(&self) -> &'static str {
        "within-grant"
    }

    fn check(&self, item: &ForeignItem) -> Cell {
        match item.boundary_class {
            BoundaryClass::JsPort | BoundaryClass::NativeFfi | BoundaryClass::OsResource => {
                match &self.grant_gate_present {
                    Ok(true) => Cell::Ok,
                    Ok(false) => Cell::Hole(format!(
                        "no `must_refuse` or `unenforceable` consent-gate invocation \
                         found in src/compiler/ffi — the grant path for {:?} is not \
                         wired",
                        item.capability
                    )),
                    Err(refusal) => unscanned("the consent-gate grant path", refusal),
                }
            }
            BoundaryClass::Disclosure => Cell::not_applicable(
                "a disclosure axis has no consent-gate grant path to wire — its enforcement is \
                 disclosure itself, not an OS grant gate",
            ),
        }
    }
}

fn scan_grant_gate_present() -> Marker {
    static RESULT: OnceLock<Marker> = OnceLock::new();
    RESULT
        .get_or_init(|| {
            let ffi_src = workspace_path("src/compiler/ffi/src");
            source_contains(&ffi_src, &["must_refuse", "unenforceable"])
        })
        .clone()
}

// ── column: documented ────────────────────────────────────────────────────────

/// Column **documented**: each capability axis has a prose entry in the
/// capability-reference doc (`docs/reference/capabilities.md`), located by its
/// wire name.
///
/// The reference is the operator-facing guide to what each axis means. An axis
/// absent from the reference is undisclosed to operators and package consumers —
/// they cannot make an informed grant decision.
pub struct ForeignDocumentedColumn {
    reference: Option<String>,
}

impl ForeignDocumentedColumn {
    #[must_use]
    pub fn new() -> Self {
        Self {
            reference: load_capability_reference(),
        }
    }
}

impl Default for ForeignDocumentedColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl AspectCheck<ForeignItem> for ForeignDocumentedColumn {
    fn name(&self) -> &'static str {
        "documented"
    }

    fn check(&self, item: &ForeignItem) -> Cell {
        let wire = item.capability.as_str();
        let Some(reference) = &self.reference else {
            // The reference file is absent: every axis is undocumented.
            // This is a real gap (not advisory) — an absent reference file means
            // operators cannot make an informed grant decision for any axis.
            return Cell::Hole(format!(
                "docs/reference/capabilities.md does not exist; `{wire}` cannot \
                 be confirmed documented — generate the reference file"
            ));
        };
        // Match the wire name inside backticks or as a section anchor so
        // `js-port:clipboard` and `network` both find their entry.
        let token = format!("`{wire}`");
        let anchor = format!("## {wire}");
        if reference.contains(&token) || reference.contains(&anchor) {
            Cell::Ok
        } else {
            Cell::Hole(format!(
                "capability `{wire}` is absent from docs/reference/capabilities.md — \
                 add a prose entry so operators can make an informed grant decision"
            ))
        }
    }
}

fn load_capability_reference() -> Option<String> {
    static REFERENCE: OnceLock<Option<String>> = OnceLock::new();
    REFERENCE
        .get_or_init(|| {
            let path = workspace_path("docs/reference/capabilities.md");
            std::fs::read_to_string(path).ok()
        })
        .clone()
}

// ── column: refusal-tested ────────────────────────────────────────────────────

/// Column **refusal-tested**: a standing test drives the REJECT path of the
/// boundary for each capability axis. This is the security-critical column.
///
/// A wired gate with no test that proves it rejects is one edit away from
/// vanishing unnoticed. The detector is deliberately broad — it recognises BOTH:
///
/// 1. A quoted wire literal in a test context: `"seal decode rejected"`,
///    `"js-port:clipboard"`, `"must_refuse"`, `"native-ffi"`.
/// 2. A typed error-variant assertion in a test: `SealDecodeError::`,
///    `UnknownCapability`, `must_refuse`, `Err(Diagnostic::WireMalformed`.
///
/// This dual recognition closes the under-detection a wire-string-only scan
/// would have: a test that asserts `matches!(result, Err(SealDecodeError::TooLarge
/// { .. }))` proves the seal gate rejects without spelling the wire literal.
///
/// Per boundary class:
///
/// - **`JsPort`**: tests covering `SealDecodeError::`, `seal decode rejected`, or
///   `seal_boundary_check` in a failing assertion must exist in the runtime test
///   tree.
/// - **`NativeFfi`**: tests covering `must_refuse` or `UnknownCapability` in the
///   FFI or capability test trees.
/// - **`OsResource`**: the capability wire name (`"network"`, `"filesystem"`, …)
///   appears in a test assertion in the capability or sandbox test trees, OR
///   `must_refuse` / `unenforceable` covers its rejection.
/// - **`Disclosure`**: `NotApplicable` — no OS-level rejection path to test; the
///   round-trip test (`from_str_rejects_an_unknown_name`) guards the vocabulary
///   boundary for all axes including disclosures.
pub struct RefusalTestedColumn {
    inner: RefusalScan,
}

impl RefusalTestedColumn {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RefusalScan::load(),
        }
    }
}

impl Default for RefusalTestedColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl AspectCheck<ForeignItem> for RefusalTestedColumn {
    fn name(&self) -> &'static str {
        "refusal-tested"
    }

    fn check(&self, item: &ForeignItem) -> Cell {
        match item.boundary_class {
            BoundaryClass::JsPort => match &self.inner.seal_reject_tested {
                Ok(true) => Cell::Ok,
                Ok(false) => Cell::Hole(
                    "no test drives the seal-decode REJECT path \
                     (`SealDecodeError::` / `\"seal decode rejected\"` in a test \
                     block) — the JS-port inbound gate is asserted wired but not \
                     proven to reject"
                        .to_owned(),
                ),
                Err(refusal) => unscanned("a seal-decode refusal test", refusal),
            },
            BoundaryClass::NativeFfi => match &self.inner.ffi_reject_tested {
                Ok(true) => Cell::Ok,
                Ok(false) => Cell::Hole(
                    "no test drives the native-FFI refuse path \
                     (`must_refuse` / `UnknownCapability` assertion in a test) — \
                     the FFI boundary gate is asserted wired but not proven to reject"
                        .to_owned(),
                ),
                Err(refusal) => unscanned("a native-FFI refusal test", refusal),
            },
            BoundaryClass::OsResource => {
                let wire = item.capability.as_str();
                match &self.inner.os_resource_reject_wires {
                    Ok(wires) if wires.iter().any(|w| w == wire) => Cell::Ok,
                    Ok(_) => Cell::Hole(format!(
                        "no test drives the rejection path for OS-resource capability \
                         `{wire}` — add a test that proves an un-granted or \
                         unenforceable `{wire}` capability is refused"
                    )),
                    Err(refusal) => unscanned(&format!("a `{wire}` refusal test"), refusal),
                }
            }
            BoundaryClass::Disclosure => {
                // Disclosure axes have no rejection path to test at the OS
                // boundary; the vocabulary round-trip test covers the parser.
                Cell::not_applicable(
                    "a disclosure axis has no OS-boundary rejection path to test — the \
                     vocabulary round-trip test covers its parser",
                )
            }
        }
    }
}

/// Lazily-scanned markers for the `refusal-tested` column.
#[derive(Clone, Debug)]
struct RefusalScan {
    /// Whether a test in the runtime tree asserts a seal-decode rejection via
    /// a typed variant (`SealDecodeError::`) OR a wire literal
    /// (`"seal decode rejected"`).
    seal_reject_tested: Marker,
    /// Whether a test in the FFI or capability trees asserts a native-FFI
    /// rejection (`must_refuse`, `UnknownCapability`, or
    /// `Err(Diagnostic::WireMalformed`).
    ffi_reject_tested: Marker,
    /// Every OS-resource wire name found in a reject-assertion context in the
    /// capability or sandbox test trees.
    os_resource_reject_wires: Result<Vec<String>, Arc<TreeRefusal>>,
}

impl RefusalScan {
    fn load() -> Self {
        static SCAN: OnceLock<RefusalScan> = OnceLock::new();
        SCAN.get_or_init(Self::compute).clone()
    }

    fn compute() -> Self {
        let runtime_tests = workspace_path("src/runtime/rust");
        let ffi_src = workspace_path("src/compiler/ffi/src");
        let kernels_tests = workspace_path("src/compiler/kernels/tests");
        let sandbox_src = workspace_path("src/compiler/sandbox/src");
        let sandbox_tests = workspace_path("src/compiler/sandbox/tests");
        let cli_tests = workspace_path("src/ipe-cli/tests");

        // JsPort: typed error variant OR wire string in a test block.
        let seal_reject_tested = either(
            test_source_contains(
                &runtime_tests,
                &["SealDecodeError::", "seal decode rejected"],
            ),
            test_source_contains(&cli_tests, &["SealDecodeError::"]),
        );

        // NativeFfi: must_refuse / UnknownCapability / WireMalformed in a test.
        let ffi_reject_tested = either(
            test_source_contains(
                &ffi_src,
                &["must_refuse", "UnknownCapability", "WireMalformed"],
            ),
            test_source_contains(&kernels_tests, &["UnknownCapability", "from_str_rejects"]),
        );

        // OsResource: collect capability wire names that appear in a reject
        // context (must_refuse / unenforceable / UnknownCapability) in the
        // test portion of the ffi or sandbox trees.
        let os_resource_caps = [
            Capability::Network,
            Capability::Filesystem,
            Capability::Database,
            Capability::Env,
            Capability::Subprocess,
        ];
        let reject_roots = [
            ffi_src.as_path(),
            kernels_tests.as_path(),
            sandbox_src.as_path(),
            sandbox_tests.as_path(),
            cli_tests.as_path(),
        ];
        // A test that mentions BOTH the wire name and a reject marker proves the
        // rejection path is exercised for that specific axis.
        let os_resource_reject_wires = reject_context_texts(&reject_roots).map(|texts| {
            os_resource_caps
                .iter()
                .map(|cap| cap.as_str())
                .filter(|wire| texts.iter().any(|src| src.contains(wire)))
                .map(str::to_owned)
                .collect()
        });

        Self {
            seal_reject_tested,
            ffi_reject_tested,
            os_resource_reject_wires,
        }
    }
}

/// Whether a source scan found a marker, or the refusal that kept it from reading
/// every file it was asked to read.
type Marker = Result<bool, Arc<TreeRefusal>>;

/// A hole naming why `what` cannot be confirmed: the scan could not read the
/// tree whole, so the marker's absence proves nothing.
fn unscanned(what: &str, refusal: &TreeRefusal) -> Cell {
    Cell::Hole(format!("{what} cannot be confirmed: {refusal}"))
}

/// A marker found by either scan; a refusal only when neither found it.
fn either(a: Marker, b: Marker) -> Marker {
    match (a, b) {
        (Ok(true), _) | (_, Ok(true)) => Ok(true),
        (Err(refusal), _) | (_, Err(refusal)) => Err(refusal),
        (Ok(false), Ok(false)) => Ok(false),
    }
}

/// The text of every test-context `.rs` file under `roots` that carries a
/// reject marker (`must_refuse`, `unenforceable`, `UnknownCapability`,
/// `WireMalformed`, `from_str_rejects`, or `from_str_hard_rejects`).
fn reject_context_texts(roots: &[&Path]) -> Result<Vec<String>, Arc<TreeRefusal>> {
    let mut texts = Vec::new();
    for root in roots {
        for_each_source(root, panic_scan::Want::RustFiles, |_, src| {
            if src.contains("must_refuse")
                || src.contains("unenforceable")
                || src.contains("UnknownCapability")
                || src.contains("WireMalformed")
                || src.contains("from_str_rejects")
                || src.contains("from_str_hard_rejects")
            {
                texts.push(src.to_owned());
            }
        })
        .map_err(Arc::new)?;
    }
    Ok(texts)
}

/// Whether any `.rs` file under `root` (recursively) contains one of `markers`.
/// Scans ALL files — the marker may live outside a `#[test]` fn but still
/// be part of a test module (`#[cfg(test)]`).
fn source_contains(root: &Path, markers: &[&str]) -> Marker {
    any_source(root, |src| markers.iter().any(|m| src.contains(m)))
}

/// Whether any `.rs` file under `root` (recursively) contains one of `markers`
/// AND also contains `#[test]` or `#[cfg(test)]` — so the marker is in a
/// test context rather than production code.
fn test_source_contains(root: &Path, markers: &[&str]) -> Marker {
    any_source(root, |src| {
        let in_test_context = src.contains("#[test]") || src.contains("#[cfg(test)]");
        in_test_context && markers.iter().any(|m| src.contains(m))
    })
}

/// Whether `hit` holds for any `.rs` file under `root`, read whole or refused.
fn any_source(root: &Path, hit: impl Fn(&str) -> bool) -> Marker {
    let mut found = false;
    for_each_source(root, panic_scan::Want::RustFiles, |_, src| {
        found = found || hit(src);
    })
    .map_err(Arc::new)?;
    Ok(found)
}

/// Resolve a workspace-root-relative path from this crate's manifest directory.
fn workspace_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

// ── public column constructor (for matrix.rs wiring) ─────────────────────────

/// Build the registered aspect columns of the foreign surface.
///
/// All five columns run in the fast (non-E2E) path — they scan only the source
/// tree and the closed [`Capability::ALL`] constant, no program build.
#[must_use]
pub fn foreign_columns() -> Vec<Box<dyn AspectCheck<ForeignItem>>> {
    vec![
        Box::new(CapabilityDeclaredColumn),
        Box::new(BoundaryDisciplineWiredColumn::new()),
        Box::new(WithinGrantColumn::new()),
        Box::new(ForeignDocumentedColumn::new()),
        Box::new(RefusalTestedColumn::new()),
    ]
}

/// Allowlisted holes: a `(aspect, capability-wire-name, reason)` triple for
/// known structural gaps that are tracked but not yet resolved.
///
/// Each entry MUST carry a one-line structural reason. An entry that is no
/// longer reported by the matrix runner is a stale allowlist entry and must
/// be removed.
/// Every foreign-binding coverage column is green over the whole surface: the
/// `documented` axis is satisfied by `docs/reference/capabilities.md`, which
/// documents every capability axis. Add an entry here (with a structural
/// reason) only for a genuinely deferred gap, never to mask a real regression.
pub const FOREIGN_ALLOWLIST: &[(&str, &str, &str)] = &[];

#[cfg(test)]
mod tests {
    use super::*;

    /// A tree the scan cannot read whole is a refusal, never an absent marker, and
    /// a refusal survives `either` unless the other scan found the marker.
    #[test]
    fn an_unlisted_tree_is_a_refusal_never_an_absent_marker() {
        let missing = ipe_test_temp::temp_root().join(format!(
            "ipe-foreign-surface-missing-{}",
            std::process::id()
        ));
        let marker = source_contains(&missing, &["seal_decode"]);
        assert!(marker.is_err(), "{marker:?}");
        assert!(test_source_contains(&missing, &["must_refuse"]).is_err());
        assert!(reject_context_texts(&[missing.as_path()]).is_err());
        assert!(either(marker.clone(), Ok(false)).is_err());
        assert!(matches!(either(marker.clone(), Ok(true)), Ok(true)));
        let refusal = marker.expect_err("a missing tree is a refusal");
        let cell = unscanned("the JS-port inbound gate", &refusal);
        assert!(
            matches!(&cell, Cell::Hole(msg) if msg.contains("cannot be listed whole")),
            "{cell:?}"
        );
    }
}
