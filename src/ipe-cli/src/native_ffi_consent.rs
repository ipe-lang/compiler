//! The build-time app-boundary consent gate for the disclosed `native-ffi`
//! capability — a crossing into opaque native `Rust.` code.
//!
//! A native crossing is *disclosed* by whichever module imports a generated
//! `Rust.<Crate>` foreign-interface module (import-derived, union-folded across
//! the whole linked program — a dependency cannot hide the crossing). Disclosure
//! is not consent: only the top-level application's `[capabilities] declared` set
//! grants the `native-ffi` axis, and the grant deliberately does NOT compose down
//! the dependency tree. A dependency crossing into native code the app has not
//! granted is a compile error naming the disclosing crate — never a silent
//! inheritance.
//!
//! This gate is the sibling of [`crate::web_consent::gate`] and shares its
//! fail-closed posture: absent an explicit grant, the secure branch (refuse) is
//! the only reachable outcome, and a non-interactive build never prompts — it
//! refuses with the typed diagnostic and the remedy. A native crossing reached by
//! a dependency is a supply-chain event: the only remedy is an explicit reviewed
//! manifest grant, so there is no interactive fast-path here.
//!
//! The `native-ffi` axis is the compiler-owned coarse disclosure of an opaque
//! native boundary (`Capability::NativeFfi`) — the lowerer inserts it on any
//! `Rust.` crossing, whatever the crate's true OS-resource effects, because those
//! effects are not visible to Ipê inference. The runtime capability jail contains
//! those effects (an undeclared syscall fails closed at the OS boundary); this
//! gate is the *consent* half — the app must have granted the crossing before it
//! is admitted. One capability vocabulary: the grant is spelled `native-ffi` in
//! the SAME `[capabilities]` set every other axis uses (the single wire spelling
//! is [`ipe_ir::Capability::as_str`]), never a parallel one.

use std::collections::{BTreeMap, BTreeSet};

use ipe_diagnostics::ConsentError;
use ipe_ir::Capability;

use crate::CliError;

/// Which modules disclosed the native crossing, keyed on the bound crate they
/// cross into — the provenance the refusal names.
///
/// Built by scanning every module source (the app's and its dependencies') for
/// generated `Rust.<Crate>` foreign-interface imports, so the map is TOTAL over
/// the disclosing modules: every disclosed crossing has at least one namable
/// importing module AND the crate it crosses into. A `native-ffi` disclosure that
/// the inferred set carries but no source attributes is an un-attributable
/// crossing — a fail-closed refusal (§ `gate`), never a silent drop.
#[derive(Debug, Default, Clone)]
pub struct NativeCrossingProvenance {
    /// Bound crate name (the `<Crate>` of `Rust.<Crate>`) → the module paths that
    /// import it.
    by_crate: BTreeMap<String, BTreeSet<String>>,
}

impl NativeCrossingProvenance {
    /// Scan `sources` (each a `(module-path, source-text)` pair spanning the app
    /// and every dependency) for `Rust.<Crate>` foreign-interface imports,
    /// recording the importing module path against the crate it crosses into.
    #[must_use]
    pub fn from_sources<'a>(sources: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut by_crate: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (module_name, src) in sources {
            for krate in rust_crates_imported_by(src) {
                by_crate
                    .entry(krate)
                    .or_default()
                    .insert(module_name.to_owned());
            }
        }
        Self { by_crate }
    }

    /// Whether any module discloses a native crossing at all — the short-circuit
    /// the gate uses to stay a no-op for a pure program.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_crate.is_empty()
    }

    /// Every `crate → disclosing modules` pair, sorted, for the refusal body.
    fn crossings(&self) -> impl Iterator<Item = (&String, &BTreeSet<String>)> {
        self.by_crate.iter()
    }
}

/// Scan one module's source for the `Rust.<Crate>` foreign-interface imports it
/// names, yielding the bound crate segment for each.
///
/// Text-level (not a full parse), the same discipline as
/// [`crate::web_consent`]'s browser-axis scan: it reads only the leading
/// `import <path>` token of each line — stable across surface syntax. The crate
/// is the second dotted segment of a `Rust.<Crate>` path; `Rust.Ffi` (the
/// author-asserted raw-signature forwarder module) is deliberately EXCLUDED — its
/// crossing discloses `ffi-raw` on top of `native-ffi` and is gated on the same
/// `native-ffi` grant through the union-folded inferred set, but it names no
/// registry crate to attribute, so it is not a per-crate provenance row.
fn rust_crates_imported_by(src: &str) -> BTreeSet<String> {
    let mut crates = BTreeSet::new();
    for line in src.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("import ") else {
            continue;
        };
        let Some(path) = rest.split_whitespace().next() else {
            continue;
        };
        let mut segments = path.split('.');
        if segments.next() != Some("Rust") {
            continue;
        }
        let Some(krate) = segments.next() else {
            continue;
        };
        // `Rust.Ffi` is the raw-assertion forwarder, not a bound registry crate.
        if krate == "Ffi" {
            continue;
        }
        crates.insert(krate.to_owned());
    }
    crates
}

/// The app-boundary native-crossing consent gate.
///
/// - When the inferred set carries no `native-ffi` axis, the program crosses into
///   no native code and the gate is a no-op.
/// - A disclosed `native-ffi` axis present in `granted` proceeds silently.
/// - A disclosed `native-ffi` axis absent from `granted` is a fail-closed, typed
///   refusal naming the disclosing crate(s) and the remedy (add `native-ffi` to
///   the app's `[capabilities] declared` set, or drop the dependency). `granted`
///   is ONLY the top-level app manifest's set — the grant does not compose.
/// - A `native-ffi` axis inferred but attributed to NO scanned module
///   (un-attributable) is ALSO a refusal, stating the crossing cannot be
///   attributed — never a silent drop.
///
/// # Errors
/// [`CliError`] carrying the typed refusal when the disclosed `native-ffi`
/// crossing is ungranted or un-attributable.
pub fn gate(
    inferred: &BTreeSet<Capability>,
    granted: &BTreeSet<Capability>,
    provenance: &NativeCrossingProvenance,
) -> Result<(), CliError> {
    // The `native-ffi` axis is the coarse disclosure the lowerer inserts on any
    // `Rust.` crossing; `ffi-raw` (an author-asserted signature) always rides
    // alongside it, so gating on `native-ffi` covers both crossing kinds.
    if !inferred.contains(&Capability::NativeFfi) {
        return Ok(());
    }
    if granted.contains(&Capability::NativeFfi) {
        return Ok(());
    }

    let mut disclosures: Vec<crate::text::Message> = Vec::new();
    for (krate, modules) in provenance.crossings() {
        let via = modules
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        disclosures.push(crate::text::native_ffi_crossing(&krate, &via));
    }
    if disclosures.is_empty() {
        // Fail-closed: the axis is inferred (a reachable module crosses into
        // native code through the link-fold) but no scanned source attributes it
        // to a crate — refuse stating exactly that, rather than dropping the axis.
        disclosures.push(crate::text::msg::native_ffi_crossing_unattributed());
    }
    Err(refusal(&disclosures))
}

/// The typed, fail-closed refusal naming each ungranted native crossing, its
/// disclosing crate/module(s), and the remedy.
fn refusal(disclosures: &[crate::text::Message]) -> CliError {
    let body = crate::text::Message::lines(
        disclosures
            .iter()
            .map(|item| crate::text::msg::consent_item(item))
            .chain(std::iter::once(
                crate::text::msg::native_ffi_consent_remedy(),
            )),
    );
    CliError::consent_refused(ConsentError::NativeCrossingUngranted {
        body: body.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(items: &[Capability]) -> BTreeSet<Capability> {
        items.iter().copied().collect()
    }

    const CSUM_DEP: &str = "module Dep.Widget exposing (w)\nimport Rust.Csum as Csum\nw = 1\n";

    #[test]
    fn a_pure_program_is_never_gated() {
        // No `native-ffi` inferred → the gate is a no-op even with an empty grant.
        let prov = NativeCrossingProvenance::default();
        let inferred = caps(&[Capability::Network, Capability::Filesystem]);
        gate(&inferred, &BTreeSet::new(), &prov).expect("no native crossing, no gate");
    }

    /// A hostile discloser name cannot carry an escape sequence or open a line.
    #[test]
    fn a_hostile_discloser_name_renders_inert() {
        let module = "Dep\u{1b}]0;title\u{7}\n\u{1b}[2Kerror: forged";
        let prov = NativeCrossingProvenance::from_sources([(module, CSUM_DEP)]);
        let inferred = caps(&[Capability::NativeFfi]);
        let err =
            gate(&inferred, &BTreeSet::new(), &prov).expect_err("an ungranted crossing is refused");
        let msg = err.to_string();
        assert!(!msg.contains('\u{1b}'), "{msg:?}");
        assert!(!msg.contains('\u{7}'), "{msg:?}");
        assert!(!msg.lines().any(|l| l.starts_with("error:")), "{msg:?}");
    }

    #[test]
    fn a_granted_crossing_proceeds() {
        let prov = NativeCrossingProvenance::from_sources([("Dep.Widget", CSUM_DEP)]);
        let inferred = caps(&[Capability::NativeFfi]);
        let granted = caps(&[Capability::NativeFfi]);
        gate(&inferred, &granted, &prov).expect("a granted native crossing proceeds");
    }

    #[test]
    fn an_ungranted_crossing_is_refused_naming_the_crate() {
        let prov = NativeCrossingProvenance::from_sources([("Dep.Widget", CSUM_DEP)]);
        let inferred = caps(&[Capability::NativeFfi]);
        let granted = BTreeSet::new();
        let err =
            gate(&inferred, &granted, &prov).expect_err("an ungranted native crossing is refused");
        let msg = err.to_string();
        assert!(msg.contains("IPE-S0003"), "carries the code: {msg}");
        assert!(msg.contains("Rust.Csum"), "names the crate: {msg}");
        assert!(msg.contains("Dep.Widget"), "names the discloser: {msg}");
        assert!(
            msg.contains("`NativeFfi` to `declares = [ … ]` in"),
            "the remedy names the manifest field the gate reads: {msg}"
        );
    }

    #[test]
    fn a_dependency_grant_does_not_compose() {
        // Two crates cross; the app granted `native-ffi` for neither — both are
        // named. (The grant is app-only; there is no per-dep self-authorisation.)
        let prov = NativeCrossingProvenance::from_sources([
            (
                "Dep.A",
                "module Dep.A exposing (a)\nimport Rust.Csum as C\na = 1\n",
            ),
            (
                "Dep.B",
                "module Dep.B exposing (b)\nimport Rust.Firestore as F\nb = 1\n",
            ),
        ]);
        let inferred = caps(&[Capability::NativeFfi]);
        let err =
            gate(&inferred, &BTreeSet::new(), &prov).expect_err("an ungranted crossing is refused");
        let msg = err.to_string();
        assert!(msg.contains("Rust.Csum"), "names crate A: {msg}");
        assert!(msg.contains("Rust.Firestore"), "names crate B: {msg}");
    }

    #[test]
    fn an_unattributable_crossing_fails_closed() {
        // The axis is inferred (a reachable module crosses via the link-fold) but
        // no scanned source attributes it — refused as un-attributable, never
        // dropped. Mirrors `web_consent`'s un-attributable case.
        let prov = NativeCrossingProvenance::default();
        let inferred = caps(&[Capability::NativeFfi]);
        let err = gate(&inferred, &BTreeSet::new(), &prov)
            .expect_err("an un-attributable native crossing fails closed");
        let msg = err.to_string();
        assert!(msg.contains("IPE-S0003"), "carries the code: {msg}");
        assert!(
            msg.contains("could not attribute"),
            "states unattributable: {msg}"
        );
    }

    #[test]
    fn ffi_raw_rides_the_same_grant_but_names_no_crate() {
        // A `Rust.Ffi` raw-assertion forwarder is not a registry crate row, so it
        // discloses no per-crate provenance; the crossing is still gated on the
        // `native-ffi` axis through the inferred set (here un-attributable).
        let prov = NativeCrossingProvenance::from_sources([(
            "Main",
            "module Main exposing (main)\nimport Rust.Ffi\nmain = 1\n",
        )]);
        assert!(
            prov.is_empty(),
            "`Rust.Ffi` is not a per-crate crossing row"
        );
        let inferred = caps(&[Capability::NativeFfi, Capability::FfiRaw]);
        gate(&inferred, &caps(&[Capability::NativeFfi]), &prov)
            .expect("a granted native-ffi admits the raw-assertion crossing too");
    }

    #[test]
    fn a_non_rust_import_is_not_a_crossing() {
        // A plain stdlib import (`Ipe.Http`) discloses no native crossing.
        let prov = NativeCrossingProvenance::from_sources([(
            "Main",
            "module Main exposing (main)\nimport Ipe.Http\nmain = 1\n",
        )]);
        assert!(prov.is_empty(), "a plain stdlib import is not a crossing");
    }
}
