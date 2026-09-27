//! The build-time app-boundary consent gate for disclosed `js-port:<axis>` web
//! capabilities.
//!
//! A browser web axis is *disclosed* by whichever module imports a reserved
//! `Ipe.Browser.<Api>` submodule (import-derived, union-folded across the whole
//! linked program — a dependency cannot hide its axis). Disclosure is not
//! consent: only the top-level application's `[capabilities] accept` set grants a
//! web axis, and the grant deliberately does NOT compose down the dependency tree.
//! A dependency reaching an axis the app has not granted is a compile error naming
//! the disclosing module — never a silent inheritance.
//!
//! This gate is the sibling of [`crate::unsafe_ack::gate`] and shares its
//! fail-closed posture: absent an explicit grant, the secure branch (refuse) is
//! the only reachable outcome, and a non-interactive build never prompts — it
//! refuses with the typed diagnostic and the remedy. Unlike `unsafe` (an author
//! exposing their own program, offered an interactive yes), an ungranted web axis
//! reached by a dependency is a supply-chain event: the only remedy is an explicit
//! reviewed manifest grant, so there is no interactive fast-path here.

use std::collections::{BTreeMap, BTreeSet};

use ipe_ir::{Capability, WebCapability};

use crate::CliError;

/// Which modules disclosed each web axis — the provenance the refusal names.
///
/// Built by scanning every module source (the app's and its dependencies') for
/// reserved `Ipe.Browser.<Api>` imports, so the map is TOTAL over the disclosing
/// modules: every disclosed axis has at least one namable importing module. An
/// axis that the inferred set carries but no source attributes is an
/// un-attributable disclosure — a fail-closed refusal (§ `gate`), never a silent
/// drop of the axis.
#[derive(Debug, Default, Clone)]
pub struct WebAxisProvenance {
    by_axis: BTreeMap<WebCapability, BTreeSet<String>>,
}

impl WebAxisProvenance {
    /// Scan `sources` (each a `(module-path, source-text)` pair spanning the app
    /// and every dependency) for reserved-`Ipe.Browser.<Api>` imports, recording
    /// the importing module path against the disclosed axis.
    #[must_use]
    pub fn from_sources<'a>(sources: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut by_axis: BTreeMap<WebCapability, BTreeSet<String>> = BTreeMap::new();
        for (module_name, src) in sources {
            for axis in browser_axes_imported_by(src) {
                by_axis
                    .entry(axis)
                    .or_default()
                    .insert(module_name.to_owned());
            }
        }
        Self { by_axis }
    }

    /// The disclosing modules for `axis`, sorted, or an empty slice-like set when
    /// no scanned source attributes it (the un-attributable case the gate refuses).
    #[must_use]
    fn discloser_of(&self, axis: WebCapability) -> Option<&BTreeSet<String>> {
        self.by_axis.get(&axis)
    }
}

/// Scan one module's source for the reserved `Ipe.Browser.<Api>` imports it names,
/// yielding the disclosed [`WebCapability`] for each.
///
/// Text-level (not a full parse), the same discipline as
/// [`crate::unsafe_ack::unsafe_modules_in_sources`]: it reads only the leading
/// `import <path>` token of each line — stable across surface syntax, and it keys
/// on the canonical reserved path via [`WebCapability::for_browser_module`], so a
/// local alias never changes the result.
fn browser_axes_imported_by(src: &str) -> BTreeSet<WebCapability> {
    let mut axes = BTreeSet::new();
    for line in src.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("import ") else {
            continue;
        };
        let Some(path) = rest.split_whitespace().next() else {
            continue;
        };
        let segments: Vec<&str> = path.split('.').collect();
        if let Some(axis) = WebCapability::for_browser_module(&segments) {
            axes.insert(axis);
        }
    }
    axes
}

/// The app-boundary web-consent gate.
///
/// - Every disclosed `js-port:<axis>` in `inferred` that is present in `granted`
///   proceeds silently.
/// - A disclosed axis absent from `granted` is a fail-closed, typed refusal naming
///   the disclosing module(s) and the remedy (add `accept = [ JsPort <Axis> ]` to
///   the app's `package.ipe`, or drop the dependency). `granted` is ONLY the
///   top-level app manifest's `accept` set — the grant does not compose.
/// - An axis disclosed but attributed to NO scanned module (un-attributable) is
///   ALSO a refusal, stating the axis cannot be attributed — never a silent drop.
///
/// # Errors
/// [`CliError`] carrying the typed refusal when any disclosed web axis is
/// ungranted or un-attributable.
pub fn gate(
    inferred: &BTreeSet<Capability>,
    granted: &BTreeSet<Capability>,
    provenance: &WebAxisProvenance,
) -> Result<(), CliError> {
    let mut ungranted: Vec<String> = Vec::new();
    for cap in inferred {
        let Capability::JsPort(axis) = cap else {
            continue;
        };
        if granted.contains(cap) {
            continue;
        }
        let wire = cap.as_str();
        match provenance.discloser_of(*axis) {
            Some(modules) => {
                let via = modules
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ");
                ungranted.push(crate::text::web_consent_disclosure(&wire, &via));
            }
            None => {
                // Fail-closed: the axis is inferred (a reachable module discloses
                // it through the link-fold) but no scanned source attributes it —
                // refuse stating exactly that, rather than dropping the axis.
                ungranted.push(crate::text::web_consent_disclosure_unattributed(&wire));
            }
        }
    }
    if ungranted.is_empty() {
        return Ok(());
    }
    Err(refusal(&ungranted))
}

/// The typed, fail-closed refusal naming each ungranted web axis, its disclosing
/// module(s), and the remedy.
fn refusal(ungranted: &[String]) -> CliError {
    let lines: Vec<String> = std::iter::once(crate::text::web_consent_header().to_owned())
        .chain(ungranted.iter().map(|item| crate::text::consent_item(item)))
        .chain(std::iter::once(
            crate::text::web_consent_remedy().to_owned(),
        ))
        .collect();
    CliError::UsageOwned(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(items: &[Capability]) -> BTreeSet<Capability> {
        items.iter().copied().collect()
    }

    const CLIPBOARD_DEP: &str =
        "module Dep.Widget exposing (w)\nimport Ipe.Browser.Clipboard as Clip\nw = 1\n";

    #[test]
    fn granted_axis_proceeds() {
        let prov = WebAxisProvenance::from_sources([("Dep.Widget", CLIPBOARD_DEP)]);
        let inferred = caps(&[Capability::JsPort(WebCapability::Clipboard)]);
        let granted = caps(&[Capability::JsPort(WebCapability::Clipboard)]);
        gate(&inferred, &granted, &prov).expect("a granted web axis proceeds");
    }

    #[test]
    fn ungranted_axis_is_refused_naming_the_module() {
        let prov = WebAxisProvenance::from_sources([("Dep.Widget", CLIPBOARD_DEP)]);
        let inferred = caps(&[Capability::JsPort(WebCapability::Clipboard)]);
        let granted = BTreeSet::new();
        let err = gate(&inferred, &granted, &prov).expect_err("an ungranted web axis is refused");
        let msg = err.to_string();
        assert!(msg.contains("IPE-S0002"), "carries the code: {msg}");
        assert!(msg.contains("js-port:clipboard"), "names the axis: {msg}");
        assert!(msg.contains("Dep.Widget"), "names the discloser: {msg}");
    }

    #[test]
    fn raw_floor_is_gated_independently_of_a_characterised_grant() {
        // A `js-port:raw` disclosure is not admitted by a `js-port:clipboard`
        // grant — the coarse-axis-as-bypass is designed out. `:raw` has no
        // characterised importing module, so it is the un-attributable refusal.
        let prov = WebAxisProvenance::from_sources([("Dep.Widget", CLIPBOARD_DEP)]);
        let inferred = caps(&[Capability::JsPort(WebCapability::Raw)]);
        let granted = caps(&[Capability::JsPort(WebCapability::Clipboard)]);
        let err = gate(&inferred, &granted, &prov)
            .expect_err("a raw port is not admitted by a clipboard grant");
        assert!(err.to_string().contains("js-port:raw"));
    }

    #[test]
    fn a_non_web_program_is_never_gated() {
        let prov = WebAxisProvenance::default();
        let inferred = caps(&[Capability::Network, Capability::Filesystem]);
        gate(&inferred, &BTreeSet::new(), &prov).expect("no web axis, no gate");
    }

    #[test]
    fn an_unattributable_disclosed_axis_fails_closed() {
        // MUST-FIX #4: an axis in the inferred set that no scanned source
        // attributes (a dep that fails standalone-lower but is reachable via the
        // link-fold) is refused stating it cannot be attributed — never dropped.
        let prov = WebAxisProvenance::default();
        let inferred = caps(&[Capability::JsPort(WebCapability::Geolocation)]);
        let err = gate(&inferred, &BTreeSet::new(), &prov)
            .expect_err("an un-attributable disclosed axis fails closed");
        let msg = err.to_string();
        assert!(msg.contains("js-port:geolocation"), "names the axis: {msg}");
        assert!(
            msg.contains("could not attribute"),
            "states unattributable: {msg}"
        );
    }
}
