//! The consent gate for a program's compiler-derived control model.
//!
//! A program's control model — how it drives itself — is *disclosed* by the
//! shape the compiler pins for `main` (TEA / Direct; see
//! [`crate::delivery::ControlModel`]). The `acceptsControl` manifest field records
//! the models the author has reviewed and consented to expose. This gate is the
//! sibling of [`crate::native_ffi_consent::gate`] and shares its fail-closed
//! posture, but its trigger mirrors the capability `accept` axis rather than the
//! coarse crossing gates: an *empty* `acceptsControl` leaves the model unconstrained
//! (disclosed, never gated) — a plain-`Task` `direct` program is a legitimate,
//! clean package and must still certify. Once the author *opts in* by declaring a
//! non-empty `acceptsControl`, the set becomes authoritative: the actual derived
//! model MUST appear in it, or the audit rejects fail-closed. This catches the
//! drift the issue targets — a package whose entry silently changes control model
//! after its author pinned an accept-set that no longer covers it — without
//! turning every self-driving script into a refusal.
//!
//! The managed model ([`ControlModel::Tea`]) runs under the runtime's own loop,
//! with every effect flowing through a capability axis the sibling gates
//! ([`crate::web_consent`] / [`crate::native_ffi_consent`]) already guard.

use std::collections::BTreeSet;

use ipe_diagnostics::ConsentError;

use crate::CliError;
use crate::delivery::ControlModel;

/// The audit-boundary control-model consent gate.
///
/// - An *empty* `accepted` set leaves the control model unconstrained: the model
///   is disclosed but not gated, so a clean package (including a legitimate
///   self-driving `direct` script) certifies unchanged.
/// - A *non-empty* `accepted` set is authoritative — the author has opted into
///   control-model consent, so the actual `derived` model MUST appear in it. A
///   derived model absent from a non-empty `accepted` set is a fail-closed, typed
///   refusal naming the entry and the remedy: the declared acceptance no longer
///   covers the program's real control model. `accepted` is the top-level
///   package's own `acceptsControl` set — it does not compose down dependencies.
///
/// # Errors
/// [`CliError`] carrying the typed refusal (`IPE-S0004`) when the author declared
/// a non-empty `acceptsControl` that does not cover the derived control model.
pub fn gate(
    derived: ControlModel,
    accepted: &BTreeSet<ControlModel>,
    entry_module: &str,
) -> Result<(), CliError> {
    // An empty accept-set is "not using this feature" — the model is disclosed,
    // never gated, so a clean package certifies unchanged. Only an opted-in
    // (non-empty) accept-set is authoritative.
    if accepted.is_empty() || accepted.contains(&derived) {
        return Ok(());
    }
    Err(refusal(derived, entry_module))
}

/// The typed, fail-closed refusal naming the elevated control model, the entry
/// module that runs it, and the remedy.
fn refusal(derived: ControlModel, entry_module: &str) -> CliError {
    // The prose names the model by its lowercase word; the remedy names the
    // capitalised constructor the manifest `acceptsControl` list expects.
    let model = derived.word();
    let ctor = control_model_ctor(derived);
    let body = crate::text::msg::control_model_consent_refusal(&entry_module, &model, &ctor);
    CliError::consent_refused(ConsentError::ControlModelUncovered {
        body: body.to_string(),
    })
}

/// The `Ipe.Package` constructor spelling for a control model — the capitalised
/// token the manifest `acceptsControl` list uses. Kept beside the refusal so the
/// remedy names exactly what the reader must type.
const fn control_model_ctor(model: ControlModel) -> &'static str {
    match model {
        ControlModel::Tea => "Tea",
        ControlModel::Direct => "Direct",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepts(items: &[ControlModel]) -> BTreeSet<ControlModel> {
        items.iter().copied().collect()
    }

    #[test]
    fn an_empty_accept_set_leaves_every_model_unconstrained() {
        // The disclosed-not-gated default: a clean package (any model, including a
        // self-driving Direct script) certifies with no `acceptsControl`.
        gate(ControlModel::Tea, &BTreeSet::new(), "Main").expect("Tea passes with empty accept");
        gate(ControlModel::Direct, &BTreeSet::new(), "Main")
            .expect("a clean Direct script (a batch tool or a server alike) certifies with no acceptsControl");
    }

    #[test]
    fn a_nonempty_accept_omitting_the_derived_model_is_refused_naming_the_module() {
        // THE REFUSAL a control-model drift walks in on: the author opted into
        // control-model consent (a non-empty acceptsControl), but the program's
        // actual derived model is not covered — the declared acceptance is stale.
        let err = gate(
            ControlModel::Direct,
            &accepts(&[ControlModel::Tea]),
            "Dep.Runner",
        )
        .expect_err("a non-empty accept omitting the derived model is refused");
        let msg = err.to_string();
        assert!(msg.contains("IPE-S0004"), "carries the code: {msg}");
        assert!(msg.contains("direct"), "names the model: {msg}");
        assert!(msg.contains("Dep.Runner"), "names the entry module: {msg}");
        assert!(
            msg.contains("acceptsControl"),
            "names the remedy field: {msg}"
        );
    }

    #[test]
    fn a_nonempty_accept_covering_the_derived_model_proceeds() {
        gate(
            ControlModel::Direct,
            &accepts(&[ControlModel::Direct]),
            "Main",
        )
        .expect("an accept covering the derived Direct model proceeds");
        // A superset accept-set also proceeds — the derived model is present.
        gate(
            ControlModel::Tea,
            &accepts(&[ControlModel::Tea, ControlModel::Direct]),
            "Main",
        )
        .expect("a covering superset accept proceeds");
    }

    #[test]
    fn a_managed_model_omitted_from_a_nonempty_accept_is_also_refused() {
        // The rule is uniform once opted in: a non-empty acceptsControl that omits
        // the actual model is refused even for a managed model — the declared set
        // is authoritative and must cover the truth.
        let err = gate(ControlModel::Tea, &accepts(&[ControlModel::Direct]), "Main")
            .expect_err("a non-empty accept omitting Tea is refused");
        assert!(err.to_string().contains("IPE-S0004"));
    }

    #[test]
    fn the_refusal_is_a_lesson_not_a_slap() {
        let err = gate(ControlModel::Direct, &accepts(&[ControlModel::Tea]), "Main")
            .expect_err("refused")
            .to_string();
        assert!(err.len() > 40, "a refusal is a lesson: {err}");
    }
}
