//! Cross-crate foreign-type nominal unification — one Ipê home per type.
//!
//! A foreign type's identity is its canonical DEFINING path (the rustdoc
//! `paths` entry, identical in every crate that can see the item). When two
//! installed member crates surface the SAME defining path under the SAME Ipê
//! name — the definer and a re-exporter — they are ONE Rust type, and must be
//! ONE Ipê nominal: the type keeps a declaration in exactly one HOME module,
//! and every other member module imports it (`import <Home> exposing (T)`),
//! so bare `T` in its signatures canonicalises to the home's nominal through
//! the ordinary dep-type injection. No checker change, no second identity
//! scheme: the Elm one-home rule applied to generated modules.
//!
//! Fail-closed guards (each skips unification, never risks a wrong collapse):
//! - a member without a defining-path identity for the name (legacy cache);
//! - two DISTINCT defining paths under one name (genuinely different types —
//!   today's distinct nominals are already correct);
//! - the defining crate resolved to different VERSIONS across the members
//!   that resolved it at all, or to none (two same-named types again —
//!   collapsing could break THE SEAL with E0308; a member with NO resolution
//!   saw the type only through the manifest-run cross-crate index and is not
//!   evidence of a second type);
//! - an import edge that would close a CYCLE among interface modules (the
//!   module graph must stay compilable; the skipped name keeps its split
//!   nominals and is reported).

use std::collections::{BTreeMap, BTreeSet};

use crate::driver::InstalledCrate;

/// One unification decision, reported for the coverage/driver layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnifiedType {
    /// The Ipê-visible opaque type name.
    pub name: String,
    /// The defining-path identity all members agreed on.
    pub defid: String,
    /// The one module that now declares the type.
    pub home_module: String,
    /// The modules whose declaration was demoted to an import.
    pub demoted_modules: Vec<String>,
}

/// A name surfaced by ≥2 members that could NOT be unified, with the reason —
/// the over-drop ledger for identity decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedUnification {
    /// The Ipê-visible opaque type name.
    pub name: String,
    /// Why the nominals stay split.
    pub reason: String,
}

/// The unification outcome.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnifyReport {
    /// Types collapsed to one home.
    pub unified: Vec<UnifiedType>,
    /// Multi-member names left split, with reasons.
    pub skipped: Vec<SkippedUnification>,
}

/// `true` when adding `from → to` to `edges` would close a cycle (i.e. `from`
/// is already reachable from `to`).
fn would_cycle(edges: &BTreeMap<String, BTreeSet<String>>, from: &str, to: &str) -> bool {
    if from == to {
        return true;
    }
    let mut stack = vec![to.to_owned()];
    let mut seen: BTreeSet<String> = BTreeSet::new();
    while let Some(m) = stack.pop() {
        if m == from {
            return true;
        }
        if !seen.insert(m.clone()) {
            continue;
        }
        if let Some(nexts) = edges.get(&m) {
            stack.extend(nexts.iter().cloned());
        }
    }
    false
}

/// One member module surfacing a candidate name, snapshotted for decisions.
struct Surfacer {
    idx: usize,
    module: String,
    rendered_path: String,
    defid: Option<String>,
}

/// The apply-plan for one unifiable name.
struct Decision {
    defid: String,
    home_module: String,
    /// `(catalog index, module name)` of every demoted member.
    demoted: Vec<(usize, String)>,
}

/// Snapshot the members surfacing `name`.
fn surfacers_of(catalog: &[InstalledCrate], name: &str) -> Vec<Surfacer> {
    catalog
        .iter()
        .enumerate()
        .filter_map(|(idx, c)| {
            c.opaque_types.get(name).map(|path| Surfacer {
                idx,
                module: c.module_name.clone(),
                rendered_path: path.clone(),
                defid: c.opaque_type_ids.get(name).cloned(),
            })
        })
        .collect()
}

/// Decide one name: `Ok(Some(decision))` to unify, `Ok(None)` when split
/// nominals are already correct, `Err(reason)` for a reported skip.
fn decide(
    catalog: &[InstalledCrate],
    surfacers: &[Surfacer],
    edges: &BTreeMap<String, BTreeSet<String>>,
) -> Result<Option<Decision>, String> {
    if surfacers.iter().any(|s| s.defid.is_none()) {
        return Err(
            "a member has no defining-path identity for this type (older cache — \
             re-run `ipe install` to enable unification)"
                .to_owned(),
        );
    }
    let defids: BTreeSet<&str> = surfacers
        .iter()
        .filter_map(|s| s.defid.as_deref())
        .collect();
    if defids.len() != 1 {
        // Genuinely distinct same-named types: split nominals are correct.
        return Ok(None);
    }
    let defid = defids.iter().next().map_or("", |d| *d).to_owned();
    let Some(def_crate) = defid.split("::").next() else {
        return Ok(None);
    };
    // Version guard: every member that RESOLVED the defining crate in its own
    // inspection must agree on its version, and at least one must have. A
    // member with no entry saw the type only through the manifest-run
    // cross-crate index — its rendered path resolves in the emitted app to
    // the ONE pinned version the resolving members agreed on (a textual
    // `::crate::Type` path can only name the app's single direct-dep
    // version), so absence is not evidence of a second type.
    let versions: BTreeSet<&str> = surfacers
        .iter()
        .filter_map(|s| {
            catalog
                .get(s.idx)
                .and_then(|c| c.dep_versions.get(def_crate))
                .map(String::as_str)
        })
        .collect();
    if versions.len() != 1 {
        return Err(format!(
            "defining crate `{def_crate}` did not resolve to one known version \
             across the members surfacing the type — collapsing could emit an \
             unbuildable project"
        ));
    }
    // Home: the member whose OWN rendered path roots in the defining crate
    // (the definer names itself), else the first surfacing module.
    let roots_in_definer = |s: &&Surfacer| {
        s.rendered_path
            .trim_start_matches("::")
            .split("::")
            .next()
            .is_some_and(|seg| seg == def_crate)
    };
    let home = surfacers
        .iter()
        .filter(roots_in_definer)
        .min_by(|a, b| a.module.cmp(&b.module))
        .or_else(|| surfacers.iter().min_by(|a, b| a.module.cmp(&b.module)));
    let Some(home) = home else { return Ok(None) };
    let home_module = home.module.clone();
    let demoted: Vec<(usize, String)> = surfacers
        .iter()
        .filter(|s| s.idx != home.idx)
        .map(|s| (s.idx, s.module.clone()))
        .collect();
    // Cycle guard: every demotion edge must keep the module graph acyclic
    // (names are processed in sorted order — deterministic).
    if demoted
        .iter()
        .any(|(_, module)| would_cycle(edges, module, &home_module))
    {
        return Err(format!(
            "importing `{home_module}` would create an interface-module import \
             cycle — nominals stay split"
        ));
    }
    Ok(Some(Decision {
        defid,
        home_module,
        demoted,
    }))
}

/// Unify same-identity foreign nominals across the installed-crate catalog.
///
/// Mutates the catalog in place: a demoted member loses the type from its
/// `opaque_types`/`opaque_type_ids` and its `interface_source` is re-rendered
/// from the structured consumer data with the corresponding
/// `import <Home> exposing (…)` lines. The home member is untouched.
#[must_use]
pub fn unify_foreign_nominals(catalog: &mut [InstalledCrate]) -> UnifyReport {
    let mut report = UnifyReport::default();

    // Every name surfaced by ≥2 members, in sorted (deterministic) order.
    let mut by_name: BTreeMap<String, usize> = BTreeMap::new();
    for c in catalog.iter() {
        for name in c.opaque_types.keys() {
            *by_name.entry(name.clone()).or_default() += 1;
        }
    }

    // Import edges accumulated across names: demoted module → home module.
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // Per-member pending imports: member idx → (home module → type names).
    let mut imports: BTreeMap<usize, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();

    for (name, surface_count) in &by_name {
        if *surface_count < 2 {
            continue;
        }
        let surfacers = surfacers_of(catalog, name);
        match decide(catalog, &surfacers, &edges) {
            Err(reason) => report.skipped.push(SkippedUnification {
                name: name.clone(),
                reason,
            }),
            Ok(None) => {}
            Ok(Some(decision)) => {
                let mut demoted_modules = Vec::with_capacity(decision.demoted.len());
                for (idx, module) in decision.demoted {
                    edges
                        .entry(module.clone())
                        .or_default()
                        .insert(decision.home_module.clone());
                    imports
                        .entry(idx)
                        .or_default()
                        .entry(decision.home_module.clone())
                        .or_default()
                        .insert(name.clone());
                    if let Some(c) = catalog.get_mut(idx) {
                        c.opaque_types.remove(name);
                        c.opaque_type_ids.remove(name);
                    }
                    demoted_modules.push(module);
                }
                report.unified.push(UnifiedType {
                    name: name.clone(),
                    defid: decision.defid,
                    home_module: decision.home_module,
                    demoted_modules,
                });
            }
        }
    }

    // Re-render every demoted member from its structured consumer data.
    for (idx, member_imports) in &imports {
        if let Some(c) = catalog.get_mut(*idx) {
            c.interface_source = crate::interface::render_module(
                &c.module_name,
                member_imports,
                &c.opaque_types,
                &c.define_types,
                &c.transparent_types,
                &c.bindings,
            );
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::InterfaceBinding;

    fn member(
        module: &str,
        types: &[(&str, &str, Option<&str>)],
        bindings: &[(&str, &str)],
        dep_versions: &[(&str, &str)],
    ) -> InstalledCrate {
        let opaque_types = types
            .iter()
            .map(|(n, p, _)| ((*n).to_owned(), (*p).to_owned()))
            .collect();
        let opaque_type_ids = types
            .iter()
            .filter_map(|(n, _, d)| d.map(|d| ((*n).to_owned(), d.to_owned())))
            .collect();
        let bindings: Vec<InterfaceBinding> = bindings
            .iter()
            .map(|(name, sig)| InterfaceBinding {
                ref_name: (*name).to_owned(),
                wrapper_ident: format!("K_{name}"),
                arity: 1,
                sig: (*sig).to_owned(),
                transparent_params: crate::interface::TransparentParams::None,
                transparent_result: None,
            })
            .collect();
        let slug =
            crate::driver::FfiSlug::parse_canonical(&module.to_lowercase().replace('.', "_"))
                .expect("a fixture module folds to a slug");
        InstalledCrate {
            kernel_name: module.replace('.', "_"),
            module_name: module.to_owned(),
            interface_source: String::new(),
            bindings_source: String::new(),
            opaque_types,
            opaque_type_ids,
            define_types: std::collections::BTreeSet::new(),
            transparent_types: std::collections::BTreeMap::new(),
            cargo_deps: vec![],
            package_name: crate::pkginfo::PackageName::parse(slug.as_str())
                .expect("a fixture slug is a package name"),
            dep_idents: std::collections::BTreeMap::new(),
            bindings,
            wrapper_idents: std::collections::BTreeSet::new(),
            dep_versions: dep_versions
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            inspected_free_fns: std::collections::BTreeMap::new(),
            inspected_consts: std::collections::BTreeMap::new(),
            slug,
        }
    }

    #[test]
    fn same_identity_collapses_to_the_definer_home() {
        let mut catalog = vec![
            member(
                "Rust.Async_stripe",
                &[(
                    "Client",
                    "::stripe::Client",
                    Some("stripe_client_core::client::Client"),
                )],
                &[("new_from_client", "String -> Client")],
                &[("stripe_client_core", "1.0.0-rc.6")],
            ),
            member(
                "Rust.Async_stripe_client_core",
                &[(
                    "Client",
                    "::stripe_client_core::Client",
                    Some("stripe_client_core::client::Client"),
                )],
                &[("timeout_from_client", "Client -> Int")],
                &[("stripe_client_core", "1.0.0-rc.6")],
            ),
        ];
        let report = unify_foreign_nominals(&mut catalog);
        assert_eq!(report.unified.len(), 1, "{report:?}");
        let unified = report.unified.first().expect("one unification");
        assert_eq!(unified.home_module, "Rust.Async_stripe_client_core");
        assert_eq!(unified.demoted_modules, vec!["Rust.Async_stripe"]);
        // Demoted module: declaration gone, import present, binding kept.
        let demoted = catalog.first().expect("demoted member");
        assert!(!demoted.opaque_types.contains_key("Client"));
        let src = &demoted.interface_source;
        assert!(
            src.contains("\nimport Rust.Async_stripe_client_core exposing (Client)\n"),
            "{src}"
        );
        assert!(!src.contains("type Client"), "{src}");
        assert!(
            src.contains("\nnew_from_client : String -> Client\n"),
            "{src}"
        );
        assert!(
            src.starts_with("module Rust.Async_stripe exposing (new_from_client)"),
            "{src}"
        );
        // Home module untouched.
        assert!(
            catalog
                .get(1)
                .is_some_and(|m| m.opaque_types.contains_key("Client"))
        );
    }

    #[test]
    fn distinct_identities_stay_split() {
        let mut catalog = vec![
            member(
                "Rust.A",
                &[("Config", "::a::Config", Some("a::Config"))],
                &[],
                &[("a", "1.0.0")],
            ),
            member(
                "Rust.B",
                &[("Config", "::b::Config", Some("b::Config"))],
                &[],
                &[("b", "1.0.0")],
            ),
        ];
        let report = unify_foreign_nominals(&mut catalog);
        assert!(report.unified.is_empty(), "{report:?}");
        assert!(
            report.skipped.is_empty(),
            "distinct types are not an over-drop"
        );
        assert!(
            catalog
                .first()
                .is_some_and(|m| m.opaque_types.contains_key("Config"))
        );
        assert!(
            catalog
                .get(1)
                .is_some_and(|m| m.opaque_types.contains_key("Config"))
        );
    }

    #[test]
    fn version_unknown_to_one_member_still_unifies_on_the_known_pin() {
        // The core member never resolved the umbrella crate in its own jail
        // (it saw `stripe::Client` only through the cross-crate index) — the
        // umbrella's own resolution is the one known pin, and it suffices.
        let mut catalog = vec![
            member(
                "Rust.Async_stripe",
                &[(
                    "Client",
                    "::stripe::Client",
                    Some("stripe::hyper::client::Client"),
                )],
                &[],
                &[("stripe", "1.0.0-rc.6")],
            ),
            member(
                "Rust.Async_stripe_core",
                &[(
                    "Client",
                    "::stripe::Client",
                    Some("stripe::hyper::client::Client"),
                )],
                &[],
                &[("stripe_shared", "1.0.0-rc.6")],
            ),
        ];
        let report = unify_foreign_nominals(&mut catalog);
        assert_eq!(report.unified.len(), 1, "{report:?}");
        assert_eq!(
            report.unified.first().map(|u| u.home_module.as_str()),
            Some("Rust.Async_stripe")
        );
    }

    #[test]
    fn missing_identity_or_version_disagreement_skips_with_reason() {
        // Missing defid on one member.
        let mut catalog = vec![
            member(
                "Rust.A",
                &[("T", "::x::T", Some("x::T"))],
                &[],
                &[("x", "1.0.0")],
            ),
            member("Rust.B", &[("T", "::x::T", None)], &[], &[("x", "1.0.0")]),
        ];
        let report = unify_foreign_nominals(&mut catalog);
        assert!(report.unified.is_empty());
        let skipped = report.skipped.first().expect("one skip reason");
        assert!(skipped.reason.contains("no defining-path identity"));

        // Version disagreement on the defining crate.
        let mut catalog = vec![
            member(
                "Rust.A",
                &[("T", "::x::T", Some("x::T"))],
                &[],
                &[("x", "1.0.0")],
            ),
            member(
                "Rust.B",
                &[("T", "::x::T", Some("x::T"))],
                &[],
                &[("x", "2.0.0")],
            ),
        ];
        let report = unify_foreign_nominals(&mut catalog);
        assert!(report.unified.is_empty());
        let skipped = report.skipped.first().expect("one skip reason");
        assert!(skipped.reason.contains("one known version"));
    }

    #[test]
    fn an_import_cycle_is_refused_deterministically() {
        // `Alpha` would demote B→A; `Beta` would demote A→B (cycle).
        let mut catalog = vec![
            member(
                "Rust.A",
                &[
                    ("Alpha", "::a::Alpha", Some("a::Alpha")),
                    ("Beta", "::a::Beta", Some("b::Beta")),
                ],
                &[],
                &[("a", "1.0.0"), ("b", "1.0.0")],
            ),
            member(
                "Rust.B",
                &[
                    ("Alpha", "::b_view::Alpha", Some("a::Alpha")),
                    ("Beta", "::b::Beta", Some("b::Beta")),
                ],
                &[],
                &[("a", "1.0.0"), ("b", "1.0.0")],
            ),
        ];
        let report = unify_foreign_nominals(&mut catalog);
        // Sorted order: `Alpha` unifies (home Rust.A), `Beta` would need
        // Rust.A → Rust.B and is refused.
        assert_eq!(report.unified.len(), 1, "{report:?}");
        assert_eq!(
            report.unified.first().map(|u| u.name.as_str()),
            Some("Alpha")
        );
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.name == "Beta" && s.reason.contains("import cycle"))
        );
    }
}
