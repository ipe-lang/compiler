//! The static aspect columns: home, resolves, closed-scheme, layer-agreement.
//!
//! These read only registries and typed interfaces — the canon module tables,
//! the kernel registry, and each module's projected [`crate::api_surface`]
//! interface — never a compiled program. They run in the fast path.

use std::collections::{BTreeMap, BTreeSet};

use ipe_canon::STDLIB_MODULE_QUALIFIERS;

use crate::api_surface::{self, DiffError, PublicApi};
use crate::coverage::contract::{AspectCheck, Cell, StdlibSymbol, SymbolKind};
use crate::coverage::error::CoverageError;

/// The set of dotted module names that are compiled-source modules.
fn compiled_source_modules() -> BTreeSet<Vec<String>> {
    ipe_stdlib::COMPILED_STD_MODULES
        .iter()
        .map(|m| m.dotted.split('.').map(str::to_owned).collect())
        .collect()
}

/// The set of dotted module segment lists that are kernel qualifiers.
fn kernel_qualifier_modules() -> BTreeSet<Vec<String>> {
    STDLIB_MODULE_QUALIFIERS
        .iter()
        .map(|(segments, _)| segments.iter().map(|s| (*s).to_owned()).collect())
        .collect()
}

// ── home ────────────────────────────────────────────────────────────────────

/// Column **home**: a symbol's module is exactly one of {kernel qualifier,
/// compiled-source module} — the `compiled_vs_kernel_qualifier_disjoint`
/// invariant lifted to the symbol surface.
///
/// The two homes are disjoint AND exhaustive at the module-qualifier level: a
/// module is either a kernel qualifier (its members are kernels) or a
/// compiled-source module (its members are Ipê source, reaching kernels through
/// `Ffi.kernel` aliases), never both and never neither. A symbol whose module is
/// in both tables, or in neither, is a hole. A symbol carrying both the
/// `has_kernel` and `has_compiled_source` facets is NOT a violation — that is the
/// intended alias bridge (a compiled-source member point-free-aliased to a
/// kernel); the disjointness axis is module membership, not the facets.
pub struct HomeColumn;

impl AspectCheck<StdlibSymbol> for HomeColumn {
    fn name(&self) -> &'static str {
        "home"
    }

    fn check(&self, sym: &StdlibSymbol) -> Cell {
        let compiled = compiled_source_modules();
        let kernels = kernel_qualifier_modules();
        let in_compiled = compiled.contains(&sym.module);
        let in_kernel = kernels.contains(&sym.module);
        match (in_compiled, in_kernel) {
            (true, false) | (false, true) => Cell::Ok,
            (true, true) => Cell::Hole(format!(
                "module {} is BOTH a compiled-source module and a kernel qualifier \
                 (disjointness violated)",
                sym.module.join(".")
            )),
            (false, false) => Cell::Hole(format!(
                "module {} is neither a compiled-source module nor a kernel \
                 qualifier (no home)",
                sym.module.join(".")
            )),
        }
    }
}

// ── the per-module projection index (shared by resolves + closed-scheme) ──────

/// Per-module projection outcomes, computed once and shared by the columns that
/// read a module's typed interface.
///
/// A compiled-source module either projects (a [`PublicApi`] whose schemes are
/// all closed — [`api_surface::extract_stdlib_module`] refuses an open interface)
/// or fails with a typed [`DiffError`]. Caching the outcome per module keeps the
/// per-symbol columns from re-typechecking a module once per member.
struct ModuleProjections {
    outcomes: BTreeMap<Vec<String>, Result<PublicApi, ProjectionFailure>>,
}

/// Why a compiled-source module did not project — the closed-scheme-relevant
/// distinction, reduced from [`DiffError`] to what the columns report.
#[derive(Debug)]
enum ProjectionFailure {
    /// The module's interface is open — a scheme reaches a residual variable.
    Open,
    /// The module did not typecheck, or another extraction error.
    Other(DiffError),
}

impl ModuleProjections {
    fn build() -> Self {
        let mut outcomes = BTreeMap::new();
        for module in ipe_stdlib::COMPILED_STD_MODULES {
            let segments: Vec<String> = module.dotted.split('.').map(str::to_owned).collect();
            let outcome =
                api_surface::extract_stdlib_module(&segments, module.source).map_err(|e| match e {
                    DiffError::OpenInterface { .. } => ProjectionFailure::Open,
                    other => ProjectionFailure::Other(other),
                });
            outcomes.insert(segments, outcome);
        }
        Self { outcomes }
    }

    /// The projection outcome for a symbol's own module, if that module is a
    /// compiled-source module. A kernel-qualifier module has no compiled-source
    /// projection, so this is `None` there.
    fn for_module(&self, module: &[String]) -> Option<&Result<PublicApi, ProjectionFailure>> {
        self.outcomes.get(module)
    }
}

// ── resolves ──────────────────────────────────────────────────────────────────

/// Column **resolves**: every exported member has a resolvable home.
///
/// [`api_surface::extract_stdlib_module`] drives the real compile pipeline over a
/// module and its injected dependency closure; it returns `Ok` only when the
/// whole module canonicalises and type-checks, which means every `exposing`
/// member has a resolvable home (a dangling declaration or a broken `Ffi.kernel`
/// alias fails that compile — the same property `stdlib_export_resolvability`
/// asserts). So an exported symbol whose module projected `Ok` resolves; a symbol
/// whose module failed to project does not. A per-member scheme is NOT required:
/// a point-free `Ffi.kernel` alias resolves to a kernel whose scheme lives in the
/// kernel table, not the module's own typed interface. A non-exported kernel-only
/// symbol is judged by the home column, so it is `NotApplicable` here.
pub struct ResolvesColumn {
    projections: ModuleProjections,
}

impl ResolvesColumn {
    #[must_use]
    pub fn new() -> Self {
        Self {
            projections: ModuleProjections::build(),
        }
    }
}

impl Default for ResolvesColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl AspectCheck<StdlibSymbol> for ResolvesColumn {
    fn name(&self) -> &'static str {
        "resolves"
    }

    fn check(&self, sym: &StdlibSymbol) -> Cell {
        if !sym.exported {
            return Cell::not_applicable("not exported — resolvability applies to exports only");
        }
        let Some(outcome) = self.projections.for_module(&sym.module) else {
            // Exported but homed in a kernel-qualifier module: its resolvability
            // is not projected here (no compiled-source interface). The home
            // column owns that surface.
            return Cell::not_applicable(
                "exported but homed in a kernel-qualifier module with no compiled-source \
                 interface — the home column owns its resolvability",
            );
        };
        match outcome {
            Ok(_) => Cell::Ok,
            Err(ProjectionFailure::Open) => Cell::Hole(format!(
                "module {} did not project — its interface is open, so {} cannot \
                 be resolved",
                sym.module.join("."),
                sym.name
            )),
            Err(ProjectionFailure::Other(msg)) => Cell::Hole(format!(
                "module {} did not project ({msg}), so {} cannot be resolved",
                sym.module.join("."),
                sym.name
            )),
        }
    }
}

// ── closed-scheme ─────────────────────────────────────────────────────────────

/// Column **closed-scheme**: the export's generalized scheme is closed — no leaky
/// residual variable an importer could pin — fail-closed.
///
/// [`api_surface::extract_stdlib_module`] refuses an OPEN module interface
/// outright, so a module that projects has every export's scheme closed. This
/// column lifts that per-module refusal to a per-symbol cell: a symbol whose
/// module failed to project with an open interface is a hole; a symbol whose
/// module projected is closed. A module that failed to typecheck (not an open
/// interface) is `NotApplicable` here — the resolves column owns that failure, so
/// it is not double-reported as a scheme hole.
pub struct ClosedSchemeColumn {
    projections: ModuleProjections,
}

impl ClosedSchemeColumn {
    #[must_use]
    pub fn new() -> Self {
        Self {
            projections: ModuleProjections::build(),
        }
    }
}

impl Default for ClosedSchemeColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl AspectCheck<StdlibSymbol> for ClosedSchemeColumn {
    fn name(&self) -> &'static str {
        "closed-scheme"
    }

    fn check(&self, sym: &StdlibSymbol) -> Cell {
        let Some(outcome) = self.projections.for_module(&sym.module) else {
            return Cell::not_applicable(
                "no compiled-source interface projected for this module — scheme openness \
                 does not apply here",
            );
        };
        match outcome {
            Ok(_) => Cell::Ok,
            Err(ProjectionFailure::Open) => Cell::Hole(format!(
                "module {} has an OPEN interface — the exported scheme of {} \
                 reaches a residual variable an importer could pin (fail-closed)",
                sym.module.join("."),
                sym.name
            )),
            // A typecheck failure is the resolves column's hole, not a scheme
            // openness hole.
            Err(ProjectionFailure::Other(_)) => Cell::not_applicable(
                "the module failed to typecheck — the resolves column owns that hole, not a \
                 scheme-openness gap",
            ),
        }
    }
}

// ── layer-agreement ───────────────────────────────────────────────────────────

/// Column **layer-agreement**: for a builtin union constructor, the canon
/// `BUILTIN_UNIONS` table and the typed-interface projection agree on the
/// constructor's payload arity.
///
/// The five-layer drift class (canon / constrain / lower / backend disagreeing on
/// a builtin ADT's shape) shipped a mis-arity ICE. Reachable statically from here
/// are the two registry layers: canon's `BUILTIN_UNIONS` (the authoritative ctor
/// arity table) and constrain (the typed interface the surface projected). The
/// lower and backend variant tables (`BuiltinCtors`, `builtin_runtime_enum`) are
/// crate-private, so this static column checks canon-vs-constrain agreement; the
/// lower/backend layers are cross-checked by the build columns (Lane B), which
/// exercise the emitted enum. A constructor the canon table knows must have a
/// payload arity matching what the projected union declares; a mismatch, or a
/// constructor the canon table forgot for a builtin-union type, is a hole. A
/// constructor of a user-declared (non-builtin) union is `NotApplicable`.
#[derive(Debug)]
pub struct LayerAgreementColumn {
    /// Canon builtin `(type name, ctor name)` → payload arity.
    canon_arities: BTreeMap<(String, String), usize>,
    /// The projected `(module, ctor name)` → (builtin type name, arity) for every
    /// constructor a compiled-source module declares under a builtin-union type.
    projected: BTreeMap<(Vec<String>, String), (String, usize)>,
}

impl LayerAgreementColumn {
    /// # Errors
    /// [`CoverageError::Extract`] if a compiled-source module fails to extract
    /// its typed interface — a module dropped here would silently lose its
    /// constructors from the cross-layer arity check rather than naming the
    /// failure.
    pub fn new() -> Result<Self, CoverageError> {
        Self::build_from(ipe_stdlib::COMPILED_STD_MODULES)
    }

    /// The parametrized core of [`Self::new`], over an explicit module list so
    /// a refusal test can inject one that fails to extract without touching
    /// the real [`ipe_stdlib::COMPILED_STD_MODULES`] table.
    fn build_from(modules: &[ipe_stdlib::CompiledStdModule]) -> Result<Self, CoverageError> {
        let mut canon_arities = BTreeMap::new();
        // The exact constructor NAME SET canon declares per builtin union — the
        // fingerprint that distinguishes the genuine builtin from a module-local
        // union that merely reuses the builtin's type name (a shadow such as a
        // sort-direction `Order { Asc, Desc }` versus the builtin comparison
        // `Order { LT, EQ, GT }`).
        let mut canon_ctor_sets: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for union in ipe_canon::builtins::BUILTIN_UNIONS {
            for (ctor_name, _index, arity) in union.ctors {
                canon_arities.insert(
                    (union.type_name.to_owned(), (*ctor_name).to_owned()),
                    *arity,
                );
                canon_ctor_sets
                    .entry(union.type_name.to_owned())
                    .or_default()
                    .insert((*ctor_name).to_owned());
            }
        }

        let mut projected = BTreeMap::new();
        for module in modules {
            let segments: Vec<String> = module.dotted.split('.').map(str::to_owned).collect();
            let api =
                api_surface::extract_stdlib_module(&segments, module.source).map_err(|source| {
                    CoverageError::Extract {
                        module: segments.clone(),
                        source,
                    }
                })?;
            for (path, module_api) in &api.modules {
                for (type_name, union) in &module_api.unions {
                    // A projected union is the genuine builtin only when its
                    // constructor name set exactly equals canon's for that type;
                    // a shadowing local union with the same type name but a
                    // different constructor set is not the builtin and is left
                    // out (its ctors are `NotApplicable`).
                    let Some(canon_set) = canon_ctor_sets.get(type_name) else {
                        continue;
                    };
                    let projected_set: BTreeSet<String> = union.ctors.keys().cloned().collect();
                    if &projected_set != canon_set {
                        continue;
                    }
                    for (ctor_name, args) in &union.ctors {
                        projected.insert(
                            (path.clone(), ctor_name.clone()),
                            (type_name.clone(), args.len()),
                        );
                    }
                }
            }
        }

        Ok(Self {
            canon_arities,
            projected,
        })
    }
}

impl AspectCheck<StdlibSymbol> for LayerAgreementColumn {
    fn name(&self) -> &'static str {
        "layer-agreement"
    }

    fn check(&self, sym: &StdlibSymbol) -> Cell {
        if sym.kind != SymbolKind::Ctor {
            return Cell::not_applicable(
                "not a constructor — payload-arity agreement applies to \
                                         union constructors only",
            );
        }
        // Only a constructor the typed interface actually declares under a
        // builtin-union type is judged: this pins the surface ctor to its union,
        // so a user/opaque ctor that merely shares a builtin ctor's name (a name
        // collision) is `NotApplicable`, not a false hole.
        let Some((type_name, projected_arity)) =
            self.projected.get(&(sym.module.clone(), sym.name.clone()))
        else {
            return Cell::not_applicable(
                "not a builtin-union constructor in the typed interface — a user/opaque ctor \
                 that merely shares a name, not a layer-agreement subject",
            );
        };
        match self
            .canon_arities
            .get(&(type_name.clone(), sym.name.clone()))
            .copied()
        {
            Some(canon_arity) if canon_arity == *projected_arity => Cell::Ok,
            Some(canon_arity) => Cell::Hole(format!(
                "constructor {}.{} payload arity disagrees: canon BUILTIN_UNIONS \
                 says {canon_arity}, the typed interface projects {projected_arity}",
                type_name, sym.name
            )),
            None => Cell::Hole(format!(
                "constructor {}.{} is projected under builtin union {type_name} but \
                 canon BUILTIN_UNIONS has no matching entry",
                type_name, sym.name
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A module that fails to extract must refuse the whole column with a typed
    /// error, never silently drop the module's constructors from the
    /// cross-layer arity check (the fail-open `let Ok(..) = .. else { continue }`
    /// this replaced).
    #[test]
    fn a_module_that_fails_to_extract_is_a_typed_error_not_a_dropped_row() {
        let modules = [ipe_stdlib::CompiledStdModule {
            dotted: "Ipe.CoverageTestBroken",
            source: "module Ipe.CoverageTestBroken exposing (broken)\n\nbroken : Int\nbroken = \"not an Int\"\n",
        }];
        let result = LayerAgreementColumn::build_from(&modules);
        assert!(
            matches!(
                &result,
                Err(CoverageError::Extract { module, .. })
                    if module.last().map(String::as_str) == Some("CoverageTestBroken")
            ),
            "expected a typed CoverageError::Extract naming the broken module, got {result:?}"
        );
    }
}
