//! The canonical stdlib surface: one reconciled enumeration of every exported
//! symbol.
//!
//! [`StdlibSurface::all`] fuses the three partial enumerations that otherwise
//! drift apart into one sorted, deterministic list:
//!
//! - the compiled-source modules ([`ipe_stdlib::COMPILED_STD_MODULES`]) — their
//!   `exposing (...)` lists give the exported members, and their projected typed
//!   interfaces ([`crate::api_surface`]) give schemes and union constructors;
//! - the kernel registry ([`ipe_kernels::StdlibKernel::ALL`]) — each wired kernel
//!   homed under its real module path, resolved through
//!   [`ipe_canon::STDLIB_MODULE_QUALIFIERS`] (or its compiled-source module when
//!   the kernel family is aliased from Ipê source, as `Ipe.List` aliases the
//!   `List_*` kernels);
//! - the per-module typed interface, the source the compiled-source projection
//!   reads.
//!
//! A member present in one enumeration but forgotten in another appears once,
//! with the missing facet visibly `false`, so the aspect columns judge a single
//! reconciled surface.
//!
//! Every fold step is fallible: a module that fails to parse or extract, an
//! unresolved `exposing` symbol, or a kernel/scheme-table drift returns a typed
//! [`CoverageError`] rather than silently dropping its contribution to the
//! surface.

use std::collections::BTreeMap;

use ipe_diagnostics::{TyDoc, render_ty};
use ipe_intern::Interner;
use ipe_syntax::{Exposed, Exposing};
use ipe_types::{KernelScheme, VarNamer, kernel_type_table, ty_to_doc};

use crate::api_surface::{self, ModuleApi};
use crate::coverage::contract::{SchemeState, StdlibSymbol, Surface, SymbolKind};
use crate::coverage::error::CoverageError;

/// A kernel qualifier's module path, keyed by the dotted name or qualifier a
/// [`kernel_module_path`] lookup table joins against.
pub(crate) type QualifierModuleMap = BTreeMap<String, Vec<String>>;

/// The reconciliation key: one row per (module, name, kind).
type Key = (Vec<String>, String, SymbolKind);

/// The reconciled stdlib surface.
///
/// Zero-sized: it holds no state and reads the registries afresh on each
/// [`Surface::all`], so the enumeration always reflects the current tables.
#[derive(Clone, Copy, Debug, Default)]
pub struct StdlibSurface;

impl Surface for StdlibSurface {
    type Item = StdlibSymbol;

    fn name(&self) -> &'static str {
        "stdlib"
    }

    fn all(&self) -> Result<Vec<StdlibSymbol>, CoverageError> {
        let mut by_key: BTreeMap<Key, StdlibSymbol> = BTreeMap::new();

        merge_compiled_source(&mut by_key)?;
        merge_kernels(&mut by_key)?;

        // `BTreeMap` iteration is sorted by the (module, name, kind) key, so the
        // result is deterministic without an explicit sort.
        Ok(by_key.into_values().collect())
    }

    fn label(item: &StdlibSymbol) -> String {
        let mut path = item.module.join(".");
        if !path.is_empty() {
            path.push('.');
        }
        path.push_str(&item.name);
        path
    }
}

/// Split a dotted module name (`"Ipe.List"`) into its segments.
fn segments_of(dotted: &str) -> Vec<String> {
    dotted.split('.').map(str::to_owned).collect()
}

// ── compiled-source enumeration ───────────────────────────────────────────────

/// Fold every compiled-source module into the reconciliation map.
///
/// The `exposing (...)` list is the authoritative export set: it names every
/// value, type, and (transitively) constructor the module publishes, including
/// the `Ffi.kernel` point-free aliases whose scheme lives in the kernel table
/// rather than the module's own typed interface. Schemes and union constructors
/// come from the projected typed interface where available.
fn merge_compiled_source(by_key: &mut BTreeMap<Key, StdlibSymbol>) -> Result<(), CoverageError> {
    for module in ipe_stdlib::COMPILED_STD_MODULES {
        let segments = segments_of(module.dotted);
        merge_one_compiled_module(by_key, &segments, module.source)?;
    }
    Ok(())
}

/// Fold one compiled-source module (by its already-split segments and source
/// text) into the reconciliation map. Separated from [`merge_compiled_source`]'s
/// registry loop so a refusal test can inject a module that fails to extract or
/// parse without touching the real [`ipe_stdlib::COMPILED_STD_MODULES`] table.
fn merge_one_compiled_module(
    by_key: &mut BTreeMap<Key, StdlibSymbol>,
    segments: &[String],
    source: &str,
) -> Result<(), CoverageError> {
    let api = api_surface::extract_stdlib_module(segments, source).map_err(|err| {
        CoverageError::Extract {
            module: segments.to_vec(),
            source: err,
        }
    })?;
    let projected = api.modules.get(segments).cloned();

    merge_exposing(by_key, segments, source, projected.as_ref())
}

/// Fold one compiled-source module's `exposing (...)` members into the map,
/// enriched with schemes and constructors from its projected interface.
fn merge_exposing(
    by_key: &mut BTreeMap<Key, StdlibSymbol>,
    segments: &[String],
    source: &str,
    projected: Option<&ModuleApi>,
) -> Result<(), CoverageError> {
    let mut interner = Interner::new();
    let parsed = ipe_parse::parse_module(source, &mut interner).map_err(|diagnostic| {
        CoverageError::Parse {
            module: segments.to_vec(),
            diagnostic,
        }
    })?;

    let exposed = match &parsed.exposing.value {
        // `exposing (..)` re-exports everything; fall back to the projected
        // interface as the export set. Compiled-source stdlib modules use
        // explicit lists, so this arm is a defensive fallback.
        Exposing::All => {
            if let Some(api) = projected {
                merge_projected_only(by_key, segments, api);
            }
            return Ok(());
        }
        Exposing::List(items) => items,
    };

    for item in exposed {
        match &item.value {
            Exposed::Value(sym) => {
                let name =
                    interner
                        .resolve(*sym)
                        .ok_or_else(|| CoverageError::UnresolvedSymbol {
                            module: segments.to_vec(),
                        })?;
                let (scheme, higher_order) = projected
                    .and_then(|api| {
                        let sig = api.values.get(name)?;
                        let ho = api
                            .value_types
                            .get(name)
                            .is_some_and(scheme_is_higher_order);
                        Some((SchemeState::Rendered(sig.clone()), ho))
                    })
                    .unwrap_or((SchemeState::Unschemed, false));
                insert(
                    by_key,
                    compiled_symbol(
                        segments.to_vec(),
                        name.to_owned(),
                        SymbolKind::Value,
                        scheme,
                        higher_order,
                    ),
                );
            }
            Exposed::Type(sym, _privacy) => {
                let name =
                    interner
                        .resolve(*sym)
                        .ok_or_else(|| CoverageError::UnresolvedSymbol {
                            module: segments.to_vec(),
                        })?;
                insert(
                    by_key,
                    compiled_symbol(
                        segments.to_vec(),
                        name.to_owned(),
                        SymbolKind::Type,
                        SchemeState::Unschemed,
                        false,
                    ),
                );
                // The exposed union's constructors come from the projected
                // interface (the `exposing` entry carries only the type name +
                // its constructor privacy, not the constructor set).
                if let Some(union) = projected.and_then(|api| api.unions.get(name)) {
                    for ctor_name in union.ctors.keys() {
                        insert(
                            by_key,
                            compiled_symbol(
                                segments.to_vec(),
                                ctor_name.clone(),
                                SymbolKind::Ctor,
                                SchemeState::Unschemed,
                                false,
                            ),
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

/// Fold a projected interface's values and unions directly (the `exposing (..)`
/// fallback path).
fn merge_projected_only(
    by_key: &mut BTreeMap<Key, StdlibSymbol>,
    segments: &[String],
    api: &ModuleApi,
) {
    for (name, signature) in &api.values {
        let higher_order = api
            .value_types
            .get(name)
            .is_some_and(scheme_is_higher_order);
        insert(
            by_key,
            compiled_symbol(
                segments.to_vec(),
                name.clone(),
                SymbolKind::Value,
                SchemeState::Rendered(signature.clone()),
                higher_order,
            ),
        );
    }
    for (type_name, union) in &api.unions {
        insert(
            by_key,
            compiled_symbol(
                segments.to_vec(),
                type_name.clone(),
                SymbolKind::Type,
                SchemeState::Unschemed,
                false,
            ),
        );
        for ctor_name in union.ctors.keys() {
            insert(
                by_key,
                compiled_symbol(
                    segments.to_vec(),
                    ctor_name.clone(),
                    SymbolKind::Ctor,
                    SchemeState::Unschemed,
                    false,
                ),
            );
        }
    }
}

/// A compiled-source symbol seed: present in a compiled-source module and
/// exported; kernel facet not yet known.
const fn compiled_symbol(
    module: Vec<String>,
    name: String,
    kind: SymbolKind,
    scheme: SchemeState,
    is_higher_order: bool,
) -> StdlibSymbol {
    StdlibSymbol {
        module,
        name,
        kind,
        has_kernel: false,
        has_compiled_source: true,
        exported: true,
        scheme,
        is_higher_order,
    }
}

// ── kernel enumeration ────────────────────────────────────────────────────────

/// Kernel qualifiers whose short name does not match their compiled-source
/// module's dotted name or final segment.
///
/// The general heuristics in [`kernel_module_path`] resolve most qualifiers
/// (`"List"` → `Ipe.List`, `"Store"` → `Ipe.Db.Store`), but a handful use a
/// short internal tag that differs from the module name. This table is the
/// single source of truth for those mismatches; its entries are cross-checked
/// against the real module lists rather than trusted blindly, so a drifted
/// entry surfaces as [`CoverageError::UnknownQualifier`] instead of silently
/// homing a kernel under an invented `Ipe.<qualifier>` path.
///
/// `Cmd` / `Sub` are intentionally absent — they are shape-scoped and have no
/// canonical standalone module (reached via `Ipe.Tea.<Shape>.Cmd` / `.Sub`).
const QUALIFIER_MODULE_OVERRIDES: &[(&str, &[&str])] = &[
    // `Attr` kernels (`attribute`, `boolAttribute`, `noAttr`) are the three
    // primitive `Kernel.kernel "Attr_*"` aliases that `Ipe.Html.Attributes` wraps.
    ("Attr", &["Ipe", "Html", "Attributes"]),
    // `EmailAddress` kernels (`parse`, `toString`) back `Ipe.Email`'s opaque
    // `EmailAddress` newtype via `parseAddress` / `addressToString` aliases.
    ("EmailAddress", &["Ipe", "Email"]),
    // `Key` and `Mac` are the opaque-type kernel families declared and used in
    // `Ipe.Crypto` (`keyFromString` / `keyFromBytes` / `macToHex` / `macFromHex`
    // aliases).
    ("Key", &["Ipe", "Crypto"]),
    ("Mac", &["Ipe", "Crypto"]),
    // `UiCells` kernels (`cells`, `column`, `el`, `none`, `row`, `text`) are the
    // six builders declared in `Ipe.Ui.Cells`.
    ("UiCells", &["Ipe", "Ui", "Cells"]),
    // `TuiUi` cell-native attribute builders (`spacing`, `padding`, `alignLeft`,
    // `alignRight`, `center`, `bold`, `underline`, `color`, `bg`) live in
    // `Ipe.Ui.Tui`.
    ("TuiUi", &["Ipe", "Ui", "Tui"]),
    // `CliUi` line-native view builders and attributes (`none`, `text`, `line`,
    // `lines`, `bold`, `underline`, `dim`, `reverse`, `color`, `bg`) live in
    // `Ipe.Ui.Cli`.
    ("CliUi", &["Ipe", "Ui", "Cli"]),
    // The `TermColor` kernel home backs the terminal palette constructors
    // (`black` … `brightWhite`, `default`, `rgb`) that now live in `Ipe.Color`,
    // typed `AnsiColor`.
    ("TermColor", &["Ipe", "Color"]),
];

/// The dotted module path a kernel qualifier lives under.
///
/// Resolution order (first match wins):
///
/// 1. [`ipe_canon::STDLIB_MODULE_QUALIFIERS`] — the authoritative
///    qualifier→path registry (`"Web"` → `Ipe.Tea.Web`).
/// 2. The compiled-source module whose dotted name is `Ipe.<qualifier>`
///    (`"List"` → `Ipe.List`; `"Db.Dsn"` → `Ipe.Db.Dsn`).
/// 3. The compiled-source module whose final segment equals the qualifier
///    (`"Store"` → `Ipe.Db.Store`).
/// 4. [`QUALIFIER_MODULE_OVERRIDES`] — short internal tags that differ from
///    their module's dotted name or final segment, cross-checked against the
///    real module lists below so a drifted override entry (renamed or
///    removed module) surfaces as [`CoverageError::UnknownQualifier`] rather
///    than silently standing in for a module that no longer exists.
/// 5. [`SHAPE_SCOPED_QUALIFIERS`] — routing tokens with no standalone module
///    by design: [`KernelHome::ShapeScoped`].
///
/// A `_`-prefixed qualifier is [`KernelHome::Internal`] before any tier is
/// consulted. Any other qualifier no tier resolves is
/// [`CoverageError::UnknownQualifier`]: a new kernel family with no module is a
/// named refusal, never an invented `Ipe.<qualifier>` path a consumer could
/// render as a real module.
///
/// # Errors
/// [`CoverageError::UnknownQualifier`] for a qualifier no tier resolves, or an
/// override entry naming a module absent from every real module list.
pub(crate) fn kernel_module_path(
    qualifier: &'static str,
    qualifier_to_path: &QualifierModuleMap,
    compiled_by_dotted: &QualifierModuleMap,
    compiled_by_last_segment: &QualifierModuleMap,
) -> Result<KernelHome, CoverageError> {
    if is_internal_qualifier(qualifier) {
        return Ok(KernelHome::Internal);
    }
    if let Some(path) = qualifier_to_path.get(qualifier) {
        return Ok(KernelHome::Module(path.clone()));
    }
    let dotted = format!("Ipe.{qualifier}");
    if let Some(path) = compiled_by_dotted.get(&dotted) {
        return Ok(KernelHome::Module(path.clone()));
    }
    if let Some(path) = compiled_by_last_segment.get(qualifier) {
        return Ok(KernelHome::Module(path.clone()));
    }
    if let Some(segs) = QUALIFIER_MODULE_OVERRIDES
        .iter()
        .find(|(q, _)| *q == qualifier)
        .map(|(_, segs)| segs)
    {
        let path: Vec<String> = segs.iter().map(|s| (*s).to_owned()).collect();
        let is_known_module = compiled_by_dotted.values().any(|known| *known == path)
            || compiled_by_last_segment
                .values()
                .any(|known| *known == path)
            || qualifier_to_path.values().any(|known| *known == path);
        return if is_known_module {
            Ok(KernelHome::Module(path))
        } else {
            Err(CoverageError::UnknownQualifier { qualifier })
        };
    }
    if SHAPE_SCOPED_QUALIFIERS.contains(&qualifier) {
        return Ok(KernelHome::ShapeScoped);
    }
    Err(CoverageError::UnknownQualifier { qualifier })
}

/// Kernel qualifiers that are shape-scoped routing tokens with no canonical
/// standalone module (reached via `Ipe.Tea.<Shape>.Cmd` / `.Sub`).
const SHAPE_SCOPED_QUALIFIERS: &[&str] = &["Cmd", "Sub"];

/// Whether `qualifier` is internal or not-yet-registered (`_`-prefixed),
/// excluded from every user-facing surface — the canon-equality tripwire's rule.
fn is_internal_qualifier(qualifier: &str) -> bool {
    qualifier.starts_with('_')
}

/// Where a kernel qualifier's members live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum KernelHome {
    /// A real stdlib module path.
    Module(Vec<String>),
    /// A [`SHAPE_SCOPED_QUALIFIERS`] routing token: no standalone module.
    ShapeScoped,
    /// A `_`-prefixed internal qualifier, on no user-facing surface.
    Internal,
}

/// The three qualifier-resolution tables [`kernel_module_path`] joins
/// against, built once from the canon and compiled-source registries.
pub(crate) fn qualifier_lookup_tables()
-> (QualifierModuleMap, QualifierModuleMap, QualifierModuleMap) {
    let qualifier_to_path: QualifierModuleMap = ipe_canon::STDLIB_MODULE_QUALIFIERS
        .iter()
        .map(|(segs, qualifier)| {
            (
                (*qualifier).to_owned(),
                segs.iter().map(|s| (*s).to_owned()).collect(),
            )
        })
        .collect();

    let compiled_by_dotted: QualifierModuleMap = ipe_stdlib::COMPILED_STD_MODULES
        .iter()
        .map(|m| (m.dotted.to_owned(), segments_of(m.dotted)))
        .collect();

    // A final segment two modules share (`Internals`, `Unsafe`, `Parser`) homes
    // no qualifier: keeping either would home a kernel by insertion order.
    let mut by_last: BTreeMap<String, Option<Vec<String>>> = BTreeMap::new();
    for m in ipe_stdlib::COMPILED_STD_MODULES {
        let segs = segments_of(m.dotted);
        if let Some(last) = segs.last().cloned() {
            by_last
                .entry(last)
                .and_modify(|slot| *slot = None)
                .or_insert(Some(segs));
        }
    }
    let compiled_by_last_segment: QualifierModuleMap = by_last
        .into_iter()
        .filter_map(|(last, segs)| segs.map(|segs| (last, segs)))
        .collect();

    (
        qualifier_to_path,
        compiled_by_dotted,
        compiled_by_last_segment,
    )
}

/// Fold the kernel registry into the reconciliation map: each wired kernel
/// becomes a value symbol whose `has_kernel` facet is set, homed under its real
/// module path.
///
/// # Errors
/// The typed [`CoverageError`] of the kernel/scheme join, a qualifier no tier
/// resolves, or a scheme that fails to render.
fn merge_kernels(by_key: &mut BTreeMap<Key, StdlibSymbol>) -> Result<(), CoverageError> {
    let (qualifier_to_path, compiled_by_dotted, compiled_by_last_segment) =
        qualifier_lookup_tables();

    let mut interner = Interner::new();
    let table = kernel_type_table(&mut interner).map_err(CoverageError::KernelTable)?;

    // The table holds one row per wired kernel, so iterating its rows (not
    // `StdlibKernel::ALL` plus a lookup) leaves no "absent" arm to default.
    for (kernel, scheme) in table.rows() {
        let def = kernel.def();
        let module = match kernel_module_path(
            def.qualifier,
            &qualifier_to_path,
            &compiled_by_dotted,
            &compiled_by_last_segment,
        )? {
            KernelHome::Module(path) => path,
            // Homed under the non-existent `Ipe.<qualifier>` so `HomeColumn`
            // names it as a hole rather than the row vanishing.
            KernelHome::ShapeScoped => segments_of(&format!("Ipe.{}", def.qualifier)),
            KernelHome::Internal => continue,
        };
        let (scheme, is_higher_order) = match scheme {
            KernelScheme::Schemed(ty) => {
                let mut namer = VarNamer::new();
                let doc = ty_to_doc(ty, &interner, &mut namer)
                    .map_err(|source| CoverageError::RenderScheme { kernel, source })?;
                let higher_order = scheme_is_higher_order(&doc);
                (SchemeState::Rendered(render_ty(&doc)), higher_order)
            }
            KernelScheme::Unschemed => (SchemeState::Unschemed, false),
        };
        insert(
            by_key,
            StdlibSymbol {
                module,
                name: def.name.to_owned(),
                kind: SymbolKind::Value,
                has_kernel: true,
                has_compiled_source: false,
                // A kernel exported through its compiled-source alias's
                // `exposing` reconciles with that (exported) row; a kernel homed
                // in a kernel-qualifier module carries its own export facet from
                // that module's surface, judged by the home column.
                exported: false,
                scheme,
                is_higher_order,
            },
        );
    }
    Ok(())
}

// ── reconciliation ────────────────────────────────────────────────────────────

/// Insert a symbol, OR-ing its facets into an existing row with the same
/// (module, name, kind) key so a member reached from two enumerations carries
/// both homes.
fn insert(by_key: &mut BTreeMap<Key, StdlibSymbol>, sym: StdlibSymbol) {
    let key = (sym.module.clone(), sym.name.clone(), sym.kind);
    by_key
        .entry(key)
        .and_modify(|existing| {
            existing.has_kernel |= sym.has_kernel;
            existing.has_compiled_source |= sym.has_compiled_source;
            existing.exported |= sym.exported;
            existing.is_higher_order |= sym.is_higher_order;
            // Prefer a present scheme; the typed-interface projection carries it,
            // the kernel seed does not.
            if matches!(existing.scheme, SchemeState::Unschemed) {
                existing.scheme = sym.scheme.clone();
            }
        })
        .or_insert(sym);
}

/// Whether a scheme takes or returns a function.
///
/// Walks the top-level arrow spine: a parameter that is itself a function, or a
/// function-typed final result, makes the symbol higher-order — the property the
/// composition column probes (`map`/`andThen`/`map2` and friends). Exhaustive
/// over every `TyDoc` variant so a new shape added there must be classified
/// here rather than silently falling through a wildcard arm.
fn scheme_is_higher_order(ty: &TyDoc) -> bool {
    match ty {
        TyDoc::Fun(param, result) => {
            matches!(param.as_ref(), TyDoc::Fun(..)) || scheme_is_higher_order(result)
        }
        TyDoc::Con { .. } | TyDoc::Var(_) | TyDoc::Unit | TyDoc::Tuple(_) | TyDoc::Record(_) => {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tydoc_variant_is_classified_without_a_wildcard() {
        assert!(!scheme_is_higher_order(&TyDoc::Unit));
        assert!(!scheme_is_higher_order(&TyDoc::Var("a".into())));
        assert!(!scheme_is_higher_order(&TyDoc::Con {
            module: "".into(),
            name: "Int".into(),
            args: Box::new([]),
        }));
        assert!(!scheme_is_higher_order(&TyDoc::Tuple(Box::new([
            TyDoc::Unit,
            TyDoc::Unit
        ]))));
        assert!(!scheme_is_higher_order(&TyDoc::Record(Box::new([(
            "x".into(),
            TyDoc::Unit
        )]))));
        // `a -> b`: first-order (neither side is itself a function).
        assert!(!scheme_is_higher_order(&TyDoc::Fun(
            Box::new(TyDoc::Var("a".into())),
            Box::new(TyDoc::Var("b".into())),
        )));
        // `(a -> b) -> a -> b`: a function-typed parameter makes it higher-order.
        assert!(scheme_is_higher_order(&TyDoc::Fun(
            Box::new(TyDoc::Fun(
                Box::new(TyDoc::Var("a".into())),
                Box::new(TyDoc::Var("b".into()))
            )),
            Box::new(TyDoc::Fun(
                Box::new(TyDoc::Var("a".into())),
                Box::new(TyDoc::Var("b".into()))
            )),
        )));
        // `a -> a -> b`: a curried result is still first-order.
        assert!(!scheme_is_higher_order(&TyDoc::Fun(
            Box::new(TyDoc::Var("a".into())),
            Box::new(TyDoc::Fun(
                Box::new(TyDoc::Var("a".into())),
                Box::new(TyDoc::Var("b".into()))
            )),
        )));
        // `a -> (a -> b) -> b`: a function-typed later parameter makes it
        // higher-order.
        assert!(scheme_is_higher_order(&TyDoc::Fun(
            Box::new(TyDoc::Var("a".into())),
            Box::new(TyDoc::Fun(
                Box::new(TyDoc::Fun(
                    Box::new(TyDoc::Var("a".into())),
                    Box::new(TyDoc::Var("b".into()))
                )),
                Box::new(TyDoc::Var("b".into()))
            )),
        )));
    }

    #[test]
    fn the_live_stdlib_surface_enumerates_a_non_vacuous_row_set() {
        let rows = StdlibSurface
            .all()
            .expect("the live stdlib surface must enumerate");
        assert!(
            !rows.is_empty(),
            "the stdlib surface must not be vacuously empty"
        );
    }

    #[test]
    fn an_unparsable_module_is_a_typed_parse_error() {
        let mut by_key = BTreeMap::new();
        let segments = vec!["Ipe".to_owned(), "NotReal".to_owned()];
        let result = merge_exposing(
            &mut by_key,
            &segments,
            "module Ipe.NotReal exposing ((((",
            None,
        );
        assert!(matches!(result, Err(CoverageError::Parse { .. })));
    }

    #[test]
    fn a_module_that_fails_to_typecheck_is_a_typed_extract_error() {
        let mut by_key = BTreeMap::new();
        let segments = vec!["Ipe".to_owned(), "NotReal".to_owned()];
        let source = "module Ipe.NotReal exposing (bad)\n\nbad : Int\nbad = \"not an Int\"\n";
        let result = merge_one_compiled_module(&mut by_key, &segments, source);
        assert!(matches!(result, Err(CoverageError::Extract { .. })));
    }

    #[test]
    fn a_shape_scoped_qualifier_is_shape_scoped_not_an_invented_module() {
        // `Cmd`/`Sub` have no standalone module by design: the home says so in
        // its type, so no consumer can page `Ipe.Cmd` as if it existed.
        let empty = BTreeMap::new();
        for qualifier in SHAPE_SCOPED_QUALIFIERS {
            let home = kernel_module_path(qualifier, &empty, &empty, &empty);
            assert!(
                matches!(home, Ok(KernelHome::ShapeScoped)),
                "{qualifier}: {home:?}"
            );
        }
    }

    #[test]
    fn an_unresolved_non_shape_qualifier_is_unknown_not_a_phantom_module() {
        // A new kernel family no tier homes must refuse by name, never fall
        // back to an invented `Ipe.<qualifier>` path.
        let empty = BTreeMap::new();
        let result = kernel_module_path("NoSuchFamily", &empty, &empty, &empty);
        assert!(matches!(
            result,
            Err(CoverageError::UnknownQualifier {
                qualifier: "NoSuchFamily"
            })
        ));
    }

    #[test]
    fn an_underscore_qualifier_is_internal_before_any_tier() {
        // Even a qualifier a tier could home is internal when `_`-prefixed.
        let homed: QualifierModuleMap =
            BTreeMap::from([("_internal_".to_owned(), vec!["Ipe".to_owned()])]);
        let empty = BTreeMap::new();
        let home = kernel_module_path("_internal_", &homed, &empty, &empty);
        assert!(matches!(home, Ok(KernelHome::Internal)), "{home:?}");
    }

    #[test]
    fn a_final_segment_two_compiled_modules_share_homes_no_qualifier() {
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for m in ipe_stdlib::COMPILED_STD_MODULES {
            if let Some(last) = segments_of(m.dotted).last() {
                *seen.entry(last.clone()).or_default() += 1;
            }
        }
        let shared: Vec<&String> = seen
            .iter()
            .filter(|(_, n)| **n > 1)
            .map(|(last, _)| last)
            .collect();
        assert!(
            !shared.is_empty(),
            "control: the live stdlib has at least one shared final segment"
        );
        let (_, _, by_last) = qualifier_lookup_tables();
        for last in shared {
            assert!(
                !by_last.contains_key(last),
                "`{last}` is shared by two modules and must home no qualifier"
            );
        }
    }

    #[test]
    fn an_override_entry_whose_module_is_unknown_is_a_typed_drift_error() {
        // `Key` has a real `QUALIFIER_MODULE_OVERRIDES` entry (`Ipe.Crypto`),
        // but with every real-module source empty, that entry cannot be
        // cross-checked against anything -- the override has drifted from the
        // module lists, and that must surface, not silently stand in.
        let empty = BTreeMap::new();
        let result = kernel_module_path("Key", &empty, &empty, &empty);
        assert!(matches!(
            result,
            Err(CoverageError::UnknownQualifier { qualifier: "Key" })
        ));
    }
}
