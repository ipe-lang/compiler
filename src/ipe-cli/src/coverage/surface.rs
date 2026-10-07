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

use std::collections::BTreeMap;

use ipe_diagnostics::{TyDoc, render_ty};
use ipe_intern::Interner;
use ipe_syntax::{Exposed, Exposing};
use ipe_types::{VarNamer, kernel_type_table, ty_to_doc};

use crate::api_surface::{self, ModuleApi};
use crate::coverage::contract::{StdlibSymbol, Surface, SymbolKind};

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

    fn all(&self) -> Vec<StdlibSymbol> {
        let mut by_key: BTreeMap<Key, StdlibSymbol> = BTreeMap::new();

        merge_compiled_source(&mut by_key);
        merge_kernels(&mut by_key);

        // `BTreeMap` iteration is sorted by the (module, name, kind) key, so the
        // result is deterministic without an explicit sort.
        by_key.into_values().collect()
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
fn merge_compiled_source(by_key: &mut BTreeMap<Key, StdlibSymbol>) {
    for module in ipe_stdlib::COMPILED_STD_MODULES {
        let segments = segments_of(module.dotted);
        let projected = api_surface::extract_stdlib_module(&segments, module.source)
            .ok()
            .and_then(|api| api.modules.get(&segments).cloned());

        merge_exposing(by_key, &segments, module.source, projected.as_ref());
    }
}

/// Fold one compiled-source module's `exposing (...)` members into the map,
/// enriched with schemes and constructors from its projected interface.
fn merge_exposing(
    by_key: &mut BTreeMap<Key, StdlibSymbol>,
    segments: &[String],
    source: &str,
    projected: Option<&ModuleApi>,
) {
    let mut interner = Interner::new();
    let Ok(parsed) = ipe_parse::parse_module(source, &mut interner) else {
        // A module that does not parse contributes nothing; the parse floor gate
        // owns that failure.
        return;
    };

    let exposed = match &parsed.exposing.value {
        // `exposing (..)` re-exports everything; fall back to the projected
        // interface as the export set. Compiled-source stdlib modules use
        // explicit lists, so this arm is a defensive fallback.
        Exposing::All => {
            if let Some(api) = projected {
                merge_projected_only(by_key, segments, api);
            }
            return;
        }
        Exposing::List(items) => items,
    };

    for item in exposed {
        match &item.value {
            Exposed::Value(sym) => {
                let Some(name) = interner.resolve(*sym) else {
                    continue;
                };
                let (scheme, higher_order) = projected
                    .and_then(|api| {
                        let sig = api.values.get(name)?;
                        let ho = api
                            .value_types
                            .get(name)
                            .is_some_and(scheme_is_higher_order);
                        Some((Some(sig.clone()), ho))
                    })
                    .unwrap_or((None, false));
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
                let Some(name) = interner.resolve(*sym) else {
                    continue;
                };
                insert(
                    by_key,
                    compiled_symbol(
                        segments.to_vec(),
                        name.to_owned(),
                        SymbolKind::Type,
                        None,
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
                                None,
                                false,
                            ),
                        );
                    }
                }
            }
        }
    }
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
                Some(signature.clone()),
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
                None,
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
                    None,
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
    scheme: Option<String>,
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
/// single source of truth for those mismatches; it is consulted before the
/// phantom fallback so the home column sees the real module rather than an
/// invented `Ipe.<qualifier>` path.
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
///    their module's dotted name or final segment.
/// 5. Phantom fallback `Ipe.<qualifier>` — homed under a non-existent path
///    so the home column flags it as unhomed.
fn kernel_module_path(
    qualifier: &str,
    qualifier_to_path: &BTreeMap<String, Vec<String>>,
    compiled_by_dotted: &BTreeMap<String, Vec<String>>,
    compiled_by_last_segment: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    if let Some(path) = qualifier_to_path.get(qualifier) {
        return path.clone();
    }
    let dotted = format!("Ipe.{qualifier}");
    if let Some(path) = compiled_by_dotted.get(&dotted) {
        return path.clone();
    }
    if let Some(path) = compiled_by_last_segment.get(qualifier) {
        return path.clone();
    }
    if let Some(segs) = QUALIFIER_MODULE_OVERRIDES
        .iter()
        .find(|(q, _)| *q == qualifier)
        .map(|(_, segs)| segs)
    {
        return segs.iter().map(|s| (*s).to_owned()).collect();
    }
    segments_of(&dotted)
}

/// Fold the kernel registry into the reconciliation map: each wired kernel
/// becomes a value symbol whose `has_kernel` facet is set, homed under its real
/// module path.
fn merge_kernels(by_key: &mut BTreeMap<Key, StdlibSymbol>) {
    let qualifier_to_path: BTreeMap<String, Vec<String>> = ipe_canon::STDLIB_MODULE_QUALIFIERS
        .iter()
        .map(|(segs, qualifier)| {
            (
                (*qualifier).to_owned(),
                segs.iter().map(|s| (*s).to_owned()).collect(),
            )
        })
        .collect();

    let compiled_by_dotted: BTreeMap<String, Vec<String>> = ipe_stdlib::COMPILED_STD_MODULES
        .iter()
        .map(|m| (m.dotted.to_owned(), segments_of(m.dotted)))
        .collect();

    let compiled_by_last_segment: BTreeMap<String, Vec<String>> = ipe_stdlib::COMPILED_STD_MODULES
        .iter()
        .filter_map(|m| {
            let segs = segments_of(m.dotted);
            segs.last().cloned().map(|last| (last, segs))
        })
        .collect();

    let schemes = kernel_schemes();

    for kernel in ipe_kernels::StdlibKernel::ALL {
        let def = kernel.def();
        // Internal or not-yet-registered qualifiers are excluded from the
        // resolvable surface, matching the canon-equality tripwire's rule.
        if def.qualifier.starts_with('_') {
            continue;
        }
        let module = kernel_module_path(
            def.qualifier,
            &qualifier_to_path,
            &compiled_by_dotted,
            &compiled_by_last_segment,
        );
        let (scheme, is_higher_order) = schemes
            .get(&(def.qualifier.to_owned(), def.name.to_owned()))
            .cloned()
            .unwrap_or((None, false));
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
}

/// Every kernel's rendered α-canonical scheme and higher-order flag, keyed by
/// `(qualifier, name)`.
///
/// Reads the same scheme table inference and `ipe doc` read, so a kernel-alias
/// member (`Ipe.List.map`, whose scheme lives in the kernel table rather than the
/// aliasing module's typed interface) carries its real signature on the surface.
fn kernel_schemes() -> BTreeMap<(String, String), (Option<String>, bool)> {
    let mut interner = Interner::new();
    let Ok(table) = kernel_type_table(&mut interner) else {
        return BTreeMap::new();
    };
    let mut out = BTreeMap::new();
    for (kernel, ty) in table {
        let def = kernel.def();
        let mut namer = VarNamer::new();
        let Ok(doc) = ty_to_doc(&ty, &interner, &mut namer) else {
            continue;
        };
        let higher_order = scheme_is_higher_order(&doc);
        out.insert(
            (def.qualifier.to_owned(), def.name.to_owned()),
            (Some(render_ty(&doc)), higher_order),
        );
    }
    out
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
            if existing.scheme.is_none() {
                existing.scheme.clone_from(&sym.scheme);
            }
        })
        .or_insert(sym);
}

/// Whether a scheme takes or returns a function.
///
/// Walks the top-level arrow spine: a parameter that is itself a function, or a
/// function-typed final result, makes the symbol higher-order — the property the
/// composition column probes (`map`/`andThen`/`map2` and friends).
fn scheme_is_higher_order(ty: &TyDoc) -> bool {
    match ty {
        TyDoc::Fun(param, result) => {
            matches!(param.as_ref(), TyDoc::Fun(..)) || scheme_is_higher_order(result)
        }
        _ => false,
    }
}
