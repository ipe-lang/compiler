#![forbid(unsafe_code)]
//! The stdlib coverage-matrix gate: the reconciled surface enumerates every
//! exported symbol, and the static aspect columns judge each on home, resolves,
//! closed-scheme, and layer-agreement.
//!
//! This is the spine that turns "no stdlib symbol is forgotten in any aspect"
//! into a checked property: one enumeration, one `surface × aspect` grid, a hole
//! named at its coordinate. A1 pins the surface's facets on a known symbol; A2
//! runs the four static columns over the WHOLE current surface.

use ipe::coverage::contract::{SchemeState, StdlibSymbol, Surface, SymbolKind};
use ipe::coverage::matrix;
use ipe::coverage::surface::StdlibSurface;

/// Find the reconciled symbol for a dotted path (`Ipe.List` + `map`).
fn find<'a>(
    symbols: &'a [StdlibSymbol],
    module: &[&str],
    name: &str,
    kind: SymbolKind,
) -> Option<&'a StdlibSymbol> {
    let module: Vec<String> = module.iter().map(|s| (*s).to_owned()).collect();
    symbols
        .iter()
        .find(|s| s.module == module && s.name == name && s.kind == kind)
}

// ── A1: the surface enumerates, deterministically, with the right facets ──────

#[test]
fn surface_is_non_empty() {
    let symbols = StdlibSurface
        .all()
        .expect("the live stdlib surface must enumerate");
    assert!(
        !symbols.is_empty(),
        "the reconciled stdlib surface must enumerate at least one symbol",
    );
}

#[test]
fn surface_is_deterministic_and_sorted() {
    let first = StdlibSurface
        .all()
        .expect("the live stdlib surface must enumerate");
    let second = StdlibSurface
        .all()
        .expect("the live stdlib surface must enumerate");
    assert_eq!(
        first, second,
        "the surface enumeration must be deterministic across calls",
    );

    let mut sorted = first.clone();
    sorted.sort();
    assert_eq!(
        first, sorted,
        "the surface must be sorted by (module, name, kind)",
    );
}

#[test]
fn list_map_has_the_right_facets() {
    let symbols = StdlibSurface
        .all()
        .expect("the live stdlib surface must enumerate");
    let map = find(&symbols, &["Ipe", "List"], "map", SymbolKind::Value)
        .expect("Ipe.List.map must be on the surface");

    assert_eq!(map.kind, SymbolKind::Value, "List.map is a value");
    assert!(map.exported, "List.map is in Ipe.List's `exposing (...)`");
    assert!(
        map.has_compiled_source || map.has_kernel,
        "List.map has a home — a compiled-source alias and/or a kernel",
    );
    assert!(
        map.is_higher_order,
        "List.map takes a function `(a -> b)` — it is higher-order",
    );
    assert!(
        matches!(map.scheme, SchemeState::Rendered(_)),
        "List.map's scheme projects through the typed interface",
    );
}

// ── A2: the four static columns pass over the WHOLE current surface ───────────

/// The pre-existing-hole allowlist. A real hole the static columns surface that
/// predates this gate is recorded here with a one-line reason, so the column
/// stays meaningful (never weakened) while the gate is not blocked on debt it
/// did not introduce.
///
/// Each entry is `(aspect, dotted-symbol, reason)`.
///
/// `Cmd` and `Sub` are the only genuinely home-less kernel qualifiers: they are
/// TEA-loop machinery that is always imported through the shape-scoped
/// `Ipe.Tea.<Shape>.Cmd` / `.Sub` paths rather than a standalone `Ipe.Cmd` /
/// `Ipe.Sub` module. A standalone module is deliberately absent (importing it
/// would create an ambiguous shape association); the qualifiers are internal
/// routing tokens, not importable paths. No `QUALIFIER_MODULE_OVERRIDES` entry
/// is possible without inventing a phantom module.
///
/// The original 14 `Attr`/`EmailAddress`/`Key`/`Mac`/`UiCells` entries were
/// resolved by wiring those qualifiers to their real compiled-source homes in
/// `coverage::surface::QUALIFIER_MODULE_OVERRIDES` (issue #1699).
const ALLOWLIST: &[(&str, &str, &str)] = &[
    (
        "home",
        "Ipe.Cmd.batch",
        "qualifier `Cmd` is shape-scoped (Ipe.Tea.<Shape>.Cmd); no standalone module by design",
    ),
    (
        "home",
        "Ipe.Cmd.map",
        "qualifier `Cmd` is shape-scoped (Ipe.Tea.<Shape>.Cmd); no standalone module by design",
    ),
    (
        "home",
        "Ipe.Cmd.none",
        "qualifier `Cmd` is shape-scoped (Ipe.Tea.<Shape>.Cmd); no standalone module by design",
    ),
    (
        "home",
        "Ipe.Cmd.perform",
        "qualifier `Cmd` is shape-scoped (Ipe.Tea.<Shape>.Cmd); no standalone module by design",
    ),
    (
        "home",
        "Ipe.Cmd.publish",
        "qualifier `Cmd` is shape-scoped (Ipe.Tea.<Shape>.Cmd); no standalone module by design",
    ),
    (
        "home",
        "Ipe.Cmd.publishNoEcho",
        "qualifier `Cmd` is shape-scoped (Ipe.Tea.<Shape>.Cmd); no standalone module by design",
    ),
    (
        "home",
        "Ipe.Sub.batch",
        "qualifier `Sub` is shape-scoped (Ipe.Tea.<Shape>.Sub); no standalone module by design",
    ),
    (
        "home",
        "Ipe.Sub.every",
        "qualifier `Sub` is shape-scoped (Ipe.Tea.<Shape>.Sub); no standalone module by design",
    ),
    (
        "home",
        "Ipe.Sub.map",
        "qualifier `Sub` is shape-scoped (Ipe.Tea.<Shape>.Sub); no standalone module by design",
    ),
    (
        "home",
        "Ipe.Sub.none",
        "qualifier `Sub` is shape-scoped (Ipe.Tea.<Shape>.Sub); no standalone module by design",
    ),
    (
        "home",
        "Ipe.Sub.subscribeTopic",
        "qualifier `Sub` is shape-scoped (Ipe.Tea.<Shape>.Sub); no standalone module by design",
    ),
    (
        "home",
        "Ipe.Sub.subscribeWebSocket",
        "qualifier `Sub` is shape-scoped (Ipe.Tea.<Shape>.Sub); no standalone module by design",
    ),
];

#[test]
fn static_columns_pass_over_the_whole_surface() {
    use std::fmt::Write as _;

    let report = matrix::run_static().expect("the stdlib matrix run must not fail closed");

    let mut unexpected = String::new();
    for h in report.holes.iter().filter(|h| {
        !ALLOWLIST
            .iter()
            .any(|(aspect, symbol, _)| *aspect == h.aspect && *symbol == h.symbol)
    }) {
        let _ = writeln!(
            unexpected,
            "  HOLE [{}] {}: {}",
            h.aspect, h.symbol, h.message
        );
    }

    assert!(
        unexpected.is_empty(),
        "the four static coverage columns must pass over the whole stdlib \
         surface (or be recorded in the allowlist with a tracking reason):\n{unexpected}\n\
         (allowlist has {} entr(y/ies))",
        ALLOWLIST.len(),
    );
}

#[test]
fn allowlisted_holes_are_still_real() {
    // Guard against a stale allowlist: every allowlisted coordinate must still be
    // a hole the run reports. A removed hole must be removed from the allowlist,
    // not left to rot.
    let report = matrix::run_static().expect("the stdlib matrix run must not fail closed");
    for (aspect, symbol, reason) in ALLOWLIST {
        let present = report
            .holes
            .iter()
            .any(|h| h.aspect == *aspect && h.symbol == *symbol);
        assert!(
            present,
            "allowlisted hole [{aspect}] {symbol} ({reason}) is no longer \
             reported — remove the stale allowlist entry",
        );
    }
}
