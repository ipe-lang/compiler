#![forbid(unsafe_code)]
//! The diagnostic coverage-matrix gate: the diagnostic surface enumerates every
//! code in [`ipe_diagnostics::ALL_CODES`] and the aspect columns judge each
//! on `has-conforming-explain-page`, `documented`, and `refusal-tested`.
//!
//! This surface mechanises the "prove the refusals" principle: every rejection
//! path the compiler can take must have a standing test that drives it. A code
//! with no such test is a Hole — a rejection one edit can delete unnoticed.
//!
//! The [`ALLOWLIST`] records every known, tracked gap with a reason. An
//! allowlisted entry that is no longer a Hole fails the gate (stale allowlist);
//! an unexpected Hole that is not listed also fails. Both directions must be
//! clean.

use ipe::coverage::contract::Surface;
use ipe::coverage::diagnostic_surface::DiagnosticSurface;
use ipe::coverage::matrix;

/// Known, tracked gaps in the `refusal-tested` column.
///
/// Each entry is `(aspect, code-wire-string, reason)`. A code here is a real,
/// acknowledged gap — the test does not yet exist; it is NOT a signal that the
/// rejection path is unsound. Add a negative-suite test and remove the entry
/// when the gap is closed.
///
/// Codes are grouped by family and reason for clarity.
const ALLOWLIST: &[(&str, &str, &str)] = &[
    // ── IPE-I#### (internal compiler errors / ICEs) ──────────────────────────
    // ICE and intern codes are invariant violations that require deliberate
    // compiler corruption to trigger from user source. They cannot be reached
    // through normal user input — a test that produces them would break the
    // compiler-internal invariant being guarded.
    (
        "refusal-tested",
        "IPE-I0010",
        "intern: unresolved symbol requires deliberate interner corruption",
    ),
    (
        "refusal-tested",
        "IPE-I0011",
        "intern: symbol table exhausted requires deliberate interner corruption",
    ),
    (
        "refusal-tested",
        "IPE-I0100",
        "ICE: match on unknown variant requires compiler-internal corruption",
    ),
    (
        "refusal-tested",
        "IPE-I0101",
        "ICE: duplicate match arm requires compiler-internal corruption",
    ),
    (
        "refusal-tested",
        "IPE-I0102",
        "ICE: non-exhaustive match requires compiler-internal corruption",
    ),
    (
        "refusal-tested",
        "IPE-I0103",
        "ICE: match arm enum mismatch requires compiler-internal corruption",
    ),
    (
        "refusal-tested",
        "IPE-I0200",
        "ICE: no Rust name for symbol requires compiler-internal corruption",
    ),
    (
        "refusal-tested",
        "IPE-I0202",
        "ICE: cross-module type-name collision requires compiler-internal corruption",
    ),
    (
        "refusal-tested",
        "IPE-I0203",
        "ICE: golden anchor missing requires compiler-internal corruption",
    ),
    // ── IPE-L#### (lowering / not-yet-supported) ────────────────────────────
    (
        "refusal-tested",
        "IPE-L0100",
        "pattern kind gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-L0103",
        "function-valued parameter gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-L0104",
        "Task () gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-L0105",
        "parameter destructuring gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-L0110",
        "partial application gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-L0111",
        "generic record update gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-L0112",
        "nested constructor pattern gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-L0113",
        "constructor-as-fn gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-L0121",
        "succeed arity gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-L0122",
        "Web.route param-count gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-L0123",
        "Web.route builder gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-L0124",
        "Web.tea no-page field gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-L0129",
        "wasm routed gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-L0143",
        "row-generic field type mismatch gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-L0144",
        "row-generic non-record gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-L0145",
        "Store.eq field accessor gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-L0147",
        "CustomElement.node browser-only gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-L0153",
        "Ui.cells Cli shape gate not yet reached by any constant assertion or wire literal",
    ),
    // ── IPE-N#### (name resolution) ─────────────────────────────────────────
    (
        "refusal-tested",
        "IPE-N0030",
        "wasm server-module reachability not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-N0041",
        "Ipe.Codec.auto derivation gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-N0043",
        "config binding not threaded not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-N0045",
        "runtime shape selection gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-N0048",
        "the injective name fold disambiguates colliding Rust names, so N0048 fires only when every suffix up to the 1,000,000 ceiling is taken — driving it needs ~1M colliding definitions, impractical in the suite",
    ),
    // ── IPE-P#### (parse) ────────────────────────────────────────────────────
    (
        "refusal-tested",
        "IPE-P0018",
        "accessor-space gate not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-P0066",
        "doc-string on non-exported binding is a warning (not a hard rejection); needs a warning-surface test",
    ),
    (
        "refusal-tested",
        "IPE-P0067",
        "exported binding has no doc-string is a warning (not a hard rejection); needs a warning-surface test",
    ),
    (
        "refusal-tested",
        "IPE-P0070",
        "source-too-large refusal fires only above u32::MAX bytes; driving it needs a >4 GiB source, impractical in the suite",
    ),
    // ── IPE-T#### (type) ────────────────────────────────────────────────────
    (
        "refusal-tested",
        "IPE-T0003",
        "type inference step budget not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-T0011",
        "redundant case branch not yet reached by any constant assertion or wire literal",
    ),
    (
        "refusal-tested",
        "IPE-T0019",
        "or-pattern variable binding not yet reached by any constant assertion or wire literal",
    ),
];

#[test]
fn diagnostic_surface_is_non_empty() {
    let items = DiagnosticSurface.all();
    assert!(
        !items.is_empty(),
        "the diagnostic surface must enumerate at least one code",
    );
}

#[test]
fn diagnostic_surface_matches_all_codes_length() {
    use ipe_diagnostics::ALL_CODES;
    let items = DiagnosticSurface.all();
    assert_eq!(
        items.len(),
        ALL_CODES.len(),
        "the diagnostic surface must enumerate exactly ALL_CODES.len() items",
    );
}

#[test]
fn diagnostic_surface_is_deterministic() {
    let first: Vec<String> = DiagnosticSurface
        .all()
        .iter()
        .map(|c| c.as_str().to_owned())
        .collect();
    let second: Vec<String> = DiagnosticSurface
        .all()
        .iter()
        .map(|c| c.as_str().to_owned())
        .collect();
    assert_eq!(
        first, second,
        "two enumerations of the diagnostic surface must be byte-identical",
    );
}

#[test]
fn a_known_code_appears_on_the_surface() {
    use ipe_diagnostics::IPE_T0001;
    let items = DiagnosticSurface.all();
    assert!(
        items.contains(&IPE_T0001),
        "IPE-T0001 must appear on the diagnostic surface",
    );
}

#[test]
fn diagnostic_columns_pass_with_allowlist() {
    use std::fmt::Write as _;

    let report = matrix::run_diagnostic();

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
        "the diagnostic coverage columns must pass over the whole surface (or be \
         recorded in the allowlist with a tracking reason):\n{unexpected}\n\
         (allowlist has {} entr(y/ies))",
        ALLOWLIST.len(),
    );
}

#[test]
fn allowlisted_holes_are_still_real() {
    let report = matrix::run_diagnostic();
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

#[test]
fn explain_page_column_passes_for_all_codes() {
    // Every code must have a conforming explain page — this column is never
    // allowlisted, so a hole here is always an immediate failure.
    let report = matrix::run_diagnostic();
    let page_holes: Vec<_> = report
        .holes
        .iter()
        .filter(|h| h.aspect == "has-conforming-explain-page")
        .collect();
    assert!(
        page_holes.is_empty(),
        "every code must have a conforming explain page:\n{}",
        page_holes.iter().fold(String::new(), |mut s, h| {
            use std::fmt::Write as _;
            let _ = writeln!(s, "  HOLE [{}] {}: {}", h.aspect, h.symbol, h.message);
            s
        }),
    );
}
