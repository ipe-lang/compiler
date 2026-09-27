//! Positive and refusal tests for the ported elm-review rules:
//! `simplify-double-not`, `simplify-map-identity`, `simplify-cons-append`,
//! `no-redundant-cons`, `no-redundant-concat`, and `no-missing-type-annotation`.
//!
//! Every fixture is asserted to parse first: the engine skips a module that
//! fails to parse, so an unparsed negative fixture would pass vacuously.

use ipe_intern::Interner;

use crate::{Finding, LintConfig, SourceModule, read_lint_config, run};

fn module(body: &str) -> SourceModule {
    SourceModule {
        module: vec!["Main".to_owned()],
        source: format!("module Main exposing (main)\n\nmain =\n{body}\n"),
    }
}

fn parses(src: &str) -> bool {
    ipe_parse::parse_module(src, &mut Interner::new()).is_ok()
}

/// The findings of `rule` over `body`, after asserting the fixture parses.
/// Uses the registry default severity, matching `style_tests.rs`'s harness —
/// correct for every rule here except `no-missing-type-annotation`, which ships
/// `Allow` by default and gets its own helper below.
fn findings(rule: &str, body: &str) -> Vec<Finding> {
    let m = module(body);
    assert!(parses(&m.source), "fixture must parse:\n{}", m.source);
    run(&[m], &LintConfig::default())
        .findings
        .into_iter()
        .filter(|f| f.rule == rule)
        .collect()
}

fn help_of(rule: &str, body: &str) -> String {
    findings(rule, body)
        .iter()
        .map(|f| f.help.join("\n"))
        .collect::<Vec<_>>()
        .join("\n")
}

// ── simplify-double-not ──────────────────────────────────────────────────────

const DOUBLE_NOT: &str = "simplify-double-not";

#[test]
fn double_not_fires() {
    assert!(help_of(DOUBLE_NOT, "    not (not ok)").contains("write `ok`"));
}

#[test]
fn single_not_is_fine() {
    assert!(findings(DOUBLE_NOT, "    not ok").is_empty());
}

#[test]
fn triple_not_reports_each_nested_pair() {
    // `not (not (not ok))` nests two overlapping `not (not _)` pairs — the
    // outer wrapping `not ok`, the inner wrapping `ok` — and each fires once.
    let hits = findings(DOUBLE_NOT, "    not (not (not ok))");
    assert_eq!(hits.len(), 2);
    let help: Vec<String> = hits.iter().map(|f| f.help.join("\n")).collect();
    assert!(help.iter().any(|h| h.contains("write `not ok`")));
    assert!(help.iter().any(|h| h.contains("write `ok`")));
}

// ── simplify-map-identity ────────────────────────────────────────────────────

const MAP_IDENTITY: &str = "simplify-map-identity";

#[test]
fn map_identity_fires_fully_applied() {
    assert!(help_of(MAP_IDENTITY, "    List.map identity xs").contains("write `xs`"));
}

#[test]
fn map_identity_fires_partially_applied() {
    assert!(help_of(MAP_IDENTITY, "    List.map identity").contains("write `identity`"));
}

#[test]
fn map_with_a_real_function_is_fine() {
    assert!(findings(MAP_IDENTITY, "    List.map fmt xs").is_empty());
}

// ── simplify-cons-append ─────────────────────────────────────────────────────

const CONS_APPEND: &str = "simplify-cons-append";

#[test]
fn single_element_append_fires() {
    assert!(help_of(CONS_APPEND, "    [ a ] ++ xs").contains("write `a :: xs`"));
}

#[test]
fn multi_element_append_is_fine() {
    assert!(findings(CONS_APPEND, "    [ a, b ] ++ xs").is_empty());
}

#[test]
fn appending_a_non_literal_is_fine() {
    assert!(findings(CONS_APPEND, "    ys ++ xs").is_empty());
}

// ── no-redundant-cons ─────────────────────────────────────────────────────────

const REDUNDANT_CONS: &str = "no-redundant-cons";

#[test]
fn cons_onto_list_literal_fires() {
    assert!(help_of(REDUNDANT_CONS, "    x :: [ a, b ]").contains("write `[ x, a, b ]`"));
}

#[test]
fn cons_onto_empty_list_fires() {
    assert!(help_of(REDUNDANT_CONS, "    x :: []").contains("write `[ x ]`"));
}

#[test]
fn cons_onto_a_name_is_fine() {
    assert!(findings(REDUNDANT_CONS, "    x :: rest").is_empty());
}

// ── no-redundant-concat ───────────────────────────────────────────────────────

const REDUNDANT_CONCAT: &str = "no-redundant-concat";

#[test]
fn list_concat_of_one_fires() {
    assert!(help_of(REDUNDANT_CONCAT, "    List.concat [ xs ]").contains("write `xs`"));
}

#[test]
fn string_concat_of_one_fires() {
    assert!(help_of(REDUNDANT_CONCAT, "    String.concat [ s ]").contains("write `s`"));
}

#[test]
fn concat_of_several_is_fine() {
    assert!(findings(REDUNDANT_CONCAT, "    List.concat [ xs, ys ]").is_empty());
}

// ── no-missing-type-annotation ────────────────────────────────────────────────
//
// `Allow` by default, so these tests build a `LintConfig` through the real
// `lint.ipe` reader (`Lint.warn "no-missing-type-annotation"`) rather than the
// registry default — exercising the same opt-in path a project would use.

const MISSING_ANNOTATION: &str = "no-missing-type-annotation";

fn warn_on_missing_annotation() -> LintConfig {
    let src = "module Lint exposing (lint)\n\nlint =\n    Lint.config\n        |> Lint.warn \"no-missing-type-annotation\"\n";
    read_lint_config(src, "lint.ipe").expect("valid lint.ipe fixture")
}

fn findings_with(config: &LintConfig, rule: &str, src: &str) -> Vec<Finding> {
    assert!(parses(src), "fixture must parse:\n{src}");
    let m = SourceModule {
        module: vec!["Main".to_owned()],
        source: src.to_owned(),
    };
    run(&[m], config)
        .findings
        .into_iter()
        .filter(|f| f.rule == rule)
        .collect()
}

#[test]
fn unannotated_top_level_value_fires_once_opted_in() {
    let src = "module Main exposing (main)\n\nmain =\n    1\n";
    let hits = findings_with(&warn_on_missing_annotation(), MISSING_ANNOTATION, src);
    assert_eq!(hits.len(), 1);
    assert!(
        hits.first()
            .expect("exactly one finding")
            .help
            .join("\n")
            .contains("add a `main : T` signature")
    );
}

#[test]
fn annotated_top_level_value_is_fine() {
    let src = "module Main exposing (main)\n\nmain : Int\nmain =\n    1\n";
    let hits = findings_with(&warn_on_missing_annotation(), MISSING_ANNOTATION, src);
    assert!(hits.is_empty());
}

#[test]
fn rule_is_allow_by_default() {
    let src = "module Main exposing (main)\n\nmain =\n    1\n";
    let hits = findings_with(&LintConfig::default(), MISSING_ANNOTATION, src);
    assert!(hits.is_empty());
}
