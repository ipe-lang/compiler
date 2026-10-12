//! A qualifier naming a known but unimported module asks for its import
//! (IPE-N0034), and the did-you-mean list never offers a qualifier the module
//! could not use.

use std::collections::BTreeMap;

use ipe_canon::{ModuleCatalog, ModuleExports, ModuleOrigin, canonicalise_module_in_project};
use ipe_diagnostics::{Diagnostic, NameError, StdlibReach};
use ipe_intern::{Interner, Symbol};

const UTIL: &str = "module Lib.Util exposing (..)\n\nf : Int -> Int\nf n =\n    n\n";

/// Canonicalise `sources` in order against `catalog`, each seeing the exports
/// of every module before it; the last module's error. A source set that
/// canonicalises cleanly fails the calling test.
#[allow(clippy::expect_used)] // a source set that canonicalises cleanly IS the failure
fn last_error(sources: &[&str], catalog: &[&str]) -> Diagnostic {
    let catalog = ModuleCatalog::new(catalog.iter().map(|m| Box::<str>::from(*m)));
    let mut interner = Interner::new();
    let mut deps: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
    let mut last = None;
    for src in sources {
        let result = ipe_parse::parse_module(src, &mut interner).and_then(|parsed| {
            let expected = parsed.name.value.clone();
            let borrowed: BTreeMap<Vec<Symbol>, &ModuleExports> =
                deps.iter().map(|(k, v)| (k.clone(), v)).collect();
            canonicalise_module_in_project(
                &parsed,
                &expected,
                &borrowed,
                &catalog,
                ModuleOrigin::User,
                &mut interner,
            )
        });
        match result {
            Ok((_, exports)) => {
                deps.insert(exports.path.clone(), exports);
                last = None;
            }
            Err(diag) => {
                last = Some(diag);
                break;
            }
        }
    }
    last.expect("expected a canonicalisation error, got none")
}

/// The candidates of an IPE-N0034 diagnostic, or `None` for any other.
fn import_candidates(diag: &Diagnostic) -> Option<Vec<&str>> {
    match diag {
        Diagnostic::Name {
            msg: NameError::ImportRequired { candidates, .. },
            ..
        } => Some(candidates.iter().map(|c| &**c).collect()),
        _ => None,
    }
}

/// The did-you-mean names of an unknown-module diagnostic, or `None` for any other.
fn unknown_module_suggestions(diag: &Diagnostic) -> Option<Vec<&str>> {
    match diag {
        Diagnostic::Name {
            msg: NameError::UnknownModule { suggestions, .. },
            ..
        } => Some(suggestions.names.iter().map(|c| &**c).collect()),
        _ => None,
    }
}

#[test]
fn unimported_compiled_std_qualifier_is_n0034() {
    let src =
        "module Main exposing (main)\n\nmain : List Int\nmain =\n    List.map identity [ 1 ]\n";
    let diag = last_error(&[src], &["Ipe.List"]);
    assert_eq!(diag.code().as_str(), "IPE-N0034", "{diag:?}");
    assert_eq!(import_candidates(&diag), Some(vec!["Ipe.List"]), "{diag:?}");
}

#[test]
fn unimported_compiled_std_type_is_n0034() {
    let src = "module Main exposing (x)\n\nx : Dict.Dict String Int -> Int\nx d =\n    1\n";
    let diag = last_error(&[src], &["Ipe.Dict"]);
    assert_eq!(diag.code().as_str(), "IPE-N0034", "{diag:?}");
    assert!(
        import_candidates(&diag).is_some_and(|c| c.contains(&"Ipe.Dict")),
        "{diag:?}"
    );
}

#[test]
fn unimported_project_module_is_n0034() {
    let src = "module Main exposing (main)\n\nmain : Int\nmain =\n    Util.f 1\n";
    let diag = last_error(&[src], &["Main", "Util"]);
    assert_eq!(diag.code().as_str(), "IPE-N0034", "{diag:?}");
    assert_eq!(import_candidates(&diag), Some(vec!["Util"]), "{diag:?}");
}

#[test]
fn two_catalog_modules_same_last_segment_list_both() {
    let src = "module Main exposing (main)\n\nmain : Int\nmain =\n    Util.f 1\n";
    let diag = last_error(&[src], &["Main", "Lib.Util", "App.Util"]);
    assert_eq!(diag.code().as_str(), "IPE-N0034", "{diag:?}");
    assert_eq!(
        import_candidates(&diag),
        Some(vec!["App.Util", "Lib.Util"]),
        "{diag:?}"
    );
}

/// `Hosts` is one edit from the gated kernel qualifier `Host`, and `Lsit` one
/// transposition from the unimported `List`: neither is offered.
#[test]
fn gated_unimported_qualifier_never_suggested() {
    for (expr, absent) in [("Hosts.name", "Host"), ("Lsit.map identity [ 1 ]", "List")] {
        let src = format!("module Main exposing (main)\n\nmain =\n    {expr}\n");
        let diag = last_error(&[src.as_str()], &["Main", "Ipe.List"]);
        let names = unknown_module_suggestions(&diag).expect("expected IPE-N0004");
        assert!(!names.contains(&absent), "{expr}: {names:?}");
        assert!(!names.contains(&"Host"), "{expr}: {names:?}");
    }
}

/// The usable-qualifier filter keeps an imported module: a typo of it is still
/// suggested.
#[test]
fn imported_qualifier_still_suggested() {
    let src =
        "module Main exposing (main)\n\nimport Lib.Util\n\nmain : Int\nmain =\n    Utli.f 1\n";
    let diag = last_error(&[UTIL, src], &["Main", "Lib.Util"]);
    let names = unknown_module_suggestions(&diag).expect("expected IPE-N0004");
    assert!(names.contains(&"Util"), "{names:?}");
}

/// The module and alias an IPE-N0034 names as already imported, or `None`.
fn imported_as(diag: &Diagnostic) -> Option<(&str, &str)> {
    match diag {
        Diagnostic::Name {
            msg:
                NameError::ImportRequired {
                    imported_as: Some(imported),
                    ..
                },
            ..
        } => Some((&*imported.module, &*imported.alias)),
        _ => None,
    }
}

/// The qualifier an IPE-N0034 reports as reached, or `None`.
fn reached_qualifier(diag: &Diagnostic) -> Option<&str> {
    match diag {
        Diagnostic::Name {
            msg:
                NameError::ImportRequired {
                    reached: StdlibReach::Qualifier(qualifier),
                    ..
                },
            ..
        } => Some(qualifier),
        _ => None,
    }
}

/// A module imported under an alias is reachable only under that alias:
/// spelling its own name is IPE-N0034 naming the alias to write.
#[test]
fn aliased_module_spelled_by_name_names_the_alias() {
    let src =
        "module Main exposing (main)\n\nimport Lib.Util as U\n\nmain : Int\nmain =\n    Util.f 1\n";
    let diag = last_error(&[UTIL, src], &["Main", "Lib.Util"]);
    assert_eq!(diag.code().as_str(), "IPE-N0034", "{diag:?}");
    assert_eq!(reached_qualifier(&diag), Some("Util"), "{diag:?}");
    assert_eq!(imported_as(&diag), Some(("Lib.Util", "U")), "{diag:?}");
    assert_eq!(import_candidates(&diag), Some(vec!["Lib.Util"]), "{diag:?}");
}

/// The same holds for a gated kernel module imported under an alias.
#[test]
fn aliased_kernel_module_spelled_by_name_names_the_alias() {
    let src = "module Main exposing (main)\n\nimport Ipe.Crypto as C\n\nmain =\n    Crypto.sha256 \"x\"\n";
    let diag = last_error(&[src], &["Main"]);
    assert_eq!(diag.code().as_str(), "IPE-N0034", "{diag:?}");
    assert_eq!(reached_qualifier(&diag), Some("Crypto"), "{diag:?}");
    assert_eq!(imported_as(&diag), Some(("Ipe.Crypto", "C")), "{diag:?}");
}

/// A bare use with no import of the module names no alias.
#[test]
fn unimported_module_names_no_alias() {
    let src = "module Main exposing (main)\n\nmain =\n    Crypto.sha256 \"x\"\n";
    let diag = last_error(&[src], &["Main"]);
    assert_eq!(diag.code().as_str(), "IPE-N0034", "{diag:?}");
    assert_eq!(imported_as(&diag), None, "{diag:?}");
    assert_eq!(
        import_candidates(&diag),
        Some(vec!["Ipe.Crypto"]),
        "{diag:?}"
    );
}

/// `Crpyto` is one transposition from the gated kernel qualifier `Crypto`; with
/// no `import Ipe.Crypto` it is never offered.
#[test]
fn gated_unimported_kernel_qualifier_never_suggested() {
    let src = "module Main exposing (main)\n\nmain =\n    Crpyto.sha256 \"x\"\n";
    let diag = last_error(&[src], &["Main"]);
    let names = unknown_module_suggestions(&diag).expect("expected IPE-N0004");
    assert!(!names.contains(&"Crypto"), "{names:?}");
}
