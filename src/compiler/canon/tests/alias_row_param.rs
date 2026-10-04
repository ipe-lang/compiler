//! A type alias parameter in row position is substituted like any other.
//!
//! `type alias Named r = { r | name : String }` applied to a record extends that
//! record with `name`; applied to a type variable it stays open over that
//! variable. Local and imported aliases expand through the same walker, so both
//! give the same type, and an argument that cannot extend the record is refused.

use std::collections::BTreeMap;

use ipe_canon::ast::{Def, Module, Type};
use ipe_canon::{ModuleExports, canonicalise_module};
use ipe_diagnostics::{AliasExpansionKind, AliasRowFault, DResult, Diagnostic, NameError};
use ipe_intern::{Interner, Symbol};

const NAMED: &str = "module Lib.Named exposing (..)\n\n\
                     type alias Named r = { r | name : String }\n";

/// Canonicalise `sources` in order, each against the exports of every module
/// before it; returns the last module's result and the interner.
fn canonicalise_chain(sources: &[&str]) -> (DResult<(Module, ModuleExports)>, Interner) {
    let mut interner = Interner::new();
    let mut deps: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
    let mut last = None;
    for src in sources {
        let result = ipe_parse::parse_module(src, &mut interner).and_then(|parsed| {
            let expected = parsed.name.value.clone();
            canonicalise_module(&parsed, &expected, &deps, &mut interner)
        });
        if let Ok((_, exports)) = &result {
            deps.insert(exports.path.clone(), exports.clone());
        }
        last = Some(result);
        if last.as_ref().is_some_and(Result::is_err) {
            break;
        }
    }
    let result = last.unwrap_or_else(|| {
        Err(Diagnostic::CompilerBug {
            where_: "alias_row_param::canonicalise_chain",
            detail: "no module source given".into(),
        })
    });
    (result, interner)
}

/// The record parameter of the top-level function `name`'s annotation.
fn param<'m>(module: &'m Module, interner: &Interner, name: &str) -> Option<&'m Type> {
    module.defs.iter().find_map(|d| match d {
        Def::Typed {
            name: n,
            ty: Type::Lambda(arg, _),
            ..
        } if interner.resolve(n.value) == Some(name) => Some(arg.as_ref()),
        _ => None,
    })
}

/// The labels of `fields`, in order, as text.
fn labels(fields: &[(Symbol, Type)], interner: &Interner) -> Vec<String> {
    fields
        .iter()
        .filter_map(|(n, _)| interner.resolve(*n).map(str::to_owned))
        .collect()
}

/// The shape of a record type: its row variable's text (if open) and its labels.
fn record_shape(ty: &Type, interner: &Interner) -> Option<(Option<String>, Vec<String>)> {
    match ty {
        Type::Record(fields) => Some((None, labels(fields, interner))),
        Type::RecordOpen(row, fields) => Some((
            interner.resolve(*row).map(str::to_owned),
            labels(fields, interner),
        )),
        _ => None,
    }
}

/// The record shape of function `name`'s parameter in the last of `sources`.
fn shape_of(sources: &[&str], name: &str) -> Option<(Option<String>, Vec<String>)> {
    let (result, i) = canonicalise_chain(sources);
    let Ok((module, _)) = result else {
        return None;
    };
    param(&module, &i, name).and_then(|t| record_shape(t, &i))
}

fn strings(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

/// A single module declaring `Named` and the function `f : <ann> -> Int`.
fn local(ann: &str) -> String {
    format!(
        "module Lib.Use exposing (..)\n\n\
         type alias Named r = {{ r | name : String }}\n\n\
         f : {ann} -> Int\n\
         f x = 1\n"
    )
}

/// A module importing `Named` and declaring `f : <ann> -> Int`.
fn importer(ann: &str) -> String {
    format!(
        "module Lib.Use exposing (..)\n\n\
         import Lib.Named exposing (Named)\n\n\
         f : {ann} -> Int\n\
         f x = 1\n"
    )
}

#[test]
fn row_param_closed_record_arg_extends() {
    assert_eq!(
        shape_of(&[&local("Named { age : Int }")], "f"),
        Some((None, strings(&["age", "name"]))),
        "a closed record argument gains the alias's own fields"
    );
}

#[test]
fn row_param_var_arg_becomes_row() {
    assert_eq!(
        shape_of(&[&local("Named a")], "f"),
        Some((Some("a".to_owned()), strings(&["name"]))),
        "a type-variable argument becomes the record's row"
    );
}

#[test]
fn row_param_open_record_arg_merges() {
    assert_eq!(
        shape_of(&[&local("Named { b | age : Int }")], "f"),
        Some((Some("b".to_owned()), strings(&["age", "name"]))),
        "an open record argument keeps its row and gains the alias's fields"
    );
}

#[test]
fn row_param_alias_of_alias() {
    let src = "module Lib.Use exposing (..)\n\n\
               type alias Named r = { r | name : String }\n\n\
               type alias Aged r = Named { r | age : Int }\n\n\
               f : Aged a -> Int\n\
               f x = 1\n";
    assert_eq!(
        shape_of(&[src], "f"),
        Some((Some("a".to_owned()), strings(&["age", "name"]))),
        "an alias whose body applies another row alias threads its own row through"
    );
}

#[test]
fn row_param_imported_parity() {
    for ann in ["Named { age : Int }", "Named a", "Named { b | age : Int }"] {
        let local_shape = shape_of(&[&local(ann)], "f");
        let imported_shape = shape_of(&[NAMED, &importer(ann)], "f");
        assert!(local_shape.is_some(), "`{ann}` must canonicalise locally");
        assert_eq!(
            local_shape, imported_shape,
            "a local and an imported `{ann}` must expand to the same record"
        );
    }
}

#[test]
fn exported_body_has_no_source_param() {
    let (result, i) = canonicalise_chain(&[NAMED]);
    let Ok((_, exports)) = result else {
        assert!(result.is_ok(), "Lib.Named must canonicalise: {result:?}");
        return;
    };
    let alias = exports
        .aliases
        .iter()
        .find_map(|(n, a)| (i.resolve(*n) == Some("Named")).then_some(a));
    let Some(alias) = alias else {
        assert!(alias.is_some(), "`Named` must be exported");
        return;
    };
    assert!(
        matches!(&alias.body, Type::RecordOpen(row, _) if alias.param_slots.first() == Some(row)),
        "the exported row must be the parameter's slot, got {:?}",
        alias.body
    );
    assert!(
        alias.free_vars.iter().all(|v| i.resolve(*v) != Some("r")),
        "the source parameter `r` must not escape as a free variable"
    );
}

/// The row-argument fault `result` was refused with, if any.
const fn row_fault<T>(result: &DResult<T>) -> Option<&AliasRowFault> {
    match result {
        Err(Diagnostic::Name {
            msg: NameError::AliasRowArgument { fault, .. },
            ..
        }) => Some(fault),
        _ => None,
    }
}

#[test]
fn row_param_non_record_arg_refused() {
    for ann in [
        "Named Int",
        "Named ( Int, Int )",
        "Named (Int -> Int)",
        "Named (Maybe Int)",
    ] {
        let (local_result, _) = canonicalise_chain(&[&local(ann)]);
        assert!(
            matches!(
                row_fault(&local_result),
                Some(AliasRowFault::NotARecord { .. })
            ),
            "a local `{ann}` must be refused with IPE-N0053, got {local_result:?}"
        );
        let (imported_result, _) = canonicalise_chain(&[NAMED, &importer(ann)]);
        assert!(
            matches!(
                row_fault(&imported_result),
                Some(AliasRowFault::NotARecord { .. })
            ),
            "an imported `{ann}` must be refused with IPE-N0053, got {imported_result:?}"
        );
    }
}

#[test]
fn row_param_label_clash_refused() {
    for ann in ["Named { name : Int }", "Named (Named { age : Int })"] {
        for sources in [vec![local(ann)], vec![NAMED.to_owned(), importer(ann)]] {
            let refs: Vec<&str> = sources.iter().map(String::as_str).collect();
            let (result, _) = canonicalise_chain(&refs);
            assert!(
                matches!(
                    row_fault(&result),
                    Some(AliasRowFault::FieldClash { field }) if &**field == "name"
                ),
                "`{ann}` repeats `name` and must be refused with IPE-N0053, got {result:?}"
            );
        }
    }
}

#[test]
fn duplicate_record_type_label_refused() {
    for ann in ["{ a : Int, a : String }", "{ r | a : Int, a : String }"] {
        let src = format!(
            "module Lib.Use exposing (..)\n\n\
             f : {ann} -> Int\n\
             f x = 1\n"
        );
        let (result, _) = canonicalise_chain(&[&src]);
        assert!(
            matches!(
                &result,
                Err(Diagnostic::Name {
                    span,
                    msg: NameError::DuplicateValue { name, first },
                }) if &**name == "a" && span.lo > first.lo
            ),
            "`{ann}` repeats `a` and must be IPE-N0010 at the second label, got {result:?}"
        );
    }
}

/// `true` when `result` is the node-ceiling refusal (IPE-N0032, `Nodes`).
const fn is_node_ceiling<T>(result: &DResult<T>) -> bool {
    matches!(
        result,
        Err(Diagnostic::Name {
            msg: NameError::TypeExpansionTooDeep {
                kind: AliasExpansionKind::Nodes,
                ..
            },
            ..
        })
    )
}

/// `T4`, an imported alias expanding to an 11 111-node tuple.
///
/// Instantiating an imported alias charges one node per body node, so each
/// `T4` use costs about 11k nodes before any row copy.
const WIDE: &str = "module Lib.Wide exposing (..)\n\n\
                    type alias Ten a = ( a, a, a, a, a, a, a, a, a, a )\n\n\
                    type alias T4 = Ten (Ten (Ten (Ten Int)))\n";

/// Six row arguments, each a record holding a `T4`.
///
/// The `T4` expansions alone (~67k nodes) stay under the 100k ceiling; copying
/// every argument into its row doubles that, so the ceiling is reached only
/// when row copies are charged.
const WIDE_ROWS: &str = "type alias Big = \
     ( Named { w : T4 }, Named { w : T4 }, Named { w : T4 }, \
     Named { w : T4 }, Named { w : T4 }, Named { w : T4 } )\n";

#[test]
fn row_param_expansion_charges_ceiling() {
    let local_src = format!(
        "module Lib.Big exposing (..)\n\n\
         import Lib.Wide exposing (T4)\n\n\
         type alias Named r = {{ r | name : String }}\n\n\
         {WIDE_ROWS}"
    );
    let (local_result, _) = canonicalise_chain(&[WIDE, &local_src]);
    assert!(
        is_node_ceiling(&local_result),
        "copied local row arguments must spend the node ceiling, got {local_result:?}"
    );
    let imported_src = format!(
        "module Lib.Big exposing (..)\n\n\
         import Lib.Wide exposing (T4)\n\
         import Lib.Named exposing (Named)\n\n\
         {WIDE_ROWS}"
    );
    let (imported_result, _) = canonicalise_chain(&[WIDE, NAMED, &imported_src]);
    assert!(
        is_node_ceiling(&imported_result),
        "copied imported row arguments must spend the node ceiling, got {imported_result:?}"
    );
}

/// `Big`, a parameterless alias expanding to a 61 111-node tuple: more than
/// half the node ceiling, so charging any of its nodes twice exceeds it.
const HALF_CEILING_ALIASES: &str = "\
    type alias A0 = ( Int, Int, Int, Int, Int, Int, Int, Int, Int, Int )\n\n\
    type alias A1 = ( A0, A0, A0, A0, A0, A0, A0, A0, A0, A0 )\n\n\
    type alias A2 = ( A1, A1, A1, A1, A1, A1, A1, A1, A1, A1 )\n\n\
    type alias A3 = ( A2, A2, A2, A2, A2, A2, A2, A2, A2, A2 )\n\n\
    type alias Big = ( A3, A3, A3, A3, A3 )\n";

#[test]
fn alias_declaration_check_does_not_halve_ceiling() {
    let src = format!("module Lib.Use exposing (..)\n\n{HALF_CEILING_ALIASES}");
    let (result, _) = canonicalise_chain(&[&src]);
    assert!(
        result.is_ok(),
        "a body within the node ceiling must be accepted at its declaration, got {result:?}"
    );
}

#[test]
fn parameterless_local_alias_charges_body_once() {
    let src = format!(
        "module Lib.Use exposing (..)\n\n{HALF_CEILING_ALIASES}\n\
         f : Big -> Int\n\
         f x = 1\n"
    );
    let (result, _) = canonicalise_chain(&[&src]);
    assert!(
        result.is_ok(),
        "a parameterless alias within the node ceiling must expand at its use site, got {result:?}"
    );
}

#[test]
fn row_param_threaded_beside_value_param() {
    // `Wrap`'s slots and `Named`'s share their spelling; the inner expansion
    // must leave the outer slots for the outer substitution.
    let src = "module Lib.Use exposing (..)\n\n\
               type alias Named r = { r | name : String }\n\n\
               type alias Wrap a r = Named { r | v : a }\n\n\
               f : Wrap Int b -> Int\n\
               f x = 1\n";
    assert_eq!(
        shape_of(&[src], "f"),
        Some((Some("b".to_owned()), strings(&["v", "name"]))),
        "the outer row argument fills the inner alias's row"
    );
    let (result, i) = canonicalise_chain(&[src]);
    let field_v = result
        .as_ref()
        .ok()
        .and_then(|(m, _)| match param(m, &i, "f") {
            Some(Type::RecordOpen(_, fields)) => fields
                .iter()
                .find(|(n, _)| i.resolve(*n) == Some("v"))
                .map(|(_, ty)| ty.clone()),
            _ => None,
        });
    assert!(
        matches!(&field_v, Some(Type::Con { args, .. }) if args.is_empty()),
        "`v` must be the value argument `Int`, got {field_v:?}"
    );
}

#[test]
fn row_param_chain_across_modules() {
    let aged = "module Lib.Aged exposing (..)\n\n\
                import Lib.Named exposing (Named)\n\n\
                type alias Aged r = Named { r | age : Int }\n";
    let user = "module Lib.Use exposing (..)\n\n\
                import Lib.Aged exposing (Aged)\n\n\
                f : Aged { id : Int } -> Int\n\
                f x = 1\n";
    assert_eq!(
        shape_of(&[NAMED, aged, user], "f"),
        Some((None, strings(&["id", "age", "name"]))),
        "an exported alias over another module's row alias threads the use site's record"
    );
}
