//! A bare `Get` seen through two open imports is refused, never picked.
//!
//! `Ipe.Http` exposes `HttpMethod(Get, Post, ..)` and `Ipe.Html.Attributes`
//! exposes `Method(Get, Post)`. A module that opens both and writes a bare
//! `Get` (in an expression or a pattern) fails closed with IPE-N0024 naming
//! both modules; a qualified `A.Get` resolves to the form method.

use std::collections::BTreeMap;

use ipe_canon::ast::{Def, Expr_, Module};
use ipe_canon::{
    ModuleExports, ModuleOrigin, canonicalise_module, canonicalise_module_with_origin,
};
use ipe_diagnostics::{DResult, Diagnostic, NameError};
use ipe_intern::{Interner, Symbol};

/// The `HttpMethod` declaration of `Ipe.Http`, as the stdlib module declares it.
const HTTP_STUB: &str = "module Ipe.Http exposing (HttpMethod(..))\n\n\
                         type HttpMethod = Get | Post | Put | Delete | Patch | Head | Options\n";

/// The `Method` declaration of `Ipe.Html.Attributes`, whose `Get` and `Post`
/// share the names.
const ATTRIBUTES_STUB: &str = "module Ipe.Html.Attributes exposing (Method(..))\n\n\
                               type Method = Get | Post\n";

/// Canonicalise the stdlib `stubs` (as embedded stdlib modules) and then the
/// user module `main` against their exports.
fn canonicalise_main(stubs: &[&str], main: &str) -> (DResult<Module>, Interner) {
    let mut interner = Interner::new();
    let mut deps: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
    for stub in stubs {
        let stub_result = ipe_parse::parse_module(stub, &mut interner).and_then(|parsed| {
            let expected = parsed.name.value.clone();
            canonicalise_module_with_origin(
                &parsed,
                &expected,
                &deps,
                ModuleOrigin::EmbeddedStdlib,
                &mut interner,
            )
        });
        match stub_result {
            Ok((_, exports)) => {
                deps.insert(exports.path.clone(), exports);
            }
            Err(err) => return (Err(err), interner),
        }
    }
    let result = ipe_parse::parse_module(main, &mut interner).and_then(|parsed| {
        let expected = parsed.name.value.clone();
        canonicalise_module(&parsed, &expected, &deps, &mut interner).map(|(module, _)| module)
    });
    (result, interner)
}

/// The dot-joined home of the constructor `main`'s body names, if its body is a
/// bare `Get` reference.
fn main_get_home(module: &Module, interner: &Interner) -> Option<String> {
    let body = module.decls.values.iter().find_map(|def| match def {
        Def::Untyped { name, body, .. } | Def::Typed { name, body, .. }
            if interner.resolve(name.value) == Some("main") =>
        {
            Some(body)
        }
        Def::Untyped { .. } | Def::Typed { .. } => None,
    })?;
    let Expr_::VarCtor { home, name, .. } = &body.value else {
        return None;
    };
    if interner.resolve(*name) != Some("Get") {
        return None;
    }
    let segments: Option<Vec<&str>> = home.iter().map(|s| interner.resolve(*s)).collect();
    segments.map(|s| s.join("."))
}

/// Assert `result` is IPE-N0024 for `Get`, naming both defining modules.
#[track_caller]
fn assert_ambiguous_get(result: &DResult<Module>) {
    assert!(
        matches!(
            result,
            Err(Diagnostic::Name {
                msg: NameError::AmbiguousImport { .. },
                ..
            })
        ),
        "a bare `Get` under two open imports must be IPE-N0024, got {result:?}"
    );
    let Err(Diagnostic::Name {
        msg: NameError::AmbiguousImport { name, modules },
        ..
    }) = result
    else {
        return;
    };
    assert_eq!(&**name, "Get");
    let rendered: Vec<&str> = modules.iter().map(AsRef::as_ref).collect();
    assert_eq!(rendered, vec!["Ipe.Html.Attributes", "Ipe.Http"]);
}

#[test]
fn a_bare_get_under_both_open_imports_is_ambiguous() {
    let (result, _) = canonicalise_main(
        &[HTTP_STUB, ATTRIBUTES_STUB],
        "module Main exposing (main)\n\n\
         import Ipe.Http exposing (..)\n\
         import Ipe.Html.Attributes exposing (..)\n\n\
         main = Get\n",
    );
    assert_ambiguous_get(&result);
}

#[test]
fn a_bare_get_pattern_under_both_open_imports_is_ambiguous() {
    let (result, _) = canonicalise_main(
        &[HTTP_STUB, ATTRIBUTES_STUB],
        "module Main exposing (main)\n\n\
         import Ipe.Http exposing (..)\n\
         import Ipe.Html.Attributes exposing (..)\n\n\
         main m =\n    case m of\n        Get -> 0\n        _ -> 1\n",
    );
    assert_ambiguous_get(&result);
}

#[test]
fn a_qualified_get_resolves_to_the_form_method() {
    let (result, interner) = canonicalise_main(
        &[HTTP_STUB, ATTRIBUTES_STUB],
        "module Main exposing (main)\n\n\
         import Ipe.Http exposing (..)\n\
         import Ipe.Html.Attributes as A exposing (..)\n\n\
         main = A.Get\n",
    );
    let Ok(module) = &result else {
        assert!(
            result.is_ok(),
            "a qualified `A.Get` must canonicalise, got {result:?}"
        );
        return;
    };
    assert_eq!(
        main_get_home(module, &interner).as_deref(),
        Some("Ipe.Html.Attributes"),
        "`A.Get` must be `Ipe.Html.Attributes.Method`'s constructor"
    );
}
