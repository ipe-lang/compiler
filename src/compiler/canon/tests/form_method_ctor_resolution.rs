//! A bare `Get` named by two explicit imports is refused, never picked.
//!
//! `Ipe.Http` (a kernel module) exposes `HttpMethod(Get, Post, ..)` and
//! `Ipe.Html.Attributes` exposes `Method(Get, Post)`. A module that names both
//! types' constructors explicitly fails closed with IPE-N0024 naming both
//! modules, in an expression and in a pattern; a qualified `A.Get` or
//! `Http.Get` resolves to its own module's constructor.

use std::collections::BTreeMap;

use ipe_canon::ast::{Def, Expr_, Module};
use ipe_canon::{
    ModuleExports, ModuleOrigin, canonicalise_module, canonicalise_module_with_origin,
};
use ipe_diagnostics::{DResult, Diagnostic, NameError};
use ipe_intern::{Interner, Symbol};

/// The `Method` declaration of `Ipe.Html.Attributes`, whose `Get` and `Post`
/// share the names of `Ipe.Http`'s `HttpMethod` constructors.
const ATTRIBUTES_STUB: &str = "module Ipe.Html.Attributes exposing (Method(..))\n\n\
                               type Method = Get | Post\n";

/// Canonicalise the `Ipe.Html.Attributes` stub (as an embedded stdlib module)
/// and then the user module `main` against its exports; `Ipe.Http` resolves
/// as the kernel module it is.
fn canonicalise_main(main: &str) -> (DResult<Module>, Interner) {
    let mut interner = Interner::new();
    let mut deps: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
    let stub_result = ipe_parse::parse_module(ATTRIBUTES_STUB, &mut interner).and_then(|parsed| {
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
    let result = ipe_parse::parse_module(main, &mut interner).and_then(|parsed| {
        let expected = parsed.name.value.clone();
        canonicalise_module(&parsed, &expected, &deps, &mut interner).map(|(module, _)| module)
    });
    (result, interner)
}

/// The dot-joined home of the constructor `main`'s body names, if its body is a
/// bare `Get` reference.
fn main_get_home(module: &Module, interner: &Interner) -> Option<String> {
    let body = module.defs.iter().find_map(|def| match def {
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

/// Assert `result` is IPE-N0024 for `Get`, naming both modules.
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
        "a bare `Get` under two explicit imports must be IPE-N0024, got {result:?}"
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

/// The home of the `Get` that `main`'s body names, which must canonicalise.
#[track_caller]
fn main_get_home_of(main: &str) -> Option<String> {
    let (result, interner) = canonicalise_main(main);
    let Ok(module) = &result else {
        assert!(result.is_ok(), "`{main}` must canonicalise, got {result:?}");
        return None;
    };
    main_get_home(module, &interner)
}

#[test]
fn a_bare_get_under_both_explicit_imports_is_ambiguous() {
    let (result, _) = canonicalise_main(
        "module Main exposing (main)\n\n\
         import Ipe.Http exposing (HttpMethod(..))\n\
         import Ipe.Html.Attributes exposing (Method(..))\n\n\
         main = Get\n",
    );
    assert_ambiguous_get(&result);
}

#[test]
fn a_bare_get_pattern_under_both_explicit_imports_is_ambiguous() {
    let (result, _) = canonicalise_main(
        "module Main exposing (main)\n\n\
         import Ipe.Http exposing (HttpMethod(..))\n\
         import Ipe.Html.Attributes exposing (Method(..))\n\n\
         main m =\n    case m of\n        Get -> 0\n        _ -> 1\n",
    );
    assert_ambiguous_get(&result);
}

#[test]
fn a_qualified_get_resolves_to_the_form_method() {
    let home = main_get_home_of(
        "module Main exposing (main)\n\n\
         import Ipe.Http exposing (HttpMethod(..))\n\
         import Ipe.Html.Attributes as A exposing (..)\n\n\
         main = A.Get\n",
    );
    assert_eq!(home.as_deref(), Some("Ipe.Html.Attributes"));
}

#[test]
fn a_qualified_http_get_resolves_to_the_http_method() {
    let home = main_get_home_of(
        "module Main exposing (main)\n\n\
         import Ipe.Http as Http\n\
         import Ipe.Html.Attributes exposing (Method(..))\n\n\
         main = Http.Get\n",
    );
    assert!(home.is_some(), "`Http.Get` must resolve to a constructor");
    assert_ne!(home.as_deref(), Some("Ipe.Html.Attributes"));
}
