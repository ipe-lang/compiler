//! A bare `Done` resolves to `Ipe.Task.Step`'s constructor once that type is
//! imported unqualified, never to the ambient `ChunkEvent.Done`.
//!
//! The ambient constructors are installed before any import, and an import of a
//! type's constructors overrides them. Two imports exposing a `Done`
//! unqualified (`Ipe.Task.Step` and `Ipe.Parser.Step`) are ambiguous and fail
//! closed with IPE-N0024.
//!
//! The same ladder holds for a kernel module's builtin union: `Ipe.Http`
//! exposes `HttpMethod(Get, Post, ..)` and `Ipe.Html.Attributes` exposes
//! `Method(Get, Post)`, so a bare `Get` under both explicit imports is IPE-N0024
//! (in an expression and a pattern), while `A.Get` and `Http.Get` each resolve
//! to their own module's constructor.

use std::collections::BTreeMap;

use ipe_canon::ast::{Def, Expr_, Module};
use ipe_canon::{
    ModuleExports, ModuleOrigin, canonicalise_module, canonicalise_module_with_origin,
};
use ipe_diagnostics::{DResult, Diagnostic, NameError};
use ipe_intern::{Interner, Symbol};

/// The `Step` declaration of `Ipe.Task`, as the stdlib module declares it.
const TASK_STUB: &str = "module Ipe.Task exposing (Step(..))\n\n\
                         type Step s a = Continue s | Done a\n";

/// The `Step` declaration of `Ipe.Parser`, whose `Done` shares the name.
const PARSER_STUB: &str = "module Ipe.Parser exposing (Step(..))\n\n\
                           type Step state a = Loop state | Done a\n";

/// The `Method` declaration of `Ipe.Html.Attributes`, whose `Get` and `Post`
/// share the names of the kernel `Ipe.Http`'s `HttpMethod` constructors.
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
/// bare reference to the constructor `ctor`.
fn main_ctor_home(module: &Module, ctor: &str, interner: &Interner) -> Option<String> {
    let body = module.defs.iter().find_map(|d| match d {
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
    if interner.resolve(*name) != Some(ctor) {
        return None;
    }
    let segments: Option<Vec<&str>> = home.iter().map(|s| interner.resolve(*s)).collect();
    segments.map(|s| s.join("."))
}

#[track_caller]
fn assert_done_resolves_to_task(main: &str) {
    let (result, interner) = canonicalise_main(&[TASK_STUB], main);
    let Ok(module) = &result else {
        assert!(
            result.is_ok(),
            "the importer must canonicalise, got {result:?}"
        );
        return;
    };
    assert_eq!(
        main_ctor_home(module, "Done", &interner).as_deref(),
        Some("Ipe.Task"),
        "`Done` must be `Ipe.Task.Step`'s constructor, not the ambient `ChunkEvent.Done`"
    );
}

#[test]
fn an_explicit_step_import_resolves_bare_done_to_ipe_task() {
    assert_done_resolves_to_task(
        "module Main exposing (main)\n\n\
         import Ipe.Task exposing (Step(..))\n\n\
         main = Done\n",
    );
}

#[test]
fn an_open_task_import_resolves_bare_done_to_ipe_task() {
    assert_done_resolves_to_task(
        "module Main exposing (main)\n\n\
         import Ipe.Task exposing (..)\n\n\
         main = Done\n",
    );
}

#[test]
fn a_qualified_task_done_resolves_to_ipe_task() {
    assert_done_resolves_to_task(
        "module Main exposing (main)\n\n\
         import Ipe.Task as Task\n\n\
         main = Task.Done\n",
    );
}

#[test]
fn two_explicit_step_imports_are_refused_as_a_duplicate_type() {
    let (result, _) = canonicalise_main(
        &[TASK_STUB, PARSER_STUB],
        "module Main exposing (main)\n\n\
         import Ipe.Task exposing (Step(..))\n\
         import Ipe.Parser exposing (Step(..))\n\n\
         main = Done\n",
    );
    assert!(
        matches!(
            &result,
            Err(Diagnostic::Name {
                msg: NameError::DuplicateType { .. },
                ..
            })
        ),
        "two explicit `Step(..)` imports must fail closed at the import as a duplicate type, got {result:?}"
    );
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
    let (result, interner) = canonicalise_main(&[ATTRIBUTES_STUB], main);
    let Ok(module) = &result else {
        assert!(result.is_ok(), "`{main}` must canonicalise, got {result:?}");
        return None;
    };
    main_ctor_home(module, "Get", &interner)
}

#[test]
fn a_bare_get_under_both_explicit_imports_is_ambiguous() {
    let (result, _) = canonicalise_main(
        &[ATTRIBUTES_STUB],
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
        &[ATTRIBUTES_STUB],
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

/// The home of the `Get` that `main`'s body names under the kernel imports alone.
#[track_caller]
fn kernel_get_home_of(main: &str) -> Option<String> {
    let (result, interner) = canonicalise_main(&[], main);
    let Ok(module) = &result else {
        assert!(result.is_ok(), "`{main}` must canonicalise, got {result:?}");
        return None;
    };
    main_ctor_home(module, "Get", &interner)
}

#[test]
fn an_open_kernel_import_binds_its_builtin_union_constructors() {
    let open = kernel_get_home_of(
        "module Main exposing (main)\n\n\
         import Ipe.Http exposing (..)\n\n\
         main = Get\n",
    );
    let explicit = kernel_get_home_of(
        "module Main exposing (main)\n\n\
         import Ipe.Http exposing (HttpMethod(..))\n\n\
         main = Get\n",
    );
    assert!(
        open.is_some(),
        "`exposing (..)` must bind `HttpMethod`'s `Get`"
    );
    assert_eq!(
        open, explicit,
        "`(..)` must deliver what `HttpMethod(..)` does"
    );
}

#[test]
fn a_bare_get_under_both_open_imports_is_ambiguous() {
    let (result, _) = canonicalise_main(
        &[ATTRIBUTES_STUB],
        "module Main exposing (main)\n\n\
         import Ipe.Http exposing (..)\n\
         import Ipe.Html.Attributes exposing (..)\n\n\
         main = Get\n",
    );
    assert_ambiguous_get(&result);
}

#[test]
fn a_local_get_outranks_an_open_kernel_import() {
    let (result, interner) = canonicalise_main(
        &[],
        "module Main exposing (main)\n\n\
         import Ipe.Http exposing (..)\n\n\
         type Verb = Get\n\n\
         main = Get\n",
    );
    let Ok(module) = &result else {
        assert!(
            result.is_ok(),
            "a local `Get` must canonicalise, got {result:?}"
        );
        return;
    };
    assert_eq!(
        main_ctor_home(module, "Get", &interner).as_deref(),
        Some("Main")
    );
}
