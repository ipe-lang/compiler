//! An open stdlib import defers its type and constructor clashes to a bare use.
//!
//! Values, types, constructors and aliases resolve with one precedence: local,
//! explicit import, open (`exposing (..)`) import, ambient built-in. Two open
//! imports exposing the same name from distinct defining homes are IPE-N0024
//! only where the name is written bare and no higher tier shadows it; a
//! qualified use always resolves, and two explicit imports of one name stay an
//! import-time error.

use std::collections::BTreeMap;

use ipe_canon::ast::{Def, Expr, Expr_, Module, Type};
use ipe_canon::{
    ModuleExports, ModuleOrigin, canonicalise_module, canonicalise_module_with_origin,
};
use ipe_diagnostics::{DResult, Diagnostic, NameError, Span};
use ipe_intern::{Interner, Symbol};

/// `Ipe.Task`'s `Step`, whose `Done` shares its name with `Ipe.Parser`'s.
const TASK_STUB: &str = "module Ipe.Task exposing (Step(..))\n\n\
                         type Step s a = Continue s | Done a\n";

/// `Ipe.Parser`'s `Step`, a distinct declaration of the same names.
const PARSER_STUB: &str = "module Ipe.Parser exposing (Step(..))\n\n\
                           type Step state a = Loop state | Done a\n";

/// Canonicalise the stdlib `stubs` in order (each as an embedded stdlib module
/// against the exports before it) and return the exports by module path.
fn stub_exports(
    stubs: &[&str],
    interner: &mut Interner,
) -> DResult<BTreeMap<Vec<Symbol>, ModuleExports>> {
    let mut deps: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
    for stub in stubs {
        let parsed = ipe_parse::parse_module(stub, interner)?;
        let expected = parsed.name.value.clone();
        let (_, exports) = canonicalise_module_with_origin(
            &parsed,
            &expected,
            &deps,
            ModuleOrigin::EmbeddedStdlib,
            interner,
        )?;
        deps.insert(exports.path.clone(), exports);
    }
    Ok(deps)
}

/// Canonicalise the stdlib `stubs`, then the user module `main` against them.
fn canonicalise_main(stubs: &[&str], main: &str) -> (DResult<Module>, Interner) {
    let mut interner = Interner::new();
    let result = stub_exports(stubs, &mut interner).and_then(|deps| {
        let parsed = ipe_parse::parse_module(main, &mut interner)?;
        let expected = parsed.name.value.clone();
        canonicalise_module(&parsed, &expected, &deps, &mut interner).map(|(module, _)| module)
    });
    (result, interner)
}

/// The dot-joined spelling of a module path.
fn dotted(path: &[Symbol], interner: &Interner) -> Option<String> {
    let segments: Option<Vec<&str>> = path.iter().map(|s| interner.resolve(*s)).collect();
    segments.map(|s| s.join("."))
}

/// The top-level definition `name` of `module`.
fn def<'m>(module: &'m Module, interner: &Interner, name: &str) -> Option<&'m Def> {
    module.defs.iter().find(|d| match d {
        Def::Untyped { name: n, .. } | Def::Typed { name: n, .. } => {
            interner.resolve(n.value) == Some(name)
        }
    })
}

/// The body of the top-level definition `name`.
fn body<'m>(module: &'m Module, interner: &Interner, name: &str) -> Option<&'m Expr> {
    def(module, interner, name).map(|d| match d {
        Def::Untyped { body, .. } | Def::Typed { body, .. } => body,
    })
}

/// The annotation of the top-level definition `name`.
fn annotation<'m>(module: &'m Module, interner: &Interner, name: &str) -> Option<&'m Type> {
    match def(module, interner, name)? {
        Def::Typed { ty, .. } => Some(ty),
        Def::Untyped { .. } => None,
    }
}

/// The dot-joined home of the constructor the body of `name` references.
fn ctor_home(module: &Module, interner: &Interner, name: &str) -> Option<String> {
    let Expr_::VarCtor { home, .. } = &body(module, interner, name)?.value else {
        return None;
    };
    dotted(home, interner)
}

/// The dot-joined home of a constructor type, looking through one arrow.
fn con_home(ty: &Type, interner: &Interner) -> Option<String> {
    let ty = match ty {
        Type::Lambda(arg, _) => arg.as_ref(),
        other => other,
    };
    let Type::Con { home, .. } = ty else {
        return None;
    };
    dotted(home, interner)
}

/// The byte span of the `nth` (0-based) occurrence of `needle` in `source`.
#[allow(clippy::expect_used)] // a fixture without the needle is a broken test
fn span_of(source: &str, needle: &str, nth: usize) -> Span {
    let lo = source
        .match_indices(needle)
        .nth(nth)
        .map(|(at, _)| at)
        .expect("the fixture contains the needle");
    let lo = u32::try_from(lo).expect("a fixture offset fits in u32");
    let len = u32::try_from(needle.len()).expect("a needle length fits in u32");
    Span { lo, hi: lo + len }
}

/// The module names an IPE-N0024 lists, or `None` for any other result.
fn ambiguous_modules(result: &DResult<Module>) -> Option<(Span, Vec<String>)> {
    let Err(Diagnostic::Name {
        span,
        msg: NameError::AmbiguousImport { modules, .. },
    }) = result
    else {
        return None;
    };
    Some((
        *span,
        modules.as_slice().iter().map(ToString::to_string).collect(),
    ))
}

/// Opening both `Step` modules.
const BOTH_OPEN: &str = "module Main exposing (main)\n\n\
                         import Ipe.Task exposing (..)\n\
                         import Ipe.Parser exposing (..)\n\n";

/// The two stub paths an ambiguity between them must name.
fn both_paths() -> Vec<String> {
    vec!["Ipe.Parser".to_owned(), "Ipe.Task".to_owned()]
}

/// W1: two open imports sharing `Step` / `Done`, with no bare use, are legal.
#[test]
fn two_open_imports_sharing_a_type_and_ctor_are_legal_unused() {
    let main = format!("{BOTH_OPEN}main = 0\n");
    let (result, _) = canonicalise_main(&[TASK_STUB, PARSER_STUB], &main);
    assert!(
        result.is_ok(),
        "an unused shared name must not reject the import, got {result:?}"
    );
}

/// W2: a bare `Done` expression is IPE-N0024 at the `Done` token, naming both.
#[test]
fn a_bare_ctor_from_two_open_imports_is_ambiguous_at_the_use() {
    let main = format!("{BOTH_OPEN}main = Done\n");
    let (result, _) = canonicalise_main(&[TASK_STUB, PARSER_STUB], &main);
    let ambiguous = ambiguous_modules(&result);
    assert!(
        ambiguous.is_some(),
        "a bare `Done` from two open imports must be IPE-N0024, got {result:?}"
    );
    #[allow(clippy::expect_used)] // `is_some` is asserted just above
    let (span, modules) = ambiguous.expect("asserted present above");
    assert_eq!(
        span.lo,
        span_of(&main, "Done", 0).lo,
        "the ambiguity is located at the bare use, not at an import"
    );
    assert_eq!(modules, both_paths());
}

/// W3: a bare `Done` pattern is IPE-N0024 at the pattern.
#[test]
fn a_bare_ctor_pattern_from_two_open_imports_is_ambiguous_at_the_pattern() {
    let main = format!(
        "{BOTH_OPEN}f x =\n    case x of\n        Done _ ->\n            0\n\n\
         main = 0\n"
    );
    let (result, _) = canonicalise_main(&[TASK_STUB, PARSER_STUB], &main);
    let ambiguous = ambiguous_modules(&result);
    assert!(
        ambiguous.is_some(),
        "a bare `Done` pattern from two open imports must be IPE-N0024, got {result:?}"
    );
    #[allow(clippy::expect_used)] // `is_some` is asserted just above
    let (span, modules) = ambiguous.expect("asserted present above");
    assert_eq!(
        span.lo,
        span_of(&main, "Done", 0).lo,
        "the ambiguity is located at the pattern"
    );
    assert_eq!(modules, both_paths());
}

/// W4: a bare `Step` annotation is IPE-N0024 at the annotation.
#[test]
fn a_bare_type_from_two_open_imports_is_ambiguous_at_the_annotation() {
    let main = format!("{BOTH_OPEN}f : Step Int Int -> Int\nf _ =\n    0\n\nmain = 0\n");
    let (result, _) = canonicalise_main(&[TASK_STUB, PARSER_STUB], &main);
    let ambiguous = ambiguous_modules(&result);
    assert!(
        ambiguous.is_some(),
        "a bare `Step` annotation from two open imports must be IPE-N0024, got {result:?}"
    );
    #[allow(clippy::expect_used)] // `is_some` is asserted just above
    let (span, modules) = ambiguous.expect("asserted present above");
    assert!(
        span.lo >= span_of(&main, "f : ", 0).lo,
        "the ambiguity is located at the annotation, not at an import: {span:?}"
    );
    assert_eq!(modules, both_paths());
}

/// W5: qualified uses of either module always resolve.
#[test]
fn qualified_uses_of_two_open_imports_resolve() {
    let main = "module Main exposing (main)\n\n\
                import Ipe.Task as Task exposing (..)\n\
                import Ipe.Parser as Parser exposing (..)\n\n\
                f : Task.Step Int Int -> Int\nf _ =\n    0\n\n\
                t = Task.Done\n\n\
                p = Parser.Done\n\n\
                main = 0\n";
    let (result, interner) = canonicalise_main(&[TASK_STUB, PARSER_STUB], main);
    assert!(
        result.is_ok(),
        "qualified uses must resolve, got {result:?}"
    );
    #[allow(clippy::expect_used)] // `is_ok` is asserted just above
    let module = result.as_ref().expect("asserted ok above");
    assert_eq!(
        ctor_home(module, &interner, "t").as_deref(),
        Some("Ipe.Task")
    );
    assert_eq!(
        ctor_home(module, &interner, "p").as_deref(),
        Some("Ipe.Parser")
    );
    let f = annotation(module, &interner, "f");
    assert_eq!(
        f.and_then(|ty| con_home(ty, &interner)).as_deref(),
        Some("Ipe.Task")
    );
}

/// W6: an explicit import outranks an open one, in either import order.
#[test]
fn an_explicit_import_outranks_an_open_one_in_either_order() {
    let explicit = "import Ipe.Parser exposing (Step(..))\n";
    let open = "import Ipe.Task exposing (..)\n";
    for imports in [format!("{explicit}{open}"), format!("{open}{explicit}")] {
        let main = format!("module Main exposing (main)\n\n{imports}\nmain = Done\n");
        let (result, interner) = canonicalise_main(&[TASK_STUB, PARSER_STUB], &main);
        assert!(
            result.is_ok(),
            "explicit-over-open must resolve, got {result:?}"
        );
        #[allow(clippy::expect_used)] // `is_ok` is asserted just above
        let module = result.as_ref().expect("asserted ok above");
        assert_eq!(
            ctor_home(module, &interner, "main").as_deref(),
            Some("Ipe.Parser"),
            "the explicit import wins whatever the order:\n{main}"
        );
    }
}

/// W7: a local type shadows an open-imported one; its constructors stay open.
#[test]
fn a_local_type_shadows_an_open_import() {
    let main = "module Main exposing (main)\n\n\
                import Ipe.Task exposing (..)\n\n\
                type Step = A | B\n\n\
                s : Step\ns =\n    A\n\n\
                main = Done\n";
    let (result, interner) = canonicalise_main(&[TASK_STUB], main);
    assert!(
        result.is_ok(),
        "a local type must shadow an open import, got {result:?}"
    );
    #[allow(clippy::expect_used)] // `is_ok` is asserted just above
    let module = result.as_ref().expect("asserted ok above");
    let s = annotation(module, &interner, "s");
    assert_eq!(
        s.and_then(|ty| con_home(ty, &interner)).as_deref(),
        Some("Main")
    );
    assert_eq!(
        ctor_home(module, &interner, "main").as_deref(),
        Some("Ipe.Task")
    );
}

/// W8: a local constructor shadows two open imports of the same name.
#[test]
fn a_local_ctor_shadows_two_open_imports() {
    let main = format!("{BOTH_OPEN}type T = Done\n\nmain = Done\n");
    let (result, interner) = canonicalise_main(&[TASK_STUB, PARSER_STUB], &main);
    assert!(
        result.is_ok(),
        "a local ctor must shadow open imports, got {result:?}"
    );
    #[allow(clippy::expect_used)] // `is_ok` is asserted just above
    let module = result.as_ref().expect("asserted ok above");
    assert_eq!(
        ctor_home(module, &interner, "main").as_deref(),
        Some("Main")
    );
}

/// W9: an open import outranks the ambient `ChunkEvent.Done`, which stands
/// alone without one.
#[test]
fn an_open_import_outranks_the_ambient_ctor() {
    let open = "module Main exposing (main)\n\nimport Ipe.Task exposing (..)\n\nmain = Done\n";
    let (result, interner) = canonicalise_main(&[TASK_STUB], open);
    assert!(
        result.is_ok(),
        "an open `Done` must resolve, got {result:?}"
    );
    #[allow(clippy::expect_used)] // `is_ok` is asserted just above
    let module = result.as_ref().expect("asserted ok above");
    assert_eq!(
        ctor_home(module, &interner, "main").as_deref(),
        Some("Ipe.Task")
    );

    let bare = "module Main exposing (main)\n\nmain = Done\n";
    let (result, interner) = canonicalise_main(&[TASK_STUB], bare);
    assert!(
        result.is_ok(),
        "the ambient `Done` must resolve, got {result:?}"
    );
    #[allow(clippy::expect_used)] // `is_ok` is asserted just above
    let module = result.as_ref().expect("asserted ok above");
    assert_eq!(ctor_home(module, &interner, "main").as_deref(), Some(""));
}

/// W10: an ambiguous open-import ctor never falls back to the ambient one.
#[test]
fn an_ambiguous_open_ctor_never_falls_back_to_the_ambient_one() {
    let main = format!("{BOTH_OPEN}main = Done\n");
    let (result, _) = canonicalise_main(&[TASK_STUB, PARSER_STUB], &main);
    assert!(
        ambiguous_modules(&result).is_some(),
        "two open `Done`s plus the ambient one must be IPE-N0024, got {result:?}"
    );
}

/// W11: two explicit imports of one constructor stay an import-time error.
#[test]
fn two_explicit_imports_stay_ambiguous_at_the_import() {
    let main = "module Main exposing (main)\n\n\
                import Ipe.Task exposing (Step(..))\n\
                import Ipe.Parser exposing (Step(..))\n\n\
                main = 0\n";
    let (result, _) = canonicalise_main(&[TASK_STUB, PARSER_STUB], main);
    assert!(
        matches!(
            &result,
            Err(Diagnostic::Name {
                msg: NameError::AmbiguousImport { .. } | NameError::DuplicateType { .. },
                span,
            }) if span.lo < span_of(main, "main = 0", 0).lo
        ),
        "two explicit `Step(..)` imports must fail at the import, got {result:?}"
    );
}

/// W12: one module opened twice (plain and under an alias) is one origin.
#[test]
fn one_module_opened_twice_is_one_origin() {
    let main = "module Main exposing (main)\n\n\
                import Ipe.Task exposing (..)\n\
                import Ipe.Task as T exposing (..)\n\n\
                s : Step Int Int\ns =\n    Done 1\n\n\
                main = Done\n";
    let (result, interner) = canonicalise_main(&[TASK_STUB], main);
    assert!(
        result.is_ok(),
        "a module opened twice must not be ambiguous with itself, got {result:?}"
    );
    #[allow(clippy::expect_used)] // `is_ok` is asserted just above
    let module = result.as_ref().expect("asserted ok above");
    assert_eq!(
        ctor_home(module, &interner, "main").as_deref(),
        Some("Ipe.Task")
    );
}

/// W13: one builtin type re-exported by two opened modules is one origin.
#[test]
fn one_reexported_builtin_type_from_two_open_imports_is_one_origin() {
    let one = "module Ipe.Html.One exposing (Attribute, one)\n\none : Int\none =\n    1\n";
    let two = "module Ipe.Html.Two exposing (Attribute, two)\n\ntwo : Int\ntwo =\n    2\n";
    let main = "module Main exposing (main)\n\n\
                import Ipe.Html.One exposing (..)\n\
                import Ipe.Html.Two exposing (..)\n\n\
                f : Attribute msg -> Int\nf _ =\n    0\n\n\
                main = 0\n";
    let (result, interner) = canonicalise_main(&[one, two], main);
    assert!(
        result.is_ok(),
        "one re-exported builtin must not be ambiguous with itself, got {result:?}"
    );
    #[allow(clippy::expect_used)] // `is_ok` is asserted just above
    let module = result.as_ref().expect("asserted ok above");
    let f = annotation(module, &interner, "f");
    assert_eq!(
        f.and_then(|ty| con_home(ty, &interner)).as_deref(),
        Some("Html")
    );
}

/// Stub exporting an alias `Foo`.
const ALIAS_STUB: &str = "module Ipe.A exposing (Foo, a)\n\n\
                          type alias Foo = Int\n\n\
                          a : Int\na =\n    0\n";

/// Stub exporting a union `Foo`.
const UNION_STUB: &str = "module Ipe.B exposing (Foo(..))\n\n\
                          type Foo = FooB\n";

/// W14: an open alias never beats an explicit union; open alias plus open
/// union of one name is ambiguous at a bare use.
#[test]
fn an_open_alias_never_beats_an_explicit_union() {
    let open_alias = "import Ipe.A exposing (..)\n";
    let explicit_union = "import Ipe.B exposing (Foo(..))\n";
    for imports in [
        format!("{open_alias}{explicit_union}"),
        format!("{explicit_union}{open_alias}"),
    ] {
        let main = format!(
            "module Main exposing (main)\n\n{imports}\nx : Foo\nx =\n    FooB\n\nmain = 0\n"
        );
        let (result, interner) = canonicalise_main(&[ALIAS_STUB, UNION_STUB], &main);
        assert!(
            result.is_ok(),
            "explicit union over open alias must resolve, got {result:?}"
        );
        #[allow(clippy::expect_used)] // `is_ok` is asserted just above
        let module = result.as_ref().expect("asserted ok above");
        let x = annotation(module, &interner, "x");
        assert_eq!(
            x.and_then(|ty| con_home(ty, &interner)).as_deref(),
            Some("Ipe.B"),
            "the explicit union wins over the open alias:\n{main}"
        );
    }

    let main = "module Main exposing (main)\n\n\
                import Ipe.A exposing (..)\n\
                import Ipe.B exposing (..)\n\n\
                x : Foo\nx =\n    FooB\n\nmain = 0\n";
    let (result, _) = canonicalise_main(&[ALIAS_STUB, UNION_STUB], main);
    assert_eq!(
        ambiguous_modules(&result).map(|(_, modules)| modules),
        Some(vec!["Ipe.A".to_owned(), "Ipe.B".to_owned()]),
        "an open alias and an open union of one name must be IPE-N0024, got {result:?}"
    );
}

/// W15: a local type over an explicitly imported one stays IPE-N0012 at the
/// local declaration.
#[test]
fn a_local_type_over_an_explicit_import_stays_a_duplicate() {
    let paint = "module Ipe.Paint exposing (Color(..))\n\ntype Color = Red\n";
    let main = "module Main exposing (main)\n\n\
                import Ipe.Paint exposing (Color(..))\n\n\
                type Color = Blue\n\n\
                main = 0\n";
    let (result, _) = canonicalise_main(&[paint], main);
    assert!(
        matches!(
            &result,
            Err(Diagnostic::Name {
                msg: NameError::DuplicateType { .. },
                span,
            }) if span.lo >= span_of(main, "type Color", 0).lo
        ),
        "a local type over an explicit import must be IPE-N0012 at the declaration, \
         got {result:?}"
    );
}

/// W16: the did-you-mean pools still offer open-imported constructors.
#[test]
fn suggestions_offer_open_imported_ctors() {
    let pattern = "module Main exposing (main)\n\n\
                   import Ipe.Task exposing (..)\n\n\
                   f x =\n    case x of\n        Contine _ ->\n            0\n\n\
                   main = 0\n";
    let (result, _) = canonicalise_main(&[TASK_STUB], pattern);
    assert!(
        matches!(
            &result,
            Err(Diagnostic::Name {
                msg: NameError::ConstructorNotFound { suggestions, .. },
                ..
            }) if suggestions.names.iter().any(|s| s.as_ref() == "Continue")
        ),
        "a misspelt open-imported ctor pattern must suggest it, got {result:?}"
    );

    let value = "module Main exposing (main)\n\n\
                 import Ipe.Task exposing (..)\n\n\
                 main = Contine\n";
    let (result, _) = canonicalise_main(&[TASK_STUB], value);
    assert!(
        matches!(
            &result,
            Err(Diagnostic::Name {
                msg: NameError::ValueNotFound { suggestions, .. },
                ..
            }) if suggestions.names.iter().any(|s| s.as_ref() == "Continue")
        ),
        "a misspelt open-imported ctor value must suggest it, got {result:?}"
    );
}

/// W17: a module that opens another exports only its own constructors.
#[test]
fn an_opening_module_exports_only_its_own_ctors() {
    let other = "module Ipe.Other exposing (..)\n\n\
                 import Ipe.Task exposing (..)\n\n\
                 type Step2 = Done2\n";
    let mut interner = Interner::new();
    let result = stub_exports(&[TASK_STUB, other], &mut interner);
    assert!(
        result.is_ok(),
        "the opening module must canonicalise, got {result:?}"
    );
    #[allow(clippy::expect_used)] // `is_ok` is asserted just above
    let deps = result.as_ref().expect("asserted ok above");
    let exports = deps
        .values()
        .find(|e| dotted(&e.path, &interner).as_deref() == Some("Ipe.Other"));
    let ctors: Option<Vec<&str>> = exports.map(|e| {
        e.ctors
            .keys()
            .filter_map(|c| interner.resolve(*c))
            .collect()
    });
    assert_eq!(ctors, Some(vec!["Done2"]));
    let types: Option<Vec<&str>> = exports.map(|e| {
        e.types
            .keys()
            .filter_map(|t| interner.resolve(*t))
            .collect()
    });
    assert_eq!(types, Some(vec!["Step2"]));
}

/// The dot-joined module of the top-level value the body of `name` references.
fn top_level_module(module: &Module, interner: &Interner, name: &str) -> Option<String> {
    let Expr_::VarTopLevel { module: home, .. } = &body(module, interner, name)?.value else {
        return None;
    };
    dotted(home, interner)
}

/// A local record alias `Done`, whose auto-constructor is a bare value.
const LOCAL_RECORD_DONE: &str = "type alias Done = { n : Int }\n\n";

/// A local record alias's auto-constructor is a tier-1 value: it outranks an
/// open-imported constructor of the same spelling in expression position.
#[test]
fn a_local_record_alias_ctor_outranks_an_open_ctor() {
    let main = format!(
        "module Main exposing (main)\n\nimport Ipe.Task exposing (..)\n\n\
         {LOCAL_RECORD_DONE}mk = Done\n\nmain = 0\n"
    );
    let (result, interner) = canonicalise_main(&[TASK_STUB], &main);
    assert!(
        result.is_ok(),
        "a local record alias over an open ctor must resolve, got {result:?}"
    );
    #[allow(clippy::expect_used)] // `is_ok` is asserted just above
    let module = result.as_ref().expect("asserted ok above");
    assert_eq!(
        top_level_module(module, &interner, "mk").as_deref(),
        Some("Main"),
        "the local auto-constructor wins over the open `Ipe.Task.Done`"
    );
}

/// A local record alias's auto-constructor outranks the ambient `Done`.
#[test]
fn a_local_record_alias_ctor_outranks_the_ambient_ctor() {
    let main = format!("module Main exposing (main)\n\n{LOCAL_RECORD_DONE}mk = Done\n\nmain = 0\n");
    let (result, interner) = canonicalise_main(&[], &main);
    assert!(
        result.is_ok(),
        "a local record alias over the ambient ctor must resolve, got {result:?}"
    );
    #[allow(clippy::expect_used)] // `is_ok` is asserted just above
    let module = result.as_ref().expect("asserted ok above");
    assert_eq!(
        top_level_module(module, &interner, "mk").as_deref(),
        Some("Main"),
        "the local auto-constructor wins over the ambient `ChunkEvent` `Done`"
    );
}

/// An open constructor and an open record-alias auto-constructor of one
/// spelling, from two modules, are IPE-N0024 at a bare use, never a silent pick.
#[test]
fn an_open_ctor_and_an_open_record_alias_ctor_are_ambiguous() {
    let record = "module Ipe.Rec exposing (Done)\n\ntype alias Done = { n : Int }\n";
    let main = "module Main exposing (main)\n\n\
                import Ipe.Task exposing (..)\n\
                import Ipe.Rec exposing (..)\n\n\
                mk = Done\n\nmain = 0\n";
    let (result, _) = canonicalise_main(&[TASK_STUB, record], main);
    assert_eq!(
        ambiguous_modules(&result),
        Some((
            span_of(main, "Done", 0),
            vec!["Ipe.Rec".to_owned(), "Ipe.Task".to_owned()]
        )),
        "an open ctor and an open value of one name must be IPE-N0024 at the use, \
         got {result:?}"
    );
}
