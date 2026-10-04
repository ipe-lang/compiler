//! Every bare module-level name binds through one ladder, keyed by defining
//! identity.
//!
//! The ladder is local, explicit import, open (`exposing (..)`) import, ambient
//! built-in, in two namespaces: expression (constructors and values together)
//! and type (unions and aliases together). Every dependency's open import joins
//! the open tier, user and stdlib alike; two explicit imports of distinct
//! definitions, and a local declaration spelling an explicitly imported name,
//! are refused where they are written. One definition reached twice is one
//! origin.

use std::collections::BTreeMap;

use ipe_canon::ast::{Def, Expr, Expr_, Module};
use ipe_canon::{
    ModuleExports, ModuleOrigin, canonicalise_module, canonicalise_module_with_origin,
};
use ipe_diagnostics::{DResult, Diagnostic, NameError, Span};
use ipe_intern::{Interner, Symbol};

/// One dependency module: its source and the origin it is canonicalised under.
type Stub<'s> = (&'s str, ModuleOrigin);

/// A dependency map keyed by module path.
type Deps = BTreeMap<Vec<Symbol>, ModuleExports>;

/// Canonicalise `stubs` in order, each against the exports before it.
fn stub_exports(stubs: &[Stub], interner: &mut Interner) -> DResult<Deps> {
    let mut deps = Deps::new();
    for &(stub, origin) in stubs {
        let parsed = ipe_parse::parse_module(stub, interner)?;
        let expected = parsed.name.value.clone();
        let (_, exports) =
            canonicalise_module_with_origin(&parsed, &expected, &deps, origin, interner)?;
        deps.insert(exports.path.clone(), exports);
    }
    Ok(deps)
}

/// Canonicalise `stubs`, then the user module `main` against them.
fn canonicalise_main(stubs: &[Stub], main: &str) -> (DResult<Module>, Interner) {
    let mut interner = Interner::new();
    let result = stub_exports(stubs, &mut interner).and_then(|deps| {
        let parsed = ipe_parse::parse_module(main, &mut interner)?;
        let expected = parsed.name.value.clone();
        canonicalise_module(&parsed, &expected, &deps, &mut interner).map(|(module, _)| module)
    });
    (result, interner)
}

/// A user dependency stub.
const fn user(src: &str) -> Stub<'_> {
    (src, ModuleOrigin::User)
}

/// A compiled-source stdlib dependency stub.
const fn stdlib(src: &str) -> Stub<'_> {
    (src, ModuleOrigin::EmbeddedStdlib)
}

/// The dot-joined spelling of a module path.
fn dotted(path: &[Symbol], interner: &Interner) -> Option<String> {
    let segments: Option<Vec<&str>> = path.iter().map(|s| interner.resolve(*s)).collect();
    segments.map(|s| s.join("."))
}

/// The body of the top-level definition `name`.
fn body<'m>(module: &'m Module, interner: &Interner, name: &str) -> Option<&'m Expr> {
    module.defs.iter().find_map(|d| match d {
        Def::Untyped { name: n, body, .. } | Def::Typed { name: n, body, .. }
            if interner.resolve(n.value) == Some(name) =>
        {
            Some(body)
        }
        Def::Untyped { .. } | Def::Typed { .. } => None,
    })
}

/// The dot-joined home of the constructor the body of `name` references.
fn ctor_home(module: &Module, interner: &Interner, name: &str) -> Option<String> {
    let Expr_::VarCtor { home, .. } = &body(module, interner, name)?.value else {
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

/// The span and module names of an IPE-N0024, or `None` for any other result.
fn ambiguous(result: &DResult<Module>) -> Option<(Span, Vec<String>)> {
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

/// The two user module names an ambiguity between `A` and `B` lists.
fn a_and_b() -> Vec<String> {
    vec!["A".to_owned(), "B".to_owned()]
}

/// User module `A`, declaring `type T = K`.
const USER_A: &str = "module A exposing (..)\n\ntype T = K\n";

/// User module `B`, a distinct declaration of the same names.
const USER_B: &str = "module B exposing (..)\n\ntype T = K\n";

/// Opening both user modules.
const OPEN_A_B: &str = "module Main exposing (main)\n\n\
                        import A exposing (..)\n\
                        import B exposing (..)\n\n";

/// Two user open imports sharing a type and constructor, unused, are legal.
#[test]
fn two_user_open_imports_sharing_names_are_legal_unused() {
    let main = format!("{OPEN_A_B}main = 0\n");
    let (result, _) = canonicalise_main(&[user(USER_A), user(USER_B)], &main);
    assert!(
        result.is_ok(),
        "an unused name two user modules share must not reject the imports, got {result:?}"
    );
}

/// A bare constructor two user open imports bring is IPE-N0024 at the use.
#[test]
fn a_bare_ctor_from_two_user_open_imports_is_ambiguous_at_the_use() {
    let main = format!("{OPEN_A_B}main = K\n");
    let (result, _) = canonicalise_main(&[user(USER_A), user(USER_B)], &main);
    assert_eq!(
        ambiguous(&result),
        Some((span_of(&main, "K", 0), a_and_b())),
        "a bare `K` from two user open imports must be IPE-N0024 at the use, got {result:?}"
    );
}

/// A bare type two user open imports bring is IPE-N0024 at the annotation.
#[test]
fn a_bare_type_from_two_user_open_imports_is_ambiguous_at_the_annotation() {
    let main = format!("{OPEN_A_B}f : T -> Int\nf _ =\n    0\n\nmain = 0\n");
    let (result, _) = canonicalise_main(&[user(USER_A), user(USER_B)], &main);
    let found = ambiguous(&result);
    assert!(
        found.as_ref().is_some_and(
            |(span, modules)| span.lo >= span_of(&main, "f : ", 0).lo && *modules == a_and_b()
        ),
        "a bare `T` from two user open imports must be IPE-N0024 at the annotation, \
         got {result:?}"
    );
}

/// A user open import and a stdlib open import share one tier.
#[test]
fn a_user_and_a_stdlib_open_import_are_one_tier() {
    let stdlib_x = "module Ipe.X exposing (..)\n\ntype U = K\n";
    let main = "module Main exposing (main)\n\n\
                import A exposing (..)\n\
                import Ipe.X exposing (..)\n\n\
                main = K\n";
    let (result, _) = canonicalise_main(&[user(USER_A), stdlib(stdlib_x)], main);
    assert_eq!(
        ambiguous(&result),
        Some((
            span_of(main, "K", 0),
            vec!["A".to_owned(), "Ipe.X".to_owned()]
        )),
        "a user `(..)` never silently outranks a stdlib `(..)`, got {result:?}"
    );
}

/// An explicit user import outranks a user open import, in either order.
#[test]
fn an_explicit_user_import_outranks_a_user_open_one_in_either_order() {
    let explicit = "import A exposing (T(..))\n";
    let open = "import B exposing (..)\n";
    for imports in [format!("{explicit}{open}"), format!("{open}{explicit}")] {
        let main = format!("module Main exposing (main)\n\n{imports}\nmain = K\n");
        let (result, interner) = canonicalise_main(&[user(USER_A), user(USER_B)], &main);
        let home = result
            .as_ref()
            .ok()
            .and_then(|module| ctor_home(module, &interner, "main"));
        assert_eq!(
            home.as_deref(),
            Some("A"),
            "the explicit import wins whatever the order, got {result:?}:\n{main}"
        );
    }
}

/// A kernel-module explicit import and a compiled dependency's explicit
/// import of one value are IPE-N0024 at the second import.
#[test]
fn a_kernel_and_a_compiled_explicit_import_of_one_value_are_ambiguous() {
    let dep = "module Dep exposing (tea)\n\ntea : Int\ntea =\n    1\n";
    let main = "module Main exposing (main)\n\n\
                import Ipe.Tea.Web exposing (tea)\n\
                import Dep exposing (tea)\n\n\
                main = 0\n";
    let (result, _) = canonicalise_main(&[user(dep)], main);
    let found = ambiguous(&result);
    assert!(
        found.as_ref().is_some_and(|(span, modules)| {
            span.lo == span_of(main, "tea", 1).lo
                && modules.iter().any(|m| m == "Dep")
                && modules.iter().any(|m| m == "Ipe.Tea.Web")
        }),
        "the second explicit `tea` must be IPE-N0024 at its import, got {result:?}"
    );
}

/// A local value spelling a compiled dependency's explicitly imported
/// value is IPE-N0010 at the local declaration.
#[test]
fn a_local_value_over_an_explicit_compiled_import_is_a_duplicate() {
    let dep = "module Dep exposing (foo)\n\nfoo : Int\nfoo =\n    1\n";
    let main = "module Main exposing (main)\n\n\
                import Dep exposing (foo)\n\n\
                foo = 2\n\n\
                main = 0\n";
    let (result, _) = canonicalise_main(&[user(dep)], main);
    let local = span_of(main, "foo = 2", 0).lo;
    assert!(
        matches!(
            &result,
            Err(Diagnostic::Name {
                span,
                msg: NameError::DuplicateValue { first, .. },
            }) if span.lo >= local && first.lo < local
        ),
        "a local `foo` over `Dep exposing (foo)` must be IPE-N0010 at the local, \
         naming the import, got {result:?}"
    );
}

/// An explicit record-alias auto-constructor and an explicit constructor
/// of one spelling are IPE-N0024 at the second import.
#[test]
fn an_explicit_record_alias_ctor_and_an_explicit_ctor_are_ambiguous() {
    let rec = "module A exposing (Foo)\n\ntype alias Foo = { n : Int }\n";
    let union = "module B exposing (T(..))\n\ntype T = Foo\n";
    let main = "module Main exposing (main)\n\n\
                import A exposing (Foo)\n\
                import B exposing (T(..))\n\n\
                main = Foo\n";
    let (result, _) = canonicalise_main(&[user(rec), user(union)], main);
    let found = ambiguous(&result);
    assert!(
        found.as_ref().is_some_and(|(span, modules)| {
            span.lo >= span_of(main, "import B", 0).lo
                && span.lo < span_of(main, "main = Foo", 0).lo
                && *modules == a_and_b()
        }),
        "a value `Foo` and a constructor `Foo` imported explicitly must be IPE-N0024 \
         at the second import, got {result:?}"
    );
}

/// Module `A`, exporting the alias `Foo = Int`.
const ALIAS_A: &str = "module A exposing (Foo)\n\ntype alias Foo = Int\n";

/// Whether `result` is IPE-N0012 at or after the byte offset `at`.
const fn duplicate_type_at_or_after(result: &DResult<Module>, at: u32) -> bool {
    matches!(
        result,
        Err(Diagnostic::Name {
            span,
            msg: NameError::DuplicateType { .. },
        }) if span.lo >= at
    )
}

/// A local union spelling an explicitly imported alias is IPE-N0012 at the
/// local declaration.
#[test]
fn a_local_union_over_an_explicit_alias_is_a_duplicate() {
    let main = "module Main exposing (main)\n\n\
                import A exposing (Foo)\n\n\
                type Foo = Bar\n\n\
                f : Foo -> Foo\nf x =\n    x\n\n\
                main = 0\n";
    let (result, _) = canonicalise_main(&[user(ALIAS_A)], main);
    assert!(
        duplicate_type_at_or_after(&result, span_of(main, "type Foo", 0).lo),
        "a local `type Foo` over an explicit alias must be IPE-N0012 at the local, \
         got {result:?}"
    );
}

/// A local alias spelling an explicitly imported alias is IPE-N0012 at the
/// local declaration.
#[test]
fn a_local_alias_over_an_explicit_alias_is_a_duplicate() {
    let main = "module Main exposing (main)\n\n\
                import A exposing (Foo)\n\n\
                type alias Foo = String\n\n\
                main = 0\n";
    let (result, _) = canonicalise_main(&[user(ALIAS_A)], main);
    assert!(
        duplicate_type_at_or_after(&result, span_of(main, "type alias Foo", 0).lo),
        "a local alias over an explicit alias must be IPE-N0012 at the local, got {result:?}"
    );
}

/// An explicit alias and an explicit union of one name are IPE-N0012 at
/// the second import.
#[test]
fn an_explicit_alias_and_an_explicit_union_are_a_duplicate() {
    let union = "module B exposing (Foo(..))\n\ntype Foo = FooB\n";
    let main = "module Main exposing (main)\n\n\
                import A exposing (Foo)\n\
                import B exposing (Foo(..))\n\n\
                main = 0\n";
    let (result, _) = canonicalise_main(&[user(ALIAS_A), user(union)], main);
    assert!(
        duplicate_type_at_or_after(&result, span_of(main, "import B", 0).lo),
        "an explicit alias and an explicit union `Foo` must be IPE-N0012 at the \
         second import, got {result:?}"
    );
}

/// A stdlib module whose `column` is the `UiCells_column` kernel.
fn column_stub(module: &str) -> String {
    format!(
        "module {module} exposing (column)\n\n\
         import Ipe.Ffi.Kernel as Kernel\n\n\
         column : Int\ncolumn =\n    Kernel.kernel \"UiCells_column\"\n"
    )
}

/// Whether the body of `main` is the backed `column` kernel.
fn main_is_column_kernel(result: &DResult<Module>, interner: &Interner) -> bool {
    let Ok(module) = result else {
        return false;
    };
    matches!(
        body(module, interner, "main").map(|b| &b.value),
        Some(Expr_::VarKernel { id: Some(_), name, .. })
            if interner.resolve(*name) == Some("column")
    )
}

/// One kernel reached through two modules is one origin, opened or
/// listed.
#[test]
fn one_kernel_through_two_modules_is_one_origin() {
    let one = column_stub("Ipe.Cols.One");
    let two = column_stub("Ipe.Cols.Two");
    for exposing in ["(..)", "(column)"] {
        let main = format!(
            "module Main exposing (main)\n\n\
             import Ipe.Cols.One exposing {exposing}\n\
             import Ipe.Cols.Two exposing {exposing}\n\n\
             main = column\n"
        );
        let (result, interner) = canonicalise_main(&[stdlib(&one), stdlib(&two)], &main);
        assert!(
            main_is_column_kernel(&result, &interner),
            "one kernel through two modules must resolve to it, got {result:?}:\n{main}"
        );
    }
}

/// Two distinct top-level definitions of one name, both opened, are
/// IPE-N0024 at the bare use.
#[test]
fn two_distinct_top_level_values_opened_are_ambiguous_at_the_use() {
    let a = "module A exposing (..)\n\nhelper = 1\n";
    let b = "module B exposing (..)\n\nhelper = 2\n";
    let main = format!("{OPEN_A_B}main = helper\n");
    let (result, _) = canonicalise_main(&[user(a), user(b)], &main);
    assert_eq!(
        ambiguous(&result),
        Some((span_of(&main, "helper", 0), a_and_b())),
        "two distinct `helper`s must be IPE-N0024 at the use, got {result:?}"
    );
}

/// Module `A`, exporting `type T = X`.
const CTOR_X_A: &str = "module A exposing (T(..))\n\ntype T = X\n";

/// A local constructor spelling an explicitly imported constructor is
/// IPE-N0011 at the local declaration.
#[test]
fn a_local_ctor_over_an_explicit_ctor_is_a_duplicate() {
    let main = "module Main exposing (main)\n\n\
                import A exposing (T(..))\n\n\
                type U = X\n\n\
                main = 0\n";
    let (result, _) = canonicalise_main(&[user(CTOR_X_A)], main);
    let local = span_of(main, "type U", 0).lo;
    assert!(
        matches!(
            &result,
            Err(Diagnostic::Name {
                span,
                msg: NameError::DuplicateConstructor { first, .. },
            }) if span.lo >= local && first.lo < local
        ),
        "a local `X` over an explicit `X` must be IPE-N0011 at the local, got {result:?}"
    );
}

/// A local record alias whose auto-constructor spells an explicitly
/// imported constructor is refused at the local declaration.
#[test]
fn a_local_record_alias_over_an_explicit_ctor_is_a_duplicate() {
    let main = "module Main exposing (main)\n\n\
                import A exposing (T(..))\n\n\
                type alias X = { a : Int }\n\n\
                main = 0\n";
    let (result, _) = canonicalise_main(&[user(CTOR_X_A)], main);
    let local = span_of(main, "type alias X", 0).lo;
    assert!(
        matches!(
            &result,
            Err(Diagnostic::Name {
                span,
                msg: NameError::DuplicateValue { first, .. }
                    | NameError::DuplicateConstructor { first, .. },
            }) if span.lo >= local && first.lo < local
        ),
        "a local record alias `X` over an explicit `X` must be refused at the local, \
         got {result:?}"
    );
}

/// In a pattern, a local record alias's auto-constructor shadows an open
/// constructor of the same spelling, and is no constructor to match on.
#[test]
fn a_local_record_alias_shadows_an_open_ctor_in_a_pattern() {
    let task = "module Ipe.Task exposing (Step(..))\n\n\
                type Step s a = Continue s | Done a\n";
    let main = "module Main exposing (main)\n\n\
                import Ipe.Task exposing (..)\n\n\
                type alias Done = { n : Int }\n\n\
                f x =\n    case x of\n        Done _ ->\n            0\n\n\
                main = 0\n";
    let (result, _) = canonicalise_main(&[stdlib(task)], main);
    let pattern = span_of(main, "Done", 1).lo;
    assert!(
        matches!(
            &result,
            Err(Diagnostic::Name {
                span,
                msg: NameError::ConstructorNotFound { name, .. },
            }) if span.lo == pattern && &**name == "Done"
        ),
        "a pattern `Done` under a local record alias must be IPE-N0003, never the \
         open `Ipe.Task.Done`, got {result:?}"
    );
}

/// User modules `A` and `B`, each declaring a `Done` that the ambient
/// built-in `Done` also spells.
const STEP_A: &str = "module A exposing (..)\n\ntype Step = Done | More\n";
const STEP_B: &str = "module B exposing (..)\n\ntype Step = Done | Again\n";

/// An ambiguous open tier never falls through to the ambient tier: a bare
/// `Done` two open imports bring is IPE-N0024 in an expression and in a
/// pattern, never the ambient built-in constructor.
#[test]
fn an_ambiguous_open_ctor_never_falls_through_to_the_ambient_one() {
    let expr = format!("{OPEN_A_B}main = Done\n");
    let pattern = format!(
        "{OPEN_A_B}f : Int -> Int\nf x =\n    case x of\n        Done ->\n            0\n\n\
         main = 0\n"
    );
    for (position, main) in [("expression", expr), ("pattern", pattern)] {
        let (result, _) = canonicalise_main(&[user(STEP_A), user(STEP_B)], &main);
        let found = ambiguous(&result);
        assert!(
            found.as_ref().is_some_and(|(span, modules)| {
                *span == span_of(&main, "Done", 0) && *modules == a_and_b()
            }),
            "a bare `Done` in {position} position from two open imports must be IPE-N0024, \
             never the ambient one, got {result:?}"
        );
    }
}

/// An open alias and an open union of one spelling from two modules are
/// IPE-N0024 at the bare use, listing both importing modules.
#[test]
fn an_open_alias_and_an_open_union_of_one_name_are_ambiguous_at_the_use() {
    let a = "module A exposing (..)\n\ntype alias Foo = Int\n";
    let b = "module B exposing (..)\n\ntype Foo = Foo\n";
    let main = format!("{OPEN_A_B}f : Foo -> Int\nf _ =\n    0\n\nmain = 0\n");
    let (result, _) = canonicalise_main(&[user(a), user(b)], &main);
    let found = ambiguous(&result);
    assert!(
        found.as_ref().is_some_and(
            |(span, modules)| span.lo == span_of(&main, "Foo", 0).lo && *modules == a_and_b()
        ),
        "a bare `Foo` naming A's alias and B's union must be IPE-N0024, got {result:?}"
    );
}

/// A stdlib module whose `max` is the `Math_max` kernel, a definition the
/// prelude's `max` (`Basics_max`) is not.
const MAX_STUB: &str = "module Ipe.Mx exposing (max)\n\n\
                        import Ipe.Ffi.Kernel as Kernel\n\n\
                        max : Int -> Int -> Int\nmax =\n    Kernel.kernel \"Math_max\"\n";

/// The prelude binds as an open import of `Ipe.Basics`: an open import of
/// another `max` is IPE-N0024 at a bare use, never the prelude's.
#[test]
fn a_prelude_value_and_an_open_import_of_another_definition_are_ambiguous() {
    let main = "module Main exposing (main)\n\nimport Ipe.Mx exposing (..)\n\nmain = max\n";
    let (result, _) = canonicalise_main(&[stdlib(MAX_STUB)], main);
    let found = ambiguous(&result);
    assert!(
        found.as_ref().is_some_and(|(span, modules)| {
            *span == span_of(main, "max", 0)
                && *modules == vec!["Ipe.Basics".to_owned(), "Ipe.Mx".to_owned()]
        }),
        "a bare `max` from the prelude and an open import must be IPE-N0024, got {result:?}"
    );
}

/// An explicit import outranks the prelude's open tier.
#[test]
fn an_explicit_import_outranks_the_prelude() {
    let main = "module Main exposing (main)\n\nimport Ipe.Mx exposing (max)\n\nmain = max\n";
    let (result, interner) = canonicalise_main(&[stdlib(MAX_STUB)], main);
    assert!(
        result.as_ref().is_ok_and(|module| matches!(
            body(module, &interner, "main").map(|b| &b.value),
            Some(Expr_::VarKernel { module: m, name, .. })
                if interner.resolve(*m) == Some("Math") && interner.resolve(*name) == Some("max")
        )),
        "explicit `exposing (max)` must resolve and a bare `max` name the explicit \
         import's `Math_max`, got {result:?}"
    );
}

/// Whether `result` refuses one of two local expression-namespace bindings of
/// one spelling, the value written at `value` and the constructor at `ctor`:
/// the diagnostic sits on one of them and its `first` on the other.
fn local_ctor_value_clash(result: &DResult<Module>, value: Span, ctor: Span) -> bool {
    let Err(Diagnostic::Name {
        span,
        msg: NameError::DuplicateValue { first, .. } | NameError::DuplicateConstructor { first, .. },
    }) = result
    else {
        return false;
    };
    let within = |s: &Span, line: Span| (line.lo..line.hi).contains(&s.lo);
    (within(span, value) && within(first, ctor)) || (within(span, ctor) && within(first, value))
}

/// Canonicalise `src` alone, as a module of `origin`.
fn canonicalise_alone(src: &str, origin: ModuleOrigin) -> DResult<Module> {
    let mut interner = Interner::new();
    let parsed = ipe_parse::parse_module(src, &mut interner)?;
    let expected = parsed.name.value.clone();
    canonicalise_module_with_origin(&parsed, &expected, &Deps::new(), origin, &mut interner)
        .map(|(module, _)| module)
}

/// A constructor and a top-level value of one spelling in one module are two
/// bindings of one expression-namespace name and are refused — whichever is
/// written first, and in a stdlib module as in a user one.
#[test]
fn a_local_ctor_and_a_same_name_local_value_are_a_duplicate() {
    const TYPE_LINE: &str = "type Strategy = Linear | Exponential\n";
    const VALUE_LINES: &str = "Linear : Strategy\nLinear = Exponential\n";
    let ctor_first = format!("module M exposing (main)\n\n{TYPE_LINE}\n{VALUE_LINES}\nmain = 0\n");
    let value_first = format!("module M exposing (main)\n\n{VALUE_LINES}\n{TYPE_LINE}\nmain = 0\n");
    for src in [&ctor_first, &value_first] {
        let value = span_of(src, VALUE_LINES, 0);
        let ctor = span_of(src, TYPE_LINE, 0);
        for origin in [ModuleOrigin::User, ModuleOrigin::EmbeddedStdlib] {
            let result = canonicalise_alone(src, origin);
            assert!(
                local_ctor_value_clash(&result, value, ctor),
                "{origin:?}: ctor `Linear` and value `Linear` in one module must be \
                 refused, one naming the other; source:\n{src}\ngot {result:?}"
            );
        }
    }
}
