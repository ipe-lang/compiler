//! A qualifier spelling resolves through the one scope its imports install,
//! keyed by the module each import reaches.
//!
//! A user module never extends a stdlib qualifier, two modules under one used
//! spelling are refused (IPE-N0027), and a shape-scoped `Cmd` / `Sub` module
//! another shape owns is refused under every spelling (IPE-N0035).

use std::collections::BTreeMap;

use ipe_canon::asserted::AssertedPath;
use ipe_canon::ast::{Def, Module, Type};
use ipe_canon::{ModuleCatalog, ModuleExports, ModuleOrigin, canonicalise_module_in_project};
use ipe_diagnostics::{DResult, Diagnostic, NameError, StdlibReach};
use ipe_intern::{Interner, Symbol};

const LIB_UTIL: &str = "module Lib.Util exposing (..)\n\nf : Int -> Int\nf n =\n    n\n";
const APP_UTIL: &str = "module App.Util exposing (..)\n\ng : Int -> Int\ng n =\n    n\n";
const USER_AUTH: &str = "module Auth exposing (..)\n\nx : Int\nx =\n    1\n";
const APP_AUTH: &str = "module App.Auth exposing (..)\n\nx : Int\nx =\n    1\n";
const USER_WEB: &str = "module Web exposing (..)\n\nx : Int\nx =\n    1\n";
const USER_CMD: &str = "module Cmd exposing (..)\n\nx : Int\nx =\n    1\n";
const APP_AUTH_TYPE: &str = "module App.Auth exposing (..)\n\ntype T\n    = T\n";

/// Canonicalise `sources` in order, each seeing the exports of every module
/// before it; the first error, or `Ok` when every module canonicalises.
fn run(sources: &[&str], catalog: &[&str]) -> DResult<()> {
    run_last(sources, catalog).map(|_| ())
}

/// As [`run`], yielding the last module's canonical form and the interner.
fn run_last(sources: &[&str], catalog: &[&str]) -> DResult<Option<(Module, Interner)>> {
    let user: Vec<(&str, ModuleOrigin)> = sources
        .iter()
        .map(|src| (*src, ModuleOrigin::User))
        .collect();
    run_with_origins(&user, catalog)
}

/// As [`run_last`], each source canonicalised under its own origin.
fn run_with_origins(
    sources: &[(&str, ModuleOrigin)],
    catalog: &[&str],
) -> DResult<Option<(Module, Interner)>> {
    let catalog = ModuleCatalog::new(catalog.iter().map(|m| Box::<str>::from(*m)));
    let mut interner = Interner::new();
    let mut deps: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
    let mut last = None;
    for &(src, origin) in sources {
        let parsed = ipe_parse::parse_module(src, &mut interner)?;
        let expected = parsed.name.value.clone();
        let borrowed: BTreeMap<Vec<Symbol>, &ModuleExports> =
            deps.iter().map(|(k, v)| (k.clone(), v)).collect();
        let (module, exports) = canonicalise_module_in_project(
            &parsed,
            &expected,
            &borrowed,
            &catalog,
            origin,
            &mut interner,
        )?;
        deps.insert(exports.path.clone(), exports);
        last = Some(module);
    }
    Ok(last.map(|module| (module, interner)))
}

/// `module Main exposing (y)`, then `imports`, then `y = body`.
fn main_module(imports: &str, body: &str) -> String {
    format!("module Main exposing (y)\n\n{imports}\ny =\n    {body}\n")
}

/// The byte offset of the module name in `src`'s line `import <name>`.
fn import_name_lo(src: &str, line: &str) -> Option<u32> {
    let import = format!("import {line}\n");
    src.find(&import)
        .and_then(|lo| u32::try_from(lo.saturating_add("import ".len())).ok())
}

/// Whether `result` is IPE-N0027 for `qualifier` at the import `second`,
/// naming the import `first`.
fn is_shared_qualifier(
    result: &DResult<()>,
    qualifier: &str,
    second: Option<u32>,
    first: Option<u32>,
) -> bool {
    matches!(
        result,
        Err(Diagnostic::Name {
            span,
            msg: NameError::DuplicateQualifier { qualifier: q, first: f },
        }) if &**q == qualifier
            && Some(span.lo) == second
            && Some(f.lo) == first
    )
}

/// Whether `result` reached the qualifier's members and missed only the member.
const fn is_no_such_member(result: &DResult<()>) -> bool {
    matches!(
        result,
        Err(Diagnostic::Name {
            msg: NameError::NoSuchMember { .. },
            ..
        })
    )
}

/// A user module named like a stdlib module reaches only its own members: the
/// stdlib kernel is never reached through the user module's qualifier.
#[test]
fn user_module_does_not_extend_a_stdlib_qualifier() {
    let auth = main_module("import Auth\n", "Auth.hashPassword");
    let result = run(&[USER_AUTH, &auth], &["Main", "Auth"]);
    assert!(is_no_such_member(&result), "{result:?}");
    let web = main_module("import Web\n", "Web.tea");
    let result = run(&[USER_WEB, &web], &["Main", "Web"]);
    assert!(is_no_such_member(&result), "{result:?}");
    let stdlib = main_module("import Ipe.Auth\n", "Auth.hashPassword");
    let result = run(&[&stdlib], &["Main"]);
    assert!(result.is_ok(), "{result:?}");
}

/// A user module and a stdlib module under one used spelling are IPE-N0027 at
/// the later import, naming the earlier, in either import order.
#[test]
fn user_and_stdlib_module_under_one_qualifier_is_n0027() {
    for (imports, first, second) in [
        ("import Auth\nimport Ipe.Auth\n", "Auth", "Ipe.Auth"),
        ("import Ipe.Auth\nimport Auth\n", "Ipe.Auth", "Auth"),
    ] {
        for body in ["Auth.x", "Auth.hashPassword"] {
            let src = main_module(imports, body);
            let result = run(&[USER_AUTH, &src], &["Main", "Auth"]);
            assert!(
                is_shared_qualifier(
                    &result,
                    "Auth",
                    import_name_lo(&src, second),
                    import_name_lo(&src, first),
                ),
                "{imports}{body}: {result:?}"
            );
        }
    }
    let aliased = main_module(
        "import Auth\nimport Ipe.Auth as IpeAuth\n",
        "( Auth.x, IpeAuth.hashPassword )",
    );
    let result = run(&[USER_AUTH, &aliased], &["Main", "Auth"]);
    assert!(result.is_ok(), "{result:?}");
    let cmd = main_module("import Cmd\nimport Ipe.Tea.Web\n", "Cmd.x");
    let result = run(&[USER_CMD, &cmd], &["Main", "Cmd"]);
    assert!(
        is_shared_qualifier(
            &result,
            "Cmd",
            import_name_lo(&cmd, "Ipe.Tea.Web"),
            import_name_lo(&cmd, "Cmd"),
        ),
        "{result:?}"
    );
}

/// A user module's last segment and a stdlib canonical under one spelling
/// leave it ambiguous: a use of it is IPE-N0027, each dotted path still
/// resolves, and an alias takes the spelling over.
#[test]
fn shared_last_segment_is_refused_only_when_used() {
    let imports = "import App.Auth\nimport Ipe.Auth\n";
    let catalog = ["Main", "App.Auth"];
    let used = main_module(imports, "Auth.hashPassword");
    let result = run(&[APP_AUTH, &used], &catalog);
    assert!(
        is_shared_qualifier(
            &result,
            "Auth",
            import_name_lo(&used, "Ipe.Auth"),
            import_name_lo(&used, "App.Auth"),
        ),
        "{result:?}"
    );
    let dotted = main_module(imports, "( App.Auth.x, Ipe.Auth.hashPassword )");
    let result = run(&[APP_AUTH, &dotted], &catalog);
    assert!(result.is_ok(), "{result:?}");
    let aliased = main_module(
        "import Ipe.Auth as Auth\nimport App.Auth\n",
        "( Auth.hashPassword, App.Auth.x )",
    );
    let result = run(&[APP_AUTH, &aliased], &catalog);
    assert!(result.is_ok(), "{result:?}");
}

/// Two explicit spellings of different modules are refused at the import,
/// used or not.
#[test]
fn two_aliases_of_different_modules_are_refused_unused() {
    let src = main_module("import Lib.Util as U\nimport App.Util as U\n", "1");
    let result = run(
        &[LIB_UTIL, APP_UTIL, &src],
        &["Main", "Lib.Util", "App.Util"],
    );
    assert!(
        is_shared_qualifier(
            &result,
            "U",
            import_name_lo(&src, "App.Util as U"),
            import_name_lo(&src, "Lib.Util as U"),
        ),
        "{result:?}"
    );
}

/// Another shape's `Cmd` module is refused whatever spelling imports it.
#[test]
fn cross_shape_cmd_is_refused_under_every_spelling() {
    for line in [
        "import Ipe.Tea.Tui.Cmd\n",
        "import Ipe.Tea.Tui.Cmd as Cmd\n",
        "import Ipe.Tea.Tui.Cmd as C\n",
    ] {
        let src = main_module(&format!("import Ipe.Tea.Web\n{line}"), "1");
        let result = run(&[&src], &["Main"]);
        assert!(
            matches!(
                &result,
                Err(Diagnostic::Name {
                    msg: NameError::WrongShapeCmdSub(_),
                    ..
                })
            ),
            "{line}: {result:?}"
        );
    }
}

/// A second app shape is IPE-N0035 at its import, naming the first.
#[test]
fn two_shape_imports_are_n0035() {
    let src = main_module("import Ipe.Tea.Web\nimport Ipe.Tea.Cli\n", "1");
    let result = run(&[&src], &["Main"]);
    let (second, first) = (
        import_name_lo(&src, "Ipe.Tea.Cli"),
        import_name_lo(&src, "Ipe.Tea.Web"),
    );
    assert!(
        matches!(
            &result,
            Err(Diagnostic::Name {
                span,
                msg: NameError::TwoShapeImports { first: f, .. },
            }) if Some(span.lo) == second && Some(f.lo) == first
        ),
        "{result:?}"
    );
    let one = main_module(
        "import Ipe.Tea.Web\nimport Ipe.Tea.Web.Cmd as Cmd\n",
        "Cmd.none",
    );
    let result = run(&[&one], &["Main"]);
    assert!(result.is_ok(), "{result:?}");
}

/// A spelling never imported is refused even when its module exists: no
/// pre-installed qualifier survives without its import.
#[test]
fn ipe_dotted_spelling_without_import_is_n0034() {
    let src = main_module("", "Ipe.Auth.hashPassword");
    let result = run(&[&src], &["Main"]);
    assert!(
        matches!(&result, Err(diag) if diag.code().as_str() == "IPE-N0034"),
        "{result:?}"
    );
}

/// The module path of the annotation head of `name` in `module`, if `name` is
/// a typed definition whose annotation is a named type.
fn annotation_home(module: &Module, interner: &Interner, name: &str) -> Option<Vec<String>> {
    let ty = module.defs.iter().find_map(|def| match def {
        Def::Typed { name: n, ty, .. } if interner.resolve(n.value) == Some(name) => Some(ty),
        Def::Typed { .. } | Def::Untyped { .. } => None,
    })?;
    let Type::Con { home, .. } = ty else {
        return None;
    };
    Some(
        home.iter()
            .filter_map(|s| interner.resolve(*s).map(str::to_owned))
            .collect(),
    )
}

/// A qualified type reaches the module its qualified values reach: a spelling
/// an alias keeps never takes its type home from a last-segment import the
/// alias outranked.
#[test]
fn qualified_type_follows_the_qualifier_owner() {
    let catalog = ["Main", "App.Auth"];
    let shadowed = "module Main exposing (y)\n\nimport Ipe.Auth as Auth\nimport App.Auth\n\n\
                    y : Auth.T\ny =\n    App.Auth.T\n";
    let result = run_last(&[APP_AUTH_TYPE, shadowed], &catalog);
    let home = match &result {
        Ok(Some((module, interner))) => annotation_home(module, interner, "y"),
        Ok(None) | Err(_) => None,
    };
    assert!(
        home.as_deref() != Some(&["App".to_owned(), "Auth".to_owned()][..]),
        "`Auth.T` must not reach `App.Auth`: {home:?}"
    );
    let dotted = "module Main exposing (y)\n\nimport Ipe.Auth as Auth\nimport App.Auth\n\n\
                  y : App.Auth.T\ny =\n    App.Auth.T\n";
    let result = run_last(&[APP_AUTH_TYPE, dotted], &catalog);
    let home = match &result {
        Ok(Some((module, interner))) => annotation_home(module, interner, "y"),
        Ok(None) | Err(_) => None,
    };
    assert_eq!(
        home.as_deref(),
        Some(&["App".to_owned(), "Auth".to_owned()][..]),
        "{home:?}"
    );
}

/// With no shape import, two shapes' `Sub` modules under one alias are two
/// modules: IPE-N0027 at the later import. A shape admits its own and the
/// shared `Terminal` module under one spelling.
#[test]
fn two_shapes_sub_modules_under_one_alias_are_n0027_without_a_shape() {
    let src = main_module(
        "import Ipe.Tea.Tui.Sub as Sub\nimport Ipe.Tea.Cli.Sub as Sub\n",
        "1",
    );
    let result = run(&[&src], &["Main"]);
    assert!(
        is_shared_qualifier(
            &result,
            "Sub",
            import_name_lo(&src, "Ipe.Tea.Cli.Sub as Sub"),
            import_name_lo(&src, "Ipe.Tea.Tui.Sub as Sub"),
        ),
        "{result:?}"
    );
    let admitted = main_module(
        "import Ipe.Tea.Tui\nimport Ipe.Tea.Terminal.Sub as Sub\n",
        "1",
    );
    let result = run(&[&admitted], &["Main"]);
    assert!(result.is_ok(), "{result:?}");
}

/// A native binding resolves only through the generated `Rust.Ffi` module: a
/// spelling another import owns never answers the forwarder's name with that
/// module's own definition (IPE-N0038).
#[test]
fn native_binding_never_resolves_through_a_foreign_ffi_spelling() {
    let def_name = AssertedPath::from_crate_and_path("tm", "shift");
    let def_name = def_name.as_ref().map(AssertedPath::def_name);
    assert!(def_name.is_ok(), "{def_name:?}");
    let def_name = def_name.unwrap_or_default();
    let definition = format!("{def_name} : Int -> Int\n{def_name} n =\n    n\n");
    let shim = format!("module App.Shim exposing (..)\n\n{definition}");
    let forwarder = format!("module Rust.Ffi exposing (..)\n\n{definition}");
    let main = |imports: &str| {
        format!(
            "module Main exposing (y)\n\nimport Ipe.Ffi.Rust as Rust\n{imports}\n\
             y : Int -> Int\ny =\n    Rust.fn \"tm\" \"shift\"\n"
        )
    };
    let hijacked = main("import App.Shim as Ffi\n");
    let result = run(&[&shim, &hijacked], &["Main", "App.Shim"]);
    assert!(
        matches!(
            result,
            Err(Diagnostic::Name {
                msg: NameError::AssertedCallMalformed { .. },
                ..
            })
        ),
        "{result:?}"
    );
    let explicit = main("import Rust.Ffi\n");
    let result = run_with_origins(
        &[
            (forwarder.as_str(), ModuleOrigin::FfiInterface),
            (explicit.as_str(), ModuleOrigin::User),
        ],
        &["Main", "Rust.Ffi"],
    );
    assert!(result.is_ok(), "{:?}", result.as_ref().map(Option::is_some));
}

/// The `Ipe.Parser` combinators the parser operators desugar into.
const PARSER_STUB: &str = "module Ipe.Parser exposing (Parser, keep, ignore)\n\n\
                           type alias Parser a =\n    Int -> a\n\n\
                           keep : Parser a -> Parser b -> Parser a\n\
                           keep kept dropped =\n    kept\n\n\
                           ignore : Parser a -> Parser b -> Parser b\n\
                           ignore dropped kept =\n    kept\n";

/// A user module an import can spell `Parser`.
const LIB_PARSER: &str = "module Lib.Parser exposing (..)\n\nx : Int\nx =\n    1\n";

/// Canonicalise the `Ipe.Parser` stub, then `others`, then `main`.
fn run_with_parser(others: &[&str], main: &str, catalog: &[&str]) -> DResult<()> {
    let mut sources = vec![(PARSER_STUB, ModuleOrigin::EmbeddedStdlib)];
    sources.extend(others.iter().map(|src| (*src, ModuleOrigin::User)));
    sources.push((main, ModuleOrigin::User));
    run_with_origins(&sources, catalog).map(|_| ())
}

/// Whether `result` is IPE-N0034 for `operator` at its span in `src`, naming
/// `Ipe.Parser` as the one import to add.
fn is_operator_import_required(result: &DResult<()>, src: &str, operator: &str) -> bool {
    let needle = format!(" {operator} ");
    let lo = src
        .find(needle.as_str())
        .and_then(|at| u32::try_from(at.saturating_add(1)).ok());
    matches!(
        result,
        Err(Diagnostic::Name {
            span,
            msg: NameError::ImportRequired {
                reached: StdlibReach::Operator(reached),
                candidates,
                imported_as: None,
            },
        }) if &**reached == operator
            && **candidates == [Box::<str>::from("Ipe.Parser")]
            && Some(span.lo) == lo
    )
}

/// `|=` and `|.` with no import of `Ipe.Parser` are IPE-N0034 at the operator.
///
/// They desugar into `Ipe.Parser`, so the refusal lands at ipe time, never as a
/// link-time failure; a module an import merely spells `Parser` is not
/// `Ipe.Parser`.
#[test]
fn parser_operators_require_the_parser_import() {
    for operator in ["|=", "|."] {
        let body = format!("\\p q -> p {operator} q");
        for imports in ["", "import Lib.Parser as Parser\n", "import Lib.Parser\n"] {
            let src = main_module(imports, &body);
            let result = run_with_parser(&[LIB_PARSER], &src, &["Main", "Lib.Parser"]);
            assert!(
                is_operator_import_required(&result, &src, operator),
                "{imports}{body}: {result:?}"
            );
        }
    }
}

/// Every import form of `Ipe.Parser` brings `|=` and `|.` into reach.
#[test]
fn parser_operators_resolve_under_every_import_form() {
    for operator in ["|=", "|."] {
        let body = format!("\\p q -> p {operator} q");
        for imports in [
            "import Ipe.Parser\n",
            "import Ipe.Parser as P\n",
            "import Ipe.Parser exposing (..)\n",
            "import Ipe.Parser as Parser exposing (Parser)\n",
        ] {
            let src = main_module(imports, &body);
            let result = run_with_parser(&[], &src, &["Main"]);
            assert!(result.is_ok(), "{imports}{body}: {result:?}");
        }
    }
}

/// A user module that imports `Ipe.Parser` and uses both operators.
const LIB_USES_PARSER: &str = "module Lib.Uses exposing (..)\n\n\
                               import Ipe.Parser\n\n\
                               both p q =\n    (p |= q) |. q\n";

/// The import that brings `|=` and `|.` into reach is the using module's own:
/// a dependency that imports `Ipe.Parser` (and uses the operators itself) does
/// not lend that import to the module importing the dependency.
#[test]
fn parser_operators_need_the_using_modules_own_import() {
    for operator in ["|=", "|."] {
        let body = format!("\\p q -> p {operator} q");
        let src = main_module("import Lib.Uses\n", &body);
        let result = run_with_parser(&[LIB_USES_PARSER], &src, &["Main", "Lib.Uses"]);
        assert!(
            is_operator_import_required(&result, &src, operator),
            "{body}: {result:?}"
        );
    }
}
