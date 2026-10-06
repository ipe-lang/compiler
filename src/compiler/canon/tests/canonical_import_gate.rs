//! A qualifier spelling resolves through the one scope its imports install,
//! keyed by the module each import reaches.
//!
//! A user module never extends a stdlib qualifier, two modules under one used
//! spelling are refused (IPE-N0027), and a shape-scoped `Cmd` / `Sub` module
//! another shape owns is refused under every spelling (IPE-N0035).

use std::collections::BTreeMap;

use ipe_canon::{ModuleCatalog, ModuleExports, ModuleOrigin, canonicalise_module_in_project};
use ipe_diagnostics::{DResult, Diagnostic, NameError};
use ipe_intern::{Interner, Symbol};

const LIB_UTIL: &str = "module Lib.Util exposing (..)\n\nf : Int -> Int\nf n =\n    n\n";
const APP_UTIL: &str = "module App.Util exposing (..)\n\ng : Int -> Int\ng n =\n    n\n";
const USER_AUTH: &str = "module Auth exposing (..)\n\nx : Int\nx =\n    1\n";
const APP_AUTH: &str = "module App.Auth exposing (..)\n\nx : Int\nx =\n    1\n";
const USER_WEB: &str = "module Web exposing (..)\n\nx : Int\nx =\n    1\n";
const USER_CMD: &str = "module Cmd exposing (..)\n\nx : Int\nx =\n    1\n";

/// Canonicalise `sources` in order, each seeing the exports of every module
/// before it; the first error, or `Ok` when every module canonicalises.
fn run(sources: &[&str], catalog: &[&str]) -> DResult<()> {
    let catalog = ModuleCatalog::new(catalog.iter().map(|m| Box::<str>::from(*m)));
    let mut interner = Interner::new();
    let mut deps: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
    for src in sources {
        let parsed = ipe_parse::parse_module(src, &mut interner)?;
        let expected = parsed.name.value.clone();
        let borrowed: BTreeMap<Vec<Symbol>, &ModuleExports> =
            deps.iter().map(|(k, v)| (k.clone(), v)).collect();
        let (_, exports) = canonicalise_module_in_project(
            &parsed,
            &expected,
            &borrowed,
            &catalog,
            ModuleOrigin::User,
            &mut interner,
        )?;
        deps.insert(exports.path.clone(), exports);
    }
    Ok(())
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
