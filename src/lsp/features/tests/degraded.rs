#![forbid(unsafe_code)]
//! Interactive requests answer per declaration: a failing declaration
//! withholds only itself and the declarations that read it, a reference to it
//! answers nothing, and diagnostics still report the module's first error.

use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};
use ipe_lsp_features::db_access::{analysis, module_types};
use ipe_lsp_features::diagnostics::collect;
use ipe_lsp_features::hover::hover;
use ipe_lsp_features::navigation::goto_definition;

fn file(db: &IpeDatabase, path: &[&str], text: &str) -> SourceFile {
    SourceFile::new(
        db,
        path.iter().map(|s| (*s).to_owned()).collect(),
        text.to_owned(),
        ModuleOrigin::User,
    )
}

fn root_of(db: &IpeDatabase, files: &[(&[&str], SourceFile)]) -> SourceRoot {
    SourceRoot::new(
        db,
        files
            .iter()
            .map(|(path, f)| (path.iter().map(|s| (*s).to_owned()).collect(), *f))
            .collect(),
    )
}

/// The byte offset of the last occurrence of `needle` in `text`, plus `skip`.
fn last(text: &str, needle: &str, skip: usize) -> Result<u32, &'static str> {
    let at = text.rfind(needle).ok_or("the fixture spells the needle")?;
    u32::try_from(at.saturating_add(skip)).map_err(|_| "the offset fits u32")
}

fn main_path() -> Vec<String> {
    vec!["Main".to_owned()]
}

const HELPER: &str = "helper : Int -> Int\nhelper n =\n    n + 1\n\n";

const EXPENSE: &str = "module Expense exposing (total)\n\n\
    total : Int -> Int\ntotal n =\n    n\n";

/// A one-module project; `Main` is the entry.
fn single(db: &IpeDatabase, text: &str) -> (SourceRoot, SourceFile) {
    let main = file(db, &["Main"], text);
    (root_of(db, &[(&["Main"], main)]), main)
}

#[test]
fn a_failed_qualified_reference_leaves_its_siblings_answered() -> Result<(), &'static str> {
    let main_text = format!(
        "module Main exposing (main)\n\nimport Expense\n\n{HELPER}\
         broken =\n    Expense.nothing\n\nmain =\n    helper 1\n"
    );
    let db = IpeDatabase::new();
    let expense = file(&db, &["Expense"], EXPENSE);
    let main = file(&db, &["Main"], &main_text);
    let root = root_of(&db, &[(&["Expense"], expense), (&["Main"], main)]);
    let byte = last(&main_text, "helper 1", 0)?;

    let info = hover(&db, root, main, main, &main_path(), byte, None);
    assert!(
        matches!(&info, Some(info) if info.ty == "Int -> Int"),
        "{info:?}"
    );
    let def = goto_definition(&db, root, main, &main_path(), byte);
    let decl =
        u32::try_from(main_text.find("helper n").ok_or("the declaration")?).map_err(|_| "fits")?;
    assert!(
        matches!(&def, Some(d) if d.module == main_path() && d.span.lo == decl),
        "{def:?}"
    );
    let analysis = analysis(&db, root, main, main).ok_or("the degraded analysis exists")?;
    assert!(!analysis.complete);
    Ok(())
}

const FAILING_DEP: &str = "module Expense exposing (total, bad)\n\n\
    total : Int -> Int\ntotal n =\n    n\n\n\
    bad : Int\nbad =\n    missing\n";

const DEP_MAIN: &str = "module Main exposing (main)\n\nimport Expense\n\n\
    main =\n    Expense.total Expense.bad\n";

#[test]
fn a_failed_dependency_declaration_withholds_only_itself() -> Result<(), &'static str> {
    let db = IpeDatabase::new();
    let expense = file(&db, &["Expense"], FAILING_DEP);
    let main = file(&db, &["Main"], DEP_MAIN);
    let root = root_of(&db, &[(&["Expense"], expense), (&["Main"], main)]);

    let total = last(DEP_MAIN, "Expense.total", "Expense.".len())?;
    let info = hover(&db, root, main, main, &main_path(), total, None);
    assert!(
        matches!(&info, Some(info) if info.ty == "Int -> Int"),
        "{info:?}"
    );
    let def = goto_definition(&db, root, main, &main_path(), total);
    assert!(
        matches!(&def, Some(d) if d.module == ["Expense"]),
        "{def:?}"
    );

    let bad = last(DEP_MAIN, "Expense.bad", "Expense.".len())?;
    assert_eq!(goto_definition(&db, root, main, &main_path(), bad), None);
    Ok(())
}

#[test]
fn an_annotated_declaration_with_a_type_error_keeps_its_signature() -> Result<(), &'static str> {
    let text = format!(
        "module Main exposing (main)\n\n{HELPER}\
         bad : Int\nbad =\n    \"x\"\n\nmain =\n    helper bad\n"
    );
    let db = IpeDatabase::new();
    let (root, main) = single(&db, &text);
    assert!(ipe_db::typecheck_module(&db, root, main, main).is_err());

    let info = hover(
        &db,
        root,
        main,
        main,
        &main_path(),
        last(&text, "helper bad", 0)?,
        None,
    );
    assert!(
        matches!(&info, Some(info) if info.ty == "Int -> Int"),
        "{info:?}"
    );
    let info = hover(
        &db,
        root,
        main,
        main,
        &main_path(),
        last(&text, "bad", 0)?,
        None,
    );
    assert!(matches!(&info, Some(info) if info.ty == "Int"), "{info:?}");
    Ok(())
}

#[test]
fn a_reference_to_a_failed_declaration_answers_nothing() -> Result<(), &'static str> {
    let text = format!(
        "module Main exposing (main)\n\n{HELPER}\
         broken =\n    missing\n\nuser =\n    broken\n\nmain =\n    helper 1\n"
    );
    let db = IpeDatabase::new();
    let (root, main) = single(&db, &text);
    let reference = last(&text, "    broken", 4)?;
    assert_eq!(
        goto_definition(&db, root, main, &main_path(), reference),
        None
    );
    // The sibling that never reads it still resolves.
    let helper = last(&text, "helper 1", 0)?;
    assert!(goto_definition(&db, root, main, &main_path(), helper).is_some());
    Ok(())
}

const IDENT: &str = "ident x =\n    x\n\n";

#[test]
fn a_pruned_solve_withholds_an_unpinned_type() -> Result<(), &'static str> {
    // Untyped bindings are monomorphic within their module, so the call in
    // `pinner` pins `ident`'s parameter.
    let strict_text = format!(
        "module Main exposing (main)\n\n{HELPER}{IDENT}pinner =\n    ident 2\n\nmain =\n    helper 1\n"
    );
    let db = IpeDatabase::new();
    let (root, main) = single(&db, &strict_text);
    let byte = last(&strict_text, "    x", 4)?;
    assert!(hover(&db, root, main, main, &main_path(), byte, None).is_some());

    // The only pinner is left out, so the parameter's type is unknown.
    let degraded_text = format!(
        "module Main exposing (main)\n\n{HELPER}{IDENT}pinner =\n    ident missing\n\nmain =\n    helper 1\n"
    );
    let db = IpeDatabase::new();
    let (root, main) = single(&db, &degraded_text);
    let byte = last(&degraded_text, "    x", 4)?;
    assert_eq!(hover(&db, root, main, main, &main_path(), byte, None), None);
    // The sibling that never reads it still answers.
    let call = last(&degraded_text, "helper 1", 0)?;
    let info = hover(&db, root, main, main, &main_path(), call, None);
    assert!(
        matches!(&info, Some(info) if info.ty == "Int -> Int"),
        "{info:?}"
    );
    Ok(())
}

#[test]
fn a_reader_of_a_failed_declaration_is_withheld_and_its_siblings_answer() -> Result<(), &'static str>
{
    let text = format!(
        "module Main exposing (main)\n\n{HELPER}\
         broken =\n    missing\n\nuser =\n    helper broken\n\nmain =\n    helper 1\n"
    );
    let db = IpeDatabase::new();
    let (root, main) = single(&db, &text);
    let sibling = last(&text, "helper 1", 0)?;
    let info = hover(&db, root, main, main, &main_path(), sibling, None);
    assert!(
        matches!(&info, Some(info) if info.ty == "Int -> Int"),
        "{info:?}"
    );
    let reader = last(&text, "helper broken", 0)?;
    assert_eq!(
        hover(&db, root, main, main, &main_path(), reader, None),
        None
    );
    Ok(())
}

#[test]
fn a_left_out_body_that_pinned_a_number_leaves_no_default() -> Result<(), &'static str> {
    // `y` reads `x` and `pinner` reads `y`: one variable, which `1.5` pins.
    let strict_text = "module Main exposing (main)\n\n\
        x =\n    1\n\ny =\n    x\n\nz =\n    2\n\npinner =\n    y + 1.5\n\nmain =\n    z\n";
    let db = IpeDatabase::new();
    let (root, main) = single(&db, strict_text);
    let byte = last(strict_text, "    1\n", 4)?;
    let info = hover(&db, root, main, main, &main_path(), byte, None);
    assert!(
        matches!(&info, Some(info) if info.ty == "Float"),
        "{info:?}"
    );

    let degraded_text = "module Main exposing (main)\n\n\
        x =\n    1\n\ny =\n    x\n\nz =\n    2\n\npinner =\n    y + missing\n\nmain =\n    z\n";
    let db = IpeDatabase::new();
    let (root, main) = single(&db, degraded_text);
    let byte = last(degraded_text, "    1\n", 4)?;
    let info = hover(&db, root, main, main, &main_path(), byte, None);
    assert!(
        info.as_ref().is_none_or(|info| info.ty == "Float"),
        "{info:?}"
    );
    // A number no left-out body reaches keeps its default.
    let byte = last(degraded_text, "    2\n", 4)?;
    let info = hover(&db, root, main, main, &main_path(), byte, None);
    assert!(matches!(&info, Some(info) if info.ty == "Int"), "{info:?}");
    Ok(())
}

const LEAKY_LIB: &str = "module Lib exposing (ident, pinner)\n\n\
    ident x =\n    x\n\npinner =\n    ident missing\n";

const LEAKY_MAIN: &str = "module Main exposing (main)\n\nimport Lib\n\n\
    main =\n    Lib.ident \"s\"\n";

#[test]
fn a_pruned_module_exports_no_scheme_a_left_out_body_could_pin() -> Result<(), &'static str> {
    let db = IpeDatabase::new();
    let lib = file(&db, &["Lib"], LEAKY_LIB);
    let main = file(&db, &["Main"], LEAKY_MAIN);
    let root = root_of(&db, &[(&["Lib"], lib), (&["Main"], main)]);
    let byte = last(LEAKY_MAIN, "Lib.ident", "Lib.".len())?;
    assert_eq!(hover(&db, root, main, main, &main_path(), byte, None), None);
    Ok(())
}

const DECLARED_LIB: &str = "module Lib exposing (pick)\n\n\
    pick : a -> a\npick x =\n    missing\n";

const DECLARED_MAIN: &str = "module Main exposing (main)\n\nimport Lib\n\n\
    main =\n    Lib.pick 1\n";

#[test]
fn a_polymorphic_annotation_with_no_body_stays_in_its_module() -> Result<(), &'static str> {
    let db = IpeDatabase::new();
    let lib = file(&db, &["Lib"], DECLARED_LIB);
    let main = file(&db, &["Main"], DECLARED_MAIN);
    let root = root_of(&db, &[(&["Lib"], lib), (&["Main"], main)]);
    let byte = last(DECLARED_MAIN, "Lib.pick", "Lib.".len())?;
    assert_eq!(hover(&db, root, main, main, &main_path(), byte, None), None);
    Ok(())
}

#[test]
fn an_annotation_holding_a_wildcard_does_not_stand_for_its_body() -> Result<(), &'static str> {
    // The body decides what `any` is, and the caller's number follows it.
    let strict_text = "module Main exposing (main)\n\n\
        view : Int -> any\nview n =\n    1.5\n\nmain =\n    view 1 + 2\n";
    let db = IpeDatabase::new();
    let (root, main) = single(&db, strict_text);
    let byte = last(strict_text, "+ 2", 2)?;
    let info = hover(&db, root, main, main, &main_path(), byte, None);
    assert!(
        matches!(&info, Some(info) if info.ty == "Float"),
        "{info:?}"
    );

    // Left out with its readers, so a sibling that reads neither answers.
    let degraded_text = format!(
        "module Main exposing (main)\n\n{HELPER}\
         view : Int -> any\nview n =\n    missing\n\nuser =\n    view 1 + 2\n\n\
         main =\n    helper 1\n"
    );
    let db = IpeDatabase::new();
    let (root, main) = single(&db, &degraded_text);
    let byte = last(&degraded_text, "+ 2", 2)?;
    let info = hover(&db, root, main, main, &main_path(), byte, None);
    assert!(
        info.as_ref().is_none_or(|info| info.ty == "Float"),
        "{info:?}"
    );
    let sibling = last(&degraded_text, "helper 1", 0)?;
    let info = hover(&db, root, main, main, &main_path(), sibling, None);
    assert!(
        matches!(&info, Some(info) if info.ty == "Int -> Int"),
        "{info:?}"
    );
    Ok(())
}

const NUMBER_LIB: &str = "module Lib exposing (one)\n\n\
    one =\n    1\n\nbroken =\n    missing\n";

const NUMBER_MAIN: &str = "module Main exposing (main)\n\nimport Lib\n\n\
    main =\n    Lib.one + 1.5\n";

#[test]
fn an_open_module_with_an_importer_withholds_its_own_types() -> Result<(), &'static str> {
    let db = IpeDatabase::new();
    let lib = file(&db, &["Lib"], NUMBER_LIB);
    let main = file(&db, &["Main"], NUMBER_MAIN);
    let root = root_of(&db, &[(&["Lib"], lib), (&["Main"], main)]);
    let byte = last(NUMBER_LIB, "    1\n", 4)?;
    let info = hover(&db, root, main, lib, &["Lib".to_owned()], byte, None);
    assert!(
        info.as_ref().is_none_or(|info| info.ty == "Float"),
        "{info:?}"
    );
    Ok(())
}

/// A module with `count` annotated declarations, each with a type error.
fn failing_chain(count: usize) -> String {
    let decls = (0..count)
        .map(|n| format!("bad{n} : Int\nbad{n} =\n    \"x\"\n\n"))
        .collect::<Vec<_>>()
        .concat();
    format!("module Main exposing (main)\n\n{decls}main =\n    1\n")
}

#[test]
fn a_degraded_solve_stops_at_its_cap() {
    let db = IpeDatabase::new();
    let (root, main) = single(&db, &failing_chain(3));
    assert!(module_types(&db, root, main, main).is_some());

    let db = IpeDatabase::new();
    let (root, main) = single(&db, &failing_chain(40));
    assert_eq!(module_types(&db, root, main, main), None);
}

const TWO_FAILURES: &str = "module Main exposing (main)\n\n\
    first =\n    missingOne\n\n\
    second =\n    missingTwo\n\n\
    main = 1\n";

#[test]
fn diagnostics_report_the_first_error_only() -> Result<(), &'static str> {
    let db = IpeDatabase::new();
    let (root, main) = single(&db, TWO_FAILURES);
    let all = collect(&db, root, main);
    let module = all
        .iter()
        .find(|m| m.module == main_path())
        .ok_or("`Main` has an entry")?;
    let [only] = module.diagnostics.as_slice() else {
        return Err("exactly one diagnostic");
    };
    assert_eq!(only.primary_span().lo, last(TWO_FAILURES, "missingOne", 0)?);
    Ok(())
}
