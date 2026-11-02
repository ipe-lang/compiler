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
    let strict_text = format!("module Main exposing (main)\n\n{IDENT}main =\n    ident 1\n");
    let db = IpeDatabase::new();
    let (root, main) = single(&db, &strict_text);
    let byte = last(&strict_text, "    x", 4)?;
    assert!(hover(&db, root, main, main, &main_path(), byte, None).is_some());

    let degraded_text = format!(
        "module Main exposing (main)\n\n{IDENT}broken =\n    missing\n\nmain =\n    ident 1\n"
    );
    let db = IpeDatabase::new();
    let (root, main) = single(&db, &degraded_text);
    let byte = last(&degraded_text, "    x", 4)?;
    assert_eq!(hover(&db, root, main, main, &main_path(), byte, None), None);
    // The pinned use site still answers.
    let call = last(&degraded_text, "ident 1", "ident ".len())?;
    let info = hover(&db, root, main, main, &main_path(), call, None);
    assert!(matches!(&info, Some(info) if info.ty == "Int"), "{info:?}");
    Ok(())
}

/// A module with `count` annotated declarations, each with a type error.
fn failing_chain(count: usize) -> String {
    let decls: String = (0..count)
        .map(|n| format!("bad{n} : Int\nbad{n} =\n    \"x\"\n\n"))
        .collect();
    format!("module Main exposing (main)\n\n{decls}main =\n    1\n")
}

#[test]
fn a_degraded_solve_stops_at_its_cap() -> Result<(), &'static str> {
    let db = IpeDatabase::new();
    let (root, main) = single(&db, &failing_chain(3));
    assert!(module_types(&db, root, main, main).is_some());

    let db = IpeDatabase::new();
    let (root, main) = single(&db, &failing_chain(40));
    assert_eq!(module_types(&db, root, main, main), None);
    Ok(())
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
