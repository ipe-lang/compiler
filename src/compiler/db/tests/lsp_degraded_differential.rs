#![forbid(unsafe_code)]
//! The degraded analysis is the strict analysis on an error-free program, and
//! the strict queries still refuse a failing module with its first error.

use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile, SourceRoot, lsp_degraded};

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

const LIB: &str = "module Lib exposing (total, ident)\n\n\
    total : Int -> Int\ntotal n =\n    n + 1\n\n\
    ident x =\n    x\n";

const MAIN: &str = "module Main exposing (main)\n\n\
    import Lib\n\n\
    twice n =\n    Lib.total (Lib.total n)\n\n\
    main = twice (Lib.ident 1)\n";

#[test]
fn degraded_equals_strict_on_an_error_free_program() -> Result<(), &'static str> {
    let db = IpeDatabase::new();
    let lib = file(&db, &["Lib"], LIB);
    let main = file(&db, &["Main"], MAIN);
    let root = root_of(&db, &[(&["Lib"], lib), (&["Main"], main)]);
    for module in [lib, main] {
        let strict = ipe_db::canonicalize(&db, root, module)
            .clone()
            .map_err(|_| "the strict canonical form exists")?;
        let degraded =
            lsp_degraded::canonicalize(&db, root, module).ok_or("the degraded form exists")?;
        assert_eq!(strict, degraded);

        let strict = ipe_db::module_interface(&db, root, module)
            .clone()
            .map_err(|_| "the strict interface exists")?;
        let degraded = lsp_degraded::module_interface(&db, root, module)
            .ok_or("the degraded interface exists")?;
        assert_eq!(strict, degraded);

        let strict = ipe_db::typecheck_module(&db, root, main, module)
            .clone()
            .map_err(|_| "the strict types exist")?;
        let degraded = lsp_degraded::typecheck_module(&db, root, main, module)
            .ok_or("the degraded types exist")?;
        assert_eq!(strict, degraded);
    }
    Ok(())
}

const TWO_FAILURES: &str = "module Main exposing (main)\n\n\
    first =\n    missingOne\n\n\
    second =\n    missingTwo\n\n\
    main = 1\n";

#[test]
fn the_strict_query_refuses_with_the_first_failure_only() -> Result<(), &'static str> {
    let db = IpeDatabase::new();
    let main = file(&db, &["Main"], TWO_FAILURES);
    let root = root_of(&db, &[(&["Main"], main)]);
    let Err(diag) = ipe_db::canonicalize(&db, root, main).clone() else {
        return Err("a module with an unbound name must refuse");
    };
    let first = TWO_FAILURES
        .find("missingOne")
        .and_then(|at| u32::try_from(at).ok())
        .ok_or("the fixture spells `missingOne`")?;
    assert_eq!(diag.primary_span().lo, first);
    // The degraded form of the same module still exists.
    assert!(lsp_degraded::canonicalize(&db, root, main).is_some());
    Ok(())
}
