#![forbid(unsafe_code)]
//! Hover, document symbols, document links, and folding over in-memory
//! fixtures — no filesystem anywhere.

use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};
use ipe_lsp_features::PositionEncoding;

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

const HELPER: &str = "module Helper exposing (three)\n\nthree : Int\nthree = 3\n";
const MAIN: &str = "module Main exposing (main)\n\n\
    import Helper exposing (three)\n\n\
    type Shade\n    = Light\n    | Dark\n\n\
    double : Int -> Int\n\
    double n =\n    n + n\n\n\
    main = double three\n";

#[test]
fn hover_reports_the_solved_type_of_the_innermost_region() {
    let db = IpeDatabase::new();
    let helper = file(&db, &["Helper"], HELPER);
    let entry = file(&db, &["Main"], MAIN);
    let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

    // `three` inside `main = double three` (the last occurrence).
    let byte = u32::try_from(MAIN.rfind("three").expect("occurrence")).expect("fits");
    let info =
        ipe_lsp_features::hover::hover(&db, root, entry, entry, &["Main".to_owned()], byte, None)
            .expect("hover hit");
    assert_eq!(info.ty, "Int");

    // Hover in the dep module works with the dep's own source file.
    let byte = u32::try_from(HELPER.rfind('3').expect("literal")).expect("fits");
    let info = ipe_lsp_features::hover::hover(
        &db,
        root,
        entry,
        helper,
        &["Helper".to_owned()],
        byte,
        None,
    )
    .expect("hover hit in dep");
    assert_eq!(info.ty, "Int");
    // A non-`main` hover discloses no control model — the disclosure is a `main`
    // fact only, never attached to an arbitrary expression.
    assert_eq!(info.control_model, None);
}

#[test]
fn hover_on_main_discloses_the_derived_control_model() {
    let db = IpeDatabase::new();
    let helper = file(&db, &["Helper"], HELPER);
    let entry = file(&db, &["Main"], MAIN);
    let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

    // A hover inside the `main` binding (`main = double three`) discloses its
    // control model. This `main` is a plain `Task`, so it is `direct` — the same
    // word `ipe audit`/`ipe doc` disclose, read from the one SSOT projection,
    // never re-derived here. The cursor is on `three` in `main = double three`, a
    // type-solved region that also falls inside the `main` binding.
    let byte = u32::try_from(MAIN.rfind("three").expect("occurrence")).expect("fits");
    let info =
        ipe_lsp_features::hover::hover(&db, root, entry, entry, &["Main".to_owned()], byte, None)
            .expect("hover hit");
    assert_eq!(info.ty, "Int");
    assert_eq!(info.control_model, Some("direct"));

    // A hover in the `double` binding body (`n + n`) is a solved region OUTSIDE
    // `main`, so it discloses no control model — the disclosure is a `main`-only
    // fact, never attached to an arbitrary binding.
    let byte = u32::try_from(MAIN.rfind("n + n").expect("double body")).expect("fits");
    let info =
        ipe_lsp_features::hover::hover(&db, root, entry, entry, &["Main".to_owned()], byte, None)
            .expect("hover hit");
    assert_eq!(info.control_model, None);
}

/// A hover on an interpolated expression reads that expression's own type,
/// never the `String` of the interpolation standing around it: the renderer
/// call owns the whole `{{…}}`, a span strictly wider than the expression.
#[test]
fn hover_on_an_interpolated_expression_reads_its_own_type() {
    const SRC: &str = "module Main exposing (main)\n\n\
        count : Int\ncount =\n    3\n\n\
        main = \"\"\"a {{count}} b {{ count + 1 }} c\"\"\"\n";
    let db = IpeDatabase::new();
    let entry = file(&db, &["Main"], SRC);
    let root = root_of(&db, &[(&["Main"], entry)]);
    // The hover byte is `skip` bytes into the first `needle`.
    let hover_ty = |needle: &str, skip: usize| {
        let at = SRC.find(needle).expect("needle") + skip;
        let byte = u32::try_from(at).expect("fits");
        ipe_lsp_features::hover::hover(&db, root, entry, entry, &["Main".to_owned()], byte, None)
            .expect("hover hit")
            .ty
    };
    // A name that is the whole body.
    assert_eq!(hover_ty("count}}", 0), "Int");
    // The space inside the operator chain: only the chain's region holds it.
    assert_eq!(hover_ty("count + 1", "count".len()), "Int");
    // The `{{` itself belongs to the interpolation alone.
    assert_eq!(hover_ty("{{ count", 0), "String");
}

#[test]
fn document_symbols_cover_values_unions_and_ctors() {
    let db = IpeDatabase::new();
    let helper = file(&db, &["Helper"], HELPER);
    let entry = file(&db, &["Main"], MAIN);
    let _root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

    let symbols = ipe_lsp_features::symbols::document_symbols(&db, entry, PositionEncoding::Utf16);
    let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec!["Shade", "double", "main"]);
    let shade = symbols.first().expect("Shade");
    let ctor_names: Vec<&str> = shade
        .children
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    assert_eq!(ctor_names, vec!["Light", "Dark"]);
}

#[test]
fn document_links_point_at_resolved_imports_only() {
    let db = IpeDatabase::new();
    let helper = file(&db, &["Helper"], HELPER);
    let entry = file(&db, &["Main"], MAIN);
    let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

    let links = ipe_lsp_features::links::document_links(&db, root, entry);
    assert_eq!(links.len(), 1);
    let link = links.first().expect("one link");
    assert_eq!(link.target_module, vec!["Helper".to_owned()]);
    let lo = link.span.lo as usize;
    let hi = link.span.hi as usize;
    assert_eq!(
        MAIN.get(lo..hi),
        Some("Helper"),
        "span covers the import path"
    );

    // The dep imports nothing → no links.
    assert!(ipe_lsp_features::links::document_links(&db, root, helper).is_empty());
}

#[test]
fn folding_covers_multi_line_decls_and_the_union() {
    let db = IpeDatabase::new();
    let helper = file(&db, &["Helper"], HELPER);
    let entry = file(&db, &["Main"], MAIN);
    let _root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

    let ranges = ipe_lsp_features::folding::folding_ranges(&db, entry, PositionEncoding::Utf16);
    // `type Shade` spans lines 4-6; `double` spans lines 8-10 (its
    // annotation line is separate). Single-line decls fold nothing.
    assert!(
        ranges.iter().any(|r| r.start_line == 4 && r.end_line == 6),
        "{ranges:?}"
    );
    assert!(
        ranges
            .iter()
            .any(|r| r.end_line > r.start_line && r.start_line >= 8),
        "{ranges:?}"
    );
}

/// `type_definition` jumps to a user-declared type's declaration: a cursor on a
/// value of type `Shade` resolves to the `type Shade` declaration name token.
#[test]
fn type_definition_jumps_to_the_union_declaration() {
    const SRC: &str = "module Main exposing (main)\n\n\
        type Shade\n    = Light\n    | Dark\n\n\
        favorite : Shade\n\
        favorite =\n    Light\n\n\
        main = favorite\n";
    let db = IpeDatabase::new();
    let entry = file(&db, &["Main"], SRC);
    let root = root_of(&db, &[(&["Main"], entry)]);

    // Cursor on `Light` in `favorite =\n    Light` — its solved type is `Shade`.
    let byte = u32::try_from(SRC.rfind("    Light").expect("body") + 4).expect("fits");
    let def =
        ipe_lsp_features::navigation::type_definition(&db, root, entry, &["Main".to_owned()], byte)
            .expect("cursor on a Shade-typed value resolves its type declaration");
    assert_eq!(def.module, vec!["Main".to_owned()]);
    let lo = def.span.lo as usize;
    let hi = def.span.hi as usize;
    assert_eq!(
        SRC.get(lo..hi),
        Some("Shade"),
        "the span must cover the `Shade` type-name token"
    );
}

/// The refusal: a cursor whose solved type is a builtin (`Int`) declared outside
/// the project resolves to no type definition — never a guess, never a panic.
#[test]
fn type_definition_returns_none_for_a_non_project_type() {
    const SRC: &str = "module Main exposing (main)\n\nmain : Int\nmain =\n    42\n";
    let db = IpeDatabase::new();
    let entry = file(&db, &["Main"], SRC);
    let root = root_of(&db, &[(&["Main"], entry)]);
    let byte = u32::try_from(SRC.find("42").expect("literal")).expect("fits");
    let def =
        ipe_lsp_features::navigation::type_definition(&db, root, entry, &["Main".to_owned()], byte);
    assert!(
        def.is_none(),
        "a builtin `Int` has no in-project declaration to jump to: {def:?}"
    );
}
