#![forbid(unsafe_code)]
//! Definition, references and name resolution read the resolver's recorded
//! name index: names inside `do` blocks and local binders resolve, and every
//! recorded occurrence answers the same target through every query.

use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};
use ipe_lsp_features::navigation::{
    NameTarget, find_references, goto_definition, resolve_name_at, span_text,
};

/// A fixture module: path, text, origin.
type Fixture<'a> = (&'a [&'a str], &'a str, ModuleOrigin);

fn project(db: &IpeDatabase, fixtures: &[Fixture<'_>]) -> (SourceRoot, Vec<SourceFile>) {
    let files: Vec<(Vec<String>, SourceFile)> = fixtures
        .iter()
        .map(|&(path, text, origin)| {
            let path: Vec<String> = path.iter().map(|s| (*s).to_owned()).collect();
            let file = SourceFile::new(db, path.clone(), text.to_owned(), origin);
            (path, file)
        })
        .collect();
    let root = SourceRoot::new(db, files.iter().cloned().collect());
    (root, files.into_iter().map(|(_, file)| file).collect())
}

/// The byte offset of the `nth` occurrence of `needle` in `text`, plus `skip`.
fn at(text: &str, needle: &str, nth: usize, skip: usize) -> Option<u32> {
    let (offset, _) = text.match_indices(needle).nth(nth)?;
    u32::try_from(offset.checked_add(skip)?).ok()
}

fn main_path() -> Vec<String> {
    vec!["Main".to_owned()]
}

const TASK_STUB: &str =
    "module Ipe.Task exposing (succeed)\n\nsucceed : a -> a\nsucceed v =\n    v\n";

const LIB: &str = "module Lib exposing (total)\n\ntotal : Int -> Int\ntotal n =\n    n\n";

const DO_MAIN: &str = "module Main exposing (main)\n\n\
                       import Ipe.Task\nimport Lib\n\n\
                       main : Int\n\
                       main =\n    do\n        \
                       first <- Task.succeed (Lib.total 1)\n        \
                       second <- Task.succeed (Lib.total first)\n        \
                       Lib.total second\n";

fn do_fixture() -> [Fixture<'static>; 3] {
    [
        (&["Ipe", "Task"], TASK_STUB, ModuleOrigin::EmbeddedStdlib),
        (&["Lib"], LIB, ModuleOrigin::User),
        (&["Main"], DO_MAIN, ModuleOrigin::User),
    ]
}

#[test]
fn a_qualified_name_inside_do_goes_to_its_declaration_at_every_statement() {
    let db = IpeDatabase::new();
    let (root, files) = project(&db, &do_fixture());
    let Some(&entry) = files.get(2) else {
        return;
    };
    let decl = at(LIB, "total", 2, 0);
    assert!(decl.is_some());
    for occurrence in 0..3 {
        let byte = at(DO_MAIN, "Lib.total", occurrence, "Lib.".len());
        let def = byte.and_then(|byte| goto_definition(&db, root, entry, &main_path(), byte));
        assert!(
            matches!(&def, Some(d) if d.module == ["Lib"] && Some(d.span.lo) == decl),
            "statement {occurrence}: {def:?}"
        );
    }
}

#[test]
fn a_do_bind_use_goes_to_its_binder() {
    let db = IpeDatabase::new();
    let (root, files) = project(&db, &do_fixture());
    let Some(&entry) = files.get(2) else {
        return;
    };
    let binder = at(DO_MAIN, "second", 0, 0);
    let byte = at(DO_MAIN, "second", 1, 0);
    let def = byte.and_then(|byte| goto_definition(&db, root, entry, &main_path(), byte));
    assert!(
        matches!(&def, Some(d) if Some(d.span.lo) == binder
            && matches!(&d.target, NameTarget::Local { name, .. } if name == "second")),
        "{def:?}"
    );
}

const LOCALS: &str = "module Main exposing (main)\n\n\
                      total : Int\ntotal = 5\n\n\
                      scale : Int -> Int\n\
                      scale n =\n    \
                      let\n        doubled = n * 2\n    in\n    \
                      case doubled of\n        \
                      0 -> n\n        \
                      other -> other + doubled\n\n\
                      shadow : Int -> Int\n\
                      shadow total =\n    total + 1\n\n\
                      twice : Int -> Int\n\
                      twice n =\n    n * 2\n\n\
                      main : Int\nmain = shadow (scale (twice total))\n";

/// `(needle, binder occurrence, use occurrence)` for every local in [`LOCALS`].
const LOCAL_USES: [(&str, usize, usize); 6] = [
    ("n", 0, 1),
    ("n", 0, 2),
    ("doubled", 0, 1),
    ("doubled", 0, 2),
    ("other", 0, 1),
    ("total", 2, 3),
];

/// The byte offset of the `nth` occurrence of `name` as a whole word.
fn word_at(text: &str, name: &str, nth: usize) -> Option<u32> {
    let (offset, _) = text
        .match_indices(name)
        .filter(|&(offset, _)| {
            let before = text.get(..offset).and_then(|s| s.chars().next_back());
            let after = offset
                .checked_add(name.len())
                .and_then(|end| text.get(end..))
                .and_then(|s| s.chars().next());
            !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
        })
        .nth(nth)?;
    u32::try_from(offset).ok()
}

#[test]
fn param_let_case_and_shadowing_uses_go_to_their_binders() {
    let db = IpeDatabase::new();
    let (root, files) = project(&db, &[(&["Main"], LOCALS, ModuleOrigin::User)]);
    let Some(&entry) = files.first() else {
        return;
    };
    for (name, binder, used) in LOCAL_USES {
        let binder = word_at(LOCALS, name, binder);
        let byte = word_at(LOCALS, name, used);
        assert!(binder.is_some() && byte.is_some(), "{name}");
        let def = byte.and_then(|byte| goto_definition(&db, root, entry, &main_path(), byte));
        assert!(
            matches!(&def, Some(d) if Some(d.span.lo) == binder
                && matches!(d.target, NameTarget::Local { .. })),
            "{name} use #{used}: {def:?}"
        );
    }
}

#[test]
fn a_local_s_references_stay_inside_its_scope() {
    let db = IpeDatabase::new();
    let (root, files) = project(&db, &[(&["Main"], LOCALS, ModuleOrigin::User)]);
    let Some(&entry) = files.first() else {
        return;
    };
    let byte = word_at(LOCALS, "n", 1);
    let def = byte.and_then(|byte| goto_definition(&db, root, entry, &main_path(), byte));
    let Some(def) = def else {
        assert!(def.is_some(), "the `n` of `scale` resolves");
        return;
    };
    let mut found: Vec<u32> = find_references(&db, root, entry, &def.target)
        .iter()
        .map(|reference| reference.span.lo)
        .collect();
    found.sort_unstable();
    let expected: Vec<u32> = [1, 2]
        .iter()
        .filter_map(|&n| word_at(LOCALS, "n", n))
        .collect();
    assert_eq!(found, expected);
}

#[test]
fn every_recorded_occurrence_answers_one_target_through_every_query() {
    let db = IpeDatabase::new();
    let fixture = do_fixture();
    let (root, files) = project(&db, &fixture);
    let mut checked = 0usize;
    for (&(path, text, origin), &file) in fixture.iter().zip(&files) {
        if origin != ModuleOrigin::User {
            continue;
        }
        let module: Vec<String> = path.iter().map(|s| (*s).to_owned()).collect();
        let canonical = ipe_db::canonicalize(&db, root, file);
        assert!(canonical.is_ok(), "{module:?} canonicalises");
        let Ok(canonical) = canonical else {
            return;
        };
        for (span, _) in canonical.names.entries() {
            let resolved = resolve_name_at(&db, root, file, &module, span.lo);
            let def = goto_definition(&db, root, file, &module, span.lo);
            let agree = matches!((&resolved, &def), (Some(r), Some(d)) if r.target == d.target
                && span_text(text, r.span) == Some(r.target.name()));
            assert!(agree, "{module:?} at {span:?}: {resolved:?} vs {def:?}");
            checked += 1;
        }
    }
    assert!(checked > 0, "the fixture records occurrences");
}

#[test]
fn an_unrecorded_occurrence_resolves_to_nothing() {
    let db = IpeDatabase::new();
    let (root, files) = project(&db, &[(&["Main"], LOCALS, ModuleOrigin::User)]);
    let Some(&entry) = files.first() else {
        return;
    };
    // An operator and a type reference record no occurrence.
    for (needle, nth) in [("+", 0), ("Int", 0)] {
        let byte = at(LOCALS, needle, nth, 0);
        let resolved = byte.and_then(|byte| resolve_name_at(&db, root, entry, &main_path(), byte));
        assert!(resolved.is_none(), "{needle}: {resolved:?}");
    }
}
