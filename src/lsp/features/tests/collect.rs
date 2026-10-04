#![forbid(unsafe_code)]
//! Diagnostics collection over in-memory fixtures — no filesystem anywhere
//! (the same structural proof as `ipe_db`'s own `lsp_seam.rs`).

use std::collections::BTreeMap;

use ipe_db::{Db as _, IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};
use ipe_lint::LintConfig;
use ipe_lsp_features::PositionEncoding;
use ipe_lsp_features::code_actions::{DbView, code_actions};
use ipe_lsp_features::diagnostics::{ModuleDiagnostics, collect, collect_lint, to_lsp};
use ipe_lsp_features::workspace_edit::Document;
use lsp_types::{CodeActionOrCommand, Range, TextEdit, Url};

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

fn diags_for<'a>(all: &'a [ModuleDiagnostics], module: &[&str]) -> &'a ModuleDiagnostics {
    #[allow(clippy::expect_used)] // test helper: a missing module entry is the failure
    all.iter()
        .find(|m| {
            m.module
                .iter()
                .map(String::as_str)
                .eq(module.iter().copied())
        })
        .expect("module entry present")
}

const DEP_A: &str = "module A exposing (visible)\n\nvisible = 1\n";
// `ENTRY_OK` uses `Ipe.System` — a kernel-qualifier module that resolves
// without needing to be in the SourceRoot, so the clean-project test can
// assert exactly 2 module entries (one per user file).
const ENTRY_OK: &str = "module Main exposing (main)\n\nimport A exposing (visible)\nimport Ipe.System as System\n\nmain : Task Error ()\nmain =\n    System.setenv \"KEY\" \"x\"\n";
const ENTRY_TYPE_ERROR: &str = "module Main exposing (main)\n\nimport A exposing (visible)\n\n\
    main : Int\n\
    main = \"not an int\"\n";
const ENTRY_PARSE_ERROR: &str = "module Main exposing (main)\n\nmain = = 1\n";

#[test]
fn clean_project_yields_empty_lists_for_every_module() {
    let db = IpeDatabase::new();
    let a = file(&db, &["A"], DEP_A);
    let entry = file(&db, &["Main"], ENTRY_OK);
    let root = root_of(&db, &[(&["A"], a), (&["Main"], entry)]);

    let all = collect(&db, root, entry);
    assert_eq!(all.len(), 2, "every module gets an entry");
    assert!(diags_for(&all, &["A"]).diagnostics.is_empty());
    assert!(diags_for(&all, &["Main"]).diagnostics.is_empty());
}

#[test]
fn type_error_is_attributed_to_the_entry_module() {
    let db = IpeDatabase::new();
    let a = file(&db, &["A"], DEP_A);
    let entry = file(&db, &["Main"], ENTRY_TYPE_ERROR);
    let root = root_of(&db, &[(&["A"], a), (&["Main"], entry)]);

    let all = collect(&db, root, entry);
    assert!(diags_for(&all, &["A"]).diagnostics.is_empty());
    let main = diags_for(&all, &["Main"]);
    assert_eq!(main.diagnostics.len(), 1);
    let diag = main.diagnostics.first().expect("one diagnostic");
    assert_eq!(diag.code().as_str(), "IPE-T0001");

    // The LSP mapping points at the failing expression, not 0:0.
    let lsp = to_lsp(diag, ENTRY_TYPE_ERROR, PositionEncoding::Utf16);
    assert_eq!(
        lsp.code,
        Some(lsp_types::NumberOrString::String("IPE-T0001".to_owned()))
    );
    assert_eq!(lsp.severity, Some(lsp_types::DiagnosticSeverity::ERROR));
    assert!(
        lsp.range.start.line > 0,
        "range must be positioned, got {:?}",
        lsp.range
    );
    assert!(lsp.message.contains("type mismatch"), "{}", lsp.message);
}

/// A dependency whose field access disagrees with its annotation: the failing
/// `rec.present` sits at a byte offset `Main`'s longer body also covers.
const DEP_FIELD_MISMATCH: &str = "module Dep exposing (bad)\n\nbad : Int\nbad =\n    let\n        pad0 = 0\n        pad1 = 0\n        pad2 = 0\n        pad3 = 0\n        pad4 = 0\n        pad5 = 0\n        rec = { present = \"a\" }\n    in\n    rec.present\n";
const ENTRY_OVER_DEP: &str = "module Main exposing (main)\n\nimport Dep exposing (bad)\n\nmain : Int\nmain =\n    bad + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0\n";

/// A field-type mismatch is attributed to the module owning the access, never
/// to the module whose def happens to enclose the same byte offsets.
#[test]
fn field_mismatch_attributes_to_owning_module() {
    let db = IpeDatabase::new();
    let dep = file(&db, &["Dep"], DEP_FIELD_MISMATCH);
    let entry = file(&db, &["Main"], ENTRY_OVER_DEP);
    let root = root_of(&db, &[(&["Dep"], dep), (&["Main"], entry)]);

    let all = collect(&db, root, entry);
    let dep_diags = &diags_for(&all, &["Dep"]).diagnostics;
    assert!(
        dep_diags.iter().any(|d| d.code().as_str() == "IPE-T0001"),
        "the T0001 must be attributed to Dep, got {all:?}"
    );
    assert!(
        diags_for(&all, &["Main"]).diagnostics.is_empty(),
        "Main must not carry Dep's mismatch, got {all:?}"
    );
}

#[test]
fn dep_parse_error_is_blamed_on_the_dep_not_the_importer() {
    let db = IpeDatabase::new();
    let a = file(
        &db,
        &["A"],
        "module A exposing (visible)\n\nvisible = = 1\n",
    );
    let entry = file(&db, &["Main"], ENTRY_OK);
    let root = root_of(&db, &[(&["A"], a), (&["Main"], entry)]);

    let all = collect(&db, root, entry);
    assert_eq!(diags_for(&all, &["A"]).diagnostics.len(), 1);
    assert!(
        diags_for(&all, &["Main"]).diagnostics.is_empty(),
        "the importer must not replay its dep's diagnostic"
    );
}

/// Convert an LSP position back to a byte offset (UTF-16 encoding) and apply a
/// single-hunk `TextEdit`, returning the new document text.
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)] // test helper: len_utf16 is 1 or 2
fn apply_edit(text: &str, edit: &TextEdit) -> String {
    let to_byte = |pos: lsp_types::Position| -> usize {
        let mut line_start = 0usize;
        for (i, l) in text.split('\n').enumerate() {
            if i == pos.line as usize {
                // character is a UTF-16 offset within the line.
                let mut utf16 = 0u32;
                for (b, ch) in l.char_indices() {
                    if utf16 >= pos.character {
                        return line_start + b;
                    }
                    utf16 += ch.len_utf16() as u32;
                }
                return line_start + l.len();
            }
            line_start += l.len() + 1;
        }
        text.len()
    };
    let start = to_byte(edit.range.start);
    let end = to_byte(edit.range.end);
    let mut out = String::with_capacity(text.len() + edit.new_text.len());
    out.push_str(&text[..start]);
    out.push_str(&edit.new_text);
    out.push_str(&text[end..]);
    out
}

/// IPE-N0034 quick-fix: a kernel-qualifier stdlib module used without its
/// import yields an "Add import `Ipe.X`" code action whose edit, once applied,
/// clears the diagnostic (SEAL — the program compiles).
#[test]
fn add_import_quick_fix_inserts_the_missing_import_and_clears_the_diagnostic() {
    // `Crypto.sha256` names the `Ipe.Crypto` kernel-qualifier module without
    // an import declaration. `Ipe.Crypto` is a kernel qualifier (present in
    // `STDLIB_MODULE_QUALIFIERS`), so the missing-import gate fires IPE-N0034.
    // Kernel qualifiers resolve without needing to be in the SourceRoot, so
    // the minimal root (only Main) is sufficient both before and after the fix.
    //
    // `System.setenv` wraps `Crypto.sha256 "hello"` to give `main` the
    // required `Task Error ()` type. `Ipe.System` is also a kernel qualifier,
    // so it too resolves without being in the SourceRoot.
    let src = "module Main exposing (main)\n\nimport Ipe.System as System\n\nmain =\n    System.setenv \"KEY\" (Crypto.sha256 \"hello\")\n";
    let mut db = IpeDatabase::new();
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);

    // The real compiler diagnostic must be IPE-N0034.
    let all = collect(&db, root, entry);
    let main = diags_for(&all, &["Main"]);
    assert_eq!(main.diagnostics.len(), 1, "one diagnostic on Main");
    let diag = main.diagnostics.first().expect("one diagnostic");
    assert_eq!(diag.code().as_str(), "IPE-N0034");
    let lsp_diag = to_lsp(diag, src, PositionEncoding::Utf16);

    // The code action offers the correctly-named insert.
    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let full_range = Range {
        start: lsp_diag.range.start,
        end: lsp_diag.range.end,
    };
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        full_range,
        std::slice::from_ref(&lsp_diag),
        PositionEncoding::Utf16,
    );
    let action = actions
        .into_iter()
        .find_map(|a| match a {
            CodeActionOrCommand::CodeAction(action) => Some(action),
            CodeActionOrCommand::Command(_) => None,
        })
        .expect("one CodeAction for IPE-N0034");
    assert_eq!(action.title, "Add import Ipe.Crypto");
    let edit = action
        .edit
        .as_ref()
        .and_then(|e| e.changes.as_ref())
        .and_then(|c| c.values().next())
        .and_then(|v| v.first())
        .expect("edit present");
    assert!(
        edit.new_text.contains("import Ipe.Crypto"),
        "inserts the named import, got {:?}",
        edit.new_text
    );

    // SEAL: applying the edit makes the program compile — N0034 is gone.
    let fixed = apply_edit(src, edit);
    assert!(
        fixed.contains("\nimport Ipe.Crypto\n"),
        "the fixed source carries the import: {fixed:?}"
    );
    assert!(ipe_db::set_text_if_changed(&mut db, entry, &fixed));
    let all = collect(&db, root, entry);
    assert!(
        diags_for(&all, &["Main"]).diagnostics.is_empty(),
        "after applying the quick-fix the module is clean, got {:?}",
        diags_for(&all, &["Main"]).diagnostics
    );
}

/// The insert is sorted among existing imports, not just appended.
#[test]
fn add_import_quick_fix_sorts_among_existing_imports() {
    // `Ipe.Crypto` should land between `Ipe.App` (A < C) and `Ipe.System`
    // (S > C). All three are kernel qualifiers (present in
    // `STDLIB_MODULE_QUALIFIERS`), so they resolve without needing to be in
    // the SourceRoot. `Crypto` is missing → IPE-N0034 fires; the quick-fix
    // must insert `import Ipe.Crypto` in sorted order.
    //
    // The body uses `System.setenv` (String -> String -> Task Error ()) with
    // `Crypto.sha256 "hello"` (String) as its second argument, so after the
    // fix the module type-checks clean.
    let src = "module Main exposing (main)\n\n\
        import Ipe.App as App\n\
        import Ipe.System as System\n\n\
        main = System.setenv \"KEY\" (Crypto.sha256 \"hello\")\n";
    let mut db = IpeDatabase::new();
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);

    let all = collect(&db, root, entry);
    let main = diags_for(&all, &["Main"]);
    let diag = main
        .diagnostics
        .iter()
        .find(|d| d.code().as_str() == "IPE-N0034")
        .expect("an IPE-N0034 diagnostic");
    let lsp_diag = to_lsp(diag, src, PositionEncoding::Utf16);

    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let range = Range {
        start: lsp_diag.range.start,
        end: lsp_diag.range.end,
    };
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        range,
        std::slice::from_ref(&lsp_diag),
        PositionEncoding::Utf16,
    );
    let action = actions
        .into_iter()
        .find_map(|a| match a {
            CodeActionOrCommand::CodeAction(action) => Some(action),
            CodeActionOrCommand::Command(_) => None,
        })
        .expect("one CodeAction for IPE-N0034");
    let edit = action
        .edit
        .as_ref()
        .and_then(|e| e.changes.as_ref())
        .and_then(|c| c.values().next())
        .and_then(|v| v.first())
        .expect("edit present");

    let fixed = apply_edit(src, edit);
    let app_at = fixed.find("import Ipe.App").expect("App present");
    let crypto_at = fixed.find("import Ipe.Crypto").expect("Crypto inserted");
    let system_at = fixed.find("import Ipe.System").expect("System present");
    assert!(
        app_at < crypto_at && crypto_at < system_at,
        "Crypto sorts between App and System: {fixed:?}"
    );

    // SEAL: the sorted insert also compiles.
    assert!(ipe_db::set_text_if_changed(&mut db, entry, &fixed));
    let all = collect(&db, root, entry);
    assert!(
        diags_for(&all, &["Main"]).diagnostics.is_empty(),
        "sorted insert compiles, got {:?}",
        diags_for(&all, &["Main"]).diagnostics
    );
}

/// IPE-N0035 quick-fix: repoint a wrong-shape `Cmd` import to the app's own.
///
/// A Cli app importing the Web shape's `Cmd` yields a
/// "Change import to `Ipe.Tea.Cli.Cmd`" code action whose edit, once
/// applied, repoints the import to the app's shape and clears the diagnostic
/// (SEAL — the program compiles), leaving the `as Cmd` binding untouched.
#[test]
fn wrong_shape_cmd_quick_fix_repoints_the_import_and_clears_the_diagnostic() {
    // IPE-N0035 is a canon/name-phase gate on the wrong-shape `Cmd` import, so it
    // fires independently of the `view` body's type. The view stays a bare string
    // literal placeholder: no `Ipe.Ui.Cli` import is needed (and none is
    // added), keeping this bare test DB's module graph to the single `Main` file
    // — importing the `Ipe.Ui.Cli` surface here would raise IPE-N0020 (unknown module)
    // and short-circuit canon before the N0035 gate.
    let src = "module Main exposing (main)\n\n\
        import Ipe.Tea.Cli as Cli\n\
        import Ipe.Tea.Web.Cmd as Cmd\n\
        import Ipe.Tea.Cli.Sub as Sub\n\n\
        init _u = ( { n = 0 }, Cmd.none )\n\
        update _m model = ( model, Cmd.none )\n\
        view _m = \"ok\"\n\
        subscriptions _m = Sub.onLine onLine\n\
        onLine l = l\n\
        main =\n    \
            Cli.tea { init = init, update = update, view = view, subscriptions = subscriptions }\n";
    let mut db = IpeDatabase::new();
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);

    // The real compiler diagnostic must be IPE-N0035.
    let all = collect(&db, root, entry);
    let main = diags_for(&all, &["Main"]);
    let diag = main
        .diagnostics
        .iter()
        .find(|d| d.code().as_str() == "IPE-N0035")
        .expect("an IPE-N0035 diagnostic");
    let lsp_diag = to_lsp(diag, src, PositionEncoding::Utf16);

    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let range = Range {
        start: lsp_diag.range.start,
        end: lsp_diag.range.end,
    };
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        range,
        std::slice::from_ref(&lsp_diag),
        PositionEncoding::Utf16,
    );
    let action = actions
        .into_iter()
        .find_map(|a| match a {
            CodeActionOrCommand::CodeAction(action) => Some(action),
            CodeActionOrCommand::Command(_) => None,
        })
        .expect("one CodeAction for IPE-N0035");
    assert_eq!(action.title, "Change import to Ipe.Tea.Cli.Cmd");
    let edit = action
        .edit
        .as_ref()
        .and_then(|e| e.changes.as_ref())
        .and_then(|c| c.values().next())
        .and_then(|v| v.first())
        .expect("edit present");

    // SEAL: applying the edit repoints the import (keeping `as Cmd`) and the
    // module compiles — N0035 is gone.
    let fixed = apply_edit(src, edit);
    assert!(
        fixed.contains("import Ipe.Tea.Cli.Cmd as Cmd"),
        "the fixed source repoints to the Cli shape, keeping the alias: {fixed:?}"
    );
    assert!(
        !fixed.contains("Ipe.Tea.Web.Cmd"),
        "the wrong-shape import is gone: {fixed:?}"
    );
    assert!(ipe_db::set_text_if_changed(&mut db, entry, &fixed));
    let all = collect(&db, root, entry);
    assert!(
        !diags_for(&all, &["Main"])
            .diagnostics
            .iter()
            .any(|d| d.code().as_str() == "IPE-N0035"),
        "after applying the quick-fix the wrong-shape diagnostic is gone, got {:?}",
        diags_for(&all, &["Main"]).diagnostics
    );
}

// ── IPE-N0023 quick-fix ─────────────────────────────────────────────────────

/// IPE-N0023 quick-fix: a module whose declaration (`module Foo`) does not match
/// its source-root path (`Main`) yields a "Rename module declaration" action
/// that rewrites the name token on line 0 to the expected name.
#[test]
fn n0023_quick_fix_renames_module_declaration_to_expected_name() {
    // `module Foo` is registered under path `["Main"]` — the mismatch fires.
    let src = "module Foo exposing (main)\n\nmain : Int\nmain = 1\n";
    let db = IpeDatabase::new();
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);

    let all = collect(&db, root, entry);
    let diag = diags_for(&all, &["Main"])
        .diagnostics
        .iter()
        .find(|d| d.code().as_str() == "IPE-N0023")
        .expect("IPE-N0023 fires for path/declaration mismatch");
    let lsp_diag = to_lsp(diag, src, PositionEncoding::Utf16);

    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        lsp_diag.range,
        std::slice::from_ref(&lsp_diag),
        PositionEncoding::Utf16,
    );
    let action = actions
        .into_iter()
        .find_map(|a| match a {
            CodeActionOrCommand::CodeAction(ca) => Some(ca),
            CodeActionOrCommand::Command(_) => None,
        })
        .expect("IPE-N0023 must offer a rename action");

    assert!(
        action.title.contains("Main"),
        "action title must name the expected module, got: {:?}",
        action.title
    );
    let edit = action
        .edit
        .as_ref()
        .and_then(|e| e.changes.as_ref())
        .and_then(|c| c.values().next())
        .and_then(|v| v.first())
        .expect("edit present");
    // The edit must be on line 0 (the `module Foo` declaration).
    assert_eq!(edit.range.start.line, 0, "edit must target line 0");
    assert_eq!(
        edit.new_text, "Main",
        "must rename to the path-expected name"
    );
    let fixed = apply_edit(src, edit);
    assert!(
        fixed.starts_with("module Main"),
        "fixed source starts with `module Main`: {fixed:?}"
    );
}

// ── IPE-N0036 quick-fix ─────────────────────────────────────────────────────

/// IPE-N0036 quick-fix: `Task.perform` (a removed stdlib surface with a known
/// replacement) yields a "Replace with `Task.attempt`" action.
#[test]
fn n0036_quick_fix_replaces_removed_surface_with_migration_target() {
    // `Task.perform` fires IPE-N0036 with replacement = "Task.attempt".
    // We only need the name-resolution phase, so a single-file root is enough.
    let src = "module Main exposing (x)\n\nx = Task.perform\n";
    let db = IpeDatabase::new();
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);

    let all = collect(&db, root, entry);
    let diag = diags_for(&all, &["Main"])
        .diagnostics
        .iter()
        .find(|d| d.code().as_str() == "IPE-N0036")
        .expect("IPE-N0036 fires for Task.perform");
    let lsp_diag = to_lsp(diag, src, PositionEncoding::Utf16);

    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        lsp_diag.range,
        std::slice::from_ref(&lsp_diag),
        PositionEncoding::Utf16,
    );
    let action = actions
        .into_iter()
        .find_map(|a| match a {
            CodeActionOrCommand::CodeAction(ca) => Some(ca),
            CodeActionOrCommand::Command(_) => None,
        })
        .expect("IPE-N0036 with a replacement must offer a replace action");

    assert!(
        action.title.contains("Task.attempt"),
        "title must name the replacement, got: {:?}",
        action.title
    );
    let edit = action
        .edit
        .as_ref()
        .and_then(|e| e.changes.as_ref())
        .and_then(|c| c.values().next())
        .and_then(|v| v.first())
        .expect("edit present");
    assert_eq!(edit.new_text, "Task.attempt");
}

/// IPE-N0036 with no replacement (e.g. `Task.run`) must produce no action.
#[test]
fn n0036_no_replacement_produces_no_action() {
    let src = "module Main exposing (x)\n\nx = Task.run\n";
    let db = IpeDatabase::new();
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);

    let all = collect(&db, root, entry);
    let diag = diags_for(&all, &["Main"])
        .diagnostics
        .iter()
        .find(|d| d.code().as_str() == "IPE-N0036")
        .expect("IPE-N0036 fires for Task.run");
    let lsp_diag = to_lsp(diag, src, PositionEncoding::Utf16);

    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        lsp_diag.range,
        std::slice::from_ref(&lsp_diag),
        PositionEncoding::Utf16,
    );
    assert!(
        actions.is_empty(),
        "Task.run has no replacement — must produce no action, got: {actions:?}"
    );
}

// ── IPE-T0020 quick-fix ─────────────────────────────────────────────────────

/// IPE-T0020 quick-fix: a `WebView` `view` that returns `Html` instead of `View`
/// yields a "Wrap in `Ui.html`" action that inserts `Ui.html (…)`.
#[test]
fn t0020_quick_fix_wraps_expression_in_ui_html() {
    // We synthesise the diagnostic directly (no live compiler run) because
    // triggering the real IPE-T0020 gate requires a full WebView shape — an
    // expensive fixture. The action is keyed purely on the diagnostic code and
    // the span text, both of which we control exactly here.
    use lsp_types::{DiagnosticSeverity, NumberOrString, Position};

    let src = "module Main exposing (view)\n\nview : Int -> Html msg\nview _ =\n    div [] []\n";
    let db = IpeDatabase::new();
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);

    // The expression `div [] []` is on line 4, characters 4..14.
    #[allow(deprecated)]
    let lsp_diag = lsp_types::Diagnostic {
        range: Range {
            start: Position {
                line: 4,
                character: 4,
            },
            end: Position {
                line: 4,
                character: 14,
            },
        },
        severity: Some(DiagnosticSeverity::ERROR),
        code: Some(NumberOrString::String("IPE-T0020".to_owned())),
        code_description: None,
        source: Some("ipe".to_owned()),
        message: "the view function returns Html instead of View".to_owned(),
        related_information: None,
        tags: None,
        data: None,
    };

    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        lsp_diag.range,
        std::slice::from_ref(&lsp_diag),
        PositionEncoding::Utf16,
    );
    let action = actions
        .into_iter()
        .find_map(|a| match a {
            CodeActionOrCommand::CodeAction(ca) => Some(ca),
            CodeActionOrCommand::Command(_) => None,
        })
        .expect("IPE-T0020 must offer a Ui.html wrap action");

    assert_eq!(action.title, "Wrap in `Ui.html`");
    let edit = action
        .edit
        .as_ref()
        .and_then(|e| e.changes.as_ref())
        .and_then(|c| c.values().next())
        .and_then(|v| v.first())
        .expect("edit present");
    assert_eq!(edit.new_text, "Ui.html (div [] [])");
}

// ── `rewrite_two_step_decoder` unit tests (IPE-N0040) ───────────────────────

/// Verify the pure decoder-pipeline rewrite function on isolated inputs.
#[test]
fn rewrite_two_step_decoder_produces_pipeline_form() {
    // Import the private function via a re-export path — the function is
    // module-private, so test it indirectly via `code_actions` by constructing
    // a synthetic IPE-N0040 diagnostic pointing at the exact span.
    use lsp_types::{DiagnosticSeverity, NumberOrString, Position};

    // `required f2 (required f1 (succeed Ctor))` — a two-step nested pipeline.
    let src = "module Main exposing (x)\n\nx =\n    required f2 (required f1 (succeed Ctor))\n";
    let db = IpeDatabase::new();
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);

    // The span covers `required f2 (required f1 (succeed Ctor))` on line 3.
    #[allow(deprecated)]
    let lsp_diag = lsp_types::Diagnostic {
        range: Range {
            start: Position {
                line: 3,
                character: 4,
            },
            end: Position {
                line: 3,
                // The full expression `required f2 (required f1 (succeed Ctor))`
                // ends at column 44 — the range must include the closing `))`,
                // or the rewrite sees an unbalanced span and conservatively
                // declines.
                character: 44,
            },
        },
        severity: Some(DiagnosticSeverity::ERROR),
        code: Some(NumberOrString::String("IPE-N0040".to_owned())),
        code_description: None,
        source: Some("ipe".to_owned()),
        message: "These decoder steps are nested, which would bind your fields in the wrong order."
            .to_owned(),
        related_information: None,
        tags: None,
        data: None,
    };

    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        lsp_diag.range,
        std::slice::from_ref(&lsp_diag),
        PositionEncoding::Utf16,
    );
    let action = actions
        .into_iter()
        .find_map(|a| match a {
            CodeActionOrCommand::CodeAction(ca) => Some(ca),
            CodeActionOrCommand::Command(_) => None,
        })
        .expect("IPE-N0040 must offer a pipeline-rewrite action");

    assert_eq!(action.title, "Rewrite as `|>` pipeline");
    let edit = action
        .edit
        .as_ref()
        .and_then(|e| e.changes.as_ref())
        .and_then(|c| c.values().next())
        .and_then(|v| v.first())
        .expect("edit present");
    // Must contain both pipeline steps in order.
    assert!(
        edit.new_text.contains("|> required f1"),
        "missing inner step: {:?}",
        edit.new_text
    );
    assert!(
        edit.new_text.contains("|> required f2"),
        "missing outer step: {:?}",
        edit.new_text
    );
    // The seed must come first.
    let f1_pos = edit.new_text.find("|> required f1").expect("f1 step");
    let f2_pos = edit.new_text.find("|> required f2").expect("f2 step");
    assert!(
        f1_pos < f2_pos,
        "inner step must precede outer step in pipeline: {:?}",
        edit.new_text
    );
}

// ── lint/unused-imports quick-fix ───────────────────────────────────────────

/// Run the real `ipe_lint` → `collect_lint` pipeline over `src` (as the single
/// module `module`) and return the one diagnostic whose code is `lint/<rule>`.
///
/// This exercises the actual engine, not a hand-built stand-in: the finding's
/// `Fix` (when the rule ships one) rides in `data` exactly as `collect_lint`
/// packages it, so a test built on this helper proves the full
/// lint → `data` → code-action pipeline, not just the decoder in isolation.
#[allow(clippy::expect_used)] // test helper: the lint not firing is the failure
fn lint_diag_for(module: &[&str], src: &str, rule: &str) -> lsp_types::Diagnostic {
    let mut user_texts = BTreeMap::new();
    user_texts.insert(
        module.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        src.to_owned(),
    );
    let config = LintConfig::default();
    let code = lsp_types::NumberOrString::String(format!("lint/{rule}"));
    collect_lint(&user_texts, &config, PositionEncoding::Utf16)
        .into_iter()
        .find(|(m, _)| m.iter().map(String::as_str).eq(module.iter().copied()))
        .into_iter()
        .flat_map(|(_, diags)| diags)
        .find(|d| d.code.as_ref() == Some(&code))
        .expect("the lint must flag this fixture")
}

/// Build a bare LSP diagnostic carrying `code` on the given zero-based line,
/// with no `data` — the shape a hand-built or otherwise fix-less diagnostic
/// takes. Used only to drive the fail-closed refusal below; every "offers an
/// action" test uses [`lint_diag_for`] instead, which carries the real fix.
fn lint_diag_on_line(code: &str, line: u32) -> lsp_types::Diagnostic {
    let range = Range {
        start: lsp_types::Position { line, character: 0 },
        end: lsp_types::Position { line, character: 6 },
    };
    lsp_types::Diagnostic {
        range,
        code: Some(lsp_types::NumberOrString::String(code.to_owned())),
        source: Some("ipe-lint".to_owned()),
        message: "unused import".to_owned(),
        ..lsp_types::Diagnostic::default()
    }
}

/// `lint/unused-imports` quick-fix: the action deletes the whole flagged
/// `import` line, and the result no longer contains that import.
#[test]
fn unused_imports_quick_fix_removes_the_import_line() {
    let src = "module Main exposing (main)\n\nimport Unused\n\nmain : Int\nmain = 1\n";
    let db = IpeDatabase::new();
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);

    let lsp_diag = lint_diag_for(&["Main"], src, "unused-imports");
    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        lsp_diag.range,
        std::slice::from_ref(&lsp_diag),
        PositionEncoding::Utf16,
    );
    let action = actions
        .into_iter()
        .find_map(|a| match a {
            CodeActionOrCommand::CodeAction(ca) => Some(ca),
            CodeActionOrCommand::Command(_) => None,
        })
        .expect("an unused-import diagnostic must offer a remove action");
    assert_eq!(action.title, "Remove unused import");
    let edit = action
        .edit
        .as_ref()
        .and_then(|e| e.changes.as_ref())
        .and_then(|c| c.values().next())
        .and_then(|v| v.first())
        .expect("edit present");
    let fixed = apply_edit(src, edit);
    assert!(
        !fixed.contains("import Unused"),
        "the unused import must be gone: {fixed:?}"
    );
    assert!(
        fixed.contains("main = 1"),
        "the rest of the module is untouched: {fixed:?}"
    );
}

/// The refusal: a `lint/<rule>` diagnostic that carries no `data` (no rule
/// ships one for every finding that lacks a `Fix` — e.g. a `NotFixable` rule,
/// or a `SigFix`-only one) yields no action. The generic decoder fails closed
/// on a missing fix payload rather than guessing an edit.
#[test]
fn lint_quick_fix_refuses_diagnostic_with_no_fix_data() {
    let src = "module Main exposing (main)\n\nimport Unused\n\nmain : Int\nmain = 1\n";
    let db = IpeDatabase::new();
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);

    // A diagnostic with the right code but no `data` — the shape a NotFixable
    // or SigFix-only rule's finding takes.
    let lsp_diag = lint_diag_on_line("lint/unused-imports", 5);
    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        lsp_diag.range,
        std::slice::from_ref(&lsp_diag),
        PositionEncoding::Utf16,
    );
    assert!(
        actions.is_empty(),
        "a diagnostic with no fix data must yield no action: {actions:?}"
    );
}

/// A multi-line unused import whose `exposing (…)` clause wraps onto a
/// continuation line. Deleting only the keyword's physical line would strand
/// the `exposing (bar, baz)` continuation and turn a compiling module into a
/// parse error. The fix must delete the WHOLE declaration, and the result must
/// still parse (SEAL — the quick-fix keeps a compiling program compiling).
#[test]
fn unused_imports_quick_fix_removes_a_multiline_exposing_import() {
    let db = IpeDatabase::new();
    // `Foo` is registered in the root, exposing `bar`/`baz`; the import names
    // them across two physical lines (2..=3) and never uses either → the
    // conservative unused-imports lint would flag the `import` keyword.
    let src = "module Main exposing (main)\n\nimport Foo\n    exposing (bar, baz)\n\nmain : Int\nmain = 1\n";
    let foo = file(
        &db,
        &["Foo"],
        "module Foo exposing (bar, baz)\n\nbar = 1\n\nbaz = 2\n",
    );
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Foo"], foo), (&["Main"], entry)]);

    let lsp_diag = lint_diag_for(&["Main"], src, "unused-imports");
    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        lsp_diag.range,
        std::slice::from_ref(&lsp_diag),
        PositionEncoding::Utf16,
    );
    let action = actions
        .into_iter()
        .find_map(|a| match a {
            CodeActionOrCommand::CodeAction(ca) => Some(ca),
            CodeActionOrCommand::Command(_) => None,
        })
        .expect("a multi-line unused import must offer a remove action");
    assert_eq!(action.title, "Remove unused import");
    let edit = action
        .edit
        .as_ref()
        .and_then(|e| e.changes.as_ref())
        .and_then(|c| c.values().next())
        .and_then(|v| v.first())
        .expect("edit present");

    let fixed = apply_edit(src, edit);
    assert!(
        !fixed.contains("import Foo"),
        "the keyword line is gone: {fixed:?}"
    );
    assert!(
        !fixed.contains("exposing (bar, baz)"),
        "the continuation line must NOT be stranded: {fixed:?}"
    );
    // SEAL: the fixed module still parses (no dangling `exposing` fragment).
    let mut interner = db.interner().lock();
    assert!(
        ipe_parse::parse_module(&fixed, &mut interner).is_ok(),
        "the fixed module must still parse: {fixed:?}"
    );
}

/// An unused import whose `exposing (…)` list is broken across several lines,
/// with the closing `)` on its own line below the last name. The clause end is
/// found by balancing the parens, so the whole list — down to the trailing `)`
/// — is removed and the module still parses.
#[test]
fn unused_imports_quick_fix_removes_a_wrapped_exposing_list() {
    let db = IpeDatabase::new();
    // The list spans lines 3..=6; the closing `)` is alone on line 6.
    let src = "module Main exposing (main)\n\nimport Foo\n    exposing ( bar\n             , baz\n             )\n\nmain : Int\nmain = 1\n";
    let foo = file(
        &db,
        &["Foo"],
        "module Foo exposing (bar, baz)\n\nbar = 1\n\nbaz = 2\n",
    );
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Foo"], foo), (&["Main"], entry)]);

    let lsp_diag = lint_diag_for(&["Main"], src, "unused-imports");
    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        lsp_diag.range,
        std::slice::from_ref(&lsp_diag),
        PositionEncoding::Utf16,
    );
    let action = actions
        .into_iter()
        .find_map(|a| match a {
            CodeActionOrCommand::CodeAction(ca) => Some(ca),
            CodeActionOrCommand::Command(_) => None,
        })
        .expect("a wrapped-list unused import must offer a remove action");
    let edit = action
        .edit
        .as_ref()
        .and_then(|e| e.changes.as_ref())
        .and_then(|c| c.values().next())
        .and_then(|v| v.first())
        .expect("edit present");

    let fixed = apply_edit(src, edit);
    assert!(
        !fixed.contains("import Foo"),
        "keyword line gone: {fixed:?}"
    );
    assert!(
        !fixed.contains("bar") && !fixed.contains("baz"),
        "the wrapped list contents must all be gone: {fixed:?}"
    );
    assert!(
        fixed.contains("main = 1"),
        "the rest of the module is untouched: {fixed:?}"
    );
    // SEAL: with the whole clause (incl. the lone closing paren) removed, the
    // fixed module still parses — no dangling `)` fragment is left behind.
    let mut interner = db.interner().lock();
    assert!(
        ipe_parse::parse_module(&fixed, &mut interner).is_ok(),
        "the fixed module must still parse: {fixed:?}"
    );
}

/// A multi-line unused import whose `as Alias` clause wraps onto a continuation
/// line. Same SEAL: deleting only the keyword line would strand `as Bar`.
#[test]
fn unused_imports_quick_fix_removes_a_multiline_as_import() {
    let db = IpeDatabase::new();
    let src = "module Main exposing (main)\n\nimport Foo\n    as Bar\n\nmain : Int\nmain = 1\n";
    let foo = file(&db, &["Foo"], "module Foo exposing (bar)\n\nbar = 1\n");
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Foo"], foo), (&["Main"], entry)]);

    let lsp_diag = lint_diag_for(&["Main"], src, "unused-imports");
    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        lsp_diag.range,
        std::slice::from_ref(&lsp_diag),
        PositionEncoding::Utf16,
    );
    let action = actions
        .into_iter()
        .find_map(|a| match a {
            CodeActionOrCommand::CodeAction(ca) => Some(ca),
            CodeActionOrCommand::Command(_) => None,
        })
        .expect("a multi-line `as` unused import must offer a remove action");
    let edit = action
        .edit
        .as_ref()
        .and_then(|e| e.changes.as_ref())
        .and_then(|c| c.values().next())
        .and_then(|v| v.first())
        .expect("edit present");

    let fixed = apply_edit(src, edit);
    assert!(
        !fixed.contains("import Foo"),
        "the keyword line is gone: {fixed:?}"
    );
    assert!(
        !fixed.contains("as Bar"),
        "the `as Bar` continuation must NOT be stranded: {fixed:?}"
    );
    let mut interner = db.interner().lock();
    assert!(
        ipe_parse::parse_module(&fixed, &mut interner).is_ok(),
        "the fixed module must still parse: {fixed:?}"
    );
}

// ── lint/unused-imports quick-fix: cursor away from the `import` keyword ───
// The diagnostic spans the whole declaration, so a code action requested with
// the cursor anywhere in it finds the overlapping diagnostic. These tests run
// the REAL `collect_lint` pipeline (not the synthetic `lint_diag_on_line`
// helper above) so they pin the actual range rather than a hand-picked
// stand-in.

/// The real `lint/unused-imports` diagnostic `collect_lint` produces for
/// `src`'s `Main` module — its range is [`ipe_syntax::Import::span`], not
/// just the `import` keyword.
#[allow(clippy::expect_used)] // test helper: a missing fixture finding is the failure
fn unused_import_diagnostic(src: &str) -> lsp_types::Diagnostic {
    let mut user_texts = BTreeMap::new();
    user_texts.insert(vec!["Main".to_owned()], src.to_owned());
    let per_module = collect_lint(&user_texts, &LintConfig::default(), PositionEncoding::Utf16);
    let (_, diags) = per_module
        .into_iter()
        .find(|(module, _)| module == &vec!["Main".to_owned()])
        .expect("Main module must appear in the lint report");
    diags
        .into_iter()
        .find(|d| {
            d.code
                == Some(lsp_types::NumberOrString::String(
                    "lint/unused-imports".to_owned(),
                ))
        })
        .expect("fixture must trigger lint/unused-imports")
}

/// `import Foo as Bar exposing (bar)` on line 2 (0-based): unused, since
/// neither `Bar` nor `bar` appears in `main`'s body.
const UNUSED_IMPORT_WIDE: &str =
    "module Main exposing (main)\n\nimport Foo as Bar exposing (bar)\n\nmain : Int\nmain = 1\n";

/// A `(line, start..end)` character range, built the same way the LSP wire
/// protocol addresses a cursor selection.
const fn point_range(line: u32, start: u32, end: u32) -> Range {
    Range {
        start: lsp_types::Position {
            line,
            character: start,
        },
        end: lsp_types::Position {
            line,
            character: end,
        },
    }
}

/// Asserts `actions` contains the "Remove unused import" quick fix.
#[track_caller]
fn assert_offers_remove_action(actions: &[CodeActionOrCommand]) {
    assert!(
        actions.iter().any(|a| matches!(
            a,
            CodeActionOrCommand::CodeAction(ca) if ca.title == "Remove unused import"
        )),
        "must offer the remove action: {actions:?}"
    );
}

/// Cursor on the module name (`Foo`, cols 7..10) offers the remove action --
/// nowhere near the `import` keyword, but inside the widened span.
#[test]
fn unused_imports_quick_fix_offered_with_cursor_on_module_name() {
    let src = UNUSED_IMPORT_WIDE;
    let db = IpeDatabase::new();
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);
    let diag = unused_import_diagnostic(src);
    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        point_range(2, 7, 10),
        std::slice::from_ref(&diag),
        PositionEncoding::Utf16,
    );
    assert_offers_remove_action(&actions);
}

/// Cursor within the `exposing (…)` list (`bar`, cols 28..31) offers the
/// remove action.
#[test]
fn unused_imports_quick_fix_offered_with_cursor_on_exposing_list() {
    let src = UNUSED_IMPORT_WIDE;
    let db = IpeDatabase::new();
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);
    let diag = unused_import_diagnostic(src);
    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        point_range(2, 28, 31),
        std::slice::from_ref(&diag),
        PositionEncoding::Utf16,
    );
    assert_offers_remove_action(&actions);
}

/// Cursor on the `as Alias` identifier (`Bar`, cols 14..17) offers the remove
/// action.
#[test]
fn unused_imports_quick_fix_offered_with_cursor_on_alias() {
    let src = UNUSED_IMPORT_WIDE;
    let db = IpeDatabase::new();
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);
    let diag = unused_import_diagnostic(src);
    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        point_range(2, 14, 17),
        std::slice::from_ref(&diag),
        PositionEncoding::Utf16,
    );
    assert_offers_remove_action(&actions);
}

/// The refusal: a cursor on the line right after the import declaration — a
/// genuinely unrelated line, outside even the widened span — offers no action.
#[test]
fn unused_imports_quick_fix_refuses_the_following_unrelated_line() {
    let src = UNUSED_IMPORT_WIDE;
    let db = IpeDatabase::new();
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);
    let diag = unused_import_diagnostic(src);
    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    // Line 4 (0-based) is `main : Int` — right after the import declaration.
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        point_range(4, 0, 4),
        std::slice::from_ref(&diag),
        PositionEncoding::Utf16,
    );
    assert!(
        actions.is_empty(),
        "the unrelated following line must yield no remove action: {actions:?}"
    );
}

/// Applies the "Remove unused import" quick fix the real `collect_lint`
/// diagnostic offers for `src`, returning the fixed text.
#[allow(clippy::expect_used)] // test helper: a missing action is the failure
fn apply_unused_import_fix(src: &str) -> String {
    let db = IpeDatabase::new();
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);
    let diag = unused_import_diagnostic(src);
    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        diag.range,
        std::slice::from_ref(&diag),
        PositionEncoding::Utf16,
    );
    let edit = actions
        .iter()
        .find_map(|a| match a {
            CodeActionOrCommand::CodeAction(ca) if ca.title == "Remove unused import" => ca
                .edit
                .as_ref()
                .and_then(|e| e.changes.as_ref())
                .and_then(|c| c.values().next())
                .and_then(|v| v.first()),
            CodeActionOrCommand::CodeAction(_) | CodeActionOrCommand::Command(_) => None,
        })
        .expect("an unused import must offer a remove action");
    let fixed = apply_edit(src, edit);
    let mut interner = db.interner().lock();
    assert!(
        ipe_parse::parse_module(&fixed, &mut interner).is_ok(),
        "the fixed module must still parse: {fixed:?}"
    );
    fixed
}

/// The refusal: a `)` inside a `--` comment in the list must not end the
/// removal early and strand the remaining `, baz )` lines.
#[test]
fn unused_import_fix_ignores_close_paren_in_line_comment() {
    let src = "module Main exposing (main)\n\nimport Foo exposing\n    ( bar -- keeps ) the old name\n    , baz\n    )\n\nmain : Int\nmain = 1\n";
    let fixed = apply_unused_import_fix(src);
    assert_eq!(
        fixed,
        "module Main exposing (main)\n\n\nmain : Int\nmain = 1\n"
    );
}

/// The refusal: a `(` inside a comment plus a stray `)` in a later comment
/// must not stretch the removal over the unrelated `main` declaration.
#[test]
fn unused_import_fix_leaves_later_declarations_untouched() {
    let src = "module Main exposing (main)\n\nimport Foo exposing (bar -- (\n    )\n\nmain : Int\nmain = 1 -- )\n";
    let fixed = apply_unused_import_fix(src);
    assert_eq!(
        fixed,
        "module Main exposing (main)\n\n\nmain : Int\nmain = 1 -- )\n"
    );
}

/// The refusal: a `{- -}` block comment between the alias and the `exposing`
/// clause must not stop the removal short and strand `exposing (bar)`.
#[test]
fn unused_import_fix_spans_block_comment_between_clauses() {
    let src = "module Main exposing (main)\n\nimport Foo\n    as Bar\n    {- ) -}\n    exposing (bar)\n\nmain : Int\nmain = 1\n";
    let fixed = apply_unused_import_fix(src);
    assert_eq!(
        fixed,
        "module Main exposing (main)\n\n\nmain : Int\nmain = 1\n"
    );
}

/// `prefer-pipeline` ships a local [`ipe_lint::Fix`] (it is, per the rule's own
/// doc, the one rule whose rewrite is provably semantics-preserving via `x |>
/// f == f x`), so it reaches an LSP quick-fix through the same generic path as
/// `unused-imports` — no rule-specific code in `code_actions.rs`.
#[test]
fn prefer_pipeline_quick_fix_rewrites_the_nested_call() {
    let db = IpeDatabase::new();
    let src = "module Main exposing (report)\n\n\nreport records =\n    String.concat (List.map fmt (List.filter live records))\n";
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);

    let lsp_diag = lint_diag_for(&["Main"], src, "prefer-pipeline");
    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        lsp_diag.range,
        std::slice::from_ref(&lsp_diag),
        PositionEncoding::Utf16,
    );
    let action = actions
        .into_iter()
        .find_map(|a| match a {
            CodeActionOrCommand::CodeAction(ca) => Some(ca),
            CodeActionOrCommand::Command(_) => None,
        })
        .expect("a nested call must offer a pipeline rewrite action");
    let edit = action
        .edit
        .as_ref()
        .and_then(|e| e.changes.as_ref())
        .and_then(|c| c.values().next())
        .and_then(|v| v.first())
        .expect("edit present");

    let fixed = apply_edit(src, edit);
    assert!(
        fixed.contains("records |> List.filter live |> List.map fmt |> String.concat"),
        "the rewrite is the author's own text re-threaded: {fixed:?}"
    );
    let mut interner = db.interner().lock();
    assert!(
        ipe_parse::parse_module(&fixed, &mut interner).is_ok(),
        "the fixed module must still parse: {fixed:?}"
    );
}

/// `unused-bindings` ships a local [`ipe_lint::Fix`] (prefix the name with
/// `_`), so the generic mechanism offers it as an LSP quick-fix with no
/// rule-specific code.
#[test]
fn unused_bindings_quick_fix_prefixes_the_name() {
    let db = IpeDatabase::new();
    let src = "module Main exposing (main)\n\nmain : Int\nmain =\n    let\n        waste = 1\n    in\n    2\n";
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);

    let lsp_diag = lint_diag_for(&["Main"], src, "unused-bindings");
    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        lsp_diag.range,
        std::slice::from_ref(&lsp_diag),
        PositionEncoding::Utf16,
    );
    let action = actions
        .into_iter()
        .find_map(|a| match a {
            CodeActionOrCommand::CodeAction(ca) => Some(ca),
            CodeActionOrCommand::Command(_) => None,
        })
        .expect("an unused let-binding must offer a prefix action");
    let edit = action
        .edit
        .as_ref()
        .and_then(|e| e.changes.as_ref())
        .and_then(|c| c.values().next())
        .and_then(|v| v.first())
        .expect("edit present");

    let fixed = apply_edit(src, edit);
    assert!(
        fixed.contains("_waste = 1"),
        "the binding is prefixed, not removed: {fixed:?}"
    );
    let mut interner = db.interner().lock();
    assert!(
        ipe_parse::parse_module(&fixed, &mut interner).is_ok(),
        "the fixed module must still parse: {fixed:?}"
    );
}

/// `unsafe-convention` is [`ipe_lint::Fixability::NotFixable`]: the rewrite --
/// keep the escape hatch or restructure the call — is an author judgement call,
/// so its findings never carry a [`ipe_lint::Fix`]. `collect_lint` threads no
/// `data` for such a finding, and the generic decoder in `code_actions.rs`
/// fails closed on that missing payload: no action, not a guess.
#[test]
fn unsafe_convention_offers_no_lsp_action() {
    let db = IpeDatabase::new();
    let src = "module Main exposing (main)\n\n\nmain =\n    unsafeFromInt 42\n";
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);

    let lsp_diag = lint_diag_for(&["Main"], src, "unsafe-convention");
    assert!(
        lsp_diag.data.is_none(),
        "a NotFixable rule's finding must carry no fix data: {lsp_diag:?}"
    );
    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        lsp_diag.range,
        std::slice::from_ref(&lsp_diag),
        PositionEncoding::Utf16,
    );
    assert!(
        actions.is_empty(),
        "an unsafe-convention diagnostic must offer no quick-fix: {actions:?}"
    );
}

/// `prim-param` is [`ipe_lint::Fixability::Fixable`] — a genuine fix exists --
/// but it is a cross-module [`ipe_lint::SigFix`] (a call-site rewrite in every
/// importer), which `collect_lint` deliberately never threads into `data` (only
/// a local, single-module [`ipe_lint::Fix`] travels that path). The rule is
/// `ipe lint --fix`-actionable but has no per-finding LSP scope, so its
/// diagnostic — like a `NotFixable` rule's — carries no fix data and the
/// generic decoder offers no action. This is the documented Tier-2 gap, not an
/// oversight: `Fixability::Fixable` records that a fix exists, not that this
/// particular transport can apply it.
#[test]
fn prim_param_sig_fix_only_offers_no_lsp_action() {
    let db = IpeDatabase::new();
    let src = "module Main exposing (connect)\n\n\nconnect : String -> Int -> String\nconnect host port =\n    host\n";
    let entry = file(&db, &["Main"], src);
    let root = root_of(&db, &[(&["Main"], entry)]);

    let lsp_diag = lint_diag_for(&["Main"], src, "prim-param");
    assert!(
        lsp_diag.data.is_none(),
        "a SigFix-only finding must carry no per-finding fix data: {lsp_diag:?}"
    );
    let uri = Url::from_file_path("/fake/Main.ipe").expect("uri");
    let actions = code_actions(
        DbView {
            db: &db,
            root,
            entry,
        },
        &["Main".to_owned()],
        Document {
            uri: &uri,
            text: src,
            version: None,
        },
        lsp_diag.range,
        std::slice::from_ref(&lsp_diag),
        PositionEncoding::Utf16,
    );
    assert!(
        actions.is_empty(),
        "a prim-param diagnostic must offer no quick-fix: {actions:?}"
    );
}

#[test]
fn edit_converges_error_then_clean() {
    let mut db = IpeDatabase::new();
    let a = file(&db, &["A"], DEP_A);
    let entry = file(&db, &["Main"], ENTRY_PARSE_ERROR);
    let root = root_of(&db, &[(&["A"], a), (&["Main"], entry)]);

    let all = collect(&db, root, entry);
    assert_eq!(diags_for(&all, &["Main"]).diagnostics.len(), 1);

    assert!(ipe_db::set_text_if_changed(&mut db, entry, ENTRY_OK));
    let all = collect(&db, root, entry);
    assert!(diags_for(&all, &["Main"]).diagnostics.is_empty());
    assert!(diags_for(&all, &["A"]).diagnostics.is_empty());
}
