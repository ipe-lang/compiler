//! Code actions: diagnostic-driven quick-fixes.
//!
//! For each LSP diagnostic in the requested range we produce zero or more
//! `CodeAction`s — workspace edits the client can apply with one click.
//!
//! **Supported quick-fixes (by diagnostic code):**
//!
//! - `IPE-T0001` (type mismatch) / no match arms on a `case`: no automatic fix
//!   (the shape is too varied).
//! - `IPE-L0106` (top-level function needs a type signature): "Add type
//!   annotation" — insert the inferred type annotation above the binding.
//! - `IPE-N0023` (module declaration name does not match its path on disk):
//!   "Rename module declaration to `Expected.Name`" — rewrites the `module X`
//!   token on line 0 to the path-expected name carried by the diagnostic message.
//! - `IPE-N0034` (a known module used without importing it): "Add import
//!   `M`" for each module the diagnostic names — insert the `import M` line
//!   into the module's import block, alphabetically among the existing imports.
//! - `IPE-N0035` (a shape-scoped `Cmd` / `Sub` imported from the wrong shape):
//!   "Change import to `Ipe.Tea.<Shape>.Cmd`" — repoint the offending import to
//!   the app's own shape, in place, leaving the `as Alias` binding untouched.
//! - `IPE-N0036` (removed stdlib surface): "Use `replacement` instead" — replaces
//!   the removed `Qualifier.name` call at the diagnostic span with the migration
//!   target name. No action is offered when the diagnostic carries no replacement.
//! - `IPE-N0040` (nested decoder pipeline): "Rewrite as `|>` pipeline" — rewrites
//!   a two-step hand-nested `required (required seed Ctor) f1 f2` into the
//!   order-preserving `seed Ctor |> required f1 |> required f2` form.
//! - `IPE-T0020` (`WebView` `view` returns `Html` instead of `View`): "Wrap in
//!   `Ui.html`" — inserts `Ui.html (` before and `)` after the expression at the
//!   diagnostic span.
//! - `lint/<rule>` (any lint finding whose rule declares
//!   [`ipe_lint::Fixability::Fixable`] and attaches a [`ipe_lint::Fix`] to the
//!   finding): the fix's own `describe` text, title-cased — a single
//!   text-range replacement applied verbatim. This arm is generic: it decodes
//!   the fix from the diagnostic's `data` payload (see
//!   `diagnostics::collect_lint`), so a newly fixable rule needs no change
//!   here — only its `Fix` in the rule and its `Fixability::Fixable` in the
//!   registry. A rule whose `Fixability` is `NotFixable`, or whose fix is a
//!   cross-module [`ipe_lint::SigFix`] (no per-finding LSP scope), carries no
//!   `data` and so offers no action.
//!
//! **Not offered — `IPE-N0048` (two definitions fold to one Rust name):** this
//! diagnostic is raised at IR-level name mangling and carries NO source spans
//! for either colliding definition, so no fail-closed rename edit can be
//! constructed — a rename would also have to locate and update every reference
//! the diagnostic cannot point at. Offering a guess would be a correctness bug,
//! so no action is produced.
//!
//! The provider is deliberately conservative: it only acts on codes it can
//! fix with a single-hunk text edit that it can prove correct. Unknown codes
//! produce no actions rather than a guess.

use lsp_types::{
    CodeAction, CodeActionKind, CodeActionOrCommand, Diagnostic, NumberOrString, Range, TextEdit,
    Url,
};

use ipe_db::{Db as _, IpeDatabase, SourceRoot};

use crate::offset::{PositionEncoding, offset_to_position};
use crate::workspace_edit::{Document, single_edit};

/// The salsa database view a quick-fix reads from.
///
/// Bundles the database, the source root, and the build's entry file so the
/// action signatures stay readable — they otherwise thread the same three
/// values through every helper.
#[derive(Clone, Copy)]
pub struct DbView<'a> {
    /// The salsa database snapshot.
    pub db: &'a IpeDatabase,
    /// The compilation's source root.
    pub root: SourceRoot,
    /// The build's entry file (the module `typecheck` is rooted at).
    pub entry: ipe_db::SourceFile,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute quick-fix code actions for the given range and diagnostic list.
///
/// `diagnostics` are the LSP diagnostics currently shown for `doc.uri` — the
/// client forwards them in the request so we do not need to re-collect them.
/// `doc.version` is the document version each produced edit is stamped with —
/// `None` yields an unversioned flat-`changes` edit, matching
/// [`crate::source_actions`]'s convention.
#[must_use]
pub fn code_actions(
    view: DbView<'_>,
    module: &[String],
    doc: Document<'_>,
    range: Range,
    diagnostics: &[Diagnostic],
    encoding: PositionEncoding,
) -> Vec<CodeActionOrCommand> {
    let Document { uri, text, version } = doc;
    let DbView { db, root, .. } = view;
    let files = root.files(db);
    let Some(&_file) = files.get(module) else {
        return Vec::new();
    };

    // Collect actions for each diagnostic that overlaps the requested range.
    let in_range: Vec<&Diagnostic> = diagnostics
        .iter()
        .filter(|d| ranges_overlap(d.range, range))
        .collect();

    if in_range.is_empty() {
        return Vec::new();
    }

    let mut actions: Vec<CodeActionOrCommand> = Vec::new();

    for diag in in_range {
        let Some(NumberOrString::String(code)) = &diag.code else {
            continue;
        };
        if code.starts_with("lint/") {
            // Every fixable lint rule reaches its LSP quick-fix through this one
            // generic path — decoding the `Fix` a rule attached to its finding's
            // `data`, never a per-rule arm below.
            if let Some(action) = lint_fix_action(diag, uri, text, encoding, version) {
                actions.push(CodeActionOrCommand::CodeAction(action));
            }
            continue;
        }
        match code.as_str() {
            "IPE-L0106" => {
                // A top-level function with no type signature — insert its
                // inferred type annotation above the binding.
                if let Some(action) =
                    add_type_annotation_action(view, module, uri, diag, text, encoding, version)
                {
                    actions.push(CodeActionOrCommand::CodeAction(action));
                }
            }
            "IPE-N0034" => {
                // A known module used without importing it — one action per
                // module the diagnostic's typed `importCandidates` names, each
                // inserting its `import M` line sorted among the existing imports.
                actions.extend(
                    add_import_actions(view, module, uri, diag, text, encoding, version)
                        .into_iter()
                        .map(CodeActionOrCommand::CodeAction),
                );
            }
            "IPE-N0035" => {
                // A shape-scoped `Cmd` / `Sub` imported from the wrong shape —
                // repoint the offending import to the app's own shape. The
                // diagnostic names both the wrong (`Ipe.Tea.Web.Cmd`) and correct
                // (`Ipe.Tea.Cli.Cmd`) module paths.
                if let Some(action) =
                    repoint_shape_import_action(diag, uri, text, encoding, version)
                {
                    actions.push(CodeActionOrCommand::CodeAction(action));
                }
            }
            "IPE-N0023" => {
                // The `module` declaration name does not match the path on disk.
                // The diagnostic message carries the expected name after
                // `expected `` — replace the declared name token on line 0.
                if let Some(action) = rename_module_decl_action(diag, uri, text, encoding, version)
                {
                    actions.push(CodeActionOrCommand::CodeAction(action));
                }
            }
            "IPE-N0036" => {
                // A removed stdlib surface: replace the call at the diagnostic
                // span with the migration target name, when one is carried.
                if let Some(action) =
                    replace_removed_surface_action(diag, uri, text, encoding, version)
                {
                    actions.push(CodeActionOrCommand::CodeAction(action));
                }
            }
            "IPE-N0040" => {
                // Hand-nested decoder pipeline: offer to rewrite as `|>` chain.
                if let Some(action) =
                    rewrite_nested_decoder_action(diag, uri, text, encoding, version)
                {
                    actions.push(CodeActionOrCommand::CodeAction(action));
                }
            }
            "IPE-T0020" => {
                // WebView `view` returns `Html` instead of `View Web msg` —
                // wrap the expression at the diagnostic span in `Ui.html ( … )`.
                if let Some(action) = wrap_in_ui_html_action(diag, uri, text, encoding, version) {
                    actions.push(CodeActionOrCommand::CodeAction(action));
                }
            }
            _ => {}
        }
    }

    actions
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ranges_overlap(a: Range, b: Range) -> bool {
    a.start <= b.end && b.start <= a.end
}

/// Quick-fix that inserts a type annotation above the binding named in the
/// diagnostic message. Extracts the name and inferred type from the message.
fn add_type_annotation_action(
    view: DbView<'_>,
    module: &[String],
    uri: &Url,
    diag: &Diagnostic,
    text: &str,
    encoding: PositionEncoding,
    version: Option<i32>,
) -> Option<CodeAction> {
    // Try to extract name + type from the solved type environment.
    // Diagnostic range points at the name token — resolve it via the parse
    // tree to find the line the annotation should precede.
    let DbView { db, root, entry } = view;
    let files = root.files(db);
    let &file = files.get(module)?;
    let parsed = ipe_db::parse(db, file).clone().ok()?;
    let byte = {
        let lo = diag.range.start;
        u32::try_from(crate::offset::position_to_offset(text, lo, encoding)).unwrap_or(u32::MAX)
    };
    // Find which top-level binding spans this byte.
    let interner = db.interner().lock();
    let mut found_name: Option<String> = None;
    let mut annotation_line: Option<u32> = None;
    for value in &parsed.values {
        let name_span = value.value.name.span;
        if name_span.lo <= byte && byte < name_span.hi {
            found_name = interner.resolve(value.value.name.value).map(str::to_owned);
            annotation_line = Some(offset_to_position(text, name_span.lo as usize, encoding).line);
            break;
        }
    }
    drop(interner);
    let name = found_name?;
    let insert_line = annotation_line?;

    // Retrieve inferred type from the solved type environment.
    let solved = ipe_db::typecheck(db, root, entry).clone().ok()?;
    let mut interner = db.interner().lock();
    let home: Vec<ipe_intern::Symbol> = module
        .iter()
        .map(|s| interner.intern(s).ok())
        .collect::<Option<Vec<_>>>()?;
    let name_sym = interner.intern(&name).ok()?;
    drop(interner);

    let ty = solved.env.get(&(home, name_sym))?;
    let interner = db.interner().lock();
    let mut namer = ipe_types::VarNamer::new();
    let doc = ipe_types::ty_to_doc(ty, &interner, &mut namer).ok()?;
    drop(interner);
    let ty_str = ipe_diagnostics::render_ty(&doc);

    // Synthesise `name : Type\n` inserted at the start of `insert_line`.
    let insert_byte = line_byte_range(text, insert_line as usize).0;
    let insert_pos = offset_to_position(text, insert_byte, encoding);
    let annotation = format!("{name} : {ty_str}\n");
    let edit = TextEdit {
        range: Range {
            start: insert_pos,
            end: insert_pos,
        },
        new_text: annotation,
    };
    Some(CodeAction {
        title: format!("Add type annotation for `{name}`"),
        kind: Some(CodeActionKind::QUICKFIX),
        diagnostics: Some(vec![diag.clone()]),
        edit: Some(single_edit(uri, version, edit)),
        command: None,
        is_preferred: Some(true),
        disabled: None,
        data: None,
    })
}

/// Quick-fixes that insert an `import M` line for each module an IPE-N0034
/// diagnostic names.
///
/// The modules come from the diagnostic's typed `importCandidates` payload
/// (set by [`crate::diagnostics::to_lsp`]), never from its prose. Each line is
/// inserted alphabetically among the existing `import` lines (import order is
/// not significant to the compiler, so a sorted position is both valid and
/// predictable); with no existing imports it goes just below the
/// `module … exposing (…)` header, separated by a blank line to match
/// first-party formatting. A sole candidate is the preferred fix.
fn add_import_actions(
    view: DbView<'_>,
    module: &[String],
    uri: &Url,
    diag: &Diagnostic,
    text: &str,
    encoding: PositionEncoding,
    version: Option<i32>,
) -> Vec<CodeAction> {
    let candidates = crate::diagnostics::import_candidates(diag);
    if candidates.is_empty() {
        return Vec::new();
    }
    let Some(block) = import_block(view, module, text, encoding) else {
        return Vec::new();
    };
    let preferred = candidates.len() == 1;
    candidates
        .iter()
        .filter_map(|import_module| {
            let edit = block.insert(import_module, text, encoding)?;
            Some(CodeAction {
                title: format!("Add import {import_module}"),
                kind: Some(CodeActionKind::QUICKFIX),
                diagnostics: Some(vec![diag.clone()]),
                edit: Some(single_edit(uri, version, edit)),
                command: None,
                is_preferred: Some(preferred),
                disabled: None,
                data: None,
            })
        })
        .collect()
}

/// A module's existing imports and where an import-less block would begin.
struct ImportBlock {
    /// Each import as (dotted path, byte offset of its line start).
    imports: Vec<(String, usize)>,
    /// The last byte of the header's `exposing (...)` clause.
    header_end: usize,
}

/// The import block of `module`'s current parse.
fn import_block(
    view: DbView<'_>,
    module: &[String],
    text: &str,
    encoding: PositionEncoding,
) -> Option<ImportBlock> {
    let DbView { db, root, .. } = view;
    let files = root.files(db);
    let &file = files.get(module)?;
    let parsed = ipe_db::parse(db, file).clone().ok()?;

    // Existing imports as (dotted-path, byte offset of the import declaration).
    // The import keyword starts at the beginning of the line that its module
    // path begins on, so we snap each path span back to its line start.
    let interner = db.interner().lock();
    let mut imports: Vec<(String, usize)> = Vec::with_capacity(parsed.imports.len());
    for imp in &parsed.imports {
        let dotted: Option<Vec<&str>> = imp
            .name
            .value
            .iter()
            .map(|&s| interner.resolve(s))
            .collect();
        let Some(segs) = dotted else { continue };
        let path = segs.join(".");
        let line = offset_to_position(text, imp.name.span.lo as usize, encoding).line as usize;
        let (line_start, _) = line_byte_range(text, line);
        imports.push((path, line_start));
    }
    // The last byte of the header's `exposing (...)` clause: where an
    // import-less module's new import block begins.
    let header_end = parsed.exposing.span.hi as usize;
    drop(interner);
    Some(ImportBlock {
        imports,
        header_end,
    })
}

impl ImportBlock {
    /// The edit inserting `import import_module`, or `None` when it is already
    /// imported (the diagnostic is stale and a duplicate never fixes anything).
    fn insert(
        &self,
        import_module: &str,
        text: &str,
        encoding: PositionEncoding,
    ) -> Option<TextEdit> {
        let Self {
            imports,
            header_end,
        } = self;
        if imports.iter().any(|(path, _)| path == import_module) {
            return None;
        }
        let (insert_byte, new_text) =
            import_insertion(imports, *header_end, import_module, text, encoding);
        let insert_pos = offset_to_position(text, insert_byte, encoding);
        Some(TextEdit {
            range: Range {
                start: insert_pos,
                end: insert_pos,
            },
            new_text,
        })
    }
}

/// Where `import import_module` goes in `imports`, and the text to insert.
fn import_insertion(
    imports: &[(String, usize)],
    header_end: usize,
    import_module: &str,
    text: &str,
    encoding: PositionEncoding,
) -> (usize, String) {
    if imports.is_empty() {
        // No imports yet: open the block just after the header, one blank line
        // down, matching the `module …\n\n\nimport …` first-party convention.
        let after_header_line = offset_to_position(text, header_end, encoding).line as usize;
        let (_, line_end) = line_byte_range(text, after_header_line);
        (line_end, format!("\nimport {import_module}\n"))
    } else if let Some((_, start)) = imports
        .iter()
        .find(|(path, _)| path.as_str() > import_module)
    {
        // Insert before the first existing import that sorts after the new one.
        (*start, format!("import {import_module}\n"))
    } else {
        // Sorts last: append after the final import line.
        let last_line_start = imports.iter().map(|(_, s)| *s).max().unwrap_or(0);
        let last_line = offset_to_position(text, last_line_start, encoding).line as usize;
        let (_, line_end) = line_byte_range(text, last_line);
        (line_end, format!("import {import_module}\n"))
    }
}

/// Quick-fix that repoints an offending `Ipe.Tea.<WrongShape>.{Cmd,Sub}` import
/// to the app's own shape, named by an IPE-N0035 diagnostic.
///
/// The message backtick-quotes both the wrong module path (first quoted token)
/// and the correct one (the quoted token before `instead`). The offending import
/// occupies the diagnostic's line, so the fix replaces the wrong path text with
/// the correct one in place, leaving the `as Alias` binding untouched.
fn repoint_shape_import_action(
    diag: &Diagnostic,
    uri: &Url,
    text: &str,
    encoding: PositionEncoding,
    version: Option<i32>,
) -> Option<CodeAction> {
    let (wrong, correct) = shape_paths_from_message(&diag.message)?;

    // The import line is the one the diagnostic points at. Replace the wrong
    // module path with the correct one wherever it appears on that line — the
    // path is a unique token there (the alias differs), so a single replace is
    // exact.
    let line = diag.range.start.line as usize;
    let (line_start, line_end) = line_byte_range(text, line);
    let line_text = text.get(line_start..line_end)?;
    let col = line_text.find(&wrong)?;
    let start_byte = line_start + col;
    let end_byte = start_byte + wrong.len();

    let start = offset_to_position(text, start_byte, encoding);
    let end = offset_to_position(text, end_byte, encoding);
    let edit = TextEdit {
        range: Range { start, end },
        new_text: correct.clone(),
    };
    Some(CodeAction {
        title: format!("Change import to {correct}"),
        kind: Some(CodeActionKind::QUICKFIX),
        diagnostics: Some(vec![diag.clone()]),
        edit: Some(single_edit(uri, version, edit)),
        command: None,
        is_preferred: Some(true),
        disabled: None,
        data: None,
    })
}

/// Quick-fix for IPE-N0023: rename the `module X` declaration on line 0 to the
/// path-expected name extracted from the diagnostic message.
///
/// `plain_message` renders IPE-N0023 as:
/// `"module path mismatch: declared as X, expected Y\nnote: …"`.
/// We extract `Y` from the last backtick-quoted token on the first line
/// and replace the declared name token on line 0.
fn rename_module_decl_action(
    diag: &Diagnostic,
    uri: &Url,
    text: &str,
    encoding: PositionEncoding,
    version: Option<i32>,
) -> Option<CodeAction> {
    let expected = expected_module_name_from_message(&diag.message)?;

    // Line 0 must start with `module ` followed by the declared name. Locate the
    // name token by scanning past the keyword and any whitespace.
    let line0 = text.lines().next()?;
    let rest = line0.strip_prefix("module ")?;
    let declared_start_in_line = "module ".len() + rest.len() - rest.trim_start().len();
    let name_text = rest.trim_start();
    // The declared name runs to the first space or end of the identifier.
    let name_len = name_text
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '.')
        .unwrap_or(name_text.len());
    if name_len == 0 {
        return None;
    }
    let start_byte = declared_start_in_line;
    let end_byte = start_byte + name_len;

    let start = offset_to_position(text, start_byte, encoding);
    let end = offset_to_position(text, end_byte, encoding);
    let edit = TextEdit {
        range: Range { start, end },
        new_text: expected.clone(),
    };
    Some(CodeAction {
        title: format!("Rename module declaration to `{expected}`"),
        kind: Some(CodeActionKind::QUICKFIX),
        diagnostics: Some(vec![diag.clone()]),
        edit: Some(single_edit(uri, version, edit)),
        command: None,
        is_preferred: Some(true),
        disabled: None,
        data: None,
    })
}

/// Quick-fix for IPE-N0036: replace the removed `Qualifier.name` call at the
/// diagnostic span with the migration replacement name.
///
/// `plain_message` for IPE-N0036 with a replacement is:
/// `"… has been removed; use `replacement` instead\nnote: …"`.
/// We lift the replacement out of the backtick pair before ` instead`.
/// No action is offered when no replacement exists.
fn replace_removed_surface_action(
    diag: &Diagnostic,
    uri: &Url,
    text: &str,
    encoding: PositionEncoding,
    version: Option<i32>,
) -> Option<CodeAction> {
    let replacement = replacement_from_removed_surface_message(&diag.message)?;

    // The diagnostic span covers the `Qualifier.name` call. Replace it verbatim.
    let start = offset_to_position(
        text,
        position_to_byte(text, diag.range.start, encoding),
        encoding,
    );
    let end = offset_to_position(
        text,
        position_to_byte(text, diag.range.end, encoding),
        encoding,
    );
    let edit = TextEdit {
        range: Range { start, end },
        new_text: replacement.clone(),
    };
    Some(CodeAction {
        title: format!("Replace with `{replacement}`"),
        kind: Some(CodeActionKind::QUICKFIX),
        diagnostics: Some(vec![diag.clone()]),
        edit: Some(single_edit(uri, version, edit)),
        command: None,
        is_preferred: Some(true),
        disabled: None,
        data: None,
    })
}

/// Quick-fix for IPE-N0040: rewrite a two-step hand-nested decoder as a `|>`
/// pipeline, preserving field-binding order.
///
/// The fix applies only when the diagnostic span covers source of the shape
/// `required f2 (required f1 (seed Ctor))` (or `optional`/`requiredAt`/`custom`
/// equivalents). More deeply nested shapes are left for the user — the action
/// is deliberately conservative (it replaces only when it can prove correctness).
///
/// The produced pipeline:
/// ```text
/// seed Ctor
///     |> required f1
///     |> required f2
/// ```
fn rewrite_nested_decoder_action(
    diag: &Diagnostic,
    uri: &Url,
    text: &str,
    encoding: PositionEncoding,
    version: Option<i32>,
) -> Option<CodeAction> {
    let start_byte = position_to_byte(text, diag.range.start, encoding);
    let end_byte = position_to_byte(text, diag.range.end, encoding);
    let span_text = text.get(start_byte..end_byte)?;

    // Rewrite: detect the two-step shape and build the |> pipeline.
    let rewritten = rewrite_two_step_decoder(span_text)?;

    let start = offset_to_position(text, start_byte, encoding);
    let end = offset_to_position(text, end_byte, encoding);
    let edit = TextEdit {
        range: Range { start, end },
        new_text: rewritten,
    };
    Some(CodeAction {
        title: "Rewrite as `|>` pipeline".to_owned(),
        kind: Some(CodeActionKind::QUICKFIX),
        diagnostics: Some(vec![diag.clone()]),
        edit: Some(single_edit(uri, version, edit)),
        command: None,
        is_preferred: Some(true),
        disabled: None,
        data: None,
    })
}

/// Quick-fix for IPE-T0020: wrap the expression at the diagnostic span in
/// `Ui.html ( … )`.
///
/// The `WebView` `view` function must return `View Web msg`, not `Html msg`. The
/// canonical one-line fix is `Ui.html (originalExpression)`.
fn wrap_in_ui_html_action(
    diag: &Diagnostic,
    uri: &Url,
    text: &str,
    encoding: PositionEncoding,
    version: Option<i32>,
) -> Option<CodeAction> {
    let start_byte = position_to_byte(text, diag.range.start, encoding);
    let end_byte = position_to_byte(text, diag.range.end, encoding);
    let inner = text.get(start_byte..end_byte)?;
    if inner.is_empty() {
        return None;
    }
    let new_text = format!("Ui.html ({inner})");
    let start = offset_to_position(text, start_byte, encoding);
    let end = offset_to_position(text, end_byte, encoding);
    let edit = TextEdit {
        range: Range { start, end },
        new_text,
    };
    Some(CodeAction {
        title: "Wrap in `Ui.html`".to_owned(),
        kind: Some(CodeActionKind::QUICKFIX),
        diagnostics: Some(vec![diag.clone()]),
        edit: Some(single_edit(uri, version, edit)),
        command: None,
        is_preferred: Some(true),
        disabled: None,
        data: None,
    })
}

/// Quick-fix for any `lint/<rule>` diagnostic.
///
/// Decodes the `Fix` a rule attached to its finding via `data` (see
/// `diagnostics::collect_lint`'s `"fix"` payload: `describe`, byte offsets
/// `lo`/`hi`, and `replacement`) and turns it into a single-hunk `TextEdit`.
/// This is the whole of the generic mechanism the module doc promises: a rule
/// that ships a [`ipe_lint::Fix`] gets an LSP quick-fix for free, with no
/// per-rule code in this file.
///
/// Fail-closed: a diagnostic with no `data`, a malformed `fix` payload, or a
/// span that is out of range or lands off a UTF-8 char boundary yields no
/// action rather than guessing or slicing unsafely.
fn lint_fix_action(
    diag: &Diagnostic,
    uri: &Url,
    text: &str,
    encoding: PositionEncoding,
    version: Option<i32>,
) -> Option<CodeAction> {
    let data = diag.data.as_ref()?;
    let fix = data.get("fix")?;
    let describe = fix.get("describe")?.as_str()?;
    let lo = usize::try_from(fix.get("lo")?.as_u64()?).ok()?;
    let hi = usize::try_from(fix.get("hi")?.as_u64()?).ok()?;
    let replacement = fix.get("replacement")?.as_str()?;
    if lo > hi || hi > text.len() || !text.is_char_boundary(lo) || !text.is_char_boundary(hi) {
        return None;
    }

    let start = offset_to_position(text, lo, encoding);
    let end = offset_to_position(text, hi, encoding);
    let edit = TextEdit {
        range: Range { start, end },
        new_text: replacement.to_owned(),
    };
    Some(CodeAction {
        title: capitalize_first(describe),
        kind: Some(CodeActionKind::QUICKFIX),
        diagnostics: Some(vec![diag.clone()]),
        edit: Some(single_edit(uri, version, edit)),
        command: None,
        is_preferred: Some(true),
        disabled: None,
        data: None,
    })
}

/// Capitalize the first character of `s`, leaving the rest untouched — turns a
/// `Fix::describe` phrase (`"remove unused import"`) into a title-case action
/// title (`"Remove unused import"`).
fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().collect::<String>() + chars.as_str()
    })
}

/// Extract the expected module name from an IPE-N0023 `plain_message`.
///
/// The message format is:
/// `"module path mismatch: declared as `X`, expected `Y`\n…"`.
/// Returns the content of the last backtick pair on the first line.
fn expected_module_name_from_message(message: &str) -> Option<String> {
    // Work only on the first line (the title + label portion).
    let first_line = message.lines().next()?;
    // Walk backtick pairs; the LAST one on the first line is the expected name.
    let mut last: Option<&str> = None;
    for chunk in first_line.split('`').skip(1).step_by(2) {
        if !chunk.is_empty() {
            last = Some(chunk);
        }
    }
    Some(last?.to_owned())
}

/// Extract the replacement name from an IPE-N0036 `plain_message`.
///
/// When a replacement exists the label is `"… use `replacement` instead"`.
/// Returns `None` when the message does not contain ` instead"` after a backtick
/// pair, i.e. when the removed surface has no direct replacement.
fn replacement_from_removed_surface_message(message: &str) -> Option<String> {
    // Walk backtick pairs on the first line; accept the one immediately before
    // ` instead`.
    let first_line = message.lines().next()?;
    for candidate in first_line.split('`').skip(1).step_by(2) {
        // Reconstruct enough suffix to detect " instead": after the closing backtick
        // of `candidate`, the raw text would be the next even-indexed split segment.
        // We check by looking at the original string for the pattern.
        let marker = format!("`{candidate}` instead");
        if first_line.contains(&marker) && !candidate.is_empty() {
            return Some(candidate.to_owned());
        }
    }
    None
}

/// Convert an LSP `Position` back to a byte offset in `text`.
///
/// This is the inverse of `offset_to_position`, capped at `text.len()`.
fn position_to_byte(text: &str, pos: lsp_types::Position, encoding: PositionEncoding) -> usize {
    crate::offset::position_to_offset(text, pos, encoding)
}

/// Attempt to rewrite a two-step hand-nested decoder into a `|>` pipeline.
///
/// Accepts `combinator2 field2 (combinator1 field1 (seed Ctor))` and produces:
/// `seed Ctor\n    |> combinator1 field1\n    |> combinator2 field2`.
///
/// Returns `None` when the pattern does not match (deeper nesting, missing
/// parens, or any ambiguity) — conservative: never produce a wrong rewrite.
fn rewrite_two_step_decoder(src: &str) -> Option<String> {
    // The shape is: `OUTER_COMBINATOR OUTER_ARG (INNER_COMBINATOR INNER_ARG (SEED))`.
    // We split at the outermost balanced paren that follows a combinator+arg prefix.
    let src = src.trim();

    // Split `combinator arg` from the rest by finding the first `(`.
    let paren_pos = src.find('(')?;
    let outer_prefix = src[..paren_pos].trim();
    // outer_prefix should be "combinator arg" — exactly two whitespace-separated tokens.
    let mut outer_parts = outer_prefix.split_whitespace();
    let outer_combinator = outer_parts.next()?;
    let outer_arg = outer_parts.next()?;
    if outer_parts.next().is_some() {
        return None; // more than two tokens — too complex
    }

    // The inner content is between the outer parens; find the matching close.
    let inner_with_parens = src.get(paren_pos..)?;
    let inner_content = strip_balanced_parens(inner_with_parens)?;
    let inner = inner_content.trim();

    // The inner content must also match `combinator arg (seed)`.
    let inner_paren = inner.find('(')?;
    let inner_prefix = inner[..inner_paren].trim();
    let mut inner_parts = inner_prefix.split_whitespace();
    let inner_combinator = inner_parts.next()?;
    let inner_arg = inner_parts.next()?;
    if inner_parts.next().is_some() {
        return None;
    }

    // The seed is everything inside the innermost parens.
    let seed_with_parens = inner.get(inner_paren..)?;
    let seed = strip_balanced_parens(seed_with_parens)?.trim().to_owned();
    if seed.is_empty() {
        return None;
    }

    Some(format!(
        "{seed}\n    |> {inner_combinator} {inner_arg}\n    |> {outer_combinator} {outer_arg}"
    ))
}

/// Strip one level of matching outer parentheses from `s`, which must start
/// with `(`. Returns `None` when parens are unbalanced or the string does not
/// end at the matching close paren.
fn strip_balanced_parens(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'(') {
        return None;
    }
    let mut depth: usize = 0;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    // Must consume the whole string (no trailing chars).
                    if i + 1 == bytes.len() {
                        return s.get(1..i);
                    }
                    return None;
                }
            }
            _ => {}
        }
    }
    None // unbalanced
}

/// Lift the (wrong, correct) `Ipe.Tea.<Shape>.{Cmd,Sub}` module paths out of an
/// IPE-N0035 message. The message quotes the wrong path first and the correct
/// path last (the one preceding `instead`); both begin `Ipe.Tea.`. Returns
/// `None` if the message does not carry two such quoted paths, so a reworded
/// diagnostic simply produces no action.
fn shape_paths_from_message(message: &str) -> Option<(String, String)> {
    let quoted: Vec<&str> = message
        .split('`')
        // Every ODD-indexed split segment is the content between a backtick pair.
        .skip(1)
        .step_by(2)
        .filter(|s| s.starts_with("Ipe.Tea.") && (s.ends_with(".Cmd") || s.ends_with(".Sub")))
        .collect();
    let wrong = (*quoted.first()?).to_owned();
    let correct = (*quoted.last()?).to_owned();
    if wrong == correct {
        return None;
    }
    Some((wrong, correct))
}

/// Returns `(start_byte, end_byte)` for `line` (0-based), where `end_byte`
/// points just past the trailing `\n` (or to `text.len()` on the last line).
fn line_byte_range(text: &str, line: usize) -> (usize, usize) {
    let mut byte = 0;
    for (i, l) in text.split('\n').enumerate() {
        let next = byte + l.len() + 1; // +1 for the '\n'
        if i == line {
            return (byte, next.min(text.len()));
        }
        byte = next;
    }
    (text.len(), text.len())
}

#[cfg(test)]
mod tests {
    use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};
    use lsp_types::{
        Diagnostic, DiagnosticSeverity, DocumentChanges, NumberOrString, Position, Range, Url,
        WorkspaceEdit,
    };

    use crate::offset::PositionEncoding;
    use crate::workspace_edit::Document;

    use super::{CodeActionOrCommand, DbView, code_actions};

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

    fn diag_at(line: u32, code: &str) -> Diagnostic {
        #[allow(deprecated)]
        Diagnostic {
            range: Range {
                start: Position { line, character: 0 },
                end: Position {
                    line,
                    character: 10,
                },
            },
            severity: Some(DiagnosticSeverity::WARNING),
            code: Some(NumberOrString::String(code.to_owned())),
            code_description: None,
            source: Some("ipe".to_owned()),
            message: format!("test diagnostic {code}"),
            related_information: None,
            tags: None,
            data: None,
        }
    }

    #[test]
    fn unknown_code_produces_no_actions() {
        let db = IpeDatabase::new();
        let src = "module Main exposing (main)\n\nmain : Int\nmain =\n    42\n";
        let entry = file(&db, &["Main"], src);
        let root = root_of(&db, &[(&["Main"], entry)]);
        let uri = Url::from_file_path("/fake/Main.ipe").unwrap();
        let range = Range {
            start: Position {
                line: 0,
                character: 0,
            },
            end: Position {
                line: 4,
                character: 0,
            },
        };
        let diag = diag_at(2, "IPE-X9999");
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
            &[diag],
            PositionEncoding::Utf16,
        );
        assert!(actions.is_empty(), "unknown code → no actions");
    }

    /// A value-not-found (`IPE-N0001`) and an unknown-module (`IPE-N0004`)
    /// diagnostic must offer NO quick-fix — neither is an unused import nor a
    /// missing annotation, so no line-deleting or annotation-inserting action
    /// may be offered against the user's code.
    #[test]
    fn value_not_found_and_unknown_module_produce_no_actions() {
        let db = IpeDatabase::new();
        let src = "module Main exposing (main)\n\nimport Unused\n\nmain : Int\nmain =\n    42\n";
        let entry = file(&db, &["Main"], src);
        let root = root_of(&db, &[(&["Main"], entry)]);
        let uri = Url::from_file_path("/fake/Main.ipe").unwrap();
        let range = Range {
            start: Position {
                line: 0,
                character: 0,
            },
            end: Position {
                line: 6,
                character: 0,
            },
        };
        for code in ["IPE-N0001", "IPE-N0004"] {
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
                &[diag_at(2, code)],
                PositionEncoding::Utf16,
            );
            assert!(
                actions.is_empty(),
                "{code} must offer no quick-fix; got {} action(s)",
                actions.len()
            );
        }
    }

    fn module_mismatch_diag() -> Diagnostic {
        #[allow(deprecated)]
        Diagnostic {
            range: Range {
                start: Position {
                    line: 0,
                    character: 0,
                },
                end: Position {
                    line: 0,
                    character: 5,
                },
            },
            severity: Some(DiagnosticSeverity::ERROR),
            code: Some(NumberOrString::String("IPE-N0023".to_owned())),
            code_description: None,
            source: Some("ipe".to_owned()),
            message: "module path mismatch: declared as `Wrong`, expected `Main`".to_owned(),
            related_information: None,
            tags: None,
            data: None,
        }
    }

    fn module_mismatch_actions(version: Option<i32>) -> Vec<CodeActionOrCommand> {
        let db = IpeDatabase::new();
        let src = "module Wrong exposing (main)\n\nmain : Int\nmain =\n    42\n";
        let entry = file(&db, &["Main"], src);
        let root = root_of(&db, &[(&["Main"], entry)]);
        let uri = Url::from_file_path("/fake/Main.ipe").unwrap();
        let range = Range {
            start: Position {
                line: 0,
                character: 0,
            },
            end: Position {
                line: 0,
                character: 20,
            },
        };
        code_actions(
            DbView {
                db: &db,
                root,
                entry,
            },
            &["Main".to_owned()],
            Document {
                uri: &uri,
                text: src,
                version,
            },
            range,
            &[module_mismatch_diag()],
            PositionEncoding::Utf16,
        )
    }

    fn only_edit(actions: &[CodeActionOrCommand]) -> Option<&WorkspaceEdit> {
        match actions {
            [CodeActionOrCommand::CodeAction(action)] => action.edit.as_ref(),
            _ => None,
        }
    }

    #[test]
    fn a_known_version_yields_versioned_document_changes() {
        let actions = module_mismatch_actions(Some(5));
        let edit = only_edit(&actions).expect("exactly one code action with an edit");
        assert!(edit.changes.is_none(), "{edit:?}");
        assert!(
            matches!(&edit.document_changes, Some(DocumentChanges::Edits(edits))
                if matches!(edits.as_slice(), [e] if e.text_document.version == Some(5))),
            "{edit:?}"
        );
    }

    #[test]
    fn no_known_version_falls_back_to_unversioned_flat_changes() {
        let actions = module_mismatch_actions(None);
        let edit = only_edit(&actions).expect("exactly one code action with an edit");
        assert!(edit.document_changes.is_none(), "{edit:?}");
        assert!(
            matches!(&edit.changes, Some(m) if !m.is_empty()),
            "{edit:?}"
        );
    }

    /// An IPE-N0034 diagnostic offers one "Add import" action per typed
    /// candidate, none preferred when several match; a diagnostic without the
    /// typed payload offers none, whatever its prose says.
    #[test]
    fn add_import_action_offers_each_candidate() {
        let db = IpeDatabase::new();
        let src = "module Main exposing (main)\n\nimport Ipe.List\n\nmain =\n    Utils.f 1\n";
        let entry = file(&db, &["Main"], src);
        let root = root_of(&db, &[(&["Main"], entry)]);
        let uri = Url::from_file_path("/fake/Main.ipe").unwrap();
        let range = Range {
            start: Position {
                line: 0,
                character: 0,
            },
            end: Position {
                line: 6,
                character: 0,
            },
        };
        let mut typed = diag_at(5, "IPE-N0034");
        typed.data = Some(serde_json::json!({ "importCandidates": ["App.Utils", "Lib.Utils"] }));
        let mut prose_only = diag_at(5, "IPE-N0034");
        prose_only.message = "add `import Lib.Utils` to use it".to_owned();
        let run = |diag: Diagnostic| {
            code_actions(
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
                &[diag],
                PositionEncoding::Utf16,
            )
        };
        let actions = run(typed);
        let titles: Vec<(&str, Option<bool>)> = actions
            .iter()
            .filter_map(|a| match a {
                CodeActionOrCommand::CodeAction(a) => Some((a.title.as_str(), a.is_preferred)),
                CodeActionOrCommand::Command(_) => None,
            })
            .collect();
        assert_eq!(
            titles,
            [
                ("Add import App.Utils", Some(false)),
                ("Add import Lib.Utils", Some(false)),
            ]
        );
        assert!(
            run(prose_only).is_empty(),
            "prose never drives an import fix"
        );
    }

    /// The candidates `data` decodes to.
    fn decoded(data: &serde_json::Value) -> Vec<String> {
        let mut diag = diag_at(5, "IPE-N0034");
        diag.data = Some(serde_json::json!({ "importCandidates": data }));
        crate::diagnostics::import_candidates(&diag)
    }

    /// The client echoes `data` back: an entry that is not a dotted module path
    /// (a newline smuggling a second line, a space, a lowercase segment, an
    /// empty segment, a bidi override, a Cyrillic homoglyph, a non-string)
    /// never becomes an inserted import — and it voids the whole list, so a
    /// valid sibling is never left standing as the sole, preferred fix.
    #[test]
    fn add_import_action_refuses_a_non_module_candidate() {
        for bad in [
            serde_json::json!("Lib.Utils\nmain = evil"),
            serde_json::json!("Lib Utils"),
            serde_json::json!("lib.Utils"),
            serde_json::json!("Lib..Utils"),
            serde_json::json!(""),
            serde_json::json!("Lib.\u{202e}Utils"),
            serde_json::json!("Lib.\u{0423}tils"),
            serde_json::json!(7),
        ] {
            assert_eq!(
                decoded(&serde_json::json!([bad.clone(), "Lib.Utils"])),
                Vec::<String>::new(),
                "{bad}"
            );
        }
        assert_eq!(
            decoded(&serde_json::json!(["App.Utils", "Lib.Utils"])),
            ["App.Utils".to_owned(), "Lib.Utils".to_owned()]
        );
    }

    /// A list out of the producer's strictly ascending order (reordered or
    /// duplicated) or over the cap is refused whole; the cap itself passes.
    #[test]
    fn add_import_candidates_are_all_or_none() {
        assert_eq!(
            decoded(&serde_json::json!(["Lib.Utils", "App.Utils"])),
            Vec::<String>::new()
        );
        assert_eq!(
            decoded(&serde_json::json!(["Lib.Utils", "Lib.Utils"])),
            Vec::<String>::new()
        );
        let names = |n: usize| -> Vec<String> { (0..n).map(|i| format!("M{i:03}")).collect() };
        let cap = crate::diagnostics::MAX_IMPORT_CANDIDATES;
        assert_eq!(decoded(&serde_json::json!(names(cap))), names(cap));
        assert_eq!(
            decoded(&serde_json::json!(names(cap + 1))),
            Vec::<String>::new()
        );
    }
}
