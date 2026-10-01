//! `refactor.rewrite`: semantics-preserving-by-construction rewrites offered
//! at the cursor, independent of diagnostics.
//!
//! Every provider here proves its own precondition before returning an edit:
//! [`proven_action`] re-parses the spliced document with the compiler's own
//! [`ipe_parse::parse_module`] and returns `None` — no action — on any parse
//! failure. A provider has no other way to construct a [`CodeAction`], so
//! "no proof, no action" holds by construction, not by convention.
//!
//! [`REGISTRY`] is the one list of `(CodeActionKind, Provider)` pairs; both
//! [`refactor_actions`] (the dispatch loop) and [`advertised_kinds`] (the
//! server's capability advertisement) derive from it, so a provider wired
//! into one is always wired into the other.
//!
//! **Implemented** — both directions are provably semantics-preserving from
//! AST shape alone, by the language's own definitional equalities, with no
//! type inference needed:
//! - Named-function ⇄ lambda sugar at the top level (`f x = e` ⇄
//!   `f = \x -> e`): this is exactly the parameter sugar the parser itself
//!   desugars (see `parse_let_binding`'s function-parameter collection), so
//!   the two forms are the same program by construction.
//! - `case` on `Bool` ⇄ `if` (`case c of { True -> e1; False -> e2 }` ⇄
//!   `if c then e1 else e2`): an exhaustive two-arm `True`/`False` match is
//!   the same program as `if`/`then`/`else` under the language's evaluation
//!   rule. [`Pattern_::PBool`] is a dedicated pattern node the parser only
//!   ever produces for the bare `True`/`False` tokens in pattern position, so
//!   the match is unambiguous without a canon-resolution pass. A `case` with
//!   any other arm shape, or an `if` with an `else if` chain, offers nothing.
//!
//! **Not implemented** — each needs more than a reparse proof to be sound:
//! - `if c then True else False` → `c`: in EXPRESSION position, bare
//!   `True`/`False` parse as a generic unqualified [`Expr_::VarLocal`], not a
//!   dedicated literal node (unlike pattern position). Collapsing it would
//!   need a canon-resolution check that the name still denotes the builtin
//!   constructor and was not shadowed — a full resolve pass this crate does
//!   not run per keystroke.
//! - pipeline ⇄ nested application: reassociating `|>` needs operator
//!   precedence/associativity reconstruction, not a text splice.
//! - `refactor.extract` / `refactor.inline`: both need free-variable capture
//!   analysis with no compiler feedback loop available to verify against.

use ipe_db::{Db as _, IpeDatabase};
use ipe_diagnostics::Span;
use ipe_syntax::{Expr, Expr_, Pattern_};
use lsp_types::{CodeAction, CodeActionKind, CodeActionOrCommand, Range, TextEdit, Url};

use crate::code_actions::DbView;
use crate::offset::{PositionEncoding, position_to_offset, span_to_range};
use crate::workspace_edit::{Document, single_edit};

type Provider = fn(
    DbView<'_>,
    &[String],
    &Url,
    Range,
    &str,
    PositionEncoding,
    Option<i32>,
) -> Option<CodeAction>;

/// The one registry of `refactor.rewrite` providers.
///
/// Adding a provider here is the only step needed to both offer and
/// advertise it — see the module docs.
const REGISTRY: &[(CodeActionKind, Provider)] = &[
    (
        CodeActionKind::REFACTOR_REWRITE,
        function_lambda_rewrite_action,
    ),
    (
        CodeActionKind::REFACTOR_REWRITE,
        if_case_bool_rewrite_action,
    ),
];

/// The deduplicated `CodeActionKind`s this crate's refactor registry can
/// produce.
///
/// The server's capability advertisement derives its `code_action_kinds`
/// from this list rather than a hand-maintained copy.
#[must_use]
pub fn advertised_kinds() -> Vec<CodeActionKind> {
    let mut kinds: Vec<CodeActionKind> = Vec::new();
    for (kind, _) in REGISTRY {
        if !kinds.contains(kind) {
            kinds.push(kind.clone());
        }
    }
    kinds
}

/// Compute `refactor.*` code actions for the cursor.
///
/// Independent of diagnostics: every provider in [`REGISTRY`] runs against
/// `range.start` and contributes an action only when it can prove its
/// rewrite well-formed (see the module docs).
#[must_use]
pub fn refactor_actions(
    view: DbView<'_>,
    module: &[String],
    uri: &Url,
    range: Range,
    text: &str,
    encoding: PositionEncoding,
    version: Option<i32>,
) -> Vec<CodeActionOrCommand> {
    REGISTRY
        .iter()
        .filter_map(|(_, provider)| provider(view, module, uri, range, text, encoding, version))
        .map(CodeActionOrCommand::CodeAction)
        .collect()
}

// ---------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------

/// `f = \x y -> e` ⇄ `f x y = e` at the top level, whichever form encloses
/// the cursor.
fn function_lambda_rewrite_action(
    view: DbView<'_>,
    module: &[String],
    uri: &Url,
    range: Range,
    text: &str,
    encoding: PositionEncoding,
    version: Option<i32>,
) -> Option<CodeAction> {
    let DbView { db, root, .. } = view;
    let files = root.files(db);
    let &file = files.get(module)?;
    let parsed = ipe_db::parse(db, file).clone().ok()?;
    let byte = u32::try_from(position_to_offset(text, range.start, encoding)).ok()?;

    let value = parsed.values.iter().find_map(|located| {
        let v = &located.value;
        let decl_span = Span {
            lo: v.name.span.lo,
            hi: v.body.span.hi,
        };
        contains(decl_span, byte).then_some(v)
    })?;

    let name_text = text.get(value.name.span.lo as usize..value.name.span.hi as usize)?;
    let span = Span {
        lo: value.name.span.lo,
        hi: value.body.span.hi,
    };

    let (new_text, title) = if value.patterns.is_empty() {
        // No top-level params yet — only a rewrite when the body is a
        // lambda: pull its params up onto the declaration.
        let Expr_::Lambda(pats, inner) = &value.body.value else {
            return None;
        };
        if pats.is_empty() {
            return None;
        }
        let params_text = pats
            .iter()
            .map(|p| text.get(p.span.lo as usize..p.span.hi as usize))
            .collect::<Option<Vec<_>>>()?
            .join(" ");
        let inner_text = text.get(inner.span.lo as usize..inner.span.hi as usize)?;
        (
            format!("{name_text} {params_text} = {inner_text}"),
            format!("Convert `{name_text}` to a named function"),
        )
    } else {
        // Top-level params already present — fold them back into a lambda.
        let params_text = value
            .patterns
            .iter()
            .map(|p| text.get(p.span.lo as usize..p.span.hi as usize))
            .collect::<Option<Vec<_>>>()?
            .join(" ");
        let body_text = text.get(value.body.span.lo as usize..value.body.span.hi as usize)?;
        (
            format!("{name_text} = \\{params_text} -> {body_text}"),
            format!("Convert `{name_text}` to a lambda"),
        )
    };

    proven_action(
        db,
        Document { uri, text, version },
        span,
        &new_text,
        &title,
        encoding,
    )
}

/// `case c of { True -> e1; False -> e2 }` ⇄ `if c then e1 else e2`, for the
/// exhaustive two-arm boolean match only.
fn if_case_bool_rewrite_action(
    view: DbView<'_>,
    module: &[String],
    uri: &Url,
    range: Range,
    text: &str,
    encoding: PositionEncoding,
    version: Option<i32>,
) -> Option<CodeAction> {
    let DbView { db, root, .. } = view;
    let files = root.files(db);
    let &file = files.get(module)?;
    let parsed = ipe_db::parse(db, file).clone().ok()?;
    let byte = u32::try_from(position_to_offset(text, range.start, encoding)).ok()?;

    let value = parsed.values.iter().find_map(|located| {
        let v = &located.value;
        let decl_span = Span {
            lo: v.name.span.lo,
            hi: v.body.span.hi,
        };
        contains(decl_span, byte).then_some(v)
    })?;

    let target = find_case_or_if(&value.body, byte)?;

    match &target.value {
        Expr_::Case(scrutinee, arms) => {
            if arms.len() != 2 {
                return None;
            }
            let mut true_body: Option<&Expr> = None;
            let mut false_body: Option<&Expr> = None;
            for (pat, body) in arms {
                match &pat.value {
                    Pattern_::PBool(true) => true_body = Some(body),
                    Pattern_::PBool(false) => false_body = Some(body),
                    _ => return None,
                }
            }
            let (Some(true_body), Some(false_body)) = (true_body, false_body) else {
                return None;
            };
            let cond_text = text.get(scrutinee.span.lo as usize..scrutinee.span.hi as usize)?;
            let then_text = text.get(true_body.span.lo as usize..true_body.span.hi as usize)?;
            let else_text = text.get(false_body.span.lo as usize..false_body.span.hi as usize)?;
            let new_text = format!("if {cond_text} then {then_text} else {else_text}");
            proven_action(
                db,
                Document { uri, text, version },
                target.span,
                &new_text,
                "Convert `case` on `Bool` to `if`",
                encoding,
            )
        }
        Expr_::If(branches, else_body) => {
            let [(cond, branch)] = branches.as_slice() else {
                return None;
            };
            let cond_text = text.get(cond.span.lo as usize..cond.span.hi as usize)?;
            let then_text = text.get(branch.span.lo as usize..branch.span.hi as usize)?;
            let else_text = text.get(else_body.span.lo as usize..else_body.span.hi as usize)?;
            let indent = " ".repeat(byte_column(text, target.span.lo as usize) + 4);
            let new_text = format!(
                "case {cond_text} of\n{indent}True -> {then_text}\n{indent}False -> {else_text}"
            );
            proven_action(
                db,
                Document { uri, text, version },
                target.span,
                &new_text,
                "Convert `if` to `case`",
                encoding,
            )
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Shared proof + helpers
// ---------------------------------------------------------------------------

/// Splice `new_text` over `span`, re-parse the result, and build the
/// `refactor.rewrite` action only when it parses.
///
/// This is the one chokepoint every provider's edit passes through — a
/// provider has no path to a [`CodeAction`] that skips the reparse proof.
fn proven_action(
    db: &IpeDatabase,
    doc: Document<'_>,
    span: Span,
    new_text: &str,
    title: &str,
    encoding: PositionEncoding,
) -> Option<CodeAction> {
    let Document { uri, text, version } = doc;
    let lo = span.lo as usize;
    let hi = span.hi as usize;
    let mut spliced = String::with_capacity(text.len() + new_text.len());
    spliced.push_str(text.get(..lo)?);
    spliced.push_str(new_text);
    spliced.push_str(text.get(hi..)?);

    let mut interner = db.interner().lock();
    let reparses = ipe_parse::parse_module(&spliced, &mut interner).is_ok();
    drop(interner);
    if !reparses {
        return None;
    }

    let edit = TextEdit {
        range: span_to_range(text, span, encoding),
        new_text: new_text.to_owned(),
    };
    Some(CodeAction {
        title: title.to_owned(),
        kind: Some(CodeActionKind::REFACTOR_REWRITE),
        diagnostics: None,
        edit: Some(single_edit(uri, version, edit)),
        command: None,
        is_preferred: None,
        disabled: None,
        data: None,
    })
}

/// Innermost `case`/`if` expression containing `byte`, or `None` if neither
/// encloses it.
fn find_case_or_if(expr: &Expr, byte: u32) -> Option<&Expr> {
    if !contains(expr.span, byte) {
        return None;
    }
    let child = match &expr.value {
        Expr_::Call(callee, args) => find_case_or_if(callee, byte)
            .or_else(|| args.iter().find_map(|a| find_case_or_if(a, byte))),
        Expr_::Case(scrutinee, arms) => find_case_or_if(scrutinee, byte).or_else(|| {
            arms.iter()
                .find_map(|(_, body)| find_case_or_if(body, byte))
        }),
        Expr_::Lambda(_, body) => find_case_or_if(body, byte),
        Expr_::Binops(pairs, last) => pairs
            .iter()
            .find_map(|(operand, _)| find_case_or_if(operand, byte))
            .or_else(|| find_case_or_if(last, byte)),
        Expr_::Let(bindings, body) => bindings
            .iter()
            .find_map(|b| find_case_or_if(&b.body, byte))
            .or_else(|| find_case_or_if(body, byte)),
        Expr_::If(branches, else_body) => branches
            .iter()
            .find_map(|(cond, branch)| {
                find_case_or_if(cond, byte).or_else(|| find_case_or_if(branch, byte))
            })
            .or_else(|| find_case_or_if(else_body, byte)),
        Expr_::Tuple(elems) | Expr_::List(elems) => {
            elems.iter().find_map(|e| find_case_or_if(e, byte))
        }
        Expr_::Record(fields) => fields.iter().find_map(|(_, v)| find_case_or_if(v, byte)),
        Expr_::Update(_, updates) => updates.iter().find_map(|(_, v)| find_case_or_if(v, byte)),
        Expr_::Access(inner, _) => find_case_or_if(inner, byte),
        Expr_::VarLocal(_)
        | Expr_::VarQual(_, _)
        | Expr_::Int(_)
        | Expr_::Float(_)
        | Expr_::Str(_)
        | Expr_::MultilineStr { .. }
        | Expr_::Char(_)
        | Expr_::Unit => None,
    };
    if child.is_some() {
        return child;
    }
    matches!(expr.value, Expr_::Case(..) | Expr_::If(..)).then_some(expr)
}

const fn contains(span: Span, byte: u32) -> bool {
    span.lo <= byte && byte < span.hi
}

/// Byte-offset column of `byte` on its line.
///
/// Used only to size synthesized indentation: a multi-byte character earlier
/// on the line makes this an overestimate of the true (character) column,
/// but an overestimate still indents deeper than the true column, which the
/// off-side layout rule accepts.
fn byte_column(text: &str, byte: usize) -> usize {
    let line_start = text
        .get(..byte)
        .and_then(|s| s.rfind('\n'))
        .map_or(0, |i| i + 1);
    byte.saturating_sub(line_start)
}

#[cfg(test)]
mod tests {
    use ipe_db::{Db as _, IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};
    use lsp_types::{Position, Range};

    use crate::offset::{PositionEncoding, offset_to_position};

    use super::{DbView, function_lambda_rewrite_action, if_case_bool_rewrite_action};

    fn file(db: &IpeDatabase, path: &[&str], text: &str) -> SourceFile {
        let path: Vec<String> = path.iter().map(|s| (*s).to_owned()).collect();
        SourceFile::new(db, path, text.to_owned(), ModuleOrigin::User)
    }

    fn root_of(db: &IpeDatabase, files: &[(&[&str], SourceFile)]) -> SourceRoot {
        let map: std::collections::BTreeMap<Vec<String>, SourceFile> = files
            .iter()
            .map(|(p, f)| (p.iter().map(|s| (*s).to_owned()).collect(), *f))
            .collect();
        SourceRoot::new(db, map)
    }

    /// A zero-width `Range` at the byte offset of `needle`'s first
    /// occurrence in `text`.
    fn range_at(text: &str, needle: &str) -> Range {
        let byte = text.find(needle).expect("needle present in fixture");
        let pos: Position = offset_to_position(text, byte, PositionEncoding::Utf8);
        Range {
            start: pos,
            end: pos,
        }
    }

    fn apply(text: &str, action: &lsp_types::CodeAction, uri: &lsp_types::Url) -> String {
        let edits = action
            .edit
            .as_ref()
            .and_then(|e| e.changes.as_ref())
            .and_then(|c| c.get(uri))
            .expect("action carries a workspace edit for this uri");
        assert_eq!(edits.len(), 1, "each rewrite is a single-hunk edit");
        let edit = edits.first().expect("one edit");
        let start = super::position_to_offset(text, edit.range.start, PositionEncoding::Utf8);
        let end = super::position_to_offset(text, edit.range.end, PositionEncoding::Utf8);
        format!(
            "{}{}{}",
            text.get(..start).expect("start in range"),
            edit.new_text,
            text.get(end..).expect("end in range")
        )
    }

    const URI: &str = "file:///Main.ipe";

    #[test]
    fn lambda_to_named_function_rewrite_applies() {
        const SRC: &str = "module Main exposing (main)\n\nmain =\n    \\x -> x + 1\n";
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Main"], f)]);
        let view = DbView {
            db: &db,
            root,
            entry: f,
        };
        let uri = lsp_types::Url::parse(URI).expect("uri");
        let range = range_at(SRC, "\\x");
        let action = function_lambda_rewrite_action(
            view,
            &["Main".to_owned()],
            &uri,
            range,
            SRC,
            PositionEncoding::Utf8,
            None,
        )
        .expect("lambda body with no top-level params offers a rewrite");
        let result = apply(SRC, &action, &uri);
        assert_eq!(
            result, "module Main exposing (main)\n\nmain x = x + 1\n",
            "params pulled up onto the declaration"
        );
        let mut interner = db.interner().lock();
        assert!(
            ipe_parse::parse_module(&result, &mut interner).is_ok(),
            "rewritten source must re-parse"
        );
    }

    #[test]
    fn named_function_to_lambda_rewrite_applies() {
        const SRC: &str = "module Main exposing (main)\n\nmain x =\n    x + 1\n";
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Main"], f)]);
        let view = DbView {
            db: &db,
            root,
            entry: f,
        };
        let uri = lsp_types::Url::parse(URI).expect("uri");
        let range = range_at(SRC, "x + 1");
        let action = function_lambda_rewrite_action(
            view,
            &["Main".to_owned()],
            &uri,
            range,
            SRC,
            PositionEncoding::Utf8,
            None,
        )
        .expect("named top-level function offers a rewrite to lambda");
        let result = apply(SRC, &action, &uri);
        assert_eq!(
            result, "module Main exposing (main)\n\nmain = \\x -> x + 1\n",
            "params folded back into a lambda"
        );
        let mut interner = db.interner().lock();
        assert!(
            ipe_parse::parse_module(&result, &mut interner).is_ok(),
            "rewritten source must re-parse"
        );
    }

    #[test]
    fn case_bool_to_if_rewrite_applies() {
        const SRC: &str = "module Main exposing (main)\n\nmain b =\n    case b of\n        True -> 1\n        False -> 2\n";
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Main"], f)]);
        let view = DbView {
            db: &db,
            root,
            entry: f,
        };
        let uri = lsp_types::Url::parse(URI).expect("uri");
        let range = range_at(SRC, "case b");
        let action = if_case_bool_rewrite_action(
            view,
            &["Main".to_owned()],
            &uri,
            range,
            SRC,
            PositionEncoding::Utf8,
            None,
        )
        .expect("exhaustive True/False case offers a rewrite to if");
        let result = apply(SRC, &action, &uri);
        assert_eq!(
            result, "module Main exposing (main)\n\nmain b =\n    if b then 1 else 2\n",
            "case-on-Bool collapsed to if"
        );
        let mut interner = db.interner().lock();
        assert!(
            ipe_parse::parse_module(&result, &mut interner).is_ok(),
            "rewritten source must re-parse"
        );
    }

    #[test]
    fn if_to_case_bool_rewrite_applies() {
        const SRC: &str = "module Main exposing (main)\n\nmain b =\n    if b then 1 else 2\n";
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Main"], f)]);
        let view = DbView {
            db: &db,
            root,
            entry: f,
        };
        let uri = lsp_types::Url::parse(URI).expect("uri");
        let range = range_at(SRC, "if b");
        let action = if_case_bool_rewrite_action(
            view,
            &["Main".to_owned()],
            &uri,
            range,
            SRC,
            PositionEncoding::Utf8,
            None,
        )
        .expect("single-branch if offers a rewrite to case");
        let result = apply(SRC, &action, &uri);
        assert_eq!(
            result,
            "module Main exposing (main)\n\nmain b =\n    case b of\n        True -> 1\n        False -> 2\n",
            "if collapsed to an exhaustive case on Bool"
        );
        let mut interner = db.interner().lock();
        assert!(
            ipe_parse::parse_module(&result, &mut interner).is_ok(),
            "rewritten source must re-parse"
        );
    }

    #[test]
    fn case_with_wildcard_arm_offers_no_rewrite() {
        const SRC: &str = "module Main exposing (main)\n\nmain b =\n    case b of\n        True -> 1\n        _ -> 2\n";
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Main"], f)]);
        let view = DbView {
            db: &db,
            root,
            entry: f,
        };
        let uri = lsp_types::Url::parse(URI).expect("uri");
        let range = range_at(SRC, "case b");
        assert!(
            if_case_bool_rewrite_action(
                view,
                &["Main".to_owned()],
                &uri,
                range,
                SRC,
                PositionEncoding::Utf8,
                None,
            )
            .is_none(),
            "a non-exhaustive-Bool arm shape must offer no rewrite"
        );
    }

    #[test]
    fn elif_chain_offers_no_rewrite() {
        const SRC: &str =
            "module Main exposing (main)\n\nmain a b =\n    if a then 1 else if b then 2 else 3\n";
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Main"], f)]);
        let view = DbView {
            db: &db,
            root,
            entry: f,
        };
        let uri = lsp_types::Url::parse(URI).expect("uri");
        let range = range_at(SRC, "if a");
        assert!(
            if_case_bool_rewrite_action(
                view,
                &["Main".to_owned()],
                &uri,
                range,
                SRC,
                PositionEncoding::Utf8,
                None,
            )
            .is_none(),
            "an else-if chain is not this rewrite's shape"
        );
    }

    #[test]
    fn cursor_outside_any_declaration_offers_no_rewrite() {
        const SRC: &str = "module Main exposing (main)\n\nmain : Int\nmain = 42\n";
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Main"], f)]);
        let view = DbView {
            db: &db,
            root,
            entry: f,
        };
        let uri = lsp_types::Url::parse(URI).expect("uri");
        let range = Range {
            start: Position {
                line: 1,
                character: 0,
            },
            end: Position {
                line: 1,
                character: 0,
            },
        };
        assert!(
            function_lambda_rewrite_action(
                view,
                &["Main".to_owned()],
                &uri,
                range,
                SRC,
                PositionEncoding::Utf8,
                None,
            )
            .is_none(),
            "a cursor on blank space between declarations offers no rewrite"
        );
        assert!(
            if_case_bool_rewrite_action(
                view,
                &["Main".to_owned()],
                &uri,
                range,
                SRC,
                PositionEncoding::Utf8,
                None,
            )
            .is_none(),
            "a cursor on blank space between declarations offers no rewrite"
        );
    }

    #[test]
    fn refactor_actions_wires_both_providers() {
        const SRC: &str = "module Main exposing (main)\n\nmain =\n    \\x -> x + 1\n";
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Main"], f)]);
        let view = DbView {
            db: &db,
            root,
            entry: f,
        };
        let uri = lsp_types::Url::parse(URI).expect("uri");
        let range = range_at(SRC, "\\x");
        let actions = super::refactor_actions(
            view,
            &["Main".to_owned()],
            &uri,
            range,
            SRC,
            PositionEncoding::Utf8,
            None,
        );
        assert_eq!(
            actions.len(),
            1,
            "only the matching provider fires for this cursor: {actions:?}"
        );
    }

    #[test]
    fn a_known_version_yields_versioned_document_changes() {
        const SRC: &str = "module Main exposing (main)\n\nmain =\n    \\x -> x + 1\n";
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Main"], f)]);
        let view = DbView {
            db: &db,
            root,
            entry: f,
        };
        let uri = lsp_types::Url::parse(URI).expect("uri");
        let range = range_at(SRC, "\\x");
        let action = function_lambda_rewrite_action(
            view,
            &["Main".to_owned()],
            &uri,
            range,
            SRC,
            PositionEncoding::Utf8,
            Some(4),
        )
        .expect("lambda body with no top-level params offers a rewrite");
        let edit = action.edit.expect("action carries an edit");
        assert!(edit.changes.is_none(), "{edit:?}");
        assert!(
            matches!(&edit.document_changes, Some(lsp_types::DocumentChanges::Edits(edits))
                if matches!(edits.as_slice(), [e] if e.text_document.version == Some(4))),
            "{edit:?}"
        );
    }

    #[test]
    fn no_known_version_falls_back_to_unversioned_flat_changes() {
        const SRC: &str = "module Main exposing (main)\n\nmain =\n    \\x -> x + 1\n";
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Main"], f)]);
        let view = DbView {
            db: &db,
            root,
            entry: f,
        };
        let uri = lsp_types::Url::parse(URI).expect("uri");
        let range = range_at(SRC, "\\x");
        let action = function_lambda_rewrite_action(
            view,
            &["Main".to_owned()],
            &uri,
            range,
            SRC,
            PositionEncoding::Utf8,
            None,
        )
        .expect("lambda body with no top-level params offers a rewrite");
        let edit = action.edit.expect("action carries an edit");
        assert!(edit.document_changes.is_none(), "{edit:?}");
        assert!(
            matches!(&edit.changes, Some(m) if !m.is_empty()),
            "{edit:?}"
        );
    }
}
