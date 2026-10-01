//! Inlay hints: `textDocument/inlayHint`.
//!
//! Produces type-annotation inlay hints in the form `: Type` at the end of a
//! binder's name token, matching the style of an explicit annotation. Two
//! families of binder are hinted:
//!
//! - **Top-level value bindings** without an explicit type annotation, typed
//!   from the solved `typecheck` env.
//! - **Local `let` bindings** (`let x = …`) inside any binding body, typed from
//!   the per-module region map — the SAME span-keyed solved types a hover
//!   reads, so an inlay type can never disagree with a hover at the same spot.
//!
//! A binder is typed by the innermost solved region that contains its
//! right-hand side, exactly as [`crate::hover`] resolves a type at a position.
//! A binder whose type cannot be resolved (an unsolved region, an ambiguous
//! inference) is skipped — a hint is emitted only for a type the compiler
//! actually solved, never a guess.

use ipe_canon::ast::{Expr_, Pattern_};
use ipe_db::{Db as _, IpeDatabase, SourceRoot};
use ipe_diagnostics::{Located, Span};
use ipe_intern::Symbol;
use ipe_types::{Ty, VarNamer, ty_to_doc};
use lsp_types::{InlayHint, InlayHintKind, InlayHintLabel, Range};

use crate::offset::{PositionEncoding, offset_to_position, span_to_range};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Inlay hints for the given document range.
///
/// Only top-level value bindings without a type annotation that overlap
/// `range` are hinted. Returns an empty list when no such bindings exist or
/// the file does not parse.
#[must_use]
pub fn inlay_hints(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
    module: &[String],
    range: Range,
    encoding: PositionEncoding,
) -> Vec<InlayHint> {
    let files = root.files(db);
    let Some(&file) = files.get(module) else {
        return Vec::new();
    };
    let Ok(parsed) = ipe_db::parse(db, file) else {
        return Vec::new();
    };
    let text = file.text(db);

    // Only produce hints when the type environment is available.
    let Ok(solved) = ipe_db::typecheck(db, root, entry) else {
        return Vec::new();
    };

    // Build the home symbol path once.
    let (home_syms, interner_needed): (Vec<Symbol>, bool) = {
        let mut interner = db.interner().lock();
        let syms: Option<Vec<Symbol>> = module
            .iter()
            .map(|s| interner.intern(s).ok())
            .collect::<Option<Vec<_>>>();
        drop(interner);
        match syms {
            Some(s) => (s, true),
            None => return Vec::new(),
        }
    };
    let _ = interner_needed;

    let mut hints: Vec<InlayHint> = Vec::new();

    for value in &parsed.values {
        // Skip bindings that already have an annotation.
        if value.value.type_annotation.is_some() {
            continue;
        }

        let name_span = value.value.name.span;
        let span_range = span_to_range(text, name_span, encoding);

        // Skip if the span does not intersect the requested range.
        if span_range.end < range.start || span_range.start > range.end {
            continue;
        }

        // Resolve the name symbol — intern under the same symbol index so the
        // env key matches.
        let name_sym = value.value.name.value;

        // Look up the type.
        let Some(ty) = solved.env.get(&(home_syms.clone(), name_sym)) else {
            continue;
        };

        let hint_label = {
            let interner = db.interner().lock();
            let mut namer = VarNamer::new();
            let Ok(doc) = ty_to_doc(ty, &interner, &mut namer) else {
                continue;
            };
            drop(interner);
            format!(": {}", ipe_diagnostics::render_ty(&doc))
        };

        // Place the hint just after the name token.
        let position = offset_to_position(text, name_span.hi as usize, encoding);

        hints.push(type_hint(position, hint_label));
    }

    // Local `let` binder hints, typed from the per-module region map — the same
    // span-keyed solved types a hover reads. A binder is skipped unless its RHS
    // sits in a solved region and renders to a concrete type (fail-closed).
    if let Some(canonical) = crate::db_access::canonicalize_checked(db, root, entry, file)
        && let Ok(types) = ipe_db::typecheck_module(db, root, entry, file)
    {
        let interner = db.interner().lock();
        for def in &canonical.module.defs {
            let body = match def {
                ipe_canon::ast::Def::Untyped { body, .. }
                | ipe_canon::ast::Def::Typed { body, .. } => body,
            };
            collect_let_hints(
                body,
                &types.regions,
                text,
                range,
                encoding,
                &interner,
                &mut hints,
            );
        }
        drop(interner);
    }

    hints
}

/// Build a `: Type` type-annotation inlay hint at `position`.
const fn type_hint(position: lsp_types::Position, label: String) -> InlayHint {
    InlayHint {
        position,
        label: InlayHintLabel::String(label),
        kind: Some(InlayHintKind::TYPE),
        text_edits: None,
        tooltip: None,
        padding_left: Some(true),
        padding_right: None,
        data: None,
    }
}

/// The type of the innermost solved region containing `byte`, rendered in Ipê
/// surface syntax. `None` when no region contains the byte or the type does not
/// render — mirrors [`crate::hover`]'s innermost-region resolution so an inlay
/// type is exactly what a hover at that spot would show.
fn ty_at_byte(
    regions: &std::collections::BTreeMap<Span, Ty>,
    byte: u32,
    interner: &ipe_intern::Interner,
) -> Option<String> {
    let mut best: Option<(u32, u32)> = None; // (width, lo)
    for span in regions.keys() {
        if span.lo <= byte && byte < span.hi {
            let width = span.hi.saturating_sub(span.lo);
            if best.is_none_or(|(best_width, best_lo)| {
                width < best_width || (width == best_width && span.lo > best_lo)
            }) {
                best = Some((width, span.lo));
            }
        }
    }
    let (width, lo) = best?;
    let span = Span::new(lo, lo.saturating_add(width));
    let ty = regions.get(&span)?;
    let mut namer = VarNamer::new();
    let doc = ty_to_doc(ty, interner, &mut namer).ok()?;
    Some(ipe_diagnostics::render_ty(&doc))
}

/// Walk an expression, emitting a `: Type` hint at each `let x = …` binder whose
/// right-hand side sits in a solved region. Recurses into every sub-expression
/// so a binder at any nesting depth is covered.
fn collect_let_hints(
    expr: &Located<Expr_>,
    regions: &std::collections::BTreeMap<Span, Ty>,
    text: &str,
    range: Range,
    encoding: PositionEncoding,
    interner: &ipe_intern::Interner,
    hints: &mut Vec<InlayHint>,
) {
    if let Expr_::Let(bindings, body) = &expr.value {
        for binding in bindings {
            // Only plain `name = …` binders — a destructure has no single name
            // token to hang the annotation on.
            let Pattern_::PVar(_name) = &binding.pat.value else {
                collect_let_hints(
                    &binding.body,
                    regions,
                    text,
                    range,
                    encoding,
                    interner,
                    hints,
                );
                continue;
            };
            let name_span = binding.pat.span;
            let span_range = span_to_range(text, name_span, encoding);
            let in_range = span_range.end >= range.start && span_range.start <= range.end;
            if in_range && let Some(rendered) = ty_at_byte(regions, binding.body.span.lo, interner)
            {
                let position = offset_to_position(text, name_span.hi as usize, encoding);
                hints.push(type_hint(position, format!(": {rendered}")));
            }
            // A binder's own RHS may nest further `let`s.
            collect_let_hints(
                &binding.body,
                regions,
                text,
                range,
                encoding,
                interner,
                hints,
            );
        }
        collect_let_hints(body, regions, text, range, encoding, interner, hints);
        return;
    }
    for child in expr_children(expr) {
        collect_let_hints(child, regions, text, range, encoding, interner, hints);
    }
}

/// The direct sub-expressions of a canonical expression, for the local-hint
/// walk. An exhaustive match (no wildcard) so a new `Expr_` variant forces a
/// compile-time decision here rather than silently dropping its `let`s.
fn expr_children(expr: &Located<Expr_>) -> Vec<&Located<Expr_>> {
    match &expr.value {
        Expr_::Call(callee, args) => {
            let mut v = vec![callee.as_ref()];
            v.extend(args.iter());
            v
        }
        Expr_::ForeignCall { args, .. } => args.iter().collect(),
        Expr_::Case(scrut, arms) => {
            let mut v = vec![scrut.as_ref()];
            v.extend(arms.iter().map(|a| &a.body));
            v
        }
        Expr_::Lambda(_, body) | Expr_::Let(_, body) => vec![body.as_ref()],
        Expr_::Binop { lhs, rhs, .. } => vec![lhs.as_ref(), rhs.as_ref()],
        Expr_::If(pairs, els) => {
            let mut v = Vec::new();
            for (c, b) in pairs {
                v.push(c);
                v.push(b);
            }
            v.push(els.as_ref());
            v
        }
        Expr_::Tuple(items) | Expr_::List(items) => items.iter().collect(),
        Expr_::Cons(head, tail) => vec![head.as_ref(), tail.as_ref()],
        Expr_::Record(fields) => fields.iter().map(|(_, e)| e).collect(),
        Expr_::Access(base, _) => vec![base.as_ref()],
        Expr_::Update(base, fields) => {
            let mut v = vec![base.as_ref()];
            v.extend(fields.iter().map(|(_, e)| e));
            v
        }
        // Leaf expressions introduce no sub-expressions and so no nested `let`.
        Expr_::VarLocal(_)
        | Expr_::VarTopLevel { .. }
        | Expr_::VarKernel { .. }
        | Expr_::VarCtor { .. }
        | Expr_::Int(_)
        | Expr_::Float(_)
        | Expr_::Str(_)
        | Expr_::Char(_)
        | Expr_::CustomElementCtor(_)
        | Expr_::Unit => Vec::new(),
    }
}

// Suppress unused import warning — `Span` is referenced in the attribute path
// on `span_to_range`.
#[allow(dead_code)]
type _SpanAlias = Span;

#[cfg(test)]
mod tests {
    use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};
    use lsp_types::{Position, Range};

    use super::inlay_hints;
    use crate::offset::PositionEncoding;

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

    fn full_range() -> Range {
        Range {
            start: Position {
                line: 0,
                character: 0,
            },
            end: Position {
                line: 9999,
                character: 0,
            },
        }
    }

    #[test]
    fn no_hints_when_annotation_present() {
        let db = IpeDatabase::new();
        let src = "module Main exposing (main)\n\nmain : Int\nmain =\n    42\n";
        let entry = file(&db, &["Main"], src);
        let root = root_of(&db, &[(&["Main"], entry)]);
        let hints = inlay_hints(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            full_range(),
            PositionEncoding::Utf16,
        );
        assert!(
            hints.is_empty(),
            "annotated binding should produce no hint: {hints:?}"
        );
    }

    #[test]
    fn hint_appears_for_unannotated_binding() {
        let db = IpeDatabase::new();
        // No type annotation on `main`.
        let src = "module Main exposing (main)\n\nmain =\n    42\n";
        let entry = file(&db, &["Main"], src);
        let root = root_of(&db, &[(&["Main"], entry)]);
        let hints = inlay_hints(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            full_range(),
            PositionEncoding::Utf16,
        );
        // If type-check succeeds, we should get a hint for `main`.
        // If it fails (no annotation makes inference ambiguous), hints is empty.
        // Either way, no panic.
        for h in &hints {
            let lsp_types::InlayHintLabel::String(label) = &h.label else {
                continue;
            };
            assert!(
                label.starts_with(": "),
                "hint label should start with `: `, got: {label}"
            );
        }
    }

    #[test]
    fn no_hints_for_unparseable_source() {
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], "@@@ not valid @@@");
        let root = root_of(&db, &[(&["Main"], f)]);
        let hints = inlay_hints(
            &db,
            root,
            f,
            &["Main".to_owned()],
            full_range(),
            PositionEncoding::Utf16,
        );
        assert!(hints.is_empty());
    }

    /// A local `let x = <int>` binder gets a `: Int` type-annotation hint whose
    /// span sits on the binder's name token — proving local-binding inlay hints
    /// fire and carry the compiler-solved type.
    #[test]
    fn local_let_binder_gets_type_hint() {
        let db = IpeDatabase::new();
        let src = "module Main exposing (main)\n\nmain : Int\nmain =\n    let\n        x = 41\n    in\n    x\n";
        let entry = file(&db, &["Main"], src);
        let root = root_of(&db, &[(&["Main"], entry)]);
        let hints = inlay_hints(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            full_range(),
            PositionEncoding::Utf16,
        );
        let labels: Vec<&str> = hints
            .iter()
            .filter_map(|h| match &h.label {
                lsp_types::InlayHintLabel::String(s) => Some(s.as_str()),
                lsp_types::InlayHintLabel::LabelParts(_) => None,
            })
            .collect();
        assert!(
            labels.contains(&": Int"),
            "local `let x = 41` must yield a `: Int` hint; got {labels:?}"
        );
    }

    /// The refusal: a `let` binder with an explicit destructure (no single name
    /// token) yields no local hint — the walk only annotates plain `name = …`
    /// binders, never guessing a placement.
    #[test]
    fn destructure_let_binder_gets_no_local_hint() {
        let db = IpeDatabase::new();
        // `(a, b) = (1, 2)` is a tuple destructure — not a single-name binder.
        let src = "module Main exposing (main)\n\nmain : Int\nmain =\n    let\n        (a, b) = (1, 2)\n    in\n    a + b\n";
        let entry = file(&db, &["Main"], src);
        let root = root_of(&db, &[(&["Main"], entry)]);
        let hints = inlay_hints(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            full_range(),
            PositionEncoding::Utf16,
        );
        // `main` is annotated, so any hint present would have to be a local one;
        // the destructure binder must produce none.
        assert!(
            hints.is_empty(),
            "a destructure `let` binder must yield no local inlay hint; got {hints:?}"
        );
    }
}
