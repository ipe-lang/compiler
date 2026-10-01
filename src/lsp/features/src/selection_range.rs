//! Selection ranges: expand-selection from a cursor position.
//!
//! For each requested cursor position, returns a chain of syntactic ranges
//! from innermost to outermost that cover the position. The chain starts at
//! the tightest span containing the byte offset and walks up to the whole
//! top-level declaration, then the entire module.

use ipe_db::{IpeDatabase, SourceFile};
use ipe_diagnostics::Span;
use ipe_syntax::{Expr_, Pattern_};
use lsp_types::{Position, Range, SelectionRange};

use crate::offset::{PositionEncoding, position_to_offset, span_to_range};

/// Returns one [`SelectionRange`] per requested position.
///
/// Each result is the innermost span enclosing the cursor, with `parent` chains
/// walking outward through the parse tree to the top-level declaration boundary.
///
/// An empty file, a parse failure, or a position outside every span returns a
/// single-node range equal to the cursor position (no expansion).
#[must_use]
pub fn selection_ranges(
    db: &IpeDatabase,
    file: SourceFile,
    positions: &[Position],
    encoding: PositionEncoding,
) -> Vec<SelectionRange> {
    let text = file.text(db);
    let Ok(module) = ipe_db::parse(db, file) else {
        return positions.iter().map(|&pos| point_range(pos)).collect();
    };

    positions
        .iter()
        .map(|&pos| {
            let byte = position_to_offset(text, pos, encoding);
            let byte = u32::try_from(byte).unwrap_or(u32::MAX);
            let spans = containing_spans(module, byte);
            build_chain(&spans, text, encoding, pos)
        })
        .collect()
}

/// Collect all spans in the parse tree that contain `byte`, from tightest to
/// widest. The result is never empty (the caller provides a point fallback).
fn containing_spans(module: &ipe_syntax::Module, byte: u32) -> Vec<Span> {
    let mut spans: Vec<Span> = Vec::new();

    // Walk top-level values.
    for val in &module.values {
        // A `Value`'s own span covers only its name token; the declaration runs
        // from the name through the body. Synthesize the full-declaration span
        // so a cursor anywhere in the body is claimed and expands out to it.
        let decl_span = Span {
            lo: val.value.name.span.lo,
            hi: val.value.body.span.hi,
        };
        if !contains(decl_span, byte) {
            continue;
        }
        // Sub-expression spans within the body.
        collect_expr_spans(&val.value.body, byte, &mut spans);
        // Patterns.
        for pat in &val.value.patterns {
            if contains(pat.span, byte) {
                push_if_new(pat.span, &mut spans);
            }
        }
        // Name token.
        if contains(val.value.name.span, byte) {
            push_if_new(val.value.name.span, &mut spans);
        }
        // Full declaration span (outermost for this binding).
        push_if_new(decl_span, &mut spans);
    }

    // Walk top-level union declarations.
    for union in &module.unions {
        if !contains(union.span, byte) {
            continue;
        }
        for ctor in &union.value.ctors {
            if contains(ctor.span, byte) {
                push_if_new(ctor.span, &mut spans);
            }
        }
        push_if_new(union.span, &mut spans);
    }

    // Walk type aliases.
    for alias in &module.aliases {
        if !contains(alias.span, byte) {
            continue;
        }
        push_if_new(alias.span, &mut spans);
    }

    // Sort innermost (smallest width) first.
    spans.sort_by_key(|s| s.hi - s.lo);
    spans
}

/// Recursively collect spans from an expression subtree that contain `byte`.
fn collect_expr_spans(expr: &ipe_syntax::Expr, byte: u32, out: &mut Vec<Span>) {
    if !contains(expr.span, byte) {
        return;
    }
    push_if_new(expr.span, out);

    match &expr.value {
        Expr_::Call(callee, args) => {
            collect_expr_spans(callee, byte, out);
            for arg in args {
                collect_expr_spans(arg, byte, out);
            }
        }
        Expr_::Case(scrutinee, arms) => {
            collect_expr_spans(scrutinee, byte, out);
            for (pat, body) in arms {
                if contains(pat.span, byte) {
                    collect_pat_spans(pat, byte, out);
                }
                collect_expr_spans(body, byte, out);
            }
        }
        Expr_::Lambda(pats, body) => {
            for pat in pats {
                if contains(pat.span, byte) {
                    collect_pat_spans(pat, byte, out);
                }
            }
            collect_expr_spans(body, byte, out);
        }
        Expr_::Binops(pairs, last) => {
            for (operand, _op) in pairs {
                collect_expr_spans(operand, byte, out);
            }
            collect_expr_spans(last, byte, out);
        }
        Expr_::Let(bindings, body) => {
            for binding in bindings {
                collect_pat_spans(&binding.pat, byte, out);
                collect_expr_spans(&binding.body, byte, out);
            }
            collect_expr_spans(body, byte, out);
        }
        Expr_::If(branches, else_body) => {
            for (cond, branch) in branches {
                collect_expr_spans(cond, byte, out);
                collect_expr_spans(branch, byte, out);
            }
            collect_expr_spans(else_body, byte, out);
        }
        Expr_::Tuple(elems) | Expr_::List(elems) => {
            for elem in elems {
                collect_expr_spans(elem, byte, out);
            }
        }
        Expr_::Record(fields) => {
            for (_name, val) in fields {
                collect_expr_spans(val, byte, out);
            }
        }
        Expr_::Update(_base, updates) => {
            for (_name, val) in updates {
                collect_expr_spans(val, byte, out);
            }
        }
        Expr_::Access(inner, _field) => {
            collect_expr_spans(inner, byte, out);
        }
        // Leaf expressions — span already pushed above.
        Expr_::VarLocal(_)
        | Expr_::VarQual(_, _)
        | Expr_::Int(_)
        | Expr_::Float(_)
        | Expr_::Str(_)
        | Expr_::MultilineStr { .. }
        | Expr_::Char(_)
        | Expr_::Unit => {}
    }
}

fn collect_pat_spans(pat: &ipe_syntax::Pattern, byte: u32, out: &mut Vec<Span>) {
    if !contains(pat.span, byte) {
        return;
    }
    push_if_new(pat.span, out);

    match &pat.value {
        Pattern_::PCtor(_name, _ty_args, sub_pats) => {
            for sub in sub_pats {
                collect_pat_spans(sub, byte, out);
            }
        }
        Pattern_::PTuple(elems) | Pattern_::PList(elems) | Pattern_::POr(elems) => {
            for elem in elems {
                collect_pat_spans(elem, byte, out);
            }
        }
        Pattern_::PCons(head, tail) => {
            collect_pat_spans(head, byte, out);
            collect_pat_spans(tail, byte, out);
        }
        Pattern_::PAlias(inner, _name) => {
            collect_pat_spans(inner, byte, out);
        }
        // `PRecord` carries field names only (no sub-patterns — pure field pun).
        Pattern_::PRecord(_fields) => {}
        // Leaves.
        Pattern_::PVar(_)
        | Pattern_::PAnything
        | Pattern_::PDebugAnything
        | Pattern_::PInt(_)
        | Pattern_::PBool(_)
        | Pattern_::PStr(_)
        | Pattern_::PChar(_)
        | Pattern_::PUnit => {}
    }
}

/// Build the `SelectionRange` chain from sorted spans (innermost first).
/// If `spans` is empty, returns a point range at `pos`.
fn build_chain(
    spans: &[Span],
    text: &str,
    encoding: PositionEncoding,
    pos: Position,
) -> SelectionRange {
    if spans.is_empty() {
        return point_range(pos);
    }
    // Build from outermost inward so we can wrap each inner node.
    let mut chain: Option<SelectionRange> = None;
    for &span in spans.iter().rev() {
        let range = span_to_range(text, span, encoding);
        chain = Some(SelectionRange {
            range,
            parent: chain.map(Box::new),
        });
    }
    // `chain` is Some because `spans` is non-empty.
    chain.unwrap_or_else(|| point_range(pos))
}

const fn contains(span: Span, byte: u32) -> bool {
    span.lo <= byte && byte < span.hi
}

fn push_if_new(span: Span, out: &mut Vec<Span>) {
    if !out.contains(&span) {
        out.push(span);
    }
}

const fn point_range(pos: Position) -> SelectionRange {
    SelectionRange {
        range: Range {
            start: pos,
            end: pos,
        },
        parent: None,
    }
}

#[cfg(test)]
mod tests {
    use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};
    use lsp_types::Position;

    use crate::offset::PositionEncoding;

    use super::selection_ranges;

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

    const MAIN: &str = "module Main exposing (main)\n\nmain : Int\nmain = 42\n";

    /// Cursor on the literal `42` → innermost range is the literal span,
    /// outer range is the full binding declaration.
    #[test]
    fn selection_range_expands_from_literal_to_declaration() {
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], MAIN);
        let _root = root_of(&db, &[(&["Main"], f)]);
        // `42` is at byte 38–40 in MAIN; line 3, col 7.
        let pos = Position {
            line: 3,
            character: 7,
        };
        let result = selection_ranges(&db, f, &[pos], PositionEncoding::Utf8);
        assert_eq!(result.len(), 1, "one result per position");
        let sr = result.first().expect("one selection range per position");
        // Innermost range must not be a zero-width point (real span returned).
        assert!(
            sr.range.start != sr.range.end || sr.parent.is_some(),
            "expected non-trivial selection range for literal position"
        );
        // Must have a parent (the enclosing declaration).
        assert!(
            sr.parent.is_some(),
            "literal inside binding should have a parent range"
        );
    }

    /// Cursor on whitespace outside every declaration → point range, no parent.
    #[test]
    fn selection_range_outside_any_span_returns_point() {
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], MAIN);
        let _root = root_of(&db, &[(&["Main"], f)]);
        // Blank line between module header and annotation: line 1, col 0.
        let pos = Position {
            line: 1,
            character: 0,
        };
        let result = selection_ranges(&db, f, &[pos], PositionEncoding::Utf8);
        assert_eq!(result.len(), 1);
        let sr = result.first().expect("one selection range per position");
        // Should be a point range or at least well-formed.
        assert_eq!(sr.range.start, sr.range.end, "whitespace pos → point range");
        assert!(sr.parent.is_none(), "point range has no parent");
    }
}
