//! Document formatting: `textDocument/formatting` and
//! `textDocument/rangeFormatting`.
//!
//! `documentFormatting` routes through the shared `ipe_fmt` engine — the same
//! comment-preserving, semantics-guarded formatter `ipe fmt` runs — so it
//! formats any parseable file, comments and doc-strings included, and returns a
//! single whole-document `TextEdit` (nothing when the source does not parse or
//! the engine's own re-parse / comment-count guard trips).
//!
//! `rangeFormatting` re-prints the parse AST directly, one declaration at a
//! time: it reformats only the top-level declarations the request range fully
//! contains, replacing each in place, and emits nothing for a declaration the
//! range merely straddles — a partial edit could truncate a declaration into
//! text that no longer parses. It fails closed twice over: a declaration whose
//! source carries comment or doc trivia is skipped (this AST path cannot
//! reproduce it), and the whole edited buffer must still parse or no edit is
//! returned at all.

use std::fmt::Write as _;

use ipe_db::{Db as _, IpeDatabase, SourceFile};
use lsp_types::{Range, TextEdit};

use crate::offset::{PositionEncoding, offset_to_position, position_to_offset};

/// Format the full text of `file`.
///
/// Returns `None` when the file does not parse, the engine's round-trip guard
/// trips, or the output would pass its cap; the client leaves the buffer
/// unchanged.
#[must_use]
pub fn format_document(
    db: &IpeDatabase,
    file: SourceFile,
    encoding: PositionEncoding,
) -> Option<Vec<TextEdit>> {
    let text = file.text(db);
    // The shared `ipe_fmt` engine preserves comments and doc-strings and guards
    // its own output with a re-parse + comment-count check, so a whole-document
    // format is comment-safe. A parse failure, the engine's round-trip guard
    // tripping on a printer bug, or an output past its cap yields no edit,
    // leaving the buffer untouched.
    let formatted = match ipe_fmt::format_source(text) {
        Ok(formatted) => formatted,
        Err(
            ipe_fmt::FmtError::Parse { .. }
            | ipe_fmt::FmtError::RoundTrip { .. }
            | ipe_fmt::FmtError::Limit(ipe_fmt::FmtLimit::OutputBytes { .. }),
        ) => return None,
    };
    if formatted == text.as_str() {
        return Some(Vec::new()); // already canonical — no edit
    }
    let start = offset_to_position(text, 0, encoding);
    let end = offset_to_position(text, text.len(), encoding);
    Some(vec![TextEdit {
        range: Range { start, end },
        new_text: formatted,
    }])
}

/// Whether `text` contains a line comment (`--`), a block comment (`{-`), or a
/// doc comment (`{-|`) outside a string, char, or multiline-string literal.
///
/// The printer cannot reproduce this trivia, so its presence forces a
/// fail-closed no-format. The scan tracks literal state so a `--` or `{-` inside
/// a string is not mistaken for a comment.
fn source_has_comment_or_doc(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes.get(i) {
            Some(b'"') => {
                // Multiline string `"""…"""` or ordinary `"…"`; skip to its end.
                if bytes.get(i + 1) == Some(&b'"') && bytes.get(i + 2) == Some(&b'"') {
                    i += 3;
                    while i < bytes.len()
                        && !(bytes.get(i) == Some(&b'"')
                            && bytes.get(i + 1) == Some(&b'"')
                            && bytes.get(i + 2) == Some(&b'"'))
                    {
                        i += 1;
                    }
                    i += 3;
                } else {
                    i += 1;
                    while i < bytes.len() && bytes.get(i) != Some(&b'"') {
                        // Skip an escaped character (e.g. `\"`) as one unit.
                        i += if bytes.get(i) == Some(&b'\\') { 2 } else { 1 };
                    }
                    i += 1;
                }
            }
            Some(b'\'') => {
                i += 1;
                while i < bytes.len() && bytes.get(i) != Some(&b'\'') {
                    i += if bytes.get(i) == Some(&b'\\') { 2 } else { 1 };
                }
                i += 1;
            }
            // `--` line comment, or `{-` block / `{-|` doc comment.
            Some(b'-' | b'{') if bytes.get(i + 1) == Some(&b'-') => return true,
            _ => i += 1,
        }
    }
    false
}

/// The full-line byte span of one top-level declaration, and the printer that
/// re-emits it in canonical form. `lo`/`hi` bound the declaration's own source
/// lines (from the start of its first line to just past its last newline) so a
/// replacement never disturbs a neighbour.
struct DeclBlock<'a> {
    lo: usize,
    hi: usize,
    kind: DeclKind<'a>,
}

enum DeclKind<'a> {
    Value(&'a ipe_syntax::Value),
    Union(&'a ipe_syntax::Union),
    Alias(&'a ipe_syntax::TypeAlias),
}

/// The byte offset of the start of the source line containing `pos`.
fn line_start(text: &str, pos: usize) -> usize {
    let pos = pos.min(text.len());
    text.get(..pos)
        .map_or(0, |p| p.rfind('\n').map_or(0, |i| i + 1))
}

/// The byte offset just past the newline ending the source line containing
/// `pos` (or `text.len()` when the last line has no trailing newline).
fn line_end_after(text: &str, pos: usize) -> usize {
    let pos = pos.min(text.len());
    text.get(pos..)
        .and_then(|rest| rest.find('\n'))
        .map_or(text.len(), |nl| pos + nl + 1)
}

/// Every top-level declaration of `module`, each widened to whole source lines.
/// A `Value`'s node span covers only its binding name, so its block start is
/// pulled back to any type annotation above it and its end pushed out to the
/// body — otherwise the annotation or trailing equation lines would be left
/// stranded by a replacement.
fn decl_blocks<'a>(module: &'a ipe_syntax::Module, text: &str) -> Vec<DeclBlock<'a>> {
    let mut blocks: Vec<DeclBlock<'a>> = Vec::new();
    for v in &module.values {
        let name_lo = v.value.name.span.lo as usize;
        let ann_lo = v
            .value
            .type_annotation
            .as_ref()
            .map_or(name_lo, |a| a.span.lo as usize);
        let lo = line_start(text, ann_lo.min(name_lo));
        let hi = line_end_after(text, v.value.body.span.hi as usize);
        blocks.push(DeclBlock {
            lo,
            hi,
            kind: DeclKind::Value(&v.value),
        });
    }
    for u in &module.unions {
        blocks.push(DeclBlock {
            lo: line_start(text, u.span.lo as usize),
            hi: line_end_after(text, u.span.hi as usize),
            kind: DeclKind::Union(&u.value),
        });
    }
    for a in &module.aliases {
        blocks.push(DeclBlock {
            lo: line_start(text, a.span.lo as usize),
            hi: line_end_after(text, a.span.hi as usize),
            kind: DeclKind::Alias(&a.value),
        });
    }
    blocks.sort_by_key(|b| b.lo);
    blocks
}

/// Canonical text of ONE declaration, with the single trailing newline every
/// full-line replacement needs. Reuses the same sub-printers the whole-document
/// path uses, so a declaration formats identically whichever entry point drives
/// it.
fn format_decl(kind: &DeclKind<'_>, interner: &ipe_intern::Interner, original: &str) -> String {
    let mut out = String::new();
    match kind {
        DeclKind::Value(v) => push_one_value(&mut out, v, interner, original),
        DeclKind::Union(u) => push_one_union(&mut out, u, interner),
        DeclKind::Alias(a) => push_one_alias(&mut out, a, interner),
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Format the top-level declarations that `range` fully contains in `file`,
/// each in place. Returns `None` when the file does not parse.
///
/// **Fail closed.** Only a declaration the request range *fully contains* is
/// reformatted; one the range merely straddles yields no edit, so an edit can
/// never truncate a declaration into unparseable text. A declaration whose
/// source carries comment or doc trivia the printer cannot reproduce is skipped
/// too. As a final guard the whole buffer with every candidate edit applied
/// must re-parse — otherwise no edit is returned at all.
#[must_use]
pub fn format_range(
    db: &IpeDatabase,
    file: SourceFile,
    range: Range,
    encoding: PositionEncoding,
) -> Option<Vec<TextEdit>> {
    let module = ipe_db::parse(db, file).clone().ok()?;
    let text = file.text(db);

    let req_lo = position_to_offset(text, range.start, encoding);
    let req_hi = position_to_offset(text, range.end, encoding);
    let (req_lo, req_hi) = (req_lo.min(req_hi), req_lo.max(req_hi));

    let interner = db.interner().lock();
    let blocks = decl_blocks(&module, text);

    let mut edits: Vec<TextEdit> = Vec::new();
    // Apply candidate edits to a scratch copy back-to-front so earlier byte
    // offsets stay valid; the whole result must re-parse before any edit ships.
    let mut edited = text.to_owned();
    let mut splices: Vec<(usize, usize, String)> = Vec::new();
    for block in &blocks {
        // Confinement: the range must cover the whole declaration. A partial
        // overlap (a straddled boundary) produces no edit for this block.
        if !(req_lo <= block.lo && block.hi <= req_hi) {
            continue;
        }
        let Some(slice) = text.get(block.lo..block.hi) else {
            continue;
        };
        // The printer drops comment/doc trivia; skip any block that carries it
        // rather than silently delete a comment.
        if source_has_comment_or_doc(slice) {
            continue;
        }
        let formatted = format_decl(&block.kind, &interner, text);
        if formatted == slice {
            continue; // already canonical — no edit for this declaration
        }
        let start = offset_to_position(text, block.lo, encoding);
        let end = offset_to_position(text, block.hi, encoding);
        edits.push(TextEdit {
            range: Range { start, end },
            new_text: formatted.clone(),
        });
        splices.push((block.lo, block.hi, formatted));
    }
    drop(interner);

    if edits.is_empty() {
        return Some(Vec::new());
    }

    // Final fail-closed gate: splice the edits into a scratch buffer (last
    // offset first, so earlier ones stay valid) and require the whole result to
    // re-parse. A single non-parsing outcome discards EVERY range edit.
    splices.sort_by_key(|s| std::cmp::Reverse(s.0));
    for (lo, hi, new_text) in &splices {
        match edited.get(*lo..*hi) {
            Some(_) => edited.replace_range(*lo..*hi, new_text),
            None => return None,
        }
    }
    let mut check_interner = ipe_intern::Interner::new();
    if ipe_parse::parse_module(&edited, &mut check_interner).is_err() {
        return None;
    }
    Some(edits)
}

// ---------------------------------------------------------------------------
// Literal reproduction
// ---------------------------------------------------------------------------

/// Push the exact source text of `span` from `original`, or the result of
/// `fallback` when the span is out of range. Literal spellings (string, char,
/// multiline-string literals) are reproduced verbatim so escapes survive a
/// reformat — the AST stores the already-unescaped value, which cannot be
/// re-quoted losslessly.
fn push_span_or(
    out: &mut String,
    span: ipe_diagnostics::Span,
    original: &str,
    fallback: impl FnOnce() -> String,
) {
    let lo = span.lo as usize;
    let hi = span.hi as usize;
    if let Some(slice) = original.get(lo..hi) {
        out.push_str(slice);
    } else {
        out.push_str(&fallback());
    }
}

/// Re-escape an unescaped string value into a quoted Ipê string literal. Used
/// only when a literal's original span is unavailable (a synthesized node), so
/// the emitted literal is still valid source rather than a raw-newline splat.
fn escaped_string_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ---------------------------------------------------------------------------
// Single-declaration printers (used by `format_range`)
// ---------------------------------------------------------------------------
//
// Each prints ONE declaration with no surrounding blank lines, reusing the
// same body sub-printers as the whole-document pass so a declaration formats
// identically whichever entry point drives it.

fn push_one_value(
    out: &mut String,
    value: &ipe_syntax::Value,
    interner: &ipe_intern::Interner,
    original: &str,
) {
    let resolve = |sym: ipe_intern::Symbol| interner.resolve(sym).unwrap_or("?");
    let name = resolve(value.name.value);
    if let Some(ann) = &value.type_annotation {
        out.push_str(name);
        out.push_str(" : ");
        push_type_annotation(out, &ann.value, interner);
        out.push('\n');
    }
    out.push_str(name);
    for pat in &value.patterns {
        out.push(' ');
        push_pattern(out, pat, interner, original);
    }
    out.push_str(" =\n    ");
    push_expr(out, &value.body, 1, interner, original);
    out.push('\n');
}

fn push_one_union(out: &mut String, union: &ipe_syntax::Union, interner: &ipe_intern::Interner) {
    let resolve = |sym: ipe_intern::Symbol| interner.resolve(sym).unwrap_or("?");
    let name = resolve(union.name.value);
    out.push_str("type ");
    out.push_str(name);
    for var in &union.vars {
        out.push(' ');
        out.push_str(resolve(var.value));
    }
    out.push('\n');
    for (i, ctor) in union.ctors.iter().enumerate() {
        if i == 0 {
            out.push_str("    = ");
        } else {
            out.push_str("    | ");
        }
        out.push_str(resolve(ctor.value.name));
        for arg in &ctor.value.args {
            out.push(' ');
            push_type_annotation(out, arg, interner);
        }
        out.push('\n');
    }
}

fn push_one_alias(
    out: &mut String,
    alias: &ipe_syntax::TypeAlias,
    interner: &ipe_intern::Interner,
) {
    let resolve = |sym: ipe_intern::Symbol| interner.resolve(sym).unwrap_or("?");
    let name = resolve(alias.name.value);
    out.push_str("type alias ");
    out.push_str(name);
    for var in &alias.vars {
        out.push(' ');
        out.push_str(resolve(var.value));
    }
    out.push_str(" =\n    ");
    push_type_annotation(out, &alias.body.value, interner);
    out.push('\n');
}

// ---------------------------------------------------------------------------
// Sub-printers
// ---------------------------------------------------------------------------

fn push_type_annotation(
    out: &mut String,
    ty: &ipe_syntax::TypeAnnotation,
    interner: &ipe_intern::Interner,
) {
    let resolve = |sym: ipe_intern::Symbol| interner.resolve(sym).unwrap_or("?");
    match ty {
        ipe_syntax::TypeAnnotation::TVar(sym) => out.push_str(resolve(*sym)),
        ipe_syntax::TypeAnnotation::TUnit => out.push_str("()"),
        ipe_syntax::TypeAnnotation::TType(qualifier, name_segs, args) => {
            let qualifier_str = resolve(*qualifier);
            if !qualifier_str.is_empty() {
                out.push_str(qualifier_str);
                out.push('.');
            }
            let name = name_segs
                .iter()
                .map(|&s| resolve(s))
                .collect::<Vec<_>>()
                .join(".");
            out.push_str(&name);
            for arg in args {
                out.push(' ');
                let needs_parens = matches!(
                    arg,
                    ipe_syntax::TypeAnnotation::TType(_, _, a) if !a.is_empty()
                ) || matches!(arg, ipe_syntax::TypeAnnotation::TLambda(..));
                if needs_parens {
                    out.push('(');
                    push_type_annotation(out, arg, interner);
                    out.push(')');
                } else {
                    push_type_annotation(out, arg, interner);
                }
            }
        }
        ipe_syntax::TypeAnnotation::TLambda(a, b) => {
            let needs_parens = matches!(a.as_ref(), ipe_syntax::TypeAnnotation::TLambda(..));
            if needs_parens {
                out.push('(');
                push_type_annotation(out, a, interner);
                out.push(')');
            } else {
                push_type_annotation(out, a, interner);
            }
            out.push_str(" -> ");
            push_type_annotation(out, b, interner);
        }
        ipe_syntax::TypeAnnotation::TTuple(elems) => {
            out.push('(');
            for (i, e) in elems.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                push_type_annotation(out, e, interner);
            }
            out.push(')');
        }
        ipe_syntax::TypeAnnotation::TRecord(fields) => {
            out.push_str("{ ");
            for (i, (name, ty)) in fields.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(resolve(name.value));
                out.push_str(" : ");
                push_type_annotation(out, ty, interner);
            }
            out.push_str(" }");
        }
        ipe_syntax::TypeAnnotation::TRecordOpen(row_var, fields) => {
            out.push_str("{ ");
            out.push_str(resolve(*row_var));
            out.push_str(" | ");
            for (i, (name, ty)) in fields.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(resolve(name.value));
                out.push_str(" : ");
                push_type_annotation(out, ty, interner);
            }
            out.push_str(" }");
        }
    }
}

/// Push `pat` in atom position (a constructor argument or the head of a `::`)
/// — wraps the pattern in parens when it would otherwise re-parse with a
/// different structure:
/// - a `PCtor` with arguments: `Just x` in atom position reads as two atoms
/// - `PCons`/`PAlias`/`POr`: all bind looser than constructor application, so
///   `a :: b` or `p as n` or `p1 | p2` as a single ctor arg would steal the
///   surrounding constructor's remaining arguments
fn push_pattern_atom(
    out: &mut String,
    pat: &ipe_syntax::Pattern,
    interner: &ipe_intern::Interner,
    original: &str,
) {
    let needs_parens = match &pat.value {
        ipe_syntax::Pattern_::PCtor(_, _, args) if !args.is_empty() => true,
        ipe_syntax::Pattern_::PCons(..)
        | ipe_syntax::Pattern_::PAlias(..)
        | ipe_syntax::Pattern_::POr(..) => true,
        _ => false,
    };
    if needs_parens {
        out.push('(');
        push_pattern(out, pat, interner, original);
        out.push(')');
    } else {
        push_pattern(out, pat, interner, original);
    }
}

fn push_pattern(
    out: &mut String,
    pat: &ipe_syntax::Pattern,
    interner: &ipe_intern::Interner,
    original: &str,
) {
    let resolve = |sym: ipe_intern::Symbol| interner.resolve(sym).unwrap_or("?");
    match &pat.value {
        ipe_syntax::Pattern_::PAnything => out.push('_'),
        ipe_syntax::Pattern_::PDebugAnything => out.push_str("Debug._"),
        ipe_syntax::Pattern_::PUnit => out.push_str("()"),
        ipe_syntax::Pattern_::PVar(sym) => out.push_str(resolve(*sym)),
        ipe_syntax::Pattern_::PCtor(name, module_segs, args) => {
            if !module_segs.is_empty() {
                for seg in module_segs {
                    out.push_str(resolve(*seg));
                    out.push('.');
                }
            }
            out.push_str(resolve(*name));
            for arg in args {
                out.push(' ');
                push_pattern_atom(out, arg, interner, original);
            }
        }
        ipe_syntax::Pattern_::PTuple(elems) => {
            out.push('(');
            for (i, e) in elems.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                push_pattern(out, e, interner, original);
            }
            out.push(')');
        }
        ipe_syntax::Pattern_::PRecord(fields) => {
            out.push_str("{ ");
            for (i, f) in fields.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(resolve(f.value));
            }
            out.push_str(" }");
        }
        ipe_syntax::Pattern_::PInt(n) => out.push_str(&n.to_string()),
        ipe_syntax::Pattern_::PBool(b) => {
            out.push_str(if *b { "True" } else { "False" });
        }
        ipe_syntax::Pattern_::PChar(c) => {
            // Reproduce the `'…'` literal verbatim so an escape is not unspooled.
            push_span_or(out, pat.span, original, || format!("'{c}'"));
        }
        ipe_syntax::Pattern_::PStr(s) => {
            // The stored value is unescaped; reproduce the literal from its span
            // so `\n` / `\"` survive, re-escaping only as a fallback.
            push_span_or(out, pat.span, original, || escaped_string_literal(s));
        }
        ipe_syntax::Pattern_::PAlias(inner, name) => {
            push_pattern(out, inner, interner, original);
            out.push_str(" as ");
            out.push_str(resolve(name.value));
        }
        ipe_syntax::Pattern_::PList(elems) => {
            out.push('[');
            for (i, e) in elems.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                push_pattern(out, e, interner, original);
            }
            out.push(']');
        }
        ipe_syntax::Pattern_::PCons(h, t) => {
            // The head is in atom position: `POr`/`PAlias`/`PCtor-with-args`
            // there would re-parse as stealing surrounding ctor args or wrapping
            // the tail in their grouping.  The tail is safe bare — `::` is
            // right-associative and `as` folds into the tail's own `parse_cons_as`.
            push_pattern_atom(out, h, interner, original);
            out.push_str(" :: ");
            push_pattern(out, t, interner, original);
        }
        ipe_syntax::Pattern_::POr(alts) => {
            for (i, alt) in alts.iter().enumerate() {
                if i > 0 {
                    out.push_str(" | ");
                }
                push_pattern(out, alt, interner, original);
            }
        }
    }
}

/// Print an expression at `indent` nesting levels (4 spaces each).
/// `original` is the module's source text, used to reproduce string/char
/// literals verbatim (avoids re-escaping).
fn push_expr(
    out: &mut String,
    expr: &ipe_syntax::Expr,
    indent: usize,
    interner: &ipe_intern::Interner,
    original: &str,
) {
    let resolve = |sym: ipe_intern::Symbol| interner.resolve(sym).unwrap_or("?");

    match &expr.value {
        ipe_syntax::Expr_::VarLocal(sym) => out.push_str(resolve(*sym)),
        ipe_syntax::Expr_::VarQual(qualifier, name) => {
            out.push_str(resolve(*qualifier));
            out.push('.');
            out.push_str(resolve(*name));
        }
        ipe_syntax::Expr_::Int(n) => out.push_str(&n.to_string()),
        ipe_syntax::Expr_::Float(f) => {
            // Reproduce the float from the original source when possible —
            // avoids precision drift from f64 Display.
            let lo = expr.span.lo as usize;
            let hi = expr.span.hi as usize;
            if let Some(slice) = original.get(lo..hi) {
                out.push_str(slice);
            } else {
                // Writing an f64 into a String is infallible.
                let _ = write!(out, "{f}");
            }
        }
        ipe_syntax::Expr_::Str(s) => {
            // The AST stores the UNESCAPED value; re-quoting it verbatim would
            // turn a `\n` or `\"` back into a raw newline/quote and corrupt the
            // source. Reproduce the literal from its original span, which carries
            // the exact escaped spelling; re-escape as a fallback.
            push_span_or(out, expr.span, original, || escaped_string_literal(s));
        }
        ipe_syntax::Expr_::MultilineStr { raw: s, .. } => {
            // Reproduce the whole `"""…"""` literal from its span so escapes and
            // interior quotes survive; fall back to the stored raw body.
            push_span_or(out, expr.span, original, || format!("\"\"\"{s}\"\"\""));
        }
        ipe_syntax::Expr_::Char(c) => {
            // Reproduce the `'…'` literal from its span to keep any escape;
            // fall back to the stored char text.
            push_span_or(out, expr.span, original, || format!("'{c}'"));
        }
        ipe_syntax::Expr_::Unit => out.push_str("()"),
        ipe_syntax::Expr_::Call(f, args) => {
            push_atom(out, f, indent, interner, original);
            for arg in args {
                out.push(' ');
                push_atom(out, arg, indent, interner, original);
            }
        }
        ipe_syntax::Expr_::Binops(pairs, last) => {
            // Re-print as `lhs op1 rhs1 op2 rhs2 … last`.
            for (lhs, op) in pairs {
                push_atom(out, lhs, indent, interner, original);
                out.push(' ');
                out.push_str(resolve(op.value));
                out.push(' ');
            }
            push_atom(out, last, indent, interner, original);
        }
        ipe_syntax::Expr_::Lambda(..)
        | ipe_syntax::Expr_::Let(..)
        | ipe_syntax::Expr_::If(..)
        | ipe_syntax::Expr_::Case(..) => {
            push_block_expr(out, expr, indent, interner, original);
        }
        ipe_syntax::Expr_::Tuple(..)
        | ipe_syntax::Expr_::List(..)
        | ipe_syntax::Expr_::Record(..)
        | ipe_syntax::Expr_::Access(..)
        | ipe_syntax::Expr_::Update(..) => {
            push_collection_expr(out, expr, indent, interner, original);
        }
    }
}

/// Print the delimited collection / record forms (tuples, lists, records,
/// field access, record update), factored out of `push_expr`.
fn push_collection_expr(
    out: &mut String,
    expr: &ipe_syntax::Expr,
    indent: usize,
    interner: &ipe_intern::Interner,
    original: &str,
) {
    let resolve = |sym: ipe_intern::Symbol| interner.resolve(sym).unwrap_or("?");
    match &expr.value {
        ipe_syntax::Expr_::Tuple(elems) => {
            out.push('(');
            for (i, e) in elems.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                push_expr(out, e, indent, interner, original);
            }
            out.push(')');
        }
        ipe_syntax::Expr_::List(elems) => {
            if elems.is_empty() {
                out.push_str("[]");
            } else {
                out.push_str("[ ");
                for (i, e) in elems.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    push_expr(out, e, indent, interner, original);
                }
                out.push_str(" ]");
            }
        }
        ipe_syntax::Expr_::Record(fields) => {
            if fields.is_empty() {
                out.push_str("{}");
            } else {
                out.push_str("{ ");
                for (i, (name, val)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(resolve(name.value));
                    out.push_str(" = ");
                    push_expr(out, val, indent, interner, original);
                }
                out.push_str(" }");
            }
        }
        ipe_syntax::Expr_::Access(rec, field) => {
            push_atom(out, rec, indent, interner, original);
            out.push('.');
            out.push_str(resolve(field.value));
        }
        ipe_syntax::Expr_::Update(base, fields) => {
            out.push_str("{ ");
            out.push_str(resolve(base.value));
            out.push_str(" | ");
            for (i, (name, val)) in fields.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(resolve(name.value));
                out.push_str(" = ");
                push_expr(out, val, indent, interner, original);
            }
            out.push_str(" }");
        }
        // `push_expr` only routes the five collection forms here.
        _ => push_expr(out, expr, indent, interner, original),
    }
}

/// Print the multi-line block expressions (`\… ->`, `let`, `if`, `case`),
/// factored out of `push_expr` so each printer stays focused.
fn push_block_expr(
    out: &mut String,
    expr: &ipe_syntax::Expr,
    indent: usize,
    interner: &ipe_intern::Interner,
    original: &str,
) {
    let pad = "    ".repeat(indent);
    let pad1 = "    ".repeat(indent + 1);
    match &expr.value {
        ipe_syntax::Expr_::Lambda(params, body) => {
            out.push('\\');
            for (i, p) in params.iter().enumerate() {
                if i > 0 {
                    out.push(' ');
                }
                push_pattern(out, p, interner, original);
            }
            out.push_str(" ->\n");
            out.push_str(&pad1);
            push_expr(out, body, indent + 1, interner, original);
        }
        ipe_syntax::Expr_::Let(bindings, body) => {
            out.push_str("let\n");
            for b in bindings {
                out.push_str(&pad1);
                push_pattern(out, &b.pat, interner, original);
                out.push_str(" =\n");
                out.push_str(&"    ".repeat(indent + 2));
                push_expr(out, &b.body, indent + 2, interner, original);
                out.push('\n');
            }
            out.push_str(&pad);
            out.push_str("in\n");
            out.push_str(&pad1);
            push_expr(out, body, indent + 1, interner, original);
        }
        ipe_syntax::Expr_::If(branches, else_expr) => {
            for (i, (cond, then_)) in branches.iter().enumerate() {
                if i == 0 {
                    out.push_str("if ");
                } else {
                    out.push_str(" else if ");
                }
                push_expr(out, cond, indent, interner, original);
                out.push_str(" then\n");
                out.push_str(&pad1);
                push_expr(out, then_, indent + 1, interner, original);
                out.push('\n');
                out.push_str(&pad);
            }
            out.push_str("else\n");
            out.push_str(&pad1);
            push_expr(out, else_expr, indent + 1, interner, original);
        }
        ipe_syntax::Expr_::Case(scrutinee, branches) => {
            out.push_str("case ");
            push_expr(out, scrutinee, indent, interner, original);
            out.push_str(" of\n");
            for (pat, body) in branches {
                out.push_str(&pad1);
                push_pattern(out, pat, interner, original);
                out.push_str(" ->\n");
                out.push_str(&"    ".repeat(indent + 2));
                push_expr(out, body, indent + 2, interner, original);
                out.push('\n');
                out.push('\n');
            }
            // Remove the final extra newline so callers get one clean end.
            if out.ends_with("\n\n") {
                out.pop();
            }
        }
        // `push_expr` only routes the four block forms here.
        _ => push_expr(out, expr, indent, interner, original),
    }
}

/// Print an expression, wrapping in parens when the top node is a compound
/// form that needs disambiguation in argument position.
fn push_atom(
    out: &mut String,
    expr: &ipe_syntax::Expr,
    indent: usize,
    interner: &ipe_intern::Interner,
    original: &str,
) {
    let needs_parens = matches!(
        &expr.value,
        ipe_syntax::Expr_::Call(_, _)
            | ipe_syntax::Expr_::Lambda(_, _)
            | ipe_syntax::Expr_::Let(_, _)
            | ipe_syntax::Expr_::If(_, _)
            | ipe_syntax::Expr_::Case(_, _)
            | ipe_syntax::Expr_::Binops(_, _)
    );
    if needs_parens {
        out.push('(');
        push_expr(out, expr, indent, interner, original);
        out.push(')');
    } else {
        push_expr(out, expr, indent, interner, original);
    }
}

#[cfg(test)]
mod tests {
    use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile};

    use lsp_types::{Position, Range};

    use super::{format_document, format_range, source_has_comment_or_doc};
    use crate::offset::{PositionEncoding, position_to_offset};

    fn file(db: &IpeDatabase, path: &[&str], text: &str) -> SourceFile {
        SourceFile::new(
            db,
            path.iter().map(|s| (*s).to_owned()).collect(),
            text.to_owned(),
            ModuleOrigin::User,
        )
    }

    const ALREADY_FORMATTED: &str = "module Main exposing (main)\n\nmain : Int\nmain =\n    42\n";

    #[test]
    fn already_formatted_produces_no_edit() {
        let db = IpeDatabase::new();
        // Canonical form is whatever the engine emits; formatting it again is a
        // no-op, so `format_document` returns an empty edit list.
        let canonical = ipe_fmt::format_source(ALREADY_FORMATTED).expect("formats");
        let f = file(&db, &["Main"], &canonical);
        let edits = format_document(&db, f, PositionEncoding::Utf16)
            .expect("parseable source returns Some");
        assert!(edits.is_empty(), "no edit when already canonical");
    }

    #[test]
    fn format_roundtrips_through_parse() {
        let db = IpeDatabase::new();
        let src = "module Main exposing (main)\n\nimport Helper exposing (three)\n\nmain : Int\nmain =\n    42\n";
        let f = file(&db, &["Main"], src);
        let edits = format_document(&db, f, PositionEncoding::Utf16)
            .expect("parseable source returns Some");
        // Apply the edit (if any) and re-parse — must still parse cleanly.
        let result = edits
            .first()
            .map_or_else(|| src.to_owned(), |e| e.new_text.clone());
        let f2 = file(&db, &["Main"], &result);
        let edits2 =
            format_document(&db, f2, PositionEncoding::Utf16).expect("formatted source parses");
        assert!(edits2.is_empty(), "idempotent after one pass");
    }

    #[test]
    fn unparseable_source_returns_none() {
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], "this is not valid ipe source @@@@");
        let result = format_document(&db, f, PositionEncoding::Utf16);
        assert!(result.is_none(), "no edit for unparseable source");
    }

    /// A list of `items` ones written on one line two lets deep; formatting
    /// puts every item on its own deeply indented line.
    fn nested_long_list(items: usize) -> String {
        let ones = vec!["1"; items].join(",");
        format!(
            "module Main exposing (x)\n\n\nx =\n    let\n        y =\n            let\n                z =\n                    [ {ones}\n                    ]\n            in\n            z\n    in\n    y\n"
        )
    }

    /// A document whose formatted output would pass the engine's cap gets no
    /// edit; the same shape small enough to fit is formatted.
    #[test]
    fn output_past_the_cap_returns_none() {
        let db = IpeDatabase::new();
        let small = file(&db, &["Main"], &nested_long_list(200));
        assert!(
            format_document(&db, small, PositionEncoding::Utf16).is_some_and(|e| !e.is_empty()),
            "control: the small list formats"
        );
        let src = nested_long_list(10_000);
        let engine = ipe_fmt::format_source(&src);
        assert!(
            matches!(engine, Err(ipe_fmt::FmtError::Limit(_))),
            "precondition: the engine refuses on its cap: {engine:?}"
        );
        let f = file(&db, &["Main"], &src);
        let result = format_document(&db, f, PositionEncoding::Utf16);
        assert!(result.is_none(), "no edit when the output passes its cap");
    }

    /// Helper: format `src` once and return the resulting text (or `src`
    /// unchanged when the formatter produced no edit).
    fn apply_format(db: &IpeDatabase, src: &str) -> String {
        let f = file(db, &["Main"], src);
        let edits = format_document(db, f, PositionEncoding::Utf16)
            .expect("source must parse for format_document to return Some");
        edits
            .into_iter()
            .next()
            .map_or_else(|| src.to_owned(), |e| e.new_text)
    }

    /// A `POr` pattern used as a constructor argument must be parenthesised in
    /// the formatted output; without parens `Wrap (A | B)` would reparse as two
    /// arms `Wrap A` and `B` in a surrounding `case`.
    ///
    /// Round-trip proof: format → re-parse → re-format must be idempotent and
    /// the re-parse must not fail (the second-parse gate in `format_document`
    /// already catches a non-parseable output, but idempotence proves the
    /// *meaning* is preserved too).
    #[test]
    fn por_as_ctor_arg_is_parenthesised() {
        let db = IpeDatabase::new();
        // `case x of\n    Wrap (A | B) -> 1` — the formatter must emit `(A | B)`
        // not `A | B` as the argument to `Wrap`.
        let src = concat!(
            "module Main exposing (main)\n\n",
            "main =\n",
            "    case x of\n",
            "        Wrap (A | B) -> 1\n",
            "        _ -> 0\n",
        );
        let pass1 = apply_format(&db, src);
        assert!(
            pass1.contains("(A | B)"),
            "POr ctor arg must be parenthesised, got:\n{pass1}"
        );
        // Idempotence: a second format must be a no-op.
        let pass2 = apply_format(&db, &pass1);
        assert_eq!(pass1, pass2, "formatter must be idempotent on POr ctor arg");
    }

    /// A `PCons` pattern used as a constructor argument must be parenthesised.
    /// `Wrap (x :: xs)` bare as `Wrap x :: xs` re-parses with `Wrap x` as the
    /// cons head and `xs` as the tail — a completely different structure.
    #[test]
    fn pcons_as_ctor_arg_is_parenthesised() {
        let db = IpeDatabase::new();
        let src = concat!(
            "module Main exposing (main)\n\n",
            "main =\n",
            "    case lst of\n",
            "        Wrap (x :: xs) -> 1\n",
            "        _ -> 0\n",
        );
        let pass1 = apply_format(&db, src);
        assert!(
            pass1.contains("(x :: xs)"),
            "PCons ctor arg must be parenthesised, got:\n{pass1}"
        );
        let pass2 = apply_format(&db, &pass1);
        assert_eq!(
            pass1, pass2,
            "formatter must be idempotent on PCons ctor arg"
        );
    }

    /// A `PAlias` pattern used as a constructor argument must be parenthesised.
    /// `Wrap (p as n)` bare as `Wrap p as n` re-parses as `(Wrap p) as n` — the
    /// alias wraps the entire constructor application, not just its argument.
    #[test]
    fn palias_as_ctor_arg_is_parenthesised() {
        let db = IpeDatabase::new();
        let src = concat!(
            "module Main exposing (main)\n\n",
            "main =\n",
            "    case x of\n",
            "        Wrap (p as n) -> 1\n",
            "        _ -> 0\n",
        );
        let pass1 = apply_format(&db, src);
        assert!(
            pass1.contains("(p as n)"),
            "PAlias ctor arg must be parenthesised, got:\n{pass1}"
        );
        let pass2 = apply_format(&db, &pass1);
        assert_eq!(
            pass1, pass2,
            "formatter must be idempotent on PAlias ctor arg"
        );
    }

    /// A `POr` pattern as the head of a `PCons` must be parenthesised.
    /// `(A | B) :: xs` bare as `A | B :: xs` re-parses as `POr(A, PCons(B, xs))`.
    #[test]
    fn por_as_pcons_head_is_parenthesised() {
        let db = IpeDatabase::new();
        let src = concat!(
            "module Main exposing (main)\n\n",
            "main =\n",
            "    case lst of\n",
            "        (A | B) :: xs -> 1\n",
            "        _ -> 0\n",
        );
        let pass1 = apply_format(&db, src);
        assert!(
            pass1.contains("(A | B) ::"),
            "POr cons head must be parenthesised, got:\n{pass1}"
        );
        let pass2 = apply_format(&db, &pass1);
        assert_eq!(
            pass1, pass2,
            "formatter must be idempotent on POr cons head"
        );
    }

    // -- rangeFormatting ----------------------------------------------------

    /// Apply LSP `TextEdit`s to `src` and return the result. Edits from
    /// `format_range` never overlap and cover whole lines, so applying them
    /// back-to-front (highest offset first) keeps every earlier offset valid.
    fn apply_edits(src: &str, edits: &[super::TextEdit]) -> String {
        let mut spans: Vec<(usize, usize, String)> = edits
            .iter()
            .map(|e| {
                let lo = position_to_offset(src, e.range.start, PositionEncoding::Utf16);
                let hi = position_to_offset(src, e.range.end, PositionEncoding::Utf16);
                (lo, hi, e.new_text.clone())
            })
            .collect();
        spans.sort_by_key(|s| std::cmp::Reverse(s.0));
        let mut out = src.to_owned();
        for (lo, hi, text) in spans {
            out.replace_range(lo..hi, &text);
        }
        out
    }

    /// A whole-line LSP range from the start of line `start_line` to the start
    /// of line `end_line` (0-based, exclusive end).
    fn line_range(start_line: u32, end_line: u32) -> Range {
        Range {
            start: Position {
                line: start_line,
                character: 0,
            },
            end: Position {
                line: end_line,
                character: 0,
            },
        }
    }

    /// Two over-indented declarations, no comments. Lines (0-based):
    /// 0 `module Main exposing (a, b)` · 1 blank · 2 `a : Int` · 3 `a =` ·
    /// 4 `      1` · 5 blank · 6 `b : Int` · 7 `b =` · 8 `      2`.
    const TWO_DECLS: &str =
        "module Main exposing (a, b)\n\na : Int\na =\n      1\n\nb : Int\nb =\n      2\n";

    /// A range that fully contains exactly one declaration reformats only that
    /// declaration; the untouched declaration keeps its original bytes.
    #[test]
    fn range_formatting_confines_to_whole_decl() {
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], TWO_DECLS);
        // Lines 6..9 cover the whole `b` declaration and nothing of `a`.
        let edits = format_range(&db, f, line_range(6, 9), PositionEncoding::Utf16)
            .expect("parseable source returns Some");
        let result = apply_edits(TWO_DECLS, &edits);
        // `b`'s body de-indents to 4 spaces; `a`'s over-indent is left as-is.
        assert!(
            result.contains("b =\n    2\n"),
            "the contained decl must reformat, got:\n{result}"
        );
        assert!(
            result.contains("a =\n      1\n"),
            "the untouched decl must keep its bytes, got:\n{result}"
        );
        // The whole edited buffer must still parse — the SEAL for a range edit.
        let f2 = file(&db, &["Main"], &result);
        assert!(
            ipe_db::parse(&db, f2).is_ok(),
            "edited buffer must re-parse"
        );
    }

    /// A range whose boundaries fall STRICTLY inside declarations (it straddles
    /// both `a` and `b`) must never emit a partial edit: it reformats neither,
    /// so no returned edit can truncate a declaration into unparseable text.
    #[test]
    fn range_formatting_straddle_yields_no_truncated_decl() {
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], TWO_DECLS);
        // Start on line 3 (`a =`, past `a`'s first line `a : Int`) and end on
        // line 7 (`b =`, before `b`'s last line) — both decls are straddled.
        let edits = format_range(&db, f, line_range(3, 8), PositionEncoding::Utf16)
            .expect("parseable source returns Some");
        assert!(
            edits.is_empty(),
            "a range that fully contains no decl yields no edit, got:\n{edits:?}"
        );
        // Applying the (empty) edit set leaves the source verbatim and parsing.
        let result = apply_edits(TWO_DECLS, &edits);
        assert_eq!(result, TWO_DECLS, "no edit ⇒ source is byte-identical");
    }

    /// Even a range that fully contains one decl and straddles another edits
    /// only the contained one, and the applied result always re-parses.
    #[test]
    fn range_formatting_partial_overlap_edits_only_contained_decl() {
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], TWO_DECLS);
        // Lines 2..8: fully contains `a` (lines 2,3,4) but ends inside `b`
        // (before its last line 8). Only `a` may be reformatted.
        let edits = format_range(&db, f, line_range(2, 8), PositionEncoding::Utf16)
            .expect("parseable source returns Some");
        let result = apply_edits(TWO_DECLS, &edits);
        assert!(
            result.contains("a =\n    1\n"),
            "the fully-contained decl reformats, got:\n{result}"
        );
        assert!(
            result.contains("b =\n      2\n"),
            "the straddled decl is left untouched, got:\n{result}"
        );
        let f2 = file(&db, &["Main"], &result);
        assert!(
            ipe_db::parse(&db, f2).is_ok(),
            "edited buffer must re-parse"
        );
    }

    /// A declaration whose source carries a comment is skipped by range
    /// formatting (the AST printer cannot reproduce it) — fail closed rather
    /// than delete the comment.
    #[test]
    fn range_formatting_skips_commented_decl() {
        let db = IpeDatabase::new();
        let src = "module Main exposing (a)\n\na : Int\na =\n      1 -- keep me\n";
        let f = file(&db, &["Main"], src);
        let edits = format_range(&db, f, line_range(0, 5), PositionEncoding::Utf16)
            .expect("parseable source returns Some");
        assert!(
            edits.is_empty(),
            "a commented decl must not be reformatted, got:\n{edits:?}"
        );
        assert!(source_has_comment_or_doc(src), "guard sees the comment");
    }

    /// `documentFormatting` formats a commented file and PRESERVES the comment:
    /// it routes through the shared `ipe_fmt` engine, which carries comment
    /// trivia, so the LSP no longer fails closed on a `--`.
    #[test]
    fn document_formatting_preserves_comments() {
        let db = IpeDatabase::new();
        // A leading comment, plus non-canonical spacing so a real edit is emitted.
        let src = "module Main exposing (a)\n\n-- keep\na =\n  1\n";
        let f = file(&db, &["Main"], src);
        let edits = format_document(&db, f, PositionEncoding::Utf16)
            .expect("commented file formats, not refused");
        let new_text = edits
            .first()
            .map_or_else(|| src.to_owned(), |e| e.new_text.clone());
        assert!(
            new_text.contains("-- keep"),
            "comment must survive formatting: {new_text}"
        );
    }
}
