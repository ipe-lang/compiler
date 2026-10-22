//! Document formatting: `textDocument/formatting` and
//! `textDocument/rangeFormatting`.
//!
//! Both route through the shared `ipe_fmt` engine — the same
//! comment-preserving, semantics-guarded formatter `ipe fmt` runs — so there
//! is one printer and one set of output guards.
//!
//! `documentFormatting` returns a single whole-document `TextEdit` (nothing
//! when the source does not parse or the engine's guards refuse its output).
//!
//! `rangeFormatting` takes the engine's whole-module output with each
//! declaration's input and output bytes, and replaces in place only the
//! declarations the request range fully contains, leading comments included.
//! A declaration the range merely straddles gets no edit, so an edit never
//! truncates one. The spliced buffer then passes the engine's own guards
//! ([`ipe_fmt::verify_rewrite`]) or no edit is returned at all.
//!
//! An edit's range means what it says only where the server and the client
//! count the same lines. A client ends a line at `\n`, at `\r\n` and at a lone
//! `\r`; the position mapper counts all three, and the lexer refuses a lone
//! `\r`. A buffer holding one gets no edit here either, checked at this sink
//! independently of the lexer and the mapper.
//!
//! Whole-document formatting writes the canonical `\n` breaks `ipe fmt`
//! writes. A range edit lands among lines it does not touch, so in a buffer
//! whose every break is `\r\n` its text breaks with `\r\n` too, and the
//! buffer keeps one line ending; any other buffer gets `\n`. The rewritten
//! edits are what [`ipe_fmt::verify_rewrite`] proves.

use ipe_db::{IpeDatabase, SourceFile};
use lsp_types::{Range, TextEdit};

use crate::offset::{
    LineEnding, PositionEncoding, lines_agree, offset_to_position, position_to_offset,
};

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
    let formatted = engine_output(text)?.text;
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

/// Format the top-level declarations that `range` fully contains in `file`,
/// each in place. Returns `None` when the file does not parse or the engine
/// refuses its output.
///
/// **Fail closed.** Only a declaration the request range *fully contains*,
/// with its leading comments, is reformatted; one the range merely straddles
/// yields no edit. The whole buffer with every edit applied must pass
/// [`ipe_fmt::verify_rewrite`], or no edit is returned at all.
#[must_use]
pub fn format_range(
    db: &IpeDatabase,
    file: SourceFile,
    range: Range,
    encoding: PositionEncoding,
) -> Option<Vec<TextEdit>> {
    let text = file.text(db);
    let formatted = engine_output(text)?;
    let req_lo = position_to_offset(text, range.start, encoding);
    let req_hi = position_to_offset(text, range.end, encoding);
    range_edits(
        text,
        &formatted,
        req_lo.min(req_hi)..req_lo.max(req_hi),
        encoding,
    )
}

/// The engine's output for `text`, or `None` when the engine refuses it.
///
/// A parse failure, a round-trip guard tripping on a printer bug, or an
/// output past its cap all leave the buffer untouched.
fn engine_output(text: &str) -> Option<ipe_fmt::Formatted> {
    if !lines_agree(text) {
        return None;
    }
    accepted(ipe_fmt::format_with_segments(text))
}

/// The engine's verdict as an edit decision: every refusal is no edit.
fn accepted<T>(verdict: Result<T, ipe_fmt::FmtError>) -> Option<T> {
    verdict.ok()
}

/// The edits replacing each declaration of `formatted` whose input bytes lie
/// inside `request`, or `None` when the edited buffer fails
/// [`ipe_fmt::verify_rewrite`].
///
/// Each edit's text breaks lines in `text`'s [`LineEnding`].
fn range_edits(
    text: &str,
    formatted: &ipe_fmt::Formatted,
    request: std::ops::Range<usize>,
    encoding: PositionEncoding,
) -> Option<Vec<TextEdit>> {
    let ending = LineEnding::of(text);
    let mut edits: Vec<TextEdit> = Vec::new();
    let mut splices: Vec<(std::ops::Range<usize>, String)> = Vec::new();
    for segment in &formatted.decls {
        // Confinement: the range must cover the whole declaration. A partial
        // overlap (a straddled boundary) produces no edit for it.
        if !(request.start <= segment.input.start && segment.input.end <= request.end) {
            continue;
        }
        let old = text.get(segment.input.clone())?;
        let new = ending.apply(formatted.text.get(segment.output.clone())?);
        if old == new {
            continue; // already canonical — no edit for this declaration
        }
        edits.push(TextEdit {
            range: Range {
                start: offset_to_position(text, segment.input.start, encoding),
                end: offset_to_position(text, segment.input.end, encoding),
            },
            new_text: new.clone(),
        });
        splices.push((segment.input.clone(), new));
    }
    if edits.is_empty() {
        return Some(Vec::new());
    }

    // Splice into a scratch buffer, last offset first so earlier ones stay
    // valid; overlapping segments refuse every edit.
    splices.sort_by_key(|(input, _)| std::cmp::Reverse(input.start));
    let mut edited = text.to_owned();
    let mut floor = text.len();
    for (input, new) in &splices {
        if input.end > floor || edited.get(input.clone()).is_none() {
            return None;
        }
        edited.replace_range(input.clone(), new);
        floor = input.start;
    }
    accepted(ipe_fmt::verify_rewrite(text, &edited))?;
    Some(edits)
}

#[cfg(test)]
mod tests {
    use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile};

    use lsp_types::{Position, Range};

    use super::{LineEnding, format_document, format_range, lines_agree, range_edits};
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

    /// A declaration holding a `do` bind reformats as a `do` block: the engine
    /// re-sugars the bind, so the edit never spells it `Task.andThen` (which
    /// an import alias could retarget) and the edited buffer still binds
    /// through the `do` identity node.
    #[test]
    fn range_formatting_keeps_a_do_bind_a_do() {
        let db = IpeDatabase::new();
        let src = "module Main exposing (a)\n\nimport Ipe.Task as T\n\na t =\n      do\n            x <- t\n            t\n";
        let f = file(&db, &["Main"], src);
        let edits = format_range(&db, f, line_range(0, 9), PositionEncoding::Utf16)
            .expect("parseable source returns Some");
        assert!(!edits.is_empty(), "the over-indented decl reformats");
        let result = apply_edits(src, &edits);
        assert!(
            result.contains("do\n") && result.contains("x <- t"),
            "the bind stays a `do` statement, got:\n{result}"
        );
        assert!(!result.contains("andThen"), "{result}");
        let mut interner = ipe_intern::Interner::new();
        let module = ipe_parse::parse_module(&result, &mut interner).expect("edited buffer parses");
        let body = &module
            .values
            .first()
            .expect("the decl survives")
            .value
            .body
            .value;
        assert!(
            matches!(
                body,
                ipe_syntax::Expr_::Call(callee, _)
                    if matches!(callee.value, ipe_syntax::Expr_::TaskAndThen)
            ),
            "{body:?}"
        );
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

    /// A declaration whose source carries a comment is reformatted in range
    /// formatting, and its comment survives: the engine carries comments.
    #[test]
    fn range_formatting_keeps_a_commented_decls_comment() {
        let db = IpeDatabase::new();
        let src = "module Main exposing (a)\n\na : Int\na =\n      1 -- keep me\n";
        let f = file(&db, &["Main"], src);
        let edits = format_range(&db, f, line_range(0, 5), PositionEncoding::Utf16)
            .expect("parseable source returns Some");
        assert_eq!(
            apply_edits(src, &edits),
            "module Main exposing (a)\n\na : Int\na =\n    1 -- keep me\n"
        );
    }

    /// A negative literal argument keeps its parentheses: `f (-5)` printed as
    /// `f -5` would be a subtraction.
    #[test]
    fn range_format_keeps_negative_literal_argument() {
        let db = IpeDatabase::new();
        let src = "module Main exposing (a)\n\na =\n      f (-5)\n";
        let f = file(&db, &["Main"], src);
        let edits = format_range(&db, f, line_range(0, 4), PositionEncoding::Utf16)
            .expect("parseable source returns Some");
        let result = apply_edits(src, &edits);
        assert_eq!(result, "module Main exposing (a)\n\na =\n    f (-5)\n");
        assert!(
            ipe_fmt::verify_rewrite(src, &result).is_ok(),
            "the edit keeps the program"
        );
    }

    /// A declaration's leading comment belongs to it: a range that holds both
    /// reformats the declaration under its comment, and a range that leaves
    /// the comment out does not edit the declaration.
    #[test]
    fn range_format_moves_leading_comment_with_declaration() {
        let db = IpeDatabase::new();
        // Lines: 0 header · 1 blank · 2 `a =` · 3 `    1` · 4 blank ·
        // 5 `-- about b` · 6 `b =` · 7 `      2`.
        let src = "module Main exposing (a, b)\n\na =\n    1\n\n-- about b\nb =\n      2\n";
        let f = file(&db, &["Main"], src);
        let with_comment = format_range(&db, f, line_range(5, 8), PositionEncoding::Utf16)
            .expect("parseable source returns Some");
        assert_eq!(
            apply_edits(src, &with_comment),
            "module Main exposing (a, b)\n\na =\n    1\n\n-- about b\nb =\n    2\n"
        );
        let without_comment = format_range(&db, f, line_range(6, 8), PositionEncoding::Utf16)
            .expect("parseable source returns Some");
        assert!(
            without_comment.is_empty(),
            "a range leaving out the leading comment edits nothing: {without_comment:?}"
        );
    }

    /// `src` with `input` replaced by `new`.
    fn splice(src: &str, input: &std::ops::Range<usize>, new: &str) -> String {
        let before = src.get(..input.start).expect("segment start in source");
        let after = src.get(input.end..).expect("segment end in source");
        format!("{before}{new}{after}")
    }

    /// The engine's output for `src` with its one declaration's text replaced
    /// by `faulty`, as a printer bug would produce it.
    fn faulty_output(src: &str, faulty: &str) -> (ipe_fmt::Formatted, std::ops::Range<usize>) {
        let real = ipe_fmt::format_with_segments(src).expect("formats");
        let input = real
            .decls
            .first()
            .map(|segment| segment.input.clone())
            .expect("one declaration");
        let output = ipe_fmt::Formatted {
            text: faulty.to_owned(),
            decls: vec![ipe_fmt::DeclSegment {
                input: input.clone(),
                output: 0..faulty.len(),
            }],
        };
        (output, input)
    }

    /// A splice the engine's guards refuse yields no edit, even when the
    /// spliced buffer parses: here the faulty output drops a comment.
    #[test]
    fn range_format_refuses_when_verify_fails() {
        let src = "module Main exposing (a)\n\na =\n    -- note\n      1\n";
        let whole = 0..src.len();
        let real = ipe_fmt::format_with_segments(src).expect("formats");
        assert!(
            range_edits(src, &real, whole.clone(), PositionEncoding::Utf16)
                .is_some_and(|edits| !edits.is_empty()),
            "control: the engine's own output is an edit"
        );
        let (faulty, input) = faulty_output(src, "a =\n    1");
        let mut interner = ipe_intern::Interner::new();
        assert!(
            ipe_parse::parse_module(&splice(src, &input, "a =\n    1"), &mut interner).is_ok(),
            "precondition: the faulty splice parses"
        );
        assert_eq!(
            range_edits(src, &faulty, whole, PositionEncoding::Utf16),
            None,
            "a splice that drops a comment yields no edit"
        );
    }

    /// An operator printed as text no program spells (an unresolved symbol)
    /// is refused, never written into the buffer.
    #[test]
    fn range_format_refuses_an_unresolved_operator_print() {
        let src = "module Main exposing (a)\n\na =\n      1 + 2\n";
        let whole = 0..src.len();
        let real = ipe_fmt::format_with_segments(src).expect("formats");
        let edits = range_edits(src, &real, whole.clone(), PositionEncoding::Utf16)
            .expect("the engine's own output is accepted");
        assert_eq!(
            apply_edits(src, &edits),
            "module Main exposing (a)\n\na =\n    1 + 2\n"
        );
        let (faulty, _) = faulty_output(src, "a =\n    1 ? 2");
        assert_eq!(
            range_edits(src, &faulty, whole, PositionEncoding::Utf16),
            None,
            "a `?` operator yields no edit"
        );
    }

    /// Two segments whose input bytes overlap refuse every edit.
    #[test]
    fn range_format_refuses_overlapping_segments() {
        let src = "module Main exposing (a)\n\na =\n      1\n";
        let real = ipe_fmt::format_with_segments(src).expect("formats");
        let segment = real.decls.first().cloned().expect("one declaration");
        let overlapping = ipe_fmt::Formatted {
            text: real.text,
            decls: vec![segment.clone(), segment],
        };
        assert_eq!(
            range_edits(src, &overlapping, 0..src.len(), PositionEncoding::Utf16),
            None
        );
    }

    /// A request over one declaration edits exactly that declaration: the
    /// other keeps its bytes, its negative literal argument included.
    #[test]
    fn range_format_edits_only_the_requested_declaration() {
        let db = IpeDatabase::new();
        // Lines: 0 header · 1-2 blank · 3 `f =` · 4 `      h (-5)` · 5-6 blank ·
        // 7 `g = 1+2`.
        let src = "module Main exposing (f, g)\n\n\nf =\n      h (-5)\n\n\ng = 1+2\n";
        let f = file(&db, &["Main"], src);
        let edits = format_range(&db, f, line_range(7, 8), PositionEncoding::Utf16)
            .expect("parseable source returns Some");
        let [edit] = edits.as_slice() else {
            assert!(edits.len() == 1, "exactly one edit: {edits:?}");
            return;
        };
        assert_eq!(edit.new_text, "g =\n    1 + 2");
        assert_eq!(
            apply_edits(src, &edits),
            "module Main exposing (f, g)\n\n\nf =\n      h (-5)\n\n\ng =\n    1 + 2\n"
        );
    }

    /// A buffer holding a lone `\r` gets no edit from either request.
    ///
    /// The lexer refuses it, and the `lines_agree` sink refuses it on its own
    /// account. The same file with `\r\n` breaks still formats.
    #[test]
    fn lone_carriage_return_yields_no_edit() {
        let db = IpeDatabase::new();
        let lone = "module Main exposing (a, b)\n\n-- x\rzz\na =\n      1\n\nb =\n      2\n";
        assert!(
            ipe_fmt::format_source(lone).is_err(),
            "the engine refuses a lone `\\r` through the lexer"
        );
        assert!(!lines_agree(lone), "the sink refuses it on its own");
        assert!(lines_agree("a\r\nb\n"), "control: `\\r\\n` and `\\n` agree");
        let f = file(&db, &["Main"], lone);
        assert_eq!(format_document(&db, f, PositionEncoding::Utf16), None);
        assert_eq!(
            format_range(&db, f, line_range(0, 20), PositionEncoding::Utf16),
            None
        );
        let last = "module Main exposing (a)\n\na =\n      1\r";
        let f = file(&db, &["Main"], last);
        assert_eq!(format_document(&db, f, PositionEncoding::Utf16), None);
        let crlf = "module Main exposing (a, b)\r\n\r\na =\r\n      1\r\n\r\nb =\r\n      2\r\n";
        let f = file(&db, &["Main"], crlf);
        assert!(
            format_document(&db, f, PositionEncoding::Utf16).is_some_and(|e| !e.is_empty()),
            "control: CRLF breaks format"
        );
        assert!(
            format_range(&db, f, line_range(0, 20), PositionEncoding::Utf16)
                .is_some_and(|e| !e.is_empty()),
            "control: CRLF breaks range-format"
        );
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

    /// Whether every line break in `text` is `\r\n` (and there is at least one).
    fn uniform_crlf(text: &str) -> bool {
        text.contains('\n')
            && text.matches('\n').count() == text.matches("\r\n").count()
            && !text.contains("\r\r")
    }

    /// The ending of a buffer is `\r\n` only when every break is `\r\n`.
    #[test]
    fn line_ending_is_crlf_only_for_a_uniform_crlf_buffer() {
        assert_eq!(LineEnding::of("a\r\nb\r\n"), LineEnding::Crlf);
        assert_eq!(LineEnding::of("a\r\nb\n"), LineEnding::Lf);
        assert_eq!(LineEnding::of("\na\r\n"), LineEnding::Lf);
        assert_eq!(LineEnding::of("no break"), LineEnding::Lf);
        assert_eq!(LineEnding::of(""), LineEnding::Lf);
        assert_eq!(LineEnding::Crlf.apply("a\nb\r\nc\n"), "a\r\nb\r\nc\r\n");
        assert_eq!(LineEnding::Lf.apply("a\nb"), "a\nb");
    }

    /// In a uniform `\r\n` buffer a range edit breaks with `\r\n`.
    ///
    /// It never doubles a `\r\n` the engine carried verbatim (a block comment,
    /// a `"""` body), the buffer keeps one line ending, and a second request is
    /// a no-op.
    #[test]
    fn range_format_keeps_a_uniform_crlf_buffer_crlf() {
        let db = IpeDatabase::new();
        let src = "module Main exposing (a, b)\r\n\r\n{- one\r\n   two -}\r\na =\r\n      1\r\n\r\nb  :  String\r\nb =\r\n    \"\"\"\r\n    x\r\n    y\r\n    \"\"\"\r\n";
        let f = file(&db, &["Main"], src);
        let edits = format_range(&db, f, line_range(0, 20), PositionEncoding::Utf16)
            .expect("parseable source returns Some");
        assert!(!edits.is_empty(), "the over-indented decls reformat");
        for edit in &edits {
            assert!(edit.new_text.contains("\r\n"), "{:?}", edit.new_text);
            assert_eq!(
                edit.new_text.matches('\n').count(),
                edit.new_text.matches("\r\n").count(),
                "every break of an edit is `\\r\\n`: {:?}",
                edit.new_text
            );
            assert!(!edit.new_text.contains("\r\r"), "{:?}", edit.new_text);
        }
        let result = apply_edits(src, &edits);
        assert!(uniform_crlf(&result), "one line ending: {result:?}");
        assert!(result.contains("{- one\r\n   two -}"), "{result:?}");
        assert!(result.contains("b : String\r\n"), "{result:?}");
        assert!(result.contains("    x\r\n    y\r\n"), "{result:?}");
        let again = file(&db, &["Again"], &result);
        assert_eq!(
            format_range(&db, again, line_range(0, 20), PositionEncoding::Utf16),
            Some(Vec::new()),
            "a second range format is a no-op"
        );
    }

    /// A buffer whose breaks mix `\r\n` and `\n` gets edits in `\n` only.
    #[test]
    fn range_format_in_a_mixed_buffer_writes_lf() {
        let db = IpeDatabase::new();
        let src = "module Main exposing (a)\r\n\r\na =\n      1\n";
        let f = file(&db, &["Main"], src);
        let edits = format_range(&db, f, line_range(0, 20), PositionEncoding::Utf16)
            .expect("parseable source returns Some");
        assert!(!edits.is_empty(), "the over-indented decl reformats");
        assert!(
            edits.iter().all(|edit| !edit.new_text.contains('\r')),
            "{edits:?}"
        );
    }

    /// A rewrite that changes a `"""` value in a `\r\n` buffer yields no edit.
    ///
    /// The faulty print splits the body's one line in two; written in `\r\n`,
    /// the value gains a line the source never held, and the engine's guards
    /// refuse the spliced buffer.
    #[test]
    fn range_format_refuses_a_crlf_rewrite_that_changes_a_string() {
        let src = "module Main exposing (a)\r\n\r\na  :  String\r\na =\r\n    \"\"\"\r\n    xy\r\n    \"\"\"\r\n";
        let whole = 0..src.len();
        let real = ipe_fmt::format_with_segments(src).expect("formats");
        assert!(
            range_edits(src, &real, whole.clone(), PositionEncoding::Utf16)
                .is_some_and(|edits| !edits.is_empty()),
            "control: the engine's own output is an edit"
        );
        let (faulty, _) =
            faulty_output(src, "a : String\na =\n    \"\"\"\n    x\n    y\n    \"\"\"");
        assert_eq!(
            range_edits(src, &faulty, whole, PositionEncoding::Utf16),
            None,
            "a rewrite that changes the string value yields no edit"
        );
    }
}
