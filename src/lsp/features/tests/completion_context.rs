#![forbid(unsafe_code)]
//! `ipe_parse::position_context` closes BUG-CLASSES 8ck for completion: the
//! cursor's lexical context (code, a comment, or a literal) comes from
//! `ipe_parse::lexical_regions`, which drives the lexer's own trivia step and
//! token dispatch, so completion never fires inside a comment or a literal.

use std::collections::BTreeSet;
use std::num::NonZeroU32;
use std::ops::Range;
use std::path::{Path, PathBuf};

use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};
use ipe_diagnostics::{Span, TokenKind};
use ipe_lsp_features::PositionEncoding;
use ipe_lsp_features::completion::{completions, qualified_completions};
use ipe_parse::{PositionContext, TokenClass};

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

const FONT_MODULE: &str = "module Font exposing (bold, italic, size)\n\n\
    bold : Int\nbold = 1\n\nitalic : Int\nitalic = 2\n\nsize : Int\nsize = 3\n";

// ---------------------------------------------------------------------------
// Refusal tests: no completion inside a comment or a string.
// ---------------------------------------------------------------------------

/// The original #3951 shape: completion after `-- Font.`, a qualifier inside
/// a line comment. Red on origin/main (`scan_qualifier_prefix` is a raw byte
/// scanner with no comment awareness, so it fires anyway and offers `Font`'s
/// members); green once `qualified_completions` and `completions` both gate
/// on `position_context` before considering any trigger.
#[test]
fn qualified_completion_never_fires_inside_a_line_comment() {
    const SRC: &str = "module Main exposing (main)\n\nimport Font\n\n-- Font.\nmain = 1\n";
    let db = IpeDatabase::new();
    let font = file(&db, &["Font"], FONT_MODULE);
    let entry = file(&db, &["Main"], SRC);
    let root = root_of(&db, &[(&["Font"], font), (&["Main"], entry)]);

    let byte = u32::try_from(SRC.find("-- Font.").expect("has comment") + "-- Font.".len())
        .expect("offset fits u32");
    assert_eq!(
        ipe_parse::position_context(SRC, byte),
        PositionContext::LineComment
    );
    assert_eq!(
        qualified_completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        ),
        None,
        "a line comment must never trigger qualified completion"
    );
    assert!(
        completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        )
        .is_empty(),
        "a line comment must never offer plain completion either"
    );
}

#[test]
fn qualified_completion_never_fires_inside_a_block_comment() {
    const SRC: &str = "module Main exposing (main)\n\nimport Font\n\n{- Font. -}\nmain = 1\n";
    let db = IpeDatabase::new();
    let font = file(&db, &["Font"], FONT_MODULE);
    let entry = file(&db, &["Main"], SRC);
    let root = root_of(&db, &[(&["Font"], font), (&["Main"], entry)]);

    let byte = u32::try_from(SRC.find("Font.").expect("has trigger") + "Font.".len())
        .expect("offset fits u32");
    assert_eq!(
        ipe_parse::position_context(SRC, byte),
        PositionContext::BlockComment
    );
    assert_eq!(
        qualified_completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        ),
        None,
        "a block comment must never trigger qualified completion"
    );
}

/// Nesting must not matter: a trigger inside the INNER `{- -}` of a nested
/// block comment is still a comment, never code.
#[test]
fn qualified_completion_never_fires_inside_a_nested_block_comment() {
    const SRC: &str = "module Main exposing (main)\n\nimport Font\n\n{- outer {- Font. -} still outer -}\nmain = 1\n";
    let db = IpeDatabase::new();
    let font = file(&db, &["Font"], FONT_MODULE);
    let entry = file(&db, &["Main"], SRC);
    let root = root_of(&db, &[(&["Font"], font), (&["Main"], entry)]);

    let byte = u32::try_from(SRC.find("Font.").expect("has trigger") + "Font.".len())
        .expect("offset fits u32");
    assert_eq!(
        ipe_parse::position_context(SRC, byte),
        PositionContext::BlockComment
    );
    assert_eq!(
        qualified_completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        ),
        None,
    );
}

#[test]
fn completion_never_fires_inside_a_doc_comment() {
    const SRC: &str =
        "module Main exposing (main)\n\nimport Font\n\n{-| Font. -}\nmain : Int\nmain = 1\n";
    let db = IpeDatabase::new();
    let font = file(&db, &["Font"], FONT_MODULE);
    let entry = file(&db, &["Main"], SRC);
    let root = root_of(&db, &[(&["Font"], font), (&["Main"], entry)]);

    let byte = u32::try_from(SRC.find("Font.").expect("has trigger") + "Font.".len())
        .expect("offset fits u32");
    assert_eq!(
        ipe_parse::position_context(SRC, byte),
        PositionContext::DocComment
    );
    assert_eq!(
        qualified_completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        ),
        None,
    );
}

#[test]
fn completion_never_fires_inside_a_string_literal() {
    const SRC: &str = "module Main exposing (main)\n\nimport Font\n\nmain = \"Font.\"\n";
    let db = IpeDatabase::new();
    let font = file(&db, &["Font"], FONT_MODULE);
    let entry = file(&db, &["Main"], SRC);
    let root = root_of(&db, &[(&["Font"], font), (&["Main"], entry)]);

    let byte = u32::try_from(SRC.find("Font.").expect("has trigger") + "Font.".len())
        .expect("offset fits u32");
    assert_eq!(
        ipe_parse::position_context(SRC, byte),
        PositionContext::String
    );
    assert_eq!(
        qualified_completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        ),
        None,
    );
}

/// A multiline triple string must gate the same as a single-line one — the
/// comment/string distinction is about the lexical kind, not line count.
#[test]
fn completion_never_fires_inside_a_multiline_triple_string() {
    const SRC: &str = "module Main exposing (main)\n\nimport Font\n\nmain =\n    \"\"\"\n    Font.\n    more text\n    \"\"\"\n";
    let db = IpeDatabase::new();
    let font = file(&db, &["Font"], FONT_MODULE);
    let entry = file(&db, &["Main"], SRC);
    let root = root_of(&db, &[(&["Font"], font), (&["Main"], entry)]);

    let byte = u32::try_from(SRC.find("Font.").expect("has trigger") + "Font.".len())
        .expect("offset fits u32");
    assert_eq!(
        ipe_parse::position_context(SRC, byte),
        PositionContext::String
    );
    assert_eq!(
        qualified_completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        ),
        None,
    );
}

#[test]
fn completion_never_fires_inside_a_char_literal() {
    const SRC: &str = "module Main exposing (main)\n\nmain = 'a'\n";
    let db = IpeDatabase::new();
    let entry = file(&db, &["Main"], SRC);
    let root = root_of(&db, &[(&["Main"], entry)]);

    let byte =
        u32::try_from(SRC.find("'a'").expect("has char literal") + 2).expect("offset fits u32");
    assert_eq!(
        ipe_parse::position_context(SRC, byte),
        PositionContext::Char
    );
    assert!(
        completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        )
        .is_empty()
    );
}

/// `position_context` is error-tolerant: a string left open all the way to
/// end of file (never lexable as a whole) still classifies as `String`,
/// because completion must answer sensibly over a buffer mid-edit.
#[test]
fn unterminated_string_at_eof_classifies_as_string() {
    const SRC: &str = "module Main exposing (main)\n\nmain = \"Font.";
    let byte = u32::try_from(SRC.len()).expect("fits u32");
    assert_eq!(
        ipe_parse::position_context(SRC, byte),
        PositionContext::String
    );
    assert!(
        ipe_parse::try_source_tokens(SRC).is_none(),
        "fixture must actually be unlexable"
    );
}

/// The gate does not over-refuse: real code — including code right after a
/// closed comment — still completes normally.
#[test]
fn qualified_completion_still_fires_in_code_after_a_comment() {
    const SRC: &str =
        "module Main exposing (main)\n\nimport Font\n\n-- not a trigger\nmain = Font.\n";
    let db = IpeDatabase::new();
    let font = file(&db, &["Font"], FONT_MODULE);
    let entry = file(&db, &["Main"], SRC);
    let root = root_of(&db, &[(&["Font"], font), (&["Main"], entry)]);

    let byte = u32::try_from(SRC.rfind("Font.").expect("has trigger") + "Font.".len())
        .expect("offset fits u32");
    assert_eq!(
        ipe_parse::position_context(SRC, byte),
        PositionContext::Code
    );
    let items = qualified_completions(
        &db,
        root,
        entry,
        &["Main".to_owned()],
        byte,
        PositionEncoding::Utf16,
        None,
    )
    .expect("code position must still trigger qualified completion");
    let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
    assert!(labels.contains(&"bold"), "bold missing: {labels:?}");
}

// ---------------------------------------------------------------------------
// Edge refusals: shapes a scanner beside the lexer reads differently.
// ---------------------------------------------------------------------------

#[allow(clippy::expect_used)] // test helper: a fixture missing its needle is the failure
fn context_after(src: &str, needle: &str) -> PositionContext {
    let at = src.rfind(needle).expect("fixture holds the needle") + needle.len();
    ipe_parse::position_context(src, u32::try_from(at).expect("offset fits u32"))
}

/// `<--x` is the token `<-` then `-`: the lexer never opens a comment there,
/// so a classifier that steps code one character at a time (and so reads the
/// second and third characters as `--`) refuses completion in real code.
#[test]
fn a_left_arrow_before_a_minus_is_code_not_a_line_comment() {
    const SRC: &str = "main =\n    do\n        p <--Font.\n";
    assert!(
        ipe_parse::lexical_regions(SRC).all(|r| r.context == PositionContext::Code),
        "the lexer reads no comment in `<--`"
    );
    assert_eq!(context_after(SRC, "Font."), PositionContext::Code);
}

/// A malformed char literal mid-edit holds the rest of its line, so a
/// qualifier typed after the quote is never offered members.
#[test]
fn an_unclosed_char_literal_holds_the_rest_of_its_line() {
    const SRC: &str = "main = 'Font.\nnext = Font.";
    assert_eq!(context_after(SRC, "'Font."), PositionContext::Char);
    assert_eq!(context_after(SRC, "next = Font."), PositionContext::Code);
}

/// A `{{expr}}` body inside `"""` is code the lexer reads, so completion
/// answers there; the text around it and its markers read as string.
#[test]
fn a_triple_string_interpolation_body_reads_as_code() {
    const SRC: &str = "main = \"\"\"a {{ Font. }} b\"\"\"\n";
    assert_eq!(context_after(SRC, "Font."), PositionContext::Code);
    assert_eq!(context_after(SRC, "\"\"\"a"), PositionContext::String);
    assert_eq!(context_after(SRC, "}} b"), PositionContext::String);
}

/// The cursor between the two characters of a closer is still inside the
/// comment; right after the closer it is code.
#[test]
fn a_cursor_inside_a_closer_is_inside_its_comment() {
    const SRC: &str = "{- Font. -}x";
    let closer = u32::try_from(SRC.find("-}").expect("closer")).expect("fits");
    assert_eq!(
        ipe_parse::position_context(SRC, closer + 1),
        PositionContext::BlockComment
    );
    assert_eq!(
        ipe_parse::position_context(SRC, closer + 2),
        PositionContext::Code
    );
}

/// A `\r\n` ends a line comment at the `\n`; the next line is code.
#[test]
fn a_crlf_line_comment_ends_at_its_line_feed() {
    const SRC: &str = "-- Font.\r\nmain = Font.";
    assert_eq!(context_after(SRC, "-- Font."), PositionContext::LineComment);
    assert_eq!(
        context_after(SRC, "-- Font.\r"),
        PositionContext::LineComment
    );
    assert_eq!(context_after(SRC, "main = Font."), PositionContext::Code);
}

/// An offset inside a multi-byte character, or past the end, never panics and
/// reads the region around it.
#[test]
fn an_offset_off_a_char_boundary_or_past_the_end_reads_its_region() {
    const SRC: &str = "x = \"é Font.";
    let mid = u32::try_from(SRC.find('é').expect("é") + 1).expect("fits");
    assert_eq!(
        ipe_parse::position_context(SRC, mid),
        PositionContext::String
    );
    assert_eq!(
        ipe_parse::position_context(SRC, u32::MAX),
        PositionContext::String
    );
    assert_eq!(ipe_parse::position_context("", 7), PositionContext::Code);
}

/// Regions tile the source: each starts where the last ended, none is empty,
/// and the last ends at the end of input, on unlexable text too.
#[test]
fn lexical_regions_tile_any_source() {
    for src in [
        "",
        "\"",
        "'",
        "{-",
        "{-|",
        "\"\"\"",
        "& . 1x \u{0007} \r",
        "x = \"a\nb = 'c' {- {- -} -} --",
    ] {
        let mut at = 0u32;
        for region in ipe_parse::lexical_regions(src) {
            assert_eq!(region.span.lo, at, "{src:?}: regions must be contiguous");
            assert!(region.span.hi > region.span.lo, "{src:?}: empty region");
            at = region.span.hi;
        }
        assert_eq!(
            at as usize,
            src.len(),
            "{src:?}: regions must reach the end"
        );
    }
}

/// A refused code token is one region over every byte the lexer read for it,
/// so the walk stays linear: rewinding to one character past its start would
/// re-read the rest of the run once per character (quadratic on a long
/// out-of-range or name-joined number).
#[test]
fn a_refused_code_token_is_one_region_over_the_bytes_the_lexer_read() {
    let run = "9".repeat(4096);
    for (src, read, refused) in [
        (run.clone(), run.len(), "out-of-range integer"),
        (format!("{run}x"), run.len(), "number joined to a name"),
        (
            format!("{run}.5e1x"),
            run.len() + 4,
            "float joined to a name",
        ),
        ("& x".to_owned(), 1, "lone ampersand"),
    ] {
        let first = ipe_parse::lexical_regions(&src)
            .next()
            .map(|r| (r.span.lo, r.span.hi, r.context, r.open_end));
        assert_eq!(
            first,
            Some((
                0,
                u32::try_from(read).unwrap_or(u32::MAX),
                PositionContext::Code,
                false
            )),
            "{refused}: the refused token's region ends where the lexer stopped"
        );
    }
}

// ---------------------------------------------------------------------------
// Differential test: every non-code region `lexical_regions` reads, against
// the real lexer's token spans and the trivia between them, over the stdlib
// and examples corpus. Equal region lists mean every byte offset agrees.
// ---------------------------------------------------------------------------

fn stdlib_root() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../stdlib")).to_path_buf()
}

fn examples_root() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../examples")).to_path_buf()
}

/// Every `.ipe` file under `dir`, recursively, in a stable order.
fn ipe_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = read.filter_map(Result::ok).map(|e| e.path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            ipe_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "ipe") {
            out.push(path);
        }
    }
}

/// A non-code region: its span, kind, and whether its end is open.
type Expected = (u32, u32, PositionContext, bool);

/// The comments in the trivia gap `[lo, hi)` between two tokens of a source
/// the lexer accepted, so the gap holds only whitespace and comments.
#[allow(clippy::panic, clippy::expect_used)] // the oracle refuses a gap the lexer could not have accepted
fn gap_comments(src: &str, lo: u32, hi: u32, out: &mut Vec<Expected>, label: &str) {
    let gap = src
        .get(lo as usize..hi as usize)
        .expect("gap on char boundaries");
    let bytes = gap.as_bytes();
    let mut i = 0usize;
    let at = |i: usize| lo + u32::try_from(i).expect("fits u32");
    while i < bytes.len() {
        match (bytes.get(i), bytes.get(i + 1)) {
            (Some(b' ' | b'\t' | b'\r' | b'\n'), _) => i += 1,
            (Some(b'-'), Some(b'-')) => {
                let start = i;
                while bytes.get(i).is_some_and(|&b| b != b'\n') {
                    i += 1;
                }
                out.push((at(start), at(i), PositionContext::LineComment, true));
            }
            (Some(b'{'), Some(b'-')) => {
                let start = i;
                i += 2;
                let mut depth = 1u32;
                while depth > 0 {
                    match (bytes.get(i), bytes.get(i + 1)) {
                        (Some(b'{'), Some(b'-')) => {
                            depth += 1;
                            i += 2;
                        }
                        (Some(b'-'), Some(b'}')) => {
                            depth -= 1;
                            i += 2;
                        }
                        (Some(_), _) => i += 1,
                        (None, _) => panic!("{label}: unclosed block comment in a lexed gap"),
                    }
                }
                out.push((at(start), at(i), PositionContext::BlockComment, false));
            }
            _ => panic!("{label}: non-trivia byte {i} in the gap at {lo}"),
        }
    }
}

/// The non-code regions of a lexed `src` per the lexer's tokens and the trivia
/// between them, or `None` when the lexer refuses `src`.
#[allow(clippy::expect_used)] // test oracle: a token span past u32 is the failure
fn expected_regions(src: &str, label: &str) -> Option<Vec<Expected>> {
    let tokens = ipe_parse::try_source_tokens(src)?;
    let mut out = Vec::new();
    let mut prev = 0u32;
    for tok in &tokens {
        gap_comments(src, prev, tok.span.lo, &mut out, label);
        let context = match tok.class {
            TokenClass::DocComment => Some(PositionContext::DocComment),
            TokenClass::Code(TokenKind::Str) => {
                string_regions(src, tok.span, &mut out, label);
                None
            }
            TokenClass::Code(TokenKind::Char) => Some(PositionContext::Char),
            TokenClass::Code(_) => None,
        };
        if let Some(context) = context {
            out.push((tok.span.lo, tok.span.hi, context, false));
        }
        prev = tok.span.hi;
    }
    let end = u32::try_from(src.len()).expect("fits u32");
    gap_comments(src, prev, end, &mut out, label);
    Some(out)
}

/// The regions of the string token at `span`: one string region, or, for a
/// `"""` string with `{{expr}}` bodies, the text between the bodies as string
/// and each body's own regions per [`expected_regions`] over its bytes.
#[allow(clippy::expect_used)] // test oracle: a lexed `"""` string judges and splits
fn string_regions(src: &str, span: Span, out: &mut Vec<Expected>, label: &str) {
    let whole = (span.lo, span.hi, PositionContext::String, false);
    let lo = span.lo as usize;
    if !src.get(lo..).is_some_and(|tail| tail.starts_with("\"\"\"")) {
        out.push(whole);
        return;
    }
    let before = src.get(..lo).expect("token on a char boundary");
    let count =
        |n: usize| NonZeroU32::new(u32::try_from(n + 1).expect("fits u32")).expect("one-based");
    let line = count(before.matches('\n').count());
    let column = count(before.rsplit('\n').next().map_or(0, |l| l.chars().count()));
    let judged = ipe_syntax::judge(
        src,
        ipe_syntax::Opener {
            lo: span.lo,
            line,
            column: ipe_syntax::Column::new(column),
        },
    )
    .expect("a lexed string judges");
    let bodies: Vec<Range<u32>> = ipe_syntax::segments(&judged.string)
        .expect("a lexed string splits")
        .into_iter()
        .filter_map(|segment| match segment {
            ipe_syntax::Segment::Body { source, .. } => Some(source),
            ipe_syntax::Segment::Lit { .. } => None,
        })
        .collect();
    if bodies.is_empty() {
        out.push(whole);
        return;
    }
    let mut text_lo = span.lo;
    for body in bodies {
        out.push((text_lo, body.start, PositionContext::String, false));
        let text = src
            .get(body.start as usize..body.end as usize)
            .expect("body on char boundaries");
        let inner = expected_regions(text, label).expect("a lexed body lexes");
        out.extend(
            inner
                .into_iter()
                .map(|(lo, hi, context, open)| (lo + body.start, hi + body.start, context, open)),
        );
        text_lo = body.end;
    }
    out.push((text_lo, span.hi, PositionContext::String, false));
}

/// The non-code regions `lexical_regions` reads in `src`.
fn read_regions(src: &str) -> Vec<Expected> {
    ipe_parse::lexical_regions(src)
        .filter(|r| r.context != PositionContext::Code)
        .map(|r| (r.span.lo, r.span.hi, r.context, r.open_end))
        .collect()
}

/// Kinds the corpus lacks, each driven through the same comparison.
const SYNTHETIC_FIXTURES: &[&str] = &[
    "module Main exposing (main)\n\n{- a {- nested -} block comment -}\nmain : Int\nmain = 1\n",
    "main = 'a' -- c\r\nx = \"\"\"a -- b {- c\"\"\" ++ \"{-\" <--y\n",
    "main = \"\"\"a {{ f \"x\" {- c -} 'y' }} b \\{{ c\"\"\"\n",
];

#[test]
fn position_context_agrees_with_the_lexer_over_the_corpus() {
    let mut files = Vec::new();
    ipe_files(&stdlib_root(), &mut files);
    ipe_files(&examples_root(), &mut files);
    assert!(files.len() > 100, "corpus too small: {}", files.len());

    let mut observed: BTreeSet<String> = BTreeSet::new();
    let mut lexed_files = 0usize;
    let mut sources: Vec<(String, String)> = files
        .iter()
        .filter_map(|path| {
            std::fs::read_to_string(path)
                .ok()
                .map(|src| (path.display().to_string(), src))
        })
        .collect();
    sources.extend(
        SYNTHETIC_FIXTURES
            .iter()
            .enumerate()
            .map(|(i, src)| (format!("<synthetic {i}>"), (*src).to_owned())),
    );

    for (label, src) in &sources {
        let Some(expected) = expected_regions(src, label) else {
            assert!(!label.starts_with("<synthetic"), "{label} must lex");
            continue;
        };
        lexed_files += 1;
        let read = read_regions(src);
        assert_eq!(read, expected, "{label}: regions disagree with the lexer");
        for (_, _, context, _) in &read {
            observed.insert(format!("{context:?}"));
        }
    }

    assert!(
        lexed_files > 100,
        "too few corpus files lexed: {lexed_files}"
    );
    for kind in [
        "LineComment",
        "BlockComment",
        "DocComment",
        "String",
        "Char",
    ] {
        assert!(
            observed.contains(kind),
            "no {kind} region was compared, so the test proves nothing for it"
        );
    }
}

/// On one source holding every kind, `position_context` at every byte offset
/// equals the region that holds it, so the corpus comparison of regions covers
/// the per-offset answer too.
#[test]
fn position_context_at_every_offset_is_the_holding_region() {
    let src = SYNTHETIC_FIXTURES.concat();
    let regions: Vec<_> = ipe_parse::lexical_regions(&src).collect();
    for offset in 0..=u32::try_from(src.len()).expect("fits u32") {
        let expected = regions
            .iter()
            .find(|r| r.holds(offset))
            .map_or(PositionContext::Code, |r| r.context);
        assert_eq!(
            ipe_parse::position_context(&src, offset),
            expected,
            "offset {offset}"
        );
    }
}
