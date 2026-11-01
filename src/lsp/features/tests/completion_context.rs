#![forbid(unsafe_code)]
//! `ipe_parse::position_context` proves BUG-CLASSES 8ck closed for
//! completion: the cursor's lexical context — code, a comment, or a string —
//! is read from the lexer itself, never a second scanner, so completion can
//! gate on it and never fire inside a comment or a string literal.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};
use ipe_diagnostics::TokenKind;
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
// Differential test: `position_context` against the real lexer's own token
// and trivia boundaries, over the stdlib and examples corpus.
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

/// How many times each `PositionContext` kind has already been checked
/// against `position_context` in the current file — capped so the
/// differential test stays O(corpus size) rather than re-scanning from
/// offset 0 once per token (an O(n^2) blow-up a large file would otherwise
/// pay for free).
#[derive(Default)]
struct ProbeBudget {
    code: u32,
    line_comment: u32,
    block_comment: u32,
    doc_comment: u32,
    string: u32,
    char: u32,
}

const PER_FILE_CAP: u32 = 3;

impl ProbeBudget {
    const fn allow(counter: &mut u32) -> bool {
        if *counter >= PER_FILE_CAP {
            return false;
        }
        *counter += 1;
        true
    }
}

/// Probe the first comment marker in the gap `[gap_lo, gap_hi)` — the real
/// lexer's trivia between two tokens (or before the first / after the last)
/// — and assert `position_context` agrees it is a line or block comment. A
/// whitespace-only gap asserts nothing further: ordinary code bytes are
/// already covered by the tokens on either side of it.
fn probe_gap(
    src: &str,
    gap_lo: u32,
    gap_hi: u32,
    budget: &mut ProbeBudget,
    observed: &mut BTreeSet<&'static str>,
    label: &str,
) {
    if gap_hi <= gap_lo {
        return;
    }
    let gap = &src[gap_lo as usize..gap_hi as usize];
    let Some((rel, _)) = gap.char_indices().find(|(_, c)| !c.is_whitespace()) else {
        return;
    };
    // `rel` is a byte offset inside `gap`, a slice of `src`; `src` is already
    // bounded to `u32` range by every span-producing lexer call, so this never
    // saturates in practice — the fallback just keeps the helper `expect`-free.
    let marker_start = gap_lo + u32::try_from(rel).unwrap_or(u32::MAX);
    let rest = &gap[rel..];
    if rest.starts_with("--") {
        if !ProbeBudget::allow(&mut budget.line_comment) {
            return;
        }
        let probe = marker_start + 2;
        assert_eq!(
            ipe_parse::position_context(src, probe),
            PositionContext::LineComment,
            "{label}: byte {probe} inside a `--` comment must classify LineComment"
        );
        observed.insert("LineComment");
    } else if rest.starts_with("{-") {
        if !ProbeBudget::allow(&mut budget.block_comment) {
            return;
        }
        let probe = marker_start + 2;
        assert_eq!(
            ipe_parse::position_context(src, probe),
            PositionContext::BlockComment,
            "{label}: byte {probe} inside a block comment must classify BlockComment"
        );
        observed.insert("BlockComment");
    }
}

/// Run every probe [`position_context_agrees_with_the_lexer_over_the_corpus`]
/// drives against one source text, identified in failure messages by `label`.
/// Returns whether `src` lexed at all — an unlexable source (a deliberately
/// malformed fixture elsewhere in the corpus) contributes no ground truth and
/// is skipped by the caller, same as `try_source_tokens`'s own contract.
fn probe_source(src: &str, label: &str, observed: &mut BTreeSet<&'static str>) -> bool {
    let Some(tokens) = ipe_parse::try_source_tokens(src) else {
        return false;
    };
    let mut budget = ProbeBudget::default();

    let mut prev_hi = 0u32;
    for tok in &tokens {
        probe_gap(src, prev_hi, tok.span.lo, &mut budget, observed, label);

        match tok.class {
            TokenClass::DocComment => {
                if ProbeBudget::allow(&mut budget.doc_comment) {
                    let probe = tok.span.lo + 3; // past the `{-|` opener
                    assert_eq!(
                        ipe_parse::position_context(src, probe),
                        PositionContext::DocComment,
                        "{label}: byte {probe} inside a doc-comment token must classify DocComment"
                    );
                    observed.insert("DocComment");
                }
            }
            TokenClass::Code(TokenKind::Str) => {
                let probe = tok.span.lo + 1; // past the opening `"`
                if probe < tok.span.hi && ProbeBudget::allow(&mut budget.string) {
                    assert_eq!(
                        ipe_parse::position_context(src, probe),
                        PositionContext::String,
                        "{label}: byte {probe} inside a string token must classify String"
                    );
                    observed.insert("String");
                }
            }
            TokenClass::Code(TokenKind::Char) => {
                let probe = tok.span.lo + 1; // past the opening `'`
                if probe < tok.span.hi && ProbeBudget::allow(&mut budget.char) {
                    assert_eq!(
                        ipe_parse::position_context(src, probe),
                        PositionContext::Char,
                        "{label}: byte {probe} inside a char token must classify Char"
                    );
                    observed.insert("Char");
                }
            }
            TokenClass::Code(_) => {
                if ProbeBudget::allow(&mut budget.code) {
                    let probe = tok.span.lo + (tok.span.hi - tok.span.lo) / 2;
                    assert_eq!(
                        ipe_parse::position_context(src, probe),
                        PositionContext::Code,
                        "{label}: byte {probe} inside an ordinary token must classify Code"
                    );
                    observed.insert("Code");
                }
            }
        }
        prev_hi = tok.span.hi;
    }
    probe_gap(
        src,
        prev_hi,
        u32::try_from(src.len()).unwrap_or(u32::MAX),
        &mut budget,
        observed,
        label,
    );
    true
}

/// The stdlib and examples corpus happens to contain zero plain `{- -}`
/// block comments — every block-shaped comment it has is a `{-|` doc
/// comment. This fragment exercises that one remaining kind through the
/// exact same lexer-derived probe every corpus file goes through
/// ([`probe_source`]), so the vacuity guard (BUG-CLASSES 8aw) stays honest
/// — proven on real lexer output, never loosened to pass on an absence.
const SYNTHETIC_BLOCK_COMMENT_FIXTURE: &str =
    "module Main exposing (main)\n\n{- a plain, non-doc block comment -}\nmain : Int\nmain = 1\n";

/// `position_context` agrees with the real lexer's own token and trivia
/// boundaries over every `.ipe` file in the stdlib and examples corpus — the
/// differential proof BUG-CLASSES 8ck asks for (mirror the real lexer,
/// proven against it, not merely asserted). The vacuity guard (BUG-CLASSES
/// 8aw) pins a non-empty corpus, at least one file that actually lexed, and
/// every `PositionContext` variant observed at least once, so this cannot
/// pass by probing nothing.
#[test]
fn position_context_agrees_with_the_lexer_over_the_corpus() {
    let mut files = Vec::new();
    ipe_files(&stdlib_root(), &mut files);
    ipe_files(&examples_root(), &mut files);
    assert!(
        !files.is_empty(),
        "corpus must be non-empty or this test proves nothing"
    );

    let mut observed: BTreeSet<&'static str> = BTreeSet::new();
    let mut lexed_files = 0usize;

    for path in &files {
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        let label = path.display().to_string();
        if probe_source(&src, &label, &mut observed) {
            lexed_files += 1;
        }
    }

    assert!(
        probe_source(
            SYNTHETIC_BLOCK_COMMENT_FIXTURE,
            "<synthetic block-comment fixture>",
            &mut observed
        ),
        "the synthetic block-comment fixture must itself lex"
    );

    assert!(
        lexed_files > 0,
        "every corpus file failed to lex — the differential test proves nothing"
    );
    for kind in [
        "Code",
        "LineComment",
        "BlockComment",
        "DocComment",
        "String",
        "Char",
    ] {
        assert!(
            observed.contains(kind),
            "the corpus never exercised PositionContext::{kind} — vacuity guard failed"
        );
    }
}
