//! Semantic tokens: `textDocument/semanticTokens/full`.
//!
//! Classifies every token in the parse tree into one of the types in
//! [`LEGEND`] and returns the LSP delta-encoded token array.
//!
//! **Token types (indexes into the legend):**
//!
//! | Index | `tokenTypes` entry  | What it covers                       |
//! |-------|---------------------|--------------------------------------|
//! | 0     | `namespace`         | Module name in `module` / `import`   |
//! | 1     | `type`              | Type constructor in annotations       |
//! | 2     | `typeParameter`     | Type variable in annotations          |
//! | 3     | `function`          | Top-level value / function name       |
//! | 4     | `variable`          | Local variable in patterns            |
//! | 5     | `enumMember`        | Constructor in patterns / expressions |
//! | 6     | `keyword`           | Keywords (`module`, `import`, …)      |
//! | 7     | `string`            | String / char / multiline-str literal |
//! | 8     | `number`            | Integer / float literal               |
//! | 9     | `operator`          | Binary operator                       |
//!
//! Only `tokenTypes` is used; `tokenModifiers` is empty.
//!
//! The token stream is produced by [`ipe_annotate::annotate`] (the shared SSOT
//! for both highlighting and term-to-definition linking) and then projected to
//! this legend.  Semantic classification therefore cannot drift from the shared
//! API.

use ipe_annotate::TokenClass;
use ipe_db::{Db as _, IpeDatabase, SourceFile};
use lsp_types::{
    Position, Range, SemanticToken, SemanticTokens, SemanticTokensLegend,
    SemanticTokensRangeResult, SemanticTokensResult,
};

use crate::offset::{LineIndex, PositionEncoding, position_to_offset};

// ---------------------------------------------------------------------------
// Legend
// ---------------------------------------------------------------------------

/// Token type indexes — must stay in sync with [`LEGEND`].
const TT_NAMESPACE: u32 = 0;
const TT_TYPE: u32 = 1;
const TT_TYPE_PARAMETER: u32 = 2;
const TT_FUNCTION: u32 = 3;
const TT_VARIABLE: u32 = 4;
const TT_ENUM_MEMBER: u32 = 5;
const TT_KEYWORD: u32 = 6;
const TT_STRING: u32 = 7;
const TT_NUMBER: u32 = 8;
const TT_OPERATOR: u32 = 9;

/// The legend this server advertises and uses.
#[must_use]
pub fn legend() -> SemanticTokensLegend {
    SemanticTokensLegend {
        token_types: vec![
            lsp_types::SemanticTokenType::NAMESPACE,
            lsp_types::SemanticTokenType::TYPE,
            lsp_types::SemanticTokenType::TYPE_PARAMETER,
            lsp_types::SemanticTokenType::FUNCTION,
            lsp_types::SemanticTokenType::VARIABLE,
            lsp_types::SemanticTokenType::ENUM_MEMBER,
            lsp_types::SemanticTokenType::KEYWORD,
            lsp_types::SemanticTokenType::STRING,
            lsp_types::SemanticTokenType::NUMBER,
            lsp_types::SemanticTokenType::OPERATOR,
        ],
        token_modifiers: vec![],
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Full semantic-token encoding for one document.
///
/// Returns an empty result for an unparseable document — the client falls back
/// to syntax highlighting.
#[must_use]
pub fn semantic_tokens_full(
    db: &IpeDatabase,
    file: SourceFile,
    encoding: PositionEncoding,
) -> SemanticTokensResult {
    let tokens = collect_tokens(db, file, encoding);
    SemanticTokensResult::Tokens(SemanticTokens {
        result_id: None,
        data: tokens,
    })
}

/// Semantic tokens for the byte span that corresponds to `range`.
///
/// Only tokens whose start byte falls within `[range_lo, range_hi)` are
/// returned; the delta encoding is reset so it is relative to the first
/// token in the range, as the protocol requires.
#[must_use]
pub fn semantic_tokens_range(
    db: &IpeDatabase,
    file: SourceFile,
    range: Range,
    encoding: PositionEncoding,
) -> SemanticTokensRangeResult {
    let (raw, text) = collect_raw(db, file);
    let range_lo = position_to_offset(text, range.start, encoding);
    let range_hi = position_to_offset(text, range.end, encoding);
    let filtered: Vec<RawToken> = raw
        .into_iter()
        .filter(|tok| {
            let start = tok.byte as usize;
            start >= range_lo && start < range_hi
        })
        .collect();
    let tokens = encode(filtered, text, encoding);
    SemanticTokensRangeResult::Tokens(SemanticTokens {
        result_id: None,
        data: tokens,
    })
}

// ---------------------------------------------------------------------------
// Token collection — thin projection over ipe_annotate::annotate
// ---------------------------------------------------------------------------

/// A raw token before delta-encoding.
#[derive(Debug, Clone, Copy)]
struct RawToken {
    /// Byte offset of the token start.
    byte: u32,
    /// Byte length of the token.
    len: u32,
    /// LSP token type index.
    token_type: u32,
}

fn collect_raw(db: &IpeDatabase, file: SourceFile) -> (Vec<RawToken>, &str) {
    let text = file.text(db);
    let Ok(module) = ipe_db::parse(db, file) else {
        return (Vec::new(), text);
    };
    let interner = db.interner().lock();

    // Uses `annotate_syntax_only` (not the full canonicaliser) — cheap on keypress;
    // yields class-only tokens with no def keys.
    let annotated = ipe_annotate::annotate_syntax_only(module, &interner);
    drop(interner);

    let raw: Vec<RawToken> = annotated
        .into_iter()
        .filter_map(|tok| {
            let token_type = class_to_lsp(tok.class)?;
            Some(RawToken {
                byte: tok.byte_start,
                len: tok.byte_len,
                token_type,
            })
        })
        .collect();

    (raw, text)
}

fn collect_tokens(
    db: &IpeDatabase,
    file: SourceFile,
    encoding: PositionEncoding,
) -> Vec<SemanticToken> {
    let (raw, text) = collect_raw(db, file);
    encode(raw, text, encoding)
}

/// Project a [`TokenClass`] to an LSP token type index, or `None` for classes
/// the LSP legend does not expose (e.g. `Comment`, `Punctuation`).
const fn class_to_lsp(class: TokenClass) -> Option<u32> {
    match class {
        TokenClass::Module => Some(TT_NAMESPACE),
        TokenClass::Type => Some(TT_TYPE),
        TokenClass::TypeVar => Some(TT_TYPE_PARAMETER),
        TokenClass::Function | TokenClass::Kernel => Some(TT_FUNCTION),
        TokenClass::Variable => Some(TT_VARIABLE),
        TokenClass::Constructor => Some(TT_ENUM_MEMBER),
        TokenClass::Keyword => Some(TT_KEYWORD),
        TokenClass::StringLit => Some(TT_STRING),
        TokenClass::Number => Some(TT_NUMBER),
        TokenClass::Operator => Some(TT_OPERATOR),
        TokenClass::Comment | TokenClass::Punctuation => None,
    }
}

// ---------------------------------------------------------------------------
// Delta encoding
// ---------------------------------------------------------------------------

/// Delta-encode `raw`, reading each token's position from the shared [`LineIndex`].
fn encode(raw: Vec<RawToken>, text: &str, encoding: PositionEncoding) -> Vec<SemanticToken> {
    let mut out: Vec<SemanticToken> = Vec::with_capacity(raw.len());
    let index = LineIndex::new(text);
    let mut prev_line: u32 = 0;
    let mut prev_char: u32 = 0;

    for tok in raw {
        let Position {
            line: pos_line,
            character: pos_char,
        } = index.position_of(tok.byte as usize, encoding);

        let delta_line = pos_line - prev_line;
        let delta_start = if delta_line == 0 {
            pos_char - prev_char
        } else {
            pos_char
        };
        let slice = text
            .get(tok.byte as usize..(tok.byte + tok.len) as usize)
            .unwrap_or("");
        let length = match encoding {
            PositionEncoding::Utf8 => tok.len,
            PositionEncoding::Utf16 => slice
                .chars()
                .map(|c| u32::try_from(c.len_utf16()).unwrap_or(2))
                .sum(),
        };
        out.push(SemanticToken {
            delta_line,
            delta_start,
            length,
            token_type: tok.token_type,
            token_modifiers_bitset: 0,
        });
        prev_line = pos_line;
        prev_char = pos_char;
    }
    out
}

#[cfg(test)]
mod tests {
    use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile};
    use lsp_types::{Position, Range};

    use super::{legend, semantic_tokens_full, semantic_tokens_range};
    use crate::offset::PositionEncoding;

    fn file(db: &IpeDatabase, path: &[&str], text: &str) -> SourceFile {
        ipe_db::SourceFile::new(
            db,
            path.iter().map(|s| (*s).to_owned()).collect(),
            text.to_owned(),
            ModuleOrigin::User,
        )
    }

    /// Unwrap the full-encoding result to its token list. `semantic_tokens_full`
    /// only ever returns the `Tokens` variant; the `Partial` case maps to `None`
    /// so the caller's `.expect` fails the test rather than panicking inline.
    fn tokens_of(result: lsp_types::SemanticTokensResult) -> lsp_types::SemanticTokens {
        let tokens = match result {
            lsp_types::SemanticTokensResult::Tokens(tokens) => Some(tokens),
            lsp_types::SemanticTokensResult::Partial(_) => None,
        };
        tokens.expect("semantic_tokens_full returns the Tokens variant")
    }

    #[test]
    fn legend_has_ten_token_types() {
        assert_eq!(legend().token_types.len(), 10);
    }

    #[test]
    fn tokens_non_empty_for_valid_module() {
        let db = IpeDatabase::new();
        let src = "module Main exposing (main)\n\nmain : Int\nmain =\n    42\n";
        let f = file(&db, &["Main"], src);
        let result = semantic_tokens_full(&db, f, PositionEncoding::Utf16);
        let tokens = tokens_of(result);
        assert!(!tokens.data.is_empty(), "tokens produced for valid module");
    }

    #[test]
    fn no_tokens_for_unparseable_module() {
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], "@@@ not parseable @@@");
        let result = semantic_tokens_full(&db, f, PositionEncoding::Utf16);
        let tokens = tokens_of(result);
        assert!(tokens.data.is_empty(), "no tokens for unparseable source");
    }

    #[test]
    fn tokens_are_delta_sorted() {
        let db = IpeDatabase::new();
        let src = "module Main exposing (main)\n\nmain : Int\nmain =\n    42\n";
        let f = file(&db, &["Main"], src);
        let result = semantic_tokens_full(&db, f, PositionEncoding::Utf16);
        let tokens = tokens_of(result);
        let mut line: u32 = 0;
        let mut col: u32 = 0;
        for tok in &tokens.data {
            if tok.delta_line == 0 {
                assert!(
                    tok.delta_start >= col || col == 0,
                    "tokens on the same line must advance right"
                );
                col += tok.delta_start;
            } else {
                line += tok.delta_line;
                col = tok.delta_start;
            }
        }
        let _ = line;
    }

    /// Range request covering only `main : Int` (line 2) returns a proper
    /// subset of the full token list and the delta encoding is reset to be
    /// relative to the first token in the range, not the file start.
    #[test]
    fn range_tokens_subset_of_full_and_delta_resets() {
        let db = IpeDatabase::new();
        // "module Main exposing (main)\n" — line 0
        // "\n"                             — line 1
        // "main : Int\n"                   — line 2  ← range covers this line only
        // "main =\n"                       — line 3
        // "    42\n"                        — line 4
        let src = "module Main exposing (main)\n\nmain : Int\nmain =\n    42\n";
        let f = file(&db, &["Main"], src);

        // Cover the definition and its body (lines 3–4), which carry real
        // expression tokens — the type-annotation line 2 is not tokenized.
        let range = Range {
            start: Position {
                line: 3,
                character: 0,
            },
            end: Position {
                line: 9999,
                character: 0,
            },
        };
        let result = semantic_tokens_range(&db, f, range, PositionEncoding::Utf8);
        let is_tokens = matches!(result, lsp_types::SemanticTokensRangeResult::Tokens(_));
        assert!(
            is_tokens,
            "semantic_tokens_range must return Tokens variant, not Partial"
        );
        let lsp_types::SemanticTokensRangeResult::Tokens(range_tokens) = result else {
            return; // unreachable — asserted above
        };

        // The definition body carries tokens.
        assert!(
            !range_tokens.data.is_empty(),
            "range covering the definition body must yield tokens"
        );

        // The full result also covers the module header (line 0), so the range
        // is a strict subset.
        let full_tokens = tokens_of(semantic_tokens_full(&db, f, PositionEncoding::Utf8));
        assert!(
            range_tokens.data.len() < full_tokens.data.len(),
            "range result must be a strict subset of the full result"
        );

        // Delta encoding is reset for the range: the first token's delta_line is
        // its ABSOLUTE line (≥ 3, the range start), not a small delta relative to
        // a token before the range.
        let first = range_tokens
            .data
            .first()
            .expect("range must yield at least one token");
        assert!(
            first.delta_line >= 3,
            "first range token delta_line must be its absolute line (encoding reset to 0), got {}",
            first.delta_line
        );
    }

    /// Every text of up to four pieces over `a`, `\r\n`, `\n`, a lone `\r` and an astral char.
    fn every_short_text() -> Vec<String> {
        let pieces = ["a", "\r\n", "\n", "\r", "😀"];
        let mut texts = vec![String::new()];
        let mut frontier = vec![String::new()];
        for _ in 0..4 {
            frontier = frontier
                .iter()
                .flat_map(|t| pieces.iter().map(move |piece| format!("{t}{piece}")))
                .collect();
            texts.extend(frontier.iter().cloned());
        }
        texts
    }

    /// The absolute positions a delta-encoded token list names.
    fn decoded(tokens: &[lsp_types::SemanticToken]) -> Vec<Position> {
        let mut at = Position {
            line: 0,
            character: 0,
        };
        tokens
            .iter()
            .map(|tok| {
                at = if tok.delta_line == 0 {
                    Position {
                        line: at.line,
                        character: at.character + tok.delta_start,
                    }
                } else {
                    Position {
                        line: at.line + tok.delta_line,
                        character: tok.delta_start,
                    }
                };
                at
            })
            .collect()
    }

    /// A token at every char boundary of every mix of line breaks sits where
    /// the shared `offset::LineIndex` puts it, a mid-`\r\n` byte included.
    #[test]
    fn semantic_tokens_positions_match_offset_line_index() {
        for text in every_short_text() {
            let bytes: Vec<usize> = (0..=text.len())
                .filter(|&b| text.is_char_boundary(b))
                .collect();
            let raw: Vec<super::RawToken> = bytes
                .iter()
                .map(|&b| super::RawToken {
                    byte: u32::try_from(b).unwrap(),
                    len: 0,
                    token_type: 0,
                })
                .collect();
            for encoding in [PositionEncoding::Utf8, PositionEncoding::Utf16] {
                let index = crate::offset::LineIndex::new(&text);
                let expected: Vec<Position> = bytes
                    .iter()
                    .map(|&b| index.position_of(b, encoding))
                    .collect();
                let got = decoded(&super::encode(raw.clone(), &text, encoding));
                assert_eq!(got, expected, "{text:?} ({encoding:?})");
            }
        }
    }
}
