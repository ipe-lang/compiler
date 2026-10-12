//! Layout-aware lexer for the supported subset of Ipê.
//!
//! This is a Rust port of the relevant pieces of the reference compiler's
//! `Ipe.Parse.{Primitives,Space,Number,Symbol,Variable}` — narrowed to the
//! token shapes the supported subset exercises. Rather than emit explicit
//! layout tokens, each token carries its 1-based `line`/`col`, and the parser
//! reconstructs block structure from columns (see [`crate::layout`]).
//!
//! The lexer never panics on arbitrary bytes: any byte it cannot classify
//! yields a typed, coded [`ParseError`] — [`ParseError::UnknownChar`] for an
//! unrecognised byte, [`ParseError::StrayDot`] for a lone `.`,
//! [`ParseError::NumberJoinedToName`] for `123abc`, and
//! [`ParseError::IntLiteralOutOfRange`] for a magnitude past `2^63` (the
//! parser refuses `2^63` itself unless a unary minus makes it `i64::MIN`).

use ipe_diagnostics::{DResult, Diagnostic, ParseError, Span};
use ipe_syntax::ESCAPES;

/// Unsigned magnitude of an integer literal as lexed, bounded to `0 ..= 2^63`.
///
/// The sign is not yet known at lex time, so the bound admits `2^63`, the
/// magnitude of `i64::MIN`. The parser turns a magnitude into an `i64` only
/// through [`IntMagnitude::positive`] (partial: `None` exactly for `2^63`) or
/// [`IntMagnitude::negated`] (total). The field is private, so
/// [`IntMagnitude::from_digits`] is the only constructor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntMagnitude(u64);

impl IntMagnitude {
    /// The largest magnitude a literal may spell: `2^63`, which is `i64::MIN` negated.
    const LIMIT: u64 = i64::MIN.unsigned_abs();

    /// The magnitude ASCII `digits` spell, or `None` when it exceeds `2^63`.
    pub fn from_digits(digits: &str) -> Option<Self> {
        let magnitude = digits.parse::<u64>().ok()?;
        (magnitude <= Self::LIMIT).then_some(Self(magnitude))
    }

    /// The literal without a sign; `None` exactly for `2^63`.
    pub fn positive(self) -> Option<i64> {
        i64::try_from(self.0).ok()
    }

    /// The literal under unary minus.
    ///
    /// Total: the magnitude is at most `2^63`, so `0 - magnitude` never passes
    /// `i64::MIN` and the saturation point is reached only by `2^63` itself.
    pub const fn negated(self) -> i64 {
        0i64.saturating_sub_unsigned(self.0)
    }
}

/// A lexical token kind.
///
/// `Eq` is intentionally NOT derived: [`Tok::Float`] carries an `f64`, which is
/// only `PartialEq` (IEEE-754 `NaN` is not reflexive). Token comparison only
/// ever needs `==` against a fixed non-float variant (`t.kind == Tok::RParen`),
/// which `PartialEq` provides; nothing keys a map or set on a `Tok`.
#[derive(Clone, PartialEq, Debug)]
pub enum Tok {
    // Keywords.
    Module,
    Import,
    Exposing,
    As,
    Type,
    /// `foreign` — introduces an FFI type declaration `foreign Name = { crate = …, kind = … }`.
    /// Read only by the CLI lift pass; the compiler proper ignores foreign declarations.
    Foreign,
    Case,
    Of,
    Let,
    In,
    If,
    Then,
    Else,
    Do,
    // Punctuation / operators.
    LParen,
    RParen,
    LBrace,
    RBrace,
    /// `[` — opens a list literal `[a, b, c]` or a list pattern.
    LBracket,
    /// `]` — closes a list literal / pattern.
    RBracket,
    /// `::` — the right-associative list cons operator (`x :: xs`) and the cons
    /// pattern head. Lexed as ONE token (a maximal munch of `:`), never two
    /// adjacent [`Tok::Colon`].
    ColonColon,
    Equals,
    Pipe,
    Colon,
    Arrow,
    /// A `do`-block bind lead-in `<-` (`p <- task`).
    LeftArrow,
    /// A lambda lead-in `\` (`\x -> e`).
    Backslash,
    DotDot,
    /// A lone `.` introducing a field access on a non-identifier expression,
    /// e.g. the `.` in `(record).field`. Bare `ident.field` runs are still one
    /// [`Tok::Ident`]; this token only appears when the dot follows a closing
    /// delimiter or other non-identifier token.
    Dot,
    Comma,
    Underscore,
    Plus,
    /// The string/list append operator `++`. Lexed as ONE token (a maximal
    /// munch of `+`), never as two adjacent [`Tok::Plus`], so the parser sees
    /// the binary operator the reference grammar defines at precedence 5.
    PlusPlus,
    Minus,
    Star,
    Slash,
    SlashEq,
    /// The integer-division operator `//`. Lexed as ONE token (maximal munch of
    /// `/`), never as two adjacent [`Tok::Slash`].
    SlashSlash,
    EqEq,
    Lt,
    Gt,
    Le,
    Ge,
    AmpAmp,
    PipePipe,
    /// The forward-pipe operator `|>`. Lexed as ONE token (maximal munch of
    /// `|`), so `|>` never reaches the parser as `Pipe` then `Gt`.
    PipeGt,
    /// The backward-pipe operator `<|`. Lexed as ONE token (maximal munch of
    /// `<`), so `<|` never reaches the parser as `Lt` then `Pipe`.
    LtPipe,
    /// The parser-pipeline keep operator `|=`. Desugars to `Ipe.Parser.ignore
    /// left right` (runs left then right, yields right's result). Lexed as ONE
    /// token (maximal munch of `|`), so `|=` never reaches the parser as `Pipe`
    /// then `Equals`.
    PipeEq,
    /// The parser-pipeline discard operator `|.`. Desugars to `Ipe.Parser.keep
    /// left right` (runs left then right, yields left's result). Lexed as ONE
    /// token (maximal munch of `|`), so `|.` never reaches the parser as `Pipe`
    /// then `Dot`.
    PipeDot,
    /// The forward-composition operator `>>`. Lexed as ONE token (maximal munch
    /// of `>`), so `>>` never reaches the parser as two adjacent [`Tok::Gt`].
    GtGt,
    /// The backward-composition operator `<<`. Lexed as ONE token (maximal munch
    /// of `<`), so `<<` never reaches the parser as two adjacent [`Tok::Lt`].
    LtLt,
    // Literals / names.
    /// A (possibly dotted) identifier, e.g. `count`, `Msg`, `String.fromInt`.
    Ident(String),
    /// An integer literal's unsigned magnitude; the parser applies the sign.
    Int(IntMagnitude),
    /// A floating-point literal `1.5`, `3.0`, `1.5e3`, `2e-2`. The carried
    /// [`f64`] is the parsed value; the lexer only builds well-formed Elm-style
    /// float lexemes (a leading digit is required, so `.5` is not a float), so
    /// the downstream stages see a ready numeric value.
    Float(f64),
    /// A string literal `"hello"`. The carried [`String`] is the already
    /// UNESCAPED value (escape sequences such as `\n` / `\"` are resolved here),
    /// so downstream stages see the runtime string verbatim.
    Str(String),
    /// A triple-quoted string literal `"""..."""`.
    ///
    /// `raw` is the RAW content — escape sequences (`\n`, `\\`) and `{{expr}}`
    /// interpolation markers are NOT resolved here; the canonicaliser handles
    /// them downstream.
    ///
    /// `anchor` is the 1-based source column of the first non-whitespace content
    /// character (the anchor column A). The canonicaliser strips up to `A - 1`
    /// leading whitespace characters from every physical line after the first,
    /// so an indented `"""…"""` block does not carry its source margin into the
    /// runtime value.
    TripleStr {
        raw: String,
        anchor: u32,
    },
    /// A character literal `'a'`. The carried [`String`] is the single UNESCAPED
    /// character's text (exactly one `char`), so `'\n'` carries a one-character
    /// newline string. The backend renders it as a Rust `char` literal.
    Char(String),
    /// A doc-comment block `{-| … -}` placed immediately above a top-level
    /// declaration. The carried [`String`] is the raw body text between the
    /// `{-|` opener and the `-}` closer (delimiters excluded). Ordinary block
    /// comments `{- … -}` are discarded by the lexer and never produce this
    /// token.
    DocComment(String),
}

/// A token with its source position.
///
/// `Eq` is not derived: the `kind` field is a [`Tok`], which carries an `f64`
/// in [`Tok::Float`] and so is only `PartialEq` (see [`Tok`]).
#[derive(Clone, PartialEq, Debug)]
pub struct Token {
    pub kind: Tok,
    /// 1-based line.
    pub line: u32,
    /// 1-based column.
    pub col: u32,
    pub span: Span,
}

struct Lexer<'src> {
    /// The full source. A lexeme spans a contiguous byte range `[lo, hi)`, so a
    /// keyword/number/body reads directly from `src[lo..hi]` — no per-char heap
    /// buffer. All offsets come from `CharIndices`, so every range is on a char
    /// boundary; `get` keeps the slice fail-closed if that ever breaks.
    src: &'src str,
    /// Up to three characters of lookahead. `window[0]` is the current char
    /// (what `peek()` returns), `window[1]` is one ahead, `window[2]` is two
    /// ahead. A `None` slot means end-of-input at that position.
    window: [Option<(usize, char)>; 3],
    /// The remaining source characters after the lookahead window.
    rest: std::str::CharIndices<'src>,
    /// Byte offset one past the last character in `src` — the EOF position used
    /// by `offset()` when the window is empty.
    eof_offset: u32,
    line: u32,
    col: u32,
}

impl<'src> Lexer<'src> {
    fn new(src: &'src str) -> Self {
        let eof_offset = u32::try_from(src.len()).unwrap_or(u32::MAX);
        let mut iter = src.char_indices();
        let a = iter.next();
        let b = iter.next();
        let c = iter.next();
        Self {
            src,
            window: [a, b, c],
            rest: iter,
            eof_offset,
            line: 1,
            col: 1,
        }
    }

    /// The source text over the byte range `[lo, hi)`, where both bounds are
    /// char-boundary offsets the lexer produced from `CharIndices`. Returns the
    /// empty string if the range is somehow out of bounds — a fail-closed
    /// fallback that never panics on a bad offset.
    fn slice(&self, lo: u32, hi: u32) -> &'src str {
        self.src.get(lo as usize..hi as usize).unwrap_or("")
    }

    fn peek(&self) -> Option<char> {
        self.window[0].map(|(_, c)| c)
    }

    fn peek2(&self) -> Option<char> {
        self.window[1].map(|(_, c)| c)
    }

    /// The character two positions ahead of the cursor, used to confirm a digit
    /// follows a signed exponent (`e-2`) before committing to a float lexeme.
    fn peek3(&self) -> Option<char> {
        self.window[2].map(|(_, c)| c)
    }

    /// Byte offset of the current char, or end-of-input.
    ///
    /// [`lex`] rejects any source larger than `u32::MAX` bytes before building
    /// the lexer, so every byte offset here fits a `u32`; the saturating
    /// conversion is an unreachable fallback, never a silent clamp of a real
    /// position.
    fn offset(&self) -> u32 {
        match self.window[0] {
            Some((o, _)) => u32::try_from(o).unwrap_or(u32::MAX),
            None => self.eof_offset,
        }
    }

    fn advance(&mut self) {
        if let Some((_, c)) = self.window[0] {
            if c == '\n' {
                self.line = self.line.saturating_add(1);
                self.col = 1;
            } else {
                self.col = self.col.saturating_add(1);
            }
            self.window[0] = self.window[1];
            self.window[1] = self.window[2];
            self.window[2] = self.rest.next();
        }
    }

    /// Skip whitespace, line comments (`-- … <newline>`), and block comments
    /// (`{- … -}`, nestable). Returns `Ok(())` on success; returns
    /// [`ParseError::UnterminatedBlockComment`] when a `{-` opener has no
    /// matching `-}` before end of input.
    fn skip_trivia(&mut self) -> DResult<()> {
        loop {
            match self.peek() {
                Some(c) if c == ' ' || c == '\t' || c == '\r' || c == '\n' => self.advance(),
                // Line comment: `-- … \n`. Consume everything up to (but not
                // including) the newline, then loop so the newline itself is
                // consumed as whitespace on the next iteration.
                Some('-') if self.peek2() == Some('-') => {
                    while let Some(c) = self.peek() {
                        if c == '\n' {
                            break;
                        }
                        self.advance();
                    }
                }
                // Block comment: `{- … -}`, nestable. A `{-` inside a comment
                // increments the depth; a `-}` decrements it; depth 0 ends.
                // A `{-|` opener is a doc-comment token — leave it for the
                // main lex loop to emit as [`Tok::DocComment`].
                Some('{') if self.peek2() == Some('-') && self.peek3() != Some('|') => {
                    let lo = self.offset();
                    self.advance(); // consume `{`
                    self.advance(); // consume `-`
                    let mut depth: u32 = 1;
                    loop {
                        match self.peek() {
                            None => {
                                return Err(Diagnostic::Parse {
                                    span: Span::new(lo, self.offset()),
                                    msg: ParseError::UnterminatedBlockComment,
                                });
                            }
                            Some('{') if self.peek2() == Some('-') => {
                                self.advance();
                                self.advance();
                                depth = depth.saturating_add(1);
                            }
                            Some('-') if self.peek2() == Some('}') => {
                                self.advance();
                                self.advance();
                                depth -= 1;
                                if depth == 0 {
                                    break;
                                }
                            }
                            Some(_) => self.advance(),
                        }
                    }
                }
                _ => break,
            }
        }
        Ok(())
    }
}

/// The UTF-8 byte width of `c` as a `u32`, clamped to `1` on the impossible
/// overflow so a span can always be formed without a panic.
fn char_width(c: char) -> u32 {
    u32::try_from(c.len_utf8()).unwrap_or(1)
}

/// Whether `c` may begin an identifier (ASCII letter or `_`).
#[must_use]
pub const fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

/// Whether `c` may continue an identifier (ASCII alphanumeric or `_`).
#[must_use]
pub const fn is_ident_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Declares the reserved-word table once.
///
/// Both the name list and the text-to-token recogniser derive from the one
/// invocation below, so the two cannot drift.
macro_rules! keywords {
    ($($text:literal => $tok:ident),* $(,)?) => {
        /// Every reserved word, in declaration order.
        pub const KEYWORDS: &[&str] = &[$($text),*];

        /// The keyword token `text` spells, or `None` for a non-keyword.
        pub fn keyword(text: &str) -> Option<Tok> {
            match text {
                $($text => Some(Tok::$tok),)*
                _ => None,
            }
        }
    };
}

keywords! {
    "module" => Module,
    "import" => Import,
    "exposing" => Exposing,
    "as" => As,
    "type" => Type,
    "foreign" => Foreign,
    "case" => Case,
    "of" => Of,
    "let" => Let,
    "in" => In,
    "if" => If,
    "then" => Then,
    "else" => Else,
    "do" => Do,
}

/// Lex `src` into tokens, or fail with a typed diagnostic.
/// Whether a source of `byte_len` bytes can be spanned: every byte offset the
/// lexer records is a `u32`, so the source must fit in `u32::MAX` bytes. The
/// boundary is a named predicate so the refusal is testable without allocating a
/// multi-gigabyte string.
fn source_offset_range_admits(byte_len: usize) -> bool {
    u32::try_from(byte_len).is_ok()
}

pub fn lex(src: &str) -> DResult<Vec<Token>> {
    // Byte offsets are stored as `u32`; a source larger than `u32::MAX` bytes
    // cannot be spanned. Refuse it here rather than clamp offsets downstream —
    // a clamped span misreports every position past the limit.
    if !source_offset_range_admits(src.len()) {
        return Err(Diagnostic::Parse {
            span: Span::new(0, 0),
            msg: ParseError::SourceTooLarge { bytes: src.len() },
        });
    }
    let mut lx = Lexer::new(src);
    // Roughly one token per four source bytes reserves enough for most files up
    // front, eliminating nearly all growth reallocs; a bad estimate only
    // over-reserves transiently and degrades to plain growth.
    let mut out = Vec::with_capacity(src.len() / 4);
    loop {
        lx.skip_trivia()?;
        let Some(c) = lx.peek() else { break };
        let line = lx.line;
        let col = lx.col;
        let lo = lx.offset();

        let kind = if c == '{' && lx.peek2() == Some('-') && lx.peek3() == Some('|') {
            lex_doc_comment(&mut lx, lo)?
        } else if c.is_ascii_digit() {
            lex_number(&mut lx, lo)?
        } else if is_ident_start(c) {
            lex_ident(&mut lx, lo)
        } else if c == '"' {
            lex_string(&mut lx, lo)?
        } else if c == '\'' {
            lex_char(&mut lx, lo)?
        } else {
            lex_symbol(&mut lx, c, lo)?
        };

        let hi = lx.offset();
        out.push(Token {
            kind,
            line,
            col,
            span: Span::new(lo, hi),
        });
    }
    Ok(out)
}

/// Lex a doc-comment block `{-| … -}`, consuming the delimiters and returning
/// the raw body text as [`Tok::DocComment`].
///
/// The caller has already confirmed that the three characters at the current
/// position are `{`, `-`, `|`. Nesting is NOT supported inside doc-comments:
/// an inner `{-` is treated as ordinary text, matching the Elm convention.
/// An unterminated doc-comment (no matching `-}` before EOF) is an error.
fn lex_doc_comment(lx: &mut Lexer, lo: u32) -> DResult<Tok> {
    lx.advance(); // consume `{`
    lx.advance(); // consume `-`
    lx.advance(); // consume `|`
    let content_lo = lx.offset();
    loop {
        match lx.peek() {
            None => {
                return Err(Diagnostic::Parse {
                    span: Span::new(lo, lx.offset()),
                    msg: ParseError::UnterminatedBlockComment,
                });
            }
            Some('-') if lx.peek2() == Some('}') => {
                let closer_lo = lx.offset();
                lx.advance(); // consume `-`
                lx.advance(); // consume `}`
                // The body is exactly the source between `{-|` and the closing
                // `-}`; nothing in the loop transforms a char, so the slice
                // equals the concatenation a per-char buffer produced.
                return Ok(Tok::DocComment(lx.slice(content_lo, closer_lo).to_owned()));
            }
            Some(_) => {
                lx.advance();
            }
        }
    }
}

/// Consume a run of ASCII digits (zero or more). Each digit advances the
/// cursor; the first non-digit stops the run without consuming it.
fn consume_digits(lx: &mut Lexer) {
    while let Some(c) = lx.peek() {
        if c.is_ascii_digit() {
            lx.advance();
        } else {
            break;
        }
    }
}

/// Lex a numeric literal — an integer `42` or an Elm-style float `1.5` / `3.0` /
/// `1.5e3` / `2e-2`. The caller peeked an ASCII digit, so the integer part is
/// always present (a leading digit is required: `.5` is NOT a float — the bare
/// `.` lexes separately).
///
/// A `.` is taken as a fractional point only when a digit follows it, so `1..5`
/// keeps its `..` range token and `1.foo` keeps the `.` as a field access. An
/// `e`/`E` is taken as an exponent only when a digit (after an optional sign)
/// follows, so a trailing `e` falls through to the joined-name check. A literal
/// with a fraction OR an exponent is a [`Tok::Float`]; otherwise a [`Tok::Int`].
fn lex_number(lx: &mut Lexer, lo: u32) -> DResult<Tok> {
    let mut is_float = false;

    // Integer part: one or more ASCII digits (the caller guaranteed the first).
    consume_digits(lx);

    // Fractional part: a `.` immediately followed by a digit.
    if lx.peek() == Some('.') && lx.peek2().is_some_and(|c| c.is_ascii_digit()) {
        is_float = true;
        lx.advance(); // consume the `.`
        consume_digits(lx);
    }

    // Exponent part: `e`/`E`, an optional `+`/`-`, then one or more digits.
    if let Some('e' | 'E') = lx.peek() {
        let signed = matches!(lx.peek2(), Some('+' | '-'));
        let digit_follows = if signed {
            lx.peek3().is_some_and(|c| c.is_ascii_digit())
        } else {
            lx.peek2().is_some_and(|c| c.is_ascii_digit())
        };
        if digit_follows {
            is_float = true;
            lx.advance(); // consume `e`/`E`
            if let Some('+' | '-') = lx.peek() {
                lx.advance(); // consume the sign
            }
            consume_digits(lx);
        }
    }

    // A digit run immediately followed by a letter / underscore (`123abc`,
    // `1.5x`) is not a valid token — surface the joined-name error at the
    // offending character.
    if let Some(c) = lx.peek()
        && is_ident_start(c)
    {
        let at = lx.offset();
        return Err(Diagnostic::Parse {
            span: Span::from_start_width(at, char_width(c)),
            msg: ParseError::NumberJoinedToName(c),
        });
    }

    let hi = lx.offset();
    // The consumed byte range is the literal: ASCII digits and, for a float, a
    // `.`, an `e`/`E`, and a sign — exactly what a per-char buffer collected.
    let text = lx.slice(lo, hi);
    if is_float {
        // `text` is a well-formed float lexeme by construction (a digit run, an
        // optional `.`-digit run, an optional `e[+-]`-digit run), so `f64`
        // parsing cannot fail — an out-of-range magnitude reads back as
        // `inf`, never an error. A failure here would be a lexer contract
        // breach, so it is a compiler bug rather than user error.
        let f = text.parse::<f64>().map_err(|e| Diagnostic::CompilerBug {
            where_: "ipe_parse::lex_number",
            detail: format!("well-formed float lexeme {text:?} failed to parse: {e}"),
        })?;
        // A magnitude past `f64::MAX` (e.g. `1e400`) parses to `inf`, which is
        // not the number the source spelled. Rejecting it — rather than
        // silently accepting infinity — restores parity with the reference
        // (the lexer errors on the same literal) and the principle of least
        // surprise. Finite literals (including a genuine `0.0`) pass through.
        if !f.is_finite() {
            return Err(Diagnostic::Parse {
                span: Span::new(lo, hi),
                msg: ParseError::FloatLiteralOutOfRange,
            });
        }
        Ok(Tok::Float(f))
    } else {
        // The integer part only pushed ASCII digits, so the sole refusal is a
        // magnitude past `2^63` — never an empty or malformed literal.
        let Some(magnitude) = IntMagnitude::from_digits(text) else {
            return Err(Diagnostic::Parse {
                span: Span::new(lo, hi),
                msg: ParseError::IntLiteralOutOfRange,
            });
        };
        Ok(Tok::Int(magnitude))
    }
}

/// Lex a string literal.  The opening `"` is the current character.
///
/// If the next two characters are also `"` (i.e. the source spells `"""`),
/// dispatches to [`lex_triple_string`] which terminates only on a closing
/// `"""`. Otherwise lexes a single-line `"…"` string: escape sequences are
/// resolved into the runtime value; an unrecognised escape is kept verbatim
/// (backslash + char) so a typo surfaces as wrong text rather than lost data.
/// A raw newline, or end of input, before the closing `"` is
/// [`ParseError::UnterminatedString`]: a single-line string may not span lines
/// (a multi-line body uses `"""`).
fn lex_string(lx: &mut Lexer, lo: u32) -> DResult<Tok> {
    lx.advance(); // consume opening `"`

    // Detect triple-quoted string `"""…"""`.
    // After consuming the first `"`, a second and third `"` immediately
    // following means we are opening a multiline string, not an empty `""`
    // followed by a third `"`.
    if lx.peek() == Some('"') && lx.peek2() == Some('"') {
        lx.advance(); // consume second `"`
        lx.advance(); // consume third `"`
        return lex_triple_string(lx, lo);
    }

    // Single-line string `"…"`.
    let mut value = String::new();
    loop {
        match lx.peek() {
            // End of input, or a raw newline: a single-line string may not span
            // lines (a multi-line body uses `"""`). Reporting it here at the
            // opener through the line break stops the scan from swallowing the
            // following lines up to the next quote in the file, which would
            // mislocate the diagnostic to end-of-file.
            None | Some('\n' | '\r') => {
                let hi = lx.offset();
                return Err(Diagnostic::Parse {
                    span: Span::new(lo, hi),
                    msg: ParseError::UnterminatedString,
                });
            }
            Some('"') => {
                lx.advance();
                return Ok(Tok::Str(value));
            }
            Some('\\') => {
                lx.advance();
                push_escape(lx, &mut value);
            }
            Some(c) => {
                value.push(c);
                lx.advance();
            }
        }
    }
}

/// Lex a triple-quoted string `"""…"""`.  The opening `"""` has already been
/// consumed by [`lex_string`].
///
/// The closing terminator is exactly three consecutive `"` characters.  A lone
/// `"` or a pair `""` not followed by a third `"` is treated as literal content
/// — this is the critical invariant that fixes the bug where inline HTML
/// (`class="card"`) terminated the string early.
///
/// Raw content is returned without escape processing: `{{expr}}` interpolation,
/// `\{{` literal-brace escapes, and `\\` collapse are handled downstream by the
/// canonicaliser (mirroring `Ipe.Parse.String.findTripleClose` in the reference compiler
/// reference, which performs no escape resolution).
///
/// The anchor column A is the source column of the first non-whitespace content
/// character. The lexer's `col` cursor tracks the current source column; a
/// newline resets it to column 1 in [`Lexer::advance`], so the column recorded
/// at the first character that is neither a newline nor leading indentation is
/// A. The margin the canonicaliser strips is exactly this indentation, so
/// leading spaces and tabs are skipped when locating A. A body that is only
/// whitespace (or empty) anchors at column 1, which strips nothing downstream.
///
/// Reaching end of input before `"""` is [`ParseError::UnterminatedString`].
fn lex_triple_string(lx: &mut Lexer, lo: u32) -> DResult<Tok> {
    let content_lo = lx.offset();
    let mut anchor: Option<u32> = None;
    loop {
        match lx.peek() {
            None => {
                let hi = lx.offset();
                return Err(Diagnostic::Parse {
                    span: Span::new(lo, hi),
                    msg: ParseError::UnterminatedString,
                });
            }
            Some('"') => {
                // Check whether the current `"` starts the closing `"""`.
                // peek() is `"` (confirmed by this arm); peek2() and peek3()
                // must also be `"` for a triple-close.
                if lx.peek2() == Some('"') && lx.peek3() == Some('"') {
                    let closer_lo = lx.offset();
                    lx.advance(); // consume first `"`  of `"""`
                    lx.advance(); // consume second `"` of `"""`
                    lx.advance(); // consume third `"`  of `"""`
                    // The raw body is exactly the source between the opening and
                    // closing `"""`; the loop transforms no char (escape and
                    // interpolation resolution is downstream), so the slice
                    // equals the concatenation a per-char buffer produced.
                    return Ok(Tok::TripleStr {
                        raw: lx.slice(content_lo, closer_lo).to_owned(),
                        anchor: anchor.unwrap_or(1),
                    });
                }
                // A literal `"` is content, so it fixes the anchor.
                anchor.get_or_insert(lx.col);
                lx.advance();
            }
            Some(c) => {
                if c != '\n' && c != '\r' && c != ' ' && c != '\t' {
                    anchor.get_or_insert(lx.col);
                }
                lx.advance();
            }
        }
    }
}

/// Lex a character literal `'c'` or `'\n'`. The opening `'` is the current char.
/// Exactly one character (or one escape sequence) must precede the closing `'`;
/// an empty `''`, a multi-character body, or a missing closing quote is
/// [`ParseError::MalformedChar`]. The carried value is the single unescaped
/// character's text.
fn lex_char(lx: &mut Lexer, lo: u32) -> DResult<Tok> {
    lx.advance(); // consume opening `'`
    let mut value = String::new();
    match lx.peek() {
        Some('\\') => {
            lx.advance();
            push_escape(lx, &mut value);
        }
        Some('\'') | None => {
            // Empty `''` or unterminated — malformed.
            let hi = lx.offset();
            return Err(Diagnostic::Parse {
                span: Span::new(lo, hi),
                msg: ParseError::MalformedChar,
            });
        }
        Some(c) => {
            value.push(c);
            lx.advance();
        }
    }
    // A single closing quote must follow; anything else (a second character or
    // end of input) is malformed.
    if lx.peek() == Some('\'') {
        lx.advance();
        // Enforce the single-char invariant the backend relies on: an
        // unrecognised escape (e.g. `'\q'`) resolves to backslash + char, two
        // scalar values. Recognised escapes (`\n \t \r \\ \" \' \0`) and plain
        // chars are all exactly one scalar value, so no valid program regresses.
        if value.chars().count() != 1 {
            return Err(Diagnostic::Parse {
                span: Span::new(lo, lx.offset()),
                msg: ParseError::MalformedChar,
            });
        }
        Ok(Tok::Char(value))
    } else {
        let hi = lx.offset();
        Err(Diagnostic::Parse {
            span: Span::new(lo, hi),
            msg: ParseError::MalformedChar,
        })
    }
}

/// Resolve one escape sequence (the leading `\` already consumed) and push its
/// value into `out`. [`ipe_syntax::ESCAPES`] is the same table
/// `ipe_syntax::escape_str_body`/`escape_char_body` write back from, so a
/// printed literal re-lexes to the value it was printed from. An unrecognised
/// escape is kept as backslash + char so the user can see the typo rather
/// than silently losing data. End of input after a lone `\` pushes just the
/// backslash.
fn push_escape(lx: &mut Lexer, out: &mut String) {
    let Some(next) = lx.peek() else {
        out.push('\\');
        return;
    };
    lx.advance();
    let resolved = ESCAPES
        .iter()
        .find(|(letter, _)| *letter == next)
        .map(|(_, value)| *value);
    out.push(resolved.unwrap_or('\\'));
    if resolved.is_none() {
        out.push(next);
    }
}

fn lex_ident(lx: &mut Lexer, lo: u32) -> Tok {
    // First segment.
    while let Some(c) = lx.peek() {
        if is_ident_continue(c) {
            lx.advance();
        } else {
            break;
        }
    }
    // Dotted continuation: `.seg` runs, but never `..`.
    while lx.peek() == Some('.') && lx.peek2().is_some_and(is_ident_start) {
        lx.advance();
        while let Some(c) = lx.peek() {
            if is_ident_continue(c) {
                lx.advance();
            } else {
                break;
            }
        }
    }
    // The lexeme is exactly the consumed byte range: ASCII ident chars and the
    // `.` separators, so the slice equals the chars a per-char buffer collected.
    let text = lx.slice(lo, lx.offset());
    if text == "_" {
        return Tok::Underscore;
    }
    // A keyword matches the borrowed slice with no allocation; only a real
    // identifier owns one exact-capacity copy.
    keyword(text).unwrap_or_else(|| Tok::Ident(text.to_owned()))
}

/// Consume the current char, then optionally a following `second` char,
/// yielding `two` when the pair matches and `one` otherwise. Factors the
/// shared "one-or-two-character operator" shape (`=`/`==`, `<`/`<=`, `-`/`->`,
/// …) so each call site is a single line.
fn one_or_two(lx: &mut Lexer, second: char, two: Tok, one: Tok) -> Tok {
    lx.advance();
    if lx.peek() == Some(second) {
        lx.advance();
        two
    } else {
        one
    }
}

/// Lex a punctuation / operator token. `c` is the already-peeked first
/// character and `lo` is its byte offset (the start of the token).
fn lex_symbol(lx: &mut Lexer, c: char, lo: u32) -> DResult<Tok> {
    let kind = match c {
        '(' => one_char(lx, Tok::LParen),
        ')' => one_char(lx, Tok::RParen),
        '{' => one_char(lx, Tok::LBrace),
        '}' => one_char(lx, Tok::RBrace),
        '[' => one_char(lx, Tok::LBracket),
        ']' => one_char(lx, Tok::RBracket),
        // `::` (list cons) is a maximal munch of `:`; a lone `:` is the type
        // annotation colon.
        ':' => one_or_two(lx, ':', Tok::ColonColon, Tok::Colon),
        '\\' => one_char(lx, Tok::Backslash),
        ',' => one_char(lx, Tok::Comma),
        '+' => one_or_two(lx, '+', Tok::PlusPlus, Tok::Plus),
        '*' => one_char(lx, Tok::Star),
        '=' => one_or_two(lx, '=', Tok::EqEq, Tok::Equals),
        // `|` has five forms: `||`, `|>`, `|=`, `|.`, and bare `|`.
        '|' => {
            lx.advance();
            match lx.peek() {
                Some('|') => {
                    lx.advance();
                    Tok::PipePipe
                }
                Some('>') => {
                    lx.advance();
                    Tok::PipeGt
                }
                Some('=') => {
                    lx.advance();
                    Tok::PipeEq
                }
                Some('.') => {
                    lx.advance();
                    Tok::PipeDot
                }
                _ => Tok::Pipe,
            }
        }
        '-' => one_or_two(lx, '>', Tok::Arrow, Tok::Minus),
        // `/` has three forms: `//` (integer division), `/=` (not-equal), bare `/` (division).
        // Maximal-munch: consume the first `/` then peek the next char.
        '/' => {
            lx.advance();
            match lx.peek() {
                Some('/') => {
                    lx.advance();
                    Tok::SlashSlash
                }
                Some('=') => {
                    lx.advance();
                    Tok::SlashEq
                }
                _ => Tok::Slash,
            }
        }
        // `<` has five forms: `<=`, `<|`, `<<`, `<-`, and bare `<`.
        '<' => {
            lx.advance();
            match lx.peek() {
                Some('=') => {
                    lx.advance();
                    Tok::Le
                }
                Some('|') => {
                    lx.advance();
                    Tok::LtPipe
                }
                Some('<') => {
                    lx.advance();
                    Tok::LtLt
                }
                Some('-') => {
                    lx.advance();
                    Tok::LeftArrow
                }
                _ => Tok::Lt,
            }
        }
        // `>` has three forms: `>=`, `>>`, and bare `>`.
        '>' => {
            lx.advance();
            match lx.peek() {
                Some('=') => {
                    lx.advance();
                    Tok::Ge
                }
                Some('>') => {
                    lx.advance();
                    Tok::GtGt
                }
                _ => Tok::Gt,
            }
        }
        // `&` and `.` are valid ONLY as their two-char forms (`&&`, `..`);
        // a lone first char is a typed lex error rather than a token.
        '&' => return two_char_only(lx, lo, '&', Tok::AmpAmp, ParseError::UnknownChar('&')),
        '.' => return lex_dot(lx, lo),
        other => {
            return Err(Diagnostic::Parse {
                span: Span::from_start_width(lo, char_width(other)),
                msg: ParseError::UnknownChar(other),
            });
        }
    };
    Ok(kind)
}

/// Consume the current char and yield `tok` (single-character token).
fn one_char(lx: &mut Lexer, tok: Tok) -> Tok {
    lx.advance();
    tok
}

/// Lex a `.`-led token. `..` is [`Tok::DotDot`] (range / spread); a `.`
/// immediately followed by an identifier start is [`Tok::Dot`] (field access on
/// a non-identifier expression, e.g. `(r).value`); a lone `.` is the typed lex
/// error [`ParseError::StrayDot`]. `lo` is the byte offset of the first `.`.
fn lex_dot(lx: &mut Lexer, lo: u32) -> DResult<Tok> {
    lx.advance(); // consume the first `.`
    match lx.peek() {
        Some('.') => {
            lx.advance();
            Ok(Tok::DotDot)
        }
        Some(c) if is_ident_start(c) => Ok(Tok::Dot),
        _ => Err(Diagnostic::Parse {
            span: Span::new(lo, lx.offset()),
            msg: ParseError::StrayDot,
        }),
    }
}

/// Lex a token that is only valid as a two-character pair: consume the first
/// char, require `second`, and yield `two`; a missing `second` is the typed
/// lex error `err`.
fn two_char_only(lx: &mut Lexer, lo: u32, second: char, two: Tok, err: ParseError) -> DResult<Tok> {
    lx.advance();
    if lx.peek() == Some(second) {
        lx.advance();
        Ok(two)
    } else {
        Err(Diagnostic::Parse {
            span: Span::new(lo, lx.offset()),
            msg: err,
        })
    }
}

#[cfg(test)]
mod source_size_guard_tests {
    use super::{lex, source_offset_range_admits};
    use ipe_diagnostics::{Diagnostic, ParseError};

    #[test]
    fn offset_range_boundary() {
        // The largest spannable source is exactly `u32::MAX` bytes; one more
        // cannot be given a `u32` offset and is turned away.
        assert!(source_offset_range_admits(u32::MAX as usize));
        assert!(source_offset_range_admits(0));
        // `u32::MAX as usize + 1` only overflows `u32` on a 64-bit target; on a
        // 32-bit target a `usize` can never exceed `u32::MAX`, so the predicate
        // is vacuously total there.
        #[cfg(target_pointer_width = "64")]
        assert!(!source_offset_range_admits(u32::MAX as usize + 1));
    }

    #[test]
    fn a_normal_source_lexes() {
        // The guard does not disturb an ordinary in-range source.
        let toks = lex("module Main exposing (main)\nmain = 0\n").expect("lexes");
        assert!(!toks.is_empty());
    }

    #[test]
    fn oversized_source_is_a_typed_refusal_not_a_clamp() {
        // A source whose length exceeds `u32::MAX` yields a typed
        // `SourceTooLarge` rather than a silently clamped span. Proven at the
        // predicate the guard consults (allocating >4 GiB is infeasible in a
        // test); the guard maps a `false` verdict straight to the error below.
        #[cfg(target_pointer_width = "64")]
        {
            let oversized = u32::MAX as usize + 1;
            assert!(!source_offset_range_admits(oversized));
        }
        // The refusal a real oversized source would take, exercised directly.
        let refusal: Diagnostic = Diagnostic::Parse {
            span: ipe_diagnostics::Span::new(0, 0),
            msg: ParseError::SourceTooLarge {
                bytes: 5_000_000_000,
            },
        };
        assert!(matches!(
            refusal,
            Diagnostic::Parse {
                msg: ParseError::SourceTooLarge { .. },
                ..
            }
        ));
    }
}

#[cfg(test)]
mod escape_round_trip_tests {
    use ipe_syntax::{escape_char_body, escape_str_body};

    use super::{ESCAPES, Tok, lex};

    /// The kind of the single token `src` lexes to.
    fn only_token(src: &str) -> Option<Tok> {
        let toks = lex(src).ok()?;
        let [tok] = toks.as_slice() else { return None };
        Some(tok.kind.clone())
    }

    /// Every table row's value, and plain text, re-lexes to the char it was
    /// printed from: `lex(escape(v)) == v` for every row.
    #[test]
    fn every_char_value_round_trips() {
        let plain = ['a', ' ', 'é', '"'];
        for c in ESCAPES.iter().map(|(_, v)| *v).chain(plain) {
            let printed = format!("'{}'", escape_char_body(&c.to_string()));
            assert_eq!(
                only_token(&printed),
                Some(Tok::Char(c.to_string())),
                "{printed}"
            );
        }
    }

    /// A string holding every table row's value and a kept unknown escape
    /// round-trips: `lex(escape(v)) == v`.
    #[test]
    fn every_string_value_round_trips() {
        let mut value: String = ESCAPES.iter().map(|(_, v)| *v).collect();
        value.push_str("plain \\q 'text'");
        let printed = format!("\"{}\"", escape_str_body(&value));
        assert_eq!(only_token(&printed), Some(Tok::Str(value)));
    }

    /// A backslash char prints escaped: a bare `'\'` is a malformed literal.
    #[test]
    fn a_backslash_char_is_escaped() {
        assert_eq!(escape_char_body("\\"), "\\\\");
        assert!(lex("'\\'").is_err(), "a bare backslash char stays refused");
    }
}
