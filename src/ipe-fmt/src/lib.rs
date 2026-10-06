//! The Ipê source formatter engine.
//!
//! Parses a `.ipe` source string into an [`ipe_syntax::Module`] via
//! [`ipe_parse::parse_module`] and pretty-prints it in canonical (elm-format
//! style) form. The single public entry point is [`format_source`]; the CLI
//! `ipe fmt` command and the LSP formatting provider both drive it, so one
//! engine — comment-preserving and semantics-guarded — serves both.
//!
//! The engine is path-agnostic: it works on a bare source string and reports a
//! typed [`FmtError`]. A caller that knows the file (the CLI) attaches the path
//! at its own boundary.

use std::cell::Cell;
use std::fmt;
use std::fmt::Write as _;

use ipe_diagnostics::{Diagnostic, Located, TokenKind, render};
use ipe_intern::Interner;
use ipe_parse::TokenClass;
use ipe_syntax::{
    Ctor, Exposed, Exposing, Expr, Expr_, ForeignDecl, Import, LetBinding, Module, Pattern,
    Pattern_, Privacy, TypeAlias, TypeAnnotation, Union, Value, escape_char_body, escape_str_body,
    strip_anchor_margin,
};

/// The column budget elm-format targets before breaking a construct onto
/// multiple lines.
const MAX_WIDTH: usize = 80;

/// A formatter-level error.
///
/// Path-agnostic: the engine operates on a source string and never sees a file
/// path. A caller that knows the file (the CLI) renders these with the real
/// path; [`RoundTrip`](Self::RoundTrip) also models the `--check` "unformatted"
/// outcome the CLI surfaces.
#[derive(Debug)]
pub enum FmtError {
    /// The source could not be parsed — formatting a syntactically invalid file
    /// would risk changing its meaning, so the formatter refuses.
    Parse { src: String, diag: Diagnostic },
    /// The formatter's own output failed to re-parse or did not round-trip to
    /// the same AST — a formatter bug, surfaced rather than written to disk.
    RoundTrip { detail: String },
    /// The formatted output would pass a ceiling; nothing is returned, so the
    /// caller leaves the file as it was.
    Limit(FmtLimit),
}

/// A ceiling the formatter refuses to pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FmtLimit {
    /// The formatted output would be longer than `cap`.
    OutputBytes { cap: OutputCap },
}

/// The most bytes of formatted output one source may produce.
///
/// Eight times the input, never under 64 KiB and never over 16 MiB: real
/// code formats to about its own size, while a crafted input whose layout
/// multiplies its size (a long flat list at deep indent) is turned back
/// before its output is written anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutputCap(usize);

impl OutputCap {
    /// The output a small input may always produce.
    pub const FLOOR: usize = 64 << 10;
    /// The output no input may pass.
    pub const CEILING: usize = 16 << 20;
    /// How many output bytes one input byte may become.
    pub const GROWTH: usize = 8;

    /// The cap for a source of `input_len` bytes.
    #[must_use]
    pub const fn for_input(input_len: usize) -> Self {
        let grown = input_len.saturating_mul(Self::GROWTH);
        let floored = if grown < Self::FLOOR {
            Self::FLOOR
        } else {
            grown
        };
        Self(if floored > Self::CEILING {
            Self::CEILING
        } else {
            floored
        })
    }

    /// The cap in bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.0
    }

    /// Whether `output` fits under the cap.
    #[must_use]
    pub const fn admits(self, output: &str) -> bool {
        output.len() <= self.0
    }
}

impl fmt::Display for OutputCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for FmtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse { src, diag } => f.write_str(&render(diag, "<source>", src)),
            Self::RoundTrip { detail } => {
                write!(f, "ipe fmt: internal error while formatting: {detail}")
            }
            Self::Limit(FmtLimit::OutputBytes { cap }) => {
                write!(f, "ipe fmt: formatted output would exceed {cap} bytes")
            }
        }
    }
}
// ---------------------------------------------------------------------------
// Comment scanning
// ---------------------------------------------------------------------------

/// A source comment recovered by [`scan_trivia`].
#[derive(Clone, Debug, PartialEq, Eq)]
struct Comment {
    /// The comment text VERBATIM (including the `--` / `{- -}` / `{-| -}`
    /// delimiters, with no trailing whitespace). A line comment keeps any
    /// interior spacing; a block comment keeps its full multi-line body.
    text: String,
    /// The offset of the comment's first byte in its source.
    start: usize,
    /// Where the comment attaches: the start offset of the first token after
    /// it that can begin a printed node, or `None` past the last token.
    ///
    /// Every print site claims the comments anchored at the first token of the
    /// node it prints, so placement is a pure function of position: a comment
    /// belongs to the node it precedes, and re-rendering a node never loses or
    /// repeats one.
    anchor: Option<usize>,
}

/// A matched `(` … `)` group: its first inner token and its `)`.
#[derive(Clone, Copy, Debug)]
struct ParenGroup {
    /// The offset of the first token after the group's leading `(` run.
    inner: usize,
    /// The offset of the closing `)`.
    close: usize,
}

/// A code token: a token of the program, doc comments excluded.
#[derive(Clone, Copy, Debug)]
struct CodeToken {
    lo: usize,
    hi: usize,
    kind: TokenKind,
}

/// The comments and code tokens of a source.
struct Trivia {
    comments: Vec<Comment>,
    code: Vec<CodeToken>,
}

/// Recover every comment in `src`, in source order, with the code tokens it
/// is anchored against; `None` when `src` does not lex.
///
/// The lexer is the single source of truth for what is a comment: the bytes
/// between its tokens are trivia (whitespace, `--` line comments, nestable
/// `{- -}` block comments), and a `{-| -}` doc comment is a token of its own.
/// So a `--` inside a string or char literal is never mistaken for a comment.
fn scan_trivia(src: &str) -> Option<Trivia> {
    let tokens = ipe_parse::try_source_tokens(src)?;
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut code: Vec<CodeToken> = Vec::with_capacity(tokens.len());
    let mut cursor = 0usize;
    for t in &tokens {
        let (lo, hi) = (t.span.lo as usize, t.span.hi as usize);
        trivia_comments(src, cursor, lo, &mut ranges);
        match t.class {
            TokenClass::DocComment => ranges.push((lo, hi)),
            TokenClass::Code(kind) => code.push(CodeToken { lo, hi, kind }),
        }
        cursor = hi;
    }
    trivia_comments(src, cursor, src.len(), &mut ranges);
    let comments = ranges
        .into_iter()
        .map(|(lo, hi)| Comment {
            text: src.get(lo..hi).unwrap_or_default().trim_end().to_owned(),
            start: lo,
            anchor: anchor_after(&code, hi),
        })
        .collect();
    Some(Trivia { comments, code })
}

/// Push the byte range of every comment in the trivia gap `src[from..to]`.
///
/// The gap holds only whitespace and comments (the lexer produced no token in
/// it), so no literal can hide a comment marker here.
fn trivia_comments(src: &str, from: usize, to: usize, out: &mut Vec<(usize, usize)>) {
    let Some(gap) = src.get(from..to) else {
        return;
    };
    let bytes = gap.as_bytes();
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        let next = bytes.get(i + 1).copied();
        if b == b'-' && next == Some(b'-') {
            let end = gap
                .get(i..)
                .and_then(|rest| rest.find('\n'))
                .map_or(bytes.len(), |n| i + n);
            out.push((from + i, from + end));
            i = end;
        } else if b == b'{' && next == Some(b'-') {
            let end = block_comment_end(bytes, i);
            out.push((from + i, from + end));
            i = end;
        } else {
            i += 1;
        }
    }
}

/// The offset just past the nestable `{- … -}` comment opening at `start`.
fn block_comment_end(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0u32;
    let mut i = start;
    while let Some(&b) = bytes.get(i) {
        let next = bytes.get(i + 1).copied();
        if b == b'{' && next == Some(b'-') {
            depth = depth.saturating_add(1);
            i += 2;
        } else if b == b'-' && next == Some(b'}') {
            depth = depth.saturating_sub(1);
            i += 2;
            if depth == 0 {
                return i;
            }
        } else {
            i += 1;
        }
    }
    bytes.len()
}

/// The anchor of a comment ending at `pos`: the first code token after it that
/// can begin a printed node.
///
/// A token that only continues the construct around it — a separator, an
/// operator, a keyword like `in` / `then` / `else` / `of` — is passed over, so
/// a comment above `|> f` or `, b` attaches to `f` / `b`. Every other token
/// stops the search, closing brackets included: a comment never crosses out of
/// the construct it was written in.
fn anchor_after(code: &[CodeToken], pos: usize) -> Option<usize> {
    let mut i = code.partition_point(|t| t.lo < pos);
    while let Some(t) = code.get(i) {
        let flush_next = code.get(i + 1).is_some_and(|n| n.lo == t.hi);
        if !continues_construct(t.kind, flush_next) {
            return Some(t.lo);
        }
        i += 1;
    }
    None
}

/// Whether a token of `kind` only continues the construct around it, so a
/// comment before it belongs to the node after it.
///
/// `flush_next` says the next token touches this one: a `-` flush against its
/// operand begins a negation, a node of its own.
const fn continues_construct(kind: TokenKind, flush_next: bool) -> bool {
    match kind {
        TokenKind::Minus => !flush_next,
        TokenKind::In
        | TokenKind::Then
        | TokenKind::Else
        | TokenKind::Of
        | TokenKind::Equals
        | TokenKind::Pipe
        | TokenKind::Colon
        | TokenKind::Arrow
        | TokenKind::LeftArrow
        | TokenKind::Comma
        | TokenKind::ColonColon
        | TokenKind::Plus
        | TokenKind::PlusPlus
        | TokenKind::Star
        | TokenKind::Slash
        | TokenKind::SlashEq
        | TokenKind::SlashSlash
        | TokenKind::EqEq
        | TokenKind::Lt
        | TokenKind::Gt
        | TokenKind::Le
        | TokenKind::Ge
        | TokenKind::AmpAmp
        | TokenKind::PipePipe
        | TokenKind::PipeGt
        | TokenKind::LtPipe
        | TokenKind::PipeEq
        | TokenKind::PipeDot
        | TokenKind::GtGt
        | TokenKind::LtLt => true,
        TokenKind::Module
        | TokenKind::Import
        | TokenKind::Exposing
        | TokenKind::As
        | TokenKind::Type
        | TokenKind::Foreign
        | TokenKind::Case
        | TokenKind::Let
        | TokenKind::If
        | TokenKind::Do
        | TokenKind::LParen
        | TokenKind::RParen
        | TokenKind::LBrace
        | TokenKind::RBrace
        | TokenKind::LBracket
        | TokenKind::RBracket
        | TokenKind::Backslash
        | TokenKind::DotDot
        | TokenKind::Dot
        | TokenKind::Underscore
        | TokenKind::Ident
        | TokenKind::Int
        | TokenKind::Float
        | TokenKind::Str
        | TokenKind::Char
        | TokenKind::Eof => false,
    }
}

/// The comment texts, sorted: the multiset the comment guard compares.
fn comment_multiset(comments: &[Comment]) -> Vec<&str> {
    let mut texts: Vec<&str> = comments.iter().map(|c| c.text.as_str()).collect();
    texts.sort_unstable();
    texts
}

/// Strip a leading run of `(`, whitespace, and comments (line or nestable
/// block) from `text`, mirroring the lexer's `skip_trivia` shapes.
///
/// Used to look past a `do` block's opening parens for its keyword even when
/// a comment sits between them — the same trivia a comment-free `(  do …)`
/// already tolerates via whitespace alone.
fn skip_paren_trivia(mut text: &str) -> &str {
    loop {
        let stripped = text.trim_start_matches(|c: char| c == '(' || c.is_whitespace());
        if let Some(rest) = stripped.strip_prefix("--") {
            let line_end = rest.find('\n').map_or(rest.len(), |i| i + 1);
            text = rest.get(line_end..).unwrap_or_default();
            continue;
        }
        if let Some(rest) = stripped.strip_prefix("{-") {
            text = skip_block_comment_body(rest);
            continue;
        }
        return stripped;
    }
}

/// Skip a nestable block comment's body, already past its opening `{-`, and
/// return what follows the matching `-}` (or the input's end, if unterminated
/// — malformed input the parser will itself refuse, so any position is safe).
fn skip_block_comment_body(mut rest: &str) -> &str {
    let mut depth = 1u32;
    while depth > 0 {
        if let Some(after) = rest.strip_prefix("{-") {
            depth += 1;
            rest = after;
        } else if let Some(after) = rest.strip_prefix("-}") {
            depth -= 1;
            rest = after;
        } else {
            let mut chars = rest.chars();
            if chars.next().is_none() {
                break;
            }
            rest = chars.as_str();
        }
    }
    rest
}

// ---------------------------------------------------------------------------
// The formatter entry point
// ---------------------------------------------------------------------------

/// Format one `.ipe` source string into canonical style.
///
/// # Errors
/// [`FmtError::Parse`] if `src` does not parse; [`FmtError::RoundTrip`] if the
/// formatted output loses, adds or alters a comment, or does not re-parse to
/// the same AST (a formatter bug — caught rather than written);
/// [`FmtError::Limit`] if the output would pass [`OutputCap::for_input`].
pub fn format_source(src: &str) -> Result<String, FmtError> {
    format_guarded(src, OutputCap::for_input(src.len()), render_module)
}

/// [`format_source`] under an explicit `cap`, so a test drives the refusal
/// with a small input.
#[cfg(test)]
fn format_source_capped(src: &str, cap: OutputCap) -> Result<String, FmtError> {
    format_guarded(src, cap, render_module)
}

/// The printer's rendering of a whole module: what [`format_source`] writes.
fn render_module(printer: &Printer<'_>, module: &Module) -> String {
    printer.module(module)
}

/// Print `src` with `render`, then refuse the output unless it fits `cap`,
/// carries the input's comments and re-parses to the input's AST.
///
/// [`format_source`] renders with [`Printer::module`]; a test passes a faulty
/// renderer to drive each refusal through the same guards.
fn format_guarded(
    src: &str,
    cap: OutputCap,
    render: impl FnOnce(&Printer<'_>, &Module) -> String,
) -> Result<String, FmtError> {
    let mut interner = Interner::new();
    let module = ipe_parse::parse_module(src, &mut interner).map_err(|diag| FmtError::Parse {
        src: src.to_owned(),
        diag,
    })?;
    let input = scan_trivia(src).ok_or_else(|| FmtError::RoundTrip {
        detail: "source parsed but did not lex".to_owned(),
    })?;
    let printer = Printer::new(&interner, &input, Some(src), cap);
    let out = render(&printer, &module);

    // Output guard: the formatted text fits the cap, and no pad was refused
    // its bytes on the way (a refused pad rendered empty, so the text alone
    // under-counts). It fires first so an over-cap output is never lexed,
    // re-parsed or returned.
    if printer.pads.exceeded() || !cap.admits(&out) {
        return Err(FmtError::Limit(FmtLimit::OutputBytes { cap }));
    }

    // Comment guard: the formatted output carries exactly the input's comments.
    // It fires BEFORE the AST equivalence check so a comment bug surfaces as a
    // clear comment message rather than an AST mismatch.
    let output = scan_trivia(&out).ok_or_else(|| FmtError::RoundTrip {
        detail: "formatted output did not lex".to_owned(),
    })?;
    let input_count = input.comments.len();
    let output_count = output.comments.len();
    if output_count < input_count {
        return Err(FmtError::RoundTrip {
            detail: format!(
                "formatter dropped comments: input had {input_count}, output has {output_count}"
            ),
        });
    }
    if comment_multiset(&input.comments) != comment_multiset(&output.comments) {
        return Err(FmtError::RoundTrip {
            detail: format!(
                "formatter changed comments: input had {input_count}, output has {output_count}"
            ),
        });
    }

    // Semantics guard: the formatted output must re-parse to the same AST.
    let mut verify_interner = Interner::new();
    match ipe_parse::parse_module(&out, &mut verify_interner) {
        Ok(reparsed) => {
            if !modules_equivalent(&module, &interner, &reparsed, &verify_interner, cap)? {
                return Err(FmtError::RoundTrip {
                    detail: "formatted output parsed to a different AST".to_owned(),
                });
            }
        }
        Err(diag) => {
            return Err(FmtError::RoundTrip {
                detail: format!("formatted output did not re-parse: {diag:?}"),
            });
        }
    }
    Ok(out)
}

/// Format `src` WITHOUT the round-trip guards. Test-only: lets a test
/// inspect the raw printer output even when a guard would reject it, so a
/// divergence can be localised rather than hidden behind a compiler-bug error.
#[cfg(test)]
pub(crate) fn format_source_unchecked(src: &str) -> Result<String, FmtError> {
    let mut interner = Interner::new();
    let module = ipe_parse::parse_module(src, &mut interner).map_err(|diag| FmtError::Parse {
        src: src.to_owned(),
        diag,
    })?;
    let input = scan_trivia(src).ok_or_else(|| FmtError::RoundTrip {
        detail: "source parsed but did not lex".to_owned(),
    })?;
    Ok(Printer::new(
        &interner,
        &input,
        Some(src),
        OutputCap::for_input(src.len()),
    )
    .module(&module))
}

#[cfg(test)]
thread_local! {
    /// A work counter for render calls, used by tests only.
    ///
    /// Counts [`Printer::expr`] / [`Printer::expr_atom`] calls since the
    /// last [`reset_render_call_count`] — standing in for wall-clock time,
    /// so a bounded-work regression test cannot flake on a slow or loaded
    /// machine. Every node is rendered through one of those two entry
    /// points, so this count is the total number of node renders: linear
    /// growth in input size is the class-closing property (`PRINCIPLES.md`,
    /// "bounded by construction"), and an exponential regression shows up
    /// here as an exponential count, not merely a slow wall clock.
    static RENDER_CALLS: Cell<u64> = const { Cell::new(0) };
}

#[cfg(test)]
fn count_render_call() {
    RENDER_CALLS.with(|c| c.set(c.get() + 1));
}

#[cfg(test)]
fn reset_render_call_count() {
    RENDER_CALLS.with(|c| c.set(0));
}

#[cfg(test)]
fn render_call_count() -> u64 {
    RENDER_CALLS.with(Cell::get)
}

/// Compare two modules parsed with (possibly different) interners for
/// structural equivalence, resolving symbols to their strings so that a
/// different interning ORDER between the two parses does not read as a
/// difference. Spans are ignored throughout.
///
/// Two independent projections must agree: the printer's canonical text, and
/// the [`ModuleTree`] of every AST field. The printer reads a node only as far
/// as it prints it, so a field it does not print can differ under an equal
/// canonical text; the tree compares every field. A triple-quoted string's
/// value depends on its column: the canonical text prints that value, so a
/// formatter that moves the string to another margin is refused rather than
/// changing what the program means.
///
/// # Errors
/// [`FmtError::Limit`] when either canonical text would pass `cap`: the
/// projection is a print like any other and is charged the same ceiling.
fn modules_equivalent(
    a: &Module,
    ai: &Interner,
    b: &Module,
    bi: &Interner,
    cap: OutputCap,
) -> Result<bool, FmtError> {
    Ok(ModuleText::of(a, ai, cap)? == ModuleText::of(b, bi, cap)?
        && ModuleTree::of(a, ai).is_some_and(|tree| ModuleTree::of(b, bi) == Some(tree)))
}

/// Every field of a module's AST, with byte positions erased and symbols
/// resolved to their text, imports sorted (the formatter sorts them).
///
/// Built from the derived `Debug` form, so a field added to the AST is compared
/// without a change here. Positions are erased because formatting moves every
/// node.
#[derive(PartialEq, Debug)]
struct ModuleTree(Vec<String>);

impl ModuleTree {
    /// `None` when the `Debug` form holds a shape this projection does not
    /// recognise; [`modules_equivalent`] then treats the modules as different.
    fn of(m: &Module, i: &Interner) -> Option<Self> {
        // Destructured with no `..`: a new module field is a build error here
        // until it is compared.
        let Module {
            module_kw: _,
            name,
            exposing,
            imports,
            values,
            unions,
            aliases,
            foreigns,
        } = m;
        let mut sorted_imports = imports
            .iter()
            .map(|imp| erase_positions(&format!("{imp:?}"), i))
            .collect::<Option<Vec<String>>>()?;
        sorted_imports.sort_unstable();
        let mut parts = vec![
            erase_positions(&format!("{name:?}"), i)?,
            erase_positions(&format!("{exposing:?}"), i)?,
        ];
        parts.extend(sorted_imports);
        parts.push(erase_positions(&format!("{values:?}"), i)?);
        parts.push(erase_positions(&format!("{unions:?}"), i)?);
        parts.push(erase_positions(&format!("{aliases:?}"), i)?);
        parts.push(erase_positions(&format!("{foreigns:?}"), i)?);
        Some(Self(parts))
    }
}

/// `debug` with every `Span { lo: …, hi: … }` and triple-quoted string
/// `anchor: …` column replaced by `_`, and every `Symbol(n)` by
/// `Symbol("text")`, leaving the contents of string literals untouched; `None`
/// on a shape the rewrite does not recognise.
///
/// The anchor is a position: what it means, the margin stripped from the
/// string's value, is compared by [`ModuleText`], which prints that value.
fn erase_positions(debug: &str, interner: &Interner) -> Option<String> {
    let mut out = String::with_capacity(debug.len());
    let mut rest = debug;
    while let Some(c) = rest.chars().next() {
        if c == '"' {
            let (literal, after) = rest.split_at_checked(debug_string_len(rest)?)?;
            out.push_str(literal);
            rest = after;
        } else if let Some(after) = rest.strip_prefix("Span { lo: ") {
            let (_, after) = split_digits(after)?;
            let (_, after) = split_digits(after.strip_prefix(", hi: ")?)?;
            out.push('_');
            rest = after.strip_prefix(" }")?;
        } else if let Some(after) = rest.strip_prefix("anchor: ") {
            let (_, after) = split_digits(after)?;
            out.push_str("anchor: _");
            rest = after;
        } else if let Some(after) = rest.strip_prefix("Symbol(") {
            let (digits, after) = split_digits(after)?;
            let text = interner.resolve(ipe_intern::Symbol::from_raw(digits.parse().ok()?))?;
            let _ = write!(out, "Symbol({text:?})");
            rest = after.strip_prefix(')')?;
        } else {
            out.push(c);
            rest = rest.get(c.len_utf8()..)?;
        }
    }
    Some(out)
}

/// The byte length of the `Debug` string literal opening `s`, quotes included.
fn debug_string_len(s: &str) -> Option<usize> {
    let mut chars = s.char_indices().skip(1);
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                chars.next()?;
            }
            '"' => return Some(i + 1),
            _ => {}
        }
    }
    None
}

/// The leading run of ASCII digits of `s` (at least one) and what follows it.
fn split_digits(s: &str) -> Option<(&str, &str)> {
    let n = s.bytes().take_while(u8::is_ascii_digit).count();
    if n == 0 {
        return None;
    }
    s.split_at_checked(n)
}

/// A fully symbol-resolved, span-free projection of a module, used only for the
/// round-trip equivalence check. Deriving `PartialEq`/`Eq` on this gives a
/// structural comparison that is immune to interning-order and span drift.
#[derive(PartialEq, Debug)]
struct ModuleText(String);

impl ModuleText {
    fn of(m: &Module, i: &Interner, cap: OutputCap) -> Result<Self, FmtError> {
        // Reuse the printer with NO trivia: the projection is a canonical string
        // form, and two ASTs are equivalent iff their comment-free canonical
        // forms are byte-identical. (Comments are checked separately by the
        // comment guard, not by this one.)
        let none = Trivia {
            comments: Vec::new(),
            code: Vec::new(),
        };
        let printer = Printer::new(i, &none, None, cap);
        let text = printer.module(m);
        if printer.pads.exceeded() || !cap.admits(&text) {
            return Err(FmtError::Limit(FmtLimit::OutputBytes { cap }));
        }
        Ok(Self(text))
    }
}

// ---------------------------------------------------------------------------
// The printer
// ---------------------------------------------------------------------------

struct Printer<'a> {
    interner: &'a Interner,
    /// The source's comments, in source order (so sorted by anchor).
    comments: &'a [Comment],
    /// The source's code tokens, in source order.
    code: &'a [CodeToken],
    /// The original source text, used to recover elm-format's MODAL layout
    /// decision: a list / record / tuple / union that spanned more than one
    /// line in the source stays multi-line even when it would fit, and one that
    /// was single-line stays single-line when it fits. `None` in the round-trip
    /// equivalence guard, where a purely width-driven canonical form is wanted
    /// (the guard compares STRUCTURE, so it must not depend on original layout).
    src: Option<&'a str>,
    /// The anchors whose comments the node being printed has already claimed:
    /// its first token's offset and the last offset of the claimed run.
    ///
    /// A node and its first child begin at the same token (`f x` and `f`), so
    /// the outermost node at an anchor prints its comments and every nested
    /// node starting there prints none. A parenthesised group also claims the
    /// tokens up to its first inner one (`(` `(` `f`), where no node of its own
    /// may start. Set and restored around each render, so rendering is pure: a
    /// trial render (to measure a layout) never consumes a comment its final
    /// render then lacks.
    claimed: Cell<Option<(usize, usize)>>,
    /// The body offset of the lambda whose parameter comments the node being
    /// printed has already claimed.
    ///
    /// Set and restored around each render, like `claimed`, so the outermost
    /// claim of a lambda takes those comments once.
    lambda_head: Cell<Option<usize>>,
    /// The indentation this print may still emit; every pad renders through it.
    pads: PadBudget,
}

impl<'a> Printer<'a> {
    const fn new(
        interner: &'a Interner,
        trivia: &'a Trivia,
        src: Option<&'a str>,
        cap: OutputCap,
    ) -> Self {
        Self {
            interner,
            comments: trivia.comments.as_slice(),
            code: trivia.code.as_slice(),
            src,
            claimed: Cell::new(None),
            lambda_head: Cell::new(None),
            pads: PadBudget::new(cap),
        }
    }

    /// Four spaces per indent level, charged to this print's budget.
    const fn pad(&self, indent: usize) -> Pad<'_> {
        self.pads.pad(indent)
    }

    /// The indentation of the leading-comma continuation lines inside a
    /// multiline record / list / tuple.
    ///
    /// elm-format aligns the `,` with the opening bracket, which sits at the
    /// construct's own indent.
    const fn pad_in(&self, indent: usize) -> Pad<'_> {
        self.pads.pad(indent)
    }

    fn sym(&self, s: ipe_intern::Symbol) -> String {
        self.interner.resolve(s).unwrap_or("?").to_owned()
    }

    /// Whether the node at `span` occupied more than one line in the original
    /// source — elm-format's modal multi-line trigger. Always `false` when no
    /// source is threaded (the equivalence guard's width-only mode).
    fn was_multiline(&self, span: ipe_diagnostics::Span) -> bool {
        let Some(src) = self.src else { return false };
        let lo = span.lo as usize;
        let hi = (span.hi as usize).min(src.len());
        if lo >= hi {
            return false;
        }
        src.get(lo..hi).is_some_and(has_layout_newline)
    }

    fn dotted(&self, segs: &[ipe_intern::Symbol]) -> String {
        segs.iter()
            .map(|s| self.sym(*s))
            .collect::<Vec<_>>()
            .join(".")
    }

    // -- Comment placement ---------------------------------------------------

    /// The comments anchored at a token starting in the byte range `[lo, hi)`.
    fn anchored_in(&self, lo: usize, hi: usize) -> &'a [Comment] {
        let key = |c: &Comment| c.anchor.unwrap_or(usize::MAX);
        let first = self.comments.partition_point(|c| key(c) < lo);
        let end = self.comments.partition_point(|c| key(c) < hi);
        self.comments.get(first..end.max(first)).unwrap_or_default()
    }

    /// The comments anchored at the token starting at byte `pos`.
    fn anchored(&self, pos: usize) -> &'a [Comment] {
        self.anchored_in(pos, pos.saturating_add(1))
    }

    /// The comments after the last token of the file.
    fn trailing(&self) -> &'a [Comment] {
        let first = self.comments.partition_point(|c| c.anchor.is_some());
        self.comments.get(first..).unwrap_or_default()
    }

    /// The last code token that starts before byte `pos`.
    fn token_before(&self, pos: usize) -> Option<CodeToken> {
        let i = self.code.partition_point(|t| t.lo < pos);
        i.checked_sub(1).and_then(|j| self.code.get(j)).copied()
    }

    /// The comments anchored at the closing bracket that ends `span`.
    fn closing_comments(&self, span: ipe_diagnostics::Span) -> &'a [Comment] {
        let i = self.code.partition_point(|t| t.hi < span.hi as usize);
        match self.code.get(i) {
            Some(t)
                if t.hi == span.hi as usize
                    && matches!(
                        t.kind,
                        TokenKind::RBracket | TokenKind::RBrace | TokenKind::RParen
                    ) =>
            {
                self.anchored(t.lo)
            }
            _ => &[],
        }
    }

    /// The `(` … `)` group spanning exactly `[lo, hi)`, or `None` when the `(`
    /// at `lo` does not match the `)` ending at `hi`.
    ///
    /// Parentheses are not in the tree, so no node starts at a `)`, nor at a
    /// `(` inside the group's leading run: the group node, which the parser
    /// stamps with the parentheses' span, owns the comments anchored there.
    fn paren_group(&self, lo: usize, hi: usize) -> Option<ParenGroup> {
        let first = self.code.partition_point(|t| t.lo < lo);
        let last = self.code.partition_point(|t| t.hi < hi);
        let group = self.code.get(first..=last)?;
        let (open, close) = (group.first()?, group.last()?);
        let shaped = open.lo == lo
            && close.hi == hi
            && matches!(open.kind, TokenKind::LParen)
            && matches!(close.kind, TokenKind::RParen);
        if !shaped {
            return None;
        }
        // The `(` matches this `)` only if the depth first returns to zero at it.
        let mut depth = 0usize;
        for (offset, t) in group.iter().enumerate() {
            match t.kind {
                TokenKind::LParen => depth = depth.saturating_add(1),
                TokenKind::RParen => depth = depth.saturating_sub(1),
                _ => {}
            }
            if depth == 0 {
                if offset + 1 != group.len() {
                    return None;
                }
                let inner = group
                    .iter()
                    .find(|t| !matches!(t.kind, TokenKind::LParen))?;
                return Some(ParenGroup {
                    inner: inner.lo,
                    close: close.lo,
                });
            }
        }
        None
    }

    /// Whether an enclosing node already claimed the comments anchored at `pos`.
    fn is_claimed(&self, pos: usize) -> bool {
        self.claimed
            .get()
            .is_some_and(|(start, end)| start <= pos && pos <= end)
    }

    /// The span end that makes `e` own a closing parenthesis's comments: any
    /// node but a tuple or unit, which print their own `)`.
    const fn closer_of(e: &Expr) -> Option<usize> {
        match e.value {
            Expr_::Tuple(_) | Expr_::Unit => None,
            _ => Some(e.span.hi as usize),
        }
    }

    /// Render the node whose first token starts at `lo`, returning its
    /// comments for the caller to place, plus the rendering.
    ///
    /// A node's comments are those anchored at its first token and, when
    /// `closer` gives the end of a parenthesised group, those above its `)`.
    /// Inside `render`, every nested node starting at `lo` prints no comments:
    /// they are this claim's. When an enclosing node already claimed `lo`, the
    /// comment list is empty.
    fn claim<T>(
        &self,
        lo: usize,
        closer: Option<usize>,
        render: impl FnOnce() -> T,
    ) -> (Comments<'a>, T) {
        let outer = self.claimed.get();
        let group = closer.and_then(|hi| self.paren_group(lo, hi));
        // The run this node claims: its first token, through the group's first
        // inner token when it is a parenthesised group.
        let end = group.map_or(lo, |g| g.inner.max(lo));
        let inside = self.is_claimed(lo);
        let leading: &[Comment] = if inside {
            &[]
        } else {
            self.anchored_in(lo, end.saturating_add(1))
        };
        // The same node claimed twice (`expr` then `expr_atom`) owns its `)`
        // once; a nested group inside a claimed run still owns its own `)`.
        let closing: &[Comment] = match group {
            Some(g) if outer.map(|(start, _)| start) != Some(lo) => self.anchored(g.close),
            _ => &[],
        };
        let comments = leading.iter().chain(closing).collect();
        let run_end = match outer {
            Some((_, outer_end)) if inside => outer_end.max(end),
            _ => end,
        };
        self.claimed.set(Some((lo, run_end)));
        let rendered = render();
        self.claimed.set(outer);
        (comments, rendered)
    }

    /// [`Self::claim`] for the expression `e`, which also owns the comments
    /// among a lambda's parameters.
    ///
    /// Those print above the lambda, with the comments at its first token: a
    /// second pass reads them there as the lambda's leading comments, so the
    /// layout is a fixed point. The outermost claim of a lambda takes them.
    fn claim_expr<T>(&self, e: &Expr, render: impl FnOnce() -> T) -> (Comments<'a>, T) {
        let outer = self.lambda_head.get();
        let head = lambda_head(e).filter(|&(_, hi)| outer != Some(hi));
        if let Some((_, hi)) = head {
            self.lambda_head.set(Some(hi));
        }
        let (mut comments, rendered) = self.claim(e.span.lo as usize, Self::closer_of(e), render);
        self.lambda_head.set(outer);
        if let Some((lo, hi)) = head {
            comments.extend(self.anchored_in(lo, hi));
            comments.sort_by_key(|c| c.start);
        }
        (comments, rendered)
    }

    /// `body` preceded by `comments`, one per line, continuing at `indent`.
    fn with_comments<'c>(
        comments: impl IntoIterator<Item = &'c Comment>,
        body: &str,
        indent: usize,
    ) -> String {
        let mut comments = comments.into_iter().peekable();
        if comments.peek().is_none() {
            return body.to_owned();
        }
        let pad = self.pad(indent);
        let mut out = String::new();
        for c in comments {
            let _ = write!(out, "{}\n{pad}", c.text);
        }
        out.push_str(body);
        out
    }

    /// The offset of a declaration's first token.
    ///
    /// A definition with a signature starts at the signature's name, the code
    /// token before the `:` that precedes the annotation.
    fn decl_start(&self, decl: &Decl<'_>) -> usize {
        match decl {
            Decl::Union(union) => union.span.lo as usize,
            Decl::Alias(alias) => alias.span.lo as usize,
            Decl::Foreign(foreign) => foreign.span.lo as usize,
            Decl::Value(value) => value.value.type_annotation.as_ref().map_or(
                value.value.name.span.lo as usize,
                |ann| {
                    let ann_lo = ann.span.lo as usize;
                    let at = self.code.partition_point(|tok| tok.lo < ann_lo);
                    let before = |back: usize| at.checked_sub(back).and_then(|j| self.code.get(j));
                    match (before(1), before(2)) {
                        (Some(colon), Some(name)) if matches!(colon.kind, TokenKind::Colon) => {
                            name.lo
                        }
                        _ => ann_lo,
                    }
                },
            ),
        }
    }

    /// Render the import block, each import with the comments `owned_from` its
    /// keyword gives it.
    ///
    /// elm-format sorts imports by module path and prints them directly under
    /// the header (one blank line separates the header from the first import
    /// only when imports exist). An import prints on one line, so every
    /// comment it owns travels above it through the sort, except the comments
    /// written directly above the FIRST import in the source, which describe
    /// the module (or the whole import block) and stay above the block. That
    /// block keeps the source's blank lines between its comments and before
    /// the first import, so the comments of an import sorted to the front
    /// print the same on every pass: the second pass reads them as part of the
    /// block, with the same blank lines.
    fn import_block<'c>(
        &self,
        out: &mut String,
        imports: &[Import],
        owned_from: impl Fn(usize) -> &'c [Comment],
    ) {
        if imports.is_empty() {
            return;
        }
        let first_in_source = imports
            .iter()
            .enumerate()
            .min_by_key(|(_, imp)| imp.import_kw.lo)
            .map(|(i, _)| i);
        out.push('\n');
        if let Some(first) = first_in_source.and_then(|i| imports.get(i)) {
            let kw = first.import_kw.lo as usize;
            let above = self.anchored(kw);
            if !above.is_empty() {
                self.push_comment_block(out, above);
                if self.blank_line_before(kw) {
                    out.push('\n');
                }
            }
        }
        let mut order: Vec<usize> = (0..imports.len()).collect();
        order.sort_by_key(|&i| imports.get(i).map(|imp| self.dotted(&imp.name.value)));
        for i in order {
            let Some(imp) = imports.get(i) else { continue };
            let kw = imp.import_kw.lo as usize;
            let owned = owned_from(kw);
            // The first import's comments above its keyword head the block.
            let travels = if Some(i) == first_in_source {
                owned.get(self.anchored(kw).len()..).unwrap_or_default()
            } else {
                owned
            };
            let line = self.import(imp);
            push_comment_lines(out, unplaced(travels, &line));
            out.push_str(&line);
            out.push('\n');
        }
    }

    /// Render a whole module.
    fn module(&self, m: &Module) -> String {
        // Destructured field by field, with no `..`: a new kind of top-level
        // declaration is a build error here until it is printed, never a
        // silently dropped declaration.
        let Module {
            module_kw: _,
            name,
            exposing,
            imports,
            values,
            unions,
            aliases,
            foreigns,
        } = m;
        // Every anchored comment has exactly one owner among the module's
        // items: the header owns those anchored before the first import or
        // declaration, an import those from its `import` keyword up to the next
        // item, a declaration those from its first token up to the next one.
        // An owner prints each comment its rendering did not place above that
        // rendering (see `unplaced`), so no comment position the parser admits
        // falls between owners and is lost.
        let mut decls: Vec<Decl<'_>> = Vec::new();
        decls.extend(unions.iter().map(Decl::Union));
        decls.extend(aliases.iter().map(Decl::Alias));
        decls.extend(values.iter().map(Decl::Value));
        decls.extend(foreigns.iter().map(Decl::Foreign));
        decls.sort_by_key(Decl::lo);
        let mut starts: Vec<usize> = imports
            .iter()
            .map(|imp| imp.import_kw.lo as usize)
            .chain(decls.iter().map(|d| self.decl_start(d)))
            .collect();
        starts.sort_unstable();
        let owner_end = |lo: usize| {
            let next = starts.partition_point(|&s| s <= lo);
            starts.get(next).copied().unwrap_or(usize::MAX)
        };
        let owned_from = |lo: usize| self.anchored_in(lo, owner_end(lo));
        let mut out = String::new();

        // module <Name> exposing (…). A comment the header does not place
        // (before `module`, inside the header line, above its first exposed
        // item) prints first, on its own line(s); elm-format then separates the
        // comment block from the header with exactly two blank lines, however
        // the source spaced them.
        let header = format!(
            "module {}{}",
            self.dotted(&name.value),
            self.module_exposing(exposing)
        );
        let header_owned = self.anchored_in(0, starts.first().copied().unwrap_or(usize::MAX));
        let above_header = unplaced(header_owned, &header);
        if !above_header.is_empty() {
            push_comment_lines(&mut out, above_header);
            out.push_str("\n\n");
        }
        out.push_str(&header);
        out.push('\n');

        self.import_block(&mut out, imports, owned_from);

        // Declarations in source order, each preceded by two blank lines
        // (elm-format's top-level spacing). Unions / aliases / values /
        // foreign declarations interleave by their span order.
        for decl in &decls {
            out.push_str("\n\n");
            // Leading comments: those anchored at the declaration's first
            // token, or at a head token before its name (`type`, `alias`, a
            // signature's name). Nothing depends on where the previous
            // declaration's span ends, which a desugared body underestimates.
            // A comment the declaration owns but its rendering does not place
            // follows them, so a second pass reads it as leading too.
            let lo = decl.lo() as usize;
            let start = self.decl_start(decl);
            let leading = self.anchored_in(start, lo.saturating_add(1));
            let mut item = String::new();
            push_comment_lines(&mut item, leading);
            let body = self.decl(decl, owner_end(start));
            let missed = unplaced(owned_from(start), &format!("{item}{body}"));
            push_comment_lines(&mut item, missed);
            item.push_str(&body);
            out.push_str(&item);
            out.push('\n');
        }

        // Trailing comments after the last token.
        let trailing = self.trailing();
        if !trailing.is_empty() {
            out.push('\n');
            push_comment_lines(&mut out, trailing);
        }

        // A formatted file ends with exactly one trailing newline (POSIX text
        // file, no trailing blank lines) — the fixed-point invariant.
        while out.ends_with("\n\n") {
            out.pop();
        }
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out
    }

    fn exposing(&self, e: &Exposing) -> String {
        match e {
            Exposing::All => "(..)".to_owned(),
            Exposing::List(items) => {
                let parts: Vec<String> = items.iter().map(|it| self.exposed(&it.value)).collect();
                format!("({})", parts.join(", "))
            }
        }
    }

    /// The module header's ` exposing (…)` clause. elm-format's breaking here is
    /// *modal* (like signatures): a header written on one line stays single-line
    /// however wide, and one written across multiple lines keeps its layout —
    /// `exposing` alone on the header line, then a four-space-indented
    /// leading-comma block. Within that block elm-format preserves the SOURCE
    /// GROUPING: exposed items that shared a source line stay on one line, so
    /// the `@docs`-section grouping survives a reformat. The grouping is
    /// recovered from each item's span line.
    ///
    /// A comment above a later exposed item, or above the closing `)`, prints
    /// in place on its own line, and the commented item opens a new group; such
    /// a clause is always multi-line. Every other comment of the header prints
    /// above it (the header owner's [`unplaced`] rule).
    fn module_exposing(&self, e: &Located<Exposing>) -> String {
        let items = match &e.value {
            Exposing::All => return " exposing (..)".to_owned(),
            Exposing::List(items) => items,
        };
        let above = |i: usize, it: &Located<Exposed>| {
            if i == 0 {
                &[][..]
            } else {
                self.anchored(it.span.lo as usize)
            }
        };
        let closing = self.closing_comments(e.span);
        let commented = !closing.is_empty()
            || items
                .iter()
                .enumerate()
                .any(|(i, it)| !above(i, it).is_empty());
        // The clause is multi-line iff its items do not all begin on the same
        // source line (a lone `(` or `)` line does not make it multi-line), or
        // it carries a comment it places.
        let multiline = commented
            || items
                .first()
                .zip(items.last())
                .is_some_and(|(a, b)| self.line_of(a.span.lo) != self.line_of(b.span.lo));
        if !multiline || items.is_empty() {
            return format!(" exposing {}", self.exposing(&e.value));
        }
        // Group consecutive items that began on the same source line; a
        // comment above an item ends the group before it.
        let mut lines: Vec<String> = Vec::new();
        let mut group: Vec<String> = Vec::new();
        let mut groups = 0usize;
        let mut cur_line: Option<usize> = None;
        for (i, it) in items.iter().enumerate() {
            let line = self.line_of(it.span.lo);
            let comments = above(i, it);
            if !comments.is_empty() || Some(line) != cur_line {
                push_exposing_group(&mut lines, &mut group, &mut groups);
            }
            lines.extend(comments.iter().map(|c| format!("    {}", c.text)));
            cur_line = Some(line);
            group.push(self.exposed(&it.value));
        }
        push_exposing_group(&mut lines, &mut group, &mut groups);
        lines.extend(closing.iter().map(|c| format!("    {}", c.text)));
        let mut out = String::from(" exposing\n");
        for line in lines {
            out.push_str(&line);
            out.push('\n');
        }
        out.push_str("    )");
        out
    }

    /// Whether a blank line ends right before byte `pos` in the source: the
    /// whitespace directly before it holds two newlines.
    fn blank_line_before(&self, pos: usize) -> bool {
        let Some(before) = self.src.and_then(|src| src.get(..pos)) else {
            return false;
        };
        before
            .chars()
            .rev()
            .take_while(|c| c.is_whitespace())
            .filter(|&c| c == '\n')
            .nth(1)
            .is_some()
    }

    /// Push `comments` one per line, keeping a blank line the source had
    /// between two of them.
    fn push_comment_block(&self, out: &mut String, comments: &[Comment]) {
        for (i, c) in comments.iter().enumerate() {
            if i > 0 && self.blank_line_before(c.start) {
                out.push('\n');
            }
            out.push_str(&c.text);
            out.push('\n');
        }
    }

    /// The 0-based source line containing byte offset `pos`.
    ///
    /// It is 0 when no source is threaded, as in the round-trip guard.
    fn line_of(&self, pos: u32) -> usize {
        let Some(src) = self.src else { return 0 };
        let pos = (pos as usize).min(src.len());
        src.get(..pos)
            .map_or(0, |s| s.bytes().filter(|&b| b == b'\n').count())
    }

    fn exposed(&self, e: &Exposed) -> String {
        match e {
            Exposed::Value(s) | Exposed::Type(s, Privacy::Private) => self.sym(*s),
            Exposed::Type(s, Privacy::Public) => format!("{}(..)", self.sym(*s)),
            Exposed::Type(s, Privacy::PublicCtors(ctors)) => {
                let cs: Vec<String> = ctors.iter().map(|c| self.sym(*c)).collect();
                format!("{}({})", self.sym(*s), cs.join(", "))
            }
        }
    }

    fn import(&self, imp: &Import) -> String {
        let mut s = format!("import {}", self.dotted(&imp.name.value));
        if let Some(alias) = imp.alias {
            let _ = write!(s, " as {}", self.sym(alias));
        }
        match &imp.exposing.value {
            Exposing::List(items) if items.is_empty() => {}
            Exposing::All => s.push_str(" exposing (..)"),
            Exposing::List(_) => {
                s.push_str(" exposing ");
                s.push_str(&self.exposing(&imp.exposing.value));
            }
        }
        s
    }

    /// Render a declaration whose comments are those anchored before `owner_end`.
    fn decl(&self, d: &Decl<'_>, owner_end: usize) -> String {
        match d {
            Decl::Union(u) => self.union(u, owner_end),
            Decl::Alias(a) => self.alias(&a.value),
            Decl::Value(v) => self.value(&v.value),
            Decl::Foreign(f) => self.foreign(&f.value),
        }
    }

    /// `foreign Name[ : T] = body` — the body on the next line, four-space
    /// indented, like a top-level definition.
    fn foreign(&self, f: &ForeignDecl) -> String {
        let ForeignDecl {
            name,
            type_annotation,
            body,
            doc: _,
        } = f;
        let head = type_annotation.as_ref().map_or_else(
            || self.sym(name.value),
            |ann| self.signature(name.value, &ann.value, false),
        );
        // A comment inside the head (outside a record field's own) prints
        // above it.
        let types = type_annotation
            .as_ref()
            .map_or(&[][..], |ann| std::slice::from_ref(&ann.value));
        let mut out = String::new();
        for c in self.type_comments(types, name.span.lo as usize, body.span.lo as usize) {
            out.push_str(&c.text);
            out.push('\n');
        }
        let _ = write!(out, "foreign {head} =\n    {}", self.expr(body, 1));
        out
    }

    /// The ` a b c` type-parameter suffix of a `type` / `type alias` head — a
    /// leading space before each variable, empty when there are none.
    fn type_vars(&self, vars: &[Located<ipe_intern::Symbol>]) -> String {
        let mut s = String::new();
        for v in vars {
            s.push(' ');
            s.push_str(&self.sym(v.value));
        }
        s
    }

    /// `type Name vars = A | B c | …` — leading-pipe multiline when it does not
    /// fit, matching elm-format (each constructor on its own line, four-space
    /// indented, aligned `= …` / `| …`).
    fn union(&self, u: &Located<Union>, owner_end: usize) -> String {
        let uv = &u.value;
        let vars = self.type_vars(&uv.vars);
        // elm-format ALWAYS breaks a union declaration onto multiple lines —
        // the `= Ctor` sits on its own four-space-indented line, and every
        // subsequent constructor is a leading-`|` continuation line — even when
        // there is a single constructor. There is no single-line union form.
        let mut s = format!("type {}{}", self.sym(uv.name.value), vars);
        // A section comment written between two constructors annotates the
        // constructor it precedes: re-emit it on its own four-space-indented
        // line just before that constructor's `| Ctor` line, keeping the
        // author's grouping inside the type. A comment inside a constructor's
        // arguments travels above that constructor too, since a constructor
        // prints on one line. A constructor's span is its name alone, so its
        // comments run up to the next constructor, or for the last one to the
        // end of the declaration's own comments.
        for (idx, c) in uv.ctors.iter().enumerate() {
            let lead = if idx == 0 { "=" } else { "|" };
            let hi = uv
                .ctors
                .get(idx + 1)
                .map_or(owner_end, |next| next.span.lo as usize);
            for cm in self.type_comments(&c.value.args, c.span.lo as usize, hi) {
                let _ = write!(s, "\n    {}", cm.text);
            }
            let _ = write!(s, "\n    {lead} {}", self.ctor(&c.value));
        }
        s
    }

    /// The comments anchored in `[lo, hi)` among `types` that no record-type
    /// printer places: all but those above a closed record's field names.
    ///
    /// A type carries no per-node spans, so these print above the line the
    /// types start on.
    fn type_comments(&self, types: &[TypeAnnotation], lo: usize, hi: usize) -> Vec<&'a Comment> {
        let mut fields = Vec::new();
        for t in types {
            record_field_anchors(t, &mut fields);
        }
        self.anchored_in(lo, hi)
            .iter()
            .filter(|c| c.anchor.is_none_or(|a| !fields.contains(&a)))
            .collect()
    }

    fn ctor(&self, c: &Ctor) -> String {
        if c.args.is_empty() {
            self.sym(c.name)
        } else {
            let args: Vec<String> = c.args.iter().map(|a| self.type_atom(a)).collect();
            format!("{} {}", self.sym(c.name), args.join(" "))
        }
    }

    /// `type alias Name vars = T` — the body goes on the next line, four-space
    /// indented, matching elm-format.
    fn alias(&self, a: &TypeAlias) -> String {
        let vars = self.type_vars(&a.vars);
        // A record alias body honours elm-format's modal multi-line trigger:
        // if the source wrote the record across multiple lines, keep it broken.
        let body = match &a.body.value {
            TypeAnnotation::TRecord(fields) => {
                self.type_record(fields, 1, self.was_multiline(a.body.span))
            }
            other => self.type_annotation(other, 1),
        };
        // A comment written between the `=` sign and the body type attaches to
        // the body's first token; one inside the body (outside a record
        // field's own) joins it.
        let (body_lo, body_hi) = (a.body.span.lo as usize, a.body.span.hi as usize);
        let inside = self.type_comments(std::slice::from_ref(&a.body.value), body_lo + 1, body_hi);
        let mut pre_body = String::new();
        for c in self.anchored(body_lo).iter().chain(inside) {
            pre_body.push_str(&c.text);
            pre_body.push('\n');
            pre_body.push_str("    ");
        }
        format!(
            "type alias {}{} =\n    {}{}",
            self.sym(a.name.value),
            vars,
            pre_body,
            body
        )
    }

    fn value(&self, v: &Value) -> String {
        let mut s = String::new();
        // Type annotation directly above the definition.
        if let Some(ann) = &v.type_annotation {
            let (lo, hi) = (ann.span.lo as usize, ann.span.hi as usize);
            for c in self.type_comments(std::slice::from_ref(&ann.value), lo + 1, hi) {
                s.push_str(&c.text);
                s.push('\n');
            }
            s.push_str(&self.signature(v.name.value, &ann.value, self.was_multiline(ann.span)));
            s.push('\n');
            // A comment written between the type annotation and the binding
            // name (e.g. `-- c` in `main : Int\n-- c\nmain = 42`) attaches to
            // the binding name.
            for c in self.anchored(v.name.span.lo as usize) {
                s.push_str(&c.text);
                s.push('\n');
            }
        }
        // The definition head: `name p0 p1 …`. Parameters are in ARGUMENT
        // position, so a constructor-with-arguments / cons / alias pattern must
        // be parenthesised — otherwise `f (Cons a)` would print as `f Cons a`,
        // silently turning one parameter into two. A comment among the
        // parameters prints above the head.
        let params_lo = v.name.span.lo as usize + 1;
        push_comment_lines(&mut s, self.anchored_in(params_lo, v.body.span.lo as usize));
        s.push_str(&self.sym(v.name.value));
        for p in &v.patterns {
            s.push(' ');
            s.push_str(&self.pattern_atom(&p.value));
        }
        s.push_str(" =");
        // The body always goes on the next line, four-space indented — the
        // elm-format canonical form for a top-level definition.
        let body = self.expr(&v.body, 1);
        let _ = write!(s, "\n    {body}");
        s
    }

    // -- Type annotations ---------------------------------------------------

    /// A top-level `name : Type` signature in the elm-format canonical form.
    ///
    /// elm-format's signature breaking is *modal*, not width-driven: a
    /// signature written on one line stays on one line no matter how wide (it
    /// keeps 1000-column function types single-line), and a signature written
    /// across multiple lines keeps `name :` on its own line with the type laid
    /// out four-space indented beneath — an arrow chain becomes one segment per
    /// line, the first bare and each subsequent one with a leading `->`. The
    /// modal trigger (`was_multi`) mirrors the record / list / tuple trigger.
    fn signature(&self, name: ipe_intern::Symbol, ann: &TypeAnnotation, was_multi: bool) -> String {
        let name = self.sym(name);
        if !was_multi {
            // Force a single line irrespective of width (elm-format keeps a
            // single-line signature single-line however wide it is). An arrow
            // chain is joined with ` -> `; anything else prints as one atom.
            let one = match ann {
                TypeAnnotation::TLambda(_, _) => self.arrow_chain(ann, 0).join(" -> "),
                _ => self.type_app(ann, 0),
            };
            // A record type inside the signature may still force its own break;
            // fall through to the multi-line form only if that happened.
            if !one.contains('\n') {
                return format!("{name} : {one}");
            }
        }
        // Multi-line: `name :` then the type indented one level.
        let body = self.type_multiline(ann, 1);
        format!("{name} :\n{body}")
    }

    /// Render `t` broken across lines at indentation `indent`. An arrow chain
    /// lays out one segment per line; a type application whose single-line form
    /// overflows the width budget breaks its arguments one per line (elm-format
    /// indents each argument one level under the applied head); anything else is
    /// a single indented line.
    fn type_multiline(&self, t: &TypeAnnotation, indent: usize) -> String {
        let cur_pad = self.pad(indent);
        match t {
            TypeAnnotation::TLambda(_, _) => {
                let parts = self.arrow_chain(t, indent);
                let mut it = parts.into_iter();
                let first = it.next().unwrap_or_default();
                let mut out = format!("{cur_pad}{first}");
                for p in it {
                    let _ = write!(out, "\n{cur_pad}-> {p}");
                }
                out
            }
            TypeAnnotation::TType(q, segs, args) if !args.is_empty() => {
                let one = self.type_app(t, indent);
                if fits(&one, indent * 4) {
                    return format!("{cur_pad}{one}");
                }
                // Break the application: head on its own line, each argument one
                // level deeper on its own line.
                let arg_pad = self.pad(indent + 1);
                let mut out = format!("{cur_pad}{}", self.type_head(*q, segs));
                for a in args {
                    let _ = write!(out, "\n{arg_pad}{}", self.type_atom_indent(a, indent + 1));
                }
                out
            }
            _ => format!("{cur_pad}{}", self.type_app(t, indent)),
        }
    }

    fn type_annotation(&self, t: &TypeAnnotation, indent: usize) -> String {
        match t {
            TypeAnnotation::TLambda(_, _) => {
                // Collect the full arrow chain and join with ` -> ` (single
                // line when it fits).
                let parts = self.arrow_chain(t, indent);
                let one = parts.join(" -> ");
                if fits(&one, indent * 4) {
                    one
                } else {
                    // Multiline arrow: each arrow on its own line, four-space
                    // indented past the current level, `->` leading.
                    let pad = self.pad(indent + 1);
                    let mut it = parts.into_iter();
                    let first = it.next().unwrap_or_default();
                    let mut out = first;
                    for p in it {
                        let _ = write!(out, "\n{pad}-> {p}");
                    }
                    out
                }
            }
            _ => self.type_app(t, indent),
        }
    }

    fn arrow_chain(&self, t: &TypeAnnotation, indent: usize) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = t;
        while let TypeAnnotation::TLambda(a, b) = cur {
            out.push(self.type_app(a, indent));
            cur = b;
        }
        out.push(self.type_app(cur, indent));
        out
    }

    fn type_app(&self, t: &TypeAnnotation, indent: usize) -> String {
        match t {
            TypeAnnotation::TType(q, segs, args) if !args.is_empty() => {
                let head = self.type_head(*q, segs);
                let arg_strs: Vec<String> = args
                    .iter()
                    .map(|a| self.type_atom_indent(a, indent))
                    .collect();
                format!("{head} {}", arg_strs.join(" "))
            }
            _ => self.type_atom_indent(t, indent),
        }
    }

    fn type_head(&self, q: ipe_intern::Symbol, segs: &[ipe_intern::Symbol]) -> String {
        let qs = self.sym(q);
        let name = self.dotted(segs);
        if qs.is_empty() {
            name
        } else {
            format!("{qs}.{name}")
        }
    }

    fn type_atom(&self, t: &TypeAnnotation) -> String {
        self.type_atom_indent(t, 0)
    }

    /// A type in atom position — parenthesised when it is a compound (arrow,
    /// applied constructor, or tuple) that would otherwise re-associate.
    fn type_atom_indent(&self, t: &TypeAnnotation, indent: usize) -> String {
        match t {
            TypeAnnotation::TVar(s) => self.sym(*s),
            TypeAnnotation::TUnit => "()".to_owned(),
            TypeAnnotation::TType(q, segs, args) if args.is_empty() => self.type_head(*q, segs),
            TypeAnnotation::TType(..) => {
                format!("({})", self.type_app(t, indent))
            }
            TypeAnnotation::TLambda(..) => {
                format!("({})", self.type_annotation(t, indent))
            }
            TypeAnnotation::TTuple(elems) => {
                let parts: Vec<String> = elems
                    .iter()
                    .map(|e| self.type_annotation(e, indent))
                    .collect();
                format!("( {} )", parts.join(", "))
            }
            TypeAnnotation::TRecord(fields) => self.type_record(fields, indent, false),
            TypeAnnotation::TRecordOpen(row_var, fields) => {
                self.type_record_open(*row_var, fields, indent)
            }
        }
    }

    /// Render a row-polymorphic record TYPE `{ r | field : T, … }`. The open
    /// tail always keeps the record on one line — the row var makes it a
    /// signature fragment, never a wide `type alias` body, so the modal
    /// multi-line trigger `type_record` honours does not apply.
    fn type_record_open(
        &self,
        row_var: ipe_intern::Symbol,
        fields: &[(Located<ipe_intern::Symbol>, TypeAnnotation)],
        indent: usize,
    ) -> String {
        let parts: Vec<String> = fields
            .iter()
            .map(|(n, ty)| {
                format!(
                    "{} : {}",
                    self.sym(n.value),
                    self.type_annotation(ty, indent)
                )
            })
            .collect();
        format!("{{ {} | {} }}", self.sym(row_var), parts.join(", "))
    }

    /// Render a record TYPE `{ field : T, … }`. `force_multi` reproduces
    /// elm-format's modal trigger (the record was written across multiple lines
    /// in the source, e.g. a `type alias` body), which breaks it even when it
    /// would fit on one line.
    fn type_record(
        &self,
        fields: &[(Located<ipe_intern::Symbol>, TypeAnnotation)],
        indent: usize,
        force_multi: bool,
    ) -> String {
        if fields.is_empty() {
            return "{}".to_owned();
        }
        let parts: Vec<String> = fields
            .iter()
            .map(|(n, ty)| {
                format!(
                    "{} : {}",
                    self.sym(n.value),
                    self.type_annotation(ty, indent)
                )
            })
            .collect();
        // A comment written above a record-type field attaches to the field's
        // name; `leading[i]` holds field `i`'s. Printing them here keeps the
        // comment guard from refusing a record whose fields are interleaved
        // with comments (the shipped `type alias Model` body is this shape).
        let leading: Vec<&[Comment]> = fields
            .iter()
            .map(|(name, _)| self.anchored(name.span.lo as usize))
            .collect();
        let has_field_comments = leading.iter().any(|cs| !cs.is_empty());
        let one = format!("{{ {} }}", parts.join(", "));
        // Modal, like every other collection: a record type written on one line
        // stays single-line however wide; only a source-multiline record (the
        // `force_multi` trigger), one whose own field broke, or one carrying an
        // inter-field comment (which cannot survive on a single line) lays out
        // one field per leading-comma line.
        if !force_multi && !has_field_comments && !one.contains('\n') {
            return one;
        }
        let pad = self.pad(indent);
        let inner = self.pad_in(indent);
        let mut out = String::from("{");
        for (i, (part, lead)) in parts.iter().zip(&leading).enumerate() {
            // The comment block precedes the field it annotates, mirroring the
            // source where the comment sits above its field.
            for c in *lead {
                let _ = write!(out, "\n{inner}{}", c.text);
            }
            if i == 0 && lead.is_empty() {
                let _ = write!(out, " {part}");
            } else if i == 0 {
                let _ = write!(out, "\n{inner}  {part}");
            } else {
                let _ = write!(out, "\n{inner}, {part}");
            }
        }
        let _ = write!(out, "\n{pad}}}");
        out
    }

    // -- Patterns -----------------------------------------------------------

    fn pattern(&self, p: &Pattern_) -> String {
        match p {
            Pattern_::PAnything => "_".to_owned(),
            Pattern_::PDebugAnything => "Debug._".to_owned(),
            Pattern_::PUnit => "()".to_owned(),
            Pattern_::PVar(s) => self.sym(*s),
            Pattern_::PInt(n) => n.to_string(),
            Pattern_::PBool(b) => if *b { "True" } else { "False" }.to_owned(),
            Pattern_::PChar(c) => format!("'{}'", escape_char_body(c)),
            Pattern_::PStr(s) => format!("\"{}\"", escape_str_body(s)),
            Pattern_::PCtor(name, segs, args) => {
                let head = if segs.is_empty() {
                    self.sym(*name)
                } else {
                    format!("{}.{}", self.dotted(segs), self.sym(*name))
                };
                if args.is_empty() {
                    head
                } else {
                    let a: Vec<String> = args.iter().map(|x| self.pattern_atom(&x.value)).collect();
                    format!("{head} {}", a.join(" "))
                }
            }
            Pattern_::PTuple(elems) => {
                let parts: Vec<String> = elems.iter().map(|e| self.pattern(&e.value)).collect();
                format!("( {} )", parts.join(", "))
            }
            Pattern_::PRecord(fields) => {
                let parts: Vec<String> = fields.iter().map(|f| self.sym(f.value)).collect();
                format!("{{ {} }}", parts.join(", "))
            }
            Pattern_::PList(elems) => {
                if elems.is_empty() {
                    "[]".to_owned()
                } else {
                    let parts: Vec<String> = elems.iter().map(|e| self.pattern(&e.value)).collect();
                    format!("[ {} ]", parts.join(", "))
                }
            }
            Pattern_::PCons(h, t) => {
                format!(
                    "{} :: {}",
                    self.pattern_atom(&h.value),
                    self.pattern(&t.value)
                )
            }
            Pattern_::PAlias(inner, name) => {
                format!("{} as {}", self.pattern(&inner.value), self.sym(name.value))
            }
            Pattern_::POr(alts) => {
                let parts: Vec<String> = alts.iter().map(|a| self.pattern(&a.value)).collect();
                parts.join(" | ")
            }
        }
    }

    /// A pattern in atom position — parenthesised when it is a compound that
    /// would otherwise bind wrongly (ctor-with-args, cons, tuple-as-arg).
    fn pattern_atom(&self, p: &Pattern_) -> String {
        match p {
            Pattern_::PCtor(_, _, args) if !args.is_empty() => format!("({})", self.pattern(p)),
            // An or-pattern binds loosest, so in any atom position (ctor arg,
            // cons head) it must be parenthesised to keep its grouping.
            Pattern_::PCons(..) | Pattern_::PAlias(..) | Pattern_::POr(..) => {
                format!("({})", self.pattern(p))
            }
            _ => self.pattern(p),
        }
    }

    // -- Expressions --------------------------------------------------------

    /// Format an expression at the given indentation (in 4-space units).
    ///
    /// A `do` block reaches the printer already desugared into its
    /// `Task.andThen` / `let` chain; it is re-sugared here so the output keeps
    /// the source's `do` form. The desugared chain is not always printable:
    /// a bare-run line becomes `let _ = task in …`, which the parser rejects
    /// outside a `do` (`BareWildcardBinding`).
    ///
    /// The comments anchored at the expression's first token print above it,
    /// each on its own line at `indent`.
    fn expr(&self, e: &Expr, indent: usize) -> String {
        #[cfg(test)]
        count_render_call();
        let (comments, body) = self.claim_expr(e, || self.expr_shape(e, indent));
        Self::with_comments(comments, &body, indent)
    }

    /// Format an expression without its leading comments.
    fn expr_shape(&self, e: &Expr, indent: usize) -> String {
        self.do_view(e).map_or_else(
            || self.expr_node(e, indent),
            |view| self.do_block(&view, indent),
        )
    }

    /// The source offset just past the `do` keyword of a block's span.
    ///
    /// `None` when `span` is not a `do` block's. The `do` desugar stamps the
    /// outermost node of its chain with the keyword's own span; a
    /// parenthesised group re-stamps its inner node with the group's span, so
    /// `(do …)` is recognised by its leading keyword — skipping over any
    /// opening parens, whitespace, and comments in between, since a comment
    /// (`( -- note\n do …)`) is as legal there as blank space and must not
    /// hide the keyword.
    /// Always `None` without source: the equivalence guard compares the
    /// desugared form directly.
    fn do_keyword_end(&self, span: ipe_diagnostics::Span) -> Option<usize> {
        let lo = span.lo as usize;
        let text = self.src?.get(lo..span.hi as usize)?;
        if text == "do" {
            return Some(lo + text.len());
        }
        if !text.ends_with(')') {
            return None;
        }
        let inner = text.strip_prefix('(')?;
        let rest = skip_paren_trivia(inner);
        let after = rest.strip_prefix("do")?;
        after
            .starts_with(char::is_whitespace)
            .then_some(lo + (text.len() - after.len()))
    }

    /// Recover the statements of the `do` block whose desugared chain is `e`.
    ///
    /// `None` when `e` is not a `do` block.
    fn do_view<'e>(&self, e: &'e Expr) -> Option<DoView<'e>> {
        let keyword_end = self.do_keyword_end(e.span)?;
        let mut steps = Vec::new();
        let mut cur = e;
        loop {
            let outer = steps.is_empty();
            // A nested `do` in result position carries its own keyword span:
            // it is this block's result, printed as its own `do` block.
            if !outer && self.do_keyword_end(cur.span).is_some() {
                break;
            }
            let Some((step, rest)) = self.do_step(cur, outer) else {
                break;
            };
            steps.push(step);
            cur = rest;
        }
        // A parenthesised node whose text merely starts with `(do` may be an
        // application or access headed by the block (`(do …) x`), which peels
        // no statement: print that node by its own shape. A lone-statement
        // `(do t)` prints as `(t)`, the same tree.
        if steps.is_empty() && keyword_end != e.span.hi as usize {
            return None;
        }
        Some(DoView {
            keyword_end,
            steps,
            result: cur,
        })
    }

    /// Peel one `do` statement off the front of a desugared chain.
    ///
    /// Returns the statement with the rest of the chain. The shapes mirror the
    /// parser's `desugar_do` span discipline:
    /// - bind `p <- t` is `Task.andThen (\p -> rest) t` with a zero-width
    ///   lambda span (no written lambda is zero-width);
    /// - bare run `t` is `let _ = t in rest` whose `_` carries `t`'s own span
    ///   (a written `let _ =` is rejected by the parser);
    /// - pure `p = v` is `let p = v in rest` stamped with the `=` span, which
    ///   lies after the binder (a written `let` starts before its binder). The
    ///   outermost node carries the `do` span instead, so there any
    ///   single-binding `let` over a statement binder is accepted — printing a
    ///   lone `let … in` result as a statement re-parses to the same AST.
    fn do_step<'e>(&self, e: &'e Expr, outer: bool) -> Option<(DoStep<'e>, &'e Expr)> {
        match &e.value {
            Expr_::Call(head, args) => {
                let Expr_::VarQual(module, name) = &head.value else {
                    return None;
                };
                let [lam, task] = args.as_slice() else {
                    return None;
                };
                let Expr_::Lambda(params, cont) = &lam.value else {
                    return None;
                };
                let [pat] = params.as_slice() else {
                    return None;
                };
                let synthetic = lam.span.lo == lam.span.hi
                    && self.sym(*module) == "Task"
                    && self.sym(*name) == "andThen";
                (synthetic && is_do_binder(&pat.value))
                    .then_some((DoStep::Bind(pat, task), cont.as_ref()))
            }
            Expr_::Let(bindings, cont) => {
                let [b] = bindings.as_slice() else {
                    return None;
                };
                if matches!(b.pat.value, Pattern_::PAnything) && b.pat.span == b.body.span {
                    return Some((DoStep::Run(&b.body), cont.as_ref()));
                }
                let stamped_after_binder = e.span.lo >= b.pat.span.hi;
                ((outer || stamped_after_binder) && is_do_binder(&b.pat.value))
                    .then_some((DoStep::Let(&b.pat, &b.body), cont.as_ref()))
            }
            _ => None,
        }
    }

    /// Print a recovered `do` block, one statement per line one level in.
    ///
    /// The result expression comes last; comments written between statements
    /// keep their place.
    fn do_block(&self, view: &DoView<'_>, indent: usize) -> String {
        let stmt_pad = self.pad(indent + 1);
        // A parenthesised block's node starts at its `(`: a comment between
        // the `(` and the keyword attaches to the keyword.
        let keyword_lo = view.keyword_end.saturating_sub("do".len());
        let mut out = if self.is_claimed(keyword_lo) {
            String::from("do")
        } else {
            Self::with_comments(self.anchored(keyword_lo), "do", indent)
        };
        for step in &view.steps {
            // A bound or pure statement starts at its binder; a bare run is an
            // expression and carries its own comments.
            let line = match step {
                DoStep::Bind(pat, task) => Self::with_comments(
                    self.anchored(pat.span.lo as usize),
                    &format!(
                        "{} <- {}",
                        self.pattern(&pat.value),
                        self.expr(task, indent + 1)
                    ),
                    indent + 1,
                ),
                DoStep::Let(pat, value) => Self::with_comments(
                    self.anchored(pat.span.lo as usize),
                    &format!(
                        "{} = {}",
                        self.pattern(&pat.value),
                        self.expr(value, indent + 1)
                    ),
                    indent + 1,
                ),
                DoStep::Run(task) => self.expr(task, indent + 1),
            };
            let _ = write!(out, "\n{stmt_pad}{line}");
        }
        // With no statement peeled, the result IS the `do`-stamped node: print
        // its own shape, or `expr` would recognise the block again.
        let result = if view.steps.is_empty() {
            self.expr_node(view.result, indent + 1)
        } else {
            self.expr(view.result, indent + 1)
        };
        let _ = write!(out, "\n{stmt_pad}{result}");
        out
    }

    /// Format an expression node by its own shape, without `do` re-sugaring.
    ///
    /// A node the parser desugared from a sugar prints as that sugar: a getter
    /// lambda as its field accessor `.a.b`, a `Basics.negate` call as `-e`.
    fn expr_node(&self, e: &Expr, indent: usize) -> String {
        if let Some(path) = ipe_parse::field_accessor(e) {
            return path.iter().fold(String::new(), |mut s, field| {
                s.push('.');
                s.push_str(&self.sym(*field));
                s
            });
        }
        if let Some(operand) = ipe_parse::negation(e, self.interner) {
            return format!("-{}", self.expr_atom(operand, indent));
        }
        match &e.value {
            Expr_::VarLocal(s) => self.sym(*s),
            Expr_::VarQual(q, n) => format!("{}.{}", self.sym(*q), self.sym(*n)),
            Expr_::Int(n) => n.to_string(),
            Expr_::Float(f) => format_float(*f),
            Expr_::Str(s) => format!("\"{}\"", escape_str_body(s)),
            // The equivalence projection (no source) prints the string's value,
            // its margin stripped at its anchor column: a printed string moved to
            // another column strips another margin, and must read as different.
            Expr_::MultilineStr { raw, anchor } => match self.src {
                Some(_) => format!("\"\"\"{raw}\"\"\""),
                None => format!("\"\"\"{}\"\"\"", strip_anchor_margin(raw, *anchor)),
            },
            Expr_::Char(c) => format!("'{}'", escape_char_body(c)),
            Expr_::Unit => "()".to_owned(),
            Expr_::Call(head, args) => self.call(head, args, indent, e.span),
            Expr_::Binops(chain, last) => self.binops(chain, last, indent, e.span),
            Expr_::Case(scrut, arms) => self.case(scrut, arms, indent),
            Expr_::Lambda(params, body) => self.lambda(params, body, indent, e.span),
            Expr_::Let(bindings, body) => self.let_(bindings, body, indent),
            Expr_::If(branches, else_) => self.if_(branches, else_, indent),
            Expr_::Tuple(elems) => self.tuple(elems, indent, e.span),
            Expr_::List(elems) => self.list(elems, indent, e.span),
            Expr_::Record(fields) => self.record(fields, indent, e.span),
            Expr_::Update(base, fields) => self.update(base, fields, indent, e.span),
            Expr_::Access(base, field) => {
                // An accessor base keeps its parentheses: `(.a).b` written bare
                // reads back as the one accessor `.a.b`.
                let base_s = if ipe_parse::field_accessor(base).is_some() {
                    format!("({})", self.expr(base, indent))
                } else {
                    self.expr_atom(base, indent)
                };
                format!("{base_s}.{}", self.sym(field.value))
            }
        }
    }

    /// An expression in atom position (application argument, operator operand,
    /// access base): parenthesised when it is a compound that would otherwise
    /// bind incorrectly against its surroundings.
    ///
    /// Leading comments print above the parentheses, not inside them.
    fn expr_atom(&self, e: &Expr, indent: usize) -> String {
        #[cfg(test)]
        count_render_call();
        let (comments, body) = self.claim_expr(e, || self.atom_shape(e, indent));
        Self::with_comments(comments, &body, indent)
    }

    /// An expression in atom position, without its leading comments.
    fn atom_shape(&self, e: &Expr, indent: usize) -> String {
        if ipe_parse::field_accessor(e).is_some() {
            return self.expr(e, indent);
        }
        // A negative numeric literal (`-5`, `-1.0`) prints with a leading `-`,
        // which the parser reads as a binary subtraction operator once the
        // literal sits after another atom — so `f (-5)` bare-printed as `f -5`
        // re-parses as `f - 5`. In atom position the sign must stay wrapped.
        if is_negative_literal(&e.value) {
            return format!("({})", self.expr(e, indent));
        }
        if needs_parens_as_atom(&e.value) {
            let inner = self.expr(e, indent);
            if inner.contains('\n') {
                // A multiline compound in parens: the head follows `(`
                // directly, continuation lines keep their indentation, and the
                // closing `)` sits on its own line at this atom's indent —
                // elm-format's parenthesised-block layout.
                format!("({}\n{})", inner, self.pad(indent))
            } else {
                format!("({inner})")
            }
        } else {
            self.expr(e, indent)
        }
    }

    fn call(
        &self,
        head: &Expr,
        args: &[Expr],
        indent: usize,
        span: ipe_diagnostics::Span,
    ) -> String {
        let head_s = self.expr_atom(head, indent);
        // Single-line application when the whole thing fits, nothing broke, and
        // the source kept it on one line (elm-format's modal rule). Each
        // argument is rendered here exactly ONCE: the multiline branch below
        // reuses these strings rather than re-rendering, so a right-nested
        // application chain (a `do` block's desugared `Task.andThen` binds,
        // one level per statement) costs one render per node, not one render
        // per node per enclosing level — the latter is exponential in nesting
        // depth, since each enclosing level's trial re-walks every level below.
        let arg_one_strs: Vec<String> =
            args.iter().map(|a| self.expr_atom(a, indent + 1)).collect();
        let one = format!("{head_s} {}", arg_one_strs.join(" "));
        if !has_layout_newline(&one) && !self.was_multiline(span) {
            return one;
        }

        // Multiline application — port of elm-format's `application`:
        //   * `FAJoinFirst` (Case 2): the first argument stays on the function
        //     line, the rest indent — but ONLY when that first argument is a
        //     "trivially joinable" atom (a name / literal / joinable string /
        //     empty collection), never a non-empty list / record / tuple /
        //     parenthesised compound, AND a *later* argument renders as a genuine
        //     multi-line block. When every argument is single-line and the call
        //     only broke on width, elm-format instead stacks all of them.
        //   * otherwise (Case 3): the function stands alone and EVERY argument
        //     goes on its own indented line.
        let inner = self.pad(indent + 1);
        // `split_first` avoids indexing/slicing panics and cleanly expresses the
        // "first argument joins the head line" branch.
        // The first argument hugs the function line — elm-format's `FAJoinFirst`
        // — when either:
        //   * it is a simple reference (a name / qualified name / accessor): such
        //     a token always joins the broken head line;
        //   * it is itself a multi-line block (a triple-quoted string); or
        //   * a *later* argument renders as a multi-line block.
        // A literal first argument (string / number) that is followed only by
        // single-line arguments does NOT join — elm-format stacks them all.
        let is_simple_ref = |a: &Expr| {
            matches!(
                a.value,
                Expr_::VarLocal(_) | Expr_::VarQual(..) | Expr_::Access(..)
            ) || ipe_parse::field_accessor(a).is_some()
        };
        let first_is_block =
            |a: &Expr| matches!(&a.value, Expr_::MultilineStr { raw, .. } if raw.contains('\n'));
        let later_block = |tail_strs: &[String]| tail_strs.iter().any(|s| has_layout_newline(s));
        let (mut out, rest_strs): (String, &[String]) =
            match (args.split_first(), arg_one_strs.split_first()) {
                (Some((first, _)), Some((first_str, tail_strs)))
                    if Self::joins_on_head_line(first, first_str)
                        && head_line_fits(&head_s, first, indent)
                        && (is_simple_ref(first)
                            || first_is_block(first)
                            || later_block(tail_strs)) =>
                {
                    (format!("{head_s} {first_str}"), tail_strs)
                }
                _ => (head_s, arg_one_strs.as_slice()),
            };
        for s in rest_strs {
            let _ = write!(out, "\n{inner}{s}");
        }
        out
    }

    /// Whether argument `a`, already rendered as `rendered` (the same string
    /// `call`'s one-line pass computed — passed in rather than re-rendered
    /// here, so this check costs no extra tree walk), may share the
    /// function's line in a broken application (elm-format's `FAJoinFirst`):
    /// a name, qualified name, literal, unit, or empty collection — anything
    /// that renders on a single line AND is not itself a block form
    /// (non-empty list / record / tuple / update / parenthesised compound).
    fn joins_on_head_line(a: &Expr, rendered: &str) -> bool {
        // A triple-quoted string hugs the function line only when it opens with
        // visible content on its first physical line (`interpolate """head\n…"""`).
        // One that opens with a newline (`"""\n…`) — or any string literal that is
        // a single line — drops to its own indented line instead.
        if let Expr_::MultilineStr { raw: s, .. } = &a.value {
            // A triple-quoted string hugs the function line only when its first
            // physical line opens with visible, non-whitespace content
            // (`"""head…`). One that opens with a newline (`"""\n…`) or with
            // leading indentation (`"""    …`) drops to its own line.
            return match s.split_once('\n') {
                Some((first, _)) => first.starts_with(|c: char| !c.is_whitespace()),
                None => false,
            };
        }
        if rendered.contains('\n') {
            return false;
        }
        if ipe_parse::field_accessor(a).is_some() {
            return true;
        }
        match &a.value {
            Expr_::List(elems) | Expr_::Tuple(elems) => elems.is_empty(),
            Expr_::Record(fields) => fields.is_empty(),
            Expr_::Update(..)
            | Expr_::Call(..)
            | Expr_::Binops(..)
            | Expr_::Case(..)
            | Expr_::Lambda(..)
            | Expr_::Let(..)
            | Expr_::If(..) => false,
            _ => true,
        }
    }

    fn binops(
        &self,
        chain: &[(Expr, Located<ipe_intern::Symbol>)],
        last: &Expr,
        indent: usize,
        span: ipe_diagnostics::Span,
    ) -> String {
        // Each operator with the operand to its right. A comment above an
        // operator line attaches to that right operand, so it is claimed here
        // and printed above the operator.
        let first_operand = chain.first().map_or(last, |(operand, _)| operand);
        let rights: Vec<(String, &Expr, bool)> = chain
            .iter()
            .enumerate()
            .map(|(i, (_, op))| {
                let right = chain.get(i + 1).map_or((last, true), |(o, _)| (o, false));
                (self.sym(op.value), right.0, right.1)
            })
            .collect();
        let right_operand = |operand: &Expr, is_last: bool, at: usize| {
            self.claim_expr(operand, || {
                if is_last {
                    self.binop_last_operand(operand, at)
                } else {
                    self.binop_operand(operand, at)
                }
            })
        };
        // Build the flat operand/operator sequence.
        let mut one = self.binop_operand(first_operand, indent);
        let mut commented = false;
        for (op, operand, is_last) in &rights {
            let (comments, s) = right_operand(operand, *is_last, indent);
            commented |= !comments.is_empty();
            let _ = write!(one, " {op} {s}");
        }
        // Modal, like every other construct: a chain written on one line stays
        // single-line however wide (elm-format keeps 900-column `::` chains
        // intact), and only a source-multiline chain — or one whose operand
        // itself broke, or that carries a comment — lays out one operator per
        // continuation line.
        if !commented && !has_layout_newline(&one) && !self.was_multiline(span) {
            return one;
        }
        // The backward pipe `<|` breaks differently from every other operator:
        // it is right-associative and elm-format leaves it at the END of the
        // left operand's line, dropping the right-hand side onto the next line
        // indented one level (`f x <|\n    g y`). A whole chain of `<|` nests
        // this way. Every other operator (`|>`, `::`, `++`, `==`, …) begins the
        // continuation line instead.
        let all_backward = chain.iter().all(|(_, op)| self.sym(op.value) == "<|");
        let inner = self.pad(indent + 1);
        if all_backward {
            // Each right operand opens the next line one level in; its
            // comments head that line.
            let mut out = self.binop_operand(first_operand, indent);
            for (op, operand, is_last) in &rights {
                let at = if *is_last { indent + 1 } else { indent };
                let (comments, s) = right_operand(operand, *is_last, at);
                let line = Self::with_comments(comments, &s, indent + 1);
                let _ = write!(out, " {op}\n{inner}{line}");
            }
            return out;
        }
        // Multiline: the FIRST operand stays on the current line at the base
        // indent; every operator then begins a continuation line indented one
        // level, with its right-hand operand following on that same line. So
        //   { … }
        //       |> Vector
        // keeps the record at the base indent and only the `|>` step indents.
        let mut out = self.binop_operand(first_operand, indent);
        for (op, operand, is_last) in &rights {
            let (comments, s) = right_operand(operand, *is_last, indent + 1);
            for c in comments {
                let _ = write!(out, "\n{inner}{}", c.text);
            }
            let _ = write!(out, "\n{inner}{op} {s}");
        }
        out
    }

    /// An operand of a binary-operator chain. Unlike a general atom, a function
    /// APPLICATION operand needs no parentheses — application binds tighter than
    /// every binary operator, so `List.foldr f start <| toList v` is
    /// unambiguous and elm-format leaves both calls bare. Only a nested operator
    /// chain, `case` / `if` / `let`, or lambda still needs wrapping.
    fn binop_operand(&self, e: &Expr, indent: usize) -> String {
        // A `do` block desugars to a call, but its statement layout would
        // swallow a following operator line: it keeps its parentheses.
        if matches!(e.value, Expr_::Call(..)) && self.do_keyword_end(e.span).is_none() {
            self.expr(e, indent)
        } else {
            self.expr_atom(e, indent)
        }
    }

    /// The final operand of an operator chain. A trailing `\x -> …` needs no
    /// wrapping parens — the operator to its left already delimits it and its
    /// body extends to the end of the expression, so elm-format emits it bare
    /// (`f <| \x -> body`). Every other operand keeps [`Self::binop_operand`].
    fn binop_last_operand(&self, e: &Expr, indent: usize) -> String {
        if matches!(e.value, Expr_::Lambda(..)) {
            self.expr(e, indent)
        } else {
            self.binop_operand(e, indent)
        }
    }

    fn lambda(
        &self,
        params: &[Pattern],
        body: &Expr,
        indent: usize,
        span: ipe_diagnostics::Span,
    ) -> String {
        let ps: Vec<String> = params.iter().map(|p| self.pattern_atom(&p.value)).collect();
        // A comment among the parameters prints above the lambda, through
        // its `claim_expr`.
        let head = format!("\\{} ->", ps.join(" "));
        // A block-form body (`let` / `case` / `if`) always drops to the next
        // line, indented one level: an inline `-> let …` would place the `let`
        // keyword mid-line, breaking its layout-sensitive block on re-parse.
        // A modal body — one written across multiple source lines — also drops
        // to its own indented line, matching elm-format's `\x ->\n    body`.
        // So does a body carrying a comment, which needs a line of its own, and
        // a body that breaks across lines inline: the printed lambda is then
        // multi-line, so the block form is the one a second pass would pick.
        // Any other body stays inline after the arrow.
        //
        // Rendered exactly ONCE, at the block indent, and reused for both the
        // inline and the block candidate: a result with no embedded newline
        // reads identically at any indent (padding is only ever inserted
        // after a newline), so that one string serves either placement.
        // Trying an inline render at this indent, rejecting it, and
        // re-rendering at the block indent — as elm-format's own two-pass
        // check would — costs one render per node per ENCLOSING level; for a
        // right-nested lambda chain (a `do` block's desugared binds, one
        // level per statement) that is exponential in the number of
        // statements. Budgeting the fits-inline check at the block indent
        // (one narrower than the inline placement actually occupies) is
        // conservative-only: a narrower width budget can only ever wrap a
        // body the wider one would have kept on one line, never the reverse,
        // so this can pick block form a body would have fit on the arrow's
        // line, but never the other way around.
        let block_body = matches!(body.value, Expr_::Let(..) | Expr_::Case(..) | Expr_::If(..))
            || !self.anchored(body.span.lo as usize).is_empty();
        let body_s = self.expr(body, indent + 1);
        if !block_body && !self.was_multiline(span) && !has_layout_newline(&body_s) {
            format!("{head} {body_s}")
        } else {
            format!("{head}\n{}{body_s}", self.pad(indent + 1))
        }
    }

    fn case(&self, scrut: &Expr, arms: &[(Pattern, Expr)], indent: usize) -> String {
        let scrut_s = self.expr(scrut, indent);
        let arm_pad = self.pad(indent + 1);
        let body_pad = self.pad(indent + 2);
        let mut out = format!("case {scrut_s} of");
        for (i, (pat, body)) in arms.iter().enumerate() {
            // A comment above an arm attaches to its pattern and sits on its
            // own arm-indented line, matching elm-format's convention for
            // section comments inside a `case`. The blank line between arms is
            // always emitted; after a comment, another blank line keeps the
            // next arm visually separated.
            // A comment inside the pattern prints above the arm too, in the
            // same run, so a second pass reads it as one above the pattern.
            if i > 0 {
                out.push('\n');
            }
            let lo = pat.span.lo as usize;
            let above = self.anchored(lo).iter();
            let inside = self.anchored_in(lo + 1, body.span.lo as usize);
            for c in above.chain(inside) {
                let _ = write!(out, "\n{arm_pad}{}", c.text);
                if i > 0 {
                    out.push('\n');
                }
            }
            let body_s = self.expr(body, indent + 2);
            let _ = write!(
                out,
                "\n{arm_pad}{} ->\n{body_pad}{body_s}",
                self.pattern(&pat.value)
            );
        }
        out
    }

    fn let_(&self, bindings: &[LetBinding], body: &Expr, indent: usize) -> String {
        let bind_pad = self.pad(indent + 1);
        let body_val_pad = self.pad(indent + 2);
        let mut out = String::from("let");
        for (i, b) in bindings.iter().enumerate() {
            // elm-format separates successive `let` bindings with a blank
            // line; the comments above a binding, attached to its binder,
            // replace that blank line.
            let above = self.anchored(b.pat.span.lo as usize);
            // A `let` binder that destructures with a constructor pattern must
            // stay parenthesised — `(Decoder d) = …`. Without the parens the
            // re-parse reads `Decoder` as the (illegal, uppercase) binding name.
            let mut binder = self.let_binder(&b.pat.value);
            // A local function `f x = body` keeps its parameters on the
            // binder; the parser stores it as `f = \x -> body`.
            let value = ipe_parse::let_function(&b.body).map_or(&b.body, |(params, body)| {
                for p in params {
                    binder.push(' ');
                    binder.push_str(&self.pattern_atom(&p.value));
                }
                body
            });
            // A comment inside the binder or among the parameters prints
            // above the binding too, in the same run, so a second pass reads
            // it as one above the binder.
            let head_lo = b.pat.span.lo as usize + 1;
            let inside = self.anchored_in(head_lo, value.span.lo as usize);
            if i > 0 && above.is_empty() && inside.is_empty() {
                out.push('\n');
            }
            push_indented_comments(&mut out, above.iter().chain(inside), bind_pad);
            // elm-format ALWAYS drops a `let` binding's value onto its own
            // four-space-indented line, however short — `x =\n    1`.
            let val = self.expr(value, indent + 2);
            let _ = write!(out, "\n{bind_pad}{binder} =\n{body_val_pad}{val}");
        }
        let in_pad = self.pad(indent);
        let _ = write!(out, "\n{in_pad}in\n{in_pad}{}", self.expr(body, indent));
        out
    }

    /// A `let` binding's binder pattern. A bare constructor destructure needs
    /// enclosing parens so it re-parses as a destructure rather than an
    /// (illegal) uppercase binding name; other binders print bare.
    fn let_binder(&self, p: &Pattern_) -> String {
        match p {
            Pattern_::PCtor(_, _, args) if !args.is_empty() => format!("({})", self.pattern(p)),
            _ => self.pattern(p),
        }
    }

    fn if_(&self, branches: &[(Expr, Expr)], else_: &Expr, indent: usize) -> String {
        let inner = self.pad(indent + 1);
        let mut out = String::new();
        for (i, (cond, body)) in branches.iter().enumerate() {
            let lead = if i == 0 { "if" } else { "else if" };
            // A comment above `else if` attaches to that `if` keyword, the
            // token just before the condition.
            if i > 0 {
                let keyword = self
                    .token_before(cond.span.lo as usize)
                    .filter(|t| matches!(t.kind, TokenKind::If));
                for c in keyword.map_or(&[][..], |t| self.anchored(t.lo)) {
                    let _ = write!(out, "{}\n{}", c.text, self.pad(indent));
                }
            }
            let _ = write!(
                out,
                "{lead} {} then\n{inner}{}\n\n{}",
                self.expr(cond, indent),
                self.expr(body, indent + 1),
                self.pad(indent)
            );
        }
        let _ = write!(out, "else\n{inner}{}", self.expr(else_, indent + 1));
        out
    }

    // Collection elements are rendered at the collection's OWN indent (the
    // bracket level), not one level deeper: elm-format treats the leading
    // `[ ` / `, ` separator as cosmetic and indents an element's internal
    // breaks (e.g. a nested application's arguments) by 4 from the bracket
    // column, i.e. to `(indent + 1) * 4`. Rendering elements at `indent + 1`
    // would double-count that step.
    //
    // A comment above an element attaches to its first token (a record
    // field's name) and prints on its own line above the element; one above
    // the closing bracket prints above the bracket. A commented collection is
    // always multi-line.
    fn tuple(&self, elems: &[Expr], indent: usize, span: ipe_diagnostics::Span) -> String {
        let items = self.elements(elems, indent);
        self.collection("(", ")", &items, span, indent)
    }

    fn list(&self, elems: &[Expr], indent: usize, span: ipe_diagnostics::Span) -> String {
        if elems.is_empty() {
            return Self::with_comments(self.closing_comments(span), "[]", indent);
        }
        let items = self.elements(elems, indent);
        self.collection("[", "]", &items, span, indent)
    }

    fn record(
        &self,
        fields: &[(Located<ipe_intern::Symbol>, Expr)],
        indent: usize,
        span: ipe_diagnostics::Span,
    ) -> String {
        if fields.is_empty() {
            return Self::with_comments(self.closing_comments(span), "{}", indent);
        }
        let items = self.fields(fields, indent);
        self.collection("{", "}", &items, span, indent)
    }

    /// Each element of a list or tuple with the comments above it.
    fn elements(&self, elems: &[Expr], indent: usize) -> Vec<Item<'a>> {
        elems
            .iter()
            .map(|e| self.claim_expr(e, || self.expr(e, indent)))
            .collect()
    }

    /// Each `name = value` field of a record with the comments above it.
    fn fields(
        &self,
        fields: &[(Located<ipe_intern::Symbol>, Expr)],
        indent: usize,
    ) -> Vec<Item<'a>> {
        fields
            .iter()
            .map(|(n, v)| {
                self.claim(n.span.lo as usize, None, || {
                    format!("{} = {}", self.sym(n.value), self.expr(v, indent))
                })
            })
            .collect()
    }

    /// A list, tuple or record: single-line when it fits, the source kept it
    /// on one line and no comment is inside; leading-comma multi-line
    /// otherwise.
    fn collection(
        &self,
        open: &str,
        close: &str,
        items: &[Item<'a>],
        span: ipe_diagnostics::Span,
        indent: usize,
    ) -> String {
        let closing = self.closing_comments(span);
        let commented = !closing.is_empty() || items.iter().any(|(cs, _)| !cs.is_empty());
        let parts: Vec<&str> = items.iter().map(|(_, s)| s.as_str()).collect();
        let one = format!("{open} {} {close}", parts.join(", "));
        if !commented && !has_layout_newline(&one) && !self.was_multiline(span) {
            return one;
        }
        comma_multiline(&self.pads, open, close, items, closing, indent)
    }

    fn update(
        &self,
        base: &Located<ipe_intern::Symbol>,
        fields: &[(Located<ipe_intern::Symbol>, Expr)],
        indent: usize,
        span: ipe_diagnostics::Span,
    ) -> String {
        let base_s = self.sym(base.value);
        // Field values render at one level deeper than the brace so a value's
        // own line breaks align under the multi-line update body.
        let items = self.fields(fields, indent + 1);
        let closing = self.closing_comments(span);
        let commented = !closing.is_empty() || items.iter().any(|(cs, _)| !cs.is_empty());
        let parts: Vec<&str> = items.iter().map(|(_, s)| s.as_str()).collect();
        let one = format!("{{ {base_s} | {} }}", parts.join(", "));
        if !commented && !has_layout_newline(&one) && !self.was_multiline(span) {
            return one;
        }
        // Multiline update: `{ base` on the first line, then the `| field` /
        // `, field` lines indented ONE LEVEL DEEPER than the brace (elm-format
        // aligns the update pipe under the record body, not under the `{`), and
        // the closing `}` back at the brace column.
        let close_pad = self.pad(indent);
        let inner = self.pad(indent + 1);
        let mut out = format!("{{ {base_s}");
        for (i, (comments, p)) in items.iter().enumerate() {
            let lead = if i == 0 { "|" } else { "," };
            push_indented_comments(&mut out, comments.iter().copied(), inner);
            let _ = write!(out, "\n{inner}{lead} {p}");
        }
        push_indented_comments(&mut out, closing, inner);
        let _ = write!(out, "\n{close_pad}}}");
        out
    }
}

/// Whether an expression is a negative numeric literal (`Int` below zero, or a
/// `Float` that carries a minus sign — including `-0.0`). Such a literal renders
/// with a leading `-`, which the parser treats as binary subtraction once the
/// literal follows another atom, so it must be parenthesised in atom position.
const fn is_negative_literal(e: &Expr_) -> bool {
    match e {
        Expr_::Int(n) => *n < 0,
        Expr_::Float(f) => f.is_sign_negative(),
        _ => false,
    }
}

/// One statement of a `do` block recovered from its desugared chain.
enum DoStep<'e> {
    /// `p <- task` — run `task`, bind its result.
    Bind(&'e Pattern, &'e Expr),
    /// `p = value` — a pure binding.
    Let(&'e Pattern, &'e Expr),
    /// `task` — run for effect, result discarded.
    Run(&'e Expr),
}

/// A `do` block recovered from its desugared chain.
struct DoView<'e> {
    /// Source offset just past the `do` keyword.
    keyword_end: usize,
    /// The statements before the result, in source order.
    steps: Vec<DoStep<'e>>,
    /// The block's final (result) expression.
    result: &'e Expr,
}

/// Whether `p` can head a `do` statement: the parser accepts only a lowercase
/// name or `_` before `<-` / `=`.
const fn is_do_binder(p: &Pattern_) -> bool {
    matches!(p, Pattern_::PVar(_) | Pattern_::PAnything)
}

/// Whether an expression needs parentheses when it appears in atom position
/// (an application argument, an operator operand, or an access base) — the
/// compound forms that would otherwise re-associate against their surroundings.
const fn needs_parens_as_atom(e: &Expr_) -> bool {
    matches!(
        e,
        Expr_::Call(..)
            | Expr_::Binops(..)
            | Expr_::Case(..)
            | Expr_::Lambda(..)
            | Expr_::Let(..)
            | Expr_::If(..)
    )
}

/// Whether `s` contains a newline that is part of the source *layout* rather
/// than the *content* of a triple-quoted (`"""…"""`) string. elm-format's modal
/// rule keys the multi-line layout of a construct on whether the construct was
/// written across multiple source lines — but a multi-line string literal is a
/// single logical token, so the `\n`s inside its `"""…"""` delimiters are
/// content, not layout. Counting them would make e.g. `interpolate """…\n…"""`
/// look "source-multiline" and wrongly break the surrounding call.
fn has_layout_newline(s: &str) -> bool {
    let mut in_triple = false;
    let mut rest = s.as_bytes();
    while let Some((&head, tail)) = rest.split_first() {
        if rest.starts_with(b"\"\"\"") {
            in_triple = !in_triple;
            rest = rest.get(3..).unwrap_or(&[]);
            continue;
        }
        if head == b'\n' && !in_triple {
            return true;
        }
        rest = tail;
    }
    false
}

/// Whether the head plus its first argument fits on one line before the
/// argument's own break. For a multi-line triple-quoted string the join line is
/// `head """first-content-line`; elm-format only hugs the string to the function
/// when that opening line stays within the width budget, otherwise the string
/// drops to its own indented line. Other joinable first arguments (names, empty
/// collections) are short and always fit.
fn head_line_fits(head_s: &str, first: &Expr, indent: usize) -> bool {
    let Expr_::MultilineStr { raw: s, .. } = &first.value else {
        return true;
    };
    let first_content = s.split_once('\n').map_or(s.as_str(), |(f, _)| f);
    // column of the head + head + ` ` + `"""` + first content line
    let col = indent * 4 + head_s.chars().count() + 1 + 3 + first_content.chars().count();
    col <= MAX_WIDTH
}

/// Push the name offset of every closed-record field inside `t`: the anchors
/// whose comments the record-type printer places above its fields.
fn record_field_anchors(t: &TypeAnnotation, out: &mut Vec<usize>) {
    match t {
        TypeAnnotation::TVar(_) | TypeAnnotation::TUnit => {}
        TypeAnnotation::TLambda(a, b) => {
            record_field_anchors(a, out);
            record_field_anchors(b, out);
        }
        TypeAnnotation::TType(_, _, args) | TypeAnnotation::TTuple(args) => {
            for a in args {
                record_field_anchors(a, out);
            }
        }
        TypeAnnotation::TRecord(fields) => {
            for (name, ty) in fields {
                out.push(name.span.lo as usize);
                record_field_anchors(ty, out);
            }
        }
        TypeAnnotation::TRecordOpen(_, fields) => {
            for (_, ty) in fields {
                record_field_anchors(ty, out);
            }
        }
    }
}

/// A collection element, rendered, with the comments printed above it.
type Item<'c> = (Comments<'c>, String);

/// The comments a node prints above itself.
type Comments<'c> = Vec<&'c Comment>;

/// Push each comment on its own line, ending each with a newline.
fn push_comment_lines<'c>(out: &mut String, comments: impl IntoIterator<Item = &'c Comment>) {
    for c in comments {
        out.push_str(&c.text);
        out.push('\n');
    }
}

/// Close the exposed-item `group` as one line of a multi-line exposing clause:
/// `( ` before the first group, `, ` before each later one.
fn push_exposing_group(lines: &mut Vec<String>, group: &mut Vec<String>, groups: &mut usize) {
    if group.is_empty() {
        return;
    }
    let lead = if *groups == 0 { "( " } else { ", " };
    lines.push(format!("    {lead}{}", group.join(", ")));
    group.clear();
    *groups += 1;
}

/// The comments of `owned` that `rendered` does not print, in source order.
///
/// `rendered` is one owner's printing; the comments it prints are matched by
/// text, the multiset the comment guard compares. A rendering that does not
/// lex places nothing here: the guard then refuses the whole output.
fn unplaced<'c>(owned: &'c [Comment], rendered: &str) -> Vec<&'c Comment> {
    if owned.is_empty() {
        return Vec::new();
    }
    let Some(printed) = scan_trivia(rendered) else {
        return Vec::new();
    };
    let mut printed = comment_multiset(&printed.comments);
    let mut missing = Vec::new();
    for c in owned {
        match printed.binary_search(&c.text.as_str()) {
            Ok(i) => {
                printed.remove(i);
            }
            Err(_) => missing.push(c),
        }
    }
    missing
}

/// The byte range of a lambda's parameters, from the first one to its body.
fn lambda_head(e: &Expr) -> Option<(usize, usize)> {
    let Expr_::Lambda(params, body) = &e.value else {
        return None;
    };
    let lo = params.first().map_or(body.span.lo, |p| p.span.lo);
    Some((lo as usize, body.span.lo as usize))
}

/// Push each comment on a fresh line at `pad`.
fn push_indented_comments<'c>(
    out: &mut String,
    comments: impl IntoIterator<Item = &'c Comment>,
    pad: Pad<'_>,
) {
    for c in comments {
        let _ = write!(out, "\n{pad}{}", c.text);
    }
}

/// Shared leading-comma multiline layout for records / lists / tuples:
/// ```text
/// { a = 1
/// , b = 2
/// }
/// ```
/// An element's comments sit on their own lines above it; a first element
/// with comments then drops below the bracket. `closing` comments sit above
/// the closing bracket.
fn comma_multiline(
    pads: &PadBudget,
    open: &str,
    close: &str,
    items: &[Item<'_>],
    closing: &[Comment],
    indent: usize,
) -> String {
    let pad = pads.pad(indent);
    let inner = pads.pad(indent);
    let mut out = String::from(open);
    for (i, (comments, part)) in items.iter().enumerate() {
        push_indented_comments(&mut out, comments.iter().copied(), inner);
        let part = hang_element(part);
        match (i, comments.is_empty()) {
            (0, true) => {
                let _ = write!(out, " {part}");
            }
            (0, false) => {
                let _ = write!(out, "\n{inner}  {part}");
            }
            _ => {
                let _ = write!(out, "\n{inner}, {part}");
            }
        }
    }
    push_indented_comments(&mut out, closing, inner);
    let _ = write!(out, "\n{pad}{close}");
    out
}

/// Align a multi-line collection ELEMENT under the two-column content offset
/// created by its `( ` / `, ` / `[ ` prefix. elm-format's box model places an
/// element two spaces past the bracket, so a nested comma-delimited collection
/// (`{ … }`, `[ … ]`, `( … )`) — whose own continuation commas and closing
/// bracket would otherwise sit at the bracket column — must hang two spaces to
/// line up under its opener. Only such a "leading-bracket" element is shifted;
/// an application or pipe element already indents correctly by four, so shifting
/// it would over-indent its continuation lines.
fn hang_element(part: &str) -> String {
    let starts_collection = part.starts_with("{ ") || part.starts_with("[ ");
    if !starts_collection || !part.contains('\n') {
        return part.to_owned();
    }
    // The element opens a comma-delimited collection at the two-space content
    // offset. Its *own* structural lines — the leading-comma continuations and
    // the closing bracket at the collection's base column — must hang two
    // spaces to sit under the opener. Lines that are more deeply indented (a
    // nested application's arguments, or a `|>` pipe step following the
    // collection) are left untouched: shifting them would misalign them.
    let base_indent = part
        .lines()
        .nth(1)
        .map_or(0, |l| l.len() - l.trim_start().len());
    let mut out = String::with_capacity(part.len() + 8);
    for (i, line) in part.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
            let this_indent = line.len() - line.trim_start().len();
            let trimmed = line.trim_start();
            let is_own_structure = this_indent == base_indent
                && (trimmed.starts_with(", ") || trimmed == "}" || trimmed == "]");
            if is_own_structure {
                out.push_str("  ");
            }
        }
        out.push_str(line);
    }
    out
}

/// A top-level declaration, tagged so unions / aliases / values / foreign
/// declarations can be interleaved in source (span) order.
enum Decl<'a> {
    Union(&'a Located<Union>),
    Alias(&'a Located<TypeAlias>),
    Value(&'a Located<Value>),
    Foreign(&'a Located<ForeignDecl>),
}

impl Decl<'_> {
    /// The declaration's name offset, or its annotation's when that is first.
    fn lo(&self) -> u32 {
        match self {
            Self::Union(u) => u.value.name.span.lo,
            Self::Alias(a) => a.value.name.span.lo,
            Self::Value(v) => {
                // A definition with a type annotation starts at the annotation.
                v.value
                    .type_annotation
                    .as_ref()
                    .map_or(v.value.name.span.lo, |ann| {
                        ann.span.lo.min(v.value.name.span.lo)
                    })
            }
            Self::Foreign(f) => f.span.lo,
        }
    }
}

// ---------------------------------------------------------------------------
// Small formatting helpers
// ---------------------------------------------------------------------------

/// One indent level.
const INDENT_UNIT: &str = "    ";

/// The indentation bytes one print may still emit.
///
/// A layout repeats one indentation on every line it breaks, so indentation
/// is the output an input multiplies: every rendering of a [`Pad`] is charged
/// its bytes here, against the print's [`OutputCap`]. Past the budget a pad
/// renders nothing and the print is marked exceeded, so the caller refuses it.
struct PadBudget {
    left: Cell<usize>,
    exceeded: Cell<bool>,
}

impl PadBudget {
    const fn new(cap: OutputCap) -> Self {
        Self {
            left: Cell::new(cap.bytes()),
            exceeded: Cell::new(false),
        }
    }

    /// The indentation of `level` levels, charged each time it renders.
    const fn pad(&self, level: usize) -> Pad<'_> {
        Pad {
            level,
            budget: self,
        }
    }

    /// Take `bytes` from the budget.
    ///
    /// `false`, and exceeded from then on, when they do not fit.
    fn charge(&self, bytes: usize) -> bool {
        if self.exceeded.get() {
            return false;
        }
        if let Some(left) = self.left.get().checked_sub(bytes) {
            self.left.set(left);
            true
        } else {
            self.left.set(0);
            self.exceeded.set(true);
            false
        }
    }

    /// Whether some pad did not fit the budget.
    const fn exceeded(&self) -> bool {
        self.exceeded.get()
    }
}

/// Indentation of a number of levels, rendered through its [`PadBudget`].
#[derive(Clone, Copy)]
struct Pad<'b> {
    level: usize,
    budget: &'b PadBudget,
}

impl fmt::Display for Pad<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self
            .budget
            .charge(self.level.saturating_mul(INDENT_UNIT.len()))
        {
            for _ in 0..self.level {
                f.write_str(INDENT_UNIT)?;
            }
        }
        Ok(())
    }
}

/// Whether `s`, placed at column `col`, fits within [`MAX_WIDTH`]. A multi-line
/// `s` never "fits" as a single line.
fn fits(s: &str, col: usize) -> bool {
    !s.contains('\n') && col + s.chars().count() <= MAX_WIDTH
}

/// Render a float the way the source spelled it back canonically: an integral
/// value keeps a single trailing `.0` (Elm requires the fractional part), and a
/// non-integral value uses Rust's shortest round-trip form.
fn format_float(f: f64) -> String {
    if f.fract() == 0.0 && f.is_finite() {
        format!("{f:.1}")
    } else {
        let s = format!("{f}");
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The comments of `src`, as the comment guard sees them.
    fn scan_comments(src: &str) -> Vec<Comment> {
        scan_trivia(src).map(|t| t.comments).unwrap_or_default()
    }

    /// `fmt(fmt(x)) == fmt(x)` over a spread of constructs.
    #[test]
    fn idempotent_over_constructs() {
        let inputs = [
            "module M exposing (x)\n\n\nx =\n    1\n",
            "module M exposing (r)\n\n\nr =\n    { a = 1, b = 2 }\n",
            "module M exposing (l)\n\n\nl =\n    [ 1, 2, 3 ]\n",
            "module M exposing (f)\n\n\nf x =\n    case x of\n        0 ->\n            \"z\"\n\n        _ ->\n            \"n\"\n",
            "module M exposing (R)\n\n\ntype alias R =\n    { a : Int\n\n    -- mid\n    , b : Int\n    }\n",
        ];
        for src in inputs {
            let once = format_source(src).expect("first pass formats");
            let twice = format_source(&once).expect("second pass");
            assert_eq!(once, twice, "not idempotent for input:\n{src}");
        }
    }

    /// Every comment in the input survives formatting.
    #[test]
    fn comments_are_preserved() {
        let src = "module M exposing (f, g)\n\
                   \n\
                   -- leading on f\n\
                   f =\n    1\n\
                   \n\
                   {- block before g -}\n\
                   g =\n    2\n";
        let out = format_source(src).expect("formats");
        assert!(out.contains("-- leading on f"), "line comment lost:\n{out}");
        assert!(
            out.contains("{- block before g -}"),
            "block comment lost:\n{out}"
        );
    }

    /// A comment written between two fields of a record TYPE (a `type alias`
    /// body) is preserved and the result is idempotent. This is the shipped
    /// `file-browser` shape that previously ICE'd the comment-count guard,
    /// because the record-type field name carried no span for the formatter to
    /// place an inter-field comment against.
    #[test]
    fn record_type_field_comment_is_preserved() {
        let src = "module M exposing (Model)\n\
                   \n\
                   \n\
                   type alias Model =\n\
                   \x20   { entries : List String\n\
                   \x20   , selected : Int\n\
                   \x20   , status : String\n\
                   \n\
                   \x20   -- The selected file's first bytes.\n\
                   \x20   , bytes : List Int\n\
                   \x20   }\n";
        let out = format_source(src).expect("record-field comment formats (was an ICE)");
        assert!(
            out.contains("-- The selected file's first bytes."),
            "inter-field record-type comment lost:\n{out}"
        );
        // The comment survives at its site AND the field ordering is intact.
        assert!(out.contains(", bytes : List Int"), "field lost:\n{out}");
        let twice = format_source(&out).expect("second pass formats");
        assert_eq!(out, twice, "not idempotent:\n{out}");
    }

    /// The comment-count guard is satisfied for a record-type inter-field
    /// comment: the output carries at least as many comments as the input, so
    /// `format_source` does not reject it. Pins the gap directly.
    #[test]
    fn record_type_inter_field_comment_count_is_not_reduced() {
        let src = "module M exposing (R)\n\
                   \n\
                   \n\
                   type alias R =\n\
                   \x20   { a : Int\n\
                   \n\
                   \x20   -- between a and b\n\
                   \x20   , b : Int\n\
                   \x20   }\n";
        let input_count = scan_comments(src).len();
        let out = format_source(src).expect("formats without dropping the comment");
        let output_count = scan_comments(&out).len();
        assert!(
            output_count >= input_count,
            "comment count fell from {input_count} to {output_count}:\n{out}"
        );
    }

    /// The semantics guard rejects nothing valid: a variety of programs all
    /// round-trip (the guard inside `format_source` would error otherwise).
    #[test]
    fn semantics_preserved_round_trip() {
        let src = "module Main exposing (main)\n\nimport Ipe.String as String\n\n\ntype Model\n    = Loading\n    | Ready Int\n\n\nmain : Model -> String\nmain model =\n    case model of\n        Loading ->\n            \"…\"\n\n        Ready n ->\n            String.fromInt n\n";
        // If the formatted output parsed to a different AST, `format_source`
        // returns `Err(RoundTrip)`. Success is the assertion.
        assert!(format_source(src).is_ok());
    }

    /// A negative numeric literal in argument (atom) position keeps its
    /// parentheses: printing `f (-5)` as bare `f -5` re-parses as the binary
    /// subtraction `f - 5`, so the round-trip guard inside `format_source` would
    /// reject it. Success (no `Err(RoundTrip)`) is the assertion, and the output
    /// retains the wrapping.
    #[test]
    fn negative_literal_argument_round_trips() {
        let cases = [
            "module M exposing (x)\n\n\nx =\n    f (-5)\n",
            "module M exposing (x)\n\n\nx =\n    f (-1.0)\n",
            "module M exposing (x)\n\n\nx =\n    g (-1) (-2)\n",
        ];
        for src in cases {
            let out = format_source(src).expect("negative-literal argument round-trips");
            assert!(
                out.contains("(-"),
                "negative literal lost its parens:\n{out}"
            );
            let twice = format_source(&out).expect("second pass formats");
            assert_eq!(out, twice, "not idempotent for input:\n{src}");
        }
    }

    /// A negative literal at TOP-LEVEL body / list-element position (not atom
    /// position) must NOT be over-parenthesised — the comma / definition already
    /// delimits it, so `x = -5` and `[ -5, -3 ]` stay bare and round-trip.
    #[test]
    fn negative_literal_not_over_parenthesised() {
        let bare = "module M exposing (x)\n\n\nx =\n    -5\n";
        let out = format_source(bare).expect("formats");
        assert_eq!(
            out, bare,
            "bare negative body must be a fixed point:\n{out}"
        );

        let list = "module M exposing (l)\n\n\nl =\n    [ -5, -3 ]\n";
        let out = format_source(list).expect("formats");
        assert!(
            !out.contains("[ (-"),
            "list element must not be parenthesised:\n{out}"
        );
    }

    /// `scan_comments` does not mistake a `--` inside a string for a comment.
    #[test]
    fn comment_scan_ignores_string_contents() {
        let comments = scan_comments("x = \"a -- b\" {- real -}\n");
        assert_eq!(comments.len(), 1);
        assert_eq!(
            comments.first().map(|c| c.text.as_str()),
            Some("{- real -}")
        );
    }

    /// `format_source_unchecked` and the checked path agree on well-formed
    /// input (the guard is transparent when the formatter is correct).
    #[test]
    fn unchecked_matches_checked() {
        let src = "module M exposing (x)\n\n\nx =\n    1\n";
        assert_eq!(
            format_source(src).unwrap(),
            format_source_unchecked(src).unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // Comment-preservation tests — each proves a specific comment site
    // -----------------------------------------------------------------------

    /// The minimal repro from the issue: a comment between a type annotation
    /// and the binding name must survive. `main : Int\n-- c\nmain = 42`.
    #[test]
    fn comment_between_annotation_and_definition_survives() {
        let src = "module M exposing (main)\n\n\nmain : Int\n-- c\nmain =\n    42\n";
        let out = format_source(src).expect("formats");
        assert!(
            out.contains("-- c"),
            "comment between annotation and definition was dropped:\n{out}"
        );
        // Idempotent.
        let twice = format_source(&out).expect("second pass");
        assert_eq!(out, twice, "not idempotent:\n{out}");
    }

    /// A block comment between annotation and definition also survives.
    #[test]
    fn block_comment_between_annotation_and_definition_survives() {
        let src = "module M exposing (f)\n\n\nf : Int\n{- block -}\nf =\n    1\n";
        let out = format_source(src).expect("formats");
        assert!(
            out.contains("{- block -}"),
            "block comment between annotation and definition was dropped:\n{out}"
        );
        let twice = format_source(&out).expect("second pass");
        assert_eq!(out, twice, "not idempotent:\n{out}");
    }

    /// A comment written between two `case` arms survives at the arm indent.
    #[test]
    fn comment_between_case_arms_survives() {
        let src = "module M exposing (f)\n\n\nf x =\n    case x of\n        0 ->\n            \"zero\"\n\n        -- separates arms\n        _ ->\n            \"other\"\n";
        let out = format_source(src).expect("formats");
        assert!(
            out.contains("-- separates arms"),
            "inter-arm comment was dropped:\n{out}"
        );
        let twice = format_source(&out).expect("second pass");
        assert_eq!(out, twice, "not idempotent:\n{out}");
    }

    /// A comment written between two `let` bindings survives at the binding
    /// indent.
    #[test]
    fn comment_between_let_bindings_survives() {
        let src = "module M exposing (f)\n\n\nf =\n    let\n        x =\n            1\n\n        -- between bindings\n        y =\n            2\n    in\n    x\n";
        let out = format_source(src).expect("formats");
        assert!(
            out.contains("-- between bindings"),
            "inter-binding comment was dropped:\n{out}"
        );
        let twice = format_source(&out).expect("second pass");
        assert_eq!(out, twice, "not idempotent:\n{out}");
    }

    /// A comment between the `type alias` head and the body type survives.
    #[test]
    fn comment_between_alias_head_and_body_survives() {
        let src = "module M exposing (A)\n\n\ntype alias A =\n    -- body comment\n    Int\n";
        let out = format_source(src).expect("formats");
        assert!(
            out.contains("-- body comment"),
            "alias body comment was dropped:\n{out}"
        );
        let twice = format_source(&out).expect("second pass");
        assert_eq!(out, twice, "not idempotent:\n{out}");
    }

    /// `fmt` never reduces the comment count: the output comment count must be
    /// >= the input comment count for every construct with inline comments.
    #[test]
    fn comment_count_never_decreases() {
        let cases = [
            // annotation gap
            "module M exposing (main)\n\n\nmain : Int\n-- c\nmain =\n    42\n",
            // case arm gap
            "module M exposing (f)\n\n\nf x =\n    case x of\n        0 ->\n            \"z\"\n\n        -- arm sep\n        _ ->\n            \"n\"\n",
            // let binding gap
            "module M exposing (f)\n\n\nf =\n    let\n        x =\n            1\n\n        -- bind sep\n        y =\n            2\n    in\n    x\n",
            // top-level leading comment
            "module M exposing (x)\n\n\n-- top\nx =\n    1\n",
            // trailing comment
            "module M exposing (x)\n\n\nx =\n    1\n\n-- trail\n",
        ];
        for src in cases {
            let input_count = scan_comments(src).len();
            let out = format_source(src).expect("formats");
            let output_count = scan_comments(&out).len();
            assert!(
                output_count >= input_count,
                "comment count decreased from {input_count} to {output_count} for:\n{src}\noutput:\n{out}"
            );
        }
    }

    /// `fmt(fmt(x)) == fmt(x)` AND both passes preserve every comment — the
    /// combined idempotency + comment-preservation fixed-point assertion.
    #[test]
    fn idempotent_and_comment_preserving() {
        let cases = [
            "module M exposing (main)\n\n\nmain : Int\n-- c\nmain =\n    42\n",
            "module M exposing (f)\n\n\nf x =\n    case x of\n        0 ->\n            \"z\"\n\n        -- arm comment\n        _ ->\n            \"n\"\n",
            "module M exposing (f)\n\n\nf =\n    let\n        x =\n            1\n\n        -- bind comment\n        y =\n            2\n    in\n    x\n",
        ];
        for src in cases {
            let once = format_source(src).expect("first pass");
            let twice = format_source(&once).expect("second pass");
            assert_eq!(once, twice, "not idempotent for:\n{src}");
            // Every comment present in the input is present in the output.
            for c in scan_comments(src) {
                assert!(
                    once.contains(&c.text),
                    "comment {:?} lost after fmt for:\n{src}\noutput:\n{once}",
                    c.text
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // `do` blocks — the printer re-sugars the parser's desugared chain
    // -----------------------------------------------------------------------

    /// Wrap `body` (already indented for a top-level definition) as a module.
    fn do_module(body: &str) -> String {
        format!("module M exposing (main)\n\n\nmain =\n{body}")
    }

    /// Format `src` and assert a fixed point that is still a `do` block.
    ///
    /// Returns the first pass's output.
    fn assert_do_round_trips(src: &str) -> String {
        let once = format_source(src).expect("do block formats");
        let twice = format_source(&once).expect("formatted do block re-formats");
        assert_eq!(once, twice, "not idempotent for:\n{src}\noutput:\n{once}");
        assert!(once.contains("do\n"), "`do` form lost:\n{once}");
        once
    }

    /// The reported ICE: a bare-run line and a wildcard bind in a `do` block.
    ///
    /// The bare run desugars to `let _ = task in …`, which the printer used to
    /// emit verbatim and the re-parse rejected with
    /// `MalformedLet(BareWildcardBinding)`.
    #[test]
    fn do_wildcard_bind_and_bare_run_round_trip() {
        let src = do_module(
            "    do\n        x <- Task.succeed 1\n        _ <- Task.succeed 2\n        Io.println \"run\"\n        Task.succeed x\n",
        );
        let out = assert_do_round_trips(&src);
        assert_eq!(out, src, "canonical do block must be a fixed point");
    }

    /// Every statement shape the `do` grammar admits survives in source order.
    ///
    /// Named bind, wildcard bind, bare run, pure `name =`, pure `_ =`.
    #[test]
    fn do_every_statement_shape_is_a_fixed_point() {
        let src = do_module(
            "    do\n        a <- Task.succeed 1\n        _ <- Task.succeed 2\n        Io.println \"step\"\n        b = a + 1\n        _ = b\n        Task.succeed b\n",
        );
        let out = assert_do_round_trips(&src);
        assert_eq!(out, src, "canonical do block must be a fixed point");
    }

    /// Each statement shape is recognised in leading position.
    ///
    /// The first statement's node carries the `do` span, not its own.
    #[test]
    fn do_each_shape_in_leading_position() {
        let leads = [
            "x <- Task.succeed 1",
            "_ <- Task.succeed 1",
            "Io.println \"first\"",
            "x = 1",
            "_ = 1",
        ];
        for lead in leads {
            let src = do_module(&format!("    do\n        {lead}\n        Task.succeed 0\n"));
            let out = assert_do_round_trips(&src);
            assert_eq!(out, src, "leading `{lead}` must be a fixed point");
        }
    }

    /// A single-statement `do` keeps its keyword.
    #[test]
    fn do_single_statement_round_trips() {
        let src = do_module("    do\n        Task.succeed 0\n");
        let out = assert_do_round_trips(&src);
        assert_eq!(out, src, "single-statement do must be a fixed point");
    }

    /// Nested `do` blocks each stay their own block.
    ///
    /// Covers result position, a bind's task, a bare run, and a lambda body.
    #[test]
    fn do_nested_blocks_round_trip() {
        let nested = [
            "    do\n        x <- Task.succeed 1\n        do\n            y <- Task.succeed x\n            Task.succeed y\n",
            "    do\n        x <- do\n            Io.println \"inner\"\n            Task.succeed 1\n        Task.succeed x\n",
            "    do\n        do\n            Io.println \"inner\"\n            Task.succeed 1\n        Task.succeed 2\n",
        ];
        for body in nested {
            let out = assert_do_round_trips(&do_module(body));
            assert_eq!(
                out.matches("do\n").count(),
                2,
                "nested do flattened or lost:\n{out}"
            );
        }
        let in_lambda = "    Task.andThen\n        (\\x ->\n            do\n                Io.println \"in lambda\"\n                Task.succeed x\n        )\n        (Task.succeed 1)\n";
        assert_do_round_trips(&do_module(in_lambda));
    }

    /// A `do` block in atom position keeps its parentheses.
    ///
    /// Bare, its statement layout would swallow the following argument or
    /// operator line.
    #[test]
    fn do_in_atom_position_round_trips() {
        let cases = [
            "    f\n        (do\n            Io.println \"arg\"\n            Task.succeed 1\n        )\n        y\n",
            "    (do\n        Io.println \"operand\"\n        Task.succeed 1\n    )\n        |> Task.map f\n",
        ];
        for body in cases {
            let out = assert_do_round_trips(&do_module(body));
            assert!(
                out.contains("(do\n"),
                "do in atom position lost its parens:\n{out}"
            );
        }
    }

    /// Block-form expressions as statement tasks, bind sources, and results.
    ///
    /// `case`, `if`, and `let` layouts must not collide with statement
    /// alignment.
    #[test]
    fn do_block_form_statements_round_trip() {
        let cases = [
            "    do\n        x <- case m of\n            Just v ->\n                Task.succeed v\n\n            Nothing ->\n                Task.succeed 0\n        Task.succeed x\n",
            "    do\n        x <- if c then\n            Task.succeed 1\n\n        else\n            Task.succeed 2\n        Task.succeed x\n",
            "    do\n        Io.println \"run\"\n        let\n            y =\n                1\n        in\n        Task.succeed y\n",
        ];
        for body in cases {
            assert_do_round_trips(&do_module(body));
        }
    }

    /// A comment between two statements keeps its place in the block.
    #[test]
    fn do_comment_between_statements_survives() {
        let src = do_module(
            "    do\n        x <- Task.succeed 1\n        -- between statements\n        Io.println \"run\"\n        Task.succeed x\n",
        );
        let out = assert_do_round_trips(&src);
        assert_eq!(out, src, "commented do block must be a fixed point");
    }

    /// A tuple or record destructure before `<-` is refused as a parse error.
    ///
    /// The `do` grammar admits only a lowercase name or `_` there.
    #[test]
    fn do_destructuring_bind_is_refused() {
        for binder in ["( a, b )", "{ a }"] {
            let src = do_module(&format!(
                "    do\n        {binder} <- t\n        Task.succeed a\n"
            ));
            assert!(
                matches!(format_source(&src), Err(FmtError::Parse { .. })),
                "destructuring `{binder} <-` must be refused as a parse error"
            );
        }
    }

    /// A whole-pattern `let _ =` outside a `do` stays refused.
    ///
    /// Re-sugaring does not widen what the formatter accepts.
    #[test]
    fn bare_wildcard_let_outside_do_is_refused() {
        let src = do_module("    let\n        _ =\n            1\n    in\n    2\n");
        assert!(
            matches!(format_source(&src), Err(FmtError::Parse { .. })),
            "`let _ =` outside a do must stay a parse error"
        );
    }

    /// #3034: a comment between a `do` block's opening paren and its `do`
    /// keyword used to hide the keyword from `do_keyword_end`'s text match,
    /// falling through to the raw printer and emitting an illegal bare
    /// wildcard `let` for the block's run statement — `IPE-I0001
    /// MalformedLet(BareWildcardBinding)`. `do_keyword_end` now skips
    /// comments (like parens and whitespace) while looking for the keyword.
    #[test]
    fn do_comment_before_keyword_in_parens_round_trips() {
        let src = do_module(
            "    Cmd.perform\n        ( -- comment before do\n        do\n            db <- reviewDb\n            recordDrain db\n            loadQueue\n        )\n        PendingLoaded\n",
        );
        let out = assert_do_round_trips(&src);
        assert!(
            out.contains("-- comment before do"),
            "comment before `do` keyword was dropped:\n{out}"
        );
    }

    /// A block comment between a `do` block's opening paren and its `do`
    /// keyword is tolerated the same way a line comment is.
    #[test]
    fn do_block_comment_before_keyword_in_parens_round_trips() {
        let src = do_module(
            "    Cmd.perform\n        ( {- note -}\n        do\n            db <- reviewDb\n            loadQueue\n        )\n        PendingLoaded\n",
        );
        let out = assert_do_round_trips(&src);
        assert!(
            out.contains("{- note -}"),
            "block comment before `do` keyword was dropped:\n{out}"
        );
    }

    // -----------------------------------------------------------------------
    // #3201: do-notation render cost stays linear in statement count
    // -----------------------------------------------------------------------

    /// A `do` block with `n` heterogeneous bind statements — the desugared
    /// shape (nested `Task.andThen (\x -> REST) task`) that triggers
    /// #3201 when the one-vs-block layout decision re-renders a subtree on
    /// every enclosing level instead of once. The statement shapes cycle
    /// through a plain bind, a pipe-chain-with-lambdas bind, a bare
    /// qualified-name bind, a single-call bind, and a nested-call bind, so
    /// the fixture exercises the same heterogeneity as the reported file
    /// rather than one repetitive shape.
    fn pathological_do_block(n: usize) -> String {
        let mut out = String::from("    do\n");
        for i in 0..n {
            let line = match i % 5 {
                0 => format!("        v{i} <- Task.succeed {i}\n"),
                1 => format!(
                    "        v{i} <- Queue.resyncReviewedWithin {{ pageSize = 5, pageCeiling = {i} }} \"db\"\n            |> Task.map (\\_ -> Nothing)\n            |> Task.onError (\\e -> Task.succeed (Just (Error.toString e)))\n"
                ),
                2 => format!("        v{i} <- Index.loadProgress\n"),
                3 => format!("        v{i} <- Db.open \"sqlite\" \"sqlite://z\"\n"),
                _ => format!(
                    "        v{i} <- Db.findWhere \"conn\" \"reviewed\" (Sql.eq (Sql.column \"uid\") (Sql.string \"pre\"))\n"
                ),
            };
            out.push_str(&line);
        }
        let _ = writeln!(out, "        Task.succeed v{}", n - 1);
        out
    }

    /// The render-call work counter grows linearly, not exponentially, as
    /// the statement count grows — the class-closing property for #3201.
    ///
    /// `call`/`lambda` used to re-render an already-rendered argument/body to
    /// decide one-line-vs-block layout, and that re-render happened at every
    /// enclosing level of the desugared bind chain, compounding
    /// multiplicatively with nesting depth. Quadrupling the statement count
    /// (6 to 24) should roughly quadruple the render-call count; a regression
    /// back to the old behaviour blows this past any generous linear bound
    /// (and, in practice, times out long before the assertion runs). Measured
    /// via a work counter, never wall time, so the test cannot flake on a
    /// loaded machine.
    #[test]
    fn do_notation_render_cost_is_linear_in_statement_count() {
        let small = do_module(&pathological_do_block(6));
        let big = do_module(&pathological_do_block(24));

        reset_render_call_count();
        format_source(&small).expect("small pathological do block formats");
        let small_calls = render_call_count();

        reset_render_call_count();
        format_source(&big).expect("big pathological do block formats");
        let big_calls = render_call_count();

        assert!(
            big_calls <= small_calls * 20,
            "render-call count grew super-linearly with statement count: \
             {small_calls} calls at 6 statements, {big_calls} calls at 24 statements"
        );
    }

    // -----------------------------------------------------------------------
    // Let-binding pattern forms — the class-closing round-trip
    // -----------------------------------------------------------------------

    /// Every let-binding pattern form the parser accepts round-trips through
    /// the printer: a plain name, a tuple destructure, a record destructure, a
    /// parenthesised constructor destructure, and a wildcard nested inside a
    /// larger pattern. A bare whole-pattern `_` binder stays refused (see
    /// `bare_wildcard_let_outside_do_is_refused`) — nested is the only legal
    /// wildcard shape in `let` position, so it is exercised here instead.
    #[test]
    fn let_binding_pattern_forms_round_trip() {
        let cases = [
            "v =\n            1\n",
            "( a, b ) =\n            pair\n",
            "{ a, b } =\n            rec\n",
            "(Just v) =\n            maybeVal\n",
            "( a, _ ) =\n            pair\n",
        ];
        for binder in cases {
            let src = do_module(&format!("    let\n        {binder}    in\n    2\n"));
            let out = format_source(&src).expect("let-binding pattern form round-trips");
            let twice = format_source(&out).expect("second pass formats");
            assert_eq!(out, twice, "not idempotent for:\n{src}\noutput:\n{out}");
        }
    }

    /// There is no `name : Type` annotation line inside a `let` block — unlike
    /// a top-level definition, a `let` binding carries no separate annotation
    /// slot in the grammar, so this stays a parse error rather than a
    /// let-binding pattern form the printer must round-trip.
    #[test]
    fn annotated_let_binding_is_refused() {
        let src =
            do_module("    let\n        v : Int\n        v =\n            1\n    in\n    v\n");
        assert!(
            matches!(format_source(&src), Err(FmtError::Parse { .. })),
            "a `name : T` line inside `let` is not grammar; it must stay a parse error"
        );
    }

    // -----------------------------------------------------------------------
    // Surface fidelity — a desugared node prints as the sugar it was written as
    // -----------------------------------------------------------------------

    /// Format `src`, assert it is already canonical, and assert a second pass
    /// changes nothing.
    fn assert_fixed_point(src: &str) {
        let once = format_source(src).expect("formats");
        assert_eq!(once, src, "not canonical:\n--- got:\n{once}");
        let twice = format_source(&once).expect("second pass formats");
        assert_eq!(twice, once, "not idempotent:\n--- got:\n{twice}");
    }

    /// A field accessor prints as `.a.b`, never as the getter lambda the
    /// parser lowers it to, and is a fixed point in argument and value
    /// position alike.
    #[test]
    fn field_accessor_prints_as_written() {
        let src = "module M exposing (deep, names)\n\n\nnames xs =\n    List.map .name xs\n\n\ndeep =\n    .a.b\n";
        assert_fixed_point(src);
        let wide = "module M exposing (f)\n\n\nf xs =\n    List.map\n        .name\n        xs\n";
        let out = format_source(wide).expect("formats");
        assert!(
            !out.contains("ipe_accessor_arg"),
            "accessor desugared:\n{out}"
        );
        assert_eq!(format_source(&out).expect("second pass"), out);
    }

    /// A hand-written getter lambda is not the accessor sugar: it stays a
    /// lambda.
    #[test]
    fn written_getter_lambda_stays_a_lambda() {
        let src = "module M exposing (f)\n\n\nf =\n    \\ipe_accessor_arg -> ipe_accessor_arg.a\n";
        assert_fixed_point(src);
    }

    /// A negation prints as `-e` and a local function keeps its parameters
    /// on the binder; neither prints its desugared form.
    #[test]
    fn negation_and_local_function_print_as_written() {
        let src = "module M exposing (f)\n\n\nf x =\n    let\n        k z =\n            -z\n    in\n    k x\n";
        assert_fixed_point(src);
        let out = format_source(src).expect("formats");
        assert!(!out.contains("Basics.negate"), "negation desugared:\n{out}");
    }

    /// Every character a char or string literal can hold prints back as a
    /// literal that lexes to the same value; a backslash char printed bare
    /// (`'\'`) would not lex at all.
    #[test]
    fn escaped_literals_round_trip() {
        let src = "module M exposing (cs, s)\n\n\ncs =\n    [ '\\\\', '\"', '\\'', '\\n', '\\t', '\\r', '\\0' ]\n\n\ns =\n    \"q\\\" b\\\\ a' n\\n\"\n";
        assert_fixed_point(src);
    }

    /// Every escapable value in a char PATTERN prints back as a literal
    /// that lexes to the same value, exactly as it does in expression
    /// position.
    #[test]
    fn escaped_char_patterns_round_trip() {
        let src = "module M exposing (f)\n\n\nf c =\n    case c of\n        '\\n' ->\n            0\n\n        '\\t' ->\n            1\n\n        '\\r' ->\n            2\n\n        '\\\\' ->\n            3\n\n        '\"' ->\n            4\n\n        '\\'' ->\n            5\n\n        '\\0' ->\n            6\n\n        _ ->\n            7\n";
        assert_fixed_point(src);
    }

    /// Every escapable value in a string PATTERN prints back as a literal
    /// that lexes to the same value; a bare `'` inside a string pattern
    /// stays unescaped.
    #[test]
    fn escaped_str_patterns_round_trip() {
        let src = "module M exposing (f)\n\n\nf s =\n    case s of\n        \"\\0\" ->\n            0\n\n        \"a\\\"b\\\\c\" ->\n            1\n\n        \"line\\ntab\\t\" ->\n            2\n\n        \"cr\\r\" ->\n            3\n\n        \"it's\" ->\n            4\n\n        _ ->\n            5\n";
        assert_fixed_point(src);
    }

    /// `"\0"` formats as the two-character escape `\0`, never a raw NUL
    /// byte spliced into the source (a raw NUL still re-lexes to the same
    /// value, so `assert_fixed_point` alone would not catch it).
    #[test]
    fn nul_string_literal_formats_as_its_escape() {
        let src = "module M exposing (s)\n\n\ns =\n    \"\\0\"\n";
        assert_fixed_point(src);
        let out = format_source(src).expect("formats");
        assert!(
            !out.contains('\0'),
            "raw NUL byte in formatted output:\n{out}"
        );
    }

    /// A `foreign` declaration is printed, never silently deleted.
    #[test]
    fn foreign_declarations_are_kept() {
        let src = "module M exposing (Counter, update)\n\n\nforeign Counter =\n    { crate = \"iced\"\n    , kind = Struct { value = Int }\n    }\n\n\nforeign update : Ffi.Fn =\n    { crate = \"iced\" }\n";
        assert_fixed_point(src);
    }

    // -----------------------------------------------------------------------
    // Comment attachment — every comment prints with the node it precedes
    // -----------------------------------------------------------------------

    /// A comment between two imports travels with the import below it
    /// through the import sort.
    #[test]
    fn comment_between_imports_travels_with_its_import() {
        let src = "module M exposing (x)\n\nimport B\n-- about A\nimport A\n\n\nx =\n    1\n";
        let out = format_source(src).expect("formats");
        assert_eq!(
            out,
            "module M exposing (x)\n\n-- about A\nimport A\nimport B\n\n\nx =\n    1\n"
        );
        assert_eq!(format_source(&out).expect("second pass"), out);
    }

    /// The comment shapes of a real escaping module: a module doc comment
    /// above the imports, a comment between `in` and the `let` body, comments
    /// after `'\\'` and `'"'` char literals, and comments heading case-arm
    /// bodies.
    #[test]
    fn escaping_module_comment_shapes_are_kept_in_place() {
        let src = "module M exposing (esc, next)\n\n{-| Escaping helpers. -}\n\nimport Ipe.String as String\n\n\nesc c =\n    let\n        backslash =\n            '\\\\'\n    in\n    -- the body\n    case c of\n        '\"' ->\n            -- a quote\n            \"q\"\n\n        _ ->\n            -- anything else\n            String.fromChar backslash\n\n\nnext =\n    2\n";
        assert_fixed_point(src);
        let out = format_source(src).expect("formats");
        let body = out.find("-- the body").expect("body comment kept");
        let next = out.find("next =").expect("next kept");
        assert!(
            body < next,
            "a body comment moved to the next declaration:\n{out}"
        );
    }

    /// A comment above a pipeline step, a list element, or the first case
    /// arm stays directly above it.
    #[test]
    fn comments_inside_expressions_stay_with_their_node() {
        let src = "module M exposing (f, l, p)\n\n\np xs =\n    xs\n        -- keep the evens\n        |> List.filter isEven\n        |> List.map double\n\n\nl =\n    [ 1\n    -- two\n    , 2\n\n    -- end\n    ]\n\n\nf x =\n    case x of\n        -- zero\n        0 ->\n            \"z\"\n\n        _ ->\n            \"n\"\n";
        let out = format_source(src).expect("formats");
        for c in scan_comments(src) {
            assert!(out.contains(&c.text), "comment {:?} lost:\n{out}", c.text);
        }
        assert_eq!(format_source(&out).expect("second pass"), out);
        let keep = out.find("-- keep the evens").expect("pipeline comment");
        let filter = out.find("|> List.filter").expect("filter step");
        assert!(keep < filter, "pipeline comment moved:\n{out}");
    }

    /// A comment inside a type annotation, among a definition's parameters,
    /// or inside a pattern prints above its line rather than being lost.
    #[test]
    fn comments_in_heads_print_above_the_head() {
        let src = "module M exposing (f)\n\n\nf :\n    Int\n    -- the result\n    -> Int\nf x =\n    case x of\n        Just -- inner\n            y ->\n            y\n\n        _ ->\n            0\n";
        let out = format_source(src).expect("formats");
        for c in scan_comments(src) {
            assert!(out.contains(&c.text), "comment {:?} lost:\n{out}", c.text);
        }
        assert_eq!(format_source(&out).expect("second pass"), out);
    }

    /// The comment guard compares comment TEXTS: an output that kept the count
    /// but changed a comment is refused, and so is one that lost a comment.
    #[test]
    fn comment_guard_refuses_a_changed_or_lost_comment() {
        let input = scan_comments("-- a\n{- b -}\n");
        let changed = scan_comments("-- a\n{- c -}\n");
        assert_ne!(comment_multiset(&input), comment_multiset(&changed));
        let reordered = scan_comments("{- b -}\n-- a\n");
        assert_eq!(comment_multiset(&input), comment_multiset(&reordered));
        assert!(scan_comments("-- a\n").len() < input.len());
    }

    /// A module whose one value is a list of `items` ones, written on one
    /// line two lets deep: the formatter puts every item on its own line at
    /// that depth, so each two-byte item grows to over twenty output bytes.
    fn nested_long_list(items: usize) -> String {
        let ones = vec!["1"; items].join(",");
        format!(
            "module M exposing (x)\n\n\nx =\n    let\n        y =\n            let\n                z =\n                    [ {ones}\n                    ]\n            in\n            z\n    in\n    y\n"
        )
    }

    /// The output one more item of [`nested_long_list`] adds, measured on
    /// inputs small enough to format under the floor.
    fn nested_long_list_growth_per_item() -> usize {
        let small = format_source(&nested_long_list(200)).expect("formats under the floor");
        let large = format_source(&nested_long_list(400)).expect("formats under the floor");
        large.len().saturating_sub(small.len()) / 200
    }

    /// An input whose rendering passes eight times its size is refused with
    /// the cap for that input, while the same shape at a size under the floor
    /// formats.
    #[test]
    fn output_cap_refuses_past_cap() {
        let growth = nested_long_list_growth_per_item();
        assert!(
            growth > 2 * OutputCap::GROWTH,
            "precondition: an item of two input bytes must grow past the cap, got {growth}"
        );
        let src = nested_long_list(10_000);
        let cap = OutputCap::for_input(src.len());
        assert_eq!(cap.bytes(), src.len() * OutputCap::GROWTH);
        let refused = format_source(&src);
        assert!(
            matches!(refused, Err(FmtError::Limit(FmtLimit::OutputBytes { cap: c })) if c == cap),
            "{refused:?}"
        );
    }

    /// One byte under the output's length refuses; the output's length admits.
    #[test]
    fn output_cap_refuses_one_byte_past_the_output() {
        let src = "module M exposing (x)\n\n\nx =\n    [ 1, 2, 3 ]\n";
        let out = format_source(src).expect("formats");
        let tight = OutputCap(out.len());
        assert_eq!(
            format_source_capped(src, tight).ok().as_deref(),
            Some(out.as_str())
        );
        let short = OutputCap(out.len() - 1);
        let refused = format_source_capped(src, short);
        assert!(
            matches!(refused, Err(FmtError::Limit(FmtLimit::OutputBytes { cap })) if cap == short),
            "{refused:?}"
        );
    }

    /// A module whose one value is a list of `items` names written on one line
    /// `depth` lets deep: the formatter puts every name on its own line at
    /// that depth, so the indentation of each line dominates the output.
    fn nested_deep_list(depth: usize, items: usize) -> String {
        let names = vec!["aaaaaaaaaaaaaaa"; items].join(",");
        let mut head = String::from("module M exposing (x)\n\n\nx =\n");
        let mut tail = String::new();
        for k in 0..depth {
            let b = " ".repeat(4 + 8 * k);
            let _ = write!(head, "{b}let\n{b}    v{k} =\n");
            tail = format!("{b}in\n{b}v{k}\n{tail}");
        }
        let b = " ".repeat(4 + 8 * depth);
        format!("{head}{b}[ {names}\n{b}]\n{tail}")
    }

    /// An 8 MiB source whose layout repeats one deep indentation on every
    /// line is refused, and the indentation past the cap is never rendered:
    /// the printer's text stays within the cap plus the source's own bytes
    /// twice, where rendering every pad would hold over 100 MiB.
    #[test]
    fn pad_past_the_cap_is_refused_unrendered() {
        let src = nested_deep_list(24, (8 << 20) / 16);
        let cap = OutputCap::for_input(src.len());
        assert_eq!(cap.bytes(), OutputCap::CEILING);
        let rendered = Cell::new(0usize);
        let refused = format_guarded(&src, cap, |p, m| {
            let out = p.module(m);
            rendered.set(out.len());
            out
        });
        assert!(
            matches!(refused, Err(FmtError::Limit(FmtLimit::OutputBytes { cap: c })) if c == cap),
            "{refused:?}"
        );
        let bound = cap.bytes() + 2 * src.len();
        assert!(
            rendered.get() <= bound,
            "the printer rendered {} bytes past the pad budget (bound {bound})",
            rendered.get()
        );
    }

    /// The same shape small enough to fit formats under a cap of exactly its
    /// output, pads included, and refuses one byte under it.
    #[test]
    fn deep_list_formats_at_its_exact_output_cap() {
        let src = nested_deep_list(24, 40);
        let out = format_source(&src).expect("a small deep list formats");
        assert!(
            out.contains(&format!("\n{}, aaaaaaaaaaaaaaa", INDENT_UNIT.repeat(49))),
            "precondition: the items sit 49 levels deep: {out}"
        );
        let exact = OutputCap(out.len());
        assert_eq!(
            format_source_capped(&src, exact).ok().as_deref(),
            Some(out.as_str())
        );
        let short = OutputCap(out.len() - 1);
        let refused = format_source_capped(&src, short);
        assert!(
            matches!(refused, Err(FmtError::Limit(FmtLimit::OutputBytes { cap })) if cap == short),
            "{refused:?}"
        );
    }

    /// A pad renders only while the budget holds its bytes; once one does not
    /// fit, every later pad renders empty and the budget stays exceeded.
    #[test]
    fn pad_budget_charges_every_rendering() {
        let budget = PadBudget::new(OutputCap(8));
        let pad = budget.pad(1);
        assert_eq!(format!("{pad}{pad}"), "        ");
        assert!(!budget.exceeded());
        assert_eq!(format!("{pad}"), "");
        assert!(budget.exceeded());
        assert_eq!(format!("{}", budget.pad(0)), "");
        assert!(budget.exceeded());
    }

    /// The cap stops at 16 MiB: a 3 MiB input may not grow to 24 MiB.
    #[test]
    fn output_cap_is_sixteen_mib_at_most() {
        assert_eq!(OutputCap::for_input(3 << 20).bytes(), 16 << 20);
        assert_eq!(OutputCap::for_input(2 << 20).bytes(), 16 << 20);
        assert_eq!(OutputCap::for_input((2 << 20) - 1).bytes(), (16 << 20) - 8);
        assert_eq!(OutputCap::for_input(usize::MAX).bytes(), 16 << 20);
    }

    /// A tiny input may still produce 64 KiB, so the cap never refuses a small
    /// file or an empty one.
    #[test]
    fn output_cap_floor_admits_tiny_input() {
        assert_eq!(OutputCap::for_input(7).bytes(), 64 << 10);
        assert_eq!(OutputCap::for_input(0).bytes(), 64 << 10);
        assert_eq!(OutputCap::for_input(8 << 10).bytes(), 64 << 10);
        assert_eq!(OutputCap::for_input((8 << 10) + 1).bytes(), (64 << 10) + 8);
        let src = "module M exposing (x)\n\n\nx =\n    1\n";
        let blank_tail = "\n".repeat(src.len() * OutputCap::GROWTH);
        let padded = format_guarded(src, OutputCap::for_input(src.len()), |p, m| {
            format!("{}{blank_tail}", p.module(m))
        });
        assert!(
            matches!(&padded, Ok(out) if out.len() > src.len() * OutputCap::GROWTH),
            "the floor admits a tiny input's output past eight times its size: {padded:?}"
        );
        assert!(OutputCap::for_input(0).admits(""));
    }

    /// The `RoundTrip` detail of formatting `src` with `render`.
    fn refusal(src: &str, render: impl FnOnce(&Printer<'_>, &Module) -> String) -> String {
        match format_guarded(src, OutputCap::for_input(src.len()), render) {
            Err(FmtError::RoundTrip { detail }) => detail,
            other => format!("not a refusal: {other:?}"),
        }
    }

    /// A renderer that loses, rewrites or adds a comment is refused by the
    /// guards `format_source` runs, and so is one that changes the program.
    #[test]
    fn format_guards_refuse_a_faulty_renderer() {
        let src = "module M exposing (x)\n\n\n-- about x\nx =\n    1\n";
        let good = format_source(src).expect("formats");
        assert_eq!(good, src);
        let dropped = refusal(src, |p, m| p.module(m).replace("-- about x\n", ""));
        assert!(
            dropped.starts_with("formatter dropped comments"),
            "{dropped}"
        );
        let changed = refusal(src, |p, m| p.module(m).replace("about x", "about y"));
        assert!(
            changed.starts_with("formatter changed comments"),
            "{changed}"
        );
        let added = refusal(src, |p, m| format!("{}-- extra\n", p.module(m)));
        assert!(added.starts_with("formatter changed comments"), "{added}");
        let meaning = refusal(src, |p, m| p.module(m).replace("    1", "    2"));
        assert_eq!(meaning, "formatted output parsed to a different AST");
    }

    /// A triple-quoted string strips the margin of its anchor column from
    /// every later line, so moving it to another column changes its value:
    /// the formatter refuses rather than printing the moved string.
    #[test]
    fn a_triple_quoted_string_moved_to_another_margin_is_refused() {
        let src = "module M exposing (x)\n\n\nx =\n    foo  \"\"\"abc\n            def\"\"\"\n";
        let detail = match format_source(src) {
            Err(FmtError::RoundTrip { detail }) => detail,
            other => format!("not a refusal: {other:?}"),
        };
        assert_eq!(detail, "formatted output parsed to a different AST");
    }

    /// A one-line triple-quoted string has no margin, so its column is free.
    #[test]
    fn a_one_line_triple_quoted_string_moves_freely() {
        let src = "module M exposing (x)\n\n\nx =\n    let\n        msg = \"\"\"n={{n}}\"\"\"\n    in\n    msg\n";
        let once = format_source(src).expect("formats");
        assert_eq!(format_source(&once).expect("second pass"), once);
    }

    /// The structural projection erases positions and resolves symbols, but
    /// never rewrites inside a string literal.
    #[test]
    fn module_tree_erases_positions_outside_strings_only() {
        let mut interner = Interner::new();
        let name = interner.intern("name").expect("interns");
        let debug = format!(
            "Located {{ span: Span {{ lo: 3, hi: 9 }}, value: {name:?} }} {:?}",
            "Span { lo: 1, hi: 2 } Symbol(0) anchor: 4"
        );
        assert_eq!(
            erase_positions(&debug, &interner).as_deref(),
            Some(
                "Located { span: _, value: Symbol(\"name\") } \"Span { lo: 1, hi: 2 } Symbol(0) anchor: 4\""
            )
        );
        assert_eq!(erase_positions("Symbol(99)", &interner), None);
        assert_eq!(erase_positions("\"open", &interner), None);
    }

    /// Comments above the first import keep their source spacing, so an
    /// import sorted to the front prints the same on every pass.
    #[test]
    fn comments_above_the_first_import_keep_their_spacing() {
        for src in [
            "module M exposing (x)\n\n-- about A\nimport A\nimport B\n\n\nx =\n    1\n",
            "module M exposing (x)\n\n{-| Doc. -}\n\nimport A\nimport B\n\n\nx =\n    1\n",
        ] {
            assert_fixed_point(src);
        }
    }

    /// A comment marker inside a char literal is not a comment.
    #[test]
    fn comment_scan_ignores_char_contents() {
        let comments = scan_comments("x = '\\\\' -- real\ny = '-'\n");
        let texts: Vec<&str> = comments.iter().map(|c| c.text.as_str()).collect();
        assert_eq!(texts, vec!["-- real"]);
    }

    /// A single-line lambda whose body breaks when printed takes the block
    /// form on the first pass, the form its now multi-line span selects on
    /// the second.
    #[test]
    fn lambda_with_a_breaking_body_is_idempotent() {
        let src = "module M exposing (mk3)\n\n\nmk3 a =\n    \\b -> \\c -> a ++ \":\" ++ (if c then \"T\" else \"F\")\n";
        let once = format_source(src).expect("formats");
        assert!(
            once.contains("\\b ->\n        \\c ->\n"),
            "not block form:\n{once}"
        );
        assert_eq!(format_source(&once).expect("second pass"), once);
    }

    /// A comment in a declaration whose desugared body ends early (a `do`
    /// block's node spans only its keyword) prints once, in place.
    #[test]
    fn comment_after_a_do_statement_prints_once() {
        let src = "module M exposing (main, next)\n\n\nmain =\n    do\n        Io.println \"a\" -- after a\n        r <- Task.parallel -- after parallel\n            [ x\n            , y\n            ]\n        Io.println r\n\n\nnext =\n    1\n";
        let out = format_source(src).expect("formats");
        assert_eq!(out.matches("-- after a").count(), 1, "{out}");
        assert_eq!(out.matches("-- after parallel").count(), 1, "{out}");
        assert_eq!(format_source(&out).expect("second pass"), out);
    }

    /// A comment above a group's closing `)` belongs to the group and prints
    /// with it, once.
    #[test]
    fn comment_before_a_closing_paren_is_kept() {
        let src =
            "module M exposing (f)\n\n\nf x =\n    g (h x\n        -- before the paren\n      )\n";
        let out = format_source(src).expect("formats");
        assert_eq!(out.matches("-- before the paren").count(), 1, "{out}");
        assert_eq!(format_source(&out).expect("second pass"), out);
    }

    /// A comment after a group's opening `(` belongs to the group, whether
    /// the group holds a lone literal (no node of its own starts after the
    /// `(`) or an application (whose head does), and prints with it, once.
    #[test]
    fn comment_after_an_opening_paren_is_kept() {
        for body in [
            "(\n        -- inner\n        1\n    )",
            "((\n        -- inner\n        1\n    ))",
            "g (\n        -- inner\n        h x\n      )",
            "g ((\n        -- inner\n        h\n      ) x)",
        ] {
            let src = format!("module M exposing (x)\n\n\nx =\n    {body}\n");
            let out = format_source(&src).expect("formats");
            assert_eq!(out.matches("-- inner").count(), 1, "{out}");
            assert_eq!(format_source(&out).expect("second pass"), out);
        }
    }
}
