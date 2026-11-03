//! The Ipê source formatter engine.
//!
//! Parses a `.ipe` source string into an [`ipe_syntax::Module`] via
//! [`ipe_parse::parse_module`] and pretty-prints it in canonical (elm-format
//! style) form. [`format_source`] formats a whole file; the CLI `ipe fmt`
//! command and the LSP formatting provider both drive it, so one engine —
//! comment-preserving and semantics-guarded — serves both. LSP range
//! formatting takes [`format_with_segments`], splices the declarations it
//! wants, and proves the result with [`verify_rewrite`], the same guards.
//!
//! A comment takes one of two placements. An end-of-line comment after a
//! token that can end a node ([`ends_node`]) is kept at the end of that
//! token's output line; every other comment leads the code below it. When a
//! layout keeps the next code on the kept comment's line (after a pattern, a
//! parameter, a type argument, or a module or import name), the comment is
//! demoted: it prints where that layout puts leading comments.
//!
//! The engine is path-agnostic: it works on a bare source string and reports a
//! typed [`FmtError`]. A caller that knows the file (the CLI) attaches the path
//! at its own boundary.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::ops::Range;

pub use comments::ends_node;
use comments::{Comment, CommentKey, Demoted, OwnerTok, Run, Tail, comment_multiset, unplaced};
pub use faithful::{Owner, RunFault};
use ipe_diagnostics::{Diagnostic, Located, TokenKind, render};
use ipe_intern::Interner;
use ipe_parse::TokenClass;
use ipe_syntax::fixity::chain_groups;

mod comments;
mod faithful;

use ipe_syntax::{
    BinOp, Ctor, Exposed, Exposing, Expr, Expr_, ForeignDecl, Import, LetBinding, Module, Pattern,
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
    /// The formatter's own output is not a faithful print of the input — a
    /// formatter bug, surfaced rather than written to disk.
    RoundTrip(RoundTripFault),
    /// The formatted output would pass a ceiling; nothing is returned, so the
    /// caller leaves the file as it was.
    Limit(FmtLimit),
}

/// How an output failed to be a faithful print of its input.
#[derive(Debug)]
pub enum RoundTripFault {
    /// The source parsed but its tokens could not be recovered.
    SourceDidNotLex,
    /// The output did not lex.
    OutputDidNotLex,
    /// The output has fewer comments than the input.
    DroppedComments { input: usize, output: usize },
    /// The output's comments are not the input's.
    ChangedComments { input: usize, output: usize },
    /// The output parsed to another program.
    DifferentAst,
    /// The output did not parse.
    DidNotReparse(Box<Diagnostic>),
    /// The output broke a comment run of one owner.
    CommentRun { owner: Owner, fault: RunFault },
    /// The printer kept an end-of-line comment at no line end, even with
    /// every comment it could not keep printed above its next code.
    UnplacedTrailing,
}

impl fmt::Display for RoundTripFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceDidNotLex => f.write_str("source parsed but did not lex"),
            Self::OutputDidNotLex => f.write_str("formatted output did not lex"),
            Self::DroppedComments { input, output } => write!(
                f,
                "formatter dropped comments: input had {input}, output has {output}"
            ),
            Self::ChangedComments { input, output } => write!(
                f,
                "formatter changed comments: input had {input}, output has {output}"
            ),
            Self::DifferentAst => f.write_str("formatted output parsed to a different AST"),
            Self::DidNotReparse(diag) => write!(f, "formatted output did not re-parse: {diag:?}"),
            Self::CommentRun { owner, fault } => {
                write!(
                    f,
                    "formatted output broke a comment run of {owner}: {fault}"
                )
            }
            Self::UnplacedTrailing => {
                f.write_str("formatter could not place an end-of-line comment")
            }
        }
    }
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
            Self::RoundTrip(fault) => {
                write!(f, "ipe fmt: internal error while formatting: {fault}")
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
    let comments = comments::scan(
        src,
        ranges,
        |end| anchor_after(&code, end),
        |lo, hi| trailing_owner(src, &code, lo, hi),
    );
    Some(Trivia { comments, code })
}

/// The token the comment at `[lo, hi)` trails, or `None` when it leads the
/// code after it.
///
/// A comment trails the last code token before it when nothing but spaces
/// separate them on one line, that token ends a node ([`ends_node`]), and the
/// line ends after the comment: a `--` comment always ends its line, and a
/// block comment trails only when a newline or the end of the file follows it
/// before the next code token (`x {- c -} + y` leads `+ y`).
fn trailing_owner(src: &str, code: &[CodeToken], lo: usize, hi: usize) -> Option<OwnerTok> {
    let next = code.partition_point(|t| t.hi <= lo);
    let t = code.get(next.checked_sub(1)?)?;
    if !ends_node(t.kind) || src.get(t.hi..lo)?.contains('\n') {
        return None;
    }
    let ends_line = src.get(lo..hi)?.starts_with("--") || {
        let next_lo = code.get(next).map_or(src.len(), |n| n.lo);
        next_lo >= src.len() || src.get(hi..next_lo)?.contains('\n')
    };
    let named = code
        .get(..next)?
        .iter()
        .rev()
        .find(|k| !matches!(k.kind, TokenKind::RParen))
        .unwrap_or(t);
    ends_line.then_some(OwnerTok {
        lo: t.lo,
        hi: t.hi,
        name: (named.lo, named.hi),
    })
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
    format_with_segments(src).map(|formatted| formatted.text)
}

/// [`format_source`], with where each top-level declaration sits in the input
/// and in the output.
///
/// The text is exactly what [`format_source`] returns, behind the same guards.
/// A caller that formats part of a file (LSP range formatting) splices the
/// output of the declarations it wants into the source, then proves the result
/// with [`verify_rewrite`].
///
/// # Errors
/// As [`format_source`].
pub fn format_with_segments(src: &str) -> Result<Formatted, FmtError> {
    format_guarded(src, OutputCap::for_input(src.len()), render_module)
}

/// Check that `edited`, a rewrite of `original`, is a faithful print of it.
///
/// These are the guards [`format_source`] runs on its own output: `edited`
/// fits the cap for `original`, carries exactly its comments and re-parses to
/// its AST. A caller that builds a rewrite from formatted pieces runs this on
/// the whole result, so one engine judges every formatted text.
///
/// # Errors
/// [`FmtError::Parse`] if `original` does not parse; [`FmtError::RoundTrip`]
/// if `edited` loses, adds, alters or re-spaces a comment, or does not
/// re-parse to the same AST; [`FmtError::Limit`] if `edited` passes
/// [`OutputCap::for_input`] of `original`.
pub fn verify_rewrite(original: &str, edited: &str) -> Result<Verified, FmtError> {
    let mut interner = Interner::new();
    let module = parse_input(original, &mut interner)?;
    let input = lex_input(original)?;
    verify(
        &module,
        &interner,
        &input,
        original,
        edited,
        OutputCap::for_input(original.len()),
    )
}

/// What the guards checked on an output they accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    head_runs: usize,
}

impl Verified {
    /// How many comment runs directly above a head (`module` or a
    /// declaration) the input had, each proven unchanged in the output.
    #[must_use]
    pub const fn head_runs(self) -> usize {
        self.head_runs
    }
}

/// A module's formatted text and where each declaration sits in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Formatted {
    /// The formatted module, as [`format_source`] returns it.
    pub text: String,
    /// One segment per top-level declaration, in source order.
    pub decls: Vec<DeclSegment>,
}

/// One top-level declaration's bytes in the input and in the output.
///
/// Both ranges hold the declaration's leading comments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclSegment {
    /// Its source bytes: from the line start of its first leading comment (or
    /// of its first token) to the end of its last token.
    pub input: Range<usize>,
    /// Its bytes in [`Formatted::text`], up to its last character and without
    /// the newline after it.
    pub output: Range<usize>,
}

/// [`format_source`] under an explicit `cap`, so a test drives the refusal
/// with a small input.
#[cfg(test)]
fn format_source_capped(src: &str, cap: OutputCap) -> Result<String, FmtError> {
    format_guarded(src, cap, render_module).map(|formatted| formatted.text)
}

/// The printer's rendering of a whole module: what [`format_source`] writes.
fn render_module(printer: &Printer<'_>, module: &Module) -> Formatted {
    printer.formatted(module)
}

/// A renderer's result, whose text the guards inspect.
trait Rendering {
    fn text(&self) -> &str;
}

impl Rendering for String {
    fn text(&self) -> &str {
        self
    }
}

impl Rendering for Formatted {
    fn text(&self) -> &str {
        &self.text
    }
}

/// `src` parsed for formatting; a parse failure is [`FmtError::Parse`].
fn parse_input(src: &str, interner: &mut Interner) -> Result<Module, FmtError> {
    ipe_parse::parse_module(src, interner).map_err(|diag| FmtError::Parse {
        src: src.to_owned(),
        diag,
    })
}

/// The trivia of a source that parsed.
fn lex_input(src: &str) -> Result<Trivia, FmtError> {
    scan_trivia(src).ok_or(FmtError::RoundTrip(RoundTripFault::SourceDidNotLex))
}

/// Print `src` with `render`, then refuse the output unless it fits `cap`,
/// carries the input's comments and re-parses to the input's AST.
///
/// [`format_source`] renders with [`Printer::formatted`]; a test passes a
/// faulty renderer to drive each refusal through the same guards.
fn format_guarded<R: Rendering>(
    src: &str,
    cap: OutputCap,
    render: impl Fn(&Printer<'_>, &Module) -> R,
) -> Result<R, FmtError> {
    let mut interner = Interner::new();
    let module = parse_input(src, &mut interner)?;
    let input = lex_input(src)?;
    let source = Source {
        interner: &interner,
        module: &module,
        trivia: &input,
        text: src,
        cap,
    };
    let rendered = render_placed(&source, &render)?;
    verify(&module, &interner, &input, src, rendered.text(), cap)?;
    Ok(rendered)
}

/// A parsed source and the ceiling its print is held to.
struct Source<'s> {
    interner: &'s Interner,
    module: &'s Module,
    trivia: &'s Trivia,
    text: &'s str,
    cap: OutputCap,
}

/// Render `source` with `render`, keeping every end-of-line comment the
/// layout gives a line end and printing every other one above its next code.
///
/// The first pass keeps every end-of-line comment; those it found no line
/// end for are demoted, and a second pass prints them as leading comments of
/// their anchor. Two passes at most: a comment the second pass still did not
/// place is a printer fault, refused rather than written.
///
/// # Errors
/// [`FmtError::Limit`] when a pass would pass the cap;
/// [`RoundTripFault::UnplacedTrailing`] when the second pass leaves a kept
/// comment unplaced.
fn render_placed<R: Rendering>(
    source: &Source<'_>,
    render: &impl Fn(&Printer<'_>, &Module) -> R,
) -> Result<R, FmtError> {
    let (first, unplaced) = render_pass(source, &Demoted::default(), render)?;
    if unplaced.is_empty() {
        return Ok(first);
    }
    let demote = if demotion_disabled() {
        Vec::new()
    } else {
        unplaced
    };
    let mask = Demoted::of(source.trivia.comments.len(), demote);
    let (second, left) = render_pass(source, &mask, render)?;
    if left.is_empty() {
        Ok(second)
    } else {
        Err(FmtError::RoundTrip(RoundTripFault::UnplacedTrailing))
    }
}

/// One render of `source` under `mask`, with the ordinals of the kept
/// comments it left unplaced.
fn render_pass<R: Rendering>(
    source: &Source<'_>,
    mask: &Demoted,
    render: &impl Fn(&Printer<'_>, &Module) -> R,
) -> Result<(R, Vec<usize>), FmtError> {
    let printer = Printer::new(
        source.interner,
        source.trivia,
        Some(source.text),
        source.cap,
        mask,
    );
    let rendered = render(&printer, source.module);
    // A refused pad rendered empty, so the text alone under-counts: the
    // budget's verdict comes before any guard reads the text.
    if printer.pads.exceeded() {
        return Err(FmtError::Limit(FmtLimit::OutputBytes { cap: source.cap }));
    }
    let unplaced = printer.unplaced_trails(rendered.text());
    Ok((rendered, unplaced))
}

#[cfg(test)]
thread_local! {
    /// Set by a test to make the second render pass demote nothing, driving
    /// the bounded-pass refusal.
    static NO_DEMOTION: Cell<bool> = const { Cell::new(false) };
}

/// Whether the second render pass is barred from demoting, a test knob.
#[cfg(test)]
fn demotion_disabled() -> bool {
    NO_DEMOTION.with(Cell::get)
}

/// Whether the second render pass is barred from demoting: never outside
/// tests.
#[cfg(not(test))]
const fn demotion_disabled() -> bool {
    false
}

/// Refuse `out` as a print of `module` unless it fits `cap`, carries exactly
/// the comments of `input` in the same runs, and re-parses to `module`'s AST.
///
/// The one set of output guards: [`format_guarded`] runs it on the printer's
/// output and [`verify_rewrite`] on a caller's spliced rewrite.
fn verify(
    module: &Module,
    interner: &Interner,
    input: &Trivia,
    input_src: &str,
    out: &str,
    cap: OutputCap,
) -> Result<Verified, FmtError> {
    let refuse = |fault| Err(FmtError::RoundTrip(fault));
    // Output guard: it fires first so an over-cap output is never lexed,
    // re-parsed or returned.
    if !cap.admits(out) {
        return Err(FmtError::Limit(FmtLimit::OutputBytes { cap }));
    }

    // Comment guard: the output carries exactly the input's comments. It fires
    // BEFORE the AST equivalence check so a comment bug surfaces as a clear
    // comment message rather than an AST mismatch.
    let Some(output) = scan_trivia(out) else {
        return refuse(RoundTripFault::OutputDidNotLex);
    };
    let counts = (input.comments.len(), output.comments.len());
    if counts.1 < counts.0 {
        return refuse(RoundTripFault::DroppedComments {
            input: counts.0,
            output: counts.1,
        });
    }
    if comment_multiset(&input.comments) != comment_multiset(&output.comments) {
        return refuse(RoundTripFault::ChangedComments {
            input: counts.0,
            output: counts.1,
        });
    }

    let mut verify_interner = Interner::new();
    let reparsed = match ipe_parse::parse_module(out, &mut verify_interner) {
        Ok(reparsed) => reparsed,
        Err(diag) => return refuse(RoundTripFault::DidNotReparse(Box::new(diag))),
    };

    // Run guard: every end-of-line comment stays on its owner's line or moves
    // above its next code, every comment run keeps its owner, its inner gaps,
    // and the run directly above each head keeps its gap to the head.
    let printed = faithful::Printed {
        input,
        input_src,
        output: &output,
        output_src: out,
    };
    let head_runs = match faithful::check(module, &reparsed, &printed) {
        Ok(head_runs) => head_runs,
        Err(faithful::Refusal::DeclCount) => return refuse(RoundTripFault::DifferentAst),
        Err(faithful::Refusal::Run { owner, fault }) => {
            return refuse(RoundTripFault::CommentRun { owner, fault });
        }
    };

    // Semantics guard: the output must re-parse to the same AST.
    if !modules_equivalent(module, interner, &reparsed, &verify_interner, cap)? {
        return refuse(RoundTripFault::DifferentAst);
    }
    Ok(Verified { head_runs })
}

/// Format `src` WITHOUT the round-trip guards. Test-only: lets a test
/// inspect the raw printer output even when a guard would reject it, so a
/// divergence can be localised rather than hidden behind a compiler-bug error.
#[cfg(test)]
pub(crate) fn format_source_unchecked(src: &str) -> Result<String, FmtError> {
    let mut interner = Interner::new();
    let module = parse_input(src, &mut interner)?;
    let input = lex_input(src)?;
    let source = Source {
        interner: &interner,
        module: &module,
        trivia: &input,
        text: src,
        cap: OutputCap::for_input(src.len()),
    };
    render_placed(&source, &|p: &Printer<'_>, m: &Module| p.module(m))
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
        let mask = Demoted::default();
        let printer = Printer::new(i, &none, None, cap, &mask);
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

/// Where a definition's signature type sits and whether its source broke it.
#[derive(Clone, Copy)]
struct SignatureLayout {
    /// The source wrote the signature across lines.
    was_multi: bool,
    /// The type's first byte.
    lo: usize,
    /// The offset just past the type.
    hi: usize,
}

struct Printer<'a> {
    interner: &'a Interner,
    /// The source's comments, in source order (so sorted by anchor).
    comments: &'a [Comment],
    /// Which end-of-line comments this render prints as leading comments.
    mask: &'a Demoted,
    /// The end-of-line comments this render keeps on their owner's line, in
    /// source order (so sorted by owner token).
    trails: Vec<&'a Comment>,
    /// Whether each of `trails` was printed, by index into `trails`.
    placed: Vec<Cell<bool>>,
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
    fn new(
        interner: &'a Interner,
        trivia: &'a Trivia,
        src: Option<&'a str>,
        cap: OutputCap,
        mask: &'a Demoted,
    ) -> Self {
        let trails: Vec<&'a Comment> = trivia.comments.iter().filter(|c| !mask.leads(c)).collect();
        let placed = trails.iter().map(|_| Cell::new(false)).collect();
        Self {
            interner,
            comments: trivia.comments.as_slice(),
            mask,
            trails,
            placed,
            code: trivia.code.as_slice(),
            src,
            claimed: Cell::new(None),
            lambda_head: Cell::new(None),
            pads: PadBudget::new(cap),
        }
    }

    /// The spaces reaching `col`, charged to this print's budget.
    const fn pad(&self, col: Col) -> Pad<'_> {
        self.pads.pad(col)
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

    /// The leading comments anchored at a token starting in the byte range
    /// `[lo, hi)`.
    fn anchored_in(&self, lo: usize, hi: usize) -> Run<'a> {
        comments::anchored_in(self.comments, self.mask, lo, hi)
    }

    /// The comments anchored at the token starting at byte `pos`.
    fn anchored(&self, pos: usize) -> Run<'a> {
        self.anchored_in(pos, pos.saturating_add(1))
    }

    /// The leading comments after the last token of the file.
    fn end_of_file(&self) -> Run<'a> {
        comments::end_of_file(self.comments, self.mask)
    }

    /// The ordinals of the kept end-of-line comments `text`, this printer's
    /// output, does not hold at the end of their owner's line.
    ///
    /// A comment counts as placed only when a render printed it and the
    /// output re-scans with it trailing a token of its owner's text, so a
    /// print a composer later discarded never passes for a placement.
    fn unplaced_trails(&self, text: &str) -> Vec<usize> {
        if self.trails.is_empty() {
            return Vec::new();
        }
        let printed = scan_trivia(text);
        let mut held: BTreeMap<(&str, CommentKey<'_>), usize> = BTreeMap::new();
        for c in printed.iter().flat_map(|t| t.comments.iter()) {
            if let Some(owner) = c.owner().and_then(|o| o.name(text)) {
                let count = held.entry((owner, c.key())).or_default();
                *count = count.saturating_add(1);
            }
        }
        let mut unplaced = Vec::new();
        for (c, placed) in self.trails.iter().zip(&self.placed) {
            let key = c
                .owner()
                .and_then(|o| o.name(self.src?))
                .map(|owner| (owner, c.key()));
            let found = key
                .filter(|_| placed.get())
                .and_then(|key| held.get_mut(&key))
                .filter(|count| **count > 0);
            match found {
                Some(count) => *count = count.saturating_sub(1),
                None => unplaced.push(c.ord()),
            }
        }
        unplaced
    }

    /// The kept end-of-line comments owned by the token ending at
    /// `owner_hi`, each after a space, for the end of the line that token
    /// ends.
    fn trail_after(&self, owner_hi: usize) -> String {
        let owner_end = |c: &&Comment| c.owner().map_or(0, |o| o.hi);
        let first = self.trails.partition_point(|c| owner_end(c) < owner_hi);
        let mut out = String::new();
        let held = self.trails.iter().zip(&self.placed).skip(first);
        for (c, placed) in held.take_while(|(c, _)| owner_end(c) == owner_hi) {
            comments::emit_trailing(&mut out, c);
            placed.set(true);
        }
        out
    }

    /// [`Self::trail_after`] for an owner inside a node ending at `node_hi`;
    /// empty for the node's own last token, whose comment its enclosing
    /// composer prints at the line end it opens after the node.
    fn trail_inside(&self, owner_hi: usize, node_hi: usize) -> String {
        if owner_hi < node_hi {
            self.trail_after(owner_hi)
        } else {
            String::new()
        }
    }

    /// Whether a kept end-of-line comment is owned by the token ending at
    /// `owner_hi`.
    fn trails_at(&self, owner_hi: usize) -> bool {
        let first = self
            .trails
            .partition_point(|c| c.owner().map_or(0, |o| o.hi) < owner_hi);
        self.trails
            .get(first)
            .and_then(|c| c.owner())
            .is_some_and(|o| o.hi == owner_hi)
    }

    /// Whether a kept end-of-line comment is owned by a token inside
    /// `[lo, hi)` short of its end: the node there needs a line end inside
    /// it.
    fn forces_break(&self, lo: usize, hi: usize) -> bool {
        let first = self
            .trails
            .partition_point(|c| c.owner().map_or(0, |o| o.lo) < lo);
        self.trails
            .get(first)
            .and_then(|c| c.owner())
            .is_some_and(|o| o.hi < hi)
    }

    /// The end of the code token before each depth-0 `separator` of the
    /// group of code tokens starting at `lo`, then the end of the token
    /// before the bracket that closes the group, which ends the scan; or
    /// before `hi`, when no bracket closes it first.
    fn item_ends(&self, lo: usize, hi: usize, separator: TokenKind) -> Vec<usize> {
        let first = self.code.partition_point(|t| t.lo < lo);
        let mut ends = Vec::new();
        let mut depth = 0usize;
        let mut prev: Option<usize> = None;
        for t in self.code.get(first..).unwrap_or_default() {
            if t.lo >= hi {
                break;
            }
            match t.kind {
                TokenKind::LParen | TokenKind::LBrace | TokenKind::LBracket => {
                    depth = depth.saturating_add(1);
                }
                TokenKind::RParen | TokenKind::RBrace | TokenKind::RBracket => {
                    let Some(inner) = depth.checked_sub(1) else {
                        ends.extend(prev);
                        return ends;
                    };
                    depth = inner;
                }
                kind if kind == separator && depth == 0 => ends.extend(prev),
                _ => {}
            }
            prev = Some(t.hi);
        }
        ends.extend(prev);
        ends
    }

    /// The end of the last code token that starts before byte `pos`, `0`
    /// when none does.
    fn end_before(&self, pos: usize) -> usize {
        self.token_before(pos).map_or(0, |t| t.hi)
    }

    /// The last code token that starts before byte `pos`.
    fn token_before(&self, pos: usize) -> Option<CodeToken> {
        let i = self.code.partition_point(|t| t.lo < pos);
        i.checked_sub(1).and_then(|j| self.code.get(j)).copied()
    }

    /// The span of the node at `span` without the grouping parentheses the
    /// parser widened it to: `([ 1, 2 ])` is the list `[ 1, 2 ]`.
    ///
    /// The group's `(` and `)` belong to the claim that owns the group
    /// ([`Self::claim`]), so a node prints neither the comments anchored at
    /// that `)` nor those trailing the token before it. Not for a tuple or a
    /// unit, whose own brackets are parentheses.
    fn own_span(&self, span: ipe_diagnostics::Span) -> ipe_diagnostics::Span {
        let (mut lo, mut hi) = (span.lo as usize, span.hi as usize);
        while let Some(g) = self.paren_group(lo, hi) {
            let after_open = self.code.partition_point(|t| t.lo <= lo);
            let Some(next) = self.code.get(after_open) else {
                break;
            };
            lo = next.lo;
            hi = self.end_before(g.close);
        }
        let narrow = |at: usize, wide: u32| u32::try_from(at).unwrap_or(wide);
        ipe_diagnostics::Span {
            lo: narrow(lo, span.lo),
            hi: narrow(hi, span.hi),
        }
    }

    /// The comments anchored at the closing bracket that ends `span`.
    fn closing_comments(&self, span: ipe_diagnostics::Span) -> Run<'a> {
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
            _ => Run::default(),
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
    ) -> (Run<'a>, T) {
        let outer = self.claimed.get();
        let group = closer.and_then(|hi| self.paren_group(lo, hi));
        // The run this node claims: its first token, through the group's first
        // inner token when it is a parenthesised group.
        let end = group.map_or(lo, |g| g.inner.max(lo));
        let inside = self.is_claimed(lo);
        let leading = if inside {
            Run::default()
        } else {
            self.anchored_in(lo, end.saturating_add(1))
        };
        // The same node claimed twice (`expr` then `expr_atom`) owns its `)`
        // once; a nested group inside a claimed run still owns its own `)`.
        let closing = match group {
            Some(g) if outer.map(|(start, _)| start) != Some(lo) => self.anchored(g.close),
            _ => Run::default(),
        };
        let comments = leading.merge(closing);
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
    fn claim_expr<T>(&self, e: &Expr, render: impl FnOnce() -> T) -> (Run<'a>, T) {
        let outer = self.lambda_head.get();
        let head = lambda_head(e).filter(|&(_, hi)| outer != Some(hi));
        if let Some((_, hi)) = head {
            self.lambda_head.set(Some(hi));
        }
        let (comments, rendered) = self.claim(e.span.lo as usize, Self::closer_of(e), render);
        self.lambda_head.set(outer);
        let comments = match head {
            Some((lo, hi)) => comments.merge(self.anchored_in(lo, hi)),
            None => comments,
        };
        (comments, rendered)
    }

    /// `body` preceded by `run`, the body continuing at `col`.
    fn with_comments(&self, run: &Run<'_>, body: &str, col: Col) -> String {
        if run.is_empty() {
            return body.to_owned();
        }
        let mut out = String::new();
        comments::emit(&mut out, run, self.pad(col), Tail::Glued);
        out.push_str(body);
        out
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
    fn import_block(
        &self,
        out: &mut String,
        imports: &[Import],
        owned_from: impl Fn(usize) -> Run<'a>,
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
        let zero = self.pad(Col::ZERO);
        if let Some(first) = first_in_source.and_then(|i| imports.get(i)) {
            let head = self.anchored(first.import_kw.lo as usize);
            comments::emit(
                out,
                &head,
                zero,
                Tail::Source {
                    blank_lines: IMPORT_BLANK_LINES,
                },
            );
        }
        let mut order: Vec<usize> = (0..imports.len()).collect();
        order.sort_by_key(|&i| imports.get(i).map(|imp| self.dotted(&imp.name.value)));
        for i in order {
            let Some(imp) = imports.get(i) else { continue };
            let kw = imp.import_kw.lo as usize;
            let owned = owned_from(kw);
            // The first import's comments above its keyword head the block.
            let travels = if Some(i) == first_in_source {
                owned.without_anchors(&[kw])
            } else {
                owned
            };
            let line = self.import(imp);
            comments::emit(out, &unplaced(travels, &line), zero, Tail::Glued);
            out.push_str(&line);
            out.push_str(&self.trail_after(imp.span.hi as usize));
            out.push('\n');
        }
    }

    /// Render a whole module.
    fn module(&self, m: &Module) -> String {
        self.formatted(m).text
    }

    /// Render a whole module, recording where each declaration sits in the
    /// input and in the output.
    fn formatted(&self, m: &Module) -> Formatted {
        let Module {
            module_kw,
            name,
            exposing,
            imports,
            ..
        } = m;
        // Every anchored comment has exactly one owner among the module's
        // items: the header owns those anchored before the first import or
        // declaration, an import those from its `import` keyword up to the next
        // item, a declaration those from its first token up to the next one.
        // An owner prints each comment its rendering did not place above that
        // rendering (see `unplaced`), so no comment position the parser admits
        // falls between owners and is lost.
        let decls = module_decls(m);
        let mut starts: Vec<usize> = imports
            .iter()
            .map(|imp| imp.import_kw.lo as usize)
            .chain(decls.iter().map(|d| decl_start(self.code, d)))
            .collect();
        starts.sort_unstable();
        let owner_end = |lo: usize| {
            let next = starts.partition_point(|&s| s <= lo);
            starts.get(next).copied().unwrap_or(usize::MAX)
        };
        let owned_from = |lo: usize| self.anchored_in(lo, owner_end(lo));
        let zero = self.pad(Col::ZERO);
        let mut out = String::new();

        // module <Name> exposing (…). The run directly above `module` prints
        // in place, with its gap to the header. A comment the header owns but
        // does not place (inside the header line) is hoisted above that run, a
        // blank line apart, so it never joins the module's doc.
        let header = format!(
            "module {}{}",
            self.dotted(&name.value),
            self.module_exposing(exposing)
        );
        let module_lo = module_kw.lo as usize;
        let head = self.anchored(module_lo);
        let first_item = starts.first().copied().unwrap_or(usize::MAX);
        let hoisted = unplaced(
            self.anchored_in(module_lo.saturating_add(1), first_item),
            &header,
        );
        comments::emit(&mut out, &hoisted, zero, hoist_tail(&head));
        comments::emit(&mut out, &head, zero, TOP_LEVEL_HEAD);
        out.push_str(&header);
        out.push_str(&self.trail_after(self.end_before(first_item)));
        out.push('\n');

        self.import_block(&mut out, imports, owned_from);

        // Declarations in source order, each preceded by two blank lines
        // (elm-format's top-level spacing). Unions / aliases / values /
        // foreign declarations interleave by their span order.
        let mut segments: Vec<DeclSegment> = Vec::new();
        for decl in &decls {
            out.push_str("\n\n");
            let item_start = out.len();
            // The run directly above the declaration's first token prints in
            // place, with its gap to the head. A comment the declaration owns
            // but its rendering does not place (in its head, before its name)
            // is hoisted above that run, a blank line apart, so it never lands
            // between a doc and its head.
            let start = decl_start(self.code, decl);
            let leading = self.anchored(start);
            let mut lead = String::new();
            comments::emit(&mut lead, &leading, zero, TOP_LEVEL_HEAD);
            let body = self.decl(decl, start, owner_end(start));
            let missed = unplaced(owned_from(start), &format!("{lead}{body}"));
            let mut item = String::new();
            comments::emit(&mut item, &missed, zero, hoist_tail(&leading));
            item.push_str(&lead);
            item.push_str(&body);
            out.push_str(&item);
            if let Some(input) = self.decl_input(start, &owned_from(start), owner_end(start)) {
                let end = item_start.saturating_add(item.trim_end_matches('\n').len());
                segments.push(DeclSegment {
                    input,
                    output: item_start..end,
                });
            }
            // The declaration's segment ends at its last token, as its input
            // range does, so a splice keeps the comment after it once.
            out.push_str(&self.trail_after(self.end_before(owner_end(start))));
            out.push('\n');
        }

        // Trailing comments after the last token.
        let trailing = self.end_of_file();
        if !trailing.is_empty() {
            out.push('\n');
            comments::emit(&mut out, &trailing, zero, Tail::Glued);
        }

        // A formatted file ends with exactly one trailing newline (POSIX text
        // file, no trailing blank lines) — the fixed-point invariant.
        while out.ends_with("\n\n") {
            out.pop();
        }
        if !out.ends_with('\n') {
            out.push('\n');
        }
        Formatted {
            text: out,
            decls: segments,
        }
    }

    /// The source bytes of the declaration whose first token starts at
    /// `start` and whose comments are `owned`: from the line start of its
    /// first comment or token to the end of its last token before
    /// `owner_end`.
    ///
    /// `None` without a source (the equivalence guard's projection), where no
    /// input position exists.
    fn decl_input(&self, start: usize, owned: &Run<'_>, owner_end: usize) -> Option<Range<usize>> {
        let src = self.src?;
        let first = owned.start().map_or(start, |c| c.min(start));
        let line = src.get(..first)?.rfind('\n').map_or(0, |nl| nl + 1);
        let lo = if src.get(line..first)?.chars().all(|c| c == ' ' || c == '\t') {
            line
        } else {
            first
        };
        let last = self.code.partition_point(|t| t.lo < owner_end);
        let hi = last.checked_sub(1).and_then(|i| self.code.get(i))?.hi;
        (lo < hi).then_some(lo..hi)
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
    /// A comment above an exposed item, or above the closing `)`, prints in
    /// place on its own line; one above a later item opens a new group, and
    /// one above the first follows its `( `. Such a clause is always
    /// multi-line. Every other comment of the header prints above it (the
    /// header owner's [`unplaced`] rule).
    fn module_exposing(&self, e: &Located<Exposing>) -> String {
        let items = match &e.value {
            Exposing::All => return " exposing (..)".to_owned(),
            Exposing::List(items) => items,
        };
        let above = |it: &Located<Exposed>| self.anchored(it.span.lo as usize);
        let closing = self.closing_comments(e.span);
        let list_hi = e.span.hi as usize;
        let items_lo = items.first().map_or(list_hi, |it| it.span.lo as usize);
        let commented = !closing.is_empty()
            || items.iter().any(|it| !above(it).is_empty())
            || self.forces_break(items_lo, list_hi);
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
        // comment above a later item ends the group before it.
        let pad = self.pad(Col::BODY);
        let mut out = format!(" exposing\n{pad}");
        let mut lead = "( ";
        let mut group: Vec<String> = Vec::new();
        let mut cur_line: Option<usize> = None;
        // An item that owns an end-of-line comment ended its source line, so
        // it is the last of its group and its comment ends the group's line.
        let ends = self.item_ends(items_lo, list_hi, TokenKind::Comma);
        let ends = (ends.len() == items.len()).then_some(ends);
        for (i, it) in items.iter().enumerate() {
            let line = self.line_of(it.span.lo);
            let run = above(it);
            if i == 0 && !run.is_empty() {
                out.push_str(lead);
                lead = "";
                comments::emit(&mut out, &run, self.pad(Col::BODY.past(2)), Tail::Glued);
            } else if !run.is_empty() || Some(line) != cur_line {
                push_exposing_group(&mut out, &mut group, &mut lead, pad);
                comments::emit(&mut out, &run, pad, Tail::Glued);
            }
            cur_line = Some(line);
            let trail = ends
                .as_ref()
                .and_then(|ends| ends.get(i))
                .map(|&end| self.trail_inside(end, list_hi))
                .unwrap_or_default();
            group.push(format!("{}{trail}", self.exposed(&it.value)));
        }
        push_exposing_group(&mut out, &mut group, &mut lead, pad);
        comments::emit(&mut out, &closing, pad, Tail::Glued);
        out.push(')');
        out
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

    /// Render a declaration starting at `start` whose comments are those
    /// anchored before `owner_end`.
    fn decl(&self, d: &Decl<'_>, start: usize, owner_end: usize) -> String {
        match d {
            Decl::Union(u) => self.union(u, owner_end),
            Decl::Alias(a) => self.alias(&a.value),
            Decl::Value(v) => self.value(&v.value, start),
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
            |ann| self.signature(name.value, &ann.value, None),
        );
        // A comment inside the head (outside a record field's own) prints at
        // the start of the body, where a second pass reads it as the body's.
        let types = type_annotation
            .as_ref()
            .map_or(&[][..], |ann| std::slice::from_ref(&ann.value));
        let run = self.type_comments(types, name.span.lo as usize, body.span.lo as usize);
        let body_s = self.expr(body, Col::BODY);
        let mut out = format!("foreign {head} =\n{}", self.pad(Col::BODY));
        out.push_str(&self.with_comments(&run, &body_s, Col::BODY));
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
        // The head's last token is the one before the first constructor's
        // `=`; the head line always ends there.
        let head_end = uv
            .ctors
            .first()
            .and_then(|first| self.token_before(first.span.lo as usize))
            .filter(|eq| eq.kind == TokenKind::Equals)
            .map(|eq| self.trail_inside(self.end_before(eq.lo), u.span.hi as usize))
            .unwrap_or_default();
        s.push_str(&head_end);
        // A section comment written between two constructors annotates the
        // constructor it precedes: re-emit it on its own four-space-indented
        // line just before that constructor's `| Ctor` line, keeping the
        // author's grouping inside the type. A comment inside a constructor's
        // arguments travels above that constructor too, since a constructor
        // prints on one line. A constructor's span is its name alone, so its
        // comments run up to the next constructor, or for the last one to the
        // end of the declaration's own comments.
        let pad = self.pad(Col::BODY);
        for (idx, c) in uv.ctors.iter().enumerate() {
            let lead = if idx == 0 { "=" } else { "|" };
            let hi = uv
                .ctors
                .get(idx + 1)
                .map_or(owner_end, |next| next.span.lo as usize);
            let run = self.type_comments(&c.value.args, c.span.lo as usize, hi);
            open_line(&mut s, &run, pad);
            let _ = write!(s, "{lead} {}", self.ctor(&c.value));
            // The constructor's last token is the one before the next `|`; the
            // last constructor's comment is the declaration's.
            let trail = uv
                .ctors
                .get(idx + 1)
                .and_then(|next| self.token_before(next.span.lo as usize))
                .filter(|pipe| pipe.kind == TokenKind::Pipe)
                .map(|pipe| self.trail_inside(self.end_before(pipe.lo), u.span.hi as usize))
                .unwrap_or_default();
            s.push_str(&trail);
        }
        s
    }

    /// The comments anchored in `[lo, hi)` among `types` that no record-type
    /// printer places: all but those above a closed record's field names.
    ///
    /// A type carries no per-node spans, so these print above the line the
    /// types start on.
    fn type_comments(&self, types: &[TypeAnnotation], lo: usize, hi: usize) -> Run<'a> {
        let mut fields = Vec::new();
        for t in types {
            record_field_anchors(t, &mut fields);
        }
        self.anchored_in(lo, hi).without_anchors(&fields)
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
                self.type_record(fields, Col::BODY, self.was_multiline(a.body.span))
            }
            other => self.type_annotation(other, Col::BODY),
        };
        // A comment written between the `=` sign and the body type attaches to
        // the body's first token; one inside the body (outside a record
        // field's own) joins it.
        let (body_lo, body_hi) = (a.body.span.lo as usize, a.body.span.hi as usize);
        let inside = self.type_comments(std::slice::from_ref(&a.body.value), body_lo + 1, body_hi);
        let run = self.anchored(body_lo).merge(inside);
        format!(
            "type alias {}{} =\n{}{}",
            self.sym(a.name.value),
            vars,
            self.pad(Col::BODY),
            self.with_comments(&run, &body, Col::BODY)
        )
    }

    /// A definition whose first token starts at `start`.
    ///
    /// A comment inside its signature prints in the name slot, after the
    /// signature; one among its parameters prints at the start of the body.
    /// Neither can join the run above the head.
    fn value(&self, v: &Value, start: usize) -> String {
        let mut s = String::new();
        // Type annotation directly above the definition.
        if let Some(ann) = &v.type_annotation {
            let (lo, hi) = (ann.span.lo as usize, ann.span.hi as usize);
            let inside =
                self.type_comments(std::slice::from_ref(&ann.value), lo.max(start + 1), hi);
            let layout = Some(SignatureLayout {
                was_multi: self.was_multiline(ann.span),
                lo,
                hi,
            });
            s.push_str(&self.signature(v.name.value, &ann.value, layout));
            s.push_str(&self.trail_after(hi));
            s.push('\n');
            // A comment written between the type annotation and the binding
            // name (e.g. `-- c` in `main : Int\n-- c\nmain = 42`) attaches to
            // the binding name.
            let slot = inside.merge(self.anchored(v.name.span.lo as usize));
            comments::emit(&mut s, &slot, self.pad(Col::ZERO), Tail::Glued);
        }
        // The definition head: `name p0 p1 …`. Parameters are in ARGUMENT
        // position, so a constructor-with-arguments / cons / alias pattern must
        // be parenthesised — otherwise `f (Cons a)` would print as `f Cons a`,
        // silently turning one parameter into two.
        s.push_str(&self.sym(v.name.value));
        for p in &v.patterns {
            s.push(' ');
            s.push_str(&self.pattern_atom(&p.value));
        }
        s.push_str(" =");
        // The body always goes on the next line, four-space indented — the
        // elm-format canonical form for a top-level definition.
        let params_lo = v.name.span.lo as usize + 1;
        let params = self.anchored_in(params_lo, v.body.span.lo as usize);
        let body = self.expr(&v.body, Col::BODY);
        let _ = write!(
            s,
            "\n{}{}",
            self.pad(Col::BODY),
            self.with_comments(&params, &body, Col::BODY)
        );
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
    ///
    /// `layout` is `None` for a head that stays single-line (a `foreign`
    /// declaration's); otherwise a broken arrow chain keeps each segment's
    /// end-of-line comment, and a chain owning one inside breaks.
    fn signature(
        &self,
        name: ipe_intern::Symbol,
        ann: &TypeAnnotation,
        layout: Option<SignatureLayout>,
    ) -> String {
        let name = self.sym(name);
        let multi = layout.is_some_and(|l| l.was_multi || self.forces_break(l.lo, l.hi));
        if !multi {
            // Force a single line irrespective of width (elm-format keeps a
            // single-line signature single-line however wide it is). An arrow
            // chain is joined with ` -> `; anything else prints as one atom.
            let mark = self.pads.mark();
            let one = match ann {
                TypeAnnotation::TLambda(_, _) => self.arrow_chain(ann, Col::ZERO).join(" -> "),
                _ => self.type_app(ann, Col::ZERO),
            };
            // A record type inside the signature may still force its own break;
            // fall through to the multi-line form only if that happened.
            if !one.contains('\n') {
                return format!("{name} : {one}");
            }
            self.pads.rewind(mark, one);
        }
        // Multi-line: `name :` then the type at the body column, each arrow
        // segment's end-of-line comment at its line end.
        let trails = layout.map_or_else(Vec::new, |l| self.segment_trails(ann, l.lo, l.hi));
        let body = self.type_multiline(ann, Col::BODY, &trails);
        format!("{name} :\n{body}")
    }

    /// Render `t` broken across lines at column `col`. An arrow chain lays out
    /// one segment per line; a type application whose single-line form
    /// overflows the width budget breaks its arguments one per line (elm-format
    /// indents each argument one tab stop past the applied head); anything else
    /// is a single indented line.
    ///
    /// `trails[i]` ends an arrow chain's segment `i`'s line.
    fn type_multiline(&self, t: &TypeAnnotation, col: Col, trails: &[String]) -> String {
        let cur_pad = self.pad(col);
        match t {
            TypeAnnotation::TLambda(_, _) => {
                let parts = self.arrow_chain(t, col);
                let mut out = String::new();
                for (i, p) in parts.iter().enumerate() {
                    let lead = if i == 0 { "" } else { "-> " };
                    let trail = trails.get(i).map_or("", String::as_str);
                    let sep = if i == 0 { "" } else { "\n" };
                    let _ = write!(out, "{sep}{cur_pad}{lead}{p}{trail}");
                }
                out
            }
            TypeAnnotation::TType(q, segs, args) if !args.is_empty() => {
                let mark = self.pads.mark();
                let one = self.type_app(t, col);
                if fits(&one, col) {
                    return format!("{cur_pad}{one}");
                }
                self.pads.rewind(mark, one);
                // Break the application: head on its own line, each argument
                // one tab stop in on its own line.
                let arg_col = col.tab();
                let arg_pad = self.pad(arg_col);
                let mut out = format!("{cur_pad}{}", self.type_head(*q, segs));
                for a in args {
                    let _ = write!(out, "\n{arg_pad}{}", self.type_atom_indent(a, arg_col));
                }
                out
            }
            _ => format!("{cur_pad}{}", self.type_app(t, col)),
        }
    }

    /// The end-of-line comments ending each but the last segment of `ann`'s
    /// arrow chain, whose type spans `[lo, hi)`: a segment ends at the token
    /// before its depth-0 `->`.
    ///
    /// Empty when the chain's segments are not its depth-0 arrows (a
    /// parenthesised arrow result), so those comments are demoted.
    fn segment_trails(&self, ann: &TypeAnnotation, lo: usize, hi: usize) -> Vec<String> {
        let mut segments = 1usize;
        let mut cur = ann;
        while let TypeAnnotation::TLambda(_, b) = cur {
            segments = segments.saturating_add(1);
            cur = b;
        }
        let ends = self.item_ends(lo, hi, TokenKind::Arrow);
        if ends.len() != segments {
            return Vec::new();
        }
        ends.iter()
            .take(segments.saturating_sub(1))
            .map(|&end| self.trail_inside(end, hi))
            .collect()
    }

    fn type_annotation(&self, t: &TypeAnnotation, col: Col) -> String {
        match t {
            TypeAnnotation::TLambda(_, _) => {
                // Collect the full arrow chain and join with ` -> ` (single
                // line when it fits).
                let parts = self.arrow_chain(t, col);
                let one = parts.join(" -> ");
                if fits(&one, col) {
                    one
                } else {
                    // Multiline arrow: each arrow on its own line, one tab stop
                    // past the type's column, `->` leading.
                    let pad = self.pad(col.tab());
                    let mut it = parts.into_iter();
                    let first = it.next().unwrap_or_default();
                    let mut out = first;
                    for p in it {
                        let _ = write!(out, "\n{pad}-> {p}");
                    }
                    out
                }
            }
            _ => self.type_app(t, col),
        }
    }

    fn arrow_chain(&self, t: &TypeAnnotation, col: Col) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = t;
        while let TypeAnnotation::TLambda(a, b) = cur {
            out.push(self.type_app(a, col));
            cur = b;
        }
        out.push(self.type_app(cur, col));
        out
    }

    fn type_app(&self, t: &TypeAnnotation, col: Col) -> String {
        match t {
            TypeAnnotation::TType(q, segs, args) if !args.is_empty() => {
                let head = self.type_head(*q, segs);
                let arg_strs: Vec<String> =
                    args.iter().map(|a| self.type_atom_indent(a, col)).collect();
                format!("{head} {}", arg_strs.join(" "))
            }
            _ => self.type_atom_indent(t, col),
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
        self.type_atom_indent(t, Col::ZERO)
    }

    /// A type in atom position — parenthesised when it is a compound (arrow,
    /// applied constructor, or tuple) that would otherwise re-associate.
    fn type_atom_indent(&self, t: &TypeAnnotation, col: Col) -> String {
        match t {
            TypeAnnotation::TVar(s) => self.sym(*s),
            TypeAnnotation::TUnit => "()".to_owned(),
            TypeAnnotation::TType(q, segs, args) if args.is_empty() => self.type_head(*q, segs),
            TypeAnnotation::TType(..) => {
                format!("({})", self.type_app(t, col.past(1)))
            }
            TypeAnnotation::TLambda(..) => {
                format!("({})", self.type_annotation(t, col.past(1)))
            }
            TypeAnnotation::TTuple(elems) => {
                let parts: Vec<String> = elems
                    .iter()
                    .map(|e| self.type_annotation(e, col.past(2)))
                    .collect();
                format!("( {} )", parts.join(", "))
            }
            TypeAnnotation::TRecord(fields) => self.type_record(fields, col, false),
            TypeAnnotation::TRecordOpen(row_var, fields) => {
                self.type_record_open(*row_var, fields, col)
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
        col: Col,
    ) -> String {
        let parts: Vec<String> = fields
            .iter()
            .map(|(n, ty)| {
                format!(
                    "{} : {}",
                    self.sym(n.value),
                    self.type_annotation(ty, col.tab())
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
        col: Col,
        force_multi: bool,
    ) -> String {
        if fields.is_empty() {
            return "{}".to_owned();
        }
        // A field's type starts on the field's line when it renders on one
        // line, and otherwise on the next line one tab stop past the field.
        let field_col = col.past(2);
        let parts: Vec<String> = fields
            .iter()
            .map(|(n, ty)| {
                let value_col = field_col.tab();
                let ty_s = self.type_annotation(ty, value_col);
                let name = self.sym(n.value);
                if has_layout_newline(&ty_s) {
                    format!("{name} :\n{}{ty_s}", self.pad(value_col))
                } else {
                    format!("{name} : {ty_s}")
                }
            })
            .collect();
        // A comment written above a record-type field attaches to the field's
        // name; `leading[i]` holds field `i`'s. Printing them here keeps the
        // comment guard from refusing a record whose fields are interleaved
        // with comments (the shipped `type alias Model` body is this shape).
        let leading: Vec<Run<'a>> = fields
            .iter()
            .map(|(name, _)| self.anchored(name.span.lo as usize))
            .collect();
        let has_field_comments = leading.iter().any(|cs| !cs.is_empty());
        // A field's last token is the one before its depth-0 `,` or the
        // closing `}`; a field owning an end-of-line comment ends its line.
        let first_lo = fields.first().map_or(0, |(n, _)| n.span.lo as usize);
        let ends = self.item_ends(first_lo, usize::MAX, TokenKind::Comma);
        let trails: Vec<String> = if ends.len() == fields.len() {
            ends.iter().map(|&end| self.trail_after(end)).collect()
        } else {
            Vec::new()
        };
        let kept = ends
            .last()
            .is_some_and(|&last| self.forces_break(first_lo, last.saturating_add(1)));
        let one = format!("{{ {} }}", parts.join(", "));
        // Modal, like every other collection: a record type written on one line
        // stays single-line however wide; only a source-multiline record (the
        // `force_multi` trigger), one whose own field broke, or one carrying an
        // inter-field comment (which cannot survive on a single line) lays out
        // one field per leading-comma line.
        if !force_multi && !has_field_comments && !kept && !one.contains('\n') {
            return one;
        }
        let pad = self.pad(col);
        let inner = pad;
        let mut out = String::from("{");
        for (i, (part, lead)) in parts.iter().zip(&leading).enumerate() {
            let trail = trails.get(i).map_or("", String::as_str);
            // The comment block precedes the field it annotates, mirroring the
            // source where the comment sits above its field.
            if i == 0 && lead.is_empty() {
                let _ = write!(out, " {part}{trail}");
                continue;
            }
            open_line(&mut out, lead, inner);
            let sep = if i == 0 { " " } else { "," };
            let _ = write!(out, "{sep} {part}{trail}");
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

    /// Format an expression whose first line starts at column `col`.
    ///
    /// A `do` block reaches the printer already desugared into its
    /// `Task.andThen` / `let` chain; it is re-sugared here so the output keeps
    /// the source's `do` form. The desugared chain is not always printable:
    /// a bare-run line becomes `let _ = task in …`, which the parser rejects
    /// outside a `do` (`BareWildcardBinding`).
    ///
    /// The comments anchored at the expression's first token print above it,
    /// each on its own line at `col`.
    fn expr(&self, e: &Expr, col: Col) -> String {
        #[cfg(test)]
        count_render_call();
        if self.pads.exceeded() {
            // The print is refused whole: rendering more is wasted work.
            return String::new();
        }
        let (comments, body) = self.claim_expr(e, || self.expr_shape(e, col));
        self.with_comments(&comments, &body, col)
    }

    /// Format an expression without its leading comments.
    fn expr_shape(&self, e: &Expr, col: Col) -> String {
        self.do_view(e)
            .map_or_else(|| self.expr_node(e, col), |view| self.do_block(&view, col))
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
            let Some((step, rest)) = Self::do_step(cur, outer) else {
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
    /// - bind `p <- t` is a call of the [`Expr_::TaskAndThen`] identity node
    ///   on `(\p -> rest)` and `t` (no written call has that head);
    /// - bare run `t` is `let _ = t in rest` whose `_` carries `t`'s own span
    ///   (a written `let _ =` is rejected by the parser);
    /// - pure `p = v` is `let p = v in rest` stamped with the `=` span, which
    ///   lies after the binder (a written `let` starts before its binder). The
    ///   outermost node carries the `do` span instead, so there any
    ///   single-binding `let` over a statement binder is accepted — printing a
    ///   lone `let … in` result as a statement re-parses to the same AST.
    fn do_step(e: &Expr, outer: bool) -> Option<(DoStep<'_>, &Expr)> {
        match &e.value {
            Expr_::Call(head, args) => {
                if !matches!(head.value, Expr_::TaskAndThen) {
                    return None;
                }
                let [lam, task] = args.as_slice() else {
                    return None;
                };
                let Expr_::Lambda(params, cont) = &lam.value else {
                    return None;
                };
                let [pat] = params.as_slice() else {
                    return None;
                };
                is_do_binder(&pat.value).then_some((DoStep::Bind(pat, task), cont.as_ref()))
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

    /// Print a recovered `do` block, one statement per line one tab stop in.
    ///
    /// The result expression comes last; comments written between statements
    /// keep their place. A statement's expression starts past its `p <- ` or
    /// `p = ` head, at the column that head ends on.
    fn do_block(&self, view: &DoView<'_>, col: Col) -> String {
        let stmt = col.tab();
        let stmt_pad = self.pad(stmt);
        // A parenthesised block's node starts at its `(`: a comment between
        // the `(` and the keyword attaches to the keyword.
        let keyword_lo = view.keyword_end.saturating_sub("do".len());
        let mut out = if self.is_claimed(keyword_lo) {
            String::from("do")
        } else {
            self.with_comments(&self.anchored(keyword_lo), "do", col)
        };
        for step in &view.steps {
            // A bound or pure statement starts at its binder; a bare run is an
            // expression and carries its own comments.
            let (line, last) = match step {
                DoStep::Bind(pat, task) => (self.do_binding(pat, "<-", task, stmt), task),
                DoStep::Let(pat, value) => (self.do_binding(pat, "=", value, stmt), value),
                DoStep::Run(task) => (self.expr(task, stmt), task),
            };
            let trail = self.trail_after(last.span.hi as usize);
            let _ = write!(out, "\n{stmt_pad}{line}{trail}");
        }
        // With no statement peeled, the result IS the `do`-stamped node: print
        // its own shape, or `expr` would recognise the block again.
        let result = if view.steps.is_empty() {
            self.expr_node(view.result, stmt)
        } else {
            self.expr(view.result, stmt)
        };
        let _ = write!(out, "\n{stmt_pad}{result}");
        out
    }

    /// A `p <- task` or `p = value` statement of a `do` block at column
    /// `stmt`, with the comments above its binder.
    ///
    /// The right-hand side starts where the `p <- ` head ends.
    fn do_binding(&self, pat: &Pattern, arrow: &str, rhs: &Expr, stmt: Col) -> String {
        let head = format!("{} {arrow} ", self.pattern(&pat.value));
        let rhs_s = self.expr(rhs, stmt.past(head.chars().count()));
        self.with_comments(
            &self.anchored(pat.span.lo as usize),
            &format!("{head}{rhs_s}"),
            stmt,
        )
    }

    /// Format an expression node by its own shape, without `do` re-sugaring.
    ///
    /// A node the parser desugared from a sugar prints as that sugar: a getter
    /// lambda as its field accessor `.a.b`, a `Basics.negate` call as `-e`.
    fn expr_node(&self, e: &Expr, col: Col) -> String {
        if let Some(path) = ipe_parse::field_accessor(e) {
            return path.iter().fold(String::new(), |mut s, field| {
                s.push('.');
                s.push_str(&self.sym(*field));
                s
            });
        }
        if let Some(operand) = ipe_parse::negation(e, self.interner) {
            return format!("-{}", self.expr_atom(operand, col.past(1)));
        }
        match &e.value {
            Expr_::VarLocal(s) => self.sym(*s),
            Expr_::VarQual(q, n) => format!("{}.{}", self.sym(*q), self.sym(*n)),
            // The `do` bind has no source spelling: it prints as statements
            // through `do_view`. Reached only by the source-free equivalence
            // projection, where it prints as a token no written callee shares,
            // so a `do` never compares equal to a spelled `Task.andThen` call.
            Expr_::TaskAndThen => "(<-)".to_owned(),
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
            Expr_::Call(head, args) => self.call(head, args, col, e.span),
            Expr_::Binops(chain, last) => self.binops(chain, last, col, e.span),
            Expr_::Case(scrut, arms) => self.case(scrut, arms, col),
            Expr_::Lambda(params, body) => self.lambda(params, body, col, e.span),
            Expr_::Let(bindings, body) => self.let_(bindings, body, col),
            Expr_::If(branches, else_) => self.if_(branches, else_, col),
            Expr_::Tuple(elems) => self.tuple(elems, col, e.span),
            Expr_::List(elems) => self.list(elems, col, e.span),
            Expr_::Record(fields) => self.record(fields, col, e.span),
            Expr_::Update(base, fields) => self.update(base, fields, col, e.span),
            Expr_::Access(base, field) => {
                // An accessor base keeps its parentheses: `(.a).b` written bare
                // reads back as the one accessor `.a.b`.
                let base_s = if ipe_parse::field_accessor(base).is_some() {
                    format!("({})", self.expr(base, col.past(1)))
                } else {
                    self.expr_atom(base, col)
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
    fn expr_atom(&self, e: &Expr, col: Col) -> String {
        #[cfg(test)]
        count_render_call();
        if self.pads.exceeded() {
            // The print is refused whole: rendering more is wasted work.
            return String::new();
        }
        let (comments, body) = self.claim_expr(e, || self.atom_shape(e, col));
        self.with_comments(&comments, &body, col)
    }

    /// An expression in atom position, without its leading comments.
    fn atom_shape(&self, e: &Expr, col: Col) -> String {
        if ipe_parse::field_accessor(e).is_some() {
            return self.expr(e, col);
        }
        // A negative numeric literal (`-5`, `-1.0`) prints with a leading `-`,
        // which the parser reads as a binary subtraction operator once the
        // literal sits after another atom — so `f (-5)` bare-printed as `f -5`
        // re-parses as `f - 5`. In atom position the sign must stay wrapped.
        if is_negative_literal(&e.value) {
            return format!("({})", self.expr(e, col.past(1)));
        }
        if needs_parens_as_atom(&e.value) {
            let inner = self.expr(e, col.past(1));
            // A written group's last inner token may own an end-of-line
            // comment: it ends the inner line, the `)` on its own line below.
            let closing = self
                .token_before(e.span.hi as usize)
                .filter(|t| t.kind == TokenKind::RParen && t.hi == e.span.hi as usize);
            let trail = closing
                .map(|paren| self.trail_after(self.end_before(paren.lo)))
                .unwrap_or_default();
            if !trail.is_empty() {
                format!("({inner}{trail}\n{})", self.pad(col))
            } else if inner.contains('\n') {
                // A multiline compound in parens: the content starts right
                // after `(`, one column in, and the closing `)` sits on its
                // own line at the `(` column — elm-format's
                // parenthesised-block layout.
                format!("({}\n{})", inner, self.pad(col))
            } else {
                format!("({inner})")
            }
        } else {
            self.expr(e, col)
        }
    }

    fn call(&self, head: &Expr, args: &[Expr], col: Col, span: ipe_diagnostics::Span) -> String {
        let head_s = self.expr_atom(head, col);
        // Single-line application when the whole thing fits, nothing broke, and
        // the source kept it on one line (elm-format's modal rule). Each
        // argument is rendered here exactly ONCE: the multiline branch below
        // reuses these strings rather than re-rendering, so a right-nested
        // application chain (a `do` block's desugared `Task.andThen` binds,
        // one level per statement) costs one render per node, not one render
        // per node per enclosing level — the latter is exponential in nesting
        // depth, since each enclosing level's trial re-walks every level below.
        let arg_col = col.tab();
        let arg_one_strs: Vec<String> = args.iter().map(|a| self.expr_atom(a, arg_col)).collect();
        let one = format!("{head_s} {}", arg_one_strs.join(" "));
        let own = self.own_span(span);
        let (lo, hi) = (own.lo as usize, own.hi as usize);
        if !has_layout_newline(&one) && !self.was_multiline(span) && !self.forces_break(lo, hi) {
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
        let inner = self.pad(arg_col);
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
        // A head owning an end-of-line comment ends its line: it stands alone.
        let head_hi = head.span.hi as usize;
        let (mut out, rest, rest_strs): (String, &[Expr], &[String]) =
            match (args.split_first(), arg_one_strs.split_first()) {
                (Some((first, rest)), Some((first_str, tail_strs)))
                    if Self::joins_on_head_line(first, first_str)
                        && head_line_fits(&head_s, first, col)
                        && !self.trails_at(head_hi)
                        && (is_simple_ref(first)
                            || first_is_block(first)
                            || later_block(tail_strs)) =>
                {
                    let trail = self.trail_inside(first.span.hi as usize, hi);
                    (format!("{head_s} {first_str}{trail}"), rest, tail_strs)
                }
                _ => {
                    let trail = self.trail_inside(head_hi, hi);
                    (format!("{head_s}{trail}"), args, arg_one_strs.as_slice())
                }
            };
        for (a, s) in rest.iter().zip(rest_strs) {
            let trail = self.trail_inside(a.span.hi as usize, hi);
            let _ = write!(out, "\n{inner}{s}{trail}");
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

    /// An operator chain, laid out by its precedence groups.
    ///
    /// A group is the run of operands its loosest operators split (see
    /// [`chain_groups`]); a tighter run between two splits is a child group.
    /// A broken group keeps its first operand on the current line and starts
    /// each split operator's line one tab stop past the group's column, the
    /// operand following on that line; a group of `<|` instead leaves each
    /// operator at the end of its line and starts the operand on the next. A
    /// child group breaks only when it must (an operand broke, or a comment
    /// sits above one); the whole chain also breaks when the source wrote it
    /// across lines, elm-format's modal rule.
    fn binops(
        &self,
        chain: &[(Expr, Located<ipe_intern::Symbol>)],
        last: &Expr,
        col: Col,
        span: ipe_diagnostics::Span,
    ) -> String {
        let ops: Vec<String> = chain.iter().map(|(_, op)| self.sym(op.value)).collect();
        let operands: Vec<&Expr> = chain
            .iter()
            .map(|(operand, _)| operand)
            .chain(std::iter::once(last))
            .collect();
        let groups = OpGroups::of(&ops);

        // Every operand is rendered exactly ONCE, at the column it takes in
        // the broken layout, and each group's flat-versus-broken choice reads
        // those renderings. A rendering with no layout newline reads
        // identically at any column (padding is only ever inserted after a
        // newline), so the same string serves a flat group too. Rendering a
        // flat candidate first and every operand again for the broken layout
        // costs two renders per node per ENCLOSING chain, which is exponential
        // in nesting depth.
        let mut at: Vec<Col> = vec![col; operands.len()];
        for g in &groups.0 {
            let base = at.get(g.lo).copied().unwrap_or(col);
            let line = base.tab();
            for &split in &g.splits {
                let op = ops.get(split).map_or("", String::as_str);
                let start = if g.backward {
                    line
                } else {
                    line.past(op.chars().count() + 1)
                };
                if let Some(slot) = at.get_mut(split + 1) {
                    *slot = start;
                }
            }
        }
        // Each operator carries the operand to its right. A comment above an
        // operator line attaches to that right operand, so it is claimed here
        // and printed above the operator.
        let last_index = operands.len().saturating_sub(1);
        let mut rendered: Vec<Item<'a>> = operands
            .iter()
            .zip(&at)
            .enumerate()
            .map(|(i, (operand, &c))| {
                let render = || {
                    if i == last_index {
                        self.binop_last_operand(operand, c)
                    } else {
                        self.binop_operand(operand, c)
                    }
                };
                if i == 0 {
                    (Run::default(), render())
                } else {
                    self.claim_expr(operand, render)
                }
            })
            .collect();

        // Children sit after their parent, so the reverse order assembles
        // every child before the group that holds it.
        let mut texts: Vec<String> = vec![String::new(); groups.0.len()];
        let operand_end = |i: usize| operands.get(i).map_or(0, |o| o.span.hi as usize);
        let chain_hi = span.hi as usize;
        for (index, g) in groups.0.iter().enumerate().rev() {
            let mut children = g.children.iter();
            let mut segments: Vec<Item<'a>> = Vec::new();
            let mut trails: Vec<String> = Vec::new();
            let ends = g.splits.iter().copied().chain(std::iter::once(g.hi));
            let mut start = g.lo;
            for end in ends {
                let comments = if start == g.lo {
                    Run::default()
                } else {
                    rendered
                        .get_mut(start)
                        .map(|(cs, _)| std::mem::take(cs))
                        .unwrap_or_default()
                };
                let text = if end > start {
                    children
                        .next()
                        .and_then(|&child| texts.get_mut(child))
                        .map(std::mem::take)
                        .unwrap_or_default()
                } else {
                    rendered
                        .get_mut(start)
                        .map(|(_, text)| std::mem::take(text))
                        .unwrap_or_default()
                };
                segments.push((comments, text));
                trails.push(if g.backward {
                    String::new()
                } else {
                    self.trail_inside(operand_end(end), chain_hi)
                });
                start = end + 1;
            }
            // A segment's end-of-line comment needs the line end a broken
            // group opens after it; a `<|` group ends its lines with the
            // operator, so its comments are demoted.
            let group_lo = operands.get(g.lo).map_or(0, |o| o.span.lo as usize);
            let owns_trail = !g.backward && self.forces_break(group_lo, operand_end(g.hi));
            let forced = owns_trail
                || segments
                    .iter()
                    .any(|(cs, text)| !cs.is_empty() || has_layout_newline(text));
            let broken = forced || (index == 0 && self.was_multiline(span));
            let line = at.get(g.lo).copied().unwrap_or(col).tab();
            if !broken {
                trails.clear();
            }
            let text = self.op_group(&ops, g, segments, &trails, broken, line);
            if let Some(slot) = texts.get_mut(index) {
                *slot = text;
            }
        }
        texts.into_iter().next().unwrap_or_default()
    }

    /// Join one operator group's `segments`, the first operand or child
    /// group and then the one right of each split, each with its comments.
    ///
    /// A `broken` group starts each split's line at `line`, `trails[i]`
    /// ending segment `i`'s line.
    fn op_group(
        &self,
        ops: &[String],
        g: &OpGroup,
        segments: Vec<Item<'a>>,
        trails: &[String],
        broken: bool,
        line: Col,
    ) -> String {
        let mut segments = segments.into_iter();
        let mut out = segments.next().map(|(_, text)| text).unwrap_or_default();
        let pad = self.pad(line);
        for (i, (&split, (comments, text))) in g.splits.iter().zip(segments).enumerate() {
            out.push_str(trails.get(i).map_or("", String::as_str));
            let op = ops.get(split).map_or("", String::as_str);
            if !broken {
                let _ = write!(out, " {op} {text}");
            } else if g.backward {
                // Each right operand opens the next line; its comments head
                // that line.
                let text = self.with_comments(&comments, &text, line);
                let _ = write!(out, " {op}\n{pad}{text}");
            } else {
                open_line(&mut out, &comments, pad);
                let _ = write!(out, "{op} {text}");
            }
        }
        out
    }

    /// An operand of a binary-operator chain. Unlike a general atom, a function
    /// APPLICATION operand needs no parentheses — application binds tighter than
    /// every binary operator, so `List.foldr f start <| toList v` is
    /// unambiguous and elm-format leaves both calls bare. Only a nested operator
    /// chain, `case` / `if` / `let`, or lambda still needs wrapping.
    fn binop_operand(&self, e: &Expr, col: Col) -> String {
        // A `do` block desugars to a call, but its statement layout would
        // swallow a following operator line: it keeps its parentheses.
        if matches!(e.value, Expr_::Call(..)) && self.do_keyword_end(e.span).is_none() {
            self.expr(e, col)
        } else {
            self.expr_atom(e, col)
        }
    }

    /// The final operand of an operator chain. A trailing `\x -> …` needs no
    /// wrapping parens — the operator to its left already delimits it and its
    /// body extends to the end of the expression, so elm-format emits it bare
    /// (`f <| \x -> body`). Every other operand keeps [`Self::binop_operand`].
    fn binop_last_operand(&self, e: &Expr, col: Col) -> String {
        if matches!(e.value, Expr_::Lambda(..)) {
            self.expr(e, col)
        } else {
            self.binop_operand(e, col)
        }
    }

    fn lambda(
        &self,
        params: &[Pattern],
        body: &Expr,
        col: Col,
        span: ipe_diagnostics::Span,
    ) -> String {
        let ps: Vec<String> = params.iter().map(|p| self.pattern_atom(&p.value)).collect();
        // A comment among the parameters prints above the lambda, through
        // its `claim_expr`.
        let head = format!("\\{} ->", ps.join(" "));
        // A block-form body (`let` / `case` / `if`) always drops to the next
        // line, one tab stop in: an inline `-> let …` would place the `let`
        // keyword mid-line, breaking its layout-sensitive block on re-parse.
        // A modal body — one written across multiple source lines — also drops
        // to its own indented line, matching elm-format's `\x ->\n    body`.
        // So does a body carrying a comment, which needs a line of its own, and
        // a body that breaks across lines inline: the printed lambda is then
        // multi-line, so the block form is the one a second pass would pick.
        // Any other body stays inline after the arrow.
        //
        // Rendered exactly ONCE, at the block column, and reused for both the
        // inline and the block candidate: a result with no embedded newline
        // reads identically at any column (padding is only ever inserted
        // after a newline), so that one string serves either placement.
        // Trying an inline render at this column, rejecting it, and
        // re-rendering at the block column — as elm-format's own two-pass
        // check would — costs one render per node per ENCLOSING level; for a
        // right-nested lambda chain (a `do` block's desugared binds, one
        // level per statement) that is exponential in the number of
        // statements. Budgeting the fits-inline check at the block column
        // (narrower than the inline placement actually occupies) is
        // conservative-only: a narrower width budget can only ever wrap a
        // body the wider one would have kept on one line, never the reverse,
        // so this can pick block form a body would have fit on the arrow's
        // line, but never the other way around.
        let block_body = matches!(body.value, Expr_::Let(..) | Expr_::Case(..) | Expr_::If(..))
            || !self.anchored(body.span.lo as usize).is_empty();
        let body_col = col.tab();
        let body_s = self.expr(body, body_col);
        if !block_body && !self.was_multiline(span) && !has_layout_newline(&body_s) {
            format!("{head} {body_s}")
        } else {
            format!("{head}\n{}{body_s}", self.pad(body_col))
        }
    }

    fn case(&self, scrut: &Expr, arms: &[(Pattern, Expr)], col: Col) -> String {
        let scrut_s = self.expr(scrut, col.past("case ".len()));
        let arm_col = col.tab();
        let body_col = arm_col.tab();
        let arm_pad = self.pad(arm_col);
        let body_pad = self.pad(body_col);
        let mut out = format!("case {scrut_s} of");
        for (i, (pat, body)) in arms.iter().enumerate() {
            // A comment above an arm attaches to its pattern and sits on its
            // own arm-indented line, glued to the pattern, matching
            // elm-format's convention for section comments inside a `case`.
            // The blank line between arms is always emitted, before the run.
            // A comment inside the pattern prints above the arm too, in the
            // same run, so a second pass reads it as one above the pattern.
            if i > 0 {
                out.push('\n');
            }
            let run = self.anchored_in(pat.span.lo as usize, body.span.lo as usize);
            let body_s = self.expr(body, body_col);
            open_line(&mut out, &run, arm_pad);
            // The last arm's body ends the `case`: its comment is the
            // enclosing composer's.
            let trail = if i + 1 < arms.len() {
                self.trail_after(body.span.hi as usize)
            } else {
                String::new()
            };
            let _ = write!(
                out,
                "{} ->\n{body_pad}{body_s}{trail}",
                self.pattern(&pat.value)
            );
        }
        out
    }

    fn let_(&self, bindings: &[LetBinding], body: &Expr, col: Col) -> String {
        let bind_col = col.tab();
        let value_col = bind_col.tab();
        let bind_pad = self.pad(bind_col);
        let body_val_pad = self.pad(value_col);
        let mut out = String::from("let");
        for (i, b) in bindings.iter().enumerate() {
            // elm-format separates successive `let` bindings with a blank
            // line; the comments above a binding, attached to its binder,
            // replace that blank line.
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
            let run = self.anchored_in(b.pat.span.lo as usize, value.span.lo as usize);
            if i > 0 && run.is_empty() {
                out.push('\n');
            }
            // elm-format ALWAYS drops a `let` binding's value onto its own
            // four-space-indented line, however short — `x =\n    1`.
            let val = self.expr(value, value_col);
            let trail = self.trail_after(value.span.hi as usize);
            open_line(&mut out, &run, bind_pad);
            let _ = write!(out, "{binder} =\n{body_val_pad}{val}{trail}");
        }
        let in_pad = self.pad(col);
        let _ = write!(out, "\n{in_pad}in\n{in_pad}{}", self.expr(body, col));
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

    fn if_(&self, branches: &[(Expr, Expr)], else_: &Expr, col: Col) -> String {
        let body_col = col.tab();
        let inner = self.pad(body_col);
        let mut out = String::new();
        for (i, (cond, body)) in branches.iter().enumerate() {
            let lead = if i == 0 { "if" } else { "else if" };
            // A comment above `else if` attaches to that `if` keyword, the
            // token just before the condition.
            if i > 0 {
                let keyword = self
                    .token_before(cond.span.lo as usize)
                    .filter(|t| matches!(t.kind, TokenKind::If));
                let run = keyword.map_or_else(Run::default, |t| self.anchored(t.lo));
                comments::emit(&mut out, &run, self.pad(col), Tail::Glued);
            }
            let _ = write!(
                out,
                "{lead} {} then\n{inner}{}{}\n\n{}",
                self.expr(cond, col.past(lead.len() + 1)),
                self.expr(body, body_col),
                self.trail_after(body.span.hi as usize),
                self.pad(col)
            );
        }
        let _ = write!(out, "else\n{inner}{}", self.expr(else_, body_col));
        out
    }

    // A collection element starts two columns past its bracket, after the
    // `[ ` / `, ` it follows, and is rendered at that column; the `,` lines
    // and the closing bracket sit at the bracket's column.
    //
    // A comment above an element attaches to its first token (a record
    // field's name) and prints on its own line above the element; one above
    // the closing bracket prints above the bracket. A commented collection is
    // always multi-line.
    fn tuple(&self, elems: &[Expr], col: Col, span: ipe_diagnostics::Span) -> String {
        let items = self.elements(elems, col.past(2));
        let ends: Vec<usize> = elems.iter().map(|e| e.span.hi as usize).collect();
        self.collection(("(", ")"), items, &ends, span, col)
    }

    fn list(&self, elems: &[Expr], col: Col, span: ipe_diagnostics::Span) -> String {
        if elems.is_empty() {
            return self.with_comments(&self.closing_comments(self.own_span(span)), "[]", col);
        }
        let items = self.elements(elems, col.past(2));
        let ends: Vec<usize> = elems.iter().map(|e| e.span.hi as usize).collect();
        self.collection(("[", "]"), items, &ends, self.own_span(span), col)
    }

    fn record(
        &self,
        fields: &[(Located<ipe_intern::Symbol>, Expr)],
        col: Col,
        span: ipe_diagnostics::Span,
    ) -> String {
        if fields.is_empty() {
            return self.with_comments(&self.closing_comments(self.own_span(span)), "{}", col);
        }
        let items = self.fields(fields, col.past(2));
        let ends: Vec<usize> = fields.iter().map(|(_, v)| v.span.hi as usize).collect();
        self.collection(("{", "}"), items, &ends, self.own_span(span), col)
    }

    /// Each element of a list or tuple, rendered at `col`, with the comments
    /// above it.
    fn elements(&self, elems: &[Expr], col: Col) -> Vec<Item<'a>> {
        elems
            .iter()
            .map(|e| self.claim_expr(e, || self.expr(e, col)))
            .collect()
    }

    /// Each `name = value` field of a record, starting at `col`, with the
    /// comments above it.
    ///
    /// A value that renders on one line follows its `=`; any other starts on
    /// the next line, one tab stop past the field.
    fn fields(&self, fields: &[(Located<ipe_intern::Symbol>, Expr)], col: Col) -> Vec<Item<'a>> {
        let value_col = col.tab();
        fields
            .iter()
            .map(|(n, v)| {
                self.claim(n.span.lo as usize, None, || {
                    let name = self.sym(n.value);
                    let value = self.expr(v, value_col);
                    if has_layout_newline(&value) {
                        format!("{name} =\n{}{value}", self.pad(value_col))
                    } else {
                        format!("{name} = {value}")
                    }
                })
            })
            .collect()
    }

    /// A list, tuple or record: single-line when it fits, the source kept it
    /// on one line and no comment is inside; leading-comma multi-line
    /// otherwise.
    ///
    /// `ends[i]` is the end of item `i`'s last token; its end-of-line comment
    /// ends the item's line.
    fn collection(
        &self,
        (open, close): (&str, &str),
        mut items: Vec<Item<'a>>,
        ends: &[usize],
        span: ipe_diagnostics::Span,
        col: Col,
    ) -> String {
        let (lo, hi) = (span.lo as usize, span.hi as usize);
        let closing = self.closing_comments(span);
        let commented = !closing.is_empty()
            || items.iter().any(|(cs, _)| !cs.is_empty())
            || self.forces_break(lo, hi);
        let parts: Vec<&str> = items.iter().map(|(_, s)| s.as_str()).collect();
        let one = format!("{open} {} {close}", parts.join(", "));
        if !commented && !has_layout_newline(&one) && !self.was_multiline(span) {
            return one;
        }
        for ((_, part), &end) in items.iter_mut().zip(ends) {
            part.push_str(&self.trail_inside(end, hi));
        }
        comma_multiline(&self.pads, open, close, &items, &closing, col)
    }

    fn update(
        &self,
        base: &Located<ipe_intern::Symbol>,
        fields: &[(Located<ipe_intern::Symbol>, Expr)],
        col: Col,
        span: ipe_diagnostics::Span,
    ) -> String {
        let base_s = self.sym(base.value);
        // The `| ` / `, ` lines start one tab stop past the brace, and each
        // field two columns past that.
        let bar_col = col.tab();
        let items = self.fields(fields, bar_col.past(2));
        let span = self.own_span(span);
        let closing = self.closing_comments(span);
        let (lo, hi) = (span.lo as usize, span.hi as usize);
        let commented = !closing.is_empty()
            || items.iter().any(|(cs, _)| !cs.is_empty())
            || self.forces_break(lo, hi);
        let parts: Vec<&str> = items.iter().map(|(_, s)| s.as_str()).collect();
        let one = format!("{{ {base_s} | {} }}", parts.join(", "));
        if !commented && !has_layout_newline(&one) && !self.was_multiline(span) {
            return one;
        }
        // Multiline update: `{ base` on the first line, then the `| field` /
        // `, field` lines one tab stop past the brace (elm-format aligns the
        // update pipe under the record body, not under the `{`), and the
        // closing `}` back at the brace column.
        let close_pad = self.pad(col);
        let inner = self.pad(bar_col);
        let mut out = format!("{{ {base_s}{}", self.trail_after(base.span.hi as usize));
        for (i, ((comments, p), (_, value))) in items.iter().zip(fields).enumerate() {
            let lead = if i == 0 { "|" } else { "," };
            open_line(&mut out, comments, inner);
            let trail = self.trail_inside(value.span.hi as usize, hi);
            let _ = write!(out, "{lead} {p}{trail}");
        }
        if closing.is_empty() {
            out.push('\n');
        } else {
            // The closing run sits at the field column, the brace back at its own.
            let _ = write!(out, "\n{inner}");
            comments::emit(&mut out, &closing, inner, Tail::Source { blank_lines: 0 });
        }
        let _ = write!(out, "{close_pad}}}");
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

/// Whether `s` contains a newline that is part of the source *layout*.
///
/// The scan follows the lexer's token boundaries: a `\n` inside a
/// triple-quoted string is content, and a `"""` inside a normal string, a
/// char literal, or a comment opens nothing. A newline inside a block comment
/// is layout, as is a token left unterminated (the conservative reading).
fn has_layout_newline(s: &str) -> bool {
    let mut rest = s;
    loop {
        rest = if let Some(after) = rest.strip_prefix("\"\"\"") {
            match after.split_once("\"\"\"") {
                Some((_, tail)) => tail,
                None => return true,
            }
        } else if let Some(after) = rest.strip_prefix("--") {
            after
                .find('\n')
                .map_or("", |end| after.get(end..).unwrap_or(""))
        } else if let Some(after) = rest.strip_prefix("{-") {
            let tail = skip_block_comment_body(after);
            let body = after
                .get(..after.len().saturating_sub(tail.len()))
                .unwrap_or(after);
            if body.contains('\n') || !body.ends_with("-}") {
                return true;
            }
            tail
        } else {
            let mut chars = rest.chars();
            match chars.next() {
                None => return false,
                Some('\n') => return true,
                Some(quote @ ('"' | '\'')) => match skip_quoted(chars.as_str(), quote) {
                    Some(tail) => tail,
                    None => return true,
                },
                Some(_) => chars.as_str(),
            }
        };
    }
}

/// What follows a single-line quoted token whose opening `quote` is already
/// consumed, honouring `\\` escapes; `None` when a raw newline or the end
/// comes before the closing quote.
fn skip_quoted(rest: &str, quote: char) -> Option<&str> {
    let mut chars = rest.chars();
    loop {
        match chars.next()? {
            '\n' => return None,
            '\\' => {
                chars.next()?;
            }
            c if c == quote => return Some(chars.as_str()),
            _ => {}
        }
    }
}

/// Whether the head plus its first argument fits on one line before the
/// argument's own break. For a multi-line triple-quoted string the join line is
/// `head """first-content-line`; elm-format only hugs the string to the function
/// when that opening line stays within the width budget, otherwise the string
/// drops to its own indented line. Other joinable first arguments (names, empty
/// collections) are short and always fit.
fn head_line_fits(head_s: &str, first: &Expr, col: Col) -> bool {
    let Expr_::MultilineStr { raw: s, .. } = &first.value else {
        return true;
    };
    let first_content = s.split_once('\n').map_or(s.as_str(), |(f, _)| f);
    // column of the head + head + ` ` + `"""` + first content line
    let end = col.past(head_s.chars().count() + 1 + 3 + first_content.chars().count());
    end.0 <= MAX_WIDTH
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
type Item<'c> = (Run<'c>, String);

/// One precedence group of an operator chain, as the printer lays it out.
struct OpGroup {
    /// The index of the group's first operand.
    lo: usize,
    /// The index of the group's last operand.
    hi: usize,
    /// The operator indices the group splits at, left to right.
    splits: Vec<usize>,
    /// The child groups' indices, left to right.
    children: Vec<usize>,
    /// Whether every split is `<|`, which ends its line instead of starting
    /// the next one.
    backward: bool,
}

/// The precedence groups of one operator chain; a child sits after its
/// parent, and group `0` is the root.
struct OpGroups(Vec<OpGroup>);

impl OpGroups {
    /// The groups of the chain whose operators are spelled `ops`.
    ///
    /// The parser builds a chain only from the closed [`BinOp`] set. A
    /// spelling outside it has no precedence, so its chain is one group that
    /// splits at every operator; the re-parse guard then judges the output.
    fn of(ops: &[String]) -> Self {
        let known: Option<Vec<BinOp>> = ops.iter().map(|op| BinOp::from_text(op)).collect();
        let Some(known) = known else {
            return Self(vec![OpGroup {
                lo: 0,
                hi: ops.len(),
                splits: (0..ops.len()).collect(),
                children: Vec::new(),
                backward: false,
            }]);
        };
        let groups = chain_groups(&known);
        Self(
            groups
                .groups()
                .iter()
                .map(|g| OpGroup {
                    lo: g.lo(),
                    hi: g.hi(),
                    splits: g.splits().to_vec(),
                    children: g.children().to_vec(),
                    backward: g
                        .splits()
                        .iter()
                        .all(|&i| known.get(i) == Some(&BinOp::PipeLeft)),
                })
                .collect(),
        )
    }
}

/// Close the exposed-item `group` as one line of a multi-line exposing
/// clause, after `lead`, then open the next line at `pad`.
///
/// The first group follows `( `, each later one `, `.
fn push_exposing_group(out: &mut String, group: &mut Vec<String>, lead: &mut &str, pad: Pad<'_>) {
    if group.is_empty() {
        return;
    }
    let _ = write!(out, "{lead}{}\n{pad}", group.join(", "));
    group.clear();
    *lead = ", ";
}

/// The byte range of a lambda's parameters, from the first one to its body.
fn lambda_head(e: &Expr) -> Option<(usize, usize)> {
    let Expr_::Lambda(params, body) = &e.value else {
        return None;
    };
    let lo = params.first().map_or(body.span.lo, |p| p.span.lo);
    Some((lo as usize, body.span.lo as usize))
}

/// Open a fresh line at `pad`, headed by `run`; the caller then writes the
/// line's text.
fn open_line(out: &mut String, run: &Run<'_>, pad: Pad<'_>) {
    let _ = write!(out, "\n{pad}");
    comments::emit(out, run, pad, Tail::Glued);
}

/// Blank lines between two top-level items.
const TOP_LEVEL_BLANK_LINES: usize = 2;

/// Blank lines between the module header and the first import.
const IMPORT_BLANK_LINES: usize = 1;

/// How a run directly above a top-level head ends: glued to the head, or
/// across the top-level gap when the source left one.
const TOP_LEVEL_HEAD: Tail = Tail::Source {
    blank_lines: TOP_LEVEL_BLANK_LINES,
};

/// How a run hoisted above a top-level item ends: one blank line before the
/// item's own head run, else the top-level gap before the head.
const fn hoist_tail(head: &Run<'_>) -> Tail {
    Tail::Blank {
        blank_lines: if head.is_empty() {
            TOP_LEVEL_BLANK_LINES
        } else {
            1
        },
    }
}

/// The offset of a declaration's first token.
///
/// A definition with a signature starts at the signature's name, the code
/// token before the `:` that precedes the annotation.
fn decl_start(code: &[CodeToken], decl: &Decl<'_>) -> usize {
    match decl {
        Decl::Union(union) => union.span.lo as usize,
        Decl::Alias(alias) => alias.span.lo as usize,
        Decl::Foreign(foreign) => foreign.span.lo as usize,
        Decl::Value(value) => {
            value
                .value
                .type_annotation
                .as_ref()
                .map_or(value.value.name.span.lo as usize, |ann| {
                    let ann_lo = ann.span.lo as usize;
                    let at = code.partition_point(|tok| tok.lo < ann_lo);
                    let before = |back: usize| at.checked_sub(back).and_then(|j| code.get(j));
                    match (before(1), before(2)) {
                        (Some(colon), Some(name)) if matches!(colon.kind, TokenKind::Colon) => {
                            name.lo
                        }
                        _ => ann_lo,
                    }
                })
        }
    }
}

/// A module's declarations in source order.
fn module_decls(m: &Module) -> Vec<Decl<'_>> {
    // Destructured field by field, with no `..`: a new kind of top-level
    // declaration is a build error here until it is printed, never a
    // silently dropped declaration.
    let Module {
        module_kw: _,
        name: _,
        exposing: _,
        imports: _,
        values,
        unions,
        aliases,
        foreigns,
    } = m;
    let mut decls: Vec<Decl<'_>> = Vec::new();
    decls.extend(unions.iter().map(Decl::Union));
    decls.extend(aliases.iter().map(Decl::Alias));
    decls.extend(values.iter().map(Decl::Value));
    decls.extend(foreigns.iter().map(Decl::Foreign));
    decls.sort_by_key(Decl::lo);
    decls
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
    closing: &Run<'_>,
    col: Col,
) -> String {
    let pad = pads.pad(col);
    let mut out = String::from(open);
    for (i, (comments, part)) in items.iter().enumerate() {
        if i == 0 && comments.is_empty() {
            let _ = write!(out, " {part}");
            continue;
        }
        open_line(&mut out, comments, pad);
        let sep = if i == 0 { " " } else { "," };
        let _ = write!(out, "{sep} {part}");
    }
    open_line(&mut out, closing, pad);
    out.push_str(close);
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

/// One indent step: the width [`Col::tab`] rounds up to.
const INDENT_UNIT: usize = 4;

/// A column of the printed text, counted in chars from the line start.
///
/// Every child is placed at the column its parent computed from the text it
/// put before the child, so no rendered text is ever re-indented and no
/// indentation is counted in levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Col(usize);

impl Col {
    /// The left margin.
    const ZERO: Self = Self(0);

    /// The body column of a top-level declaration.
    const BODY: Self = Self(INDENT_UNIT);

    /// The next tab stop strictly right of this column.
    const fn tab(self) -> Self {
        Self(
            (self.0 / INDENT_UNIT)
                .saturating_add(1)
                .saturating_mul(INDENT_UNIT),
        )
    }

    /// The column `width` chars right of this one.
    const fn past(self, width: usize) -> Self {
        Self(self.0.saturating_add(width))
    }
}

/// The indentation bytes one print may still emit.
///
/// A layout repeats one indentation on every line it breaks, so indentation
/// is the output an input multiplies: every rendering of a [`Pad`] is charged
/// its bytes here, against the print's [`OutputCap`]. A candidate layout that is thrown
/// away gives its bytes back ([`PadBudget::rewind`]), so only the kept text is
/// charged. Past the budget a pad renders nothing, the print is marked
/// exceeded for good, and every later render returns at once: the caller
/// refuses the whole print.
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

    /// The indentation reaching `col`, charged each time it renders.
    const fn pad(&self, col: Col) -> Pad<'_> {
        Pad { col, budget: self }
    }

    /// Take `bytes` from the budget.
    ///
    /// `false`, and exceeded from then on, when they do not fit.
    fn charge(&self, bytes: usize) -> bool {
        if self.exceeded.get() {
            return false;
        }
        let Some(left) = self.left.get().checked_sub(bytes) else {
            self.left.set(0);
            self.exceeded.set(true);
            return false;
        };
        self.left.set(left);
        true
    }

    /// Whether some pad did not fit the budget.
    const fn exceeded(&self) -> bool {
        self.exceeded.get()
    }

    /// The budget left now, to return to if what renders next is discarded.
    const fn mark(&self) -> PadMark {
        PadMark(self.left.get())
    }

    /// Drop `discarded`, a candidate rendered since `mark` that the print
    /// does not keep, and give back the bytes it was charged.
    ///
    /// The candidate is taken by value, so no text those bytes paid for
    /// outlives the refund. An exceeded budget stays exceeded: a print that
    /// once ran past its cap is refused whole.
    fn rewind(&self, mark: PadMark, discarded: String) {
        drop(discarded);
        if !self.exceeded.get() {
            self.left.set(mark.0);
        }
    }
}

/// The budget a [`PadBudget`] held at one point of a print.
#[derive(Clone, Copy)]
struct PadMark(usize);

/// The spaces reaching one column, rendered through its [`PadBudget`].
#[derive(Clone, Copy)]
struct Pad<'b> {
    col: Col,
    budget: &'b PadBudget,
}

impl fmt::Display for Pad<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.budget.charge(self.col.0) {
            let mut left = self.col.0;
            while left > 0 {
                let chunk = left.min(SPACES.len());
                f.write_str(SPACES.get(..chunk).unwrap_or(""))?;
                left -= chunk;
            }
        }
        Ok(())
    }
}

/// One write of spaces. A `{:width$}` argument is a `u16` at run time and
/// panics past 65535, so a column an input decides is written in chunks.
const SPACES: &str = "                                                                ";

/// Whether `s`, placed at column `col`, fits within [`MAX_WIDTH`]. A multi-line
/// `s` never "fits" as a single line.
fn fits(s: &str, col: Col) -> bool {
    !s.contains('\n') && col.past(s.chars().count()).0 <= MAX_WIDTH
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
        assert_eq!(comments.first().map(Comment::text), Some("{- real -}"));
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
                    once.contains(c.text()),
                    "comment {:?} lost after fmt for:\n{src}\noutput:\n{once}",
                    c.text()
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
                3 => format!("        v{i} <- Db.open Location.memory\n"),
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
            assert!(
                out.contains(c.text()),
                "comment {:?} lost:\n{out}",
                c.text()
            );
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
            assert!(
                out.contains(c.text()),
                "comment {:?} lost:\n{out}",
                c.text()
            );
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
            out.contains(&format!("\n{}, aaaaaaaaaaaaaaa", " ".repeat(196))),
            "precondition: the items sit 196 columns deep: {out}"
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
        let pad = budget.pad(Col(4));
        assert_eq!(format!("{pad}{pad}"), "        ");
        assert!(!budget.exceeded());
        assert_eq!(format!("{pad}"), "");
        assert!(budget.exceeded());
        assert_eq!(format!("{}", budget.pad(Col::ZERO)), "");
        assert!(budget.exceeded());
    }

    /// A column past `u16::MAX` renders in full: the pad never hands a
    /// runtime width to the formatter, which panics there.
    #[test]
    fn pad_past_u16_max_renders_every_space() {
        let budget = PadBudget::new(OutputCap(1 << 20));
        let rendered = format!("{}", budget.pad(Col(70_000)));
        assert_eq!(rendered.len(), 70_000);
        assert!(rendered.bytes().all(|b| b == b' '));
        assert!(!budget.exceeded());
        assert_eq!(SPACES.len(), 64);
    }

    /// A rewind gives back what was charged since its mark, and an exceeded
    /// budget stays exceeded through one.
    #[test]
    fn pad_budget_rewind_refunds_only_an_unexceeded_budget() {
        let budget = PadBudget::new(OutputCap(8));
        let mark = budget.mark();
        let discarded = format!("{}", budget.pad(Col(8)));
        assert_eq!(discarded, "        ");
        budget.rewind(mark, discarded);
        assert_eq!(format!("{}", budget.pad(Col(8))), "        ");
        let mark = budget.mark();
        assert_eq!(format!("{}", budget.pad(Col(1))), "");
        assert!(budget.exceeded());
        budget.rewind(mark, String::new());
        assert!(budget.exceeded());
        assert_eq!(format!("{}", budget.pad(Col::ZERO)), "");
    }

    /// A module whose value is `depth` source-multiline pipes, each into a
    /// lambda whose body is the next pipe.
    fn nested_pipe_lambdas(depth: usize) -> String {
        let pad = |n: usize| " ".repeat(INDENT_UNIT * n);
        let mut body = format!("{}b", pad(1 + 3 * depth));
        for k in (0..depth).rev() {
            let i = 1 + 3 * k;
            body = format!(
                "{}a\n{}|> f\n{}(\\v{k} ->\n{body}\n{})",
                pad(i),
                pad(i + 1),
                pad(i + 2),
                pad(i + 2)
            );
        }
        format!("module M exposing (x)\n\n\nx =\n{body}\n")
    }

    /// Only the layout a print keeps is charged: an operator chain renders
    /// no flat candidate beside its broken layout, so nested pipes format
    /// under a cap of exactly their output.
    #[test]
    fn discarded_operator_layout_is_not_charged() {
        let depth = 12;
        let src = nested_pipe_lambdas(depth);
        let out = format_source_capped(&src, OutputCap(usize::MAX)).expect("nested pipes format");
        assert_eq!(
            out.matches("|> f").count(),
            depth,
            "precondition: every chain is printed: {out}"
        );
        assert!(
            out.lines().all(|l| !l.contains("a |> f")),
            "precondition: every chain stays broken: {out}"
        );
        assert_eq!(
            format_source_capped(&src, OutputCap(out.len()))
                .ok()
                .as_deref(),
            Some(out.as_str())
        );
        assert_eq!(format_source(&src).ok().as_deref(), Some(out.as_str()));
    }

    /// A module whose value is one source line of `depth` pipes, each carrying
    /// a block comment before its right operand and nesting the next pipe in a
    /// lambda. The comment breaks every chain, whatever the source layout.
    fn nested_commented_pipes(depth: usize) -> String {
        let mut body = "b".to_owned();
        for k in (0..depth).rev() {
            body = format!("a |> {{- c -}} f (\\v{k} -> {body})");
        }
        format!("module M exposing (x)\n\n\nx =\n    {body}\n")
    }

    /// A named generator of a nested module by depth.
    type NamedShape = (&'static str, fn(usize) -> String);

    /// The render calls one format of `src` makes. A refused format has
    /// rendered all the same, so the outcome is not read.
    fn render_calls_of(src: &str) -> u64 {
        reset_render_call_count();
        let _ = format_source(src);
        render_call_count()
    }

    /// Each operand of an operator chain renders once, so the render count of
    /// nested chains grows with their depth, not with its power of two.
    ///
    /// A chain that renders a flat candidate and then every operand again for
    /// its broken layout renders the chain below it twice per level; depth 16
    /// would then cost about 4096 times depth 4 where this bound allows 8. The
    /// count is a work counter, never wall time, so the test cannot flake.
    #[test]
    fn nested_operator_chains_render_each_operand_once() {
        let shapes: [NamedShape; 2] = [
            ("source-multiline", nested_pipe_lambdas),
            ("commented", nested_commented_pipes),
        ];
        for (name, shape) in shapes {
            let small = render_calls_of(&shape(4));
            let big = render_calls_of(&shape(16));
            assert!(
                small >= 4,
                "{name}: precondition: every level renders at least once: {small}"
            );
            assert!(
                big <= small * 8,
                "{name}: render calls grew super-linearly with depth: \
                 {small} at depth 4, {big} at depth 16"
            );
        }
    }

    /// A module whose value is `depth` lists nested in their first element,
    /// the innermost holding `items` ones: every line of the innermost list
    /// starts two columns further in per enclosing list.
    fn nested_first_lists(depth: usize, items: usize) -> String {
        let ones = vec!["1"; items].join(",");
        let open = "[ ".repeat(depth);
        let close = "]".repeat(depth);
        format!("module M exposing (x)\n\n\nx =\n    {open}{ones}\n    {close}\n")
    }

    /// The columns a nested collection adds to each line are charged like
    /// any indentation: past the cap the printer stops rendering, so its text
    /// stays within the cap plus four times the source, where rendering every
    /// line's columns would hold the source's items times twice its depth.
    #[test]
    fn nested_collection_columns_past_the_cap_are_charged() {
        let depth = 20;
        let small = format_source(&nested_first_lists(depth, 50)).expect("a small nest formats");
        let deepest = small
            .lines()
            .filter(|l| l.trim_start().starts_with(", 1"))
            .map(|l| l.len() - l.trim_start().len())
            .max()
            .unwrap_or(0);
        assert!(
            deepest >= 2 * (depth - 1),
            "precondition: the innermost items move in once per enclosing list: {small}"
        );
        let larger = format_source(&nested_first_lists(depth, 100)).expect("a small nest formats");
        let growth = larger.len().saturating_sub(small.len()) / 50;

        let items = 20_000;
        let src = nested_first_lists(depth, items);
        let cap = OutputCap::for_input(src.len());
        let bound = cap.bytes() + 4 * src.len();
        assert!(
            growth * items > bound,
            "precondition: rendering every column passes the bound: {growth} * {items} <= {bound}"
        );
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
        assert!(
            rendered.get() <= bound,
            "the printer rendered {} bytes past the budget (bound {bound})",
            rendered.get()
        );
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
    fn refusal(src: &str, render: impl Fn(&Printer<'_>, &Module) -> String) -> String {
        match format_guarded(src, OutputCap::for_input(src.len()), render) {
            Err(FmtError::RoundTrip(fault)) => fault.to_string(),
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

    /// The run fault of formatting `src` with its own print, `from` replaced
    /// by `to`; the edit keeps every comment, so only the run guard can fire.
    fn run_fault(src: &str, from: &str, to: &str) -> Option<(Owner, RunFault)> {
        let printed = format_source(src).expect("formats");
        assert!(printed.contains(from), "{from:?} not in:\n{printed}");
        match format_guarded(src, OutputCap::for_input(src.len()), |p, m| {
            p.module(m).replacen(from, to, 1)
        }) {
            Err(FmtError::RoundTrip(RoundTripFault::CommentRun { owner, fault })) => {
                Some((owner, fault))
            }
            _ => None,
        }
    }

    #[test]
    fn comment_guard_refuses_glued_section_comment() {
        let src = "module M exposing (x)\n\n\n-- section\n\n\nx =\n    1\n";
        assert_eq!(
            run_fault(src, "-- section\n\n\n", "-- section\n"),
            Some((Owner::Decl(0), RunFault::HeadRun))
        );
    }

    #[test]
    fn comment_guard_refuses_split_run() {
        let src = "module M exposing (x)\n\n\n-- a\n-- b\nx =\n    1\n";
        assert_eq!(
            run_fault(src, "-- b\nx =\n    1", "x =\n    -- b\n    1"),
            Some((Owner::Decl(0), RunFault::Adjacency))
        );
    }

    #[test]
    fn comment_guard_refuses_lost_gap_inside_run() {
        let src = "module M exposing (x)\n\n\n-- a\n\n-- b\nx =\n    1\n";
        assert_eq!(
            run_fault(src, "-- a\n\n-- b", "-- a\n-- b"),
            Some((Owner::Decl(0), RunFault::Adjacency))
        );
    }

    #[test]
    fn comment_guard_refuses_detached_module_doc() {
        let src = "-- | doc\nmodule M exposing (x)\n\n\nx =\n    1\n";
        assert_eq!(
            run_fault(src, "-- | doc\n", "-- | doc\n\n"),
            Some((Owner::Header, RunFault::HeadRun))
        );
    }

    #[test]
    fn comment_guard_refuses_run_moved_to_another_declaration() {
        let src = "module M exposing (x, y)\n\n\nx =\n    1\n\n\n-- about y\ny =\n    2\n";
        assert_eq!(
            run_fault(
                src,
                "x =\n    1\n\n\n-- about y\n",
                "-- about y\nx =\n    1\n\n\n"
            ),
            Some((Owner::Decl(0), RunFault::OwnerMultiset))
        );
    }

    #[test]
    fn comment_guard_refuses_hoist_joining_a_doc() {
        let src = "module M exposing (x)\n\n\n-- | doc\nx =\n    -- inner\n    1\n";
        assert_eq!(
            run_fault(
                src,
                "-- | doc\nx =\n    -- inner\n",
                "-- inner\n-- | doc\nx =\n"
            ),
            Some((Owner::Decl(0), RunFault::HeadRun))
        );
    }

    #[test]
    fn comment_guard_refuses_comment_inserted_inside_run() {
        let src = "module M exposing (x)\n\n\n-- a\n-- b\nx =\n    -- c\n    1\n";
        assert_eq!(
            run_fault(
                src,
                "-- a\n-- b\nx =\n    -- c\n",
                "-- a\n-- c\n-- b\nx =\n"
            ),
            Some((Owner::Decl(0), RunFault::Adjacency))
        );
    }

    #[test]
    fn comment_guard_refuses_blank_inserted_in_case_arm_run() {
        let src = "module M exposing (f)\n\n\nf x =\n    case x of\n        0 ->\n            1\n\n        -- one\n        -- two\n        _ ->\n            2\n";
        assert_eq!(
            run_fault(src, "-- one\n        -- two", "-- one\n\n        -- two"),
            Some((Owner::Decl(0), RunFault::Adjacency))
        );
    }

    /// A triple-quoted string strips the margin of its anchor column from
    /// every later line, so moving it to another column changes its value:
    /// the formatter refuses rather than printing the moved string.
    #[test]
    fn a_triple_quoted_string_moved_to_another_margin_is_refused() {
        let src = "module M exposing (x)\n\n\nx =\n    foo  \"\"\"abc\n            def\"\"\"\n";
        let detail = match format_source(src) {
            Err(FmtError::RoundTrip(fault)) => fault.to_string(),
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
        let texts: Vec<&str> = comments.iter().map(Comment::text).collect();
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

    /// `src` with each segment's input replaced by its output, last first.
    fn splice_all(src: &str, formatted: &Formatted) -> String {
        let mut segments = formatted.decls.clone();
        segments.sort_by_key(|segment| std::cmp::Reverse(segment.input.start));
        let mut edited = src.to_owned();
        for segment in segments {
            let new = formatted.text.get(segment.output).expect("output in text");
            edited.replace_range(segment.input, new);
        }
        edited
    }

    /// Each segment's output is its declaration's formatted text, leading
    /// comment included, and its input is that declaration's source bytes.
    #[test]
    fn format_with_segments_maps_each_declaration() {
        let src = "module M exposing (a, b)\n\na : Int\na =\n      1\n\n-- about b\nb = 2\n";
        let formatted = format_with_segments(src).expect("formats");
        assert_eq!(formatted.text, format_source(src).expect("formats"));
        let texts: Vec<(&str, &str)> = formatted
            .decls
            .iter()
            .map(|segment| {
                (
                    src.get(segment.input.clone()).expect("input in source"),
                    formatted
                        .text
                        .get(segment.output.clone())
                        .expect("output in text"),
                )
            })
            .collect();
        assert_eq!(
            texts,
            vec![
                ("a : Int\na =\n      1", "a : Int\na =\n    1"),
                ("-- about b\nb = 2", "-- about b\nb =\n    2"),
            ]
        );
        let edited = splice_all(src, &formatted);
        assert!(
            verify_rewrite(src, &edited).is_ok(),
            "the spliced segments verify"
        );
    }

    /// A declaration's interior and end-of-declaration end-of-line comments
    /// splice back once each: input and output segments both end at the
    /// declaration's last token, so the comment after it stays outside both.
    #[test]
    fn splicing_keeps_each_end_of_line_comment_once() {
        let src = "module M exposing (a, b)\n\n\na =\n    [ 1 -- one\n    , 2 ]\n\n\nb =\n      2 -- end\n";
        let formatted = format_with_segments(src).expect("formats");
        let whole = format_source(src).expect("formats");
        assert_eq!(formatted.text, whole);
        assert!(whole.contains("    [ 1 -- one\n"), "{whole}");
        assert!(whole.ends_with("    2 -- end\n"), "{whole}");
        let edited = splice_all(src, &formatted);
        assert_eq!(edited, whole, "splicing every segment is the format");
        assert!(
            verify_rewrite(src, &edited).is_ok(),
            "the spliced segments verify"
        );
    }

    /// `verify_rewrite` accepts a faithful rewrite and refuses one that drops
    /// a comment, changes the program, or does not parse.
    #[test]
    fn verify_rewrite_refuses_an_unfaithful_rewrite() {
        let src = "module M exposing (x)\n\n\n-- about x\nx =\n    1\n";
        assert!(
            verify_rewrite(src, src).is_ok(),
            "an identical rewrite verifies"
        );
        let detail = |edited: &str| match verify_rewrite(src, edited) {
            Err(FmtError::RoundTrip(fault)) => fault.to_string(),
            other => format!("not a refusal: {other:?}"),
        };
        let dropped = detail(&src.replace("-- about x\n", ""));
        assert!(
            dropped.starts_with("formatter dropped comments"),
            "{dropped}"
        );
        assert_eq!(
            detail(&src.replace("    1", "    2")),
            "formatted output parsed to a different AST"
        );
        let unparsed = detail(&src.replace("    1", "    1 +"));
        assert!(
            unparsed.starts_with("formatted output did not re-parse"),
            "{unparsed}"
        );
        assert!(matches!(
            verify_rewrite("not ipe @@@@", src),
            Err(FmtError::Parse { .. })
        ));
    }

    /// The owner token text of each comment of `src`, `None` for a leading
    /// comment.
    fn trail_owners(src: &str) -> Vec<Option<String>> {
        scan_comments(src)
            .iter()
            .map(|c| {
                c.owner()
                    .and_then(|o| src.get(o.lo..o.hi))
                    .map(str::to_owned)
            })
            .collect()
    }

    /// A comment trails the token before it only at a line end and only after
    /// a token that ends a node; a block comment with code after it on its
    /// line leads that code.
    #[test]
    fn trailing_classifier_pins_its_boundary() {
        let owner = |text: &str| Some(text.to_owned());
        assert_eq!(trail_owners("x = a {- c -} + y\n"), vec![None]);
        assert_eq!(trail_owners("x = a {- c -}\ny = 1\n"), vec![owner("a")]);
        assert_eq!(trail_owners("x = a {- c -}"), vec![owner("a")]);
        assert_eq!(trail_owners("x = a {-| d -}\ny = 1\n"), vec![owner("a")]);
        assert_eq!(trail_owners("x = f y -- c\n"), vec![owner("y")]);
        assert_eq!(trail_owners("x = (f y) -- c\n"), vec![owner(")")]);
        assert_eq!(trail_owners("x =\n    1 -- c"), vec![owner("1")]);
        assert_eq!(
            trail_owners("x = a {- b -} -- c\n"),
            vec![owner("a"), owner("a")]
        );
        assert_eq!(trail_owners("-- own line\nx = 1\n"), vec![None]);
        assert_eq!(trail_owners("x = 1\n-- own line\n"), vec![None]);
    }

    /// A comment after a token that leaves its construct open leads the code
    /// after it, whatever line it ends.
    #[test]
    fn comments_after_open_tokens_lead() {
        for src in [
            "x = -- c\n    1\n",
            "x = case y of -- c\n    _ -> 1\n",
            "x = a + -- c\n    b\n",
            "x = ( -- c\n    1)\n",
            "module M exposing -- c\n    (x)\n",
            "x = if a then -- c\n    1 else 2\n",
        ] {
            assert_eq!(trail_owners(src), vec![None], "{src:?}");
        }
    }

    /// `ends_node` is true exactly for the tokens a node can end on.
    #[test]
    fn ends_node_names_the_node_final_tokens() {
        for kind in [
            TokenKind::Ident,
            TokenKind::Int,
            TokenKind::Float,
            TokenKind::Str,
            TokenKind::Char,
            TokenKind::Underscore,
            TokenKind::RParen,
            TokenKind::RBracket,
            TokenKind::RBrace,
        ] {
            assert!(ends_node(kind), "{kind:?}");
        }
        for kind in [
            TokenKind::Equals,
            TokenKind::Of,
            TokenKind::Then,
            TokenKind::Arrow,
            TokenKind::Comma,
            TokenKind::LParen,
            TokenKind::PipeGt,
            TokenKind::Exposing,
            TokenKind::Eof,
        ] {
            assert!(!ends_node(kind), "{kind:?}");
        }
    }

    /// The fault detail of `verify_rewrite(original, edited)`.
    fn rewrite_fault(original: &str, edited: &str) -> Option<(Owner, RunFault)> {
        match verify_rewrite(original, edited) {
            Err(FmtError::RoundTrip(RoundTripFault::CommentRun { owner, fault })) => {
                Some((owner, fault))
            }
            _ => None,
        }
    }

    const TRAILS_ONE: &str = "module M exposing (x)\n\n\nx =\n    [ 1 -- one\n    , 2\n    ]\n";

    /// A rewrite that moves an end-of-line comment to another line's end is
    /// refused, though it keeps every comment's text and owner.
    #[test]
    fn verify_refuses_an_end_of_line_comment_moved_to_another_line() {
        let moved = "module M exposing (x)\n\n\nx =\n    [ 1\n    , 2 -- one\n    ]\n";
        assert_eq!(
            rewrite_fault(TRAILS_ONE, moved),
            Some((Owner::Decl(0), RunFault::Attachment))
        );
    }

    /// An end-of-line comment may move onto its own line inside its
    /// declaration, never into the run above the declaration's head.
    #[test]
    fn verify_accepts_only_a_demotion_inside_its_declaration() {
        let demoted = "module M exposing (x)\n\n\nx =\n    [ 1\n    -- one\n    , 2\n    ]\n";
        assert!(verify_rewrite(TRAILS_ONE, demoted).is_ok());
        let hoisted = "module M exposing (x)\n\n\n-- one\nx =\n    [ 1\n    , 2\n    ]\n";
        assert_eq!(
            rewrite_fault(TRAILS_ONE, hoisted),
            Some((Owner::Decl(0), RunFault::HeadRun))
        );
    }

    /// A leading comment never joins the end of a code line.
    #[test]
    fn verify_refuses_a_leading_comment_moved_to_a_line_end() {
        let leading = "module M exposing (x)\n\n\nx =\n    [ 1\n    -- one\n    , 2\n    ]\n";
        let gained = "module M exposing (x)\n\n\nx =\n    [ 1 -- one\n    , 2\n    ]\n";
        assert_eq!(
            rewrite_fault(leading, gained),
            Some((Owner::Decl(0), RunFault::Attachment))
        );
    }

    /// A second render pass that may not demote leaves an end-of-line comment
    /// at no line end unplaced, and the formatter refuses rather than run a
    /// third pass.
    #[test]
    fn an_unplaced_end_of_line_comment_after_two_passes_is_refused() {
        let src = "module M exposing (f)\n\n\nf x =\n    case x of\n        Just -- inner\n            y ->\n            y\n\n        _ ->\n            0\n";
        NO_DEMOTION.with(|knob| knob.set(true));
        let refused = format_source(src);
        NO_DEMOTION.with(|knob| knob.set(false));
        assert!(
            matches!(
                refused,
                Err(FmtError::RoundTrip(RoundTripFault::UnplacedTrailing))
            ),
            "{refused:?}"
        );
        assert!(format_source(src).is_ok(), "demotion places it");
    }

    /// An operator printed as `?`, the text a symbol the printer cannot
    /// resolve renders, is refused rather than written.
    #[test]
    fn format_guards_refuse_an_unresolved_operator_print() {
        let src = "module M exposing (x)\n\n\nx =\n    1 + 2\n";
        assert_eq!(format_source(src).expect("formats"), src);
        let unknown = refusal(src, |p, m| p.module(m).replace(" + ", " ? "));
        assert!(
            unknown.starts_with("formatted output"),
            "a `?` operator is refused: {unknown}"
        );
        assert!(verify_rewrite(src, &src.replace(" + ", " ? ")).is_err());
    }

    /// The layout scan reads token boundaries: a `"""` inside a comment, a
    /// normal string, or a char literal opens no string, so the newline after
    /// it is still layout.
    #[test]
    fn layout_newline_ignores_triple_quote_outside_a_string() {
        assert!(!has_layout_newline("f \"\"\"a\nb\"\"\" x"));
        assert!(has_layout_newline("-- see \"\"\"\nx"));
        assert!(has_layout_newline("\"a\\\"\"\"\" \nx"));
        assert!(has_layout_newline("{- \"\"\" -}\nx"));
        assert!(has_layout_newline("{- a\nb -} x"));
        assert!(has_layout_newline("'\"' \"\"\"\nx"));
        assert!(!has_layout_newline("'\\'' x"));
        assert!(has_layout_newline("\"\"\"never closed"));
        assert!(!has_layout_newline("{- {- -} -} x -- tail"));
    }

    /// Format `src`, asserting the print is a fixed point of itself.
    #[allow(clippy::panic)] // a refused print fails the test with its reason
    fn fixed_point(src: &str) -> String {
        let once = format_source(src).unwrap_or_else(|e| panic!("refused: {e:?}\n{src}"));
        let twice = format_source(&once).unwrap_or_else(|e| panic!("refused twice: {e:?}\n{once}"));
        assert_eq!(once, twice, "not idempotent");
        once
    }

    const LAYOUT_A: &str = "module X exposing (x)\n\n\na : Int -> { x : Int, p : { r : Int, t : Int }, y : Int }\na n =\n    { x = 1\n    , p =\n        { r = n - 1 + (n - 2)\n        , t = n + 3\n        }\n    , y = 2\n    }\n";
    const LAYOUT_B: &str = "module X exposing (x)\n\n\nb : Bool -> String -> Bool\nb rootText base =\n    String.startsWith \"/\" rootText\n        && String.length base > 1\n        && String.length base > 2\n";
    const LAYOUT_C: &str = "module X exposing (x)\n\n\nc : List ( String, Bool )\nc =\n    [ ( \"one\"\n      , True\n            && False\n            && True\n      )\n    , ( \"two\"\n      , True\n            && False\n            && True\n      )\n    ]\n";
    const LAYOUT_D: &str = "module X exposing (x)\n\n\nd : Bool -> List String\nd x =\n    (if x then\n        [ \"a\" ]\n\n     else\n        []\n    )\n        ++ (if x then\n                [ \"b\" ]\n\n            else\n                []\n           )\n";

    /// A nested record under `field =` and a newline keeps its own lines at
    /// the field's next tab stop.
    #[test]
    fn nested_record_value_is_a_fixed_point() {
        assert_eq!(fixed_point(LAYOUT_A), LAYOUT_A);
    }

    /// An `&&` chain whose operands hold a tighter `>` breaks only at `&&`.
    #[test]
    fn mixed_precedence_chain_is_a_fixed_point() {
        assert_eq!(fixed_point(LAYOUT_B), LAYOUT_B);
        let split_at_gt = LAYOUT_B.replace(
            "        && String.length base > 1\n",
            "        && String.length base\n        > 1\n",
        );
        assert_eq!(fixed_point(&split_at_gt), LAYOUT_B);
        let regrouped = LAYOUT_B.replace(
            "String.startsWith \"/\" rootText\n        && String.length base > 1",
            "(String.startsWith \"/\" rootText\n        && String.length base)\n        > 1",
        );
        assert_ne!(regrouped, LAYOUT_B, "precondition: the rewrite applies");
        assert!(
            verify_rewrite(LAYOUT_B, &regrouped).is_err(),
            "a print that regroups the chain is refused"
        );
    }

    /// A multi-line tuple element of a list keeps its continuation lines at
    /// the columns its own `(` and operands start on.
    #[test]
    fn multiline_tuple_in_list_is_a_fixed_point() {
        assert_eq!(fixed_point(LAYOUT_C), LAYOUT_C);
    }

    /// A parenthesised `if` after `++` lays out from the column its `(`
    /// starts on.
    #[test]
    fn parenthesised_if_under_append_is_a_fixed_point() {
        assert_eq!(fixed_point(LAYOUT_D), LAYOUT_D);
    }

    /// A record field whose value carries a comment holding `"""` still
    /// breaks: the comment opens no string.
    #[test]
    fn triple_quote_in_comment_keeps_the_layout() {
        let src = "module X exposing (x)\n\n\na : { p : Int, q : Int }\na =\n    { p =\n        -- see \"\"\"\n        1\n    , q = 2\n    }\n";
        assert_eq!(fixed_point(src), src);
    }

    const BAD_A: &str = "module X exposing (x)\n\n\na : Int -> { x : Int, p : { r : Int, t : Int }, y : Int }\na n =\n    { x = 1\n    , p = { r = n - 1 + (n - 2)\n    , t = n + 3\n    }\n    , y = 2\n    }\n";
    const BAD_C: &str = "module X exposing (x)\n\n\nc : List ( String, Bool )\nc =\n    [ ( \"one\"\n    , True\n        && False\n        && True\n    )\n    , ( \"two\"\n    , True\n        && False\n        && True\n    )\n    ]\n";
    const BAD_D: &str = "module X exposing (x)\n\n\nd : Bool -> List String\nd x =\n    (if x then\n        [ \"a\" ]\n\n    else\n        []\n    )\n        ++ (if x then\n            [ \"b\" ]\n\n        else\n            []\n        )\n";

    /// The prints the level-counted printer produced for A, C and D format
    /// back to the layouts they were printed from.
    #[test]
    fn earlier_misprints_format_to_their_layout() {
        assert_eq!(fixed_point(BAD_A), LAYOUT_A);
        assert_eq!(fixed_point(BAD_C), LAYOUT_C);
        assert_eq!(fixed_point(BAD_D), LAYOUT_D);
    }
}
