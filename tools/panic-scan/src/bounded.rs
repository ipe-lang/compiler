//! The one bounded entry to `syn`: every parse, visit and drop of a source file.
//!
//! `syn` recurses without a guard: unary operators, closures, types, patterns
//! and groups recurse while parsing, and the left-nested trees that binary
//! chains, trailers and `else if` build are recursed by the derived `Drop`, by
//! `Visit`, and by the flat macro-body scan. Input that dictates that depth
//! would overflow the stack and kill the process, so no source reaches `syn`
//! before a ceiling the parse is sized for:
//!
//! 1. on the caller's thread, the source length is checked against
//!    [`SourceBytes`];
//! 2. on a fresh thread with a [`ParseStack`] stack, the source is lexed
//!    (`proc-macro2` lexes and drops tokens with explicit stacks, safe at any
//!    depth), its tokens are counted against [`TokenCeiling`], and its
//!    [`nest depth`](Measure::depth) is measured against [`NestDepth`] with an
//!    explicit worklist;
//! 3. only then, on that same thread, `syn` parses the file, the caller's judge
//!    reads it, and the tree is dropped. A `syn::File` is not `Send`, so it can
//!    never leave the sized thread, and its recursive `Drop` always runs there.
//!
//! A fresh thread per call also frees `proc-macro2`'s thread-local span map,
//! which only grows, so a long-lived process never exhausts its offsets.
//!
//! The depth measure over-approximates every recursion `syn` performs: a refused
//! legal file is a fail-closed refusal, never a partial scan. The heap a parsed
//! tree occupies is bounded only by [`TokenCeiling`] and [`SourceBytes`]: a
//! source near the ceilings can cost hundreds of MiB of heap during one parse.
//! That is bounded, not proportional to anything but the source itself.

use std::fmt;
use std::io::Read;
use std::num::NonZeroUsize;
use std::path::Path;

use proc_macro2::{Delimiter, Ident, Punct, Spacing, TokenStream, TokenTree};

/// Largest source, in bytes, the scanner reads or parses.
const SOURCE_BYTES: usize = 8 << 20;

/// Largest token count, groups included, the scanner lexes into a tree.
const TOKEN_CEILING: usize = 1 << 21;

/// Stack reserved for each parse thread, paired with [`NEST_DEPTH`].
///
/// The pair is chosen together: [`ParseStack::CALIBRATION`], a quarter of this
/// stack, must parse, visit and drop every recursive shape at [`NEST_DEPTH`]
/// units, so each unit costs at most `CALIBRATION / NEST_DEPTH` bytes of stack.
/// The stack is reserved virtual memory, committed only as it is used.
const PARSE_STACK: usize = 128 << 20;

/// Deepest nesting, in measure units, the scanner hands to `syn`.
const NEST_DEPTH: usize = 2048;

/// Stack budget per measure unit that the calibration proves.
const UNIT_STACK: usize = 16 << 10;

// IPE-RUST-AUDIT:ACCEPTED — compile-time `const` assertion (not a runtime panic); it fails the build if a ceiling is zero or the stack and depth pair stops leaving each unit its calibrated stack budget with a 4x margin
const _: () = assert!(
    SOURCE_BYTES > 0
        && TOKEN_CEILING > 0
        && NEST_DEPTH > 0
        && PARSE_STACK / 4 / NEST_DEPTH >= UNIT_STACK
);

/// `n` as a non-zero count; the `const` assertion above proves every ceiling is.
const fn non_zero(n: usize) -> NonZeroUsize {
    match NonZeroUsize::new(n) {
        Some(n) => n,
        None => NonZeroUsize::MIN,
    }
}

/// Largest source, in bytes, the scanner accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceBytes(NonZeroUsize);

/// Deepest nesting, in measure units, the scanner hands to `syn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NestDepth(NonZeroUsize);

/// Largest token count, groups included, the scanner accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenCeiling(NonZeroUsize);

/// Stack size, in bytes, of a parse thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseStack(NonZeroUsize);

impl SourceBytes {
    /// The ceiling every scan enforces.
    pub const CEILING: Self = Self(non_zero(SOURCE_BYTES));

    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

impl NestDepth {
    /// The ceiling every scan enforces.
    pub const CEILING: Self = Self(non_zero(NEST_DEPTH));

    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

impl TokenCeiling {
    /// The ceiling every scan enforces.
    pub const CEILING: Self = Self(non_zero(TOKEN_CEILING));

    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

impl ParseStack {
    /// The stack every scan runs on.
    pub const CEILING: Self = Self(non_zero(PARSE_STACK));

    /// A quarter of [`Self::CEILING`]: the stack the calibration tests prove
    /// every recursive shape fits in at [`NestDepth::CEILING`].
    pub const CALIBRATION: Self = Self(non_zero(PARSE_STACK / 4));

    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

impl fmt::Display for SourceBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for NestDepth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for TokenCeiling {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Why a source is refused before, or by, its parse.
#[derive(Debug)]
pub enum ScanError {
    /// The source holds at least `bytes` bytes, more than the ceiling.
    TooLarge { bytes: usize, ceiling: SourceBytes },
    /// The source nests `depth` units deep around `line`, more than the ceiling.
    TooDeep {
        line: usize,
        depth: usize,
        ceiling: NestDepth,
    },
    /// The source holds at least `count` tokens, more than the ceiling.
    TooManyTokens { count: usize, ceiling: TokenCeiling },
    /// The source does not lex or parse as a Rust file; `line` is 1-based.
    Parse { line: usize, source: syn::Error },
    /// The parse thread could not start.
    Thread(std::io::Error),
    /// The parse thread ended without a result.
    Aborted,
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { bytes, ceiling } => write!(
                f,
                "too large: at least {bytes} bytes, over the {ceiling}-byte source ceiling"
            ),
            Self::TooDeep {
                line,
                depth,
                ceiling,
            } => write!(
                f,
                "too deep: line {line} nests {depth} units, over the ceiling of {ceiling}"
            ),
            Self::TooManyTokens { count, ceiling } => write!(
                f,
                "too many tokens: at least {count}, over the ceiling of {ceiling}"
            ),
            Self::Parse { line, source } => {
                write!(f, "does not parse as Rust: line {line}: {source}")
            }
            Self::Thread(error) => write!(f, "the parse thread could not start: {error}"),
            Self::Aborted => f.write_str("the parse thread aborted"),
        }
    }
}

impl std::error::Error for ScanError {}

/// Why a source file could not be read for a scan.
#[derive(Debug)]
pub enum SourceReadError {
    /// The file could not be opened or read, or is not UTF-8.
    Io(std::io::Error),
    /// The file is larger than [`SourceBytes::CEILING`].
    Refused(ScanError),
}

impl fmt::Display for SourceReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "cannot read ({error})"),
            Self::Refused(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SourceReadError {}

/// Read the file at `path`, never more than one byte past [`SourceBytes::CEILING`].
///
/// # Errors
///
/// [`SourceReadError::Io`] when the file cannot be read or is not UTF-8, and
/// [`SourceReadError::Refused`] with [`ScanError::TooLarge`] when it is larger
/// than the ceiling.
pub fn read_source(path: &Path) -> Result<String, SourceReadError> {
    let file = std::fs::File::open(path).map_err(SourceReadError::Io)?;
    let limit = SourceBytes::CEILING.get().saturating_add(1);
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(SourceReadError::Io)?;
    within_source_ceiling(bytes.len()).map_err(SourceReadError::Refused)?;
    String::from_utf8(bytes).map_err(|error| {
        SourceReadError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    })
}

/// How a lexed source measures against the token and depth ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measure {
    /// Tokens in the source, each group counted once besides its contents.
    pub tokens: usize,
    /// Nest depth in measure units: an over-approximation of `syn`'s deepest
    /// recursion over the source.
    pub depth: usize,
    /// 1-based line of the open delimiter of the group the depth was reached in.
    pub line: usize,
}

/// Measure `src` on a parse thread, enforcing the source and token ceilings.
///
/// The depth is reported, not enforced, so a caller can see how far a source
/// sits from [`NestDepth::CEILING`].
///
/// # Errors
///
/// [`ScanError::TooLarge`], [`ScanError::TooManyTokens`], [`ScanError::Parse`]
/// when `src` does not lex, and [`ScanError::Thread`] or [`ScanError::Aborted`]
/// when the parse thread fails.
pub fn measure(src: &str) -> Result<Measure, ScanError> {
    within_source_ceiling(src.len())?;
    on_parse_thread(ParseStack::CEILING, move || lex_and_measure(src))
}

/// Parse `src` as a Rust file and hand it to `judge`, all on a sized thread.
///
/// # Errors
///
/// A [`ScanError`] when `src` is over a ceiling, does not parse, or the parse
/// thread fails; `judge` then never runs.
pub fn with_parsed<R: Send>(
    src: &str,
    judge: impl FnOnce(&syn::File) -> R + Send,
) -> Result<R, ScanError> {
    with_parsed_on(ParseStack::CEILING, src, judge)
}

/// [`with_parsed`] on a parse thread of `stack` bytes.
///
/// Only the calibration that proves [`ParseStack::CEILING`] runs on a smaller
/// stack; every scan goes through [`with_parsed`].
///
/// # Errors
///
/// As [`with_parsed`].
pub fn with_parsed_on<R: Send>(
    stack: ParseStack,
    src: &str,
    judge: impl FnOnce(&syn::File) -> R + Send,
) -> Result<R, ScanError> {
    within_source_ceiling(src.len())?;
    on_parse_thread(stack, move || {
        let found = lex_and_measure(src)?;
        let ceiling = NestDepth::CEILING;
        if found.depth > ceiling.get() {
            return Err(ScanError::TooDeep {
                line: found.line,
                depth: found.depth,
                ceiling,
            });
        }
        // The error's span is read here: across threads it reads as `call_site`.
        let file = syn::parse_file(src).map_err(|source| ScanError::Parse {
            line: source.span().start().line,
            source,
        })?;
        let verdict = judge(&file);
        drop(file);
        Ok(verdict)
    })
}

/// Refuse a source of `bytes` bytes when it is over [`SourceBytes::CEILING`].
const fn within_source_ceiling(bytes: usize) -> Result<(), ScanError> {
    let ceiling = SourceBytes::CEILING;
    if bytes > ceiling.get() {
        return Err(ScanError::TooLarge { bytes, ceiling });
    }
    Ok(())
}

/// Run `work` on a fresh thread with a `stack`-byte stack and return its result.
fn on_parse_thread<R: Send>(
    stack: ParseStack,
    work: impl FnOnce() -> Result<R, ScanError> + Send,
) -> Result<R, ScanError> {
    std::thread::scope(|scope| -> Result<R, ScanError> {
        let handle = std::thread::Builder::new()
            .name("panic-scan-parse".to_owned())
            .stack_size(stack.get())
            .spawn_scoped(scope, work)
            .map_err(ScanError::Thread)?;
        handle.join().map_err(|_| ScanError::Aborted)?
    })
}

/// Lex `src` and measure its tokens; the token stream is dropped before returning.
fn lex_and_measure(src: &str) -> Result<Measure, ScanError> {
    let stream = without_shebang(src)
        .parse::<TokenStream>()
        .map_err(|lex| ScanError::Parse {
            line: lex.span().start().line,
            source: syn::Error::from(lex),
        })?;
    nest_depth(stream)
}

/// `src` without the byte-order mark and the shebang line `syn::parse_file` skips.
///
/// The line break that ends the shebang is kept, so every later line keeps its
/// number. A `#!` the parser reads as an inner attribute is kept whole.
fn without_shebang(src: &str) -> &str {
    let body = src.strip_prefix('\u{feff}').unwrap_or(src);
    let Some(rest) = body.strip_prefix("#!") else {
        return body;
    };
    let after = rest.trim_start();
    if after.starts_with('[') || after.starts_with("//") || after.starts_with("/*") {
        return body;
    }
    body.find('\n')
        .map_or("", |end| body.get(end..).unwrap_or(""))
}

/// Every keyword, strict, reserved and weak: each counts as one measure unit.
const KEYWORDS: &[&str] = &[
    "as",
    "async",
    "await",
    "break",
    "const",
    "continue",
    "crate",
    "dyn",
    "else",
    "enum",
    "extern",
    "false",
    "fn",
    "for",
    "if",
    "impl",
    "in",
    "let",
    "loop",
    "match",
    "mod",
    "move",
    "mut",
    "pub",
    "ref",
    "return",
    "self",
    "Self",
    "static",
    "struct",
    "super",
    "trait",
    "true",
    "type",
    "unsafe",
    "use",
    "where",
    "while",
    "abstract",
    "become",
    "box",
    "do",
    "final",
    "gen",
    "macro",
    "override",
    "priv",
    "try",
    "typeof",
    "unsized",
    "virtual",
    "yield",
    "auto",
    "default",
    "macro_rules",
    "raw",
    "safe",
    "union",
];

/// A group of tokens waiting to be measured.
struct Pending {
    stream: TokenStream,
    /// Measure units of every enclosing segment, outermost first, summed.
    base: usize,
    /// 1-based line of the group's open delimiter.
    line: usize,
}

/// Count `stream`'s tokens and measure its nest depth, without recursion.
///
/// A group nested in segment `seg` of a parent at base `b` sits at base
/// `b + 1 + W(seg)`, where `W(seg)` is the weight of that whole segment, since
/// the tokens after a group wrap it as much as the tokens before it. The depth
/// is the largest base plus heaviest segment over every group, the file root
/// included at base 0.
fn nest_depth(stream: TokenStream) -> Result<Measure, ScanError> {
    let ceiling = TokenCeiling::CEILING;
    let mut found = Measure {
        tokens: 0,
        depth: 0,
        line: 1,
    };
    let mut work = vec![Pending {
        stream,
        base: 0,
        line: 1,
    }];
    while let Some(group) = work.pop() {
        let trees: Vec<TokenTree> = group.stream.into_iter().collect();
        found.tokens = found.tokens.saturating_add(trees.len());
        if found.tokens > ceiling.get() {
            return Err(ScanError::TooManyTokens {
                count: found.tokens,
                ceiling,
            });
        }
        let segments = Segments::of(&trees);
        let depth = group.base.saturating_add(segments.heaviest());
        if depth > found.depth {
            found.depth = depth;
            found.line = group.line;
        }
        for (tree, segment) in trees.iter().zip(&segments.of_tree) {
            if let TokenTree::Group(inner) = tree {
                work.push(Pending {
                    stream: inner.stream(),
                    base: group
                        .base
                        .saturating_add(1)
                        .saturating_add(segments.weight_of(*segment)),
                    line: inner.span_open().start().line,
                });
            }
        }
    }
    Ok(found)
}

/// How one group's tokens split into segments.
struct Segments {
    /// The segment index of each token, in order.
    of_tree: Vec<usize>,
    /// The total weight of each segment.
    weight: Vec<usize>,
}

impl Segments {
    /// Split `trees`, one group's tokens, into weighted segments.
    fn of(trees: &[TokenTree]) -> Self {
        let mut segments = Self {
            of_tree: Vec::with_capacity(trees.len()),
            weight: vec![0],
        };
        let mut cutter = Cutter::default();
        for (index, tree) in trees.iter().enumerate() {
            if cutter.after_brace && opens_segment(tree) {
                segments.open();
                cutter.piped = false;
            }
            let (weight, ends) = cutter.step(tree, trees.get(index.saturating_add(1)));
            segments.add(weight);
            if ends {
                segments.open();
            }
        }
        segments
    }

    /// Add one token of `weight` to the current segment.
    fn add(&mut self, weight: usize) {
        self.of_tree.push(self.weight.len().saturating_sub(1));
        if let Some(total) = self.weight.last_mut() {
            *total = total.saturating_add(weight);
        }
    }

    /// Start a new segment at weight 0.
    fn open(&mut self) {
        self.weight.push(0);
    }

    /// The weight of the heaviest segment.
    fn heaviest(&self) -> usize {
        self.weight.iter().copied().max().unwrap_or(0)
    }

    /// The weight of segment `segment`.
    fn weight_of(&self, segment: usize) -> usize {
        self.weight.get(segment).copied().unwrap_or(0)
    }
}

/// Whether `tree`, right after a `{}` group, starts a new segment.
fn opens_segment(tree: &TokenTree) -> bool {
    match tree {
        TokenTree::Ident(ident) => ident != "else" && ident != "as",
        TokenTree::Literal(_) => true,
        TokenTree::Punct(punct) => punct.as_char() == '#',
        TokenTree::Group(_) => false,
    }
}

/// Whether `tree` is the punctuation character `ch`.
fn is_punct(tree: Option<&TokenTree>, ch: char) -> bool {
    matches!(tree, Some(TokenTree::Punct(punct)) if punct.as_char() == ch)
}

/// Whether `ident` is a keyword.
fn is_keyword(ident: &Ident) -> bool {
    KEYWORDS.iter().any(|keyword| ident == keyword)
}

/// The segmenting state carried from one token of a group to the next.
#[derive(Default)]
struct Cutter {
    /// Open `<` not yet closed by a `>`, clamped at 0.
    angle: usize,
    /// A `|` appeared since the segment started or since the last `=>`.
    piped: bool,
    /// The previous token was a `{}` group.
    after_brace: bool,
    /// The previous token was a joint punctuation character.
    prev_joint: Option<char>,
    /// The current token is the second `:` of a joint `::`.
    colon_tail: bool,
}

impl Cutter {
    /// The weight of `tree`, followed by `next`, and whether a segment ends after it.
    fn step(&mut self, tree: &TokenTree, next: Option<&TokenTree>) -> (usize, bool) {
        let prev_joint = self.prev_joint.take();
        self.after_brace =
            matches!(tree, TokenTree::Group(group) if group.delimiter() == Delimiter::Brace);
        match tree {
            TokenTree::Group(_) => (1, false),
            TokenTree::Ident(ident) => (usize::from(is_keyword(ident)), false),
            TokenTree::Literal(_) => (0, false),
            TokenTree::Punct(punct) => {
                self.prev_joint = (punct.spacing() == Spacing::Joint).then_some(punct.as_char());
                self.punct(punct, prev_joint, next)
            }
        }
    }

    /// The weight of `punct`, after a joint `prev_joint`, and whether a segment
    /// ends after it.
    fn punct(
        &mut self,
        punct: &Punct,
        prev_joint: Option<char>,
        next: Option<&TokenTree>,
    ) -> (usize, bool) {
        let colon_tail = std::mem::take(&mut self.colon_tail);
        match punct.as_char() {
            ';' => {
                self.angle = 0;
                self.piped = false;
                (0, true)
            }
            ',' => (0, self.angle == 0 && !self.piped),
            ':' if colon_tail => (0, false),
            ':' if punct.spacing() == Spacing::Joint && is_punct(next, ':') => {
                self.colon_tail = true;
                (0, false)
            }
            '|' => {
                self.piped = true;
                (1, false)
            }
            '<' => {
                self.angle = self.angle.saturating_add(1);
                (1, false)
            }
            '>' => {
                match prev_joint {
                    Some('=') => self.piped = false,
                    Some('-') => {}
                    _ => self.angle = self.angle.saturating_sub(1),
                }
                (1, false)
            }
            _ => (1, false),
        }
    }
}
