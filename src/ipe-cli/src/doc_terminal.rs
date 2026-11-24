//! The one terminal renderer for human `ipe doc` pages.
//!
//! Parsed Markdown blocks go in; a [`DocText`] comes out. [`render`] is the only producer of a
//! [`DocText`], and [`crate::screen::Screen::doc`] accepts nothing else, so a doc body that
//! skipped this renderer has no type that reaches the doc screen. Every piece of page text is
//! sanitised here before it is laid out; the palette's own escapes are the only control bytes a
//! [`DocText`] carries. Links print as `text <href>`, never as an OSC 8 hyperlink.

use std::fmt::Write as _;
use std::io::IsTerminal;

use ipe_diagnostics::{display_width, expand_tabs};
use ipe_docs::markdown::parse::parse_spans;
use ipe_docs::markdown::{Block, MAX_BLOCKQUOTE_DEPTH, Span};

use crate::style::{GUTTER, Palette, TerminalLine, TerminalSafe};

/// The column budget a doc page wraps at.
///
/// Either a terminal width inside [`Width::MIN`]`..=`[`Width::MAX`] or no wrapping at all, so a
/// wrap loop never runs against a zero or absurd width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Width(Option<u16>);

impl Width {
    /// The narrowest terminal a page wraps for.
    pub const MIN: u16 = 20;
    /// The widest terminal a page wraps for.
    pub const MAX: u16 = 200;
    /// Lines are never wrapped: the output is not a terminal, or its size is unknown.
    pub const NO_WRAP: Self = Self(None);
    /// The width used when a terminal reports a size outside [`Self::MIN`]`..=`[`Self::MAX`].
    pub const DEFAULT: Self = Self(Some(80));

    /// The width for a terminal reporting `columns`.
    ///
    /// Zero (no size reported) is [`Self::NO_WRAP`]; any other value outside the range is
    /// [`Self::DEFAULT`].
    #[must_use]
    pub const fn from_columns(columns: u16) -> Self {
        match columns {
            0 => Self::NO_WRAP,
            Self::MIN..=Self::MAX => Self(Some(columns)),
            _ => Self::DEFAULT,
        }
    }

    /// The column count lines wrap at, or `None` when lines are never wrapped.
    #[must_use]
    pub const fn columns(self) -> Option<u16> {
        self.0
    }

    /// The width of the terminal `stream` writes to, read from that same descriptor.
    #[cfg(unix)]
    #[must_use]
    pub fn of_terminal(stream: &(impl IsTerminal + std::os::fd::AsFd)) -> Self {
        if !stream.is_terminal() {
            return Self::NO_WRAP;
        }
        rustix::termios::tcgetwinsize(stream)
            .map_or(Self::DEFAULT, |size| Self::from_columns(size.ws_col))
    }

    /// The width of the terminal `stream` writes to: [`Self::DEFAULT`] on a Windows console.
    #[cfg(not(unix))]
    #[must_use]
    pub fn of_terminal(stream: &impl IsTerminal) -> Self {
        if cfg!(windows) && stream.is_terminal() {
            Self::DEFAULT
        } else {
            Self::NO_WRAP
        }
    }
}

/// A doc page laid out for the terminal.
///
/// Sanitised page text plus the palette's escapes; [`render`] is its only producer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocText(String);

impl DocText {
    /// The page text, one line per terminal row, not yet guttered.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The columns a blockquote's bar takes from its content.
const QUOTE_BAR: &str = "│ ";

/// The narrowest content budget nested blocks shrink to.
const MIN_BUDGET: usize = 8;

/// The longest horizontal rule.
const RULE_COLUMNS: usize = 40;

/// The gap between two table columns.
const COLUMN_GAP: &str = "  ";

/// Lay out one doc page: a `title` line (with an optional dim `tag`), then `blocks`.
///
/// Every text run is sanitised before it is measured or styled. Paragraphs, list items and the
/// cells of a table that fits are wrapped at `width` less the screen gutter; code is indented by
/// [`GUTTER`] and never wrapped.
#[must_use]
pub fn render(
    title: &TerminalLine,
    tag: Option<&str>,
    blocks: &[Block],
    width: Width,
    palette: &Palette,
) -> DocText {
    let mut out = format!("{}{title}{}", palette.bold, palette.reset);
    if let Some(tag) = tag {
        let tag = TerminalLine::sanitize(tag);
        let _ = write!(out, "  {}[{tag}]{}", palette.dim, palette.reset);
    }
    out.push('\n');
    let budget = width
        .columns()
        .map(|columns| usize::from(columns).saturating_sub(display_width(GUTTER, 0)));
    let body = blocks_lines(blocks, budget, palette, 0);
    if !body.is_empty() {
        out.push('\n');
        for line in body {
            out.push_str(line.trim_end_matches(' '));
            out.push('\n');
        }
    }
    DocText(out)
}

/// The lines of `blocks` at `budget` columns, one blank line between two blocks.
fn blocks_lines(
    blocks: &[Block],
    budget: Option<usize>,
    palette: &Palette,
    depth: usize,
) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for block in blocks {
        let block_lines = block_lines(block, budget, palette, depth);
        if block_lines.is_empty() {
            continue;
        }
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.extend(block_lines);
    }
    lines
}

/// The lines of one `block` at `budget` columns.
fn block_lines(
    block: &Block,
    budget: Option<usize>,
    palette: &Palette,
    depth: usize,
) -> Vec<String> {
    match block {
        Block::Header(_, text) => {
            let text = TerminalLine::sanitize(&spans_text(&parse_spans(text)));
            vec![format!("{}{text}{}", palette.bold, palette.reset)]
        }
        Block::Para(text) => wrap(&words(&parse_spans(text)), budget, "", "", palette),
        Block::Code(body) => code_lines(body, palette),
        Block::Bullet(items) => items
            .iter()
            .flat_map(|item| wrap(&words(&parse_spans(item)), budget, "- ", "  ", palette))
            .collect(),
        Block::Numbered(items) => items
            .iter()
            .zip(1_usize..)
            .flat_map(|(item, n)| {
                let first = format!("{n}. ");
                let rest = " ".repeat(display_width(&first, 0));
                wrap(&words(&parse_spans(item)), budget, &first, &rest, palette)
            })
            .collect(),
        Block::Table(headers, rows) => table_lines(headers, rows, budget, palette),
        Block::Rule => {
            let columns = budget.map_or(RULE_COLUMNS, |b| b.min(RULE_COLUMNS));
            vec![format!(
                "{}{}{}",
                palette.dim,
                "─".repeat(columns),
                palette.reset
            )]
        }
        Block::Blockquote(inner) => {
            // The parser folds deeper nesting already; this ceiling is the renderer's own.
            if depth >= MAX_BLOCKQUOTE_DEPTH {
                return Vec::new();
            }
            let narrowed = budget.map(|b| {
                b.saturating_sub(display_width(QUOTE_BAR, 0))
                    .max(MIN_BUDGET)
            });
            blocks_lines(inner, narrowed, palette, depth.saturating_add(1))
                .into_iter()
                .map(|line| format!("{}{QUOTE_BAR}{}{line}", palette.dim, palette.reset))
                .collect()
        }
    }
}

/// The flat text of `spans`, a link or image as `text <href>`.
fn spans_text(spans: &[Span]) -> String {
    let mut out = String::new();
    for span in spans {
        match span {
            Span::Plain(text) | Span::Bold(text) | Span::Italic(text) | Span::Code(text) => {
                out.push_str(text);
            }
            Span::Link(text, href) | Span::Image(text, href) => {
                out.push_str(text);
                out.push_str(" <");
                out.push_str(href.as_str());
                out.push('>');
            }
            Span::HardBreak => out.push(' '),
        }
    }
    out
}

/// How a run of page text is painted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Style {
    /// Unstyled text.
    Plain,
    /// Bold text.
    Bold,
    /// Inline code.
    Code,
    /// A link target.
    Dim,
}

impl Style {
    /// The escape that opens this style under `palette`.
    const fn open(self, palette: &Palette) -> &'static str {
        match self {
            Self::Plain => "",
            Self::Bold => palette.bold,
            Self::Code => palette.yellow,
            Self::Dim => palette.dim,
        }
    }
}

/// One run of a word in a single style.
#[derive(Debug)]
struct Piece {
    /// The sanitised text.
    text: String,
    /// How it is painted.
    style: Style,
}

/// A wrap unit: a word no line break may split, unless it is wider than a line.
#[derive(Debug, Default)]
struct Word {
    /// The word's runs, in order.
    pieces: Vec<Piece>,
    /// The word's display width.
    width: usize,
}

/// A step of the wrapped text.
#[derive(Debug)]
enum Token {
    /// A word.
    Word(Word),
    /// A forced line break.
    Break,
}

/// The wrap tokens of `spans`: whitespace separates words; a hard break forces a line.
fn words(spans: &[Span]) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut word = Word::default();
    for span in spans {
        match span {
            Span::Plain(text) | Span::Italic(text) => {
                feed(text, Style::Plain, &mut word, &mut tokens)
            }
            Span::Bold(text) => feed(text, Style::Bold, &mut word, &mut tokens),
            Span::Code(text) => feed(text, Style::Code, &mut word, &mut tokens),
            Span::Link(text, href) | Span::Image(text, href) => {
                feed(text, Style::Plain, &mut word, &mut tokens);
                flush(&mut word, &mut tokens);
                feed(
                    &format!("<{}>", href.as_str()),
                    Style::Dim,
                    &mut word,
                    &mut tokens,
                );
            }
            Span::HardBreak => {
                flush(&mut word, &mut tokens);
                tokens.push(Token::Break);
            }
        }
    }
    flush(&mut word, &mut tokens);
    tokens
}

/// Add the sanitised `raw` text in `style` to the open `word`, closing it at each whitespace.
fn feed(raw: &str, style: Style, word: &mut Word, tokens: &mut Vec<Token>) {
    let safe = TerminalSafe::sanitize(raw);
    for c in safe.as_str().chars() {
        if c.is_whitespace() {
            flush(word, tokens);
            continue;
        }
        let mut buf = [0_u8; 4];
        let encoded = c.encode_utf8(&mut buf);
        word.width = word.width.saturating_add(display_width(encoded, 0));
        match word.pieces.last_mut() {
            Some(piece) if piece.style == style => piece.text.push(c),
            _ => word.pieces.push(Piece {
                text: encoded.to_owned(),
                style,
            }),
        }
    }
}

/// Close the open `word` into `tokens` when it holds any text.
fn flush(word: &mut Word, tokens: &mut Vec<Token>) {
    if !word.pieces.is_empty() {
        tokens.push(Token::Word(std::mem::take(word)));
    }
}

/// A line under construction.
struct Line {
    /// The text so far.
    text: String,
    /// Its display width.
    column: usize,
    /// Whether it holds a word yet.
    empty: bool,
}

impl Line {
    /// A fresh line opening with `indent`.
    fn open(indent: &str) -> Self {
        Self {
            text: indent.to_owned(),
            column: display_width(indent, 0),
            empty: true,
        }
    }
}

/// Lay `tokens` out in lines of at most `budget` columns (unbounded when `None`).
///
/// The first line opens with `first`, every later one with `rest`. A word wider than a line is
/// split at character boundaries, so every character is placed exactly once: the work is linear
/// in the text.
fn wrap(
    tokens: &[Token],
    budget: Option<usize>,
    first: &str,
    rest: &str,
    palette: &Palette,
) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = Line::open(first);
    for token in tokens {
        let Token::Word(word) = token else {
            lines.push(std::mem::replace(&mut line, Line::open(rest)).text);
            continue;
        };
        let gap = usize::from(!line.empty);
        let fits =
            budget.is_none_or(|b| line.column.saturating_add(gap).saturating_add(word.width) <= b);
        if !fits && !line.empty {
            lines.push(std::mem::replace(&mut line, Line::open(rest)).text);
        } else if !line.empty {
            line.text.push(' ');
            line.column = line.column.saturating_add(1);
        }
        place(word, budget, rest, palette, &mut line, &mut lines);
        line.empty = false;
    }
    if !line.empty || lines.is_empty() {
        lines.push(line.text);
    }
    lines
}

/// Append `word` to `line`, breaking inside it only when it is wider than `budget`.
fn place(
    word: &Word,
    budget: Option<usize>,
    rest: &str,
    palette: &Palette,
    line: &mut Line,
    lines: &mut Vec<String>,
) {
    let split = budget.filter(|&b| line.column.saturating_add(word.width) > b);
    let Some(b) = split else {
        for piece in &word.pieces {
            let open = piece.style.open(palette);
            let close = if open.is_empty() { "" } else { palette.reset };
            line.text.push_str(open);
            line.text.push_str(&piece.text);
            line.text.push_str(close);
        }
        line.column = line.column.saturating_add(word.width);
        return;
    };
    let indent = display_width(rest, 0);
    for piece in &word.pieces {
        let open = piece.style.open(palette);
        let close = if open.is_empty() { "" } else { palette.reset };
        line.text.push_str(open);
        for c in piece.text.chars() {
            let mut buf = [0_u8; 4];
            let width = display_width(c.encode_utf8(&mut buf), 0);
            let holds_text = line.column > indent || !line.empty;
            if line.column.saturating_add(width) > b && holds_text {
                line.text.push_str(close);
                lines.push(std::mem::replace(line, Line::open(rest)).text);
                line.text.push_str(open);
            }
            line.text.push(c);
            line.column = line.column.saturating_add(width);
            line.empty = false;
        }
        line.text.push_str(close);
    }
}

/// The lines of a code block: sanitised, tabs expanded, indented by [`GUTTER`], highlighted
/// when the palette paints.
fn code_lines(body: &str, palette: &Palette) -> Vec<String> {
    let safe = TerminalSafe::sanitize(body);
    let expanded: Vec<String> = safe.as_str().lines().map(expand_tabs).collect();
    let source = expanded.join("\n");
    let painted = if palette.reset.is_empty() {
        source
    } else {
        highlight(&source, palette)
    };
    painted
        .lines()
        .map(|line| {
            if line.is_empty() {
                String::new()
            } else {
                format!("{GUTTER}{line}")
            }
        })
        .collect()
}

/// `source` painted by its syntax tokens, or unchanged when it does not parse as a module.
fn highlight(source: &str, palette: &Palette) -> String {
    let mut interner = ipe_intern::Interner::default();
    let Ok(syntax) = ipe_parse::parse_module(source, &mut interner) else {
        return source.to_owned();
    };
    let tokens = ipe_annotate::annotate_syntax_only(&syntax, &interner);
    let mut out = String::with_capacity(source.len());
    let mut cursor = 0_usize;
    for token in &tokens {
        let start = usize::try_from(token.byte_start).unwrap_or(usize::MAX);
        let end = start.saturating_add(usize::try_from(token.byte_len).unwrap_or(usize::MAX));
        let (Some(gap), Some(text)) = (source.get(cursor..start), source.get(start..end)) else {
            continue;
        };
        out.push_str(gap);
        let open = token_colour(token.class, palette);
        for (i, part) in text.split('\n').enumerate() {
            if i > 0 {
                out.push('\n');
            }
            if open.is_empty() || part.is_empty() {
                out.push_str(part);
            } else {
                out.push_str(open);
                out.push_str(part);
                out.push_str(palette.reset);
            }
        }
        cursor = end;
    }
    out.push_str(source.get(cursor..).unwrap_or_default());
    out
}

/// The escape a token class is painted with.
const fn token_colour(class: ipe_annotate::TokenClass, palette: &Palette) -> &'static str {
    use ipe_annotate::TokenClass;
    match class {
        TokenClass::Keyword => palette.orange,
        TokenClass::Type | TokenClass::Constructor | TokenClass::Module => palette.yellow,
        TokenClass::TypeVar => palette.bright_yellow,
        TokenClass::StringLit | TokenClass::Number => palette.green,
        TokenClass::Comment => palette.dim,
        TokenClass::Function | TokenClass::Kernel => palette.white,
        TokenClass::Variable | TokenClass::Operator | TokenClass::Punctuation => "",
    }
}

/// The lines of a table: aligned columns when it fits `budget`, else one `header: value` line
/// per cell.
fn table_lines(
    headers: &[String],
    rows: &[Vec<String>],
    budget: Option<usize>,
    palette: &Palette,
) -> Vec<String> {
    let cell = |raw: &str| TerminalLine::sanitize(&spans_text(&parse_spans(raw)));
    let head: Vec<TerminalLine> = headers.iter().map(|h| cell(h)).collect();
    let body: Vec<Vec<TerminalLine>> = rows
        .iter()
        .map(|row| row.iter().map(|c| cell(c)).collect())
        .collect();
    let columns = body
        .iter()
        .map(Vec::len)
        .chain([head.len()])
        .max()
        .unwrap_or(0);
    let mut widths = vec![0_usize; columns];
    for row in body.iter().chain([&head]) {
        for (width, text) in widths.iter_mut().zip(row) {
            *width = (*width).max(display_width(text.as_str(), 0));
        }
    }
    let gaps = display_width(COLUMN_GAP, 0).saturating_mul(columns.saturating_sub(1));
    let total = widths.iter().fold(gaps, |sum, w| sum.saturating_add(*w));
    if budget.is_some_and(|b| total > b) {
        return table_fallback(&head, &body, palette);
    }
    let row_line = |row: &[TerminalLine], open: &str, close: &str| {
        let mut line = String::new();
        for (i, width) in widths.iter().enumerate() {
            if i > 0 {
                line.push_str(COLUMN_GAP);
            }
            let text = row.get(i).map_or("", TerminalLine::as_str);
            line.push_str(open);
            line.push_str(text);
            line.push_str(close);
            line.push_str(&" ".repeat(width.saturating_sub(display_width(text, 0))));
        }
        line
    };
    let mut lines = Vec::with_capacity(body.len().saturating_add(1));
    if !head.iter().all(TerminalLine::is_empty) {
        lines.push(row_line(&head, palette.bold, palette.reset));
    }
    lines.extend(body.iter().map(|row| row_line(row, "", "")));
    lines
}

/// A table too wide for the terminal: each row as `header: value` lines, rows apart.
fn table_fallback(
    head: &[TerminalLine],
    body: &[Vec<TerminalLine>],
    palette: &Palette,
) -> Vec<String> {
    let mut lines = Vec::new();
    for row in body {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        for (i, value) in row.iter().enumerate() {
            match head.get(i).filter(|h| !h.is_empty()) {
                Some(key) => lines.push(format!("{}{key}{}: {value}", palette.bold, palette.reset)),
                None => lines.push(value.as_str().to_owned()),
            }
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use ipe_docs::markdown::HeadingLevel;
    use ipe_docs::markdown::parse::parse_blocks;

    use super::*;

    /// The control bytes and format characters a hostile page plants.
    const HOSTILE: &str =
        "a\u{1b}]52;c;Zm9v\u{7}b \u{1b}]8;;http://x\u{1b}\\c \u{1b}[2Jd \u{9b}e \u{202e}f g\rh";

    fn page(markdown: &str, width: Width) -> String {
        render(
            &TerminalLine::sanitize("Title"),
            Some("guide"),
            &parse_blocks(markdown),
            width,
            &Palette::PLAIN,
        )
        .as_str()
        .to_owned()
    }

    /// Whether `text` holds a byte or character a terminal would act on.
    fn has_hazard(text: &str) -> bool {
        text.chars().any(|c| {
            c != '\n' && ipe_diagnostics::terminal::is_display_hazard(c)
                || c == '\u{1b}'
                || c == '\r'
        })
    }

    #[test]
    fn hostile_body_rendered_inert() {
        for markdown in [
            HOSTILE.to_owned(),
            format!("# {HOSTILE}"),
            format!("- {HOSTILE}"),
            format!("```\n{HOSTILE}\n```"),
            format!("| h |\n|---|\n| {HOSTILE} |"),
            format!("> {HOSTILE}"),
        ] {
            for width in [Width::NO_WRAP, Width::DEFAULT, Width::from_columns(20)] {
                let out = page(&markdown, width);
                assert!(!has_hazard(&out), "{out:?}");
                assert!(
                    !out.contains("52;c") && !out.contains("http://x"),
                    "{out:?}"
                );
            }
            let coloured = render(
                &TerminalLine::sanitize("t"),
                None,
                &parse_blocks(&markdown),
                Width::DEFAULT,
                &Palette::COLOR,
            );
            let stripped = coloured
                .as_str()
                .replace(Palette::COLOR.reset, "")
                .replace(Palette::COLOR.bold, "")
                .replace(Palette::COLOR.dim, "")
                .replace(Palette::COLOR.yellow, "");
            assert!(!has_hazard(&stripped), "{stripped:?}");
        }
    }

    #[test]
    fn hostile_title_inert() {
        let out = render(
            &TerminalLine::sanitize(HOSTILE),
            Some(HOSTILE),
            &[],
            Width::DEFAULT,
            &Palette::PLAIN,
        );
        assert!(!has_hazard(out.as_str()), "{:?}", out.as_str());
        assert_eq!(out.as_str().lines().count(), 1);
    }

    #[test]
    fn oversize_body_bounded() {
        let paragraph = "word ".repeat(1 << 18);
        let out = page(&paragraph, Width::DEFAULT);
        let lines = out.lines().count();
        // 2^18 five-column words at 78 columns: 15 words per line.
        let expected = (1_usize << 18).div_ceil(15);
        assert!(lines > expected && lines < expected + 8, "{lines}");
        assert!(out.lines().all(|l| display_width(l, 0) <= 78));

        let word = "x".repeat(1 << 20);
        let out = page(&word, Width::DEFAULT);
        let lines = out.lines().count();
        assert!(
            lines > (1 << 20) / 78 && lines < (1 << 20) / 78 + 8,
            "{lines}"
        );
        assert!(out.lines().all(|l| display_width(l, 0) <= 78));

        let deep = Block::Blockquote(vec![Block::Para("x".to_owned())]);
        let mut nested = deep;
        for _ in 0..MAX_BLOCKQUOTE_DEPTH.saturating_add(8) {
            nested = Block::Blockquote(vec![nested]);
        }
        let out = render(
            &TerminalLine::sanitize("t"),
            None,
            std::slice::from_ref(&nested),
            Width::DEFAULT,
            &Palette::PLAIN,
        );
        assert!(!out.as_str().contains('x'), "past the ceiling is truncated");

        let quoted = format!("{}x", "> ".repeat(10_000));
        let out = page(&quoted, Width::DEFAULT);
        assert!(out.contains('x'));
        assert!(out.lines().count() < quoted.len());
    }

    #[test]
    fn wide_table_falls_back() {
        let wide = "w".repeat(60);
        let table = format!("| key | value |\n|---|---|\n| a | {wide} |\n| b | {wide} |");
        let out = page(&table, Width::from_columns(40));
        assert!(
            out.contains(&format!("key: a\nvalue: {wide}\n\nkey: b")),
            "{out}"
        );

        let fits = page(&table, Width::NO_WRAP);
        assert!(fits.contains(&format!("a    {wide}")), "{fits}");
    }

    #[test]
    fn link_is_text_not_osc8() {
        let out = page(
            "See [the guide](https://ipe.dev/guide) now.",
            Width::DEFAULT,
        );
        assert!(
            out.contains("See the guide <https://ipe.dev/guide> now."),
            "{out}"
        );
        assert!(!out.contains("\u{1b}]8"));
        let coloured = render(
            &TerminalLine::sanitize("t"),
            None,
            &parse_blocks("[x](https://ipe.dev)"),
            Width::DEFAULT,
            &Palette::COLOR,
        );
        assert!(!coloured.as_str().contains("\u{1b}]"));
    }

    #[test]
    fn width_parse_rejects_out_of_range() {
        assert_eq!(Width::from_columns(0), Width::NO_WRAP);
        assert_eq!(Width::from_columns(19), Width::DEFAULT);
        assert_eq!(Width::from_columns(201), Width::DEFAULT);
        assert_eq!(Width::from_columns(u16::MAX), Width::DEFAULT);
        assert_eq!(Width::from_columns(20).columns(), Some(20));
        assert_eq!(Width::from_columns(200).columns(), Some(200));
        for columns in [0, 19, 201, u16::MAX] {
            let width = Width::from_columns(columns).columns();
            assert!(width.is_none_or(|c| (Width::MIN..=Width::MAX).contains(&c)));
        }
    }

    #[test]
    fn blocks_take_their_terminal_shape() {
        let out = page(
            "# Head\n\nOne *two* **three** `four`.\n\n- a\n- b\n\n1. x\n2. y\n\n```ipe:error\nfoo =\n```",
            Width::DEFAULT,
        );
        assert_eq!(
            out,
            "Title  [guide]\n\nHead\n\nOne two three four.\n\n- a\n- b\n\n1. x\n2. y\n\n  foo =\n"
        );
        assert!(!out.contains("ipe:error"));
        assert!(!out.contains('#'));
    }

    #[test]
    fn list_items_wrap_under_their_marker() {
        let out = page(&format!("- {}", "ab ".repeat(20)), Width::from_columns(24));
        let mut lines = out.lines().skip(2);
        assert!(lines.next().is_some_and(|l| l.starts_with("- ab")));
        assert!(lines.all(|l| l.starts_with("  ab")));
    }

    #[test]
    fn heading_level_is_not_printed() {
        let out = render(
            &TerminalLine::sanitize("t"),
            None,
            &[Block::Header(HeadingLevel::H3, "Deep".to_owned())],
            Width::NO_WRAP,
            &Palette::PLAIN,
        );
        assert_eq!(out.as_str(), "t\n\nDeep\n");
    }
}
