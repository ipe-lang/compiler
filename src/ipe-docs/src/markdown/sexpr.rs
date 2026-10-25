//! Canonical S-expression serialization of the parse tree, byte-identical to
//! the `Ipe.Markdown` serializer in
//! `examples/shapes/script/markdown-parity/src/Main.ipe`.
//!
//! The semantic-parity gate compares this port's tree, serialized here, to a
//! snapshot produced by an `ipe` run of that program — so `Ipe.Markdown` stays
//! authoritative and any divergence reddens CI. The two serializers MUST agree
//! character-for-character; every arm here mirrors a `blockLines` or `spanLine`
//! arm there.

use super::{Block, HeadingLevel, Span};
use std::fmt::Write as _;

/// Serialize a block list to canonical S-expression lines (joined by `\n`),
/// mirroring the Ipê serializer's `List.map (blockLines "") blocks |> join "\n"`.
#[must_use]
pub fn blocks_to_sexpr(blocks: &[Block]) -> String {
    blocks
        .iter()
        .map(|b| block_lines("", b))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Mirrors `blockLines indent block`.
fn block_lines(indent: &str, block: &Block) -> String {
    match block {
        Block::Header(level, text) => {
            format!("{indent}(header {} {})", level_name(*level), quote(text))
        }
        Block::Para(text) => format!("{indent}(para {})", quote(text)),
        Block::Code(body) => format!("{indent}(code {})", quote(body)),
        Block::Bullet(items) => format!("{indent}(bullet{})", items_(items)),
        Block::Numbered(items) => format!("{indent}(numbered{})", items_(items)),
        Block::Table(header, rows) => {
            let mut out = format!("{indent}(table (hdr{})", items_(header));
            for r in rows {
                let _ = write!(out, " (row{})", items_(r));
            }
            out.push(')');
            out
        }
        Block::Rule => format!("{indent}(rule)"),
        Block::Blockquote(inner) => {
            let child_indent = format!("{indent}  ");
            let mut lines: Vec<String> = Vec::new();
            lines.push(format!("{indent}(blockquote"));
            for b in inner {
                lines.push(block_lines(&child_indent, b));
            }
            lines.push(format!("{indent})"));
            lines.join("\n")
        }
    }
}

/// Serialize a span list to canonical S-expression lines (joined by `\n`).
///
/// Mirrors the Ipê serializer's `List.map spanLine spans |> join "\n"`; a link
/// or image target prints as its [`SafeHref`](super::SafeHref) string.
#[must_use]
pub fn spans_to_sexpr(spans: &[Span]) -> String {
    spans.iter().map(span_line).collect::<Vec<_>>().join("\n")
}

/// Mirrors `spanLine span`.
fn span_line(span: &Span) -> String {
    match span {
        Span::Plain(text) => format!("(plain {})", quote(text)),
        Span::Bold(text) => format!("(bold {})", quote(text)),
        Span::Italic(text) => format!("(italic {})", quote(text)),
        Span::Code(text) => format!("(code {})", quote(text)),
        Span::Link(text, url) => format!("(link {} {})", quote(text), quote(url.as_str())),
        Span::Image(alt, url) => format!("(image {} {})", quote(alt), quote(url.as_str())),
        Span::HardBreak => "(hardbreak)".to_owned(),
    }
}

/// Mirrors `items_`: each string prefixed by a space, quoted.
fn items_(xs: &[String]) -> String {
    let mut out = String::new();
    for x in xs {
        let _ = write!(out, " {}", quote(x));
    }
    out
}

/// Mirrors the Ipê `quote`: wrap in `"`, escaping `\`, `"`, newline, tab in
/// exactly this order.
fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

const fn level_name(level: HeadingLevel) -> &'static str {
    match level {
        HeadingLevel::H1 => "H1",
        HeadingLevel::H2 => "H2",
        HeadingLevel::H3 => "H3",
        HeadingLevel::H4 => "H4",
        HeadingLevel::H5 => "H5",
        HeadingLevel::H6 => "H6",
    }
}
