//! Human rendering of lint findings — a caret snippet that teaches like the
//! compiler's own diagnostics, without depending on the compiler's diagnostic
//! registry (a lint finding is not a compiler `Diagnostic`; it has no error
//! code and never blocks a build).
//!
//! Each finding renders as a title rule naming the rule and file, a one-line
//! message, the offending source line with a caret underline, and the teaching
//! help lines. Colour is omitted so output is byte-stable for goldens and CI;
//! each line carries its [`LineRole`] so a terminal front-end can paint it.

use crate::finding::{Finding, Severity};

/// The part of a rendered finding a line belongs to — what a front-end keys its
/// colour on, so no caller re-parses the rendered text to find the title.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LineRole {
    /// The `-- <SEVERITY> lint/<rule> ----- file` title rule.
    Title,
    /// The finding's message.
    Message,
    /// A location, source, or caret line of the snippet.
    Snippet,
    /// A teaching `= ` help line.
    Help,
    /// An empty separator line.
    Blank,
}

/// Render one finding against its module's `source`, showing `file` on the title line.
///
/// Deterministic and colour-free: the lines of [`render_finding_lines`], each ended by a newline.
#[must_use]
pub fn render_finding(finding: &Finding, file: &str, source: &str, severity: Severity) -> String {
    let mut out = String::new();
    for (_, line) in render_finding_lines(finding, file, source, severity) {
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// Render one finding as role-tagged lines (no trailing newlines): the title
/// rule, the message, the caret snippet, then the teaching help lines.
#[must_use]
pub fn render_finding_lines(
    finding: &Finding,
    file: &str,
    source: &str,
    severity: Severity,
) -> Vec<(LineRole, String)> {
    let start_loc = locate(source, finding.span.lo);
    // The last byte the span actually covers (spans are half-open); a
    // zero-width span anchors its end line to the start line.
    let end_anchor = if finding.span.hi > finding.span.lo {
        finding.span.hi - 1
    } else {
        finding.span.lo
    };
    let end_loc = locate(source, end_anchor);
    // Every row's `│` gutter aligns on the widest line number the span
    // touches, so a single-digit start line next to a double-digit end line
    // still lines up.
    let pad_width = end_loc.line.to_string().len();
    let pad = " ".repeat(pad_width);

    let mut lines = Vec::with_capacity(finding.help.len().saturating_add(8));

    let title = format!("{} lint/{}", severity.word().to_uppercase(), finding.rule);
    lines.push((LineRole::Title, title_rule(&title, file)));
    lines.push((LineRole::Blank, String::new()));
    lines.push((LineRole::Message, finding.message.clone()));
    lines.push((LineRole::Blank, String::new()));

    lines.push((
        LineRole::Snippet,
        format!("{pad} ┌─ {file}:{}:{}", start_loc.line, start_loc.col),
    ));
    lines.push((LineRole::Snippet, format!("{pad} │")));

    // One source line + one caret row per line the span covers; a covered line
    // with nothing to underline (a blank line inside the span) shows no caret
    // row. `cursor` strictly increases each pass (past the current line's
    // end), so the loop is bounded by `source`'s own length.
    let multi_line = end_loc.line > start_loc.line;
    let mut cursor = finding.span.lo;
    loop {
        let loc = locate(source, cursor);
        let line_text = source
            .get(loc.line_start..loc.content_end)
            .unwrap_or("")
            .replace('\t', "    ");
        let line_no = loc.line.to_string();
        let line_no_pad = " ".repeat(pad_width.saturating_sub(line_no.len()));
        let seg_lo = finding
            .span
            .lo
            .max(u32::try_from(loc.line_start).unwrap_or(u32::MAX));
        let seg_hi = finding
            .span
            .hi
            .min(u32::try_from(loc.content_end).unwrap_or(u32::MAX));
        let indent = caret_indent(source, loc.line_start, seg_lo);
        let width = caret_width(source, seg_lo, seg_hi);
        let source_row = if line_text.is_empty() {
            format!("{line_no_pad}{line_no} │")
        } else {
            format!("{line_no_pad}{line_no} │ {line_text}")
        };
        lines.push((LineRole::Snippet, source_row));
        if width > 0 || !multi_line {
            lines.push((
                LineRole::Snippet,
                format!("{pad} │ {}{}", " ".repeat(indent), "^".repeat(width.max(1))),
            ));
        }

        if loc.line >= end_loc.line {
            break;
        }
        let next = loc.line_end.saturating_add(1);
        if next > source.len() {
            break;
        }
        cursor = u32::try_from(next).unwrap_or(u32::MAX);
    }

    for help in &finding.help {
        lines.push((LineRole::Help, format!("{pad} = {help}")));
    }
    lines
}

/// A resolved 1-based line/column plus the byte bounds of the containing line.
struct Loc {
    line: usize,
    col: usize,
    line_start: usize,
    /// The byte of the line's `\n` terminator (or the end of `source`).
    line_end: usize,
    /// Where the line's visible text ends: `line_end` less a CRLF's `\r`.
    content_end: usize,
}

/// Locate a byte offset within `source`, clamping out-of-range / mid-character
/// offsets to the nearest boundary. Never panics.
fn locate(source: &str, raw: u32) -> Loc {
    let byte = floor_boundary(source, raw as usize);
    let before = source.get(..byte).unwrap_or("");
    let line = before.bytes().filter(|&b| b == b'\n').count() + 1;
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    let col = source.get(line_start..byte).unwrap_or("").chars().count() + 1;
    let rest = source.get(line_start..).unwrap_or("");
    let line_len = rest.find('\n').unwrap_or(rest.len());
    let content_len = rest
        .get(..line_len)
        .and_then(|l| l.strip_suffix('\r'))
        .map_or(line_len, str::len);
    Loc {
        line,
        col,
        line_start,
        line_end: line_start + line_len,
        content_end: line_start + content_len,
    }
}

/// The number of characters (tabs counted as four) from a line's start to the
/// span start — the caret's leading indent.
fn caret_indent(source: &str, line_start: usize, span_lo: u32) -> usize {
    let lo = floor_boundary(source, span_lo as usize);
    source
        .get(line_start..lo)
        .unwrap_or("")
        .chars()
        .map(|c| if c == '\t' { 4 } else { 1 })
        .sum()
}

/// The caret width in characters between two byte offsets, at least the width of
/// the underlined text.
fn caret_width(source: &str, lo: u32, hi: u32) -> usize {
    let lo = floor_boundary(source, lo as usize);
    let hi = floor_boundary(source, hi as usize);
    source.get(lo..hi).unwrap_or("").chars().count()
}

/// The largest char boundary `<= b` (and `<= source.len()`).
fn floor_boundary(source: &str, b: usize) -> usize {
    let mut b = b.min(source.len());
    while b > 0 && !source.is_char_boundary(b) {
        b -= 1;
    }
    b
}

/// The width the title rule pads to.
const RULE_WIDTH: usize = 60;

/// A `-- <title> ----- <file>` rule padded to [`RULE_WIDTH`].
fn title_rule(title: &str, file: &str) -> String {
    let lead = format!("-- {title} ");
    let trail = format!(" {file}");
    let used = lead.chars().count() + trail.chars().count();
    let dashes = RULE_WIDTH.saturating_sub(used).max(3);
    format!("{lead}{}{trail}", "-".repeat(dashes))
}

#[cfg(test)]
mod tests {
    use ipe_diagnostics::Span;

    use super::{LineRole, render_finding_lines};
    use crate::finding::{Finding, Severity};

    /// A finding for `rule` over `lo..hi`, with one help line.
    fn finding(lo: usize, hi: usize) -> Finding {
        Finding {
            rule: "unused-imports",
            module: vec!["Main".to_owned()],
            span: Span::new(
                u32::try_from(lo).unwrap_or(u32::MAX),
                u32::try_from(hi).unwrap_or(u32::MAX),
            ),
            message: "unused import".to_owned(),
            help: vec!["remove it".to_owned()],
            fix: None,
            sig_fix: None,
        }
    }

    /// The snippet rows (location line through the last caret row).
    fn snippet(finding: &Finding, source: &str) -> Vec<String> {
        render_finding_lines(finding, "Main.ipe", source, Severity::Warn)
            .into_iter()
            .filter(|(role, _)| *role == LineRole::Snippet)
            .map(|(_, line)| line)
            .collect()
    }

    /// A span crossing from line 9 to line 11 aligns every gutter on the
    /// two-digit width, shows the blank middle line without a caret row, and
    /// never renders a CRLF's `\r` as part of the line or its underline.
    #[test]
    fn multi_line_span_aligns_gutter_skips_blank_line_and_strips_crlf() {
        let decl = "import Foo exposing\r\n\r\n    (bar)";
        let source = format!("{}{decl}\r\nmain = 1\r\n", "a = 1\r\n".repeat(8));
        let lo = source.find("import").unwrap_or(0);
        let rows = snippet(&finding(lo, lo + decl.len()), &source);
        assert_eq!(
            rows,
            [
                "   ┌─ Main.ipe:9:1",
                "   │",
                " 9 │ import Foo exposing",
                "   │ ^^^^^^^^^^^^^^^^^^^",
                "10 │",
                "11 │     (bar)",
                "   │     ^^^^^",
            ]
        );
    }

    /// A single-line span keeps its single-digit gutter and underlines exactly
    /// its own text, excluding the CRLF terminator.
    #[test]
    fn single_line_span_underlines_only_its_text() {
        let source = "import Foo\r\nmain = 1\r\n";
        let rows = snippet(&finding(0, "import Foo".len()), source);
        assert_eq!(
            rows,
            [
                "  ┌─ Main.ipe:1:1",
                "  │",
                "1 │ import Foo",
                "  │ ^^^^^^^^^^"
            ]
        );
    }
}
