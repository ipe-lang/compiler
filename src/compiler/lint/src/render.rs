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
    let loc = locate(source, finding.span.lo);
    let mut lines = Vec::with_capacity(finding.help.len().saturating_add(8));

    let title = format!("{} lint/{}", severity.word().to_uppercase(), finding.rule);
    lines.push((LineRole::Title, title_rule(&title, file)));
    lines.push((LineRole::Blank, String::new()));
    lines.push((LineRole::Message, finding.message.clone()));
    lines.push((LineRole::Blank, String::new()));

    let line_text = source
        .get(loc.line_start..loc.line_end)
        .unwrap_or("")
        .replace('\t', "    ");
    let line_no = loc.line.to_string();
    let pad = " ".repeat(line_no.len());
    let caret_indent = caret_indent(source, loc.line_start, finding.span.lo);
    let caret_width = caret_width(source, finding.span.lo, finding.span.hi);
    lines.push((
        LineRole::Snippet,
        format!("{pad} ┌─ {file}:{}:{}", loc.line, loc.col),
    ));
    lines.push((LineRole::Snippet, format!("{pad} │")));
    lines.push((LineRole::Snippet, format!("{line_no} │ {line_text}")));
    lines.push((
        LineRole::Snippet,
        format!(
            "{pad} │ {}{}",
            " ".repeat(caret_indent),
            "^".repeat(caret_width.max(1))
        ),
    ));

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
    line_end: usize,
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
    Loc {
        line,
        col,
        line_start,
        line_end: line_start + line_len,
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
