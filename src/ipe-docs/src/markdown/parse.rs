//! Hand-port of `Ipe.Markdown.parseBlocks` / `parseSpans`.
//!
//! Each function mirrors its `Ipe.Markdown` counterpart one-to-one so the
//! semantic-parity gate (parser tree == an `ipe`-run snapshot of
//! `Ipe.Markdown`) stays a faithful check. Recursion in the source is rewritten
//! as iteration where a Rust translation would otherwise risk deep recursion,
//! preserving the exact tree.
//!
//! No indexing, `unwrap`, or `panic`: `&[char]` slices are accessed through
//! `slice` / `index_of_first` / `.get`, iterators, and pattern matching.

use super::{
    Block, HeadingLevel, MAX_BLOCKQUOTE_DEPTH, SafeHref, Span, index_of_first, len_i, slice,
    starts_with,
};

// ── Block parsing ───────────────────────────────────────────────────────────

/// Split a Markdown document into its list of `Block`s. Mirrors
/// `Ipe.Markdown.parseBlocks`.
#[must_use]
pub fn parse_blocks(src: &str) -> Vec<Block> {
    // `Ipe.Markdown` calls `String.lines` once, then recurses over the list.
    let lines: Vec<&str> = src.lines().collect();
    blocks_from_lines(&lines, 0)
}

/// Mirrors `blocksFromLines`. Rewritten as a loop over the line slice (the Ipê
/// source recurses on the tail) so a long document cannot deep-recurse.
///
/// `depth` is the current blockquote nesting level. The ONLY input-driven
/// recursion here is the blockquote arm (`blocks_from_lines` on the stripped
/// inner lines); every other block former consumes lines iteratively. Bounding
/// that one arm at [`MAX_BLOCKQUOTE_DEPTH`] makes the whole parse bounded by
/// construction (principle 3): a `>>>>…` document deeper than the ceiling can
/// neither overflow the parse recursion nor build a `Block::Blockquote` tree
/// whose recursive `Drop` overflows the stack, because the tree is never built
/// past the ceiling. A blockquote opened at the ceiling folds its inner lines
/// into one paragraph (joined by spaces, trimmed; none when blank), the
/// `Ipe.Markdown` `maxQuoteDepth` rule — the nesting is truncated, never
/// silently discarded and never recursed.
fn blocks_from_lines<'a>(mut lines: &'a [&'a str], depth: usize) -> Vec<Block> {
    let mut out: Vec<Block> = Vec::new();
    while let Some((&l, rest)) = lines.split_first() {
        let t = l.trim();
        if t.is_empty() {
            lines = rest;
        } else if is_hr_line(t) {
            out.push(Block::Rule);
            lines = rest;
        } else if let Some(hdr) = atx_header(l) {
            out.push(hdr);
            lines = rest;
        } else if l.starts_with("```") {
            let (body, after) = take_code_fence(rest);
            out.push(Block::Code(body));
            lines = after;
        } else if is_bullet_line(l) {
            let (items, after) = take_bullet_group(lines);
            out.push(Block::Bullet(items));
            lines = after;
        } else if is_numbered_line(l) {
            let (items, after) = take_numbered_group(lines);
            out.push(Block::Numbered(items));
            lines = after;
        } else if is_table_header_line(l, rest) {
            let (header, rows, after) = take_table(lines);
            out.push(Block::Table(header, rows));
            lines = after;
        } else if is_blockquote_line(l) {
            let (inner_lines, after) = take_blockquote_group(lines);
            lines = after;
            if depth >= MAX_BLOCKQUOTE_DEPTH {
                // Bounded by construction: at the ceiling we neither recurse nor
                // wrap further. The already-stripped inner lines are folded into
                // a single paragraph so their text is preserved as inert content
                // without adding another `Blockquote` level — the deep nesting
                // is truncated, never recursed and never silently dropped.
                let joined = inner_lines.join("\n");
                let flattened = joined.replace(['\n'], " ");
                let text = flattened.trim();
                if !text.is_empty() {
                    out.push(Block::Para(text.to_owned()));
                }
                continue;
            }
            let inner_refs: Vec<&str> = inner_lines.iter().map(String::as_str).collect();
            out.push(Block::Blockquote(blocks_from_lines(&inner_refs, depth + 1)));
        } else {
            let (body, after) = take_paragraph(lines);
            out.push(Block::Para(body));
            lines = after;
        }
    }
    out
}

/// The ATX-heading arms of `blocksFromLines`, folded into one helper: `#`..
/// `######` followed by a single space. Mirrors the six `String.startsWith`
/// arms exactly (a space after the hashes is required; the hash run is sliced
/// off with the trailing space).
fn atx_header(l: &str) -> Option<Block> {
    for (marker, level) in [
        ("###### ", HeadingLevel::H6),
        ("##### ", HeadingLevel::H5),
        ("#### ", HeadingLevel::H4),
        ("### ", HeadingLevel::H3),
        ("## ", HeadingLevel::H2),
        ("# ", HeadingLevel::H1),
    ] {
        if l.starts_with(marker) {
            let chars: Vec<char> = l.chars().collect();
            let marker_len = isize::try_from(marker.chars().count()).unwrap_or(0);
            let text = slice(marker_len, len_i(&chars), &chars);
            return Some(Block::Header(level, text));
        }
    }
    None
}

/// `"---" / "***" / "___"` (and a couple of longer dash runs) → rule.
/// Mirrors `isHrLine`.
fn is_hr_line(t: &str) -> bool {
    matches!(t, "---" | "***" | "___" | "----" | "-----")
}

/// Mirrors `isBlockquoteLine`.
fn is_blockquote_line(l: &str) -> bool {
    l.starts_with("> ") || l == ">"
}

/// Collect consecutive blockquote lines, stripping the `> ` prefix. Mirrors
/// `takeBlockquoteGroup` (rewritten iteratively).
fn take_blockquote_group<'a>(lines: &'a [&'a str]) -> (Vec<String>, &'a [&'a str]) {
    let mut inner: Vec<String> = Vec::new();
    let mut rest = lines;
    while let Some((&l, tail)) = rest.split_first() {
        if is_blockquote_line(l) {
            let stripped = if l.starts_with("> ") {
                let chars: Vec<char> = l.chars().collect();
                slice(2, len_i(&chars), &chars)
            } else {
                String::new()
            };
            inner.push(stripped);
            rest = tail;
        } else {
            break;
        }
    }
    (inner, rest)
}

/// Mirrors `isBulletLine`.
fn is_bullet_line(l: &str) -> bool {
    l.starts_with("- ") || l.starts_with("* ") || l.starts_with("  - ") || l.starts_with("  * ")
}

/// Mirrors `isNumberedLine` (prefixes `1. `..`10. `).
fn is_numbered_line(l: &str) -> bool {
    const PREFIXES: [&str; 10] = [
        "1. ", "2. ", "3. ", "4. ", "5. ", "6. ", "7. ", "8. ", "9. ", "10. ",
    ];
    PREFIXES.iter().any(|p| l.starts_with(p))
}

/// Consume a code-fence body up to (and consuming) the next closing ```` ``` ````.
/// Mirrors `takeCodeFence` + `codeFenceLoop`, joining with `\n`.
fn take_code_fence<'a>(lines: &'a [&'a str]) -> (String, &'a [&'a str]) {
    let mut body: Vec<&str> = Vec::new();
    let mut rest = lines;
    while let Some((&l, tail)) = rest.split_first() {
        if l.starts_with("```") {
            return (body.join("\n"), tail);
        }
        body.push(l);
        rest = tail;
    }
    (body.join("\n"), rest)
}

/// Group consecutive bullet lines, stripping each marker. Mirrors
/// `takeBulletGroup` + `stripBulletPrefix`.
fn take_bullet_group<'a>(lines: &'a [&'a str]) -> (Vec<String>, &'a [&'a str]) {
    let mut items: Vec<String> = Vec::new();
    let mut rest = lines;
    while let Some((&l, tail)) = rest.split_first() {
        if is_bullet_line(l) {
            items.push(strip_bullet_prefix(l));
            rest = tail;
        } else {
            break;
        }
    }
    (items, rest)
}

/// Group consecutive numbered lines. Mirrors `takeNumberedGroup` +
/// `stripNumberedPrefix`.
fn take_numbered_group<'a>(lines: &'a [&'a str]) -> (Vec<String>, &'a [&'a str]) {
    let mut items: Vec<String> = Vec::new();
    let mut rest = lines;
    while let Some((&l, tail)) = rest.split_first() {
        if is_numbered_line(l) {
            items.push(strip_numbered_prefix(l));
            rest = tail;
        } else {
            break;
        }
    }
    (items, rest)
}

/// Drop `- ` / `* ` / `  - ` / `  * `. Mirrors `stripBulletPrefix`.
fn strip_bullet_prefix(l: &str) -> String {
    let chars: Vec<char> = l.chars().collect();
    let n = if l.starts_with("  - ") || l.starts_with("  * ") {
        4
    } else {
        2
    };
    slice(n, len_i(&chars), &chars)
}

/// Drop `1. ` / `10. ` etc. — split on `". "`, rejoin the tail. Mirrors
/// `stripNumberedPrefix`.
fn strip_numbered_prefix(l: &str) -> String {
    let parts: Vec<&str> = l.split(". ").collect();
    match parts.split_first() {
        Some((_, rest)) if !rest.is_empty() => rest.join(". "),
        _ => l.to_owned(),
    }
}

/// Consume contiguous paragraph lines. A line ending in two-or-more spaces
/// keeps a `\n` (hard break); other continuations fold with a space. Mirrors
/// `takeParagraph` (rewritten iteratively, preserving the join/hard-break rule).
fn take_paragraph<'a>(lines: &'a [&'a str]) -> (String, &'a [&'a str]) {
    let mut collected: Vec<&str> = Vec::new();
    let mut rest = lines;
    while let Some((&l, tail)) = rest.split_first() {
        if l.trim().is_empty() || is_block_starter(l) {
            break;
        }
        collected.push(l);
        rest = tail;
    }
    // Fold with per-line separators: a line ending in "  " is a hard break.
    let mut body = String::new();
    let mut prev_hard_break = false;
    for (idx, &l) in collected.iter().enumerate() {
        if idx > 0 {
            // The separator BEFORE this line is decided by the PREVIOUS line's
            // trailing spaces — matching the Ipê right-fold, where `sep` is
            // chosen from `l` (the earlier line) before appending `more`.
            body.push_str(if prev_hard_break { "\n" } else { " " });
        }
        body.push_str(l);
        prev_hard_break = l.ends_with("  ");
    }
    (body, rest)
}

/// Mirrors `isBlockStarter`.
fn is_block_starter(l: &str) -> bool {
    l.starts_with("# ")
        || l.starts_with("## ")
        || l.starts_with("### ")
        || l.starts_with("#### ")
        || l.starts_with("##### ")
        || l.starts_with("###### ")
        || l.starts_with("```")
        || is_bullet_line(l)
        || is_numbered_line(l)
        || is_hr_line(l.trim())
        || is_blockquote_line(l)
}

// ── Table parsing ─────────────────────────────────────────────────────────────

/// A header row `| ... |` immediately followed by a separator row. Mirrors
/// `isTableHeaderLine`.
fn is_table_header_line(l: &str, rest: &[&str]) -> bool {
    if !looks_like_table_row(l) {
        return false;
    }
    rest.first().is_some_and(|next| is_table_separator(next))
}

/// Mirrors `looksLikeTableRow`.
fn looks_like_table_row(l: &str) -> bool {
    let t: Vec<char> = l.trim().chars().collect();
    starts_with("|", &t) && slice(1, len_i(&t), &t).contains('|')
}

/// Mirrors `isTableSeparator`.
fn is_table_separator(l: &str) -> bool {
    let t = l.trim();
    t.starts_with('|') && (t.contains('-') || t.contains('=')) && table_separator_ok(t)
}

/// A separator row is only `|`, `-`, `:`, `=`, and whitespace. Mirrors
/// `tableSeparatorOk`.
fn table_separator_ok(t: &str) -> bool {
    t.chars()
        .all(|c| matches!(c, '|' | '-' | ':' | '=') || c.is_whitespace())
}

/// Consume a table: header row, separator (dropped), then body rows. Mirrors
/// `takeTable` + `takeTableRows`.
fn take_table<'a>(lines: &'a [&'a str]) -> (Vec<String>, Vec<Vec<String>>, &'a [&'a str]) {
    // `header :: _sep :: dataLines` — anything shorter yields the empty table.
    let Some((&header, rest_after_header)) = lines.split_first() else {
        return (Vec::new(), Vec::new(), lines);
    };
    let Some((_sep, data_lines)) = rest_after_header.split_first() else {
        return (Vec::new(), Vec::new(), lines);
    };
    let header_cells = parse_table_row(header);
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut rest = data_lines;
    while let Some((&l, tail)) = rest.split_first() {
        if looks_like_table_row(l) {
            rows.push(parse_table_row(l));
            rest = tail;
        } else {
            break;
        }
    }
    (header_cells, rows, rest)
}

/// `| a | b | c |` → `["a", "b", "c"]`. Strips outer pipes, splits on `|`,
/// trims each cell. Mirrors `parseTableRow`.
fn parse_table_row(l: &str) -> Vec<String> {
    let t: Vec<char> = l.trim().chars().collect();
    let stripped = if starts_with("|", &t) {
        slice(1, len_i(&t), &t)
    } else {
        t.iter().collect()
    };
    let stripped_chars: Vec<char> = stripped.chars().collect();
    let trimmed_trailing = if stripped.ends_with('|') {
        slice(0, len_i(&stripped_chars) - 1, &stripped_chars)
    } else {
        stripped
    };
    trimmed_trailing
        .split('|')
        .map(|c| c.trim().to_owned())
        .collect()
}

// ── Inline span parsing ───────────────────────────────────────────────────────

/// Parse one line of inline markup into its `Span`s. Mirrors
/// `Ipe.Markdown.parseSpans` / `spanLoop`.
#[must_use]
pub fn parse_spans(s: &str) -> Vec<Span> {
    let chars: Vec<char> = s.chars().collect();
    span_loop(&chars, Vec::new(), String::new())
}

/// Character-by-character span loop. `pending` accumulates plain text; a
/// delimiter flushes the run and consumes the delimited span. Mirrors
/// `spanLoop` (rewritten as a loop; the Ipê source prepends onto a reversed
/// accumulator then `List.reverse`s once — this port appends in source order,
/// so the result is already forward and no final reverse is needed).
///
/// A failed link scan records in `links_off_until` how far its proof reaches
/// (see [`take_link`]), so no `[` it covers is scanned again and a run of `[`
/// costs one scan in total: the loop is linear in the line's length.
fn span_loop(mut remaining: &[char], mut acc: Vec<Span>, mut pending: String) -> Vec<Span> {
    let total = remaining.len();
    let mut links_off_until = 0_usize;
    loop {
        let pos = total.saturating_sub(remaining.len());
        if remaining.is_empty() {
            if pending.ends_with("  ") {
                let trimmed = strip_trailing_spaces(&pending);
                acc = flush_pending(&trimmed, acc);
                acc.push(Span::HardBreak);
            } else {
                acc = flush_pending(&pending, acc);
            }
            return acc;
        } else if starts_with("\n", remaining) {
            let trimmed = strip_trailing_spaces(&pending);
            acc = flush_pending(&trimmed, acc);
            acc.push(Span::HardBreak);
            remaining = remaining.get(1..).unwrap_or(&[]);
            pending = String::new();
        } else if starts_with("![", remaining) {
            let bracket = remaining.get(1..).unwrap_or(&[]);
            if let Some((alt, url, after)) =
                try_link(bracket, pos.saturating_add(1), &mut links_off_until)
            {
                acc = flush_pending(&pending, acc);
                acc.push(Span::Image(alt, url));
                remaining = after;
                pending = String::new();
            } else {
                remaining = remaining.get(1..).unwrap_or(&[]);
                pending.push('!');
            }
        } else if starts_with("**", remaining) {
            let inner = remaining.get(2..).unwrap_or(&[]);
            let (text, after) = take_between("**", inner);
            acc = flush_pending(&pending, acc);
            acc.push(Span::Bold(text));
            remaining = after;
            pending = String::new();
        } else if starts_with("`", remaining) {
            let inner = remaining.get(1..).unwrap_or(&[]);
            let (text, after) = take_between("`", inner);
            acc = flush_pending(&pending, acc);
            acc.push(Span::Code(text));
            remaining = after;
            pending = String::new();
        } else if starts_with("[", remaining) {
            if let Some((text, url, after)) = try_link(remaining, pos, &mut links_off_until) {
                acc = flush_pending(&pending, acc);
                acc.push(Span::Link(text, url));
                remaining = after;
                pending = String::new();
            } else {
                remaining = remaining.get(1..).unwrap_or(&[]);
                pending.push('[');
            }
        } else if starts_with("*", remaining) {
            let inner = remaining.get(1..).unwrap_or(&[]);
            let (text, after) = take_between("*", inner);
            if text.is_empty() {
                remaining = remaining.get(1..).unwrap_or(&[]);
                pending.push('*');
            } else {
                acc = flush_pending(&pending, acc);
                acc.push(Span::Italic(text));
                remaining = after;
                pending = String::new();
            }
        } else {
            // One codepoint of plain text.
            if let Some((c, rest)) = remaining.split_first() {
                pending.push(*c);
                remaining = rest;
            } else {
                remaining = &[];
            }
        }
    }
}

/// Mirrors `flushPending`: push the pending run onto the (reversed) accumulator.
fn flush_pending(pending: &str, mut acc: Vec<Span>) -> Vec<Span> {
    if !pending.is_empty() {
        acc.push(Span::Plain(pending.to_owned()));
    }
    acc
}

/// Take text up to (and consuming) the closing delimiter; if none, the rest is
/// the inner (graceful degradation). Mirrors `takeBetween` (`s` is already the
/// codepoint slice past the opening delimiter). Returns `(inner, after)` where
/// `after` is the remaining codepoint slice.
fn take_between<'a>(delim: &str, s: &'a [char]) -> (String, &'a [char]) {
    let d: Vec<char> = delim.chars().collect();
    index_of_first(&d, s).map_or_else(
        || (s.iter().collect(), &[][..]),
        |idx| {
            let inner: String = s.get(..idx).map(|r| r.iter().collect()).unwrap_or_default();
            let after = s.get(idx + d.len()..).unwrap_or(&[]);
            (inner, after)
        },
    )
}

/// A parsed link: its text, its proven-safe target, and the input after it.
type LinkParts<'a> = (String, SafeHref, &'a [char]);

/// Parse the link whose `[` opens `s`, unless an earlier miss already covers it.
///
/// `bracket` is that `[`'s codepoint offset in the line. A miss widens
/// `links_off_until` to the first offset where a `[` may still open a link.
fn try_link<'a>(
    s: &'a [char],
    bracket: usize,
    links_off_until: &mut usize,
) -> Option<LinkParts<'a>> {
    if bracket < *links_off_until {
        return None;
    }
    match take_link(s) {
        Ok(parts) => Some(parts),
        Err(clear) => {
            *links_off_until = bracket.saturating_add(clear);
            None
        }
    }
}

/// Parse `[text](url)` at the current position (`s` starts with `[`).
///
/// The parsed span carries a proven-safe href by type, so an unsafe scheme is
/// turned away at the parse boundary and cannot reach the emitter
/// (defend-in-depth beside the emit gate). Mirrors `takeLink`, with the scheme
/// gate at the parse boundary.
///
/// # Errors
///
/// On a miss, the codepoint count from the start of `s` before which no `[`
/// can open a link either. Link text ends at the FIRST `]`, so every `[` ahead
/// of that `]` shares this one's `]`, `(` and URL and fails the same way: the
/// count is the `]`'s offset when the `(` is missing or the URL is unsafe.
/// With no `]`, or no `)` after the `(`, no later `[` can close either, so the
/// count is the length of `s`.
fn take_link(s: &[char]) -> Result<LinkParts<'_>, usize> {
    let Some(close) = index_of_first(&[']'], s) else {
        return Err(s.len());
    };
    let after_close = s.get(close + 1..).unwrap_or(&[]);
    if !starts_with("(", after_close) {
        return Err(close);
    }
    let url_and_after = after_close.get(1..).unwrap_or(&[]);
    let Some(close_paren) = index_of_first(&[')'], url_and_after) else {
        return Err(s.len());
    };
    let link_text: String = s
        .get(1..close)
        .map(|r| r.iter().collect())
        .unwrap_or_default();
    let link_url: String = url_and_after
        .get(..close_paren)
        .map(|r| r.iter().collect())
        .unwrap_or_default();
    // Parse boundary of the two-boundary href gate: an unsafe scheme degrades
    // to literal text (the caller pushes `[` and continues), never a link.
    let Some(href) = SafeHref::parse(&link_url) else {
        return Err(close);
    };
    let after_link = url_and_after.get(close_paren + 1..).unwrap_or(&[]);
    Ok((link_text, href, after_link))
}

/// Right-trim ASCII spaces only. Mirrors `stripTrailingSpaces`.
fn strip_trailing_spaces(s: &str) -> String {
    s.trim_end_matches(' ').to_owned()
}

#[cfg(test)]
mod tests {
    use super::super::{Block, HeadingLevel, SafeHref, Span};
    use super::{parse_blocks, parse_spans};

    fn href(url: &str) -> SafeHref {
        SafeHref::parse(url).expect("test href must be safe")
    }

    #[test]
    fn headers_all_six_levels() {
        assert_eq!(
            parse_blocks("# One"),
            vec![Block::Header(HeadingLevel::H1, "One".to_owned())]
        );
        assert_eq!(
            parse_blocks("###### Six"),
            vec![Block::Header(HeadingLevel::H6, "Six".to_owned())]
        );
        // A hash run without a trailing space is prose, not a header.
        assert_eq!(
            parse_blocks("#nospace"),
            vec![Block::Para("#nospace".to_owned())]
        );
    }

    #[test]
    fn paragraph_folds_lines_with_space_and_hard_break() {
        assert_eq!(
            parse_blocks("alpha\nbeta"),
            vec![Block::Para("alpha beta".to_owned())]
        );
        // A line ending in two spaces keeps a newline (hard break).
        assert_eq!(
            parse_blocks("alpha  \nbeta"),
            vec![Block::Para("alpha  \nbeta".to_owned())]
        );
    }

    #[test]
    fn bullet_and_numbered_groups() {
        assert_eq!(
            parse_blocks("- a\n- b"),
            vec![Block::Bullet(vec!["a".to_owned(), "b".to_owned()])]
        );
        assert_eq!(
            parse_blocks("1. a\n2. b"),
            vec![Block::Numbered(vec!["a".to_owned(), "b".to_owned()])]
        );
    }

    #[test]
    fn code_fence_body_without_delimiters() {
        assert_eq!(
            parse_blocks("```ipe\nfoo =\n    bar\n```"),
            vec![Block::Code("foo =\n    bar".to_owned())]
        );
    }

    #[test]
    fn horizontal_rule() {
        assert_eq!(parse_blocks("---"), vec![Block::Rule]);
        assert_eq!(parse_blocks("***"), vec![Block::Rule]);
    }

    #[test]
    fn table_header_and_rows() {
        assert_eq!(
            parse_blocks("| A | B |\n|---|---|\n| 1 | 2 |"),
            vec![Block::Table(
                vec!["A".to_owned(), "B".to_owned()],
                vec![vec!["1".to_owned(), "2".to_owned()]],
            )]
        );
    }

    #[test]
    fn blockquote_nests_inner_blocks() {
        assert_eq!(
            parse_blocks("> quoted line"),
            vec![Block::Blockquote(vec![Block::Para(
                "quoted line".to_owned()
            )])]
        );
    }

    #[test]
    fn blockquote_parse_depth_is_bounded_far_past_ceiling() {
        // A ~200 KB README of `> ` markers on a single line: 100_000 nesting
        // markers, ~3000x the ceiling. The pre-fix parser recursed once per
        // marker and overflowed the stack (an uncatchable abort). Bounded by
        // construction, the parser caps the Blockquote tree it builds at
        // MAX_BLOCKQUOTE_DEPTH, so this returns without deep recursion and the
        // resulting tree's recursive Drop cannot overflow either. Reaching the
        // assertions at all is the proof there was no stack blow-up.
        use super::super::MAX_BLOCKQUOTE_DEPTH;

        // Nesting depth of the built tree.
        fn depth(bs: &[Block]) -> usize {
            bs.iter()
                .map(|b| match b {
                    Block::Blockquote(inner) => 1 + depth(inner),
                    _ => 0,
                })
                .max()
                .unwrap_or(0)
        }

        let src = format!("{}x", "> ".repeat(100_000));
        let blocks = parse_blocks(&src);
        let built = depth(&blocks);
        assert!(
            built <= MAX_BLOCKQUOTE_DEPTH,
            "parse nesting must cap at the ceiling, built {built} deep"
        );
        assert_eq!(
            built, MAX_BLOCKQUOTE_DEPTH,
            "deep input should reach exactly the ceiling: {built}"
        );
    }

    #[test]
    fn blockquote_many_lines_stay_shallow() {
        // 100_000 SEPARATE blockquote lines nest only ONE level (all collected
        // at the same group), so this is bounded regardless of the ceiling — a
        // second input-shape proof that the only depth driver is markers-per-
        // line, which the ceiling caps.
        let mut src = String::new();
        for _ in 0..100_000 {
            src.push_str("> a\n");
        }
        let blocks = parse_blocks(&src);
        assert!(matches!(blocks.as_slice(), [Block::Blockquote(_)]));
    }

    #[test]
    fn spans_emphasis_code_and_plain() {
        assert_eq!(
            parse_spans("a **b** c"),
            vec![
                Span::Plain("a ".to_owned()),
                Span::Bold("b".to_owned()),
                Span::Plain(" c".to_owned()),
            ]
        );
        assert_eq!(parse_spans("`code`"), vec![Span::Code("code".to_owned())]);
        assert_eq!(parse_spans("*i*"), vec![Span::Italic("i".to_owned())]);
    }

    #[test]
    fn spans_safe_link_parsed() {
        assert_eq!(
            parse_spans("[text](guide.html)"),
            vec![Span::Link("text".to_owned(), href("guide.html"))]
        );
    }

    #[test]
    fn spans_reject_javascript_link_at_parse() {
        // Defend-in-depth boundary #1: an unsafe scheme never becomes a LinkSpan.
        // The `[` degrades to literal text (no Link span present).
        let spans = parse_spans("[x](javascript:alert(1))");
        assert!(
            !spans.iter().any(|s| matches!(s, Span::Link(..))),
            "javascript: must not parse as a link: {spans:?}"
        );
    }

    #[test]
    fn spans_reject_vbscript_and_data_links_at_parse() {
        for src in [
            "[x](vbscript:msgbox(1))",
            "[x](data:text/html,<script>)",
            "[x](data:image/png;base64,AAAA)",
        ] {
            let spans = parse_spans(src);
            assert!(
                !spans.iter().any(|s| matches!(s, Span::Link(..))),
                "unsafe scheme must not parse as a link ({src}): {spans:?}"
            );
        }
    }

    #[test]
    fn spans_reject_control_char_bypass_at_parse() {
        // The exact inputs the fail-open predicate waved through: a tab/LF/CR or
        // interior space/NUL inside the scheme region. A browser strips
        // tab/LF/CR before scheme detection, so each re-forms `javascript:`. All
        // must degrade to literal text — no Link span present.
        let cases = [
            "[x](java\tscript:alert(1))",
            "[x](java\nscript:alert(1))",
            "[x](java\rscript:alert(1))",
            "[x](javascript\t:alert(1))",
            "[x](java\0script:alert(1))",
            "[x](java script:alert(1))",
            "[x](\njavascript:alert(1))",
        ];
        for src in cases {
            let spans = parse_spans(src);
            assert!(
                !spans.iter().any(|s| matches!(s, Span::Link(..))),
                "control-char scheme bypass must not parse as a link ({src:?}): {spans:?}"
            );
        }
        // The literal `&#09;` entity form is inert text at the Markdown layer
        // (no HTML-entity decode happens in the parser), so the target is the
        // scheme-less string `java&#09;script:...` — not a `javascript:` scheme.
        // It never reaches an href unescaped; the HTML-escape at emit renders
        // `&` as `&amp;`. It parses as a link with a scheme-less (safe) target,
        // which is fine — the danger is only a live `javascript:` scheme, and
        // there is none here.
        let entity = parse_spans("[x](java&#09;script:alert(1))");
        assert!(
            entity.iter().any(|s| matches!(s, Span::Link(..))),
            "entity form is scheme-less inert text, a safe relative target: {entity:?}"
        );
    }

    #[test]
    fn spans_image_alt_and_url() {
        assert_eq!(
            parse_spans("![alt](img.png)"),
            vec![Span::Image("alt".to_owned(), href("img.png"))]
        );
    }

    #[test]
    fn spans_unmatched_link_and_bold_stay_plain() {
        // A lone `[` with no closing `](url)` never becomes a link; an
        // unbalanced `**` with no closing `**` never becomes bold. These match
        // `Ipe.Markdown`'s fail-closed degradation: malformed markup renders as
        // text, never a broken span. (An unmatched SINGLE `*` is a documented
        // exception below — the SSOT parser italicises to end-of-line.)
        let spans = parse_spans("[x](y and no close");
        assert!(
            !spans.iter().any(|s| matches!(s, Span::Link(..))),
            "lone bracket must not be a link: {spans:?}"
        );
        let bold = parse_spans("a **b with no close");
        assert!(
            bold.iter().any(|s| matches!(s, Span::Bold(_))),
            "an unclosed ** consumes to end as Bold in the SSOT parser: {bold:?}"
        );
    }

    #[test]
    fn spans_unmatched_single_star_italicises_to_end() {
        // `Ipe.Markdown`'s `spanLoop`: a `*` with no closing `*` yields a
        // non-empty `takeBetween`, so it becomes an ItalicSpan spanning the
        // rest of the line. Pinned here so the port's fidelity to the SSOT
        // (not to any other renderer) is explicit — the parity gate asserts the
        // same tree against an `ipe` run.
        assert_eq!(
            parse_spans("a * b"),
            vec![Span::Plain("a ".to_owned()), Span::Italic(" b".to_owned())]
        );
    }

    #[test]
    fn spans_hard_break_on_trailing_double_space() {
        let spans = parse_spans("text  ");
        assert!(spans.contains(&Span::HardBreak), "{spans:?}");
    }

    #[test]
    fn bracket_run_is_linear() {
        // A run of unclosable `[` (or `![`) costs one link scan in total: a
        // rescan per bracket is quadratic and blows this deadline by orders of
        // magnitude.
        for line in ["[".repeat(100_000), "![".repeat(50_000)] {
            let started = std::time::Instant::now();
            let spans = parse_spans(&line);
            let elapsed = started.elapsed();
            assert!(
                elapsed < std::time::Duration::from_secs(2),
                "bracket run took {elapsed:?}"
            );
            assert_eq!(spans, vec![Span::Plain(line)]);
        }
    }

    #[test]
    fn link_miss_memo_keeps_later_links() {
        // A miss proves only the brackets it covers: a link after them parses.
        assert_eq!(
            parse_spans("[a]x [b](c)"),
            vec![
                Span::Plain("[a]x ".to_owned()),
                Span::Link("b".to_owned(), href("c"))
            ]
        );
        assert_eq!(
            parse_spans("[x](javascript:1) [y](z)"),
            vec![
                Span::Plain("[x](javascript:1) ".to_owned()),
                Span::Link("y".to_owned(), href("z"))
            ]
        );
        assert_eq!(
            parse_spans("[a [b](c)"),
            vec![Span::Link("a [b".to_owned(), href("c"))]
        );
        assert_eq!(
            parse_spans("[a](b [c] ![d]"),
            vec![Span::Plain("[a](b [c] ![d]".to_owned())]
        );
    }

    #[test]
    fn multibyte_header_slices_by_codepoint() {
        // `café` is 4 codepoints; the `# ` marker strip must be codepoint-exact.
        assert_eq!(
            parse_blocks("# café ☕"),
            vec![Block::Header(HeadingLevel::H1, "café ☕".to_owned())]
        );
    }
}
