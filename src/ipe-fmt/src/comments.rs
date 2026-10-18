//! Source comments as typed runs, and the one emitter that prints them.
//!
//! A comment's text never leaves this module except through [`emit`], which
//! prints a whole [`Run`] in source order with its gaps, so no print site can
//! drop, split or re-space a run.

use std::fmt;
use std::fmt::Write as _;

use super::Pad;

/// The whitespace between two comments, or between a comment and its anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Gap {
    /// On the next line, or on the same line.
    Adjacent,
    /// Separated by at least one blank line.
    Blank,
}

impl Gap {
    /// The gap that the whitespace `ws` makes.
    fn of(ws: &str) -> Self {
        if ws.bytes().filter(|&b| b == b'\n').nth(1).is_some() {
            Self::Blank
        } else {
            Self::Adjacent
        }
    }
}

/// A source comment, with where it attaches and the gaps around it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Comment {
    /// The comment text verbatim, delimiters included, trailing whitespace
    /// excluded.
    text: String,
    /// The offset of the comment's first byte in its source.
    start: usize,
    /// The start offset of the first code token after it that can begin a
    /// printed node, or `None` past the last token.
    anchor: Option<usize>,
    /// The gap after the previous comment; `Adjacent` when code or nothing
    /// precedes it.
    gap_before: Gap,
    /// The gap after it, up to the next token.
    gap_to_anchor: Gap,
    /// Its index among the source's comments.
    ord: usize,
}

impl Comment {
    /// Where the comment attaches.
    pub const fn anchor(&self) -> Option<usize> {
        self.anchor
    }

    /// The gap after the previous comment.
    pub const fn gap_before(&self) -> Gap {
        self.gap_before
    }

    /// The gap after the comment, up to the next token.
    pub const fn gap_to_anchor(&self) -> Gap {
        self.gap_to_anchor
    }

    /// The value the guards compare the comment by.
    pub fn key(&self) -> CommentKey<'_> {
        CommentKey(&self.text)
    }

    /// The comment text, for a test to inspect.
    #[cfg(test)]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// An opaque comparison key for one comment's text.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommentKey<'a>(&'a str);

impl fmt::Debug for CommentKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CommentKey({} bytes)", self.0.len())
    }
}

/// The comments whose byte ranges are `ranges` in `src`, in source order,
/// each attached at `anchor_after` its end.
pub fn scan(
    src: &str,
    ranges: Vec<(usize, usize)>,
    anchor_after: impl Fn(usize) -> Option<usize>,
) -> Vec<Comment> {
    let mut prev_end: Option<usize> = None;
    ranges
        .into_iter()
        .enumerate()
        .map(|(ord, (lo, hi))| {
            let gap_before = prev_end
                .and_then(|end| src.get(end..lo))
                .filter(|ws| ws.chars().all(char::is_whitespace))
                .map_or(Gap::Adjacent, Gap::of);
            let after = src.get(hi..).unwrap_or_default();
            let ws_len = after.len().saturating_sub(after.trim_start().len());
            prev_end = Some(hi);
            Comment {
                text: src.get(lo..hi).unwrap_or_default().trim_end().to_owned(),
                start: lo,
                anchor: anchor_after(hi),
                gap_before,
                gap_to_anchor: Gap::of(after.get(..ws_len).unwrap_or_default()),
                ord,
            }
        })
        .collect()
}

/// The comment texts, sorted: the multiset the comment guard compares.
pub fn comment_multiset(comments: &[Comment]) -> Vec<CommentKey<'_>> {
    let mut keys: Vec<CommentKey<'_>> = comments.iter().map(Comment::key).collect();
    keys.sort_unstable();
    keys
}

/// Comments a print site places together, in source order; empty prints
/// nothing.
#[derive(Clone, Default)]
pub struct Run<'a>(Vec<&'a Comment>);

impl<'a> Run<'a> {
    /// Whether the run holds no comment.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The offset of the run's first comment.
    pub fn start(&self) -> Option<usize> {
        self.0.iter().map(|c| c.start).min()
    }

    /// This run and `other`, in source order.
    #[must_use]
    pub fn merge(mut self, other: Self) -> Self {
        self.0.extend(other.0);
        self.0.sort_by_key(|c| c.start);
        self
    }

    /// The run without the comments anchored at one of `anchors`.
    #[must_use]
    pub fn without_anchors(self, anchors: &[usize]) -> Self {
        Self(
            self.0
                .into_iter()
                .filter(|c| c.anchor.is_none_or(|a| !anchors.contains(&a)))
                .collect(),
        )
    }
}

/// The comments of `list` anchored at a token starting in `[lo, hi)`.
pub fn anchored_in(list: &[Comment], lo: usize, hi: usize) -> Run<'_> {
    let key = |c: &Comment| c.anchor.unwrap_or(usize::MAX);
    let first = list.partition_point(|c| key(c) < lo);
    let end = list.partition_point(|c| key(c) < hi);
    Run(list
        .get(first..end.max(first))
        .unwrap_or_default()
        .iter()
        .collect())
}

/// The comments of `list` after its last token.
pub fn trailing(list: &[Comment]) -> Run<'_> {
    let first = list.partition_point(|c| c.anchor.is_some());
    Run(list.get(first..).unwrap_or_default().iter().collect())
}

/// The comments of `owned` that `rendered` does not print, in source order.
///
/// `rendered` is one owner's printing; the comments it prints are matched by
/// text, the multiset the comment guard compares. A rendering that does not
/// lex places nothing here: the guard then refuses the whole output.
pub fn unplaced<'a>(owned: Run<'a>, rendered: &str) -> Run<'a> {
    if owned.is_empty() {
        return owned;
    }
    let Some(printed) = super::scan_trivia(rendered) else {
        return Run::default();
    };
    let mut printed = comment_multiset(&printed.comments);
    let mut missing = Vec::new();
    for c in owned.0 {
        match printed.binary_search(&c.key()) {
            Ok(i) => {
                printed.remove(i);
            }
            Err(_) => missing.push(c),
        }
    }
    Run(missing)
}

/// What [`emit`] writes after a run's last comment.
#[derive(Clone, Copy)]
pub enum Tail {
    /// A newline and the run's pad: the node follows on the next line.
    Glued,
    /// A newline, plus `blank_lines` more when the source had a blank line
    /// before the anchor; for a top-level run at the left margin.
    Source { blank_lines: usize },
    /// A newline, plus `blank_lines` more; for a run moved above a head at the
    /// left margin, which never lands next to it.
    Blank { blank_lines: usize },
}

/// Write `run` at `pad`, its first comment where `out` ends, then `tail`.
///
/// Consecutive source comments keep a blank line the source had between them;
/// an empty run writes nothing.
pub fn emit(out: &mut String, run: &Run<'_>, pad: Pad<'_>, tail: Tail) {
    let mut prev: Option<&Comment> = None;
    for &c in &run.0 {
        if let Some(p) = prev {
            out.push('\n');
            if c.ord == p.ord.saturating_add(1) && c.gap_before == Gap::Blank {
                out.push('\n');
            }
            let _ = write!(out, "{pad}");
        }
        out.push_str(&c.text);
        prev = Some(c);
    }
    let Some(last) = prev else { return };
    out.push('\n');
    let blank_lines = match tail {
        Tail::Glued => {
            let _ = write!(out, "{pad}");
            0
        }
        Tail::Source { blank_lines } if last.gap_to_anchor == Gap::Blank => blank_lines,
        Tail::Source { .. } => 0,
        Tail::Blank { blank_lines } => blank_lines,
    };
    for _ in 0..blank_lines {
        out.push('\n');
    }
}
