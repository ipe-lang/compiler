//! A line scanner for the fenced `ipe` blocks of a served documentation page.
//!
//! Every fence on a page is read, whatever its language, so a fence's own
//! length decides where it closes and an `ipe` fence nested inside a longer
//! fence stays body text. An `ipe` fence's info string is one of four forms
//! (check, error, skip, excerpt); anything else is a typed refusal, never
//! prose. A served page must also fence every code sample: a bare fence with
//! no info string, and a four-space indented block outside a list, table, or
//! blockquote, are both classified ([`Kind::Unlabelled`] / [`Kind::Indented`])
//! rather than silently skipped, so Ipê cannot hide uncompiled in either shape.

use std::path::{Path, PathBuf};

use ipe_diagnostics::{ALL_CODES, Code};

/// The page a block sits on, which fixes what its error blocks must name.
#[derive(Clone, Copy, Debug)]
pub enum Page {
    /// An explain page: its error blocks are refused with the page's own code.
    Explain(Code),
    /// A `docs/` page: each error block names the code it is refused with.
    Doc,
}

/// Why a block is skipped rather than compiled; never empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reason(String);

/// Why a declared excerpt path was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExcerptPathError {
    /// `ipe:excerpt` named no path at all.
    Missing,
    /// The path holds a `..` segment.
    ParentTraversal,
    /// The path is absolute.
    Absolute,
    /// The path holds a byte no portable repository path carries: a
    /// backslash (a second separator on Windows), a `:` (a drive or stream
    /// prefix), or a NUL.
    ForeignByte,
    /// The path holds an empty or `.` segment (`examples//x`, `examples/./x`,
    /// a trailing `/`): every segment must name one directory entry.
    EmptySegment,
    /// The path's first segment is not `examples`.
    OutsideExamples,
    /// The path is `examples` itself, naming no file under it.
    NoFile,
}

/// The one directory an excerpt may quote from, as its path's first segment.
const EXAMPLES_DIR: &str = "examples";

/// A fenced excerpt's declared path: relative, `..`-free, and under `examples/`.
///
/// The only constructor is [`ExampleRel::parse`], which refuses a traversal,
/// an absolute or drive-prefixed path, and an empty or `.` segment at the text
/// boundary. A caller resolves [`ExampleRel::within_examples`] against the
/// `examples/` directory itself (e.g. through
/// `contained_path::ContainedRelPath`), which proves filesystem containment
/// under `examples/` — a symlink out of it included — so the escape this type
/// closes is refused a second, independent time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExampleRel {
    /// The declared path, `examples/` included.
    declared: PathBuf,
    /// The declared path with its leading `examples/` segment removed.
    within: String,
}

impl ExampleRel {
    /// Parse a declared excerpt path.
    ///
    /// # Errors
    ///
    /// [`ExcerptPathError::Missing`] for an empty path,
    /// [`ExcerptPathError::Absolute`] for an absolute one,
    /// [`ExcerptPathError::ForeignByte`] for one holding a backslash, `:` or
    /// NUL, [`ExcerptPathError::ParentTraversal`] for one holding a `..`
    /// segment, [`ExcerptPathError::EmptySegment`] for an empty or `.`
    /// segment, [`ExcerptPathError::OutsideExamples`] for one whose first
    /// segment is not `examples`, and [`ExcerptPathError::NoFile`] for
    /// `examples` alone.
    pub fn parse(raw: &str) -> Result<Self, ExcerptPathError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ExcerptPathError::Missing);
        }
        if trimmed.starts_with('/') || Path::new(trimmed).is_absolute() {
            return Err(ExcerptPathError::Absolute);
        }
        if trimmed.contains(['\\', ':', '\0']) {
            return Err(ExcerptPathError::ForeignByte);
        }
        let segments: Vec<&str> = trimmed.split('/').collect();
        if segments.contains(&"..") {
            return Err(ExcerptPathError::ParentTraversal);
        }
        if segments.iter().any(|s| s.is_empty() || *s == ".") {
            return Err(ExcerptPathError::EmptySegment);
        }
        match segments.split_first() {
            Some((&EXAMPLES_DIR, [])) => Err(ExcerptPathError::NoFile),
            Some((&EXAMPLES_DIR, within)) => Ok(Self {
                declared: PathBuf::from(trimmed),
                within: within.join("/"),
            }),
            _ => Err(ExcerptPathError::OutsideExamples),
        }
    }

    /// The declared path, relative to the repository root.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.declared
    }

    /// The declared path relative to the `examples/` directory: the form to
    /// resolve against that directory, so containment is proven under it.
    #[must_use]
    pub fn within_examples(&self) -> &str {
        &self.within
    }
}

/// Why an excerpt's body does not stand for its named file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExcerptMiss {
    /// The body holds no non-blank line, so it would occur in any file.
    Empty,
    /// No run of whole lines of the file equals the body, after dedent.
    Absent,
}

/// Whether `body` occurs in `file` as a run of whole lines, each side
/// dedented by its own least indent.
///
/// Whole lines, so a one-word excerpt cannot match mid-line; dedented, so an
/// excerpt of a nested `let` or `case` arm may be quoted flush-left. A blank
/// body line matches a blank file line only.
///
/// # Errors
///
/// [`ExcerptMiss::Empty`] for a body with no non-blank line, and
/// [`ExcerptMiss::Absent`] when no run of the file matches it.
pub fn excerpt_occurs(body: &str, file: &str) -> Result<(), ExcerptMiss> {
    let all: Vec<&str> = body.lines().collect();
    let want = trim_blank_edges(&all);
    if want.is_empty() {
        return Err(ExcerptMiss::Empty);
    }
    let want = dedented(want);
    let lines: Vec<&str> = file.lines().collect();
    if lines.windows(want.len()).any(|run| dedented(run) == want) {
        Ok(())
    } else {
        Err(ExcerptMiss::Absent)
    }
}

/// `lines` without its leading and trailing blank lines.
fn trim_blank_edges<'a, 'b>(lines: &'b [&'a str]) -> &'b [&'a str] {
    let blank = |l: &str| l.trim().is_empty();
    let start = lines.iter().position(|l| !blank(l)).unwrap_or(lines.len());
    let end = lines
        .iter()
        .rposition(|l| !blank(l))
        .map_or(start, |i| i.saturating_add(1));
    lines.get(start..end).unwrap_or(&[])
}

/// `lines` with their least leading-space run removed, trailing space
/// trimmed, and blank lines empty.
fn dedented(lines: &[&str]) -> Vec<String> {
    let indent = lines
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.len() - l.trim_start_matches(' ').len())
        .min()
        .unwrap_or(0);
    lines
        .iter()
        .map(|l| {
            if l.trim().is_empty() {
                String::new()
            } else {
                l.get(indent..).unwrap_or(l).trim_end().to_owned()
            }
        })
        .collect()
}

/// What a fenced or indented block on a page declares it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An `ipe` fence that must compile as-is.
    Check,
    /// An `ipe ipe:error <CODE>` fence that must be refused with `CODE`.
    Error(Code),
    /// An `ipe ipe:skip <reason>` fence, never compiled.
    Skip(Reason),
    /// A fence with no info string at all.
    Unlabelled,
    /// A four-space indented block outside a list, table, or blockquote.
    Indented,
    /// An `ipe ipe:excerpt <path>` fence that must match its named file verbatim.
    Excerpt(ExampleRel),
}

/// A classified block, ready to be judged against what it declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// The 1-based source line the block starts on.
    pub line: usize,
    /// What the block declares.
    pub kind: Kind,
    /// The block's body, dedented, fence markers stripped.
    pub body: String,
}

/// Why a block's own declaration is malformed, independent of judging it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FenceError {
    /// An `ipe`-prefixed info string that is none of the known forms.
    UnknownInfo(String),
    /// A fence opened but the text ended before it closed.
    Unclosed,
    /// `ipe:skip` named no reason.
    SkipWithoutReason,
    /// An error block on an explain page named its own code redundantly.
    ErrorCodeOnExplainPage,
    /// An error block on a `docs/` page named no code.
    ErrorCodeMissing,
    /// An error block named a code the registry does not carry.
    ErrorCodeUnknown(String),
    /// `ipe:excerpt` named a path [`ExampleRel::parse`] refuses.
    ExcerptPath(ExcerptPathError),
    /// The served-page renderer reads this line's fence differently: it opens
    /// and closes a code block exactly at a line starting with ```` ``` ```` in
    /// column 0, whatever its length or info string, so an indented, tilde, or
    /// backtick-bearing fence, or a closer the two disagree on, would be
    /// judged as one block and served as another.
    RendererDisagrees,
}

/// A block whose own declaration is malformed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The 1-based source line the block starts on.
    pub line: usize,
    /// Why the declaration is malformed.
    pub error: FenceError,
}

/// The registered code whose wire form is `wire`.
#[must_use]
pub fn registered(wire: &str) -> Option<Code> {
    ALL_CODES.iter().copied().find(|c| c.as_str() == wire)
}

/// An opening fence: its indent, fence character, run length and info string.
struct Opening<'a> {
    indent: usize,
    ch: char,
    len: usize,
    info: &'a str,
}

/// Read `line` as an opening fence of three or more backticks or tildes.
fn opening(line: &str) -> Option<Opening<'_>> {
    let trimmed = line.trim_start_matches(' ');
    let indent = line.len() - trimmed.len();
    let ch = trimmed.chars().next().filter(|c| *c == '`' || *c == '~')?;
    let len = trimmed.chars().take_while(|c| *c == ch).count();
    if len < 3 {
        return None;
    }
    let info = trimmed.get(len..)?.trim();
    // A backtick run followed by more backticks on the line is inline code.
    if ch == '`' && info.contains('`') {
        return None;
    }
    Some(Opening {
        indent,
        ch,
        len,
        info,
    })
}

/// Whether `line` closes a fence of `len` `ch` characters.
fn closes(line: &str, ch: char, len: usize) -> bool {
    let trimmed = line.trim_start_matches(' ');
    let run = trimmed.chars().take_while(|c| *c == ch).count();
    run >= len
        && trimmed
            .get(run..)
            .is_some_and(|rest| rest.trim().is_empty())
}

/// Strip up to `indent` leading spaces from `line`.
fn dedent(line: &str, indent: usize) -> String {
    let spaces = line.chars().take(indent).take_while(|c| *c == ' ').count();
    line.get(spaces..).unwrap_or(line).to_owned()
}

/// Whether a line opens or continues a list / table / blockquote — a context
/// where an indented follow-on line is a continuation, not a code block.
fn is_container_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("- ")
        || t.starts_with("* ")
        || t.starts_with("+ ")
        || t.starts_with('|')
        || t.starts_with("> ")
        || t == ">"
        || t.split_once(". ")
            .is_some_and(|(n, _)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

fn classify<'a>(
    info: &str,
    mut words: impl Iterator<Item = &'a str>,
    page: Page,
) -> Result<Kind, FenceError> {
    let unknown = || FenceError::UnknownInfo(info.to_owned());
    match words.next() {
        None => Ok(Kind::Check),
        Some("ipe:error") => {
            let named = words.next();
            if words.next().is_some() {
                return Err(unknown());
            }
            match (page, named) {
                (Page::Explain(own), None) => Ok(Kind::Error(own)),
                (Page::Explain(_), Some(_)) => Err(FenceError::ErrorCodeOnExplainPage),
                (Page::Doc, None) => Err(FenceError::ErrorCodeMissing),
                (Page::Doc, Some(wire)) => registered(wire)
                    .map(Kind::Error)
                    .ok_or_else(|| FenceError::ErrorCodeUnknown(wire.to_owned())),
            }
        }
        Some("ipe:skip") => {
            let reason = words.collect::<Vec<_>>().join(" ");
            if reason.is_empty() {
                Err(FenceError::SkipWithoutReason)
            } else {
                Ok(Kind::Skip(Reason(reason)))
            }
        }
        Some("ipe:excerpt") => {
            let raw = words.collect::<Vec<_>>().join(" ");
            ExampleRel::parse(&raw)
                .map(Kind::Excerpt)
                .map_err(FenceError::ExcerptPath)
        }
        Some(_) => Err(unknown()),
    }
}

fn ipe_kind(info: &str, page: Page) -> Option<Result<Kind, FenceError>> {
    let mut words = info.split_whitespace();
    let Some(lang) = words.next() else {
        return Some(Ok(Kind::Unlabelled));
    };
    if lang == "ipe" {
        Some(classify(info, words, page))
    } else if lang.starts_with("ipe") {
        Some(Err(FenceError::UnknownInfo(info.to_owned())))
    } else {
        None
    }
}

/// Whether the served-page renderer (`ipe_docs::markdown::parse`) opens or
/// closes a code block at `line`: exactly a column-0 ```` ``` ```` run, of any
/// length, with any info string.
fn renderer_fence(line: &str) -> bool {
    line.starts_with("```")
}

/// Whether `line` opens a four-space (or tab) indented code block when it is
/// not a container's continuation.
fn is_indented(line: &str) -> bool {
    line.starts_with("    ") || line.starts_with('\t')
}

/// `line` with its one indent marker (a tab or four spaces) removed.
fn strip_indent_marker(line: &str) -> String {
    line.strip_prefix('\t')
        .unwrap_or_else(|| line.get(4..).unwrap_or(""))
        .to_owned()
}

/// A fence being read.
struct Open {
    line: usize,
    indent: usize,
    ch: char,
    len: usize,
    /// Whether the served-page renderer opened a code block here too.
    rendered: bool,
    kind: Option<Result<Kind, FenceError>>,
    body: Vec<String>,
}

impl Open {
    /// The fence `line` (1-based `number`) opens, for the checker or the
    /// served-page renderer alike.
    fn at(line: &str, number: usize, page: Page) -> Option<Self> {
        let rendered = renderer_fence(line);
        let (indent, ch, len, kind) = match opening(line) {
            Some(o) => {
                // A fence only the checker sees hides its body from the page
                // as served; refuse one that would carry Ipê.
                let kind = match ipe_kind(o.info, page) {
                    Some(_) if !rendered => Some(Err(FenceError::RendererDisagrees)),
                    other => other,
                };
                (o.indent, o.ch, o.len, kind)
            }
            // A column-0 backtick run the renderer opens but CommonMark reads
            // as inline code (its info string holds a backtick).
            None if rendered => {
                let len = line.chars().take_while(|c| *c == '`').count();
                (0, '`', len, Some(Err(FenceError::RendererDisagrees)))
            }
            None => return None,
        };
        Some(Self {
            line: number,
            indent,
            ch,
            len,
            rendered,
            kind,
            body: Vec::new(),
        })
    }

    /// The closed fence's block or refusal, or `None` for a fence no verdict
    /// covers (a non-`ipe` info string).
    fn finish(self) -> Option<Result<Block, Refusal>> {
        let line = self.line;
        Some(match self.kind? {
            Ok(kind) => Ok(Block {
                line,
                kind,
                body: self.body.join("\n"),
            }),
            Err(error) => Err(Refusal { line, error }),
        })
    }
}

/// The indented block starting at `start` with `rows` as its body, the blank
/// rows that separated it from the next line dropped.
fn indented_block(start: usize, rows: &[String]) -> Block {
    let end = rows
        .iter()
        .rposition(|row| !row.is_empty())
        .map_or(0, |last| last.saturating_add(1));
    Block {
        line: start,
        kind: Kind::Indented,
        body: rows.get(..end).unwrap_or(rows).join("\n"),
    }
}

/// Every fenced `ipe` block, bare fence, or free-standing indented block on
/// `text`, in page order, or its refusal.
///
/// A fence with no info string, and a four-space indented block outside a
/// list/table/blockquote, are both classified ([`Kind::Unlabelled`] /
/// [`Kind::Indented`]) rather than skipped, so a served page cannot hide
/// uncompiled Ipê in either shape. A fence line the served-page renderer reads
/// differently is refused ([`FenceError::RendererDisagrees`]), so a judged
/// block is always the block `ipe doc` serves.
#[must_use]
pub fn scan(text: &str, page: Page) -> Vec<Result<Block, Refusal>> {
    let mut items = Vec::new();
    let mut open: Option<Open> = None;
    let mut indented: Option<(usize, Vec<String>)> = None;
    let mut in_container = false;

    for (index, line) in text.lines().enumerate() {
        if let Some(fence) = open.as_mut() {
            let closed = closes(line, fence.ch, fence.len);
            if renderer_fence(line) != (fence.rendered && closed) {
                items.push(Err(Refusal {
                    line: index + 1,
                    error: FenceError::RendererDisagrees,
                }));
            }
            if !closed {
                fence.body.push(dedent(line, fence.indent));
                continue;
            }
            items.extend(open.take().and_then(Open::finish));
            continue;
        }

        if let Some(fence) = Open::at(line, index + 1, page) {
            items.extend(
                indented
                    .take()
                    .map(|(start, rows)| Ok(indented_block(start, &rows))),
            );
            open = Some(fence);
            in_container = false;
            continue;
        }

        let line_indented = is_indented(line);
        let is_blank = line.trim().is_empty();

        if let Some((start, mut rows)) = indented.take() {
            if line_indented {
                rows.push(strip_indent_marker(line));
                indented = Some((start, rows));
            } else if is_blank {
                rows.push(String::new());
                indented = Some((start, rows));
            } else {
                items.push(Ok(indented_block(start, &rows)));
                in_container = is_container_line(line);
            }
            continue;
        }

        if line_indented && !in_container {
            indented = Some((index + 1, vec![strip_indent_marker(line)]));
            continue;
        }

        // A container lasts through its own indented continuation lines and
        // blank lines; a flush-left line that opens none ends it.
        if !is_blank {
            in_container =
                is_container_line(line) || (in_container && line.starts_with([' ', '\t']));
        }
    }

    if let Some(fence) = open {
        items.push(Err(Refusal {
            line: fence.line,
            error: FenceError::Unclosed,
        }));
    }
    items.extend(indented.map(|(start, rows)| Ok(indented_block(start, &rows))));
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_info_string_is_refused() {
        let text = "```ipe ipe:eror\nx\n```\n";
        let items = scan(text, Page::Doc);
        assert_eq!(items.len(), 1);
        assert_eq!(
            *items.first().expect("one item"),
            Err(Refusal {
                line: 1,
                error: FenceError::UnknownInfo("ipe ipe:eror".to_owned()),
            })
        );

        let text = "```ipe:error\nx\n```\n";
        let items = scan(text, Page::Doc);
        assert_eq!(items.len(), 1);
        assert_eq!(
            *items.first().expect("one item"),
            Err(Refusal {
                line: 1,
                error: FenceError::UnknownInfo("ipe:error".to_owned()),
            })
        );
    }

    #[test]
    fn skip_without_reason_is_refused() {
        let text = "```ipe ipe:skip\nx\n```\n";
        let items = scan(text, Page::Doc);
        assert_eq!(
            *items.first().expect("one item"),
            Err(Refusal {
                line: 1,
                error: FenceError::SkipWithoutReason,
            })
        );
    }

    #[test]
    fn unclosed_fence_is_refused() {
        let text = "```ipe\nx = 1\n";
        let items = scan(text, Page::Doc);
        assert_eq!(
            *items.first().expect("one item"),
            Err(Refusal {
                line: 1,
                error: FenceError::Unclosed,
            })
        );
    }

    #[test]
    fn four_backtick_fence_closes_only_at_four() {
        // The nested fence is indented, so the renderer reads it as body too.
        let text = "````ipe\n  ```ipe\n  x\n  ```\n````\n";
        let items = scan(text, Page::Doc);
        assert_eq!(items.len(), 1, "{items:?}");
        let block = items
            .first()
            .expect("one item")
            .as_ref()
            .expect("a check block");
        assert_eq!(block.kind, Kind::Check);
        assert_eq!(block.body, "  ```ipe\n  x\n  ```");
    }

    /// The renderer closes a code block at any column-0 ```` ``` ```` line, so a
    /// longer fence's flush-left inner fence would be served as two blocks.
    #[test]
    fn a_flush_left_fence_inside_a_longer_fence_is_refused() {
        let text = "````ipe\n```ipe\nx\n```\n````\n";
        let refused: Vec<usize> = scan(text, Page::Doc)
            .into_iter()
            .filter_map(|item| match item {
                Err(Refusal {
                    line,
                    error: FenceError::RendererDisagrees,
                }) => Some(line),
                _ => None,
            })
            .collect();
        assert_eq!(refused, vec![2, 4]);
    }

    #[test]
    fn error_code_on_explain_page_is_refused() {
        let text = "```ipe ipe:error IPE-N0001\nx\n```\n";
        let items = scan(text, Page::Explain(ipe_diagnostics::IPE_N0001));
        assert_eq!(
            *items.first().expect("one item"),
            Err(Refusal {
                line: 1,
                error: FenceError::ErrorCodeOnExplainPage,
            })
        );
    }

    #[test]
    fn unknown_error_code_is_refused() {
        let text = "```ipe ipe:error IPE-N9999\nx\n```\n";
        let items = scan(text, Page::Doc);
        assert_eq!(
            *items.first().expect("one item"),
            Err(Refusal {
                line: 1,
                error: FenceError::ErrorCodeUnknown("IPE-N9999".to_owned()),
            })
        );
    }

    #[test]
    fn error_block_on_doc_page_must_name_its_code() {
        let text = "```ipe ipe:error\nx\n```\n";
        let items = scan(text, Page::Doc);
        assert_eq!(
            *items.first().expect("one item"),
            Err(Refusal {
                line: 1,
                error: FenceError::ErrorCodeMissing,
            })
        );
    }

    #[test]
    fn explain_page_error_block_takes_the_page_code() {
        let text = "```ipe ipe:error\nx\n```\n";
        let code = ipe_diagnostics::IPE_N0001;
        let items = scan(text, Page::Explain(code));
        let block = items
            .first()
            .expect("one item")
            .as_ref()
            .expect("an error block");
        assert_eq!(block.kind, Kind::Error(code));
    }

    #[test]
    fn an_untagged_fence_is_classified_as_unlabelled() {
        let text = "```\nx = 1\n```\n";
        let items = scan(text, Page::Doc);
        assert_eq!(items.len(), 1);
        let block = items
            .first()
            .expect("one item")
            .as_ref()
            .expect("an unlabelled block");
        assert_eq!(block.kind, Kind::Unlabelled);
        assert_eq!(block.body, "x = 1");
    }

    #[test]
    fn a_non_ipe_language_fence_is_not_scanned() {
        let text = "```json\n{}\n```\n";
        let items = scan(text, Page::Doc);
        assert!(items.is_empty(), "{items:?}");
    }

    #[test]
    fn indented_block_outside_a_container_is_flagged() {
        let text = "Prose line.\n\n    x = 1\n    y = 2\n\nMore prose.\n";
        let items = scan(text, Page::Doc);
        assert_eq!(items.len(), 1, "{items:?}");
        let block = items
            .first()
            .expect("one item")
            .as_ref()
            .expect("an indented block");
        assert_eq!(block.kind, Kind::Indented);
        assert_eq!(block.line, 3);
        assert_eq!(block.body, "x = 1\ny = 2");
    }

    #[test]
    fn indented_continuation_of_a_list_item_is_not_flagged() {
        let text = "- item\n    continued\n";
        let items = scan(text, Page::Doc);
        assert!(items.is_empty(), "{items:?}");
    }

    #[test]
    fn excerpt_names_an_examples_path() {
        let text = "```ipe ipe:excerpt examples/shapes/script/Main.ipe\nx\n```\n";
        let items = scan(text, Page::Doc);
        let block = items
            .first()
            .expect("one item")
            .as_ref()
            .expect("an excerpt block");
        assert_eq!(
            block.kind,
            Kind::Excerpt(ExampleRel::parse("examples/shapes/script/Main.ipe").unwrap())
        );
    }

    #[test]
    fn an_excerpt_naming_a_path_outside_examples_is_refused() {
        let text = "```ipe ipe:excerpt src/Main.ipe\nx\n```\n";
        let items = scan(text, Page::Doc);
        assert_eq!(
            *items.first().expect("one item"),
            Err(Refusal {
                line: 1,
                error: FenceError::ExcerptPath(ExcerptPathError::OutsideExamples),
            })
        );

        let text = "```ipe ipe:excerpt examples/../secrets\nx\n```\n";
        let items = scan(text, Page::Doc);
        assert_eq!(
            *items.first().expect("one item"),
            Err(Refusal {
                line: 1,
                error: FenceError::ExcerptPath(ExcerptPathError::ParentTraversal),
            })
        );

        let text = "```ipe ipe:excerpt /etc/passwd\nx\n```\n";
        let items = scan(text, Page::Doc);
        assert_eq!(
            *items.first().expect("one item"),
            Err(Refusal {
                line: 1,
                error: FenceError::ExcerptPath(ExcerptPathError::Absolute),
            })
        );

        let text = "```ipe ipe:excerpt\nx\n```\n";
        let items = scan(text, Page::Doc);
        assert_eq!(
            *items.first().expect("one item"),
            Err(Refusal {
                line: 1,
                error: FenceError::ExcerptPath(ExcerptPathError::Missing),
            })
        );
    }

    fn renderer_refusals(text: &str) -> Vec<usize> {
        scan(text, Page::Doc)
            .into_iter()
            .filter_map(|item| match item {
                Err(Refusal {
                    line,
                    error: FenceError::RendererDisagrees,
                }) => Some(line),
                _ => None,
            })
            .collect()
    }

    /// A backtick in the info string makes `CommonMark` read inline code where
    /// the renderer opens a code block: one refusal, and the body stays body.
    #[test]
    fn a_fence_whose_info_holds_a_backtick_is_one_refusal() {
        let text = "```ipe ipe:skip the real `B` is wider\ntype T a\n    = Z\n```\n";
        let items = scan(text, Page::Doc);
        assert_eq!(
            items,
            vec![Err(Refusal {
                line: 1,
                error: FenceError::RendererDisagrees,
            })]
        );
    }

    #[test]
    fn an_ipe_fence_the_renderer_does_not_open_is_refused() {
        assert_eq!(
            renderer_refusals("Prose.\n\n  ```ipe\n  x = 1\n  ```\n"),
            vec![3]
        );
        assert_eq!(renderer_refusals("~~~ipe\nx = 1\n~~~\n"), vec![1]);
        assert_eq!(renderer_refusals("~~~\nx = 1\n~~~\n"), vec![1]);
        // A flush-left fence line inside a fence only the checker opened.
        assert_eq!(
            renderer_refusals("~~~text\n```ipe\nx\n```\n~~~\n"),
            vec![2, 4]
        );
    }

    #[test]
    fn a_non_ipe_fence_inside_a_list_item_is_not_judged() {
        let text = "1. Run:\n\n   ```sh\n   ipe dev build\n   ```\n";
        assert!(scan(text, Page::Doc).is_empty());
    }

    /// The checker's fence reading agrees with the renderer's on every shape
    /// it does not refuse: one served code block per judged fence.
    #[test]
    fn unrefused_fences_are_exactly_the_rendered_code_blocks() {
        use ipe_docs::markdown::{Block as Rendered, parse::parse_blocks};
        fn code_blocks(blocks: &[Rendered]) -> usize {
            blocks
                .iter()
                .map(|b| match b {
                    Rendered::Code(_) => 1,
                    Rendered::Blockquote(inner) => code_blocks(inner),
                    Rendered::Header(..)
                    | Rendered::Para(_)
                    | Rendered::Bullet(_)
                    | Rendered::Numbered(_)
                    | Rendered::Table(..)
                    | Rendered::Rule => 0,
                })
                .sum()
        }
        for text in [
            "```ipe\nx = 1\n```\n",
            "# H\n\n```ipe ipe:skip why\nx\n```\n\nProse.\n\n```\ny\n```\n",
            "````ipe\n  ```ipe\n  x\n  ```\n````\n",
            "- item\n\n```ipe\nx = 1\n```\n",
        ] {
            let items = scan(text, Page::Doc);
            assert!(
                items.iter().all(Result::is_ok),
                "{text:?} is refused: {items:?}"
            );
            assert_eq!(
                items.len(),
                code_blocks(&parse_blocks(text)),
                "{text:?}: judged fences and served code blocks differ"
            );
        }
    }

    /// A list item's own indented continuation lines keep the list open: the
    /// four-space line after them is still list content, not a code block.
    #[test]
    fn a_list_items_wrapped_lines_keep_its_continuation_open() {
        let text = "   - it generates a key at\n     `~/.config/ipe/key` (the public half\n     `key.pub`);\n";
        assert!(scan(text, Page::Doc).is_empty());
        let text = "1. item\n   continued\n\n       more of the item\n";
        assert!(scan(text, Page::Doc).is_empty());
    }

    #[test]
    fn a_flush_left_paragraph_ends_the_list_context() {
        let text = "- item\n\nProse.\n\n    x = 1\n";
        let items = scan(text, Page::Doc);
        assert_eq!(items.len(), 1, "{items:?}");
        assert_eq!(
            items.first().expect("one item").as_ref().map(|b| &b.kind),
            Ok(&Kind::Indented)
        );
    }

    #[test]
    fn a_tab_indented_block_is_flagged() {
        let text = "Prose.\n\n\tx = 1\n";
        let items = scan(text, Page::Doc);
        assert_eq!(items.len(), 1, "{items:?}");
        let block = items
            .first()
            .expect("one item")
            .as_ref()
            .expect("an indented block");
        assert_eq!(block.kind, Kind::Indented);
        assert_eq!(block.body, "x = 1");
    }

    #[test]
    fn crlf_lines_scan_as_lf_lines() {
        let text = "```ipe\r\nx = 1\r\n```\r\n";
        let items = scan(text, Page::Doc);
        assert_eq!(items.len(), 1, "{items:?}");
        assert_eq!(
            items
                .first()
                .expect("one item")
                .as_ref()
                .map(|b| b.body.as_str()),
            Ok("x = 1")
        );
    }

    #[test]
    fn an_excerpt_path_with_a_foreign_byte_or_empty_segment_is_refused() {
        for (raw, want) in [
            ("examples\\..\\..\\etc", ExcerptPathError::ForeignByte),
            ("C:/examples/x.ipe", ExcerptPathError::ForeignByte),
            ("examples/a:b", ExcerptPathError::ForeignByte),
            ("examples/x\0.ipe", ExcerptPathError::ForeignByte),
            ("examples//x.ipe", ExcerptPathError::EmptySegment),
            ("examples/./x.ipe", ExcerptPathError::EmptySegment),
            ("examples/x/", ExcerptPathError::EmptySegment),
            ("./examples/x.ipe", ExcerptPathError::EmptySegment),
            ("examplesX/x.ipe", ExcerptPathError::OutsideExamples),
            ("Examples/x.ipe", ExcerptPathError::OutsideExamples),
            ("examples", ExcerptPathError::NoFile),
            ("examples/a/../../src", ExcerptPathError::ParentTraversal),
            ("//host/share", ExcerptPathError::Absolute),
        ] {
            assert_eq!(ExampleRel::parse(raw), Err(want), "{raw:?}");
        }
        let rel = ExampleRel::parse("examples/wasm/counter/src/Main.ipe").expect("accepted");
        assert_eq!(rel.within_examples(), "wasm/counter/src/Main.ipe");
    }

    #[test]
    fn an_empty_excerpt_never_matches() {
        assert_eq!(excerpt_occurs("", "x = 1\n"), Err(ExcerptMiss::Empty));
        assert_eq!(
            excerpt_occurs("\n   \n", "x = 1\n"),
            Err(ExcerptMiss::Empty)
        );
    }

    #[test]
    fn an_excerpt_matches_whole_lines_only() {
        let file = "main =\n    let\n        n = 1\n    in\n    n\n";
        assert_eq!(excerpt_occurs("n = 1", file), Ok(()));
        assert_eq!(excerpt_occurs("let\n    n = 1\nin", file), Ok(()));
        // A fragment of a line is not an excerpt of it.
        assert_eq!(excerpt_occurs("ma", file), Err(ExcerptMiss::Absent));
        assert_eq!(excerpt_occurs("n = 2", file), Err(ExcerptMiss::Absent));
        // Relative indentation is part of the excerpt.
        assert_eq!(excerpt_occurs("let\nn = 1", file), Err(ExcerptMiss::Absent));
    }
}
