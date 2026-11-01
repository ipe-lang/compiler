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
    /// The path does not start with `examples/`.
    OutsideExamples,
}

/// A fenced excerpt's declared path: relative, `..`-free, and under `examples/`.
///
/// The only constructor is [`ExampleRel::parse`], which refuses a traversal or
/// an absolute path at the text boundary. A caller that resolves the path
/// against the repository root (e.g. `contained_path::ContainedRelPath`)
/// proves filesystem containment too, so the escape this type closes is
/// refused a second, independent time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExampleRel(PathBuf);

impl ExampleRel {
    /// Parse a declared excerpt path.
    ///
    /// # Errors
    ///
    /// [`ExcerptPathError::Missing`] for an empty path, [`ExcerptPathError::Absolute`]
    /// for an absolute one, [`ExcerptPathError::ParentTraversal`] for one holding a
    /// `..` segment, and [`ExcerptPathError::OutsideExamples`] for one that does not
    /// start with `examples/`.
    pub fn parse(raw: &str) -> Result<Self, ExcerptPathError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ExcerptPathError::Missing);
        }
        if Path::new(trimmed).is_absolute() {
            return Err(ExcerptPathError::Absolute);
        }
        if trimmed.split('/').any(|segment| segment == "..") {
            return Err(ExcerptPathError::ParentTraversal);
        }
        if !trimmed.starts_with("examples/") {
            return Err(ExcerptPathError::OutsideExamples);
        }
        Ok(Self(PathBuf::from(trimmed)))
    }

    /// The declared path, relative to the repository root.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
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

struct Open {
    line: usize,
    indent: usize,
    ch: char,
    len: usize,
    kind: Option<Result<Kind, FenceError>>,
    body: Vec<String>,
}

/// Every fenced `ipe` block, bare fence, or free-standing indented block on
/// `text`, in page order, or its refusal.
///
/// A fence with no info string, and a four-space indented block outside a
/// list/table/blockquote, are both classified ([`Kind::Unlabelled`] /
/// [`Kind::Indented`]) rather than skipped, so a served page cannot hide
/// uncompiled Ipê in either shape.
#[must_use]
pub fn scan(text: &str, page: Page) -> Vec<Result<Block, Refusal>> {
    let mut items = Vec::new();
    let mut open: Option<Open> = None;
    let mut indented: Option<(usize, Vec<String>)> = None;
    let mut prev_was_container = false;

    for (index, line) in text.lines().enumerate() {
        if let Some(fence) = open.as_mut() {
            if !closes(line, fence.ch, fence.len) {
                fence.body.push(dedent(line, fence.indent));
                continue;
            }
            let Some(Open {
                line,
                kind: Some(kind),
                body,
                ..
            }) = open.take()
            else {
                continue;
            };
            items.push(match kind {
                Ok(kind) => Ok(Block {
                    line,
                    kind,
                    body: body.join("\n"),
                }),
                Err(error) => Err(Refusal { line, error }),
            });
            continue;
        }

        if let Some(o) = opening(line) {
            if let Some((start, rows)) = indented.take() {
                items.push(Ok(Block {
                    line: start,
                    kind: Kind::Indented,
                    body: rows.join("\n"),
                }));
            }
            open = Some(Open {
                line: index + 1,
                indent: o.indent,
                ch: o.ch,
                len: o.len,
                kind: ipe_kind(o.info, page),
                body: Vec::new(),
            });
            prev_was_container = false;
            continue;
        }

        let line_indented = line.starts_with("    ");
        let is_blank = line.trim().is_empty();

        if let Some((start, mut rows)) = indented.take() {
            if line_indented {
                rows.push(dedent(line, 4));
                indented = Some((start, rows));
            } else if is_blank {
                rows.push(String::new());
                indented = Some((start, rows));
            } else {
                items.push(Ok(Block {
                    line: start,
                    kind: Kind::Indented,
                    body: rows.join("\n"),
                }));
                prev_was_container = is_container_line(line);
            }
            continue;
        }

        if line_indented && !prev_was_container {
            indented = Some((index + 1, vec![dedent(line, 4)]));
            continue;
        }

        if !is_blank {
            prev_was_container = is_container_line(line);
        }
    }

    if let Some(fence) = open {
        items.push(Err(Refusal {
            line: fence.line,
            error: FenceError::Unclosed,
        }));
    }
    if let Some((start, rows)) = indented {
        items.push(Ok(Block {
            line: start,
            kind: Kind::Indented,
            body: rows.join("\n"),
        }));
    }
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
            items[0],
            Err(Refusal {
                line: 1,
                error: FenceError::UnknownInfo("ipe ipe:eror".to_owned()),
            })
        );

        let text = "```ipe:error\nx\n```\n";
        let items = scan(text, Page::Doc);
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0],
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
            items[0],
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
            items[0],
            Err(Refusal {
                line: 1,
                error: FenceError::Unclosed,
            })
        );
    }

    #[test]
    fn four_backtick_fence_closes_only_at_four() {
        let text = "````ipe\n```ipe\nx\n```\n````\n";
        let items = scan(text, Page::Doc);
        assert_eq!(items.len(), 1);
        let block = items[0].as_ref().expect("a check block");
        assert_eq!(block.kind, Kind::Check);
        assert_eq!(block.body, "```ipe\nx\n```");
    }

    #[test]
    fn error_code_on_explain_page_is_refused() {
        let text = "```ipe ipe:error IPE-N0001\nx\n```\n";
        let items = scan(text, Page::Explain(ipe_diagnostics::IPE_N0001));
        assert_eq!(
            items[0],
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
            items[0],
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
            items[0],
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
        let block = items[0].as_ref().expect("an error block");
        assert_eq!(block.kind, Kind::Error(code));
    }

    #[test]
    fn an_untagged_fence_is_classified_as_unlabelled() {
        let text = "```\nx = 1\n```\n";
        let items = scan(text, Page::Doc);
        assert_eq!(items.len(), 1);
        let block = items[0].as_ref().expect("an unlabelled block");
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
        let block = items[0].as_ref().expect("an indented block");
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
        let block = items[0].as_ref().expect("an excerpt block");
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
            items[0],
            Err(Refusal {
                line: 1,
                error: FenceError::ExcerptPath(ExcerptPathError::OutsideExamples),
            })
        );

        let text = "```ipe ipe:excerpt examples/../secrets\nx\n```\n";
        let items = scan(text, Page::Doc);
        assert_eq!(
            items[0],
            Err(Refusal {
                line: 1,
                error: FenceError::ExcerptPath(ExcerptPathError::ParentTraversal),
            })
        );

        let text = "```ipe ipe:excerpt /etc/passwd\nx\n```\n";
        let items = scan(text, Page::Doc);
        assert_eq!(
            items[0],
            Err(Refusal {
                line: 1,
                error: FenceError::ExcerptPath(ExcerptPathError::Absolute),
            })
        );

        let text = "```ipe ipe:excerpt\nx\n```\n";
        let items = scan(text, Page::Doc);
        assert_eq!(
            items[0],
            Err(Refusal {
                line: 1,
                error: FenceError::ExcerptPath(ExcerptPathError::Missing),
            })
        );
    }
}
