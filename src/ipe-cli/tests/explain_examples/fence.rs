//! A line scanner for the fenced `ipe` blocks of an explain or doc page.
//!
//! Every fence on a page is read, whatever its language, so a fence's own
//! length decides where it closes and an `ipe` fence nested inside a longer
//! fence stays body text. An `ipe` fence's info string is one of three forms
//! (check, error, skip); anything else is a typed refusal, never prose.

use ipe_diagnostics::{ALL_CODES, Code};

/// The page a block sits on, which fixes what its error blocks must name.
#[derive(Clone, Copy, Debug)]
pub enum Page {
    /// An explain page: its error blocks are refused with the page's own code.
    Explain(Code),
    /// A `docs/` page: each error block names the code it is refused with.
    Doc,
}

/// Why a block is not compiled; never empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reason(String);

/// What a block's info string says about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// ` ```ipe ` — the program must be accepted.
    Check,
    /// ` ```ipe ipe:error ` — the program must be refused with this code.
    Error(Code),
    /// ` ```ipe ipe:skip <reason> ` — the program is not compiled.
    Skip(Reason),
}

/// One fenced `ipe` block.
#[derive(Clone, Debug)]
pub struct Block {
    /// The 1-based line of the opening fence.
    pub line: usize,
    /// What the block must do.
    pub kind: Kind,
    /// The text between the fences, dedented by the opening fence's indent.
    pub body: String,
}

/// Why a fence was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FenceError {
    /// An `ipe` info string that is none of the three forms.
    UnknownInfo(String),
    /// A fence that never closes.
    Unclosed,
    /// An `ipe:skip` with no reason.
    SkipWithoutReason,
    /// An `ipe:error` on an explain page naming a code: the page's own code is
    /// implied, so a second one is a conflict.
    ErrorCodeOnExplainPage,
    /// An `ipe:error` on a `docs/` page naming no code.
    ErrorCodeMissing,
    /// An `ipe:error` naming a code the registry does not hold.
    ErrorCodeUnknown(String),
}

/// A refused fence and the 1-based line it opens on.
#[derive(Clone, Debug)]
pub struct Refusal {
    /// The 1-based line of the opening fence.
    pub line: usize,
    /// Why it was refused.
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

/// Classify an `ipe` fence from the info words after `ipe`.
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
        Some(_) => Err(unknown()),
    }
}

/// Classify an opening fence's info string: `None` for a non-`ipe` fence.
fn ipe_kind(info: &str, page: Page) -> Option<Result<Kind, FenceError>> {
    let mut words = info.split_whitespace();
    let lang = words.next()?;
    if lang == "ipe" {
        Some(classify(info, words, page))
    } else if lang.starts_with("ipe") {
        Some(Err(FenceError::UnknownInfo(info.to_owned())))
    } else {
        None
    }
}

/// An open fence being read.
struct Open {
    line: usize,
    indent: usize,
    ch: char,
    len: usize,
    kind: Option<Result<Kind, FenceError>>,
    body: Vec<String>,
}

/// Strip up to `indent` leading spaces from `line`.
fn dedent(line: &str, indent: usize) -> String {
    let spaces = line.chars().take(indent).take_while(|c| *c == ' ').count();
    line.get(spaces..).unwrap_or(line).to_owned()
}

/// Every fenced `ipe` block on `text` in page order, or its fence's refusal.
#[must_use]
pub fn scan(text: &str, page: Page) -> Vec<Result<Block, Refusal>> {
    let mut items = Vec::new();
    let mut open: Option<Open> = None;
    for (index, line) in text.lines().enumerate() {
        let Some(fence) = open.as_mut() else {
            open = opening(line).map(|o| Open {
                line: index + 1,
                indent: o.indent,
                ch: o.ch,
                len: o.len,
                kind: ipe_kind(o.info, page),
                body: Vec::new(),
            });
            continue;
        };
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
    }
    if let Some(fence) = open {
        items.push(Err(Refusal {
            line: fence.line,
            error: FenceError::Unclosed,
        }));
    }
    items
}

#[cfg(test)]
mod tests {
    use super::{FenceError, Kind, Page, scan};

    fn only_error(text: &str, page: Page) -> Option<FenceError> {
        let items = scan(text, page);
        assert_eq!(items.len(), 1, "one item expected: {items:?}");
        items.into_iter().next()?.err().map(|r| r.error)
    }

    #[test]
    fn unknown_info_string_is_refused() {
        let text = "```ipe ipe:eror\nx = 1\n```\n";
        assert_eq!(
            only_error(text, Page::Doc),
            Some(FenceError::UnknownInfo("ipe ipe:eror".to_owned()))
        );
        let glued = "```ipe:error\nx = 1\n```\n";
        assert_eq!(
            only_error(glued, Page::Doc),
            Some(FenceError::UnknownInfo("ipe:error".to_owned()))
        );
    }

    #[test]
    fn skip_without_reason_is_refused() {
        let text = "```ipe ipe:skip\nx = 1\n```\n";
        assert_eq!(
            only_error(text, Page::Doc),
            Some(FenceError::SkipWithoutReason)
        );
        let with_reason = scan("```ipe ipe:skip needs FFI\nx = 1\n```\n", Page::Doc);
        assert!(
            matches!(with_reason.as_slice(), [Ok(b)] if matches!(b.kind, Kind::Skip(_))),
            "{with_reason:?}"
        );
    }

    #[test]
    fn unclosed_fence_is_refused() {
        assert_eq!(
            only_error("```ipe\nx = 1\n", Page::Doc),
            Some(FenceError::Unclosed)
        );
        // An unclosed non-ipe fence would swallow every later ipe block.
        assert_eq!(
            only_error("```text\n```ipe\nx = 1\n", Page::Doc),
            Some(FenceError::Unclosed)
        );
    }

    #[test]
    fn four_backtick_fence_closes_only_at_four() {
        let text = "````ipe\n{-| doc\n\n    ```ipe\n    greet \"w\"\n    ```\n-}\ngreet : String -> String\ngreet n = n\n````\n";
        let items = scan(text, Page::Doc);
        assert_eq!(items.len(), 1, "{items:?}");
        let block = items
            .first()
            .expect("one block")
            .as_ref()
            .expect("a checked block");
        assert_eq!(block.kind, Kind::Check);
        assert!(block.body.contains("    ```ipe"), "{}", block.body);
        assert!(block.body.ends_with("greet n = n"), "{}", block.body);
    }

    #[test]
    fn error_code_on_explain_page_is_refused() {
        let text = "```ipe ipe:error IPE-N0004\nx = 1\n```\n";
        assert_eq!(
            only_error(text, Page::Explain(ipe_diagnostics::IPE_N0004)),
            Some(FenceError::ErrorCodeOnExplainPage)
        );
    }

    #[test]
    fn unknown_error_code_is_refused() {
        let text = "```ipe ipe:error IPE-Z9999\nx = 1\n```\n";
        assert_eq!(
            only_error(text, Page::Doc),
            Some(FenceError::ErrorCodeUnknown("IPE-Z9999".to_owned()))
        );
    }

    #[test]
    fn error_block_on_doc_page_must_name_its_code() {
        let text = "```ipe ipe:error\nx = 1\n```\n";
        assert_eq!(
            only_error(text, Page::Doc),
            Some(FenceError::ErrorCodeMissing)
        );
        let named = scan("```ipe ipe:error IPE-N0004\nx = 1\n```\n", Page::Doc);
        assert!(
            matches!(named.as_slice(), [Ok(b)] if b.kind == Kind::Error(ipe_diagnostics::IPE_N0004)),
            "{named:?}"
        );
    }

    #[test]
    fn explain_page_error_block_takes_the_page_code() {
        let items = scan(
            "```ipe ipe:error\nx = 1\n```\n",
            Page::Explain(ipe_diagnostics::IPE_N0004),
        );
        assert!(
            matches!(items.as_slice(), [Ok(b)] if b.kind == Kind::Error(ipe_diagnostics::IPE_N0004) && b.line == 1),
            "{items:?}"
        );
    }
}
