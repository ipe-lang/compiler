//! Rendering and choosing from an `ipe doc` miss list.
//!
//! [`crate::doc_search`] ranks; this module shows the ranking — numbered for a
//! person, tab-separated for `--plain`, a JSON array for `--json` — and reads
//! a person's choice through a typed [`BufRead`] seam, so the prompt's
//! refusals are driven in tests without a terminal.

use std::fmt::Write as _;
use std::io::{BufRead, Read as _, Write};

use crate::cli_args::{OutputFormat, json};
use crate::doc_search::{Closeness, DocMiss};
use crate::style::gutter;
use crate::text;

/// The most answers the prompt reads before it gives up.
pub const PICK_ATTEMPTS: usize = 3;

/// The most bytes one answer may carry, its newline included.
const ANSWER_BYTES: u64 = 64;

/// The outcome of the prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pick {
    /// The person chose the hit at this zero-based position.
    Chosen(usize),
    /// The person cancelled (Enter, `q`, or end of input).
    Cancelled,
    /// Every attempt named no listed entry.
    Exhausted,
}

/// Ask which of `count` listed entries to open, reading answers from `reader`
/// and writing the prompt to `out`.
///
/// An answer is a number in `1..=count`; an empty answer, `q`, end of input,
/// or a read error cancels. Anything else — a number out of range, a
/// non-number, an answer longer than its byte ceiling, invalid UTF-8 — is
/// refused with a re-prompt, at most [`PICK_ATTEMPTS`] times in all.
pub fn pick<R: BufRead, W: Write>(reader: &mut R, out: &mut W, count: usize) -> Pick {
    let prompt = text::doc_pick_prompt(&count);
    for _ in 0..PICK_ATTEMPTS {
        if write!(out, "{} ", gutter(&prompt)).is_err() || out.flush().is_err() {
            return Pick::Cancelled;
        }
        let mut buf = Vec::new();
        match reader
            .by_ref()
            .take(ANSWER_BYTES)
            .read_until(b'\n', &mut buf)
        {
            Ok(0) | Err(_) => return Pick::Cancelled,
            Ok(_) => {}
        }
        if let Some(pick) = answer(&buf, count) {
            return pick;
        }
        if !buf.ends_with(b"\n") {
            drain_line(reader);
        }
        if writeln!(out, "{}", gutter(text::doc_pick_retry())).is_err() {
            return Pick::Cancelled;
        }
    }
    Pick::Exhausted
}

/// The pick one answer line names, or `None` when it names no listed entry.
fn answer(buf: &[u8], count: usize) -> Option<Pick> {
    if !buf.ends_with(b"\n") && u64::try_from(buf.len()).is_ok_and(|len| len >= ANSWER_BYTES) {
        return None;
    }
    let line = std::str::from_utf8(buf).ok()?.trim();
    if line.is_empty() || line.eq_ignore_ascii_case("q") {
        return Some(Pick::Cancelled);
    }
    if !line.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    line.parse::<usize>()
        .ok()
        .filter(|n| (1..=count).contains(n))
        .and_then(|n| n.checked_sub(1))
        .map(Pick::Chosen)
}

/// Discard the rest of an over-long answer line, a bounded chunk at a time, so
/// its tail is not read as the next answer.
///
/// Stops at the newline, at end of input, on a read error, or after
/// [`PICK_ATTEMPTS`] chunks — the next prompt then sees whatever remains.
fn drain_line<R: BufRead>(reader: &mut R) {
    for _ in 0..PICK_ATTEMPTS {
        let mut sink = Vec::new();
        match reader
            .by_ref()
            .take(ANSWER_BYTES)
            .read_until(b'\n', &mut sink)
        {
            Ok(0) | Err(_) => return,
            Ok(_) if sink.ends_with(b"\n") => return,
            Ok(_) => {}
        }
    }
}

/// The header over a miss list.
const fn header(miss: &DocMiss) -> &'static str {
    match miss.closeness {
        Closeness::Match => text::cli_doc_suggestions_header(),
        Closeness::Nearest => text::cli_doc_nearest_header(),
    }
}

/// The numbered lines of a miss list, the numbers right-aligned and the terms
/// padded to one column.
#[must_use]
pub fn human_lines(miss: &DocMiss) -> Vec<String> {
    let index_width = miss.hits.len().to_string().len();
    let term_width = miss
        .hits
        .iter()
        .map(|hit| hit.term.as_str().chars().count())
        .max()
        .unwrap_or(0);
    miss.hits
        .iter()
        .enumerate()
        .map(|(at, hit)| {
            let index = format!("{:>index_width$}", at.saturating_add(1));
            let term = format!("{:<term_width$}", hit.term.as_str());
            text::cli_doc_suggestion_line(&index, &term, &hit.summary, &hit.kind)
                .to_string()
                .trim_end()
                .to_owned()
        })
        .collect()
}

/// The person-facing text of a miss: the not-found line, then the header,
/// the numbered list, and the more-matches note when the ceiling cut it.
#[must_use]
pub fn miss_text(miss: &DocMiss) -> String {
    let mut out = text::cli_doc_not_found(&miss.query).to_string();
    if miss.hits.is_empty() {
        return out;
    }
    let _ = write!(out, "\n{}", header(miss));
    for line in human_lines(miss) {
        let _ = write!(out, "\n{line}");
    }
    if miss.truncated {
        let _ = write!(out, "\n{}", text::cli_doc_more_matches());
    }
    out
}

/// The person-facing header and closing note of a miss, for a screen that
/// tones each part on its own.
#[must_use]
pub fn human_parts(miss: &DocMiss) -> (&'static str, Option<&'static str>) {
    (
        header(miss),
        miss.truncated.then(text::cli_doc_more_matches),
    )
}

/// The `--plain` miss list: one `term<TAB>kind<TAB>summary` line per hit, the
/// term first so a script re-runs `ipe doc` with the first field.
#[must_use]
pub fn plain_lines(miss: &DocMiss) -> String {
    let mut out = String::new();
    for hit in &miss.hits {
        let _ = writeln!(
            out,
            "{}\t{}\t{}",
            hit.term.as_str(),
            hit.kind,
            hit.summary.as_str()
        );
    }
    out
}

/// The `--json` miss fields, added to the error payload beside `kind` and
/// `message`.
#[must_use]
pub fn json_fields(miss: &DocMiss) -> Vec<(&'static str, String)> {
    let results: Vec<String> = miss
        .hits
        .iter()
        .map(|hit| {
            json::object(&[
                ("term", json::string(hit.term.as_str())),
                ("kind", json::string(hit.kind.prefix())),
                ("summary", json::string(hit.summary.as_str())),
            ])
        })
        .collect();
    vec![
        ("query", json::string(miss.query.as_str())),
        ("closeness", json::string(miss.closeness.word())),
        (
            "truncated",
            if miss.truncated { "true" } else { "false" }.to_owned(),
        ),
        ("results", json::array(&results)),
    ]
}

/// The machine form of a miss for `format`.
///
/// `--json` is the shared error envelope carrying [`json_fields`]; `--plain`
/// is [`plain_lines`], or the plain error line when the list is empty.
#[must_use]
pub fn machine_miss(
    format: OutputFormat,
    command: &str,
    kind: &str,
    message: &str,
    miss: &DocMiss,
) -> String {
    match format {
        OutputFormat::Json => crate::machine_output::machine_error_with(
            format,
            command,
            kind,
            message,
            &json_fields(miss),
        ),
        OutputFormat::Plain | OutputFormat::Human if !miss.hits.is_empty() => plain_lines(miss),
        OutputFormat::Plain | OutputFormat::Human => {
            crate::machine_output::machine_error(format, command, kind, message)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc_bundle::DocKind;
    use crate::doc_search::DocHit;
    use crate::style::TerminalLine;

    fn hit(term: &str, kind: DocKind, summary: &str) -> DocHit {
        DocHit {
            term: TerminalLine::sanitize(term),
            kind,
            summary: TerminalLine::sanitize(summary),
        }
    }

    fn miss(truncated: bool) -> DocMiss {
        DocMiss {
            query: TerminalLine::sanitize("pipe"),
            hits: vec![
                hit("topic:pipelines", DocKind::Topic, "Pipelines"),
                hit("Ipe.List.map", DocKind::Symbol, "Apply a function"),
            ],
            closeness: Closeness::Match,
            truncated,
        }
    }

    fn run_pick(input: &[u8], count: usize) -> (Pick, String) {
        let mut reader = input;
        let mut out = Vec::new();
        let pick = pick(&mut reader, &mut out, count);
        (pick, String::from_utf8_lossy(&out).into_owned())
    }

    // -- Prompt ---------------------------------------------------------------

    #[test]
    fn a_listed_number_opens_that_entry() {
        assert_eq!(run_pick(b"1\n", 2).0, Pick::Chosen(0));
        assert_eq!(run_pick(b" 2 \n", 2).0, Pick::Chosen(1));
        assert_eq!(
            run_pick(b"2", 2).0,
            Pick::Chosen(1),
            "end of input ends the line"
        );
        assert_eq!(run_pick(b"2\r\n", 2).0, Pick::Chosen(1));
    }

    #[test]
    fn enter_q_or_end_of_input_cancels() {
        for input in [&b"\n"[..], b"q\n", b"Q\n", b"  \n", b""] {
            assert_eq!(run_pick(input, 2).0, Pick::Cancelled, "{input:?}");
        }
    }

    #[test]
    fn an_unlisted_answer_is_refused_and_re_prompted() {
        let (pick, out) = run_pick(b"0\n3\n1\n", 2);
        assert_eq!(pick, Pick::Chosen(0));
        assert_eq!(out.matches("Not a listed number.").count(), 2, "{out:?}");
        assert_eq!(out.matches("Open which entry? [1-2").count(), 3, "{out:?}");
        for refused in [
            &b"-1\n"[..],
            b"+1\n",
            b"1.0\n",
            b"one\n",
            b"\xff\n",
            b"99999999999999999999999999\n",
            b"\xd9\xa1\n",
        ] {
            let mut input = refused.to_vec();
            input.extend_from_slice(b"2\n");
            assert_eq!(run_pick(&input, 2).0, Pick::Chosen(1), "{refused:?}");
        }
    }

    #[test]
    fn the_prompt_gives_up_after_its_attempts() {
        let (pick, out) = run_pick(b"x\nx\nx\n1\n", 2);
        assert_eq!(pick, Pick::Exhausted);
        assert_eq!(out.matches("Open which entry?").count(), PICK_ATTEMPTS);
    }

    #[test]
    fn an_over_long_answer_is_refused_and_its_tail_never_answers() {
        let mut input = vec![b'1'; 200];
        input.extend_from_slice(b"\n2\n");
        assert_eq!(run_pick(&input, 2).0, Pick::Chosen(1));
        let mut digits = vec![b' '; 62];
        digits.extend_from_slice(b"1\n");
        assert_eq!(
            run_pick(&digits, 2).0,
            Pick::Chosen(0),
            "an answer of exactly the ceiling, newline included, is read"
        );
    }

    // -- Rendering ------------------------------------------------------------

    #[test]
    fn the_human_list_is_numbered_and_aligned() {
        let lines = human_lines(&miss(false));
        assert_eq!(
            lines,
            [
                "  1. ipe doc topic:pipelines  Pipelines (topic)",
                "  2. ipe doc Ipe.List.map     Apply a function (symbol)",
            ]
        );
        let text = miss_text(&miss(true));
        assert!(
            text.starts_with("no documentation entry is named `pipe`\nClosest matches:\n"),
            "{text:?}"
        );
        assert!(
            text.ends_with("\nMore entries match; refine the term."),
            "{text:?}"
        );
        assert!(!miss_text(&miss(false)).contains("More entries"));
    }

    #[test]
    fn a_nearest_list_says_nothing_matched_closely() {
        let nearest = DocMiss {
            closeness: Closeness::Nearest,
            ..miss(false)
        };
        assert!(miss_text(&nearest).contains("No close match; the nearest entries:"));
    }

    #[test]
    fn the_plain_list_is_tab_separated_with_the_term_first() {
        assert_eq!(
            plain_lines(&miss(false)),
            "topic:pipelines\ttopic\tPipelines\nIpe.List.map\tsymbol\tApply a function\n"
        );
        let out = machine_miss(
            OutputFormat::Plain,
            "doc",
            "doc-not-found",
            "m",
            &miss(false),
        );
        assert!(!out.contains('\u{1b}'));
        let empty = DocMiss {
            hits: Vec::new(),
            ..miss(false)
        };
        assert_eq!(
            machine_miss(
                OutputFormat::Plain,
                "doc",
                "doc-not-found",
                "no entry",
                &empty
            ),
            "no entry\n"
        );
    }

    #[test]
    fn the_json_miss_is_the_error_envelope_with_ordered_results() {
        let out = machine_miss(
            OutputFormat::Json,
            "doc",
            "doc-not-found",
            "no entry",
            &miss(true),
        );
        assert!(
            out.starts_with("{\"schema\":\"ipe.cli.error/1\",\"status\":\"error\","),
            "{out}"
        );
        assert!(out.contains("\"kind\":\"doc-not-found\""), "{out}");
        assert!(out.contains("\"query\":\"pipe\""), "{out}");
        assert!(out.contains("\"closeness\":\"match\""), "{out}");
        assert!(out.contains("\"truncated\":true"), "{out}");
        assert!(
            out.contains(
                "\"results\":[{\"term\":\"topic:pipelines\",\"kind\":\"topic\",\
                 \"summary\":\"Pipelines\"},{\"term\":\"Ipe.List.map\",\
                 \"kind\":\"symbol\",\"summary\":\"Apply a function\"}]"
            ),
            "{out}"
        );
        assert!(out.ends_with("}\n"));
    }
}
