//! The canonical view of a unit's source and its attestation hash.
//!
//! This is the one definition of "the bytes a unit names" and of their
//! attestation. Every unit but a `file` unit stores `attest` of
//! `view_text(src, line_start, line_end)`; a `file` unit stores
//! `attest_residual` of its residual (`extract::residual_text`), built from
//! `view_lines`. The code-review app re-derives the hash with the same rules
//! before showing a unit. The rules are pinned for both sides by
//! `tests/view_hash_vectors.json` and `tests/residual_vectors.json`.

use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// The scheme prefix of a line-range view's attestation.
pub const SCHEME: &str = "sha256:";

/// The scheme prefix of a `file` unit's residual attestation.
///
/// Any text is the view of some file, so no encoding of the residual's bytes
/// alone keeps its hash apart from every `SCHEME` hash, among them the
/// whole-file hash an older index stored for the same file unit and the
/// review log still holds. The scheme does: a residual attestation never
/// equals the attestation of any view.
pub const RESIDUAL_SCHEME: &str = "sha256-residual:";

/// The lines of `src`, split on `'\n'` exactly.
///
/// A `'\r'` is content and stays in its line. The empty segment after a
/// trailing `'\n'` is not a line, so `""` and `"\n"` are both one empty line.
pub fn view_lines(src: &str) -> Vec<&str> {
    let body = src.strip_suffix('\n').unwrap_or(src);
    body.split('\n').collect()
}

/// The number of lines `view_lines` yields for `src`.
pub fn view_line_count(src: &str) -> i64 {
    let body = src.strip_suffix('\n').unwrap_or(src);
    let breaks = body.bytes().filter(|b| *b == b'\n').count();
    i64::try_from(breaks).map_or(i64::MAX, |n| n.saturating_add(1))
}

/// Why a line range names no view of a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeError {
    /// The first line is below line 1.
    StartBelowOne,
    /// The last line comes before the first line.
    EndBeforeStart,
    /// The last line is past the source's last line.
    EndPastFile { end: i64, count: i64 },
}

impl std::fmt::Display for RangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StartBelowOne => f.write_str("line range starts below line 1"),
            Self::EndBeforeStart => f.write_str("line range ends before it starts"),
            Self::EndPastFile { end, count } => {
                write!(f, "line range ends at {end}, past the last line {count}")
            }
        }
    }
}

impl std::error::Error for RangeError {}

/// Lines `start..=end` of `src` (1-based, inclusive) joined with `"\n"`.
///
/// Total: an out-of-range span is refused with its `RangeError`, never clamped.
pub fn view_text(src: &str, start: i64, end: i64) -> Result<String, RangeError> {
    if start < 1 {
        return Err(RangeError::StartBelowOne);
    }
    if end < start {
        return Err(RangeError::EndBeforeStart);
    }
    let lines = view_lines(src);
    let count = i64::try_from(lines.len()).unwrap_or(i64::MAX);
    let past = RangeError::EndPastFile { end, count };
    let (Ok(first), Ok(last)) = (usize::try_from(start - 1), usize::try_from(end)) else {
        return Err(past);
    };
    lines
        .get(first..last)
        .map(|span| span.join("\n"))
        .ok_or(past)
}

/// `SCHEME` followed by the lowercase hex SHA-256 of the UTF-8 bytes of `view`.
pub fn attest(view: &str) -> String {
    attest_under(SCHEME, view)
}

/// `RESIDUAL_SCHEME` followed by the lowercase hex SHA-256 of the UTF-8 bytes
/// of `residual`: a `file` unit's attestation.
pub fn attest_residual(residual: &str) -> String {
    attest_under(RESIDUAL_SCHEME, residual)
}

fn attest_under(scheme: &str, text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    let mut out = String::with_capacity(scheme.len() + 2 * digest.len());
    out.push_str(scheme);
    for byte in digest {
        // Writing into a `String` cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../../tests/view_hash_vectors.json");

    fn refusal_name(e: RangeError) -> &'static str {
        match e {
            RangeError::StartBelowOne => "StartBelowOne",
            RangeError::EndBeforeStart => "EndBeforeStart",
            RangeError::EndPastFile { .. } => "EndPastFile",
        }
    }

    #[test]
    fn vectors() {
        let rows: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
        assert!(rows.len() >= 12, "the shared vector file lost rows");
        for row in rows {
            let name = row["name"].as_str().unwrap();
            let src = row["src"].as_str().unwrap();
            let start = row["start"].as_i64().unwrap();
            let end = row["end"].as_i64().unwrap();
            let got = view_text(src, start, end);
            match (row["view"].as_str(), row["hash"].as_str()) {
                (Some(view), Some(hash)) => {
                    assert_eq!(got.as_deref(), Ok(view), "{name}: view");
                    assert_eq!(attest(view), hash, "{name}: hash");
                }
                _ => {
                    let want = row["refusal"].as_str().unwrap();
                    assert_eq!(got.map_err(refusal_name), Err(want), "{name}: refusal");
                }
            }
        }
    }

    #[test]
    fn view_text_refuses_out_of_range() {
        let src = "a\nb\n";
        assert_eq!(view_text(src, 0, 1), Err(RangeError::StartBelowOne));
        assert_eq!(view_text(src, i64::MIN, 1), Err(RangeError::StartBelowOne));
        assert_eq!(view_text(src, 2, 1), Err(RangeError::EndBeforeStart));
        assert_eq!(
            view_text(src, 1, 3),
            Err(RangeError::EndPastFile { end: 3, count: 2 })
        );
        assert_eq!(
            view_text(src, 1, i64::MAX),
            Err(RangeError::EndPastFile {
                end: i64::MAX,
                count: 2
            })
        );
        assert_eq!(
            view_text(src, i64::MAX, i64::MAX),
            Err(RangeError::EndPastFile {
                end: i64::MAX,
                count: 2
            })
        );
    }

    #[test]
    fn line_count_matches_lines() {
        for src in ["", "\n", "a", "a\n", "a\n\n", "a\r\nb", "a\nb\n"] {
            assert_eq!(
                view_line_count(src),
                i64::try_from(view_lines(src).len()).unwrap(),
                "{src:?}"
            );
        }
    }
}
