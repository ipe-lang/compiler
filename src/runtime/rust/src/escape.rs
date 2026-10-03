//! The runtime's one HTML escaper and its one JSON display/log escaper.
//!
//! Every runtime site that writes text into HTML (the `Html` render sink, the
//! `Ipe.Html` escape kernels, the dev-console banner, the debugger overlay)
//! escapes through this module, and so does every JSON log record and console
//! payload ([`json_str_body`]). It is std-only and declared in every runtime
//! module set, so a program that serves HTML without importing `Ipe.Html` (a
//! headless `Ipe.Http.Server` serving the dev banner) still has it.
//!
//! HTML byte contract (the rendered goldens and e2e expectations depend on it):
//! - text form: `&` `<` `>` `'` become `&amp;` `&lt;` `&gt;` `&#39;`; `"` stays
//!   raw;
//! - attribute form: the text form plus `"` as `&#34;` (never `&quot;`).
//!
//! Both forms escape `'`, so a value is safe in a single- or double-quoted
//! attribute alike. URL-bearing attributes are scheme-checked separately, at
//! the render sink.
//!
//! JSON display/log contract: valid JSON that decodes to the input, with every
//! log hazard (`crate::system::is_log_hazard`, Unicode `Cc ∪ Cf ∪ Zl ∪ Zp`)
//! spelled as a `\u` escape. It is byte-equal to the compiler-side owner,
//! `ipe_diagnostics::json::string_body`, which a test asserts.

use std::fmt::Write as _;

/// Append `t`, escaped for HTML text content, to `out`.
///
/// `"` is left raw: it carries no meaning in text content.
pub fn html_text_into(t: &str, out: &mut String) {
    escape_into(t, false, out);
}

/// Append `t`, escaped for a quoted HTML attribute value, to `out`.
///
/// Safe in single- and double-quoted attributes.
pub fn html_attr_into(t: &str, out: &mut String) {
    escape_into(t, true, out);
}

/// Escape `t` for HTML text content.
///
/// The allocating form of [`html_text_into`].
#[must_use]
pub fn html_text(t: &str) -> String {
    let mut out = String::with_capacity(t.len() + 8);
    html_text_into(t, &mut out);
    out
}

/// Escape `t` for a quoted HTML attribute value.
///
/// The allocating form of [`html_attr_into`].
#[must_use]
pub fn html_attr(t: &str) -> String {
    let mut out = String::with_capacity(t.len() + 8);
    html_attr_into(t, &mut out);
    out
}

/// Single-pass escape of `t` into `out`.
///
/// One original-to-output map never re-scans its own output; the
/// metacharacter-free common case appends the input verbatim.
fn escape_into(t: &str, escape_quote: bool, out: &mut String) {
    if !t.contains(['&', '<', '>', '\'', '"']) {
        out.push_str(t);
        return;
    }
    out.reserve(t.len() + 8);
    for c in t.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&#39;"),
            '"' if escape_quote => out.push_str("&#34;"),
            _ => out.push(c),
        }
    }
}

/// The JSON `\u` spelling of one hazard character.
///
/// Four lowercase hex digits for a BMP character, the UTF-16 surrogate pair
/// for an astral one (U+E0041 is `\udb40\udc41`). Every runtime JSON writer
/// spells a hazard through it, so the display escaper and the replay-log
/// formatter cannot drift apart.
pub(crate) struct JsonHazardEscape(pub(crate) char);

impl std::fmt::Display for JsonHazardEscape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut units = [0_u16; 2];
        for unit in self.0.encode_utf16(&mut units) {
            write!(f, "\\u{unit:04x}")?;
        }
        Ok(())
    }
}

/// Append the JSON string body (no surrounding quotes) of `s` to `out`, display role.
///
/// `"` and `\` are backslash-escaped, `\n` `\r` `\t` use their short forms,
/// every other [`crate::system::is_log_hazard`] character is spelled by
/// [`JsonHazardEscape`], and every other character is kept as is.
pub(crate) fn json_str_body_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if crate::system::is_log_hazard(c) => {
                let _ = write!(out, "{}", JsonHazardEscape(c));
            }
            c => out.push(c),
        }
    }
}

/// The JSON string body (no surrounding quotes) of `s`, display role.
///
/// The allocating form of [`json_str_body_into`].
#[must_use]
pub fn json_str_body(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    json_str_body_into(s, &mut out);
    out
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod json_tests {
    use super::json_str_body;

    #[allow(clippy::expect_used)] // an invalid body fails the test
    fn decode(body: &str) -> String {
        serde_json::from_str::<String>(&format!("\"{body}\"")).expect("valid JSON string")
    }

    fn neighbour(c: char, step: i64) -> Option<char> {
        let n = i64::from(u32::from(c)).checked_add(step)?;
        char::from_u32(u32::try_from(n).ok()?)
    }

    #[allow(clippy::expect_used)] // a malformed fixture fails the test
    fn fixture_ranges() -> Vec<(char, char)> {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/log_hazard_ranges.json"))
                .expect("fixture is JSON");
        fixture
            .as_array()
            .expect("fixture is an array")
            .iter()
            .map(|row| {
                let bound = |key: &str| {
                    row.get(key)
                        .and_then(serde_json::Value::as_u64)
                        .and_then(|v| u32::try_from(v).ok())
                        .and_then(char::from_u32)
                        .expect("bound is a scalar value")
                };
                (bound("lo"), bound("hi"))
            })
            .collect()
    }

    /// Every edge of every fixture range escapes; every non-hazard neighbour stays raw.
    #[test]
    fn json_hazards_escape_at_every_boundary() {
        let ranges = fixture_ranges();
        assert!(!ranges.is_empty(), "fixture must list the hazard ranges");
        for (lo, hi) in ranges {
            for edge in [lo, hi] {
                let body = json_str_body(&edge.to_string());
                assert!(body.starts_with('\\'), "{edge:?} stayed raw: {body:?}");
                assert!(!body.contains(edge), "{edge:?} survived: {body:?}");
                assert_eq!(decode(&body), edge.to_string());
            }
            for outside in [neighbour(lo, -1), neighbour(hi, 1)].into_iter().flatten() {
                if crate::system::is_log_hazard(outside) || matches!(outside, '"' | '\\') {
                    continue;
                }
                assert_eq!(json_str_body(&outside.to_string()), outside.to_string());
            }
        }
        let csi = json_str_body("a\u{9b}[2Jb");
        assert!(!csi.contains('\u{9b}'), "{csi:?}");
        assert_eq!(csi, "a\\u009b[2Jb");
        assert_eq!(json_str_body("\u{202e}"), "\\u202e");
        assert_eq!(json_str_body("\u{e0041}"), "\\udb40\\udc41");
        assert_eq!(json_str_body("\u{7f}"), "\\u007f");
        for vector in ["a\u{9b}[2Jb", "\u{202e}", "\u{e0041}", "q\"b\\s\n\r\t"] {
            assert_eq!(decode(&json_str_body(vector)), vector);
        }
    }

    /// Over every scalar value the runtime body equals the compiler-side owner's.
    #[test]
    fn json_body_equals_compiler_side() {
        for c in (0..=u32::from(char::MAX)).filter_map(char::from_u32) {
            let input = format!("a{c}b");
            assert_eq!(
                json_str_body(&input),
                ipe_diagnostics::json::string_body(&input),
                "U+{:04X}",
                u32::from(c)
            );
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::{html_attr, html_attr_into, html_text, html_text_into};

    #[test]
    fn attr_form_escapes_all_five_with_numeric_quote_entities() {
        assert_eq!(html_attr("\"'<>&"), "&#34;&#39;&lt;&gt;&amp;");
    }

    #[test]
    fn text_form_leaves_double_quote_raw() {
        assert_eq!(html_text("\""), "\"");
        assert_eq!(html_text("\"'<>&"), "\"&#39;&lt;&gt;&amp;");
    }

    #[test]
    fn into_forms_append_and_match_allocating_forms() {
        let mut out = String::from("x");
        html_attr_into("a\"b", &mut out);
        html_text_into("c\"d", &mut out);
        assert_eq!(out, "xa&#34;bc\"d");
    }

    #[test]
    fn metacharacter_free_input_is_unchanged() {
        assert_eq!(html_attr("plain text 123"), "plain text 123");
        assert_eq!(html_text(""), "");
    }
}
