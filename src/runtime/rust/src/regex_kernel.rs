//! Regex kernels for `Ipe.Regex`. A pattern is compiled ONCE via
//! [`regex_compile`] into an opaque [`Regex`] handle; an invalid pattern is a
//! typed `Err`, never a silent no-match. Every operation takes the already
//! compiled [`Regex`], so no operation can re-encounter an unvalidated pattern
//! string (parse, don't validate).

use super::{IpeMaybe, IpeResult};
use std::sync::Arc;

/// Subject-length ceiling (default 16 MiB) shared by every `Ipe.Regex`
/// operation. The `regex` crate is linear-time (RE2, no catastrophic
/// backtracking) and `Regex::new` bounds COMPILE via its 10 MB `size_limit`,
/// but the SUBJECT is otherwise unbounded: a multi-hundred-MB attacker-supplied
/// string handed to `findAll` on `\b` allocates tens of millions of small
/// `String`s. Bounded by construction (PRINCIPLES §3, and §1's exhaustion
/// clause when the subject arrives over the network): past this ceiling each
/// operation returns its total safe outcome (no match / no split / identity)
/// rather than being driven through an unbounded scan-and-collect. Mirrors the
/// sibling decode caps (`IPE_CSV_MAX_BYTES`, `IPE_DECOMPRESS_MAX_BYTES`,
/// `DEFAULT_SEAL_MAX_INPUT_BYTES`). Overridable via `IPE_REGEX_MAX_INPUT_BYTES`.
fn regex_max_input_bytes() -> usize {
    crate::system::read_env_var("IPE_REGEX_MAX_INPUT_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(16 * 1024 * 1024)
}

/// The single fail-closed gate all five entrypoints share: is `s` within the
/// declared subject ceiling? A subject past the bound is turned back at the
/// boundary before any scan begins.
fn within_input_ceiling(s: &str) -> bool {
    s.len() <= regex_max_input_bytes()
}

/// `Ipe.Regex`'s opaque compiled-pattern handle. Newtype over an `Arc`-shared
/// [`regex::Regex`] so cloning is a refcount bump (a `Regex` value may flow
/// through several call sites).
///
/// Deliberately carries only `Clone`: `regex::Regex` is neither `PartialEq`,
/// `Eq`, `Hash`, `Ord` nor serde, so the opaque handle inherits none of those.
/// The absence is load-bearing — a `Ipe.Web` Model field of type `Regex`, a
/// `Dict`-key use, or a serde round-trip is a compile-time rejection, never a
/// silent wrong behaviour. `Debug` is derived (prints the source pattern),
/// backing `{{…}}` interpolation through the runtime's `Debug`-based stringify fallback.
#[derive(Clone, Debug)]
pub struct Regex(Arc<regex::Regex>);

/// `Regex.compile : String -> Result Error Regex` — THE construction boundary.
/// Every [`Regex`] value traces back to one of these calls; an invalid pattern
/// surfaces here as a typed `Err`, never anywhere downstream as a silent
/// no-match.
#[must_use]
pub fn regex_compile<E: From<String>>(pattern: String) -> IpeResult<E, Regex> {
    match regex::Regex::new(&pattern) {
        Ok(re) => IpeResult::Ok(Regex(Arc::new(re))),
        Err(e) => IpeResult::Err(format!("Ipe.Regex: invalid pattern: {e}").into()),
    }
}

/// `Regex.match : Regex -> String -> Bool` — does the pattern match anywhere?
/// A subject past the shared ceiling yields `false` (fail-closed: absent a
/// bounded scan, the safe answer is "no proven match").
#[must_use]
pub fn regex_match(re: Regex, s: String) -> bool {
    within_input_ceiling(&s) && re.0.is_match(&s)
}

/// `Regex.find : Regex -> String -> Maybe String` — first match, if any.
/// A subject past the shared ceiling yields `Nothing` (fail-closed).
#[must_use]
pub fn regex_find(re: Regex, s: String) -> IpeMaybe<String> {
    if !within_input_ceiling(&s) {
        return IpeMaybe::Nothing;
    }
    match re.0.find(&s) {
        Some(m) => IpeMaybe::Just(m.as_str().to_string()),
        None => IpeMaybe::Nothing,
    }
}

/// `Regex.findAll : Regex -> String -> List String` — every match, in order.
/// A subject past the shared ceiling yields the empty list (fail-closed: no
/// unbounded `Vec<String>` collect over an oversized subject).
#[must_use]
pub fn regex_find_all(re: Regex, s: String) -> Vec<String> {
    if !within_input_ceiling(&s) {
        return Vec::new();
    }
    re.0.find_iter(&s).map(|m| m.as_str().to_string()).collect()
}

/// `Regex.replace : Regex -> String -> String -> String` — replace every match
/// with `replacement` (RE2 `$1` substitution syntax).
/// A subject past the shared ceiling is returned unchanged (fail-closed: the
/// identity is the total safe outcome, applying no replacements rather than
/// scanning an oversized subject).
#[must_use]
pub fn regex_replace(re: Regex, replacement: String, s: String) -> String {
    if !within_input_ceiling(&s) {
        return s;
    }
    re.0.replace_all(&s, replacement.as_str()).to_string()
}

/// `Regex.split : Regex -> String -> List String` — split on every match.
///
/// Splits on every non-overlapping match. Diverges from `Regex::split` on
/// zero-width matches: a zero-width match ending at byte 0 does NOT emit a
/// leading empty string, while interior zero-width matches still split.
/// Implements this by tracking the start of the most recent match manually.
#[must_use]
pub fn regex_split(re: Regex, s: String) -> Vec<String> {
    // A subject past the shared ceiling yields the whole subject as one field
    // (fail-closed: the no-split outcome, applying no split rather than
    // collecting one owned String per match over an oversized subject).
    if !within_input_ceiling(&s) {
        return vec![s];
    }
    // A non-empty pattern against empty input yields one empty field.
    if !re.0.as_str().is_empty() && s.is_empty() {
        return vec![String::new()];
    }
    let mut out: Vec<String> = Vec::new();
    let mut beg: usize = 0;
    // `end` tracks the START offset of the most recent match;
    // the trailing field is suppressed when it reaches len(s).
    let mut end: usize = 0;
    for m in re.0.find_iter(&s) {
        end = m.start();
        // Skip the field for a match ending at byte 0 — drops the leading
        // empty produced by a zero-width match at position 0.
        if m.end() != 0 {
            out.push(s[beg..end].to_string());
        }
        beg = m.end();
    }
    if end != s.len() {
        out.push(s[beg..].to_string());
    }
    out
}

/// `String.isUrl : String -> Bool`
/// Absolute URL with scheme http/https/ws/wss.
///
/// Lives here (not in `string.rs`) because it is the sole `regex`-crate consumer
/// outside the `Ipe.Regex` kernels; keeping it in this `regex`-feature-gated
/// module keeps the always-compiled `string.rs` free of the `regex` crate.
/// Structural parse without the `url` crate — scheme + "://" + non-empty host —
/// rejecting relative paths and `javascript:`/`data:` URLs to prevent XSS
/// footguns.
#[must_use]
pub fn string_is_url(s: String) -> bool {
    use std::sync::OnceLock;
    // Compiled once; the pattern is a string literal so `Regex::new` can only
    // fail if the literal is malformed — verified by the unit tests below.
    // `OnceLock::get_or_init` returns a reference to the cached value; if
    // compilation somehow failed we store `None` and return `false` (total).
    static URL_RE: OnceLock<Option<regex::Regex>> = OnceLock::new();
    let re = URL_RE.get_or_init(|| {
        // Scheme in {http, https, ws, wss} (case-insensitive), followed by
        // "://" and at least one non-whitespace host character.
        regex::Regex::new(r"(?i)^(https?|wss?)://[^/\s?#]+").ok()
    });
    let t = s.trim();
    // Reject ASCII control bytes (0x00–0x1F, 0x7F) anywhere: the host class
    // `[^/\s?#]` only excludes whitespace, so an embedded NUL / ESC would
    // otherwise slip through this XSS-link gate.
    if t.bytes().any(|b| b.is_ascii_control()) {
        return false;
    }
    match re {
        Some(re) => re.is_match(t),
        None => false,
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    fn ok(pattern: &str) -> Regex {
        match regex_compile::<String>(pattern.to_string()) {
            IpeResult::Ok(re) => re,
            IpeResult::Err(e) => panic!("expected a valid pattern, got Err: {e}"),
        }
    }

    #[test]
    fn compile_valid_pattern_is_ok() {
        assert!(matches!(
            regex_compile::<String>(r"^\d+$".to_string()),
            IpeResult::Ok(_)
        ));
    }

    #[test]
    fn compile_invalid_pattern_is_typed_err_not_silent() {
        // The core contract: an invalid pattern is an observable typed Err,
        // NOT a silently-degrading success.
        match regex_compile::<String>(r"[unclosed".to_string()) {
            IpeResult::Ok(_) => panic!("invalid pattern must NOT compile"),
            IpeResult::Err(e) => assert!(e.contains("invalid pattern")),
        }
    }

    #[test]
    fn test_match() {
        assert!(regex_match(ok(r"^\d+$"), "12345".to_string()));
        assert!(!regex_match(ok(r"^\d+$"), "abc".to_string()));
    }

    #[test]
    fn test_find() {
        let m = regex_find(ok(r"\d+"), "foo 42 bar".to_string());
        assert!(matches!(m, IpeMaybe::Just(ref s) if s == "42"));
        let none = regex_find(ok(r"\d+"), "no digits here".to_string());
        assert!(matches!(none, IpeMaybe::Nothing));
    }

    #[test]
    fn test_find_all() {
        let all = regex_find_all(ok(r"\d+"), "1 and 22 and 333".to_string());
        assert_eq!(
            all,
            vec!["1".to_string(), "22".to_string(), "333".to_string()]
        );
    }

    #[test]
    fn test_replace() {
        let r = regex_replace(ok(r"\d+"), "N".to_string(), "a1b2c3".to_string());
        assert_eq!(r, "aNbNcN");
    }

    #[test]
    fn test_split() {
        let parts = regex_split(ok(r",\s*"), "a, b,c,  d".to_string());
        assert_eq!(parts, vec!["a", "b", "c", "d"]);
    }

    /// A subject one byte past the default ceiling is turned back at the
    /// boundary by EVERY entrypoint — the refusal that keeps an untrusted
    /// subject from driving an unbounded scan-and-collect (issue #2644). Each
    /// op returns its total safe outcome, never an unbounded `Vec<String>`.
    #[test]
    fn oversized_subject_is_refused_by_every_entrypoint() {
        let cap = regex_max_input_bytes();
        // One byte past the ceiling: `a`*cap then a trailing byte, so a match
        // WOULD exist were the subject scanned — proving the refusal is the
        // ceiling, not an absent match.
        let mut oversized = "a".repeat(cap);
        oversized.push('b');
        assert!(oversized.len() > cap);

        let re = ok(r"a|b");

        // match → false (no proven match)
        assert!(!regex_match(re.clone(), oversized.clone()));

        // find → Nothing
        assert!(matches!(
            regex_find(re.clone(), oversized.clone()),
            IpeMaybe::Nothing
        ));

        // findAll → empty list (the unbounded-Vec vector, closed)
        assert!(regex_find_all(re.clone(), oversized.clone()).is_empty());

        // replace → identity (input returned unchanged, no replacements)
        assert_eq!(
            regex_replace(re.clone(), "X".to_string(), oversized.clone()),
            oversized
        );

        // split → whole subject as one field (no split applied)
        assert_eq!(regex_split(re, oversized.clone()), vec![oversized]);
    }

    /// A subject exactly AT the ceiling is still processed normally — the bound
    /// is `len() <= cap`, so the last legal size is not spuriously refused.
    #[test]
    fn subject_at_ceiling_is_processed_normally() {
        let cap = regex_max_input_bytes();
        // `cap`-byte subject beginning with a digit, so a match exists and is
        // returned — confirming AT-cap is inside the accepted region.
        let mut at_cap = String::with_capacity(cap);
        at_cap.push('7');
        at_cap.push_str(&"a".repeat(cap - 1));
        assert_eq!(at_cap.len(), cap);

        assert!(regex_match(ok(r"\d"), at_cap.clone()));
        assert!(matches!(
            regex_find(ok(r"\d"), at_cap),
            IpeMaybe::Just(ref d) if d == "7"
        ));
    }

    #[test]
    fn compiled_regex_clones_share_one_pattern() {
        let re = ok(r"\d+");
        let re2 = re.clone();
        assert!(regex_match(re, "x9".to_string()));
        assert!(regex_match(re2, "7".to_string()));
    }

    #[test]
    fn test_is_url_http() {
        assert!(string_is_url("http://example.com".into()));
    }
    #[test]
    fn test_is_url_https() {
        assert!(string_is_url("https://example.com/path".into()));
    }
    #[test]
    fn test_is_url_ws() {
        assert!(string_is_url("ws://example.com".into()));
    }
    #[test]
    fn test_is_url_wss() {
        assert!(string_is_url("wss://example.com".into()));
    }
    #[test]
    fn test_is_url_relative() {
        assert!(!string_is_url("/api/users".into()));
    }
    #[test]
    fn test_is_url_javascript() {
        assert!(!string_is_url("javascript:alert(1)".into()));
    }
    #[test]
    fn test_is_url_data() {
        assert!(!string_is_url("data:text/html,<h1>".into()));
    }
    #[test]
    fn test_is_url_empty() {
        assert!(!string_is_url(String::new()));
    }
    #[test]
    fn test_is_url_ftp() {
        assert!(!string_is_url("ftp://example.com".into()));
    }
    #[test]
    fn test_is_url_rejects_control_chars() {
        // Embedded control bytes (NUL / ESC) → reject (XSS-link-gate).
        assert!(!string_is_url("http://exa\u{0}mple.com".into()));
        assert!(!string_is_url("https://e\u{1b}vil.com".into()));
    }
}
