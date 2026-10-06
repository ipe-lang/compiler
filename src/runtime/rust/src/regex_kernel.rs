//! Regex kernels for `Ipe.Regex`. A pattern is compiled ONCE via
//! [`regex_compile`] into an opaque [`Regex`] handle; an invalid pattern is a
//! typed `Err`, never a silent no-match. Every operation takes the already
//! compiled [`Regex`], so no operation can re-encounter an unvalidated pattern
//! string (parse, don't validate).

use super::{IpeMaybe, IpeResult};
use crate::system::{EnvCeiling, EnvCeilingRefusal, ZeroCeiling};
use std::sync::{Arc, OnceLock};

/// Subject-length ceiling (default 16 MiB) shared by every `Ipe.Regex`
/// operation, read from `IPE_REGEX_MAX_INPUT_BYTES`.
///
/// The `regex` crate is linear-time (RE2, no catastrophic backtracking) and
/// `Regex::new` bounds COMPILE via its 10 MB `size_limit`, but the SUBJECT is
/// otherwise unbounded: a multi-hundred-MB attacker-supplied string handed to
/// `findAll` on `\b` allocates tens of millions of small `String`s. Past this
/// ceiling each operation returns its total safe outcome (no match / no split /
/// identity) rather than being driven through an unbounded scan-and-collect. A
/// present value must be a positive decimal byte count; anything else (`0`
/// included) makes [`regex_compile`] return `Err` naming the variable.
const REGEX_INPUT_CEILING: EnvCeiling = EnvCeiling::new(
    "IPE_REGEX_MAX_INPUT_BYTES",
    16 * 1024 * 1024,
    ZeroCeiling::Refused,
    "decimal byte count",
);

/// The process's one snapshot of [`REGEX_INPUT_CEILING`], parsed at the first
/// `Regex.compile`; a later `System.setenv` does not move it.
fn regex_input_ceiling() -> Result<usize, EnvCeilingRefusal> {
    static CAP: OnceLock<Result<usize, EnvCeilingRefusal>> = OnceLock::new();
    CAP.get_or_init(|| REGEX_INPUT_CEILING.read::<usize>())
        .clone()
}

/// Whether `s` is within the subject ceiling `re` was compiled under.
///
/// The single fail-closed gate all five entrypoints share: a subject past the
/// bound is turned back at the boundary before any scan begins.
const fn within_input_ceiling(re: &Regex, s: &str) -> bool {
    s.len() <= re.max_input
}

/// `Ipe.Regex`'s opaque compiled-pattern handle.
///
/// Holds an `Arc`-shared [`regex::Regex`], so cloning is a refcount bump (a
/// `Regex` value may flow through several call sites), and the subject ceiling
/// parsed when it was compiled, so no handle exists without a parsed ceiling.
///
/// Deliberately carries only `Clone`: `regex::Regex` is neither `PartialEq`,
/// `Eq`, `Hash`, `Ord` nor serde, so the opaque handle inherits none of those.
/// The absence is load-bearing — a `Ipe.Web` Model field of type `Regex`, a
/// `Dict`-key use, or a serde round-trip is a compile-time rejection, never a
/// silent wrong behaviour. `Debug` is derived (prints the source pattern),
/// backing `{{…}}` interpolation through the runtime's `Debug`-based stringify fallback.
#[derive(Clone, Debug)]
pub struct Regex {
    re: Arc<regex::Regex>,
    max_input: usize,
}

crate::stringify::show_row!("Regex", Redacted, [] Regex, |_| crate::stringify::REDACTED_SHOW.to_owned());

/// `Regex.compile : String -> Result Error Regex` — THE construction boundary.
/// Every [`Regex`] value traces back to one of these calls; an invalid pattern
/// or a malformed `IPE_REGEX_MAX_INPUT_BYTES` surfaces here as a typed `Err`,
/// never anywhere downstream as a silent no-match or a default ceiling.
#[must_use]
pub fn regex_compile<E: From<String>>(pattern: String) -> IpeResult<E, Regex> {
    compile_within(&pattern, regex_input_ceiling())
}

/// Compiles `pattern` under an already parsed subject `ceiling`.
///
/// A refused ceiling is the `Err`, before the pattern is compiled.
fn compile_within<E: From<String>>(
    pattern: &str,
    ceiling: Result<usize, EnvCeilingRefusal>,
) -> IpeResult<E, Regex> {
    let max_input = match ceiling {
        Ok(max_input) => max_input,
        Err(refusal) => return IpeResult::Err(E::from(String::from(refusal))),
    };
    match regex::Regex::new(pattern) {
        Ok(re) => IpeResult::Ok(Regex {
            re: Arc::new(re),
            max_input,
        }),
        Err(e) => IpeResult::Err(format!("Ipe.Regex: invalid pattern: {e}").into()),
    }
}

/// `Regex.match : Regex -> String -> Bool` — does the pattern match anywhere?
/// A subject past the handle's ceiling yields `false` (fail-closed: absent a
/// bounded scan, the safe answer is "no proven match").
#[must_use]
pub fn regex_match(re: Regex, s: String) -> bool {
    within_input_ceiling(&re, &s) && re.re.is_match(&s)
}

/// `Regex.find : Regex -> String -> Maybe String` — first match, if any.
/// A subject past the handle's ceiling yields `Nothing` (fail-closed).
#[must_use]
pub fn regex_find(re: Regex, s: String) -> IpeMaybe<String> {
    if !within_input_ceiling(&re, &s) {
        return IpeMaybe::Nothing;
    }
    match re.re.find(&s) {
        Some(m) => IpeMaybe::Just(m.as_str().to_string()),
        None => IpeMaybe::Nothing,
    }
}

/// `Regex.findAll : Regex -> String -> List String` — every match, in order.
/// A subject past the handle's ceiling yields the empty list (fail-closed: no
/// unbounded `Vec<String>` collect over an oversized subject).
#[must_use]
pub fn regex_find_all(re: Regex, s: String) -> Vec<String> {
    if !within_input_ceiling(&re, &s) {
        return Vec::new();
    }
    re.re
        .find_iter(&s)
        .map(|m| m.as_str().to_string())
        .collect()
}

/// `Regex.replace : Regex -> String -> String -> String` — replace every match
/// with `replacement` (RE2 `$1` substitution syntax).
/// A subject past the handle's ceiling is returned unchanged (fail-closed: the
/// identity is the total safe outcome, applying no replacements rather than
/// scanning an oversized subject).
#[must_use]
pub fn regex_replace(re: Regex, replacement: String, s: String) -> String {
    if !within_input_ceiling(&re, &s) {
        return s;
    }
    re.re.replace_all(&s, replacement.as_str()).to_string()
}

/// `Regex.split : Regex -> String -> List String` — split on every match.
///
/// Splits on every non-overlapping match. Diverges from `Regex::split` on
/// zero-width matches: a zero-width match ending at byte 0 does NOT emit a
/// leading empty string, while interior zero-width matches still split.
/// Implements this by tracking the start of the most recent match manually.
#[must_use]
pub fn regex_split(re: Regex, s: String) -> Vec<String> {
    // A subject past the handle's ceiling yields the whole subject as one field
    // (fail-closed: the no-split outcome, applying no split rather than
    // collecting one owned String per match over an oversized subject).
    if !within_input_ceiling(&re, &s) {
        return vec![s];
    }
    // A non-empty pattern against empty input yields one empty field.
    if !re.re.as_str().is_empty() && s.is_empty() {
        return vec![String::new()];
    }
    let mut out: Vec<String> = Vec::new();
    let mut beg: usize = 0;
    // `end` tracks the START offset of the most recent match;
    // the trailing field is suppressed when it reaches len(s).
    let mut end: usize = 0;
    for m in re.re.find_iter(&s) {
        end = m.start();
        // Skip the field for a match ending at byte 0 — drops the leading
        // empty produced by a zero-width match at position 0. Match offsets
        // lie on char boundaries, so each piece is `Some`; a `None` pushes
        // nothing.
        if m.end() != 0
            && let Some(piece) = s.get(beg..end)
        {
            out.push(piece.to_string());
        }
        beg = m.end();
    }
    if end != s.len()
        && let Some(piece) = s.get(beg..)
    {
        out.push(piece.to_string());
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

    /// Compiles `pattern` under an explicit subject `ceiling`, as `Regex.compile`
    /// does under the parsed environment snapshot.
    fn within(pattern: &str, ceiling: usize) -> Option<Regex> {
        match compile_within::<String>(pattern, Ok(ceiling)) {
            IpeResult::Ok(re) => Some(re),
            IpeResult::Err(_) => None,
        }
    }

    /// Every malformed `IPE_REGEX_MAX_INPUT_BYTES` (zero included) makes the
    /// constructor return `Err` naming the variable, never a handle under the
    /// default ceiling.
    #[test]
    fn regex_ceiling_refuses_malformed() {
        use std::env::VarError;
        let refused = |raw: Result<String, VarError>| {
            let shown = format!("{raw:?}");
            let outcome = compile_within::<String>("a", REGEX_INPUT_CEILING.parse_as::<usize>(raw));
            assert!(
                matches!(&outcome, IpeResult::Err(e) if e.starts_with("IPE_REGEX_MAX_INPUT_BYTES")),
                "{shown} must be refused naming the variable"
            );
        };
        for raw in ["", "abc", "0", "-5", " 42", "16MiB", "18446744073709551616"] {
            refused(Ok(raw.to_owned()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt as _;
            refused(Err(VarError::NotUnicode(std::ffi::OsString::from_vec(
                vec![b'1', 0xFF],
            ))));
        }
        crate::system::assert_env_ceiling_contract(REGEX_INPUT_CEILING);
    }

    /// An absent variable compiles a handle under the 16 MiB default.
    #[test]
    fn regex_ceiling_absent_is_default() {
        let outcome = compile_within::<String>(
            "a",
            REGEX_INPUT_CEILING.parse_as::<usize>(Err(std::env::VarError::NotPresent)),
        );
        let max_input = match outcome {
            IpeResult::Ok(re) => Some(re.max_input),
            IpeResult::Err(_) => None,
        };
        assert_eq!(max_input, Some(16 * 1024 * 1024));
    }

    /// Every entrypoint judges a subject against the ceiling its handle carries.
    ///
    /// One byte past it takes the refused outcome, exactly at it is processed.
    /// The pattern matches the oversized subject, so the refusal is the ceiling,
    /// not an absent match.
    #[test]
    fn regex_handle_carries_its_ceiling() {
        #[allow(clippy::expect_used)] // a literal pattern under a literal ceiling
        let re = within(",", 3).expect("`,` compiles");
        let at_cap = "a,b".to_string();
        let past_cap = "a,b,".to_string();

        assert!(!regex_match(re.clone(), past_cap.clone()));
        assert!(matches!(
            regex_find(re.clone(), past_cap.clone()),
            IpeMaybe::Nothing
        ));
        assert!(regex_find_all(re.clone(), past_cap.clone()).is_empty());
        assert_eq!(
            regex_replace(re.clone(), ";".to_string(), past_cap.clone()),
            past_cap
        );
        assert_eq!(regex_split(re.clone(), past_cap.clone()), vec![past_cap]);

        assert!(regex_match(re.clone(), at_cap.clone()));
        assert!(matches!(
            regex_find(re.clone(), at_cap.clone()),
            IpeMaybe::Just(ref m) if m == ","
        ));
        assert_eq!(regex_find_all(re.clone(), at_cap.clone()), vec![","]);
        assert_eq!(
            regex_replace(re.clone(), ";".to_string(), at_cap.clone()),
            "a;b"
        );
        assert_eq!(regex_split(re, at_cap), vec!["a", "b"]);
    }

    /// Splitting a subject of multibyte characters yields whole characters, on a
    /// separator match and on zero-width matches between characters alike.
    #[test]
    fn regex_split_multibyte_subject() {
        assert_eq!(
            regex_split(ok(","), "é,日本,ü".to_string()),
            vec!["é", "日本", "ü"]
        );
        assert_eq!(regex_split(ok(""), "é日".to_string()), vec!["é", "日"]);
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
