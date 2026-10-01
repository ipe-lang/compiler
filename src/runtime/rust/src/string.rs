//! Ipe.String kernel — the single home for the String runtime surface.
//!

use super::IpeMaybe;

// ── Core String kernels (relocated from core.rs so the String surface has one home) ──

#[must_use]
pub fn string_from_int(i: i64) -> String {
    format!("{i}")
}
#[must_use]
pub fn string_join(sep: String, strs: Vec<String>) -> String {
    strs.join(&sep)
}
#[must_use]
pub fn string_append(mut a: String, b: String) -> String {
    a.push_str(&b);
    a
}
#[must_use]
pub fn string_length(s: String) -> i64 {
    s.chars().count() as i64
}
#[must_use]
pub fn string_is_empty(s: String) -> bool {
    s.is_empty()
}
#[must_use]
pub fn string_reverse(s: String) -> String {
    s.chars().rev().collect()
}
#[must_use]
pub fn string_to_upper(s: String) -> String {
    s.to_uppercase()
}
#[must_use]
pub fn string_to_lower(s: String) -> String {
    s.to_lowercase()
}
#[must_use]
pub fn string_trim(s: String) -> String {
    s.trim().to_string()
}
// Ipê `contains : String -> String -> Bool  -- contains sub str` (str contains
// sub). Args arrive as (sub, str), so test the SECOND against the first.
#[must_use]
pub fn string_contains(sub: String, s: String) -> bool {
    s.contains(&sub)
}
/// `String.toInt : String -> Maybe Int`. Leading and trailing Unicode
/// whitespace is trimmed before parsing (`str::trim` = the Unicode
/// `White_Space` property), so `String.toInt " 42 " == Just 42`, consistent
/// with `String.toFloat`. Interior whitespace or any non-digit content still
/// fails: `String.toInt "4 2" == Nothing`.
#[must_use]
pub fn string_to_int(s: String) -> IpeMaybe<i64> {
    match s.trim().parse::<i64>() {
        Ok(v) => IpeMaybe::Just(v),
        Err(_) => IpeMaybe::Nothing,
    }
}
/// `String.toFloat : String -> Maybe Float`. Leading and trailing Unicode
/// whitespace is trimmed before parsing (`str::trim` = the Unicode
/// `White_Space` property), so `String.toFloat " 1.5 " == Just 1.5`, consistent
/// with `String.toInt`.
///
/// `f64::from_str` accepts only the standard decimal / scientific grammar,
/// rejecting hex-float (`0x1p-2`) and underscore-digit-separator forms — these
/// never round-trip from `String.fromFloat`, so they are deliberately refused.
#[must_use]
pub fn string_to_float(s: String) -> IpeMaybe<f64> {
    match s.trim().parse::<f64>() {
        Ok(v) => IpeMaybe::Just(v),
        Err(_) => IpeMaybe::Nothing,
    }
}
/// `String.fromBool : Bool -> String` — the one canonical `Bool` rendering.
///
/// Lowercase `"true"` / `"false"`; `{{flag}}` interpolation renders through
/// this same function, so the two cannot disagree.
#[must_use]
pub fn string_from_bool(b: bool) -> String {
    if b { "true" } else { "false" }.to_owned()
}

/// `String.fromChar : Char -> String`.
#[must_use]
pub fn string_from_char(c: char) -> String {
    c.to_string()
}
/// `String.slice : Int -> Int -> String -> String`. Unicode-codepoint-indexed
/// with negative-index-from-end + clamping.
#[must_use]
pub fn string_slice(start: i64, end: i64, s: String) -> String {
    let runes: Vec<char> = s.chars().collect();
    let total = runes.len() as i64;
    let mut start = if start < 0 { start + total } else { start };
    let mut end = if end < 0 { end + total } else { end };
    if start < 0 {
        start = 0;
    }
    if end > total {
        end = total;
    }
    if start > end {
        return String::new();
    }
    // start/end are clamped to [0, total] with start <= end, so the slice is
    // valid; `.get` keeps it total regardless.
    runes
        .get(start as usize..end as usize)
        .map(|r| r.iter().collect())
        .unwrap_or_default()
}
/// `Ipe.String.left n s` — the first `n` characters (clamped; negative → "").
#[must_use]
pub fn string_left(n: i64, s: String) -> String {
    if n <= 0 {
        return String::new();
    }
    s.chars().take(n as usize).collect()
}
/// `Ipe.String.right n s` — the last `n` characters (clamped).
#[must_use]
pub fn string_right(n: i64, s: String) -> String {
    if n <= 0 {
        return String::new();
    }
    let runes: Vec<char> = s.chars().collect();
    let start = runes.len().saturating_sub(n as usize);
    runes
        .get(start..)
        .map(|r| r.iter().collect())
        .unwrap_or_default()
}
/// `String.fromFloat : Float -> String` — `'g'`-mode shortest-round-trip float.
///
/// Chooses positional form when the decimal exponent lands in `[-4, 6)` and
/// exponent form otherwise (`'g'`'s `eprec = 6` rule). Non-finite values render
/// as `+Inf` / `-Inf` / `NaN`; negative zero renders as `"-0"`.
///
/// WHY a hand-written helper: Rust's `{}` never uses exponent form and `{:e}`
/// always does; neither expresses `'g'`'s conditional rule on its own. Obtains
/// the shortest round-trip digits + scientific exponent from `{:e}`, then
/// re-renders under the positional-vs-exponent decision.
#[must_use]
pub fn string_from_float(f: f64) -> String {
    // Non-finite: infinities carry a sign (`+Inf` / `-Inf`).
    if f.is_nan() {
        return "NaN".to_string();
    }
    if f.is_infinite() {
        return if f < 0.0 { "-Inf" } else { "+Inf" }.to_string();
    }
    // Negative zero must keep its sign ("-0"); `is_sign_negative`
    // is the only check that distinguishes -0.0 from +0.0.
    let neg = f.is_sign_negative();
    if f == 0.0 {
        return if neg { "-0" } else { "0" }.to_string();
    }

    // `{:e}` yields the shortest round-trip form `d[.ddd]e<exp>` for the
    // magnitude; split it into significant digits and the scientific exponent.
    let sci = format!("{:e}", f.abs());
    // Unreachable for a finite f64 — `{:e}` always emits an `e`. Falling
    // back to the raw string keeps the function total rather than panicking.
    let Some((mantissa, exp_str)) = sci.split_once('e') else {
        return sci;
    };
    let sci_exp: i32 = exp_str.parse().unwrap_or(0);
    // Significant digits with the radix point removed: e.g. "1.256" -> "1256".
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();

    // Digit count and decimal-point position: the value is `digits * 10^(dp - nd)`;
    // `{:e}` puts one digit before the point, so `dp = sci_exp + 1`.
    let dp = sci_exp + 1;
    let exp = dp - 1; // the exponent `'g'` tests against, == sci_exp

    // `'g'` rule (shortest mode): positional `%f` for an exponent in `[-4, 6)`,
    // exponent `%e` otherwise.
    if (-4..6).contains(&exp) {
        fmt_g_positional(neg, &digits, dp)
    } else {
        fmt_g_exponent(neg, &digits, exp)
    }
}

/// `'g'`'s `%e` rendering (shortest mode): `d[.ddd]e±NN`, with the sign always
/// present and at least two exponent digits (`1e-05`, `1e+21`).
fn fmt_g_exponent(neg: bool, digits: &str, exp: i32) -> String {
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    let mut chars = digits.chars();
    if let Some(first) = chars.next() {
        out.push(first);
    }
    let rest: String = chars.collect();
    if !rest.is_empty() {
        out.push('.');
        out.push_str(&rest);
    }
    out.push('e');
    let (sign, mag) = if exp < 0 { ('-', -exp) } else { ('+', exp) };
    out.push(sign);
    if mag < 10 {
        // Pad to the two-digit minimum exponent width.
        out.push('0');
    }
    out.push_str(&mag.to_string());
    out
}

/// `'g'`'s `%f` rendering (shortest mode): `ddd[.ddd]`, padding the integer
/// part with zeros (`1500`) and reading fraction digits past the point.
fn fmt_g_positional(neg: bool, digits: &str, dp: i32) -> String {
    let bytes = digits.as_bytes();
    let nd = bytes.len() as i32;
    let frac = (nd - dp).max(0); // fractional digit count
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    // Integer part: the first `dp` digits, zero-padded if the value has more
    // integer places than significant digits (e.g. 1500 from digits "15").
    if dp > 0 {
        let take = nd.min(dp);
        for i in 0..take {
            if let Some(&b) = bytes.get(i as usize) {
                out.push(b as char);
            }
        }
        for _ in take..dp {
            out.push('0');
        }
    } else {
        out.push('0');
    }
    // Fraction: each place reads a significant digit when one exists at that
    // position, otherwise a zero (leading zeros for sub-1 values like 0.0001).
    if frac > 0 {
        out.push('.');
        for i in 0..frac {
            let j = dp + i;
            let ch = if j >= 0 && j < nd {
                bytes.get(j as usize).map_or(b'0', |&b| b)
            } else {
                b'0'
            };
            out.push(ch as char);
        }
    }
    out
}
/// `String.split : String -> String -> List String`. A non-empty separator
/// splits on each occurrence; an EMPTY separator splits `s` into individual
/// Unicode codepoints with NO leading/trailing empty sentinels — and
/// `split("", "")` yields the empty list. Rust's `str::split("")` emits
/// boundary `""` entries, so the empty-sep case is handled by codepoint
/// iteration.
#[must_use]
pub fn string_split(sep: String, s: String) -> Vec<String> {
    if sep.is_empty() {
        return s.chars().map(|c| c.to_string()).collect();
    }
    s.split(&sep)
        .map(std::string::ToString::to_string)
        .collect()
}
// Ipe.String.lines / .words — split on line breaks / runs of whitespace.
#[must_use]
pub fn string_lines(s: String) -> Vec<String> {
    s.lines().map(std::string::ToString::to_string).collect()
}
#[must_use]
pub fn string_words(s: String) -> Vec<String> {
    s.split_whitespace()
        .map(std::string::ToString::to_string)
        .collect()
}

// ── String kernels ──

/// Ipê `replace : String -> String -> String -> String`.
/// Replaces all occurrences of `old` with `new_` in `s`.
#[must_use]
pub fn string_replace(old: String, new_: String, s: String) -> String {
    s.replace(&old, &new_)
}

/// Ipê `startsWith : String -> String -> Bool`. `prefix` first, `s` second.
#[must_use]
pub fn string_starts_with(prefix: String, s: String) -> bool {
    s.starts_with(&prefix)
}

/// Ipê `endsWith : String -> String -> Bool`. `suffix` first, `s` second.
#[must_use]
pub fn string_ends_with(suffix: String, s: String) -> bool {
    s.ends_with(&suffix)
}

// ── Haystack-first companions (`*In`) ────────────────────────────────────────
// Ipê `containsIn : String -> String -> Bool  -- containsIn haystack needle`.
// Args arrive in Ipê order `(haystack, needle)`, so the runtime signature is
// haystack-first — the exact opposite operand order of `string_contains`.
// Defined as a delegation so the single substring check stays in one place.
#[must_use]
pub fn string_contains_in(haystack: String, needle: String) -> bool {
    string_contains(needle, haystack)
}

/// Ipê `startsWithIn : String -> String -> Bool  -- startsWithIn haystack prefix`.
/// Haystack-first companion of `startsWith`.
#[must_use]
pub fn string_starts_with_in(haystack: String, prefix: String) -> bool {
    string_starts_with(prefix, haystack)
}

/// Ipê `endsWithIn : String -> String -> Bool  -- endsWithIn haystack suffix`.
/// Haystack-first companion of `endsWith`.
#[must_use]
pub fn string_ends_with_in(haystack: String, suffix: String) -> bool {
    string_ends_with(suffix, haystack)
}

/// Ipê `repeat : Int -> String -> String`. Non-positive `n` returns "".
///
/// `n` is caller-controlled; `n * s.len()` can overflow or exhaust memory, so
/// the result is bounded at a 64 MiB ceiling. Past the ceiling the count is
/// clamped to the whole copies that fit rather than collapsed to "": the output
/// stays a genuine prefix of the requested repetition, never a silent empty
/// string that a caller could not tell apart from a legitimate `repeat 0 s`.
#[must_use]
pub fn string_repeat(n: i64, s: String) -> String {
    if n <= 0 || s.is_empty() {
        return String::new();
    }
    const CAP: u64 = 64 * 1024 * 1024;
    let len = s.len() as u64;
    let want = n as u64;
    // Whole copies that fit under the cap; `len > 0` here, so no divide-by-zero.
    let max_fit = CAP / len;
    // At least one whole copy for a non-empty `s` with `n > 0` — never collapse to
    // "" (indistinguishable from `repeat 0 s`). When a single copy already exceeds
    // the 64 MiB repetition ceiling, emit exactly that one copy: `s` is already
    // materialised at `len`, so this is a bounded ~2x transient, not an
    // input-dictated blowup. The cap bounds repetition, not the size of `s` itself.
    let copies = want.min(max_fit).max(1);
    // `copies` is `1` (single-copy case) or `<= max_fit` (so `copies * len <= CAP`);
    // either way it fits `usize` on a 64-bit target, so the cast cannot truncate.
    s.repeat(copies as usize)
}

/// `String.concat : List String -> String`
/// Concatenates a list of strings with no separator.
#[must_use]
pub fn string_concat(parts: Vec<String>) -> String {
    let mut out = String::new();
    for p in parts {
        out.push_str(&p);
    }
    out
}

/// `String.casefold : String -> String`
/// Unicode-aware case-fold for locale-neutral case-insensitive comparison.
/// Uses `to_lowercase()` which performs full Unicode case folding.
#[must_use]
pub fn string_casefold(s: String) -> String {
    s.to_lowercase()
}

/// `String.dropLeft : Int -> String -> String`
/// Drops the first `n` codepoints. Elm semantics:
/// negative n → s unchanged; n >= length → "".
#[must_use]
pub fn string_drop_left(n: i64, s: String) -> String {
    if n <= 0 {
        return s;
    }
    let mut chars = s.chars();
    for _ in 0..n {
        if chars.next().is_none() {
            return String::new();
        }
    }
    chars.collect()
}

/// `String.dropRight : Int -> String -> String`
/// Drops the last `n` codepoints. Elm semantics:
/// negative n → s unchanged; n >= length → "".
#[must_use]
pub fn string_drop_right(n: i64, s: String) -> String {
    if n <= 0 {
        return s;
    }
    let runes: Vec<char> = s.chars().collect();
    let len = runes.len() as i64;
    if n >= len {
        return String::new();
    }
    // 0 < len-n < len here (n>0 and n<len guarded above), so `take` keeps the
    // leading runes. `take` is total (never panics) — clippy flags the `[..k]`
    // slice form even though the bound is guaranteed, so use the iterator form.
    runes.iter().take((len - n) as usize).collect()
}

/// `String.equalFold : String -> String -> Bool`
/// Case-insensitive Unicode-aware string equality.
#[must_use]
pub fn string_equal_fold(a: String, b: String) -> bool {
    // `to_lowercase()` is the same transform used in `string_casefold`.
    a.to_lowercase() == b.to_lowercase()
}

/// `String.fromList : List Char -> String`
/// Concatenates a list of `Char` values into a UTF-8 string.
#[must_use]
pub fn string_from_list(chars: Vec<char>) -> String {
    chars.into_iter().collect()
}

/// True for an unquoted RFC 5321 local-part atom character: `ALPHA` / `DIGIT`
/// and the atext specials `!#$%&'*+/=?^_`{|}~-`. The `.` separator is handled
/// by the label walk, not here, so a bare `.` is not an atom character.
fn is_local_atext(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+/=?^_`{|}~-".contains(c)
}

/// True when `part` is a dot-separated sequence of non-empty runs of
/// characters satisfying `atom_char` — i.e. no leading dot, no trailing dot,
/// and no empty label from a `..`. An empty `part` is rejected.
fn is_dot_atom(part: &str, atom_char: impl Fn(char) -> bool) -> bool {
    if part.is_empty() {
        return false;
    }
    part.split('.')
        .all(|label| !label.is_empty() && label.chars().all(&atom_char))
}

/// True when `label` is a legal RFC 5321 domain label: a non-empty run of
/// `ALPHA` / `DIGIT` / `-` with neither a leading nor a trailing hyphen.
fn is_domain_label(label: &str) -> bool {
    !label.is_empty()
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// `String.isEmail : String -> Bool`
/// Syntactic check for an RFC 5321 dot-atom mailbox. Does NOT verify the
/// mailbox exists.
///
/// Fail-closed: absent proof the address is a legal dot-atom mailbox it is
/// rejected. Only bare `user@host` is accepted — no `Name <user@host>`
/// wrapping, no quoted-string local part, no address-literal domain.
///
/// - exactly one `@`, splitting a non-empty local part from a non-empty domain
/// - local part is an unquoted dot-atom: each `.`-separated label non-empty
///   (so no leading/trailing/consecutive dot) and drawn from `ALPHA` / `DIGIT`
///   plus `!#$%&'*+/=?^_`{|}~-`
/// - domain is at least two dot-atom labels (so it carries a `.`); each label
///   is `ALPHA` / `DIGIT` / `-` with no leading/trailing hyphen and non-empty
///   (so no leading/trailing/consecutive dot)
///
/// (No regex crate needed for this level of validation.)
#[must_use]
pub fn string_is_email(s: String) -> bool {
    let s = s.trim();
    // Exactly one `@`: a missing or a second `@` is not a dot-atom mailbox.
    let mut parts = s.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if !is_dot_atom(local, is_local_atext) {
        return false;
    }
    // A mailbox domain needs at least two labels so it carries a separating
    // `.` (`user@example` is not a deliverable domain).
    let mut labels = domain.split('.');
    let has_two_labels = labels.by_ref().take(2).count() == 2;
    if !has_two_labels {
        return false;
    }
    domain.split('.').all(is_domain_label)
}

// `String.isUrl` (`string_is_url`) is the sole `regex`-crate consumer outside the
// `Ipe.Regex` kernels, so its validator body lives in `regex_kernel.rs` — behind
// the `regex` feature — keeping this always-compiled module free of the `regex`
// crate. `String.isUrl` therefore reaches the `regex_kernel` module and selects
// the `regex` feature, exactly like an `Ipe.Regex` kernel.

/// Ceiling on any pad target width. `n` is caller-controlled; an unbounded
/// value would OOM on the fill loop, so every pad builder refuses past this.
const MAX_PAD_WIDTH: i64 = 16_000_000;

/// Bounded number of pad characters to add to reach target width `n` from an
/// `have`-codepoint string. `None` when no padding is needed (`n <= have`) or
/// when `n` exceeds `MAX_PAD_WIDTH` — the caller returns the string unchanged,
/// so no pad builder can exhaust the allocator on caller-controlled `n`.
fn bounded_pad_count(n: i64, have: i64) -> Option<usize> {
    if n <= have || n > MAX_PAD_WIDTH {
        return None;
    }
    Some((n - have) as usize)
}

/// `String.padLeft : Int -> Char -> String -> String`
/// Pads `s` on the left with `ch` until `s` is at least `n` Unicode codepoints
/// wide. Returns `s` unchanged when already `n` or more codepoints wide.
#[must_use]
pub fn string_pad_left(n: i64, ch: char, s: String) -> String {
    let rune_count = s.chars().count() as i64;
    let Some(pad_count) = bounded_pad_count(n, rune_count) else {
        return s;
    };
    let mut out = String::with_capacity(s.len() + pad_count);
    for _ in 0..pad_count {
        out.push(ch);
    }
    out.push_str(&s);
    out
}

/// `String.padRight : Int -> Char -> String -> String`
/// Pads `s` on the right with `ch` until `s` is at least `n` Unicode codepoints
/// wide. Returns `s` unchanged when already `n` or more codepoints wide.
#[must_use]
pub fn string_pad_right(n: i64, ch: char, s: String) -> String {
    let rune_count = s.chars().count() as i64;
    let Some(pad_count) = bounded_pad_count(n, rune_count) else {
        return s;
    };
    let mut out = String::with_capacity(s.len() + pad_count);
    out.push_str(&s);
    for _ in 0..pad_count {
        out.push(ch);
    }
    out
}

/// `String.toList : String -> List Char`
/// Decomposes a string into its Unicode code points.
#[must_use]
pub fn string_to_list(s: String) -> Vec<char> {
    s.chars().collect()
}

/// `String.cons : Char -> String -> String` — prepend a character.
#[must_use]
pub fn string_cons(c: char, s: String) -> String {
    let mut out = String::with_capacity(s.len() + c.len_utf8());
    out.push(c);
    out.push_str(&s);
    out
}

/// `String.uncons : String -> Maybe (Char, String)` — split off the first
/// character; `Nothing` on the empty string. Code-point (rune) based.
#[must_use]
pub fn string_uncons(s: String) -> IpeMaybe<(char, String)> {
    let mut it = s.chars();
    match it.next() {
        Some(c) => IpeMaybe::Just((c, it.collect())),
        None => IpeMaybe::Nothing,
    }
}

/// `String.pad : Int -> Char -> String -> String` — centre-pad `s` to width `n`
/// with `ch`. Matches Elm: extra padding on the RIGHT when the total is odd.
/// `n <= length s` returns `s` unchanged.
#[must_use]
pub fn string_pad(n: i64, ch: char, s: String) -> String {
    let len = s.chars().count() as i64;
    let Some(total) = bounded_pad_count(n, len) else {
        return s;
    };
    let left = total / 2;
    let right = total - left;
    let mut out = String::with_capacity(s.len() + total);
    for _ in 0..left {
        out.push(ch);
    }
    out.push_str(&s);
    for _ in 0..right {
        out.push(ch);
    }
    out
}

/// `String.indexes : String -> String -> List Int` — every code-point start
/// index of `sub` within `s` (overlapping matches included, mirroring Elm).
/// Empty `sub` yields `[]` (matches Elm).
#[must_use]
pub fn string_indexes(sub: String, s: String) -> Vec<i64> {
    if sub.is_empty() {
        return Vec::new();
    }
    let hay: Vec<char> = s.chars().collect();
    let needle: Vec<char> = sub.chars().collect();
    let mut out = Vec::new();
    if needle.len() > hay.len() {
        return out;
    }
    // Slide a window in CODE-POINT space so the returned indices are rune
    // offsets (consistent with the rest of the module), not byte offsets.
    for start in 0..=(hay.len() - needle.len()) {
        if hay
            .get(start..start + needle.len())
            .is_some_and(|w| w == needle.as_slice())
        {
            out.push(start as i64);
        }
    }
    out
}

/// `String.map : (Char -> Char) -> String -> String` — transform each rune.
pub fn string_map(f: impl Fn(char) -> char, s: String) -> String {
    s.chars().map(f).collect()
}

/// `String.filter : (Char -> Bool) -> String -> String` — keep matching runes.
pub fn string_filter(pred: impl Fn(char) -> bool, s: String) -> String {
    s.chars().filter(|c| pred(*c)).collect()
}

/// `String.foldl : (Char -> b -> b) -> b -> String -> b` — fold left over runes.
pub fn string_foldl<B>(f: impl Fn(char, B) -> B, init: B, s: String) -> B {
    let mut acc = init;
    for c in s.chars() {
        acc = f(c, acc);
    }
    acc
}

/// `String.foldr : (Char -> b -> b) -> b -> String -> b` — fold right over runes.
pub fn string_foldr<B>(f: impl Fn(char, B) -> B, init: B, s: String) -> B {
    let mut acc = init;
    for c in s.chars().rev() {
        acc = f(c, acc);
    }
    acc
}

/// `String.any : (Char -> Bool) -> String -> Bool`.
pub fn string_any(pred: impl Fn(char) -> bool, s: String) -> bool {
    s.chars().any(pred)
}

/// `String.all : (Char -> Bool) -> String -> Bool`.
pub fn string_all(pred: impl Fn(char) -> bool, s: String) -> bool {
    s.chars().all(pred)
}

/// `String.trimStart : String -> String`
/// Removes leading Unicode whitespace (includes NBSP, various space categories,
/// BOM — see `unicode_is_space`).
pub fn string_trim_start(s: String) -> String {
    s.trim_start_matches(unicode_is_space).to_string()
}

/// `String.trimEnd : String -> String`
/// Removes trailing Unicode whitespace. Same whitespace set as `trimStart`.
pub fn string_trim_end(s: String) -> String {
    s.trim_end_matches(unicode_is_space).to_string()
}

/// Whitespace predicate: covers ASCII whitespace, NBSP (U+00A0), general-
/// category Zs (U+2000–U+200A), line/paragraph separators (U+2028/U+2029),
/// ideographic space (U+3000), and BOM (U+FEFF).
fn unicode_is_space(c: char) -> bool {
    matches!(
        c,
        ' ' | '\t' | '\n' | '\r' | '\x0B' | '\x0C'  // ASCII whitespace + VT/FF
        | '\u{00A0}'                                   // NBSP
        | '\u{2000}'
            ..='\u{200A}'                      // En quad … Hair space
        | '\u{2028}'                                   // Line separator
        | '\u{2029}'                                   // Paragraph separator
        | '\u{3000}'                                   // Ideographic space
        | '\u{FEFF}' // BOM / Zero-width NBSP
    )
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn test_from_bool_lowercase() {
        assert_eq!(string_from_bool(true), "true");
        assert_eq!(string_from_bool(false), "false");
    }
    #[test]
    fn test_replace_simple() {
        assert_eq!(
            string_replace("foo".into(), "bar".into(), "foofoo".into()),
            "barbar"
        );
    }
    #[test]
    fn test_replace_no_match() {
        assert_eq!(string_replace("x".into(), "y".into(), "abc".into()), "abc");
    }
    #[test]
    fn test_replace_empty_old() {
        assert_eq!(
            string_replace(String::new(), "_".into(), "abc".into()),
            "_a_b_c_"
        );
    }

    #[test]
    fn test_starts_with_hit() {
        assert!(string_starts_with("he".into(), "hello".into()));
    }
    #[test]
    fn test_starts_with_miss() {
        assert!(!string_starts_with("xy".into(), "hello".into()));
    }
    #[test]
    fn test_starts_with_empty_prefix() {
        assert!(string_starts_with(String::new(), "hello".into()));
    }

    #[test]
    fn test_ends_with_hit() {
        assert!(string_ends_with("lo".into(), "hello".into()));
    }
    #[test]
    fn test_ends_with_miss() {
        assert!(!string_ends_with("xy".into(), "hello".into()));
    }

    #[test]
    fn test_repeat_three() {
        assert_eq!(string_repeat(3, "ab".into()), "ababab");
    }
    #[test]
    fn test_repeat_zero() {
        assert_eq!(string_repeat(0, "ab".into()), "");
    }
    #[test]
    fn test_repeat_negative() {
        assert_eq!(string_repeat(-1, "ab".into()), "");
    }
    #[test]
    fn test_repeat_empty_string() {
        assert_eq!(string_repeat(1_000, String::new()), "");
    }
    #[test]
    fn test_repeat_over_cap_clamps_to_prefix_not_empty() {
        // A request whose n * len(s) blows past the 64 MiB ceiling must not
        // collapse to "" for a non-empty s (that would be indistinguishable
        // from a legitimate `repeat 0 s`). It clamps to the whole copies that
        // fit, so the output stays a genuine prefix of the requested string.
        const CAP: usize = 64 * 1024 * 1024;
        let s = "ab"; // len 2
        let n: i64 = 100_000_000; // 2 * 1e8 = 200 MB, far past the cap
        let out = string_repeat(n, s.into());
        assert!(
            !out.is_empty(),
            "over-cap repeat of a non-empty string must not return \"\""
        );
        assert!(out.len() <= CAP, "clamped output must respect the ceiling");
        // The clamped output is exactly the whole copies that fit — a prefix.
        let fit = CAP / s.len();
        assert_eq!(out, s.repeat(fit));
        assert!(out.starts_with(s), "clamped output is a prefix of s*");
    }
    #[test]
    fn test_repeat_single_copy_exceeds_cap_still_emits_one_copy() {
        // When a SINGLE copy of `s` already exceeds the 64 MiB repetition
        // ceiling, `n > 0` must still yield exactly one whole copy — never "".
        // (`s` is already materialised, so one copy is a bounded transient.)
        const CAP: usize = 64 * 1024 * 1024;
        let big = "a".repeat(CAP + 1); // one copy already over the ceiling
        let out = string_repeat(5, big.clone());
        assert_eq!(
            out, big,
            "a non-empty s larger than the cap must repeat to exactly one copy, not \"\""
        );
    }

    // string_from_float — `'g'`-mode shortest-round-trip (FormatFloat 'g' -1 64
    // semantics). Ground-truth expected values from reference-audit.md.
    #[test]
    fn ff_small_exponent() {
        assert_eq!(string_from_float(0.00001), "1e-05");
    }
    #[test]
    fn ff_tiny_exponent() {
        assert_eq!(string_from_float(1e-10), "1e-10");
    }
    #[test]
    fn ff_huge_exponent() {
        assert_eq!(string_from_float(1e21), "1e+21");
    }
    #[test]
    fn ff_e5_neg_exponent() {
        assert_eq!(string_from_float(1e-5), "1e-05");
    }
    #[test]
    fn ff_whole_positional() {
        assert_eq!(string_from_float(1500.0), "1500");
    }
    #[test]
    fn ff_simple_fraction() {
        assert_eq!(string_from_float(1.5), "1.5");
    }
    #[test]
    fn ff_two_fraction() {
        assert_eq!(string_from_float(12.56), "12.56");
    }
    #[test]
    fn ff_sub_one_positional() {
        assert_eq!(string_from_float(0.0001), "0.0001");
    }
    #[test]
    fn ff_e6_flips_to_exponent() {
        assert_eq!(string_from_float(1e6), "1e+06");
    }
    #[test]
    fn ff_e5_stays_positional() {
        assert_eq!(string_from_float(1e5), "100000");
    }
    #[test]
    fn ff_g_threshold_is_six_not_twentyone() {
        // The `'g'` threshold is exp>=6 (reference-audit.md item 27).
        assert_eq!(string_from_float(999_999.0), "999999"); // exp 5 positional
        assert_eq!(string_from_float(1_000_001.0), "1.000001e+06"); // exp 6 scientific
        assert_eq!(string_from_float(1e15), "1e+15"); // 21 would print 16 zeros
        assert_eq!(string_from_float(1e20), "1e+20"); // 21 would print 21 digits
    }
    #[test]
    fn ff_many_fraction() {
        assert_eq!(string_from_float(123_456.789), "123456.789");
    }
    #[test]
    fn ff_pos_inf() {
        assert_eq!(string_from_float(f64::INFINITY), "+Inf");
    }
    #[test]
    fn ff_neg_inf() {
        assert_eq!(string_from_float(f64::NEG_INFINITY), "-Inf");
    }
    #[test]
    fn ff_nan() {
        assert_eq!(string_from_float(f64::NAN), "NaN");
    }
    #[test]
    fn ff_pos_zero() {
        assert_eq!(string_from_float(0.0), "0");
    }
    #[test]
    fn ff_neg_zero() {
        assert_eq!(string_from_float(-0.0), "-0");
    }
    #[test]
    fn ff_negative() {
        assert_eq!(string_from_float(-1.5), "-1.5");
    }

    // ── Elm behaviour verdicts (float formatting) ─────────────────────────────
    // `String.fromFloat` uses `'g'`-mode shortest-round-trip formatting. Where
    // that diverges from Elm's JS `String(f)`, the divergence is recorded in
    // `docs/topics/elm-coverage/behaviour-verdicts.md` (verdict: keep-ours).
    // These tests pin the exact points of agreement and divergence.

    // Agrees with Elm: an integral float drops its fraction.
    #[test]
    fn verdict_integral_float_has_no_fraction() {
        assert_eq!(string_from_float(1.0), "1");
    }

    // Agrees with Elm: the shortest round-tripping digits are emitted, so
    // `0.1 + 0.2` surfaces its true binary value rather than a rounded "0.3".
    #[test]
    fn verdict_shortest_round_trip_digits() {
        assert_eq!(string_from_float(0.1 + 0.2), "0.30000000000000004");
    }

    // Diverges from Elm: the exponent is padded to two digits (`1e-07`);
    // Elm's JS `String(1e-7)` yields `1e-7`. Ipê keeps two-digit exponents (documented).
    #[test]
    fn verdict_small_exponent_is_two_digit_padded_unlike_elm() {
        assert_eq!(string_from_float(1e-7), "1e-07");
    }

    // Diverges from Elm: negative zero keeps its sign (`-0`); Elm's JS
    // `String(-0)` collapses it to `0`. Ipê keeps the sign (documented).
    #[test]
    fn verdict_negative_zero_keeps_sign_unlike_elm() {
        assert_eq!(string_from_float(-0.0), "-0");
    }

    // ── New kernels ───────────────────────────────────────────────────────────

    // string_concat
    #[test]
    fn test_concat_basic() {
        assert_eq!(
            string_concat(vec!["foo".into(), "bar".into(), "baz".into()]),
            "foobarbaz"
        );
    }
    #[test]
    fn test_concat_empty_list() {
        assert_eq!(string_concat(vec![]), "");
    }
    #[test]
    fn test_concat_unicode() {
        assert_eq!(
            string_concat(vec!["héllo".into(), " ".into(), "wörld".into()]),
            "héllo wörld"
        );
    }

    // string_casefold
    #[test]
    fn test_casefold_upper() {
        assert_eq!(string_casefold("HELLO".into()), "hello");
    }
    #[test]
    fn test_casefold_mixed() {
        assert_eq!(string_casefold("CaFé".into()), "café");
    }
    #[test]
    fn test_casefold_empty() {
        assert_eq!(string_casefold(String::new()), "");
    }

    // string_drop_left
    #[test]
    fn test_drop_left_basic() {
        assert_eq!(string_drop_left(2, "hello".into()), "llo");
    }
    #[test]
    fn test_drop_left_zero() {
        assert_eq!(string_drop_left(0, "hello".into()), "hello");
    }
    #[test]
    fn test_drop_left_negative() {
        assert_eq!(string_drop_left(-1, "hello".into()), "hello");
    }
    #[test]
    fn test_drop_left_exact() {
        assert_eq!(string_drop_left(5, "hello".into()), "");
    }
    #[test]
    fn test_drop_left_over() {
        assert_eq!(string_drop_left(99, "hello".into()), "");
    }
    #[test]
    fn test_drop_left_unicode() {
        assert_eq!(string_drop_left(1, "héllo".into()), "éllo");
    }

    // string_drop_right
    #[test]
    fn test_drop_right_basic() {
        assert_eq!(string_drop_right(2, "hello".into()), "hel");
    }
    #[test]
    fn test_drop_right_zero() {
        assert_eq!(string_drop_right(0, "hello".into()), "hello");
    }
    #[test]
    fn test_drop_right_negative() {
        assert_eq!(string_drop_right(-1, "hello".into()), "hello");
    }
    #[test]
    fn test_drop_right_exact() {
        assert_eq!(string_drop_right(5, "hello".into()), "");
    }
    #[test]
    fn test_drop_right_over() {
        assert_eq!(string_drop_right(99, "hello".into()), "");
    }
    #[test]
    fn test_drop_right_unicode() {
        assert_eq!(string_drop_right(1, "héllo".into()), "héll");
    }

    // string_equal_fold
    #[test]
    fn test_equal_fold_same() {
        assert!(string_equal_fold("hello".into(), "HELLO".into()));
    }
    #[test]
    fn test_equal_fold_diff() {
        assert!(!string_equal_fold("hello".into(), "world".into()));
    }
    #[test]
    fn test_equal_fold_unicode() {
        assert!(string_equal_fold("café".into(), "CAFÉ".into()));
    }
    #[test]
    fn test_equal_fold_empty() {
        assert!(string_equal_fold(String::new(), String::new()));
    }

    // string_from_list
    #[test]
    fn test_from_list_basic() {
        assert_eq!(string_from_list(vec!['h', 'i']), "hi");
    }
    #[test]
    fn test_from_list_empty() {
        assert_eq!(string_from_list(vec![]), "");
    }
    #[test]
    fn test_from_list_unicode() {
        assert_eq!(string_from_list(vec!['é', 'à']), "éà");
    }

    // string_is_email
    #[test]
    fn test_is_email_valid() {
        assert!(string_is_email("user@example.com".into()));
    }
    #[test]
    fn test_is_email_no_at() {
        assert!(!string_is_email("userexample.com".into()));
    }
    #[test]
    fn test_is_email_no_domain_dot() {
        assert!(!string_is_email("user@example".into()));
    }
    #[test]
    fn test_is_email_name_component() {
        assert!(!string_is_email("Foo Bar <foo@bar.com>".into()));
    }
    #[test]
    fn test_is_email_empty() {
        assert!(!string_is_email(String::new()));
    }
    #[test]
    fn test_is_email_with_plus() {
        assert!(string_is_email("user+tag@example.com".into()));
    }
    #[test]
    fn test_is_email_dot_atom_specials_accepted() {
        // Every atext special in the local part is a legal dot-atom character.
        assert!(string_is_email("a!#$%&'*+/=?^_`{|}~-b@example.com".into()));
    }
    #[test]
    fn test_is_email_subdomain_accepted() {
        assert!(string_is_email("user@mail.example.co.uk".into()));
    }
    #[test]
    fn test_is_email_hyphen_in_label_accepted() {
        // A hyphen inside (not leading/trailing) a domain label is legal.
        assert!(string_is_email("user@my-host.example.com".into()));
    }
    #[test]
    fn test_is_email_reject_comma_local() {
        assert!(!string_is_email("a,b@example.com".into()));
    }
    #[test]
    fn test_is_email_reject_semicolon_local() {
        assert!(!string_is_email("a;b@example.com".into()));
    }
    #[test]
    fn test_is_email_reject_quoted_local() {
        assert!(!string_is_email("\"quoted\"@x.com".into()));
    }
    #[test]
    fn test_is_email_reject_leading_dot_local() {
        assert!(!string_is_email(".a@b.co".into()));
    }
    #[test]
    fn test_is_email_reject_trailing_dot_local() {
        assert!(!string_is_email("a.@b.co".into()));
    }
    #[test]
    fn test_is_email_reject_double_dot_local() {
        assert!(!string_is_email("a..b@b.co".into()));
    }
    #[test]
    fn test_is_email_reject_leading_hyphen_label() {
        assert!(!string_is_email("a@-b.co".into()));
    }
    #[test]
    fn test_is_email_reject_trailing_hyphen_label() {
        assert!(!string_is_email("a@b-.co".into()));
    }
    #[test]
    fn test_is_email_reject_double_dot_domain() {
        assert!(!string_is_email("foo@bar..com".into()));
    }
    #[test]
    fn test_is_email_reject_trailing_dot_domain() {
        assert!(!string_is_email("foo@bar.com.".into()));
    }
    #[test]
    fn test_is_email_reject_leading_dot_domain() {
        assert!(!string_is_email("foo@.bar.com".into()));
    }
    #[test]
    fn test_is_email_reject_second_at() {
        assert!(!string_is_email("a@b@c.com".into()));
    }
    #[test]
    fn test_is_email_reject_control_char() {
        // A C0 control (here CR) is outside atext — kept rejected so no
        // SMTP-header-injection address slips the seal.
        assert!(!string_is_email("a\rb@example.com".into()));
    }

    // string_pad_left
    #[test]
    fn test_pad_left_basic() {
        assert_eq!(string_pad_left(5, '0', "42".into()), "00042");
    }
    #[test]
    fn test_pad_left_already_wide() {
        assert_eq!(string_pad_left(3, '0', "hello".into()), "hello");
    }
    #[test]
    fn test_pad_left_zero_n() {
        assert_eq!(string_pad_left(0, ' ', "x".into()), "x");
    }
    #[test]
    fn test_pad_left_unicode_pad() {
        assert_eq!(string_pad_left(4, '★', "ab".into()), "★★ab");
    }
    #[test]
    fn test_pad_left_unicode_str() {
        assert_eq!(string_pad_left(4, '-', "éà".into()), "--éà");
    }

    // string_pad_right
    #[test]
    fn test_pad_right_basic() {
        assert_eq!(string_pad_right(5, '-', "x".into()), "x----");
    }
    #[test]
    fn test_pad_right_already_wide() {
        assert_eq!(string_pad_right(2, '-', "hello".into()), "hello");
    }
    #[test]
    fn test_pad_right_zero_n() {
        assert_eq!(string_pad_right(0, ' ', "x".into()), "x");
    }
    #[test]
    fn test_pad_right_unicode_pad() {
        assert_eq!(string_pad_right(4, '★', "ab".into()), "ab★★");
    }

    // string_to_list
    #[test]
    fn test_to_list_basic() {
        assert_eq!(string_to_list("hi".into()), vec!['h', 'i']);
    }
    #[test]
    fn test_to_list_empty() {
        assert_eq!(string_to_list(String::new()), Vec::<char>::new());
    }
    #[test]
    fn test_to_list_unicode() {
        assert_eq!(string_to_list("éà".into()), vec!['é', 'à']);
    }

    // string_trim_start
    #[test]
    fn test_trim_start_spaces() {
        assert_eq!(string_trim_start("  hello".into()), "hello");
    }
    #[test]
    fn test_trim_start_tabs() {
        assert_eq!(string_trim_start("\t\nhello".into()), "hello");
    }
    #[test]
    fn test_trim_start_nbsp() {
        assert_eq!(string_trim_start("\u{00A0}hello".into()), "hello");
    }
    #[test]
    fn test_trim_start_no_trailing() {
        assert_eq!(string_trim_start("  hello  ".into()), "hello  ");
    }
    #[test]
    fn test_trim_start_empty() {
        assert_eq!(string_trim_start(String::new()), "");
    }

    // string_trim_end
    #[test]
    fn test_trim_end_spaces() {
        assert_eq!(string_trim_end("hello  ".into()), "hello");
    }
    #[test]
    fn test_trim_end_mixed() {
        assert_eq!(string_trim_end("hello\t\n".into()), "hello");
    }
    #[test]
    fn test_trim_end_nbsp() {
        assert_eq!(string_trim_end("hello\u{00A0}".into()), "hello");
    }
    #[test]
    fn test_trim_end_no_leading() {
        assert_eq!(string_trim_end("  hello  ".into()), "  hello");
    }
    #[test]
    fn test_trim_end_empty() {
        assert_eq!(string_trim_end(String::new()), "");
    }

    // string_split
    #[test]
    fn test_split_nonempty_sep() {
        assert_eq!(
            string_split(",".into(), "a,b,c".into()),
            vec!["a", "b", "c"]
        );
    }
    #[test]
    fn test_split_empty_sep_runes() {
        assert_eq!(
            string_split(String::new(), "abc".into()),
            vec!["a", "b", "c"]
        );
    }
    #[test]
    fn test_split_empty_sep_unicode() {
        assert_eq!(
            string_split(String::new(), "héi".into()),
            vec!["h", "é", "i"]
        );
    }
    #[test]
    fn test_split_empty_sep_empty_str() {
        assert_eq!(
            string_split(String::new(), String::new()),
            Vec::<String>::new()
        );
    }
    #[test]
    fn test_split_trailing_sep() {
        assert_eq!(string_split(",".into(), "a,".into()), vec!["a", ""]);
    }

    // string_to_int — leading/trailing Unicode whitespace is trimmed before
    // parsing; interior whitespace or any non-digit content still fails.
    #[test]
    fn test_to_int_plain() {
        assert!(matches!(string_to_int("42".into()), IpeMaybe::Just(42)));
    }
    #[test]
    fn test_to_int_negative() {
        assert!(matches!(string_to_int("-5".into()), IpeMaybe::Just(-5)));
    }
    #[test]
    fn test_to_int_trims_leading() {
        assert!(matches!(string_to_int(" 42".into()), IpeMaybe::Just(42)));
    }
    #[test]
    fn test_to_int_trims_trailing() {
        assert!(matches!(string_to_int("42 ".into()), IpeMaybe::Just(42)));
    }
    #[test]
    fn test_to_int_trims_both() {
        assert!(matches!(string_to_int(" 42 ".into()), IpeMaybe::Just(42)));
    }
    #[test]
    fn test_to_int_interior_whitespace() {
        assert!(matches!(string_to_int("4 2".into()), IpeMaybe::Nothing));
    }
    #[test]
    fn test_to_int_garbage() {
        assert!(matches!(string_to_int("4x".into()), IpeMaybe::Nothing));
    }

    // string_to_float — Unicode-whitespace trim
    // 1.5 and 1e3 are exactly representable IEEE 754 values; direct equality is correct.
    #[test]
    #[allow(clippy::float_cmp)]
    fn test_to_float_plain() {
        assert!(matches!(string_to_float("1.5".into()), IpeMaybe::Just(v) if v == 1.5));
    }
    #[test]
    #[allow(clippy::float_cmp)]
    fn test_to_float_trimmed() {
        assert!(matches!(string_to_float("  1.5\n".into()), IpeMaybe::Just(v) if v == 1.5));
    }
    #[test]
    #[allow(clippy::float_cmp)]
    fn test_to_float_scientific() {
        assert!(matches!(string_to_float(" 1e3 ".into()), IpeMaybe::Just(v) if v == 1000.0));
    }
    #[test]
    fn test_to_float_garbage() {
        assert!(matches!(string_to_float("1.2.3".into()), IpeMaybe::Nothing));
    }

    // round-trip toList / fromList
    #[test]
    fn test_list_roundtrip() {
        let s = "héllo wörld".to_string();
        let chars = string_to_list(s.clone());
        assert_eq!(string_from_list(chars), s);
    }

    // ── New String fills — Elm-matching semantics ─────────────────────────

    #[test]
    fn left_right_match_elm() {
        assert_eq!(string_left(3, "abcdef".into()), "abc");
        assert_eq!(string_right(3, "abcdef".into()), "def");
        assert_eq!(string_left(0, "abc".into()), "");
        assert_eq!(string_left(-2, "abc".into()), ""); // Elm: n<=0 → ""
        assert_eq!(string_left(9, "ab".into()), "ab"); // n>len → whole
    }

    #[test]
    fn cons_uncons_match_elm() {
        assert_eq!(string_cons('a', "bc".into()), "abc");
        assert_eq!(
            string_uncons("abc".into()),
            IpeMaybe::Just(('a', "bc".to_string()))
        );
        assert_eq!(string_uncons(String::new()), IpeMaybe::Nothing);
        // rune-based: astral char stays whole.
        assert_eq!(
            string_uncons("😀x".into()),
            IpeMaybe::Just(('😀', "x".to_string()))
        );
    }

    #[test]
    fn pad_matches_elm() {
        // Elm: pad 5 ' ' "abc" == "  abc " (extra pad on the right when odd).
        assert_eq!(string_pad(5, ' ', "abc".into()), " abc ");
        assert_eq!(string_pad(4, '.', "ab".into()), ".ab.");
        assert_eq!(string_pad(2, '.', "abc".into()), "abc"); // n<=len → unchanged
    }

    // Refusal: a caller-controlled width past MAX_PAD_WIDTH must return the
    // string unchanged, never attempt the unbounded fill loop that would OOM.
    #[test]
    fn pad_width_past_ceiling_returns_unchanged() {
        assert_eq!(string_pad(9_000_000_000_000, ' ', "x".into()), "x");
        assert_eq!(string_pad(i64::MAX, ' ', "x".into()), "x");
    }
    #[test]
    fn pad_left_width_past_ceiling_returns_unchanged() {
        assert_eq!(string_pad_left(9_000_000_000_000, '0', "x".into()), "x");
        assert_eq!(string_pad_left(i64::MAX, '0', "x".into()), "x");
    }
    #[test]
    fn pad_right_width_past_ceiling_returns_unchanged() {
        assert_eq!(string_pad_right(9_000_000_000_000, '-', "x".into()), "x");
        assert_eq!(string_pad_right(i64::MAX, '-', "x".into()), "x");
    }
    // The ceiling itself is the last width that still pads.
    #[test]
    fn pad_at_exact_ceiling_still_pads() {
        assert_eq!(
            bounded_pad_count(MAX_PAD_WIDTH, 0),
            Some(MAX_PAD_WIDTH as usize)
        );
        assert_eq!(bounded_pad_count(MAX_PAD_WIDTH + 1, 0), None);
    }

    #[test]
    fn indexes_matches_elm() {
        // Elm: indexes "i" "Mississippi" == [1,4,7,10].
        assert_eq!(
            string_indexes("i".into(), "Mississippi".into()),
            vec![1, 4, 7, 10]
        );
        // Overlapping matches included.
        assert_eq!(string_indexes("aa".into(), "aaa".into()), vec![0, 1]);
        // Elm: indexes "" "abc" == [].
        assert_eq!(
            string_indexes(String::new(), "abc".into()),
            Vec::<i64>::new()
        );
    }

    #[test]
    fn char_fold_family_matches_elm() {
        // map / filter over runes.
        assert_eq!(
            string_map(|c| if c == 'a' { 'A' } else { c }, "banana".into()),
            "bAnAnA"
        );
        assert_eq!(string_filter(|c| c != 'a', "banana".into()), "bnn");
        // foldl / foldr build a string in each direction.
        let l = string_foldl(
            |c, mut acc: String| {
                acc.push(c);
                acc
            },
            String::new(),
            "abc".into(),
        );
        assert_eq!(l, "abc");
        let r = string_foldr(
            |c, mut acc: String| {
                acc.push(c);
                acc
            },
            String::new(),
            "abc".into(),
        );
        assert_eq!(r, "cba");
        // any / all.
        assert!(string_any(|c| c == 'z', "xyz".into()));
        assert!(!string_any(|c| c == 'q', "xyz".into()));
        assert!(string_all(|c| c.is_ascii_lowercase(), "xyz".into()));
        assert!(!string_all(|c| c.is_ascii_lowercase(), "xYz".into()));
    }
}
