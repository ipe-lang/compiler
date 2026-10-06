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
///
/// Unicode default full case folding (`CaseFolding.txt` statuses C + F, never
/// T), read from the one [`CASEFOLD`] table. Locale-independent and
/// context-free. The result is for comparing, not for display: it can be
/// longer than `s` (`ß` folds to `ss`, at most 3x the input bytes) and is not
/// always lowercase. No Unicode normalization is applied.
#[must_use]
pub fn string_casefold(s: String) -> String {
    let mut out = String::with_capacity(s.len());
    out.extend(folded(&s));
    out
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
///
/// `casefold a == casefold b`, compared without allocating: both sides read
/// the same [`folded`] stream `string_casefold` collects. No Unicode
/// normalization is applied, so precomposed and decomposed forms differ.
#[must_use]
pub fn string_equal_fold(a: String, b: String) -> bool {
    folded(&a).eq(folded(&b))
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

/// One character's default full case fold: itself, or its [`CASEFOLD`] mapping.
enum Fold {
    Same(Option<char>),
    Mapped(std::str::Chars<'static>),
}

impl Iterator for Fold {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        match self {
            Self::Same(c) => c.take(),
            Self::Mapped(chars) => chars.next(),
        }
    }
}

/// The fold of `c`: its table row's mapping, or `c` itself when it has none.
fn fold_char(c: char) -> Fold {
    CASEFOLD
        .binary_search_by_key(&c, |&(k, _)| k)
        .ok()
        .and_then(|i| CASEFOLD.get(i))
        .map_or(Fold::Same(Some(c)), |&(_, v)| Fold::Mapped(v.chars()))
}

/// The default full case fold of `s`, one character at a time.
fn folded(s: &str) -> impl Iterator<Item = char> + '_ {
    s.chars().flat_map(fold_char)
}

/// Whether the keys of `table` strictly increase, checked in one pass.
const fn casefold_table_sorted(table: &[(char, &str)]) -> bool {
    let mut rest = table;
    let mut prev: Option<char> = None;
    while let Some(((c, _), tail)) = rest.split_first() {
        if let Some(p) = prev
            && *c <= p
        {
            return false;
        }
        prev = Some(*c);
        rest = tail;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if `CASEFOLD` is not strictly sorted, which the `fold_char` binary search requires [ledger #boundary]
const _: () = assert!(casefold_table_sorted(CASEFOLD));

// ── generated: Unicode default full case folding (C + F) ── do not edit;
// regenerate with the ignored `print_casefold_table` test (see its doc).
/// Unicode default full case folding (statuses C + F) of every character whose
/// fold differs from itself, sorted by character.
///
/// Generated from `icu_casemap_data` (the version in the workspace lock); the
/// `casefold_table_matches_unicode_fold` test asserts it equal to ICU's
/// `CaseMapper::fold_string` over every scalar value.
static CASEFOLD: &[(char, &str)] = &[
    ('A', "a"),
    ('B', "b"),
    ('C', "c"),
    ('D', "d"),
    ('E', "e"),
    ('F', "f"),
    ('G', "g"),
    ('H', "h"),
    ('I', "i"),
    ('J', "j"),
    ('K', "k"),
    ('L', "l"),
    ('M', "m"),
    ('N', "n"),
    ('O', "o"),
    ('P', "p"),
    ('Q', "q"),
    ('R', "r"),
    ('S', "s"),
    ('T', "t"),
    ('U', "u"),
    ('V', "v"),
    ('W', "w"),
    ('X', "x"),
    ('Y', "y"),
    ('Z', "z"),
    ('\u{b5}', "\u{3bc}"),
    ('\u{c0}', "\u{e0}"),
    ('\u{c1}', "\u{e1}"),
    ('\u{c2}', "\u{e2}"),
    ('\u{c3}', "\u{e3}"),
    ('\u{c4}', "\u{e4}"),
    ('\u{c5}', "\u{e5}"),
    ('\u{c6}', "\u{e6}"),
    ('\u{c7}', "\u{e7}"),
    ('\u{c8}', "\u{e8}"),
    ('\u{c9}', "\u{e9}"),
    ('\u{ca}', "\u{ea}"),
    ('\u{cb}', "\u{eb}"),
    ('\u{cc}', "\u{ec}"),
    ('\u{cd}', "\u{ed}"),
    ('\u{ce}', "\u{ee}"),
    ('\u{cf}', "\u{ef}"),
    ('\u{d0}', "\u{f0}"),
    ('\u{d1}', "\u{f1}"),
    ('\u{d2}', "\u{f2}"),
    ('\u{d3}', "\u{f3}"),
    ('\u{d4}', "\u{f4}"),
    ('\u{d5}', "\u{f5}"),
    ('\u{d6}', "\u{f6}"),
    ('\u{d8}', "\u{f8}"),
    ('\u{d9}', "\u{f9}"),
    ('\u{da}', "\u{fa}"),
    ('\u{db}', "\u{fb}"),
    ('\u{dc}', "\u{fc}"),
    ('\u{dd}', "\u{fd}"),
    ('\u{de}', "\u{fe}"),
    ('\u{df}', "ss"),
    ('\u{100}', "\u{101}"),
    ('\u{102}', "\u{103}"),
    ('\u{104}', "\u{105}"),
    ('\u{106}', "\u{107}"),
    ('\u{108}', "\u{109}"),
    ('\u{10a}', "\u{10b}"),
    ('\u{10c}', "\u{10d}"),
    ('\u{10e}', "\u{10f}"),
    ('\u{110}', "\u{111}"),
    ('\u{112}', "\u{113}"),
    ('\u{114}', "\u{115}"),
    ('\u{116}', "\u{117}"),
    ('\u{118}', "\u{119}"),
    ('\u{11a}', "\u{11b}"),
    ('\u{11c}', "\u{11d}"),
    ('\u{11e}', "\u{11f}"),
    ('\u{120}', "\u{121}"),
    ('\u{122}', "\u{123}"),
    ('\u{124}', "\u{125}"),
    ('\u{126}', "\u{127}"),
    ('\u{128}', "\u{129}"),
    ('\u{12a}', "\u{12b}"),
    ('\u{12c}', "\u{12d}"),
    ('\u{12e}', "\u{12f}"),
    ('\u{130}', "i\u{307}"),
    ('\u{132}', "\u{133}"),
    ('\u{134}', "\u{135}"),
    ('\u{136}', "\u{137}"),
    ('\u{139}', "\u{13a}"),
    ('\u{13b}', "\u{13c}"),
    ('\u{13d}', "\u{13e}"),
    ('\u{13f}', "\u{140}"),
    ('\u{141}', "\u{142}"),
    ('\u{143}', "\u{144}"),
    ('\u{145}', "\u{146}"),
    ('\u{147}', "\u{148}"),
    ('\u{149}', "\u{2bc}n"),
    ('\u{14a}', "\u{14b}"),
    ('\u{14c}', "\u{14d}"),
    ('\u{14e}', "\u{14f}"),
    ('\u{150}', "\u{151}"),
    ('\u{152}', "\u{153}"),
    ('\u{154}', "\u{155}"),
    ('\u{156}', "\u{157}"),
    ('\u{158}', "\u{159}"),
    ('\u{15a}', "\u{15b}"),
    ('\u{15c}', "\u{15d}"),
    ('\u{15e}', "\u{15f}"),
    ('\u{160}', "\u{161}"),
    ('\u{162}', "\u{163}"),
    ('\u{164}', "\u{165}"),
    ('\u{166}', "\u{167}"),
    ('\u{168}', "\u{169}"),
    ('\u{16a}', "\u{16b}"),
    ('\u{16c}', "\u{16d}"),
    ('\u{16e}', "\u{16f}"),
    ('\u{170}', "\u{171}"),
    ('\u{172}', "\u{173}"),
    ('\u{174}', "\u{175}"),
    ('\u{176}', "\u{177}"),
    ('\u{178}', "\u{ff}"),
    ('\u{179}', "\u{17a}"),
    ('\u{17b}', "\u{17c}"),
    ('\u{17d}', "\u{17e}"),
    ('\u{17f}', "s"),
    ('\u{181}', "\u{253}"),
    ('\u{182}', "\u{183}"),
    ('\u{184}', "\u{185}"),
    ('\u{186}', "\u{254}"),
    ('\u{187}', "\u{188}"),
    ('\u{189}', "\u{256}"),
    ('\u{18a}', "\u{257}"),
    ('\u{18b}', "\u{18c}"),
    ('\u{18e}', "\u{1dd}"),
    ('\u{18f}', "\u{259}"),
    ('\u{190}', "\u{25b}"),
    ('\u{191}', "\u{192}"),
    ('\u{193}', "\u{260}"),
    ('\u{194}', "\u{263}"),
    ('\u{196}', "\u{269}"),
    ('\u{197}', "\u{268}"),
    ('\u{198}', "\u{199}"),
    ('\u{19c}', "\u{26f}"),
    ('\u{19d}', "\u{272}"),
    ('\u{19f}', "\u{275}"),
    ('\u{1a0}', "\u{1a1}"),
    ('\u{1a2}', "\u{1a3}"),
    ('\u{1a4}', "\u{1a5}"),
    ('\u{1a6}', "\u{280}"),
    ('\u{1a7}', "\u{1a8}"),
    ('\u{1a9}', "\u{283}"),
    ('\u{1ac}', "\u{1ad}"),
    ('\u{1ae}', "\u{288}"),
    ('\u{1af}', "\u{1b0}"),
    ('\u{1b1}', "\u{28a}"),
    ('\u{1b2}', "\u{28b}"),
    ('\u{1b3}', "\u{1b4}"),
    ('\u{1b5}', "\u{1b6}"),
    ('\u{1b7}', "\u{292}"),
    ('\u{1b8}', "\u{1b9}"),
    ('\u{1bc}', "\u{1bd}"),
    ('\u{1c4}', "\u{1c6}"),
    ('\u{1c5}', "\u{1c6}"),
    ('\u{1c7}', "\u{1c9}"),
    ('\u{1c8}', "\u{1c9}"),
    ('\u{1ca}', "\u{1cc}"),
    ('\u{1cb}', "\u{1cc}"),
    ('\u{1cd}', "\u{1ce}"),
    ('\u{1cf}', "\u{1d0}"),
    ('\u{1d1}', "\u{1d2}"),
    ('\u{1d3}', "\u{1d4}"),
    ('\u{1d5}', "\u{1d6}"),
    ('\u{1d7}', "\u{1d8}"),
    ('\u{1d9}', "\u{1da}"),
    ('\u{1db}', "\u{1dc}"),
    ('\u{1de}', "\u{1df}"),
    ('\u{1e0}', "\u{1e1}"),
    ('\u{1e2}', "\u{1e3}"),
    ('\u{1e4}', "\u{1e5}"),
    ('\u{1e6}', "\u{1e7}"),
    ('\u{1e8}', "\u{1e9}"),
    ('\u{1ea}', "\u{1eb}"),
    ('\u{1ec}', "\u{1ed}"),
    ('\u{1ee}', "\u{1ef}"),
    ('\u{1f0}', "j\u{30c}"),
    ('\u{1f1}', "\u{1f3}"),
    ('\u{1f2}', "\u{1f3}"),
    ('\u{1f4}', "\u{1f5}"),
    ('\u{1f6}', "\u{195}"),
    ('\u{1f7}', "\u{1bf}"),
    ('\u{1f8}', "\u{1f9}"),
    ('\u{1fa}', "\u{1fb}"),
    ('\u{1fc}', "\u{1fd}"),
    ('\u{1fe}', "\u{1ff}"),
    ('\u{200}', "\u{201}"),
    ('\u{202}', "\u{203}"),
    ('\u{204}', "\u{205}"),
    ('\u{206}', "\u{207}"),
    ('\u{208}', "\u{209}"),
    ('\u{20a}', "\u{20b}"),
    ('\u{20c}', "\u{20d}"),
    ('\u{20e}', "\u{20f}"),
    ('\u{210}', "\u{211}"),
    ('\u{212}', "\u{213}"),
    ('\u{214}', "\u{215}"),
    ('\u{216}', "\u{217}"),
    ('\u{218}', "\u{219}"),
    ('\u{21a}', "\u{21b}"),
    ('\u{21c}', "\u{21d}"),
    ('\u{21e}', "\u{21f}"),
    ('\u{220}', "\u{19e}"),
    ('\u{222}', "\u{223}"),
    ('\u{224}', "\u{225}"),
    ('\u{226}', "\u{227}"),
    ('\u{228}', "\u{229}"),
    ('\u{22a}', "\u{22b}"),
    ('\u{22c}', "\u{22d}"),
    ('\u{22e}', "\u{22f}"),
    ('\u{230}', "\u{231}"),
    ('\u{232}', "\u{233}"),
    ('\u{23a}', "\u{2c65}"),
    ('\u{23b}', "\u{23c}"),
    ('\u{23d}', "\u{19a}"),
    ('\u{23e}', "\u{2c66}"),
    ('\u{241}', "\u{242}"),
    ('\u{243}', "\u{180}"),
    ('\u{244}', "\u{289}"),
    ('\u{245}', "\u{28c}"),
    ('\u{246}', "\u{247}"),
    ('\u{248}', "\u{249}"),
    ('\u{24a}', "\u{24b}"),
    ('\u{24c}', "\u{24d}"),
    ('\u{24e}', "\u{24f}"),
    ('\u{345}', "\u{3b9}"),
    ('\u{370}', "\u{371}"),
    ('\u{372}', "\u{373}"),
    ('\u{376}', "\u{377}"),
    ('\u{37f}', "\u{3f3}"),
    ('\u{386}', "\u{3ac}"),
    ('\u{388}', "\u{3ad}"),
    ('\u{389}', "\u{3ae}"),
    ('\u{38a}', "\u{3af}"),
    ('\u{38c}', "\u{3cc}"),
    ('\u{38e}', "\u{3cd}"),
    ('\u{38f}', "\u{3ce}"),
    ('\u{390}', "\u{3b9}\u{308}\u{301}"),
    ('\u{391}', "\u{3b1}"),
    ('\u{392}', "\u{3b2}"),
    ('\u{393}', "\u{3b3}"),
    ('\u{394}', "\u{3b4}"),
    ('\u{395}', "\u{3b5}"),
    ('\u{396}', "\u{3b6}"),
    ('\u{397}', "\u{3b7}"),
    ('\u{398}', "\u{3b8}"),
    ('\u{399}', "\u{3b9}"),
    ('\u{39a}', "\u{3ba}"),
    ('\u{39b}', "\u{3bb}"),
    ('\u{39c}', "\u{3bc}"),
    ('\u{39d}', "\u{3bd}"),
    ('\u{39e}', "\u{3be}"),
    ('\u{39f}', "\u{3bf}"),
    ('\u{3a0}', "\u{3c0}"),
    ('\u{3a1}', "\u{3c1}"),
    ('\u{3a3}', "\u{3c3}"),
    ('\u{3a4}', "\u{3c4}"),
    ('\u{3a5}', "\u{3c5}"),
    ('\u{3a6}', "\u{3c6}"),
    ('\u{3a7}', "\u{3c7}"),
    ('\u{3a8}', "\u{3c8}"),
    ('\u{3a9}', "\u{3c9}"),
    ('\u{3aa}', "\u{3ca}"),
    ('\u{3ab}', "\u{3cb}"),
    ('\u{3b0}', "\u{3c5}\u{308}\u{301}"),
    ('\u{3c2}', "\u{3c3}"),
    ('\u{3cf}', "\u{3d7}"),
    ('\u{3d0}', "\u{3b2}"),
    ('\u{3d1}', "\u{3b8}"),
    ('\u{3d5}', "\u{3c6}"),
    ('\u{3d6}', "\u{3c0}"),
    ('\u{3d8}', "\u{3d9}"),
    ('\u{3da}', "\u{3db}"),
    ('\u{3dc}', "\u{3dd}"),
    ('\u{3de}', "\u{3df}"),
    ('\u{3e0}', "\u{3e1}"),
    ('\u{3e2}', "\u{3e3}"),
    ('\u{3e4}', "\u{3e5}"),
    ('\u{3e6}', "\u{3e7}"),
    ('\u{3e8}', "\u{3e9}"),
    ('\u{3ea}', "\u{3eb}"),
    ('\u{3ec}', "\u{3ed}"),
    ('\u{3ee}', "\u{3ef}"),
    ('\u{3f0}', "\u{3ba}"),
    ('\u{3f1}', "\u{3c1}"),
    ('\u{3f4}', "\u{3b8}"),
    ('\u{3f5}', "\u{3b5}"),
    ('\u{3f7}', "\u{3f8}"),
    ('\u{3f9}', "\u{3f2}"),
    ('\u{3fa}', "\u{3fb}"),
    ('\u{3fd}', "\u{37b}"),
    ('\u{3fe}', "\u{37c}"),
    ('\u{3ff}', "\u{37d}"),
    ('\u{400}', "\u{450}"),
    ('\u{401}', "\u{451}"),
    ('\u{402}', "\u{452}"),
    ('\u{403}', "\u{453}"),
    ('\u{404}', "\u{454}"),
    ('\u{405}', "\u{455}"),
    ('\u{406}', "\u{456}"),
    ('\u{407}', "\u{457}"),
    ('\u{408}', "\u{458}"),
    ('\u{409}', "\u{459}"),
    ('\u{40a}', "\u{45a}"),
    ('\u{40b}', "\u{45b}"),
    ('\u{40c}', "\u{45c}"),
    ('\u{40d}', "\u{45d}"),
    ('\u{40e}', "\u{45e}"),
    ('\u{40f}', "\u{45f}"),
    ('\u{410}', "\u{430}"),
    ('\u{411}', "\u{431}"),
    ('\u{412}', "\u{432}"),
    ('\u{413}', "\u{433}"),
    ('\u{414}', "\u{434}"),
    ('\u{415}', "\u{435}"),
    ('\u{416}', "\u{436}"),
    ('\u{417}', "\u{437}"),
    ('\u{418}', "\u{438}"),
    ('\u{419}', "\u{439}"),
    ('\u{41a}', "\u{43a}"),
    ('\u{41b}', "\u{43b}"),
    ('\u{41c}', "\u{43c}"),
    ('\u{41d}', "\u{43d}"),
    ('\u{41e}', "\u{43e}"),
    ('\u{41f}', "\u{43f}"),
    ('\u{420}', "\u{440}"),
    ('\u{421}', "\u{441}"),
    ('\u{422}', "\u{442}"),
    ('\u{423}', "\u{443}"),
    ('\u{424}', "\u{444}"),
    ('\u{425}', "\u{445}"),
    ('\u{426}', "\u{446}"),
    ('\u{427}', "\u{447}"),
    ('\u{428}', "\u{448}"),
    ('\u{429}', "\u{449}"),
    ('\u{42a}', "\u{44a}"),
    ('\u{42b}', "\u{44b}"),
    ('\u{42c}', "\u{44c}"),
    ('\u{42d}', "\u{44d}"),
    ('\u{42e}', "\u{44e}"),
    ('\u{42f}', "\u{44f}"),
    ('\u{460}', "\u{461}"),
    ('\u{462}', "\u{463}"),
    ('\u{464}', "\u{465}"),
    ('\u{466}', "\u{467}"),
    ('\u{468}', "\u{469}"),
    ('\u{46a}', "\u{46b}"),
    ('\u{46c}', "\u{46d}"),
    ('\u{46e}', "\u{46f}"),
    ('\u{470}', "\u{471}"),
    ('\u{472}', "\u{473}"),
    ('\u{474}', "\u{475}"),
    ('\u{476}', "\u{477}"),
    ('\u{478}', "\u{479}"),
    ('\u{47a}', "\u{47b}"),
    ('\u{47c}', "\u{47d}"),
    ('\u{47e}', "\u{47f}"),
    ('\u{480}', "\u{481}"),
    ('\u{48a}', "\u{48b}"),
    ('\u{48c}', "\u{48d}"),
    ('\u{48e}', "\u{48f}"),
    ('\u{490}', "\u{491}"),
    ('\u{492}', "\u{493}"),
    ('\u{494}', "\u{495}"),
    ('\u{496}', "\u{497}"),
    ('\u{498}', "\u{499}"),
    ('\u{49a}', "\u{49b}"),
    ('\u{49c}', "\u{49d}"),
    ('\u{49e}', "\u{49f}"),
    ('\u{4a0}', "\u{4a1}"),
    ('\u{4a2}', "\u{4a3}"),
    ('\u{4a4}', "\u{4a5}"),
    ('\u{4a6}', "\u{4a7}"),
    ('\u{4a8}', "\u{4a9}"),
    ('\u{4aa}', "\u{4ab}"),
    ('\u{4ac}', "\u{4ad}"),
    ('\u{4ae}', "\u{4af}"),
    ('\u{4b0}', "\u{4b1}"),
    ('\u{4b2}', "\u{4b3}"),
    ('\u{4b4}', "\u{4b5}"),
    ('\u{4b6}', "\u{4b7}"),
    ('\u{4b8}', "\u{4b9}"),
    ('\u{4ba}', "\u{4bb}"),
    ('\u{4bc}', "\u{4bd}"),
    ('\u{4be}', "\u{4bf}"),
    ('\u{4c0}', "\u{4cf}"),
    ('\u{4c1}', "\u{4c2}"),
    ('\u{4c3}', "\u{4c4}"),
    ('\u{4c5}', "\u{4c6}"),
    ('\u{4c7}', "\u{4c8}"),
    ('\u{4c9}', "\u{4ca}"),
    ('\u{4cb}', "\u{4cc}"),
    ('\u{4cd}', "\u{4ce}"),
    ('\u{4d0}', "\u{4d1}"),
    ('\u{4d2}', "\u{4d3}"),
    ('\u{4d4}', "\u{4d5}"),
    ('\u{4d6}', "\u{4d7}"),
    ('\u{4d8}', "\u{4d9}"),
    ('\u{4da}', "\u{4db}"),
    ('\u{4dc}', "\u{4dd}"),
    ('\u{4de}', "\u{4df}"),
    ('\u{4e0}', "\u{4e1}"),
    ('\u{4e2}', "\u{4e3}"),
    ('\u{4e4}', "\u{4e5}"),
    ('\u{4e6}', "\u{4e7}"),
    ('\u{4e8}', "\u{4e9}"),
    ('\u{4ea}', "\u{4eb}"),
    ('\u{4ec}', "\u{4ed}"),
    ('\u{4ee}', "\u{4ef}"),
    ('\u{4f0}', "\u{4f1}"),
    ('\u{4f2}', "\u{4f3}"),
    ('\u{4f4}', "\u{4f5}"),
    ('\u{4f6}', "\u{4f7}"),
    ('\u{4f8}', "\u{4f9}"),
    ('\u{4fa}', "\u{4fb}"),
    ('\u{4fc}', "\u{4fd}"),
    ('\u{4fe}', "\u{4ff}"),
    ('\u{500}', "\u{501}"),
    ('\u{502}', "\u{503}"),
    ('\u{504}', "\u{505}"),
    ('\u{506}', "\u{507}"),
    ('\u{508}', "\u{509}"),
    ('\u{50a}', "\u{50b}"),
    ('\u{50c}', "\u{50d}"),
    ('\u{50e}', "\u{50f}"),
    ('\u{510}', "\u{511}"),
    ('\u{512}', "\u{513}"),
    ('\u{514}', "\u{515}"),
    ('\u{516}', "\u{517}"),
    ('\u{518}', "\u{519}"),
    ('\u{51a}', "\u{51b}"),
    ('\u{51c}', "\u{51d}"),
    ('\u{51e}', "\u{51f}"),
    ('\u{520}', "\u{521}"),
    ('\u{522}', "\u{523}"),
    ('\u{524}', "\u{525}"),
    ('\u{526}', "\u{527}"),
    ('\u{528}', "\u{529}"),
    ('\u{52a}', "\u{52b}"),
    ('\u{52c}', "\u{52d}"),
    ('\u{52e}', "\u{52f}"),
    ('\u{531}', "\u{561}"),
    ('\u{532}', "\u{562}"),
    ('\u{533}', "\u{563}"),
    ('\u{534}', "\u{564}"),
    ('\u{535}', "\u{565}"),
    ('\u{536}', "\u{566}"),
    ('\u{537}', "\u{567}"),
    ('\u{538}', "\u{568}"),
    ('\u{539}', "\u{569}"),
    ('\u{53a}', "\u{56a}"),
    ('\u{53b}', "\u{56b}"),
    ('\u{53c}', "\u{56c}"),
    ('\u{53d}', "\u{56d}"),
    ('\u{53e}', "\u{56e}"),
    ('\u{53f}', "\u{56f}"),
    ('\u{540}', "\u{570}"),
    ('\u{541}', "\u{571}"),
    ('\u{542}', "\u{572}"),
    ('\u{543}', "\u{573}"),
    ('\u{544}', "\u{574}"),
    ('\u{545}', "\u{575}"),
    ('\u{546}', "\u{576}"),
    ('\u{547}', "\u{577}"),
    ('\u{548}', "\u{578}"),
    ('\u{549}', "\u{579}"),
    ('\u{54a}', "\u{57a}"),
    ('\u{54b}', "\u{57b}"),
    ('\u{54c}', "\u{57c}"),
    ('\u{54d}', "\u{57d}"),
    ('\u{54e}', "\u{57e}"),
    ('\u{54f}', "\u{57f}"),
    ('\u{550}', "\u{580}"),
    ('\u{551}', "\u{581}"),
    ('\u{552}', "\u{582}"),
    ('\u{553}', "\u{583}"),
    ('\u{554}', "\u{584}"),
    ('\u{555}', "\u{585}"),
    ('\u{556}', "\u{586}"),
    ('\u{587}', "\u{565}\u{582}"),
    ('\u{10a0}', "\u{2d00}"),
    ('\u{10a1}', "\u{2d01}"),
    ('\u{10a2}', "\u{2d02}"),
    ('\u{10a3}', "\u{2d03}"),
    ('\u{10a4}', "\u{2d04}"),
    ('\u{10a5}', "\u{2d05}"),
    ('\u{10a6}', "\u{2d06}"),
    ('\u{10a7}', "\u{2d07}"),
    ('\u{10a8}', "\u{2d08}"),
    ('\u{10a9}', "\u{2d09}"),
    ('\u{10aa}', "\u{2d0a}"),
    ('\u{10ab}', "\u{2d0b}"),
    ('\u{10ac}', "\u{2d0c}"),
    ('\u{10ad}', "\u{2d0d}"),
    ('\u{10ae}', "\u{2d0e}"),
    ('\u{10af}', "\u{2d0f}"),
    ('\u{10b0}', "\u{2d10}"),
    ('\u{10b1}', "\u{2d11}"),
    ('\u{10b2}', "\u{2d12}"),
    ('\u{10b3}', "\u{2d13}"),
    ('\u{10b4}', "\u{2d14}"),
    ('\u{10b5}', "\u{2d15}"),
    ('\u{10b6}', "\u{2d16}"),
    ('\u{10b7}', "\u{2d17}"),
    ('\u{10b8}', "\u{2d18}"),
    ('\u{10b9}', "\u{2d19}"),
    ('\u{10ba}', "\u{2d1a}"),
    ('\u{10bb}', "\u{2d1b}"),
    ('\u{10bc}', "\u{2d1c}"),
    ('\u{10bd}', "\u{2d1d}"),
    ('\u{10be}', "\u{2d1e}"),
    ('\u{10bf}', "\u{2d1f}"),
    ('\u{10c0}', "\u{2d20}"),
    ('\u{10c1}', "\u{2d21}"),
    ('\u{10c2}', "\u{2d22}"),
    ('\u{10c3}', "\u{2d23}"),
    ('\u{10c4}', "\u{2d24}"),
    ('\u{10c5}', "\u{2d25}"),
    ('\u{10c7}', "\u{2d27}"),
    ('\u{10cd}', "\u{2d2d}"),
    ('\u{13f8}', "\u{13f0}"),
    ('\u{13f9}', "\u{13f1}"),
    ('\u{13fa}', "\u{13f2}"),
    ('\u{13fb}', "\u{13f3}"),
    ('\u{13fc}', "\u{13f4}"),
    ('\u{13fd}', "\u{13f5}"),
    ('\u{1c80}', "\u{432}"),
    ('\u{1c81}', "\u{434}"),
    ('\u{1c82}', "\u{43e}"),
    ('\u{1c83}', "\u{441}"),
    ('\u{1c84}', "\u{442}"),
    ('\u{1c85}', "\u{442}"),
    ('\u{1c86}', "\u{44a}"),
    ('\u{1c87}', "\u{463}"),
    ('\u{1c88}', "\u{a64b}"),
    ('\u{1c89}', "\u{1c8a}"),
    ('\u{1c90}', "\u{10d0}"),
    ('\u{1c91}', "\u{10d1}"),
    ('\u{1c92}', "\u{10d2}"),
    ('\u{1c93}', "\u{10d3}"),
    ('\u{1c94}', "\u{10d4}"),
    ('\u{1c95}', "\u{10d5}"),
    ('\u{1c96}', "\u{10d6}"),
    ('\u{1c97}', "\u{10d7}"),
    ('\u{1c98}', "\u{10d8}"),
    ('\u{1c99}', "\u{10d9}"),
    ('\u{1c9a}', "\u{10da}"),
    ('\u{1c9b}', "\u{10db}"),
    ('\u{1c9c}', "\u{10dc}"),
    ('\u{1c9d}', "\u{10dd}"),
    ('\u{1c9e}', "\u{10de}"),
    ('\u{1c9f}', "\u{10df}"),
    ('\u{1ca0}', "\u{10e0}"),
    ('\u{1ca1}', "\u{10e1}"),
    ('\u{1ca2}', "\u{10e2}"),
    ('\u{1ca3}', "\u{10e3}"),
    ('\u{1ca4}', "\u{10e4}"),
    ('\u{1ca5}', "\u{10e5}"),
    ('\u{1ca6}', "\u{10e6}"),
    ('\u{1ca7}', "\u{10e7}"),
    ('\u{1ca8}', "\u{10e8}"),
    ('\u{1ca9}', "\u{10e9}"),
    ('\u{1caa}', "\u{10ea}"),
    ('\u{1cab}', "\u{10eb}"),
    ('\u{1cac}', "\u{10ec}"),
    ('\u{1cad}', "\u{10ed}"),
    ('\u{1cae}', "\u{10ee}"),
    ('\u{1caf}', "\u{10ef}"),
    ('\u{1cb0}', "\u{10f0}"),
    ('\u{1cb1}', "\u{10f1}"),
    ('\u{1cb2}', "\u{10f2}"),
    ('\u{1cb3}', "\u{10f3}"),
    ('\u{1cb4}', "\u{10f4}"),
    ('\u{1cb5}', "\u{10f5}"),
    ('\u{1cb6}', "\u{10f6}"),
    ('\u{1cb7}', "\u{10f7}"),
    ('\u{1cb8}', "\u{10f8}"),
    ('\u{1cb9}', "\u{10f9}"),
    ('\u{1cba}', "\u{10fa}"),
    ('\u{1cbd}', "\u{10fd}"),
    ('\u{1cbe}', "\u{10fe}"),
    ('\u{1cbf}', "\u{10ff}"),
    ('\u{1e00}', "\u{1e01}"),
    ('\u{1e02}', "\u{1e03}"),
    ('\u{1e04}', "\u{1e05}"),
    ('\u{1e06}', "\u{1e07}"),
    ('\u{1e08}', "\u{1e09}"),
    ('\u{1e0a}', "\u{1e0b}"),
    ('\u{1e0c}', "\u{1e0d}"),
    ('\u{1e0e}', "\u{1e0f}"),
    ('\u{1e10}', "\u{1e11}"),
    ('\u{1e12}', "\u{1e13}"),
    ('\u{1e14}', "\u{1e15}"),
    ('\u{1e16}', "\u{1e17}"),
    ('\u{1e18}', "\u{1e19}"),
    ('\u{1e1a}', "\u{1e1b}"),
    ('\u{1e1c}', "\u{1e1d}"),
    ('\u{1e1e}', "\u{1e1f}"),
    ('\u{1e20}', "\u{1e21}"),
    ('\u{1e22}', "\u{1e23}"),
    ('\u{1e24}', "\u{1e25}"),
    ('\u{1e26}', "\u{1e27}"),
    ('\u{1e28}', "\u{1e29}"),
    ('\u{1e2a}', "\u{1e2b}"),
    ('\u{1e2c}', "\u{1e2d}"),
    ('\u{1e2e}', "\u{1e2f}"),
    ('\u{1e30}', "\u{1e31}"),
    ('\u{1e32}', "\u{1e33}"),
    ('\u{1e34}', "\u{1e35}"),
    ('\u{1e36}', "\u{1e37}"),
    ('\u{1e38}', "\u{1e39}"),
    ('\u{1e3a}', "\u{1e3b}"),
    ('\u{1e3c}', "\u{1e3d}"),
    ('\u{1e3e}', "\u{1e3f}"),
    ('\u{1e40}', "\u{1e41}"),
    ('\u{1e42}', "\u{1e43}"),
    ('\u{1e44}', "\u{1e45}"),
    ('\u{1e46}', "\u{1e47}"),
    ('\u{1e48}', "\u{1e49}"),
    ('\u{1e4a}', "\u{1e4b}"),
    ('\u{1e4c}', "\u{1e4d}"),
    ('\u{1e4e}', "\u{1e4f}"),
    ('\u{1e50}', "\u{1e51}"),
    ('\u{1e52}', "\u{1e53}"),
    ('\u{1e54}', "\u{1e55}"),
    ('\u{1e56}', "\u{1e57}"),
    ('\u{1e58}', "\u{1e59}"),
    ('\u{1e5a}', "\u{1e5b}"),
    ('\u{1e5c}', "\u{1e5d}"),
    ('\u{1e5e}', "\u{1e5f}"),
    ('\u{1e60}', "\u{1e61}"),
    ('\u{1e62}', "\u{1e63}"),
    ('\u{1e64}', "\u{1e65}"),
    ('\u{1e66}', "\u{1e67}"),
    ('\u{1e68}', "\u{1e69}"),
    ('\u{1e6a}', "\u{1e6b}"),
    ('\u{1e6c}', "\u{1e6d}"),
    ('\u{1e6e}', "\u{1e6f}"),
    ('\u{1e70}', "\u{1e71}"),
    ('\u{1e72}', "\u{1e73}"),
    ('\u{1e74}', "\u{1e75}"),
    ('\u{1e76}', "\u{1e77}"),
    ('\u{1e78}', "\u{1e79}"),
    ('\u{1e7a}', "\u{1e7b}"),
    ('\u{1e7c}', "\u{1e7d}"),
    ('\u{1e7e}', "\u{1e7f}"),
    ('\u{1e80}', "\u{1e81}"),
    ('\u{1e82}', "\u{1e83}"),
    ('\u{1e84}', "\u{1e85}"),
    ('\u{1e86}', "\u{1e87}"),
    ('\u{1e88}', "\u{1e89}"),
    ('\u{1e8a}', "\u{1e8b}"),
    ('\u{1e8c}', "\u{1e8d}"),
    ('\u{1e8e}', "\u{1e8f}"),
    ('\u{1e90}', "\u{1e91}"),
    ('\u{1e92}', "\u{1e93}"),
    ('\u{1e94}', "\u{1e95}"),
    ('\u{1e96}', "h\u{331}"),
    ('\u{1e97}', "t\u{308}"),
    ('\u{1e98}', "w\u{30a}"),
    ('\u{1e99}', "y\u{30a}"),
    ('\u{1e9a}', "a\u{2be}"),
    ('\u{1e9b}', "\u{1e61}"),
    ('\u{1e9e}', "ss"),
    ('\u{1ea0}', "\u{1ea1}"),
    ('\u{1ea2}', "\u{1ea3}"),
    ('\u{1ea4}', "\u{1ea5}"),
    ('\u{1ea6}', "\u{1ea7}"),
    ('\u{1ea8}', "\u{1ea9}"),
    ('\u{1eaa}', "\u{1eab}"),
    ('\u{1eac}', "\u{1ead}"),
    ('\u{1eae}', "\u{1eaf}"),
    ('\u{1eb0}', "\u{1eb1}"),
    ('\u{1eb2}', "\u{1eb3}"),
    ('\u{1eb4}', "\u{1eb5}"),
    ('\u{1eb6}', "\u{1eb7}"),
    ('\u{1eb8}', "\u{1eb9}"),
    ('\u{1eba}', "\u{1ebb}"),
    ('\u{1ebc}', "\u{1ebd}"),
    ('\u{1ebe}', "\u{1ebf}"),
    ('\u{1ec0}', "\u{1ec1}"),
    ('\u{1ec2}', "\u{1ec3}"),
    ('\u{1ec4}', "\u{1ec5}"),
    ('\u{1ec6}', "\u{1ec7}"),
    ('\u{1ec8}', "\u{1ec9}"),
    ('\u{1eca}', "\u{1ecb}"),
    ('\u{1ecc}', "\u{1ecd}"),
    ('\u{1ece}', "\u{1ecf}"),
    ('\u{1ed0}', "\u{1ed1}"),
    ('\u{1ed2}', "\u{1ed3}"),
    ('\u{1ed4}', "\u{1ed5}"),
    ('\u{1ed6}', "\u{1ed7}"),
    ('\u{1ed8}', "\u{1ed9}"),
    ('\u{1eda}', "\u{1edb}"),
    ('\u{1edc}', "\u{1edd}"),
    ('\u{1ede}', "\u{1edf}"),
    ('\u{1ee0}', "\u{1ee1}"),
    ('\u{1ee2}', "\u{1ee3}"),
    ('\u{1ee4}', "\u{1ee5}"),
    ('\u{1ee6}', "\u{1ee7}"),
    ('\u{1ee8}', "\u{1ee9}"),
    ('\u{1eea}', "\u{1eeb}"),
    ('\u{1eec}', "\u{1eed}"),
    ('\u{1eee}', "\u{1eef}"),
    ('\u{1ef0}', "\u{1ef1}"),
    ('\u{1ef2}', "\u{1ef3}"),
    ('\u{1ef4}', "\u{1ef5}"),
    ('\u{1ef6}', "\u{1ef7}"),
    ('\u{1ef8}', "\u{1ef9}"),
    ('\u{1efa}', "\u{1efb}"),
    ('\u{1efc}', "\u{1efd}"),
    ('\u{1efe}', "\u{1eff}"),
    ('\u{1f08}', "\u{1f00}"),
    ('\u{1f09}', "\u{1f01}"),
    ('\u{1f0a}', "\u{1f02}"),
    ('\u{1f0b}', "\u{1f03}"),
    ('\u{1f0c}', "\u{1f04}"),
    ('\u{1f0d}', "\u{1f05}"),
    ('\u{1f0e}', "\u{1f06}"),
    ('\u{1f0f}', "\u{1f07}"),
    ('\u{1f18}', "\u{1f10}"),
    ('\u{1f19}', "\u{1f11}"),
    ('\u{1f1a}', "\u{1f12}"),
    ('\u{1f1b}', "\u{1f13}"),
    ('\u{1f1c}', "\u{1f14}"),
    ('\u{1f1d}', "\u{1f15}"),
    ('\u{1f28}', "\u{1f20}"),
    ('\u{1f29}', "\u{1f21}"),
    ('\u{1f2a}', "\u{1f22}"),
    ('\u{1f2b}', "\u{1f23}"),
    ('\u{1f2c}', "\u{1f24}"),
    ('\u{1f2d}', "\u{1f25}"),
    ('\u{1f2e}', "\u{1f26}"),
    ('\u{1f2f}', "\u{1f27}"),
    ('\u{1f38}', "\u{1f30}"),
    ('\u{1f39}', "\u{1f31}"),
    ('\u{1f3a}', "\u{1f32}"),
    ('\u{1f3b}', "\u{1f33}"),
    ('\u{1f3c}', "\u{1f34}"),
    ('\u{1f3d}', "\u{1f35}"),
    ('\u{1f3e}', "\u{1f36}"),
    ('\u{1f3f}', "\u{1f37}"),
    ('\u{1f48}', "\u{1f40}"),
    ('\u{1f49}', "\u{1f41}"),
    ('\u{1f4a}', "\u{1f42}"),
    ('\u{1f4b}', "\u{1f43}"),
    ('\u{1f4c}', "\u{1f44}"),
    ('\u{1f4d}', "\u{1f45}"),
    ('\u{1f50}', "\u{3c5}\u{313}"),
    ('\u{1f52}', "\u{3c5}\u{313}\u{300}"),
    ('\u{1f54}', "\u{3c5}\u{313}\u{301}"),
    ('\u{1f56}', "\u{3c5}\u{313}\u{342}"),
    ('\u{1f59}', "\u{1f51}"),
    ('\u{1f5b}', "\u{1f53}"),
    ('\u{1f5d}', "\u{1f55}"),
    ('\u{1f5f}', "\u{1f57}"),
    ('\u{1f68}', "\u{1f60}"),
    ('\u{1f69}', "\u{1f61}"),
    ('\u{1f6a}', "\u{1f62}"),
    ('\u{1f6b}', "\u{1f63}"),
    ('\u{1f6c}', "\u{1f64}"),
    ('\u{1f6d}', "\u{1f65}"),
    ('\u{1f6e}', "\u{1f66}"),
    ('\u{1f6f}', "\u{1f67}"),
    ('\u{1f80}', "\u{1f00}\u{3b9}"),
    ('\u{1f81}', "\u{1f01}\u{3b9}"),
    ('\u{1f82}', "\u{1f02}\u{3b9}"),
    ('\u{1f83}', "\u{1f03}\u{3b9}"),
    ('\u{1f84}', "\u{1f04}\u{3b9}"),
    ('\u{1f85}', "\u{1f05}\u{3b9}"),
    ('\u{1f86}', "\u{1f06}\u{3b9}"),
    ('\u{1f87}', "\u{1f07}\u{3b9}"),
    ('\u{1f88}', "\u{1f00}\u{3b9}"),
    ('\u{1f89}', "\u{1f01}\u{3b9}"),
    ('\u{1f8a}', "\u{1f02}\u{3b9}"),
    ('\u{1f8b}', "\u{1f03}\u{3b9}"),
    ('\u{1f8c}', "\u{1f04}\u{3b9}"),
    ('\u{1f8d}', "\u{1f05}\u{3b9}"),
    ('\u{1f8e}', "\u{1f06}\u{3b9}"),
    ('\u{1f8f}', "\u{1f07}\u{3b9}"),
    ('\u{1f90}', "\u{1f20}\u{3b9}"),
    ('\u{1f91}', "\u{1f21}\u{3b9}"),
    ('\u{1f92}', "\u{1f22}\u{3b9}"),
    ('\u{1f93}', "\u{1f23}\u{3b9}"),
    ('\u{1f94}', "\u{1f24}\u{3b9}"),
    ('\u{1f95}', "\u{1f25}\u{3b9}"),
    ('\u{1f96}', "\u{1f26}\u{3b9}"),
    ('\u{1f97}', "\u{1f27}\u{3b9}"),
    ('\u{1f98}', "\u{1f20}\u{3b9}"),
    ('\u{1f99}', "\u{1f21}\u{3b9}"),
    ('\u{1f9a}', "\u{1f22}\u{3b9}"),
    ('\u{1f9b}', "\u{1f23}\u{3b9}"),
    ('\u{1f9c}', "\u{1f24}\u{3b9}"),
    ('\u{1f9d}', "\u{1f25}\u{3b9}"),
    ('\u{1f9e}', "\u{1f26}\u{3b9}"),
    ('\u{1f9f}', "\u{1f27}\u{3b9}"),
    ('\u{1fa0}', "\u{1f60}\u{3b9}"),
    ('\u{1fa1}', "\u{1f61}\u{3b9}"),
    ('\u{1fa2}', "\u{1f62}\u{3b9}"),
    ('\u{1fa3}', "\u{1f63}\u{3b9}"),
    ('\u{1fa4}', "\u{1f64}\u{3b9}"),
    ('\u{1fa5}', "\u{1f65}\u{3b9}"),
    ('\u{1fa6}', "\u{1f66}\u{3b9}"),
    ('\u{1fa7}', "\u{1f67}\u{3b9}"),
    ('\u{1fa8}', "\u{1f60}\u{3b9}"),
    ('\u{1fa9}', "\u{1f61}\u{3b9}"),
    ('\u{1faa}', "\u{1f62}\u{3b9}"),
    ('\u{1fab}', "\u{1f63}\u{3b9}"),
    ('\u{1fac}', "\u{1f64}\u{3b9}"),
    ('\u{1fad}', "\u{1f65}\u{3b9}"),
    ('\u{1fae}', "\u{1f66}\u{3b9}"),
    ('\u{1faf}', "\u{1f67}\u{3b9}"),
    ('\u{1fb2}', "\u{1f70}\u{3b9}"),
    ('\u{1fb3}', "\u{3b1}\u{3b9}"),
    ('\u{1fb4}', "\u{3ac}\u{3b9}"),
    ('\u{1fb6}', "\u{3b1}\u{342}"),
    ('\u{1fb7}', "\u{3b1}\u{342}\u{3b9}"),
    ('\u{1fb8}', "\u{1fb0}"),
    ('\u{1fb9}', "\u{1fb1}"),
    ('\u{1fba}', "\u{1f70}"),
    ('\u{1fbb}', "\u{1f71}"),
    ('\u{1fbc}', "\u{3b1}\u{3b9}"),
    ('\u{1fbe}', "\u{3b9}"),
    ('\u{1fc2}', "\u{1f74}\u{3b9}"),
    ('\u{1fc3}', "\u{3b7}\u{3b9}"),
    ('\u{1fc4}', "\u{3ae}\u{3b9}"),
    ('\u{1fc6}', "\u{3b7}\u{342}"),
    ('\u{1fc7}', "\u{3b7}\u{342}\u{3b9}"),
    ('\u{1fc8}', "\u{1f72}"),
    ('\u{1fc9}', "\u{1f73}"),
    ('\u{1fca}', "\u{1f74}"),
    ('\u{1fcb}', "\u{1f75}"),
    ('\u{1fcc}', "\u{3b7}\u{3b9}"),
    ('\u{1fd2}', "\u{3b9}\u{308}\u{300}"),
    ('\u{1fd3}', "\u{3b9}\u{308}\u{301}"),
    ('\u{1fd6}', "\u{3b9}\u{342}"),
    ('\u{1fd7}', "\u{3b9}\u{308}\u{342}"),
    ('\u{1fd8}', "\u{1fd0}"),
    ('\u{1fd9}', "\u{1fd1}"),
    ('\u{1fda}', "\u{1f76}"),
    ('\u{1fdb}', "\u{1f77}"),
    ('\u{1fe2}', "\u{3c5}\u{308}\u{300}"),
    ('\u{1fe3}', "\u{3c5}\u{308}\u{301}"),
    ('\u{1fe4}', "\u{3c1}\u{313}"),
    ('\u{1fe6}', "\u{3c5}\u{342}"),
    ('\u{1fe7}', "\u{3c5}\u{308}\u{342}"),
    ('\u{1fe8}', "\u{1fe0}"),
    ('\u{1fe9}', "\u{1fe1}"),
    ('\u{1fea}', "\u{1f7a}"),
    ('\u{1feb}', "\u{1f7b}"),
    ('\u{1fec}', "\u{1fe5}"),
    ('\u{1ff2}', "\u{1f7c}\u{3b9}"),
    ('\u{1ff3}', "\u{3c9}\u{3b9}"),
    ('\u{1ff4}', "\u{3ce}\u{3b9}"),
    ('\u{1ff6}', "\u{3c9}\u{342}"),
    ('\u{1ff7}', "\u{3c9}\u{342}\u{3b9}"),
    ('\u{1ff8}', "\u{1f78}"),
    ('\u{1ff9}', "\u{1f79}"),
    ('\u{1ffa}', "\u{1f7c}"),
    ('\u{1ffb}', "\u{1f7d}"),
    ('\u{1ffc}', "\u{3c9}\u{3b9}"),
    ('\u{2126}', "\u{3c9}"),
    ('\u{212a}', "k"),
    ('\u{212b}', "\u{e5}"),
    ('\u{2132}', "\u{214e}"),
    ('\u{2160}', "\u{2170}"),
    ('\u{2161}', "\u{2171}"),
    ('\u{2162}', "\u{2172}"),
    ('\u{2163}', "\u{2173}"),
    ('\u{2164}', "\u{2174}"),
    ('\u{2165}', "\u{2175}"),
    ('\u{2166}', "\u{2176}"),
    ('\u{2167}', "\u{2177}"),
    ('\u{2168}', "\u{2178}"),
    ('\u{2169}', "\u{2179}"),
    ('\u{216a}', "\u{217a}"),
    ('\u{216b}', "\u{217b}"),
    ('\u{216c}', "\u{217c}"),
    ('\u{216d}', "\u{217d}"),
    ('\u{216e}', "\u{217e}"),
    ('\u{216f}', "\u{217f}"),
    ('\u{2183}', "\u{2184}"),
    ('\u{24b6}', "\u{24d0}"),
    ('\u{24b7}', "\u{24d1}"),
    ('\u{24b8}', "\u{24d2}"),
    ('\u{24b9}', "\u{24d3}"),
    ('\u{24ba}', "\u{24d4}"),
    ('\u{24bb}', "\u{24d5}"),
    ('\u{24bc}', "\u{24d6}"),
    ('\u{24bd}', "\u{24d7}"),
    ('\u{24be}', "\u{24d8}"),
    ('\u{24bf}', "\u{24d9}"),
    ('\u{24c0}', "\u{24da}"),
    ('\u{24c1}', "\u{24db}"),
    ('\u{24c2}', "\u{24dc}"),
    ('\u{24c3}', "\u{24dd}"),
    ('\u{24c4}', "\u{24de}"),
    ('\u{24c5}', "\u{24df}"),
    ('\u{24c6}', "\u{24e0}"),
    ('\u{24c7}', "\u{24e1}"),
    ('\u{24c8}', "\u{24e2}"),
    ('\u{24c9}', "\u{24e3}"),
    ('\u{24ca}', "\u{24e4}"),
    ('\u{24cb}', "\u{24e5}"),
    ('\u{24cc}', "\u{24e6}"),
    ('\u{24cd}', "\u{24e7}"),
    ('\u{24ce}', "\u{24e8}"),
    ('\u{24cf}', "\u{24e9}"),
    ('\u{2c00}', "\u{2c30}"),
    ('\u{2c01}', "\u{2c31}"),
    ('\u{2c02}', "\u{2c32}"),
    ('\u{2c03}', "\u{2c33}"),
    ('\u{2c04}', "\u{2c34}"),
    ('\u{2c05}', "\u{2c35}"),
    ('\u{2c06}', "\u{2c36}"),
    ('\u{2c07}', "\u{2c37}"),
    ('\u{2c08}', "\u{2c38}"),
    ('\u{2c09}', "\u{2c39}"),
    ('\u{2c0a}', "\u{2c3a}"),
    ('\u{2c0b}', "\u{2c3b}"),
    ('\u{2c0c}', "\u{2c3c}"),
    ('\u{2c0d}', "\u{2c3d}"),
    ('\u{2c0e}', "\u{2c3e}"),
    ('\u{2c0f}', "\u{2c3f}"),
    ('\u{2c10}', "\u{2c40}"),
    ('\u{2c11}', "\u{2c41}"),
    ('\u{2c12}', "\u{2c42}"),
    ('\u{2c13}', "\u{2c43}"),
    ('\u{2c14}', "\u{2c44}"),
    ('\u{2c15}', "\u{2c45}"),
    ('\u{2c16}', "\u{2c46}"),
    ('\u{2c17}', "\u{2c47}"),
    ('\u{2c18}', "\u{2c48}"),
    ('\u{2c19}', "\u{2c49}"),
    ('\u{2c1a}', "\u{2c4a}"),
    ('\u{2c1b}', "\u{2c4b}"),
    ('\u{2c1c}', "\u{2c4c}"),
    ('\u{2c1d}', "\u{2c4d}"),
    ('\u{2c1e}', "\u{2c4e}"),
    ('\u{2c1f}', "\u{2c4f}"),
    ('\u{2c20}', "\u{2c50}"),
    ('\u{2c21}', "\u{2c51}"),
    ('\u{2c22}', "\u{2c52}"),
    ('\u{2c23}', "\u{2c53}"),
    ('\u{2c24}', "\u{2c54}"),
    ('\u{2c25}', "\u{2c55}"),
    ('\u{2c26}', "\u{2c56}"),
    ('\u{2c27}', "\u{2c57}"),
    ('\u{2c28}', "\u{2c58}"),
    ('\u{2c29}', "\u{2c59}"),
    ('\u{2c2a}', "\u{2c5a}"),
    ('\u{2c2b}', "\u{2c5b}"),
    ('\u{2c2c}', "\u{2c5c}"),
    ('\u{2c2d}', "\u{2c5d}"),
    ('\u{2c2e}', "\u{2c5e}"),
    ('\u{2c2f}', "\u{2c5f}"),
    ('\u{2c60}', "\u{2c61}"),
    ('\u{2c62}', "\u{26b}"),
    ('\u{2c63}', "\u{1d7d}"),
    ('\u{2c64}', "\u{27d}"),
    ('\u{2c67}', "\u{2c68}"),
    ('\u{2c69}', "\u{2c6a}"),
    ('\u{2c6b}', "\u{2c6c}"),
    ('\u{2c6d}', "\u{251}"),
    ('\u{2c6e}', "\u{271}"),
    ('\u{2c6f}', "\u{250}"),
    ('\u{2c70}', "\u{252}"),
    ('\u{2c72}', "\u{2c73}"),
    ('\u{2c75}', "\u{2c76}"),
    ('\u{2c7e}', "\u{23f}"),
    ('\u{2c7f}', "\u{240}"),
    ('\u{2c80}', "\u{2c81}"),
    ('\u{2c82}', "\u{2c83}"),
    ('\u{2c84}', "\u{2c85}"),
    ('\u{2c86}', "\u{2c87}"),
    ('\u{2c88}', "\u{2c89}"),
    ('\u{2c8a}', "\u{2c8b}"),
    ('\u{2c8c}', "\u{2c8d}"),
    ('\u{2c8e}', "\u{2c8f}"),
    ('\u{2c90}', "\u{2c91}"),
    ('\u{2c92}', "\u{2c93}"),
    ('\u{2c94}', "\u{2c95}"),
    ('\u{2c96}', "\u{2c97}"),
    ('\u{2c98}', "\u{2c99}"),
    ('\u{2c9a}', "\u{2c9b}"),
    ('\u{2c9c}', "\u{2c9d}"),
    ('\u{2c9e}', "\u{2c9f}"),
    ('\u{2ca0}', "\u{2ca1}"),
    ('\u{2ca2}', "\u{2ca3}"),
    ('\u{2ca4}', "\u{2ca5}"),
    ('\u{2ca6}', "\u{2ca7}"),
    ('\u{2ca8}', "\u{2ca9}"),
    ('\u{2caa}', "\u{2cab}"),
    ('\u{2cac}', "\u{2cad}"),
    ('\u{2cae}', "\u{2caf}"),
    ('\u{2cb0}', "\u{2cb1}"),
    ('\u{2cb2}', "\u{2cb3}"),
    ('\u{2cb4}', "\u{2cb5}"),
    ('\u{2cb6}', "\u{2cb7}"),
    ('\u{2cb8}', "\u{2cb9}"),
    ('\u{2cba}', "\u{2cbb}"),
    ('\u{2cbc}', "\u{2cbd}"),
    ('\u{2cbe}', "\u{2cbf}"),
    ('\u{2cc0}', "\u{2cc1}"),
    ('\u{2cc2}', "\u{2cc3}"),
    ('\u{2cc4}', "\u{2cc5}"),
    ('\u{2cc6}', "\u{2cc7}"),
    ('\u{2cc8}', "\u{2cc9}"),
    ('\u{2cca}', "\u{2ccb}"),
    ('\u{2ccc}', "\u{2ccd}"),
    ('\u{2cce}', "\u{2ccf}"),
    ('\u{2cd0}', "\u{2cd1}"),
    ('\u{2cd2}', "\u{2cd3}"),
    ('\u{2cd4}', "\u{2cd5}"),
    ('\u{2cd6}', "\u{2cd7}"),
    ('\u{2cd8}', "\u{2cd9}"),
    ('\u{2cda}', "\u{2cdb}"),
    ('\u{2cdc}', "\u{2cdd}"),
    ('\u{2cde}', "\u{2cdf}"),
    ('\u{2ce0}', "\u{2ce1}"),
    ('\u{2ce2}', "\u{2ce3}"),
    ('\u{2ceb}', "\u{2cec}"),
    ('\u{2ced}', "\u{2cee}"),
    ('\u{2cf2}', "\u{2cf3}"),
    ('\u{a640}', "\u{a641}"),
    ('\u{a642}', "\u{a643}"),
    ('\u{a644}', "\u{a645}"),
    ('\u{a646}', "\u{a647}"),
    ('\u{a648}', "\u{a649}"),
    ('\u{a64a}', "\u{a64b}"),
    ('\u{a64c}', "\u{a64d}"),
    ('\u{a64e}', "\u{a64f}"),
    ('\u{a650}', "\u{a651}"),
    ('\u{a652}', "\u{a653}"),
    ('\u{a654}', "\u{a655}"),
    ('\u{a656}', "\u{a657}"),
    ('\u{a658}', "\u{a659}"),
    ('\u{a65a}', "\u{a65b}"),
    ('\u{a65c}', "\u{a65d}"),
    ('\u{a65e}', "\u{a65f}"),
    ('\u{a660}', "\u{a661}"),
    ('\u{a662}', "\u{a663}"),
    ('\u{a664}', "\u{a665}"),
    ('\u{a666}', "\u{a667}"),
    ('\u{a668}', "\u{a669}"),
    ('\u{a66a}', "\u{a66b}"),
    ('\u{a66c}', "\u{a66d}"),
    ('\u{a680}', "\u{a681}"),
    ('\u{a682}', "\u{a683}"),
    ('\u{a684}', "\u{a685}"),
    ('\u{a686}', "\u{a687}"),
    ('\u{a688}', "\u{a689}"),
    ('\u{a68a}', "\u{a68b}"),
    ('\u{a68c}', "\u{a68d}"),
    ('\u{a68e}', "\u{a68f}"),
    ('\u{a690}', "\u{a691}"),
    ('\u{a692}', "\u{a693}"),
    ('\u{a694}', "\u{a695}"),
    ('\u{a696}', "\u{a697}"),
    ('\u{a698}', "\u{a699}"),
    ('\u{a69a}', "\u{a69b}"),
    ('\u{a722}', "\u{a723}"),
    ('\u{a724}', "\u{a725}"),
    ('\u{a726}', "\u{a727}"),
    ('\u{a728}', "\u{a729}"),
    ('\u{a72a}', "\u{a72b}"),
    ('\u{a72c}', "\u{a72d}"),
    ('\u{a72e}', "\u{a72f}"),
    ('\u{a732}', "\u{a733}"),
    ('\u{a734}', "\u{a735}"),
    ('\u{a736}', "\u{a737}"),
    ('\u{a738}', "\u{a739}"),
    ('\u{a73a}', "\u{a73b}"),
    ('\u{a73c}', "\u{a73d}"),
    ('\u{a73e}', "\u{a73f}"),
    ('\u{a740}', "\u{a741}"),
    ('\u{a742}', "\u{a743}"),
    ('\u{a744}', "\u{a745}"),
    ('\u{a746}', "\u{a747}"),
    ('\u{a748}', "\u{a749}"),
    ('\u{a74a}', "\u{a74b}"),
    ('\u{a74c}', "\u{a74d}"),
    ('\u{a74e}', "\u{a74f}"),
    ('\u{a750}', "\u{a751}"),
    ('\u{a752}', "\u{a753}"),
    ('\u{a754}', "\u{a755}"),
    ('\u{a756}', "\u{a757}"),
    ('\u{a758}', "\u{a759}"),
    ('\u{a75a}', "\u{a75b}"),
    ('\u{a75c}', "\u{a75d}"),
    ('\u{a75e}', "\u{a75f}"),
    ('\u{a760}', "\u{a761}"),
    ('\u{a762}', "\u{a763}"),
    ('\u{a764}', "\u{a765}"),
    ('\u{a766}', "\u{a767}"),
    ('\u{a768}', "\u{a769}"),
    ('\u{a76a}', "\u{a76b}"),
    ('\u{a76c}', "\u{a76d}"),
    ('\u{a76e}', "\u{a76f}"),
    ('\u{a779}', "\u{a77a}"),
    ('\u{a77b}', "\u{a77c}"),
    ('\u{a77d}', "\u{1d79}"),
    ('\u{a77e}', "\u{a77f}"),
    ('\u{a780}', "\u{a781}"),
    ('\u{a782}', "\u{a783}"),
    ('\u{a784}', "\u{a785}"),
    ('\u{a786}', "\u{a787}"),
    ('\u{a78b}', "\u{a78c}"),
    ('\u{a78d}', "\u{265}"),
    ('\u{a790}', "\u{a791}"),
    ('\u{a792}', "\u{a793}"),
    ('\u{a796}', "\u{a797}"),
    ('\u{a798}', "\u{a799}"),
    ('\u{a79a}', "\u{a79b}"),
    ('\u{a79c}', "\u{a79d}"),
    ('\u{a79e}', "\u{a79f}"),
    ('\u{a7a0}', "\u{a7a1}"),
    ('\u{a7a2}', "\u{a7a3}"),
    ('\u{a7a4}', "\u{a7a5}"),
    ('\u{a7a6}', "\u{a7a7}"),
    ('\u{a7a8}', "\u{a7a9}"),
    ('\u{a7aa}', "\u{266}"),
    ('\u{a7ab}', "\u{25c}"),
    ('\u{a7ac}', "\u{261}"),
    ('\u{a7ad}', "\u{26c}"),
    ('\u{a7ae}', "\u{26a}"),
    ('\u{a7b0}', "\u{29e}"),
    ('\u{a7b1}', "\u{287}"),
    ('\u{a7b2}', "\u{29d}"),
    ('\u{a7b3}', "\u{ab53}"),
    ('\u{a7b4}', "\u{a7b5}"),
    ('\u{a7b6}', "\u{a7b7}"),
    ('\u{a7b8}', "\u{a7b9}"),
    ('\u{a7ba}', "\u{a7bb}"),
    ('\u{a7bc}', "\u{a7bd}"),
    ('\u{a7be}', "\u{a7bf}"),
    ('\u{a7c0}', "\u{a7c1}"),
    ('\u{a7c2}', "\u{a7c3}"),
    ('\u{a7c4}', "\u{a794}"),
    ('\u{a7c5}', "\u{282}"),
    ('\u{a7c6}', "\u{1d8e}"),
    ('\u{a7c7}', "\u{a7c8}"),
    ('\u{a7c9}', "\u{a7ca}"),
    ('\u{a7cb}', "\u{264}"),
    ('\u{a7cc}', "\u{a7cd}"),
    ('\u{a7ce}', "\u{a7cf}"),
    ('\u{a7d0}', "\u{a7d1}"),
    ('\u{a7d2}', "\u{a7d3}"),
    ('\u{a7d4}', "\u{a7d5}"),
    ('\u{a7d6}', "\u{a7d7}"),
    ('\u{a7d8}', "\u{a7d9}"),
    ('\u{a7da}', "\u{a7db}"),
    ('\u{a7dc}', "\u{19b}"),
    ('\u{a7f5}', "\u{a7f6}"),
    ('\u{ab70}', "\u{13a0}"),
    ('\u{ab71}', "\u{13a1}"),
    ('\u{ab72}', "\u{13a2}"),
    ('\u{ab73}', "\u{13a3}"),
    ('\u{ab74}', "\u{13a4}"),
    ('\u{ab75}', "\u{13a5}"),
    ('\u{ab76}', "\u{13a6}"),
    ('\u{ab77}', "\u{13a7}"),
    ('\u{ab78}', "\u{13a8}"),
    ('\u{ab79}', "\u{13a9}"),
    ('\u{ab7a}', "\u{13aa}"),
    ('\u{ab7b}', "\u{13ab}"),
    ('\u{ab7c}', "\u{13ac}"),
    ('\u{ab7d}', "\u{13ad}"),
    ('\u{ab7e}', "\u{13ae}"),
    ('\u{ab7f}', "\u{13af}"),
    ('\u{ab80}', "\u{13b0}"),
    ('\u{ab81}', "\u{13b1}"),
    ('\u{ab82}', "\u{13b2}"),
    ('\u{ab83}', "\u{13b3}"),
    ('\u{ab84}', "\u{13b4}"),
    ('\u{ab85}', "\u{13b5}"),
    ('\u{ab86}', "\u{13b6}"),
    ('\u{ab87}', "\u{13b7}"),
    ('\u{ab88}', "\u{13b8}"),
    ('\u{ab89}', "\u{13b9}"),
    ('\u{ab8a}', "\u{13ba}"),
    ('\u{ab8b}', "\u{13bb}"),
    ('\u{ab8c}', "\u{13bc}"),
    ('\u{ab8d}', "\u{13bd}"),
    ('\u{ab8e}', "\u{13be}"),
    ('\u{ab8f}', "\u{13bf}"),
    ('\u{ab90}', "\u{13c0}"),
    ('\u{ab91}', "\u{13c1}"),
    ('\u{ab92}', "\u{13c2}"),
    ('\u{ab93}', "\u{13c3}"),
    ('\u{ab94}', "\u{13c4}"),
    ('\u{ab95}', "\u{13c5}"),
    ('\u{ab96}', "\u{13c6}"),
    ('\u{ab97}', "\u{13c7}"),
    ('\u{ab98}', "\u{13c8}"),
    ('\u{ab99}', "\u{13c9}"),
    ('\u{ab9a}', "\u{13ca}"),
    ('\u{ab9b}', "\u{13cb}"),
    ('\u{ab9c}', "\u{13cc}"),
    ('\u{ab9d}', "\u{13cd}"),
    ('\u{ab9e}', "\u{13ce}"),
    ('\u{ab9f}', "\u{13cf}"),
    ('\u{aba0}', "\u{13d0}"),
    ('\u{aba1}', "\u{13d1}"),
    ('\u{aba2}', "\u{13d2}"),
    ('\u{aba3}', "\u{13d3}"),
    ('\u{aba4}', "\u{13d4}"),
    ('\u{aba5}', "\u{13d5}"),
    ('\u{aba6}', "\u{13d6}"),
    ('\u{aba7}', "\u{13d7}"),
    ('\u{aba8}', "\u{13d8}"),
    ('\u{aba9}', "\u{13d9}"),
    ('\u{abaa}', "\u{13da}"),
    ('\u{abab}', "\u{13db}"),
    ('\u{abac}', "\u{13dc}"),
    ('\u{abad}', "\u{13dd}"),
    ('\u{abae}', "\u{13de}"),
    ('\u{abaf}', "\u{13df}"),
    ('\u{abb0}', "\u{13e0}"),
    ('\u{abb1}', "\u{13e1}"),
    ('\u{abb2}', "\u{13e2}"),
    ('\u{abb3}', "\u{13e3}"),
    ('\u{abb4}', "\u{13e4}"),
    ('\u{abb5}', "\u{13e5}"),
    ('\u{abb6}', "\u{13e6}"),
    ('\u{abb7}', "\u{13e7}"),
    ('\u{abb8}', "\u{13e8}"),
    ('\u{abb9}', "\u{13e9}"),
    ('\u{abba}', "\u{13ea}"),
    ('\u{abbb}', "\u{13eb}"),
    ('\u{abbc}', "\u{13ec}"),
    ('\u{abbd}', "\u{13ed}"),
    ('\u{abbe}', "\u{13ee}"),
    ('\u{abbf}', "\u{13ef}"),
    ('\u{fb00}', "ff"),
    ('\u{fb01}', "fi"),
    ('\u{fb02}', "fl"),
    ('\u{fb03}', "ffi"),
    ('\u{fb04}', "ffl"),
    ('\u{fb05}', "st"),
    ('\u{fb06}', "st"),
    ('\u{fb13}', "\u{574}\u{576}"),
    ('\u{fb14}', "\u{574}\u{565}"),
    ('\u{fb15}', "\u{574}\u{56b}"),
    ('\u{fb16}', "\u{57e}\u{576}"),
    ('\u{fb17}', "\u{574}\u{56d}"),
    ('\u{ff21}', "\u{ff41}"),
    ('\u{ff22}', "\u{ff42}"),
    ('\u{ff23}', "\u{ff43}"),
    ('\u{ff24}', "\u{ff44}"),
    ('\u{ff25}', "\u{ff45}"),
    ('\u{ff26}', "\u{ff46}"),
    ('\u{ff27}', "\u{ff47}"),
    ('\u{ff28}', "\u{ff48}"),
    ('\u{ff29}', "\u{ff49}"),
    ('\u{ff2a}', "\u{ff4a}"),
    ('\u{ff2b}', "\u{ff4b}"),
    ('\u{ff2c}', "\u{ff4c}"),
    ('\u{ff2d}', "\u{ff4d}"),
    ('\u{ff2e}', "\u{ff4e}"),
    ('\u{ff2f}', "\u{ff4f}"),
    ('\u{ff30}', "\u{ff50}"),
    ('\u{ff31}', "\u{ff51}"),
    ('\u{ff32}', "\u{ff52}"),
    ('\u{ff33}', "\u{ff53}"),
    ('\u{ff34}', "\u{ff54}"),
    ('\u{ff35}', "\u{ff55}"),
    ('\u{ff36}', "\u{ff56}"),
    ('\u{ff37}', "\u{ff57}"),
    ('\u{ff38}', "\u{ff58}"),
    ('\u{ff39}', "\u{ff59}"),
    ('\u{ff3a}', "\u{ff5a}"),
    ('\u{10400}', "\u{10428}"),
    ('\u{10401}', "\u{10429}"),
    ('\u{10402}', "\u{1042a}"),
    ('\u{10403}', "\u{1042b}"),
    ('\u{10404}', "\u{1042c}"),
    ('\u{10405}', "\u{1042d}"),
    ('\u{10406}', "\u{1042e}"),
    ('\u{10407}', "\u{1042f}"),
    ('\u{10408}', "\u{10430}"),
    ('\u{10409}', "\u{10431}"),
    ('\u{1040a}', "\u{10432}"),
    ('\u{1040b}', "\u{10433}"),
    ('\u{1040c}', "\u{10434}"),
    ('\u{1040d}', "\u{10435}"),
    ('\u{1040e}', "\u{10436}"),
    ('\u{1040f}', "\u{10437}"),
    ('\u{10410}', "\u{10438}"),
    ('\u{10411}', "\u{10439}"),
    ('\u{10412}', "\u{1043a}"),
    ('\u{10413}', "\u{1043b}"),
    ('\u{10414}', "\u{1043c}"),
    ('\u{10415}', "\u{1043d}"),
    ('\u{10416}', "\u{1043e}"),
    ('\u{10417}', "\u{1043f}"),
    ('\u{10418}', "\u{10440}"),
    ('\u{10419}', "\u{10441}"),
    ('\u{1041a}', "\u{10442}"),
    ('\u{1041b}', "\u{10443}"),
    ('\u{1041c}', "\u{10444}"),
    ('\u{1041d}', "\u{10445}"),
    ('\u{1041e}', "\u{10446}"),
    ('\u{1041f}', "\u{10447}"),
    ('\u{10420}', "\u{10448}"),
    ('\u{10421}', "\u{10449}"),
    ('\u{10422}', "\u{1044a}"),
    ('\u{10423}', "\u{1044b}"),
    ('\u{10424}', "\u{1044c}"),
    ('\u{10425}', "\u{1044d}"),
    ('\u{10426}', "\u{1044e}"),
    ('\u{10427}', "\u{1044f}"),
    ('\u{104b0}', "\u{104d8}"),
    ('\u{104b1}', "\u{104d9}"),
    ('\u{104b2}', "\u{104da}"),
    ('\u{104b3}', "\u{104db}"),
    ('\u{104b4}', "\u{104dc}"),
    ('\u{104b5}', "\u{104dd}"),
    ('\u{104b6}', "\u{104de}"),
    ('\u{104b7}', "\u{104df}"),
    ('\u{104b8}', "\u{104e0}"),
    ('\u{104b9}', "\u{104e1}"),
    ('\u{104ba}', "\u{104e2}"),
    ('\u{104bb}', "\u{104e3}"),
    ('\u{104bc}', "\u{104e4}"),
    ('\u{104bd}', "\u{104e5}"),
    ('\u{104be}', "\u{104e6}"),
    ('\u{104bf}', "\u{104e7}"),
    ('\u{104c0}', "\u{104e8}"),
    ('\u{104c1}', "\u{104e9}"),
    ('\u{104c2}', "\u{104ea}"),
    ('\u{104c3}', "\u{104eb}"),
    ('\u{104c4}', "\u{104ec}"),
    ('\u{104c5}', "\u{104ed}"),
    ('\u{104c6}', "\u{104ee}"),
    ('\u{104c7}', "\u{104ef}"),
    ('\u{104c8}', "\u{104f0}"),
    ('\u{104c9}', "\u{104f1}"),
    ('\u{104ca}', "\u{104f2}"),
    ('\u{104cb}', "\u{104f3}"),
    ('\u{104cc}', "\u{104f4}"),
    ('\u{104cd}', "\u{104f5}"),
    ('\u{104ce}', "\u{104f6}"),
    ('\u{104cf}', "\u{104f7}"),
    ('\u{104d0}', "\u{104f8}"),
    ('\u{104d1}', "\u{104f9}"),
    ('\u{104d2}', "\u{104fa}"),
    ('\u{104d3}', "\u{104fb}"),
    ('\u{10570}', "\u{10597}"),
    ('\u{10571}', "\u{10598}"),
    ('\u{10572}', "\u{10599}"),
    ('\u{10573}', "\u{1059a}"),
    ('\u{10574}', "\u{1059b}"),
    ('\u{10575}', "\u{1059c}"),
    ('\u{10576}', "\u{1059d}"),
    ('\u{10577}', "\u{1059e}"),
    ('\u{10578}', "\u{1059f}"),
    ('\u{10579}', "\u{105a0}"),
    ('\u{1057a}', "\u{105a1}"),
    ('\u{1057c}', "\u{105a3}"),
    ('\u{1057d}', "\u{105a4}"),
    ('\u{1057e}', "\u{105a5}"),
    ('\u{1057f}', "\u{105a6}"),
    ('\u{10580}', "\u{105a7}"),
    ('\u{10581}', "\u{105a8}"),
    ('\u{10582}', "\u{105a9}"),
    ('\u{10583}', "\u{105aa}"),
    ('\u{10584}', "\u{105ab}"),
    ('\u{10585}', "\u{105ac}"),
    ('\u{10586}', "\u{105ad}"),
    ('\u{10587}', "\u{105ae}"),
    ('\u{10588}', "\u{105af}"),
    ('\u{10589}', "\u{105b0}"),
    ('\u{1058a}', "\u{105b1}"),
    ('\u{1058c}', "\u{105b3}"),
    ('\u{1058d}', "\u{105b4}"),
    ('\u{1058e}', "\u{105b5}"),
    ('\u{1058f}', "\u{105b6}"),
    ('\u{10590}', "\u{105b7}"),
    ('\u{10591}', "\u{105b8}"),
    ('\u{10592}', "\u{105b9}"),
    ('\u{10594}', "\u{105bb}"),
    ('\u{10595}', "\u{105bc}"),
    ('\u{10c80}', "\u{10cc0}"),
    ('\u{10c81}', "\u{10cc1}"),
    ('\u{10c82}', "\u{10cc2}"),
    ('\u{10c83}', "\u{10cc3}"),
    ('\u{10c84}', "\u{10cc4}"),
    ('\u{10c85}', "\u{10cc5}"),
    ('\u{10c86}', "\u{10cc6}"),
    ('\u{10c87}', "\u{10cc7}"),
    ('\u{10c88}', "\u{10cc8}"),
    ('\u{10c89}', "\u{10cc9}"),
    ('\u{10c8a}', "\u{10cca}"),
    ('\u{10c8b}', "\u{10ccb}"),
    ('\u{10c8c}', "\u{10ccc}"),
    ('\u{10c8d}', "\u{10ccd}"),
    ('\u{10c8e}', "\u{10cce}"),
    ('\u{10c8f}', "\u{10ccf}"),
    ('\u{10c90}', "\u{10cd0}"),
    ('\u{10c91}', "\u{10cd1}"),
    ('\u{10c92}', "\u{10cd2}"),
    ('\u{10c93}', "\u{10cd3}"),
    ('\u{10c94}', "\u{10cd4}"),
    ('\u{10c95}', "\u{10cd5}"),
    ('\u{10c96}', "\u{10cd6}"),
    ('\u{10c97}', "\u{10cd7}"),
    ('\u{10c98}', "\u{10cd8}"),
    ('\u{10c99}', "\u{10cd9}"),
    ('\u{10c9a}', "\u{10cda}"),
    ('\u{10c9b}', "\u{10cdb}"),
    ('\u{10c9c}', "\u{10cdc}"),
    ('\u{10c9d}', "\u{10cdd}"),
    ('\u{10c9e}', "\u{10cde}"),
    ('\u{10c9f}', "\u{10cdf}"),
    ('\u{10ca0}', "\u{10ce0}"),
    ('\u{10ca1}', "\u{10ce1}"),
    ('\u{10ca2}', "\u{10ce2}"),
    ('\u{10ca3}', "\u{10ce3}"),
    ('\u{10ca4}', "\u{10ce4}"),
    ('\u{10ca5}', "\u{10ce5}"),
    ('\u{10ca6}', "\u{10ce6}"),
    ('\u{10ca7}', "\u{10ce7}"),
    ('\u{10ca8}', "\u{10ce8}"),
    ('\u{10ca9}', "\u{10ce9}"),
    ('\u{10caa}', "\u{10cea}"),
    ('\u{10cab}', "\u{10ceb}"),
    ('\u{10cac}', "\u{10cec}"),
    ('\u{10cad}', "\u{10ced}"),
    ('\u{10cae}', "\u{10cee}"),
    ('\u{10caf}', "\u{10cef}"),
    ('\u{10cb0}', "\u{10cf0}"),
    ('\u{10cb1}', "\u{10cf1}"),
    ('\u{10cb2}', "\u{10cf2}"),
    ('\u{10d50}', "\u{10d70}"),
    ('\u{10d51}', "\u{10d71}"),
    ('\u{10d52}', "\u{10d72}"),
    ('\u{10d53}', "\u{10d73}"),
    ('\u{10d54}', "\u{10d74}"),
    ('\u{10d55}', "\u{10d75}"),
    ('\u{10d56}', "\u{10d76}"),
    ('\u{10d57}', "\u{10d77}"),
    ('\u{10d58}', "\u{10d78}"),
    ('\u{10d59}', "\u{10d79}"),
    ('\u{10d5a}', "\u{10d7a}"),
    ('\u{10d5b}', "\u{10d7b}"),
    ('\u{10d5c}', "\u{10d7c}"),
    ('\u{10d5d}', "\u{10d7d}"),
    ('\u{10d5e}', "\u{10d7e}"),
    ('\u{10d5f}', "\u{10d7f}"),
    ('\u{10d60}', "\u{10d80}"),
    ('\u{10d61}', "\u{10d81}"),
    ('\u{10d62}', "\u{10d82}"),
    ('\u{10d63}', "\u{10d83}"),
    ('\u{10d64}', "\u{10d84}"),
    ('\u{10d65}', "\u{10d85}"),
    ('\u{118a0}', "\u{118c0}"),
    ('\u{118a1}', "\u{118c1}"),
    ('\u{118a2}', "\u{118c2}"),
    ('\u{118a3}', "\u{118c3}"),
    ('\u{118a4}', "\u{118c4}"),
    ('\u{118a5}', "\u{118c5}"),
    ('\u{118a6}', "\u{118c6}"),
    ('\u{118a7}', "\u{118c7}"),
    ('\u{118a8}', "\u{118c8}"),
    ('\u{118a9}', "\u{118c9}"),
    ('\u{118aa}', "\u{118ca}"),
    ('\u{118ab}', "\u{118cb}"),
    ('\u{118ac}', "\u{118cc}"),
    ('\u{118ad}', "\u{118cd}"),
    ('\u{118ae}', "\u{118ce}"),
    ('\u{118af}', "\u{118cf}"),
    ('\u{118b0}', "\u{118d0}"),
    ('\u{118b1}', "\u{118d1}"),
    ('\u{118b2}', "\u{118d2}"),
    ('\u{118b3}', "\u{118d3}"),
    ('\u{118b4}', "\u{118d4}"),
    ('\u{118b5}', "\u{118d5}"),
    ('\u{118b6}', "\u{118d6}"),
    ('\u{118b7}', "\u{118d7}"),
    ('\u{118b8}', "\u{118d8}"),
    ('\u{118b9}', "\u{118d9}"),
    ('\u{118ba}', "\u{118da}"),
    ('\u{118bb}', "\u{118db}"),
    ('\u{118bc}', "\u{118dc}"),
    ('\u{118bd}', "\u{118dd}"),
    ('\u{118be}', "\u{118de}"),
    ('\u{118bf}', "\u{118df}"),
    ('\u{16e40}', "\u{16e60}"),
    ('\u{16e41}', "\u{16e61}"),
    ('\u{16e42}', "\u{16e62}"),
    ('\u{16e43}', "\u{16e63}"),
    ('\u{16e44}', "\u{16e64}"),
    ('\u{16e45}', "\u{16e65}"),
    ('\u{16e46}', "\u{16e66}"),
    ('\u{16e47}', "\u{16e67}"),
    ('\u{16e48}', "\u{16e68}"),
    ('\u{16e49}', "\u{16e69}"),
    ('\u{16e4a}', "\u{16e6a}"),
    ('\u{16e4b}', "\u{16e6b}"),
    ('\u{16e4c}', "\u{16e6c}"),
    ('\u{16e4d}', "\u{16e6d}"),
    ('\u{16e4e}', "\u{16e6e}"),
    ('\u{16e4f}', "\u{16e6f}"),
    ('\u{16e50}', "\u{16e70}"),
    ('\u{16e51}', "\u{16e71}"),
    ('\u{16e52}', "\u{16e72}"),
    ('\u{16e53}', "\u{16e73}"),
    ('\u{16e54}', "\u{16e74}"),
    ('\u{16e55}', "\u{16e75}"),
    ('\u{16e56}', "\u{16e76}"),
    ('\u{16e57}', "\u{16e77}"),
    ('\u{16e58}', "\u{16e78}"),
    ('\u{16e59}', "\u{16e79}"),
    ('\u{16e5a}', "\u{16e7a}"),
    ('\u{16e5b}', "\u{16e7b}"),
    ('\u{16e5c}', "\u{16e7c}"),
    ('\u{16e5d}', "\u{16e7d}"),
    ('\u{16e5e}', "\u{16e7e}"),
    ('\u{16e5f}', "\u{16e7f}"),
    ('\u{16ea0}', "\u{16ebb}"),
    ('\u{16ea1}', "\u{16ebc}"),
    ('\u{16ea2}', "\u{16ebd}"),
    ('\u{16ea3}', "\u{16ebe}"),
    ('\u{16ea4}', "\u{16ebf}"),
    ('\u{16ea5}', "\u{16ec0}"),
    ('\u{16ea6}', "\u{16ec1}"),
    ('\u{16ea7}', "\u{16ec2}"),
    ('\u{16ea8}', "\u{16ec3}"),
    ('\u{16ea9}', "\u{16ec4}"),
    ('\u{16eaa}', "\u{16ec5}"),
    ('\u{16eab}', "\u{16ec6}"),
    ('\u{16eac}', "\u{16ec7}"),
    ('\u{16ead}', "\u{16ec8}"),
    ('\u{16eae}', "\u{16ec9}"),
    ('\u{16eaf}', "\u{16eca}"),
    ('\u{16eb0}', "\u{16ecb}"),
    ('\u{16eb1}', "\u{16ecc}"),
    ('\u{16eb2}', "\u{16ecd}"),
    ('\u{16eb3}', "\u{16ece}"),
    ('\u{16eb4}', "\u{16ecf}"),
    ('\u{16eb5}', "\u{16ed0}"),
    ('\u{16eb6}', "\u{16ed1}"),
    ('\u{16eb7}', "\u{16ed2}"),
    ('\u{16eb8}', "\u{16ed3}"),
    ('\u{1e900}', "\u{1e922}"),
    ('\u{1e901}', "\u{1e923}"),
    ('\u{1e902}', "\u{1e924}"),
    ('\u{1e903}', "\u{1e925}"),
    ('\u{1e904}', "\u{1e926}"),
    ('\u{1e905}', "\u{1e927}"),
    ('\u{1e906}', "\u{1e928}"),
    ('\u{1e907}', "\u{1e929}"),
    ('\u{1e908}', "\u{1e92a}"),
    ('\u{1e909}', "\u{1e92b}"),
    ('\u{1e90a}', "\u{1e92c}"),
    ('\u{1e90b}', "\u{1e92d}"),
    ('\u{1e90c}', "\u{1e92e}"),
    ('\u{1e90d}', "\u{1e92f}"),
    ('\u{1e90e}', "\u{1e930}"),
    ('\u{1e90f}', "\u{1e931}"),
    ('\u{1e910}', "\u{1e932}"),
    ('\u{1e911}', "\u{1e933}"),
    ('\u{1e912}', "\u{1e934}"),
    ('\u{1e913}', "\u{1e935}"),
    ('\u{1e914}', "\u{1e936}"),
    ('\u{1e915}', "\u{1e937}"),
    ('\u{1e916}', "\u{1e938}"),
    ('\u{1e917}', "\u{1e939}"),
    ('\u{1e918}', "\u{1e93a}"),
    ('\u{1e919}', "\u{1e93b}"),
    ('\u{1e91a}', "\u{1e93c}"),
    ('\u{1e91b}', "\u{1e93d}"),
    ('\u{1e91c}', "\u{1e93e}"),
    ('\u{1e91d}', "\u{1e93f}"),
    ('\u{1e91e}', "\u{1e940}"),
    ('\u{1e91f}', "\u{1e941}"),
    ('\u{1e920}', "\u{1e942}"),
    ('\u{1e921}', "\u{1e943}"),
];
// ── end generated ──

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
    #[test]
    fn casefold_sharp_s_expands() {
        assert_eq!(string_casefold("Straße".into()), "strasse");
    }
    #[test]
    fn casefold_capital_sharp_s() {
        assert_eq!(string_casefold("\u{1e9e}".into()), "ss");
    }
    #[test]
    fn casefold_final_sigma_is_sigma() {
        assert_eq!(string_casefold("\u{3c2}".into()), "\u{3c3}");
    }
    #[test]
    fn casefold_long_s() {
        assert_eq!(string_casefold("\u{17f}".into()), "s");
    }
    #[test]
    fn casefold_cherokee_folds_to_upper() {
        assert_eq!(string_casefold("\u{ab70}".into()), "\u{13a0}");
        assert_eq!(string_casefold("\u{13f8}".into()), "\u{13f0}");
    }
    #[test]
    fn casefold_max_expansion() {
        assert_eq!(string_casefold("\u{390}".into()), "\u{3b9}\u{308}\u{301}");
    }
    #[test]
    fn casefold_dotted_capital_i_keeps_its_dot() {
        assert_eq!(string_casefold("\u{130}".into()), "i\u{307}");
        assert_eq!(string_casefold("I".into()), "i");
    }
    #[test]
    fn casefold_table_expansion_bounded() {
        for &(k, v) in CASEFOLD {
            assert!(!v.is_empty(), "empty fold for U+{:04X}", u32::from(k));
            assert!(
                v.len() <= 3 * k.len_utf8(),
                "fold of U+{:04X} grows past 3x",
                u32::from(k)
            );
        }
    }
    #[test]
    fn casefold_table_has_no_identity_row() {
        for &(k, v) in CASEFOLD {
            let mut buf = [0u8; 4];
            let one: &str = k.encode_utf8(&mut buf);
            assert_ne!(one, v, "identity row U+{:04X}", u32::from(k));
        }
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
    #[test]
    fn equal_fold_sharp_s() {
        assert!(string_equal_fold("STRASSE".into(), "straße".into()));
    }
    #[test]
    fn equal_fold_sigma_forms() {
        assert!(string_equal_fold(
            "\u{39f}\u{394}\u{39f}\u{3a3}".into(),
            "\u{3bf}\u{3b4}\u{3bf}\u{3c3}".into()
        ));
        assert!(string_equal_fold("\u{3c2}".into(), "\u{3a3}".into()));
    }
    #[test]
    fn equal_fold_distinct_words() {
        assert!(!string_equal_fold("hello".into(), "world".into()));
        assert!(!string_equal_fold("ss".into(), "s".into()));
    }
    #[test]
    fn equal_fold_no_turkic() {
        assert!(!string_equal_fold("i".into(), "\u{130}".into()));
        assert!(string_equal_fold("I".into(), "i".into()));
        assert!(!string_equal_fold("\u{131}".into(), "i".into()));
    }
    #[test]
    fn equal_fold_no_normalization() {
        assert!(!string_equal_fold("\u{e9}".into(), "e\u{301}".into()));
    }
    #[test]
    fn equal_fold_agrees_with_casefold() {
        for (a, b) in [
            ("Straße", "STRASSE"),
            ("\u{390}", "\u{3b9}\u{308}\u{301}"),
            ("ab", "abc"),
        ] {
            assert_eq!(
                string_equal_fold(a.into(), b.into()),
                string_casefold(a.into()) == string_casefold(b.into())
            );
        }
    }

    /// Checks the generated [`CASEFOLD`] table against ICU's default full case folding.
    ///
    /// Regenerate the table with
    /// `cargo test -p ipe-runtime-rust --features locale --lib print_casefold_table -- --ignored --nocapture`,
    /// paste the printed rows between the generated markers, and run `rustfmt`.
    #[cfg(feature = "locale")]
    mod icu_oracle {
        use super::super::folded;
        use icu_casemap::CaseMapper;

        /// The Rust source spelling of `s`: ASCII alphanumerics verbatim, every other char escaped.
        fn source_spelling(s: &str) -> String {
            s.chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() {
                        c.to_string()
                    } else {
                        c.escape_unicode().to_string()
                    }
                })
                .collect()
        }

        #[test]
        fn casefold_table_matches_unicode_fold() {
            let mapper = CaseMapper::new();
            let mut buf = [0u8; 4];
            for c in '\0'..=char::MAX {
                let one: &str = c.encode_utf8(&mut buf);
                let ours: String = folded(one).collect();
                assert_eq!(
                    ours,
                    mapper.fold_string(one),
                    "fold of U+{:04X}",
                    u32::from(c)
                );
            }
        }

        /// Prints the generated table rows from ICU, in table order.
        #[test]
        #[ignore = "generator: prints the CASEFOLD rows; run with --ignored --nocapture"]
        fn print_casefold_table() {
            let mapper = CaseMapper::new();
            let mut buf = [0u8; 4];
            for c in '\0'..=char::MAX {
                let one: &str = c.encode_utf8(&mut buf);
                let fold = mapper.fold_string(one);
                if fold != one {
                    println!(
                        "    ('{}', \"{}\"),",
                        source_spelling(one),
                        source_spelling(&fold)
                    );
                }
            }
        }
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
