//! Shared CSS/style injection-safety encoders — one policy, one place.
//!
//! This module is the SINGLE home for the CSS boundary smart constructors and
//! the `<style>`-body close-tag stripper. `Ipe.Ui`'s inline-style path
//! (`ui/render.rs`), `Ipe.Html.styleNode`'s `<style>` body (`html.rs`), and
//! `Ipe.Css`'s stylesheet renderers (`css.rs`) all import the identical
//! functions from here so no second, weaker encoder can drift into existence
//! (design §Q5 "three producers, two shared encoders, zero new ones").
//!
//! Security posture (PARSE, DON'T VALIDATE / MAKE INVALID STATES
//! UNREPRESENTABLE): every constructor here is the SOLE way to obtain the
//! corresponding `Safe*` type; each runs its charset/scan policy exactly once at
//! the boundary and the resulting value carries the proof of safety in its
//! structure, so downstream emit sinks consume the typed value and cannot forget
//! the check.

/// A validated CSS property name.  The SOLE construction path runs the full
/// charset policy exactly once at the call-site boundary; no downstream
/// re-check is needed (PARSE, DON'T VALIDATE).
///
/// Accepted charset: ASCII alphanumeric + `-` (covers standard properties and
/// vendor-prefixed ones).  CSS custom properties (`--foo`) are also accepted
/// since `--` is two `-` chars.  The empty string and any char outside
/// `[A-Za-z0-9-]` (including `:`, `;`, `{`, whitespace) is rejected, which
/// closes the key-injection vector where a malicious key like
/// `background:url(javascript:alert(1));x` could smuggle a full rule through.
pub(crate) struct SafeCssPropertyName<'a>(&'a str);

impl<'a> SafeCssPropertyName<'a> {
    /// Parse and validate a CSS property name.
    ///
    /// Returns `None` (silently drop) when `k` is empty or contains any byte
    /// outside `[A-Za-z0-9-]` after trimming leading/trailing whitespace.
    pub(crate) fn parse(k: &'a str) -> Option<Self> {
        let k = k.trim();
        let ok = !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if ok {
            Some(SafeCssPropertyName(k))
        } else {
            None
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0
    }
}

/// A validated CSS property value.  The SOLE construction path runs the full
/// security scan exactly once at the call-site boundary (PARSE, DON'T
/// VALIDATE).  Covers the two live XSS holes in the previous prefix-only gate:
///
/// 1. **Prefix bypass** — `0; background:url(javascript:…)` has a safe prefix
///    but contains an injection mid-value.  Whole-string scan closes this.
/// 2. **Key bypass** — delegated to [`SafeCssPropertyName`]; value gate is
///    not responsible for keys.
///
/// Checks (all case-folded on the whole string, with whitespace stripped for
/// the `url(`-scheme sub-checks to catch `url( javascript:…`):
/// - Declaration / ruleset breakout chars: `;` `{` `}` `</` `/*` `@import`.
/// - Script sinks anywhere in the value: `expression(`, `javascript:`,
///   `vbscript:`, `url(javascript:`, `url(vbscript:`, `url(data:text`,
///   `url(data:application`.
pub(crate) struct SafeCssValue<'a>(&'a str);

/// Structural breakout / script-property patterns that must never survive in a
/// raw `<style>`-body fragment (`Css.raw` / `Css.keyframes`). A raw body is a
/// full stylesheet fragment, so block-structure characters (`{` `}` `;`) are
/// LEGAL here (unlike a single declaration value) — the danger is an at-rule
/// (`@import` CSS-level SSRF, `@charset`), a style-tag / comment breakout
/// (`</` `/*`), or a script-execution property.
///
/// URL schemes are NOT in this list: every `url(…)` argument is judged
/// positively by [`raw_body_url_args_all_safe`], which delegates to the SAME
/// scheme-free [`url_arg_is_safe`] the declaration-value grammar uses — so a
/// remote (`url(http://…)`), protocol-relative (`url(//…)`), script-scheme, or
/// scriptable-data (`url(data:image/svg…)`, `url(data:text/html…)`) reference is
/// rejected by construction, none of which a denylist would need to name.
/// Checked against BOTH the raw fragment and its CSS-escape-decoded form so a
/// hex-escaped payload (`\40 import`, `x:e\78 pression(…)`) cannot slip past.
const BAD_RAW_BODY_PATTERNS: &[&str] = &[
    "@import",
    "@charset",
    "@namespace",
    "@font-face",
    "</",
    "/*",
    "*/",
    "expression(",
    "javascript:",
    "vbscript:",
    // Legacy script-execution properties: Firefox XBL (`-moz-binding:`) and
    // IE HTC (`behavior:`). Neither appears in valid modern CSS; block both
    // as defence-in-depth for contexts that must defend legacy engines.
    "-moz-binding:",
    "behavior:",
];

/// True when EVERY `url(…)` occurrence in `low_nows` (already lowercased,
/// whitespace stripped) carries a safe argument, judged by the shared
/// scheme-free [`url_arg_is_safe`] — the identical policy the declaration-value
/// grammar applies to a `url(...)` token, so the raw-body path and the value
/// path cannot disagree on a URL. A `url(` with no closing `)` in the remaining
/// input is treated as UNSAFE (fail closed on a malformed / truncated token).
///
/// Parse, don't validate: only a scheme-free same-origin reference is accepted;
/// every scheme-bearing or authority-bearing argument is refused without a
/// per-scheme denylist entry, so a novel scheme fails closed by default.
fn raw_body_url_args_all_safe(low_nows: &str) -> bool {
    let mut rest = low_nows;
    while let Some(pos) = rest.find("url(") {
        let after = &rest[pos + "url(".len()..];
        // The argument runs to the first `)`; a missing close is fail-closed.
        let Some(close) = after.find(')') else {
            return false;
        };
        // Strip one layer of matching quotes so `url('…')` / `url("…")` is
        // judged on the same bytes as the bare form.
        let arg = after[..close].trim_matches(|c| c == '"' || c == '\'');
        if !url_arg_is_safe(arg.as_bytes()) {
            return false;
        }
        rest = &after[close + 1..];
    }
    true
}

/// True when `low` (already lowercased) carries a raw-`<style>`-body breakout —
/// an at-rule, a style-tag / comment breakout, a script-execution property, or a
/// `url(…)` whose argument fails the shared scheme-free [`url_arg_is_safe`]
/// allowlist. Shared by the raw and CSS-escape-decoded passes of
/// [`sink_safe_raw_body`] so they cannot drift. Whitespace is stripped before
/// the scan so `@ import`, `url( http:`, and `expression (` cannot evade by
/// inserting spaces.
fn raw_body_has_dangerous_pattern(low: &str) -> bool {
    let low_nows: String = low.chars().filter(|c| !c.is_whitespace()).collect();
    if BAD_RAW_BODY_PATTERNS
        .iter()
        .any(|bad| low_nows.contains(bad))
    {
        return true;
    }
    !raw_body_url_args_all_safe(&low_nows)
}

/// Sink-side validation of a raw `<style>`-body fragment — the body carried by
/// `Css.raw` and (per-frame-joined) `Css.keyframes`. A raw fragment is a
/// TRUSTED-INPUT escape hatch (`dangerouslySetInnerHTML`-class): block structure
/// (`{` `}` `;`) is legitimate, so this does NOT reuse the flat declaration-value
/// policy. It rejects an at-rule (`@import` CSS-level SSRF), a `<style>`/comment
/// breakout (`</` `/*` `*/`), a script-execution property, or a `url(…)` whose
/// argument fails the scheme-free [`url_arg_is_safe`] allowlist — so a remote
/// (`url(http://…)`), protocol-relative (`url(//…)`), script-scheme, or
/// scriptable-data (`url(data:image/svg…)`, `url(data:text/html…)`) reference is
/// rejected by construction rather than by naming it. Checked in BOTH the raw
/// and CSS-escape-decoded (`css_unescape`) forms, with whitespace stripped for
/// the scan. This is the faithful counterpart to `Ipe.Css`'s `.ipe` gate: the
/// same normalization the `<style>` sink relies on runs at the `raw`/`keyframes`
/// boundary, so a CSS-escaped payload that a raw substring check would miss
/// (`\40 import`, `x:e\78 pression(…)`) is dropped here.
///
/// Returns `Just(())` when the body carries no dangerous construct (the Ipê side
/// keeps its ORIGINAL, unmodified bytes — no reformat), `Nothing` (fail-closed)
/// the moment a breakout is detected.
#[must_use]
pub(crate) fn sink_safe_raw_body(body: &str) -> bool {
    let low = body.to_ascii_lowercase();
    if raw_body_has_dangerous_pattern(&low) {
        return false;
    }
    // Defence-in-depth: decode CSS backslash escapes and re-scan so a
    // hex-escaped bypass (`\40 import`, `x:e\78 pression(…)`) is caught too.
    let decoded_low = css_unescape(&low);
    !raw_body_has_dangerous_pattern(&decoded_low)
}

/// Decode CSS backslash escapes (CSS Syntax Level 3 §4.3.7) for DETECTION
/// purposes only — the decoded string is never emitted; [`SafeCssValue`]
/// keeps the caller's ORIGINAL string on success. A value that hides a
/// blocked keyword or breakout char behind a hex escape (`\65 xpression(…)`,
/// `\3b` for `;`) decodes to the literal form here, so the second-pass scan
/// (each gate's grammar / allowlist check) catches it.
///
/// Best-effort / fail-closed, not a spec-complete CSS tokenizer: an escape
/// decoding to an invalid Unicode scalar value is dropped rather than
/// reconstructed (erring toward "the scan sees less" is the safe direction
/// for a detector — it never helps an attacker hide a keyword).
fn css_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let mut hex = String::new();
        while hex.len() < 6 {
            match chars.peek() {
                Some(h) if h.is_ascii_hexdigit() => {
                    hex.push(*h);
                    chars.next();
                }
                _ => break,
            }
        }
        if !hex.is_empty() {
            // One trailing whitespace char is consumed as the escape's
            // delimiter (CSS Syntax §4.3.7), if present.
            if matches!(chars.peek(), Some(w) if w.is_whitespace()) {
                chars.next();
            }
            if let Ok(cp) = u32::from_str_radix(&hex, 16)
                && let Some(ch) = char::from_u32(cp)
            {
                out.push(ch);
            }
            continue;
        }
        // `\` followed by a non-hex char: CSS escapes that literal char.
        if let Some(next) = chars.next() {
            out.push(next);
        }
        // trailing lone backslash (no following char): dropped.
    }
    out
}

/// Why a CSS value was rejected by the security scan. Used only to name the
/// reason in the A9 developer-facing diagnostic; the security decision itself is
/// unchanged (any reason ⇒ drop).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CssStripReason {
    /// A declaration / ruleset / `<style>` / comment breakout in the raw value.
    RawBreakout,
    /// A breakout revealed only after decoding CSS backslash escapes (a
    /// hex-escaped payload like `\65 xpression(…)`).
    EscapedBreakout,
}

impl CssStripReason {
    fn describe(self) -> &'static str {
        match self {
            Self::RawBreakout => {
                "contains a CSS breakout (one of ; { } </ /* @import or a script-sink scheme)"
            }
            Self::EscapedBreakout => {
                "hides a CSS breakout behind a backslash escape (decodes to ; { } @import or a script sink)"
            }
        }
    }
}

/// Where a CSS value came from — the provenance the A9 loud-strip diagnostic
/// keys on. A `DeveloperLiteral` is a compile-time-literal value the author
/// wrote in source, so silently dropping it is almost always a mistake worth
/// surfacing; an `Untrusted` value is Model-derived / attacker-influenceable and
/// MUST stay silently stripped (a diagnostic on it would be a log-spam / info
/// leak vector driven by untrusted input).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CssValueOrigin {
    DeveloperLiteral,
    Untrusted,
}

/// Function names accepted as the `<ident>(` head of a value function token.
/// Every other name rejects the value (deny-by-default). MUST stay identical to
/// `ipe_kernels::css_value_safety::ALLOWED_FUNCTIONS` — the
/// `value_policy_agrees_with_shared_kernel_policy` test pins the whole policy
/// equal, so a divergence here is caught at test time. `url` is present but its
/// argument is gated scheme-free by [`url_arg_is_safe`].
const ALLOWED_VALUE_FUNCTIONS: &[&str] = &[
    "rgb",
    "rgba",
    "hsl",
    "hsla",
    "hwb",
    "lab",
    "lch",
    "oklab",
    "oklch",
    "color",
    "color-mix",
    "var",
    "calc",
    "min",
    "max",
    "clamp",
    "env",
    "linear-gradient",
    "radial-gradient",
    "conic-gradient",
    "repeating-linear-gradient",
    "repeating-radial-gradient",
    "repeating-conic-gradient",
    "translate",
    "translatex",
    "translatey",
    "translatez",
    "translate3d",
    "scale",
    "scalex",
    "scaley",
    "scalez",
    "scale3d",
    "rotate",
    "rotatex",
    "rotatey",
    "rotatez",
    "rotate3d",
    "skew",
    "skewx",
    "skewy",
    "matrix",
    "matrix3d",
    "perspective",
    "repeat",
    "minmax",
    "fit-content",
    "blur",
    "brightness",
    "contrast",
    "drop-shadow",
    "grayscale",
    "hue-rotate",
    "invert",
    "opacity",
    "saturate",
    "sepia",
    "cubic-bezier",
    "steps",
    "url",
    "format",
    "local",
    "attr",
    "counter",
    "counters",
];

/// Maximum nested-function depth the value grammar descends before rejecting.
/// Every allowlisted function argument list recurses one level
/// ([`value_parse_function`] → [`value_grammar_parses`]), so an attacker-authored
/// value like `calc(calc(calc(…)))` nested N deep would otherwise cost N stack
/// frames — unbounded on untrusted (Model-derived) CSS, a stack-overflow abort
/// that breaks soundness (PRINCIPLES §3, bounded by construction). A real CSS
/// value nests only a handful of levels (`repeating-linear-gradient(color-mix(…),
/// calc(…))`); this ceiling is far above any legitimate value, and a value past
/// it is refused (fail-closed, same drop-on-doubt outcome as any unrecognized
/// construct). MUST stay identical to
/// `ipe_kernels::css_value_safety::MAX_VALUE_DEPTH` — the
/// `value_policy_agrees_with_shared_kernel_policy` test pins the whole policy
/// equal, so a divergence is caught at test time.
const MAX_VALUE_DEPTH: usize = 32;

/// Parse `s` (already lowercased) against the allowlisted CSS declaration-value
/// grammar. Returns `false` on the first unrecognized byte, unbalanced paren,
/// unrecognized function name, scheme-bearing `url(...)`, or a nesting depth past
/// [`MAX_VALUE_DEPTH`]. Mirror of the shared
/// `ipe_kernels::css_value_safety::value_parses`.
fn value_grammar_parses(s: &str) -> bool {
    value_grammar_parses_at(s, 0)
}

/// Depth-tracked core of [`value_grammar_parses`]. `depth` counts the nested
/// function-argument recursions taken to reach `s`; past [`MAX_VALUE_DEPTH`] the
/// value is rejected (fail-closed) rather than descending further.
fn value_grammar_parses_at(s: &str, depth: usize) -> bool {
    if depth > MAX_VALUE_DEPTH {
        return false;
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    while let Some(&c) = bytes.get(i) {
        if c.is_ascii_whitespace() || c == b',' || c == b'/' || c == b'%' {
            i += 1;
            continue;
        }
        // The `!important` priority flag: `!` is admitted ONLY when the trimmed
        // remainder is exactly `important`. Mirror of the shared kernel gate.
        if c == b'!' {
            return s
                .get(i + 1..)
                .is_some_and(|rest| rest.trim() == "important");
        }
        if c == b'"' || c == b'\'' {
            match value_parse_string(bytes, i, c) {
                Some(next) => i = next,
                None => return false,
            }
            continue;
        }
        match value_parse_token(bytes, i, depth) {
            Some(next) => i = next,
            None => return false,
        }
    }
    true
}

/// Parse one value token (ident/number run, optionally an `ident(...)` function
/// call) starting at `start`. Mirror of the shared kernel's `parse_token`.
fn value_parse_token(bytes: &[u8], start: usize, depth: usize) -> Option<usize> {
    let mut i = start;
    while bytes.get(i).is_some_and(|&b| is_value_token_byte(b)) {
        i += 1;
    }
    if bytes.get(i) == Some(&b'(') {
        return value_parse_function(bytes, bytes.get(start..i)?, i, depth);
    }
    if i > start { Some(i) } else { None }
}

/// Parse a balanced `name(...)` function call. `name` must be on
/// [`ALLOWED_VALUE_FUNCTIONS`]; `url(...)` gates its argument scheme-free, every
/// other function recurses into its argument list (one deeper level). Mirror of
/// the shared kernel's `parse_function`.
fn value_parse_function(bytes: &[u8], name: &[u8], open: usize, depth: usize) -> Option<usize> {
    let name_str = core::str::from_utf8(name).ok()?;
    if !ALLOWED_VALUE_FUNCTIONS.contains(&name_str) {
        return None;
    }
    // `paren_depth` is the local bracket-balance counter — distinct from the
    // recursion `depth` param, which bounds nested-function descent.
    let mut paren_depth = 0usize;
    let mut close = None;
    let mut i = open;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'(' => paren_depth += 1,
            b')' => {
                paren_depth = paren_depth.saturating_sub(1);
                if paren_depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    let close = close?;
    let inner = bytes.get(open + 1..close)?;
    if name_str == "url" {
        if !url_arg_is_safe(inner) {
            return None;
        }
    } else {
        let inner_str = core::str::from_utf8(inner).ok()?;
        if !value_grammar_parses_at(inner_str, depth + 1) {
            return None;
        }
    }
    Some(close + 1)
}

/// A `url(...)` argument is safe ONLY when it is a scheme-free, non-authority
/// reference: no `:` (scheme), no leading `//` (protocol-relative host), no
/// quote/paren/whitespace/control byte. Mirror of the shared kernel's
/// `url_arg_is_safe`.
fn url_arg_is_safe(inner: &[u8]) -> bool {
    let arg = inner.trim_ascii();
    if arg.is_empty() || arg.starts_with(b"//") {
        return false;
    }
    arg.iter().all(|&b| is_url_path_byte(b))
}

/// Parse a quoted string token starting at the opening quote `q` at `start`.
/// Mirror of the shared kernel's `parse_string`.
fn value_parse_string(bytes: &[u8], start: usize, q: u8) -> Option<usize> {
    let mut i = start + 1;
    while let Some(&c) = bytes.get(i) {
        if c == b'\\' {
            i += 2;
            continue;
        }
        if c == q {
            return Some(i + 1);
        }
        if c == b'<' || c == b'>' || c == b'{' || c == b'}' || c == b';' || c < 0x20 {
            return None;
        }
        i += 1;
    }
    None
}

/// Bytes permitted in a bare value token. Mirror of the shared kernel's
/// `is_token_byte` (`\` admitted in the raw parse; the decoded parse judges it).
const fn is_value_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'#' | b'.' | b'+' | b'-' | b'_' | b'\\') || b >= 0x80
}

/// Bytes permitted inside a scheme-free `url()` path argument. Mirror of the
/// shared kernel's `is_url_path_byte`.
const fn is_url_path_byte(b: u8) -> bool {
    is_value_token_byte(b) || matches!(b, b'/' | b'?' | b'&' | b'=' | b'~')
}

/// Run the CSS value security scan, returning WHY the value is unsafe (for the
/// A9 diagnostic) rather than a bare `Option`. `Ok(())` ⇒ safe.
///
/// The DECISION is an allowlisted CSS declaration-value grammar
/// ([`value_grammar_parses`], parse-don't-validate): a value is safe IFF every
/// token is a recognized ident / number / hex-colour / string / allowlisted
/// function and every `url(...)` argument is scheme-free — anything
/// unrecognized is rejected (deny-by-default / fail-closed). This is the exact
/// policy of the shared `ipe_kernels::css_value_safety` gate; a `#[test]`
/// (`value_policy_agrees_with_shared_kernel_policy`) pins the two equal so the
/// render gate and the backend hoist gate can never drift. The kernel is a
/// compiler crate and stays a test-only dependency of the runtime (it must not
/// enter the runtime's `wasm32` production closure), so the grammar is mirrored
/// here rather than called at render time.
///
/// The A9 reason classification distinguishes a value rejected in its RAW form
/// from one that parsed raw but is rejected only after CSS-escape decoding (a
/// hex-escaped payload), so the developer diagnostic can name which.
fn scan_css_value(v: &str) -> Result<(), CssStripReason> {
    if v.trim().is_empty() {
        return Err(CssStripReason::RawBreakout);
    }
    let low = v.to_ascii_lowercase();
    if !value_grammar_parses(&low) {
        return Err(CssStripReason::RawBreakout);
    }
    // `css_unescape` is the identity on backslash-free input, so the escaped-form
    // pass runs only when a backslash is present; a backslash-free value can never
    // be an `EscapedBreakout`, keeping both the decision and the reason identical.
    if low.contains('\\') && !value_grammar_parses(&css_unescape(&low)) {
        return Err(CssStripReason::EscapedBreakout);
    }
    Ok(())
}

impl<'a> SafeCssValue<'a> {
    /// Parse and validate a CSS property value.
    ///
    /// Returns `None` (silently drop) when any dangerous pattern is found —
    /// in either the raw value or its CSS-escape-decoded form.
    pub(crate) fn parse(v: &'a str) -> Option<Self> {
        match scan_css_value(v) {
            Ok(()) => Some(SafeCssValue(v)),
            Err(_) => None,
        }
    }

    /// A9 (loud-strip diagnostic): parse a CSS value, and when it is rejected,
    /// surface a developer-facing diagnostic IFF the value was
    /// developer-authored (a compile-time literal). A Model-derived / untrusted
    /// value stays silently stripped — the security outcome is identical to
    /// [`parse`] in every case; only the diagnostic side effect differs.
    ///
    /// The diagnostic names the offending value and the reason, so a developer
    /// whose literal `Ui.style` / gradient / font value was silently doing
    /// nothing learns why. It goes to stderr (dev channel), never the rendered
    /// page, so it cannot become an XSS or content sink.
    pub(crate) fn parse_reporting(v: &'a str, origin: CssValueOrigin) -> Option<Self> {
        match scan_css_value(v) {
            Ok(()) => Some(SafeCssValue(v)),
            Err(reason) => {
                report_stripped_value(v, reason, origin);
                None
            }
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0
    }
}

/// Emit the A9 loud-strip diagnostic for a rejected CSS value — but ONLY for a
/// developer-authored literal. Kept separate + `#[cold]` so the common
/// (accepted, or untrusted-rejected) path stays branch-light.
///
/// Testable in isolation: the decision "does this (value, origin, reason) warrant
/// a diagnostic?" is [`should_report_stripped`]; this function performs the I/O.
#[cold]
fn report_stripped_value(value: &str, reason: CssStripReason, origin: CssValueOrigin) {
    if should_report_stripped(origin) {
        // A bounded, single-line preview so a huge value cannot flood the log.
        let preview: String = value.chars().take(120).collect();
        crate::system::write_stderr_line(&format!(
            "ipe: dropped an unsafe developer-authored CSS value {preview:?} — it {} \
             (nothing was emitted for it). Fix the literal or move the dynamic part \
             into your Model.",
            reason.describe()
        ));
    }
}

/// A9: the pure decision behind [`report_stripped_value`] — a developer literal
/// warrants a diagnostic; an untrusted value never does. Split out so both
/// branches are unit-testable without capturing stderr.
pub(crate) fn should_report_stripped(origin: CssValueOrigin) -> bool {
    matches!(origin, CssValueOrigin::DeveloperLiteral)
}

/// Sink-side re-validation of a `;`-joined CSS declaration list — the payload
/// carried by the `data-ipe-mq-rules` / `data-ipe-pc-rules` style markers.
///
/// The PRODUCER (`ui_media_query_` / `ui_on_pseudo_`) builds this string from
/// [`SafeCssValue`]-gated declarations, but a caller can FORGE the marker
/// directly with `Ui.htmlAttribute "data-ipe-mq-rules" "…}[x]{@import url(…)"`,
/// which never passes through the producer at all. The raw marker String is
/// therefore the real untrusted boundary — parse, don't validate — so the SINK
/// must re-validate rather than trust an upstream that a generic `htmlAttribute`
/// escape hatch can side-step.
///
/// Splits on `;` into declarations and each declaration on its FIRST `:` into a
/// `property:value` pair (parse, don't validate — a declaration IS that pair),
/// gating the property name through [`SafeCssPropertyName`] and the value
/// through the shared allowlist-grammar [`SafeCssValue`] policy. A declaration
/// with no `:`, an unsafe property name, or an unrecognized value drops the
/// WHOLE block (`None`, fail-closed). Returns the ORIGINAL, unmodified slice
/// when EVERY declaration is safe (byte-identical to the producer output — no
/// reformat). A block of only empty declarations yields `None`.
///
/// `cfg(feature = "web-core")`-gated: its only callers are the render-core style
/// sink's `build_mq` / `build_pc` (`web/style_inject.rs`), themselves under the
/// render-core floor — so the helper is dead code in a runtime built without any
/// render host (served web, browser-WASM, or native webview).
#[cfg(feature = "web-core")]
pub(crate) fn sink_safe_declaration_list(rules: &str) -> Option<&str> {
    let mut any = false;
    for decl in rules.split(';') {
        let d = decl.trim();
        if d.is_empty() {
            continue;
        }
        // A declaration is `property : value`; split on the FIRST `:` only, so a
        // `:` inside the value (none survive the value gate, but be precise) does
        // not mis-split. A declaration with no `:` is malformed — reject.
        let (prop, value) = d.split_once(':')?;
        SafeCssPropertyName::parse(prop)?;
        SafeCssValue::parse(value.trim())?;
        any = true;
    }
    if any { Some(rules) } else { None }
}

/// Sink-side re-validation of a `@keyframes` BODY — the `<kfBody>` slot of the
/// `data-ipe-anim-rules` marker (`name||tail||kfBody||respect`). A keyframes
/// body legitimately contains `{` `}` `;` (`0% { opacity: 0; … } 100% { … }`),
/// so the flat declaration-value policy cannot be reused — this validator
/// parses the keyframe GRAMMAR instead:
///
/// ```text
/// body      := (selector block)+          -- nothing outside blocks
/// selector  := comma-separated tokens, each `from` | `to` | `<number>%`
/// block     := `{` decl-list `}`          -- keyframe blocks cannot nest
/// decl-list := `;`-separated declarations, each through the shared
///              SafeCssValue policy (raw + CSS-escape-decoded scans)
/// ```
///
/// Returns the ORIGINAL slice when every selector and every declaration is
/// safe (byte-identical passthrough — no reformat); `None` (fail-closed) on
/// ANY breakout: non-keyframe selector text, trailing content after the last
/// block, a missing `{`/`}`, `@import`/script-sink/`</`/`/*` in a declaration
/// (a nested `{` inside a block lands in a declaration and is rejected by the
/// same policy), or an empty body.
///
/// `cfg(feature = "web-core")`-gated for the same reason as
/// [`sink_safe_declaration_list`]: its only caller is the render-core style
/// sink's `build_anim` (`web/style_inject.rs`).
#[cfg(feature = "web-core")]
pub(crate) fn sink_safe_keyframes_body(body: &str) -> Option<&str> {
    let mut rest = body.trim_start();
    if rest.is_empty() {
        return None;
    }
    while !rest.is_empty() {
        let open = rest.find('{')?;
        if !is_safe_keyframe_selector(&rest[..open]) {
            return None;
        }
        let after_open = &rest[open + 1..];
        // First `}` closes the block — a nested `{` before it stays inside
        // `decls` and is rejected by the SafeCssValue scan below.
        let close = after_open.find('}')?;
        for d in after_open[..close].split(';') {
            let d = d.trim();
            if d.is_empty() {
                continue;
            }
            // Each keyframe declaration is a `property : value` pair — split on
            // the first `:` and gate the name and value separately (a nested `{`
            // or breakout lands in one side and is rejected by its gate).
            let (prop, value) = d.split_once(':')?;
            SafeCssPropertyName::parse(prop)?;
            SafeCssValue::parse(value.trim())?;
        }
        rest = after_open[close + 1..].trim_start();
    }
    Some(body)
}

/// A keyframe selector list: comma-separated tokens, each `from` / `to`
/// (ASCII-case-insensitive) or a percentage with an optional single decimal
/// point (`0%`, `12.5%`). Anything else — including every breakout char — is
/// rejected, so no escape/obfuscation can hide in the selector slot.
#[cfg(feature = "web-core")]
fn is_safe_keyframe_selector(sel: &str) -> bool {
    let s = sel.trim();
    !s.is_empty()
        && s.split(',').all(|tok| {
            let t = tok.trim();
            if t.eq_ignore_ascii_case("from") || t.eq_ignore_ascii_case("to") {
                return true;
            }
            match t.strip_suffix('%') {
                Some(num) => {
                    !num.is_empty()
                        && num.bytes().all(|b| b.is_ascii_digit() || b == b'.')
                        && num.bytes().filter(|&b| b == b'.').count() <= 1
                }
                None => false,
            }
        })
}

/// A validated CSS selector / media-query string (NEW — strict, drop-on-doubt).
///
/// Allowed charset: ASCII letters, digits, and the CSS structural set
/// `. # : - _ [ ] = " ' , > + ~ * ( ) % space` plus the injection-safe
/// attribute-selector operators `^ $ |` (`[href^="/"]`, `[lang|="en"]`).
/// Rejected: `{ } ;` (declaration/ruleset breakout), `@` (at-rule injection —
/// the leading `@media`/`@keyframes` keyword is supplied by the renderer, never
/// by the user selector string), `<` `/` `\` (element / close-tag / comment /
/// escape breakout, `</style>` and `/*`).  A selector that fails is DROPPED
/// with its rule
/// (design §Q4-4 + §6.3 "start strict; `strip_style_close` is defence-in-depth,
/// not the primary gate").
pub(crate) struct SafeCssSelector<'a>(&'a str);

impl<'a> SafeCssSelector<'a> {
    /// Parse and validate a CSS selector / media-query string.
    ///
    /// Returns `None` (drop the rule) when `sel` is empty (after trimming) or
    /// contains any byte outside the conservative structural allowlist.
    pub(crate) fn parse(sel: &'a str) -> Option<Self> {
        let s = sel.trim();
        if s.is_empty() {
            return None;
        }
        // Comment digraphs are rejected up front: a lone `/` is allowed (it
        // occurs in attribute-value selectors like `a[href^="/blog"]`), but
        // `/*` / `*/` would open/close a CSS comment that could swallow later
        // rules. `<` is fully blocked below, so `</style` cannot form.
        if s.contains("/*") || s.contains("*/") {
            return None;
        }
        // Explicit allowlist — every accepted byte is enumerated; anything else
        // (notably `{ } ; @ < \` and controls / non-ASCII) drops the rule.
        let ok = s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'.' | b'#'
                        | b':'
                        | b'-'
                        | b'_'
                        | b'['
                        | b']'
                        | b'='
                        | b'"'
                        | b'\''
                        | b','
                        | b'>'
                        | b'+'
                        | b'~'
                        | b'*'
                        | b'('
                        | b')'
                        | b'%'
                        | b'^'
                        | b'$'
                        | b'|'
                        | b'/'
                        | b' '
                )
        });
        if ok { Some(SafeCssSelector(s)) } else { None }
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0
    }
}

/// A validated CSS media-query condition string (`Ui.mediaQuery` /
/// `Ui.breakpoint` — the text spliced into `@media <query> {` inside a raw
/// `<style>` body by `web::style_inject::build_mq`).
///
/// Deliberately a DISTINCT boundary type from [`SafeCssSelector`]: the selector
/// allowlist blocks `<` outright, but Media Queries Level 4 range syntax
/// legitimately uses it (`(400px <= width <= 700px)`), and a media query is a
/// different grammar from a selector.
///
/// The policy is a POSITIVE grammar allowlist, not a breakout denylist: a media
/// query is a boolean feature test (`(min-width: 768px) and (hover: hover)`,
/// media types like `screen`/`all`, the connectives `and`/`or`/`not`/`only`,
/// `,` lists, and Level-4 range operators `< > =`). It therefore uses ONLY the
/// charset `[a-z0-9 _-]`, `:`, `.`, `%`, `(`, `)`, `,`, `<`, `>`, `=`. Every
/// other byte — `{` `}` `;` `@` `/` `\` `<tag>` quotes, and crucially any `url(`
/// which never appears in a real query — is outside the grammar and drops the
/// whole rule by construction. Because URLs are grammatically impossible here,
/// there is no fetch / SSRF / exfil sink to reason about at all. Checked on both
/// the raw and CSS-escape-decoded forms so a hex-escaped byte cannot smuggle a
/// character back into the string.
pub(crate) struct SafeCssMediaQuery<'a>(&'a str);

impl<'a> SafeCssMediaQuery<'a> {
    /// The positive per-byte grammar of a media-query condition, PLUS an
    /// explicit rejection of any `url(` token. The charset allows `:` `(` `)`
    /// (needed by `(min-width: 768px)`), which together happen to spell
    /// `url(scheme:…)`; a real media query never contains a URL, so a `url(`
    /// substring is refused outright rather than relying on the charset to
    /// exclude it. Anything else outside the charset is rejected too, so no
    /// breakout / at-rule / tag can form.
    fn charset_ok(low: &str) -> bool {
        // Whitespace-stripped so `url ( …` cannot evade the `url(` check.
        let low_nows: String = low.chars().filter(|c| !c.is_whitespace()).collect();
        if low_nows.contains("url(") {
            return false;
        }
        low.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b' ' | b'_'
                        | b'-'
                        | b':'
                        | b'.'
                        | b'%'
                        | b'('
                        | b')'
                        | b','
                        | b'<'
                        | b'>'
                        | b'='
                )
        })
    }

    /// Parse and validate a CSS media-query condition string.
    ///
    /// Returns `None` (drop the media-query styling) when `q` is empty after
    /// trimming or contains any byte outside the media-query grammar, in either
    /// its raw or CSS-escape-decoded form.
    pub(crate) fn parse(q: &'a str) -> Option<Self> {
        let s = q.trim();
        if s.is_empty() {
            return None;
        }
        let low = s.to_ascii_lowercase();
        if !Self::charset_ok(&low) {
            return None;
        }
        // Defence-in-depth: decode CSS backslash escapes and re-check so a
        // hex-escaped byte (`\7b` → `{`, `\2f` → `/`) that decodes to an
        // out-of-grammar character is caught too. A lone `\` is itself outside
        // the grammar, so an escape sequence in the raw form is already
        // rejected above; the decoded pass closes the theoretical gap where the
        // decoder collapses an escape into an in-grammar-looking string.
        let decoded_low = css_unescape(&low);
        if !Self::charset_ok(&decoded_low) {
            return None;
        }
        Some(SafeCssMediaQuery(s))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0
    }
}

/// Strip every `</style` close-tag occurrence from a raw CSS body before it
/// becomes an `HRaw` `<style>` child (or is spliced into a `<style>` sink).
///
/// * tag-name matched ASCII-case-insensitively, so `</StYle` breaks out just as
///   `</style` does (a plain two-literal `replace` missed every mixed case);
/// * fixpoint-iterated — `str::replace` removes only non-overlapping matches in
///   ONE left-to-right pass and never re-scans the join seam, so a crafted
///   `</sty</stylele` reconstructs `</style` after a single pass.  Loop until a
///   pass removes nothing.
///
/// Total (never panics; the `</style` needle is ASCII so byte indices are valid
/// char boundaries in `out`).  Stricter on purpose: security outranks
/// byte-for-byte (documented divergence).
pub(crate) fn strip_style_close(s: &str) -> String {
    let mut out = s.to_string();
    loop {
        let lowered = out.to_ascii_lowercase();
        match lowered.find("</style") {
            None => return out,
            Some(idx) => {
                // `</style` is ASCII, so byte index `idx` and the 7-byte length
                // are valid char boundaries in `out` (same byte layout as the
                // lowercased copy).
                out.replace_range(idx..idx.saturating_add("</style".len()), "");
            }
        }
    }
}

/// Split any ASCII-case-insensitive `</script` breakout in a `<script>` body so
/// it cannot terminate the enclosing element early. The browser's HTML parser
/// ends a script element only at a literal `</script` byte run; inserting a `\`
/// after the `<` (`<\/script`) keeps the JavaScript semantically identical (a
/// redundant escape inside a string/regex, inert outside one) while removing the
/// exact byte run the parser scans for. Non-`</script` text is untouched, so
/// ordinary script bodies pass through unchanged.
///
/// Sibling of `strip_style_close`: both neutralise a raw-text element's own
/// close tag at the sink so no attacker-influenced body can break out. `<script>`
/// splits rather than strips because a script body is executable code the author
/// owns — dropping bytes could corrupt the program — whereas a `<style>` body is
/// declarative CSS where deletion is safe.
///
/// Total (never panics; only ASCII single-byte characters are ever compared or
/// emitted specially, and every multi-byte `char` is copied whole).
pub(crate) fn neutralise_script_close(body: &str) -> String {
    const NEEDLE: &[u8] = b"</script";
    let bytes = body.as_bytes();
    let mut out = String::with_capacity(body.len());
    let mut i = 0;
    while i < bytes.len() {
        let matches_here = bytes
            .get(i..i.saturating_add(NEEDLE.len()))
            .is_some_and(|w| w.eq_ignore_ascii_case(NEEDLE));
        if matches_here {
            out.push_str("<\\/script");
            i = i.saturating_add(NEEDLE.len());
        } else {
            // A multi-byte UTF-8 char never starts with `<`, so the needle branch
            // only fires on single-byte ASCII; here we copy the next whole char
            // (ASCII or multi-byte) and advance past it.
            match body.get(i..).and_then(|s| s.chars().next()) {
                Some(c) => {
                    out.push(c);
                    i = i.saturating_add(c.len_utf8());
                }
                None => break,
            }
        }
    }
    out
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn value_rejects_expression_and_scheme_sinks() {
        assert!(SafeCssValue::parse("expression(alert(1))").is_none());
        assert!(SafeCssValue::parse("0; background:url(javascript:alert(1))").is_none());
        assert!(SafeCssValue::parse("url( javascript:alert(1))").is_none()); // ws-stripped
        assert!(SafeCssValue::parse("#ff6600").is_some()); // benign passes
    }

    /// Bounded by construction (PRINCIPLES §3): an untrusted (Model-derived) CSS
    /// value whose nested-function depth exceeds [`MAX_VALUE_DEPTH`] is REFUSED
    /// rather than recursed into. Without the cap this deeply-nested
    /// `calc(calc(…))` would overflow the stack at render time — a soundness
    /// break and a remote-input exhaustion vector (PRINCIPLES §1). A
    /// legitimately shallow value still parses; the boundary is exact.
    #[test]
    fn value_rejects_pathologically_nested_value_fail_closed() {
        let deep = format!("{}1px{}", "calc(".repeat(5_000), ")".repeat(5_000));
        assert!(
            SafeCssValue::parse(&deep).is_none(),
            "a value nested past MAX_VALUE_DEPTH must be refused, not recursed into"
        );
        assert!(SafeCssValue::parse("calc(min(10px, max(2px, 4px)))").is_some());
        let ok = format!(
            "{}1px{}",
            "calc(".repeat(MAX_VALUE_DEPTH),
            ")".repeat(MAX_VALUE_DEPTH)
        );
        assert!(
            SafeCssValue::parse(&ok).is_some(),
            "depth == MAX_VALUE_DEPTH must parse"
        );
        let over = format!(
            "{}1px{}",
            "calc(".repeat(MAX_VALUE_DEPTH + 2),
            ")".repeat(MAX_VALUE_DEPTH + 2)
        );
        assert!(
            SafeCssValue::parse(&over).is_none(),
            "depth past MAX_VALUE_DEPTH must be refused"
        );
    }

    // ── A9: loud-strip diagnostic ────────────────────────────────────────────

    /// The security OUTCOME of `parse_reporting` is identical to `parse` for
    /// every value and both origins — a diagnostic never changes what is
    /// emitted, only whether stderr is written.
    #[test]
    fn parse_reporting_never_changes_the_security_outcome() {
        for v in [
            "expression(alert(1))",
            "0; background:url(javascript:alert(1))",
            "\\65 xpression(alert(1))",
            "#ff6600",
            "linear-gradient(90deg, red 0%, blue 100%)",
        ] {
            let baseline = SafeCssValue::parse(v).is_some();
            for origin in [CssValueOrigin::DeveloperLiteral, CssValueOrigin::Untrusted] {
                assert_eq!(
                    SafeCssValue::parse_reporting(v, origin).is_some(),
                    baseline,
                    "parse_reporting must match parse for {v:?} / {origin:?}"
                );
            }
        }
    }

    /// A stripped DEVELOPER literal warrants a diagnostic; a stripped UNTRUSTED
    /// (Model-derived) value never does — the exact A9 split.
    #[test]
    fn only_developer_literals_are_reported_on_strip() {
        assert!(
            should_report_stripped(CssValueOrigin::DeveloperLiteral),
            "a stripped developer literal must be surfaced"
        );
        assert!(
            !should_report_stripped(CssValueOrigin::Untrusted),
            "a stripped untrusted / Model-derived value must stay silent"
        );
    }

    /// The scan reason distinguishes a raw breakout from an escape-hidden one,
    /// so the diagnostic can name WHY — and a safe value scans clean. Under the
    /// allowlist grammar a bare backslash is itself unrecognized structure, so
    /// an escaped payload whose backslash sits at top level fails the RAW parse
    /// (`RawBreakout`); `EscapedBreakout` is reached only when the raw form
    /// parses cleanly and the CSS-escape decode reveals the reject — e.g. a
    /// `var(...)` custom-property name that decodes to a breakout character.
    #[test]
    fn scan_reason_names_raw_vs_escaped_breakout() {
        assert_eq!(
            scan_css_value("red; color:blue"),
            Err(CssStripReason::RawBreakout)
        );
        // `\3a` decodes to `:` inside a `var()` name — the raw `var(--x\3a)`
        // parses (backslash never reaches top level; it is inside the nested
        // value that recurses), but the decoded `var(--x:)` fails the grammar.
        assert_eq!(
            scan_css_value("var(--x\\3a y)"),
            Err(CssStripReason::EscapedBreakout)
        );
        assert_eq!(scan_css_value("#ff6600"), Ok(()));
        // Every reason has a non-empty human description for the diagnostic.
        assert!(!CssStripReason::RawBreakout.describe().is_empty());
        assert!(!CssStripReason::EscapedBreakout.describe().is_empty());
    }

    #[test]
    fn value_rejects_hex_escaped_expression_and_scheme_sinks() {
        // CSS backslash-hex escapes (CSS Syntax L3 §4.3.7)
        // decode to a blocked keyword / breakout char ANYWHERE a token is
        // lexed. The raw substring scan misses these; the decode-then-rescan
        // pass catches them.
        // `\65 `='e' (space delimiter consumed) → "expression(alert(1))".
        assert!(SafeCssValue::parse("\\65 xpression(alert(1))").is_none());
        // `\75`='u', `\6a`='j' → "url(javascript:alert(1))".
        assert!(SafeCssValue::parse("\\75 rl(\\6a avascript:alert(1))").is_none());
        // `\3b`=';' (hex-escaped BREAKOUT char, not just a script-sink kw).
        assert!(SafeCssValue::parse("red\\3b  malicious").is_none());
        // benign values with no escapes still pass unchanged.
        assert_eq!(
            SafeCssValue::parse("#ff6600").map(|v| v.as_str().to_owned()),
            Some("#ff6600".to_owned())
        );
        assert_eq!(
            SafeCssValue::parse("rgba(0,0,0,0.2)").map(|v| v.as_str().to_owned()),
            Some("rgba(0,0,0,0.2)".to_owned())
        );
    }

    #[test]
    fn propname_rejects_key_smuggle() {
        assert!(SafeCssPropertyName::parse("background:url(x);x").is_none());
        assert!(SafeCssPropertyName::parse("--brand").is_some());
        assert!(SafeCssPropertyName::parse("-webkit-box-shadow").is_some());
    }

    #[test]
    fn selector_strict_drops_breakout() {
        assert!(SafeCssSelector::parse("body{}</style><script>").is_none());
        assert!(SafeCssSelector::parse("@import url(x)").is_none());
        assert!(SafeCssSelector::parse("a/*{}*/b").is_none()); // comment digraph
        assert!(SafeCssSelector::parse(".card:hover > a[href^=\"/\"]").is_some());
    }

    #[test]
    fn media_query_accepts_real_queries_including_level4_ranges() {
        for q in [
            "(min-width: 768px)",
            "(max-width: 600px)",
            "(min-width: 768px) and (max-width: 1023px)",
            "(prefers-color-scheme: dark)",
            "(prefers-reduced-motion: reduce)",
            "(hover: hover) and (pointer: fine)",
            "only screen and (min-resolution: 2dppx)",
            "not all and (monochrome)",
            // Media Queries Level 4 range syntax — `<`/`<=` are legitimate
            // here (this is exactly why SafeCssSelector is NOT reused).
            "(400px <= width <= 700px)",
            "(width < 600px)",
        ] {
            assert!(
                SafeCssMediaQuery::parse(q).is_some(),
                "valid media query must pass: {q}"
            );
            assert_eq!(
                SafeCssMediaQuery::parse(q).map(|v| v.as_str().to_owned()),
                Some(q.to_owned())
            );
        }
    }

    #[test]
    fn media_query_rejects_breakout_and_escaped_breakout() {
        for q in [
            "",
            "   ",
            // ruleset / declaration breakout
            "(min-width: 1px) { } body { display:none }",
            "screen) { } @media (",
            "(min-width: 1px); color:red",
            // style-tag breakout + comment obfuscation
            "(min-width: 1px) </style><script>alert(1)</script>",
            "(min-width: 1px) /* */",
            // at-rule smuggling
            "(min-width: 1px) @import url(evil)",
            // CSS-hex-escaped `{` (`\7b`) — caught by the decode-then-rescan.
            "(min-width: 1px) \\7b  color:red",
            // script sink
            "url(javascript:alert(1))",
            // Exfil / remote-fetch vectors a media query never legitimately
            // contains — the positive grammar rejects every `url(…)` outright,
            // so these fail closed without any per-scheme denylist entry.
            "(min-width: 1px) and url(http://evil.example/x)",
            "screen url(//evil.example/x)",
            "(min-width: 1px) url(data:image/svg+xml,<svg onload=alert(1)>)",
            // A bare `/` or `\` (comment / escape byte) is outside the grammar.
            "(min-width: 1px) /x",
            "(min-width: 1px) \\x",
        ] {
            assert!(
                SafeCssMediaQuery::parse(q).is_none(),
                "breakout media query must be dropped: {q:?}"
            );
        }
    }

    #[cfg(feature = "web")]
    #[test]
    fn keyframes_body_accepts_legit_bodies_byte_identical() {
        for b in [
            "0% { opacity: 0 } 100% { opacity: 1 }",
            "0% { opacity: 0; transform: translateY(10px) } 100% { opacity: 1; transform: translateY(0px) }",
            "from { opacity: 0 } to { opacity: 1 }",
            "FROM { opacity: 0 } TO { opacity: 1 }",
            "0%, 50% { opacity: 0 } 100% { opacity: 1 }",
            "12.5% { transform: scale(1.5) rotate(45deg) }",
            "0% {  }", // empty block is legal CSS
        ] {
            assert_eq!(
                sink_safe_keyframes_body(b),
                Some(b),
                "legit keyframes body must pass byte-identical: {b}"
            );
        }
    }

    #[cfg(feature = "web")]
    #[test]
    fn keyframes_body_rejects_breakout() {
        for b in [
            "",
            "   ",
            // trailing content after the last block — the classic close-then-
            // inject shape (`</style>`, page-wide rule, at-rule…).
            "0% { opacity: 0 } </style><script>alert(1)</script>",
            "0% { opacity: 0 } } body { display:none }",
            "0% { opacity: 0 } @import url(//evil/x.css) ;",
            // non-keyframe selector text (rule injection in the selector slot)
            "body { display:none }",
            "0% </style> { opacity: 0 }",
            "0%; { opacity: 0 }",
            // nested `{` inside a block (lands in a declaration → rejected)
            "0% { a: b { } }",
            // script sinks / comment obfuscation inside a declaration
            "0% { background: url(javascript:alert(1)) }",
            "0% { opacity: 0 /* } body { */ }",
            // hex-escaped breakout inside a declaration (`\7d` = `}`)
            "0% { opacity: 0\\7d  }",
            // unbalanced blocks
            "0% { opacity: 0",
            "0% opacity: 0 }",
        ] {
            assert_eq!(
                sink_safe_keyframes_body(b),
                None,
                "breakout keyframes body must be dropped: {b:?}"
            );
        }
    }

    #[test]
    fn strip_style_close_is_fixpoint_and_case_insensitive() {
        assert!(
            !strip_style_close("a{}</StYlE ><script>")
                .to_ascii_lowercase()
                .contains("</style")
        );
        assert!(
            !strip_style_close("</sty</stylele")
                .to_ascii_lowercase()
                .contains("</style")
        );
    }

    #[test]
    fn neutralise_script_close_splits_breakout_case_insensitively() {
        // The exact XSS payload from the safe-surface `<script>` sink must not
        // survive as a live `</script` byte run.
        assert_eq!(
            neutralise_script_close("a</script><img src=x onerror=alert(1)>"),
            "a<\\/script><img src=x onerror=alert(1)>"
        );
        assert_eq!(neutralise_script_close("b</SCRIPT >"), "b<\\/script >");
        let out = neutralise_script_close("x</script>y</ScRiPt>z");
        assert!(!out.to_ascii_lowercase().contains("</script"));
        // Non-breakout text (incl. multibyte UTF-8) is untouched.
        assert_eq!(neutralise_script_close("λ = 1; // ok"), "λ = 1; // ok");
    }

    #[test]
    fn neutralise_script_close_is_a_fixpoint() {
        // Already-neutralised output (e.g. from `unsafeScript` at construction)
        // passes through unchanged, so routing it through the sink again is a
        // no-op — the capability-gated path keeps its exact bytes.
        let once = neutralise_script_close("x</script>y");
        assert_eq!(neutralise_script_close(&once), once);
    }

    /// Legacy script-execution CSS properties are blocked in both the value
    /// and raw-body scanners. These properties (`-moz-binding:` / Firefox XBL;
    /// `behavior:` / IE HTC) never appear in valid modern CSS, so blocking them
    /// is zero-false-positive defence-in-depth.
    #[test]
    fn legacy_script_execution_properties_are_rejected() {
        // Declaration-value gate rejects both plain and url-wrapped forms.
        assert!(SafeCssValue::parse("-moz-binding: url(x.xml)").is_none());
        assert!(SafeCssValue::parse("behavior: url(x.htc)").is_none());
        assert!(SafeCssValue::parse("url(-moz-binding: url(x))").is_none());
        // Benign values still pass.
        assert!(SafeCssValue::parse("red").is_some());
        assert!(SafeCssValue::parse("1px solid blue").is_some());

        // Raw-body gate rejects a stylesheet fragment that carries either property.
        assert!(!sink_safe_raw_body("a { -moz-binding: url(x.xml#foo) }"));
        assert!(!sink_safe_raw_body("a { behavior: url(x.htc) }"));
        // Whitespace-obfuscated form (whitespace stripped before scan).
        assert!(!sink_safe_raw_body("a { -moz-binding : url(x.xml) }"));
        assert!(!sink_safe_raw_body("a { behavior : url(x.htc) }"));
        // Benign block-structured body still passes.
        assert!(sink_safe_raw_body(".card { color: red; padding: 8px }"));
    }

    /// `sink_safe_raw_body` — the authoritative raw/keyframes-body gate — drops
    /// every at-rule / breakout / script-sink construct, INCLUDING the
    /// CSS-escape-decoded and whitespace-obfuscated forms a raw substring check
    /// misses, while keeping a benign block-structured body (`{` `}` `;` are
    /// legal in a stylesheet fragment).
    #[test]
    fn raw_body_gate_drops_dangerous_keeps_benign() {
        let must_reject = [
            // At-rule injection (`@import` = CSS-level SSRF), plain form.
            "@import url(//evil/x.css)",
            "0% { transform: rotate(0deg) } @import url(x)",
            "@charset \"utf-8\"; body { display:none }",
            // Style-tag / comment breakout.
            "a { color: red } </style><script>alert(1)</script>",
            "/* comment */ body { display:none }",
            // Script-sink URL schemes.
            "a { x: expression(alert(1)) }",
            "a { background: url(javascript:alert(1)) }",
            "a { background: url(vbscript:alert(1)) }",
            "a { background: url(data:text/html;base64,abc) }",
            "a { background: url(data:application/x-www-form-urlencoded,abc) }",
            // Whitespace-obfuscated (whitespace stripped before the scan).
            "a { background: url( javascript:alert(1)) }",
            "a { x: expression (alert(1)) }",
            // CSS-hex-escaped payloads a raw substring scan MISSES — caught by
            // the css_unescape re-scan. `\40 `='@', `\78 `='x', `\69 `='i'.
            "\\40 import url(//evil/x.css)",
            "x:e\\78 pression(alert(1))",
            "@\\69 mport url(x)",
        ];
        for body in &must_reject {
            assert!(
                !sink_safe_raw_body(body),
                "raw body gate must drop: {body:?}"
            );
        }

        // Benign block-structured bodies pass — block chars `{` `}` `;` are legal
        // in a raw stylesheet / keyframes fragment.
        let must_pass = [
            "0% { opacity: 0 } 100% { opacity: 1 }",
            ".card { color: red; padding: 8px }",
            "from { transform: translateX(0) } to { transform: translateX(100px) }",
            // A scheme-free same-origin asset reference passes the url() gate.
            ".hero { background: url(/assets/hero.png) }",
            ".icon { background: url('../img/sprite.svg') }",
            ".mask { mask: url(#clip) }",
            ".bg { background: url(img/bg.webp?v=2) }",
        ];
        for body in &must_pass {
            assert!(
                sink_safe_raw_body(body),
                "benign raw body must pass: {body:?}"
            );
        }
    }

    /// Exfil / remote-fetch vectors the OLD denylist let through because it
    /// enumerated only the schemes it feared. The scheme-free `url(…)` allowlist
    /// (`raw_body_url_args_all_safe` → `url_arg_is_safe`) rejects every `url(…)`
    /// that is not a same-origin, scheme-free reference — so these fail closed in
    /// the raw-body path (a `data:` image is refused too: it carries a `:`).
    #[test]
    fn raw_body_gate_rejects_unenumerated_url_exfil_vectors() {
        let must_reject = [
            // Remote fetch (SSRF / exfil) — never on any denylist.
            "a { background: url(http://evil.example/x.png) }",
            "a { background: url(https://evil.example/track.gif) }",
            "a { background: url(ftp://evil.example/x) }",
            // Protocol-relative fetch resolves to a foreign host.
            "a { background: url(//evil.example/x.png) }",
            // Any data: URL is refused (it bears a `:`); a scriptable SVG data
            // image (which can carry <script>) is the reason to never special-case it.
            "a { background: url(data:image/svg+xml,<svg onload=alert(1)>) }",
            "a { background: url(data:image/svg+xml;base64,PHN2Zz4=) }",
            // Quoted forms must not evade the scheme check.
            "a { background: url('https://evil.example/x') }",
            "a { background: url(\"//evil.example/x\") }",
            // Whitespace-obfuscated remote fetch (whitespace stripped first).
            "a { background: url( https://evil.example/x ) }",
            // CSS-hex-escaped remote scheme (`\68`='h') — caught by the
            // decode-then-rescan. `\68 ttps:` → `https:`.
            "a { background: url(\\68 ttps://evil.example/x) }",
            // A `url(` with no closing paren is a malformed token — fail closed.
            "a { background: url(https://evil.example/x }",
        ];
        for body in &must_reject {
            assert!(
                !sink_safe_raw_body(body),
                "url exfil vector must be dropped: {body:?}"
            );
        }
    }

    /// SSOT anti-drift: the backend hoists a direct `CssSafety.safeValue` literal
    /// for dev appearance hot-swap iff `ipe_kernels::css_value_is_safe` accepts
    /// it, and this runtime sanitizer is the authoritative gate the hoisted slot
    /// is re-run through. Both MUST agree on every value, or a hoisted value could
    /// be less-gated than a compiled one. This test pins that equivalence across
    /// the benign + adversarial vectors the value gate is tested on.
    #[test]
    fn value_policy_agrees_with_shared_kernel_policy() {
        for v in [
            // benign — accepted by both
            "#ff6600",
            "8px",
            "rgba(0,0,0,0.2)",
            "1px solid #ccc",
            "translateX(100px)",
            "red !important",
            "red !important ",
            // adversarial — rejected by both
            "expression(alert(1))",
            "0; background:url(javascript:alert(1))",
            "red</style><script>alert(1)</script>",
            "url( javascript:alert(1))",
            "\\65 xpression(alert(1))",
            "behavior:url(x.htc)",
            "-moz-binding:url(x)",
            "a { color: red }",
            "@import url(x)",
        ]
        .into_iter()
        .map(String::from)
        // Depth-bound agreement: both mirrors share MAX_VALUE_DEPTH, so a value
        // at the ceiling is accepted by both and one past it rejected by both.
        .chain([
            format!(
                "{}1px{}",
                "calc(".repeat(MAX_VALUE_DEPTH),
                ")".repeat(MAX_VALUE_DEPTH)
            ),
            format!(
                "{}1px{}",
                "calc(".repeat(MAX_VALUE_DEPTH + 2),
                ")".repeat(MAX_VALUE_DEPTH + 2)
            ),
        ]) {
            let v = v.as_str();
            assert_eq!(
                SafeCssValue::parse(v).is_some(),
                ipe_kernels::css_value_is_safe(v),
                "runtime SafeCssValue and shared css_value_is_safe disagree on {v:?} \
                 — the hoist gate and the render gate must be one policy"
            );
        }
    }

    use proptest::prelude::*;
    use proptest::test_runner::FileFailurePersistence;

    // Names the two mirrors must agree on function-wise: the kernel allowlist
    // (`ipe_kernels`) plus a few off-list names, so an `ALLOWED_FUNCTIONS` vs
    // `ALLOWED_VALUE_FUNCTIONS` drift is a generated (not merely sampled)
    // divergence. Off-list names (`expression`, `image-set`, `-moz-binding`)
    // probe the reject side.
    fn css_function_name() -> impl Strategy<Value = String> {
        prop_oneof![
            // On-list: drawn from the kernel's own allowlist so a runtime-mirror
            // allowlist drift is caught.
            prop::sample::select(
                &[
                    "attr",
                    "blur",
                    "calc",
                    "clamp",
                    "color-mix",
                    "conic-gradient",
                    "counter",
                    "cubic-bezier",
                    "drop-shadow",
                    "env",
                    "format",
                    "hsl",
                    "hsla",
                    "linear-gradient",
                    "local",
                    "matrix",
                    "max",
                    "min",
                    "minmax",
                    "radial-gradient",
                    "repeat",
                    "repeating-linear-gradient",
                    "rgb",
                    "rgba",
                    "rotate",
                    "scale",
                    "steps",
                    "translate",
                    "translatex",
                    "url",
                    "var",
                ][..]
            )
            .prop_map(str::to_owned),
            // Off-list: must be rejected by both mirrors.
            prop::sample::select(
                &["expression", "image-set", "-moz-binding", "behavior", "foo"][..]
            )
            .prop_map(str::to_owned),
            // Arbitrary idents, to probe the allowlist edge with unlisted names.
            "[a-z][a-z0-9-]{0,10}",
        ]
    }

    // A leaf CSS token: ident, number+unit, hex colour, quoted string with
    // occasional embedded metacharacters, the `!important` flag, or a `url(...)`
    // whose arg spans `is_url_path_byte` members AND excluded bytes (`:`, `//`,
    // quote, ws) to probe the scheme gate. Hex-escapes (`\65 `, `\3a`) exercise
    // the raw-vs-`css_unescape` double-parse divergence.
    fn css_leaf() -> impl Strategy<Value = String> {
        prop_oneof![
            "[a-z][a-z0-9-]{0,12}",
            r"[-+]?[0-9]{1,4}(\.[0-9]{1,3})?(px|%|deg|rem|fr|vw|em)?",
            "#[0-9a-fA-F]{3}",
            "#[0-9a-fA-F]{6}",
            "#[0-9a-fA-F]{8}",
            r#""[a-z0-9 \\"()<>;]{0,10}""#,
            Just("!important".to_owned()),
            r"\\(65|75|3a|3A) ?[a-z]{0,6}",
            // url(...) arg pool: path bytes + scheme-gate probes.
            prop::sample::select(
                &[
                    "url(x.png)",
                    "url(/a/b.woff2)",
                    "url(javascript:alert(1))",
                    "url(data:text/html,x)",
                    "url(//evil.example/x)",
                    "url( x.png)",
                    "url(\"x.png\")",
                    "url(a:b)",
                ][..]
            )
            .prop_map(str::to_owned),
        ]
    }

    // Recursive CSS value straddling `MAX_VALUE_DEPTH` (nesting 0..35) with the
    // grammar's separators, so the two mirrors are compared on and just past the
    // depth ceiling and the allowlist boundary — where hand-synced parsers drift.
    fn css_value_structured() -> impl Strategy<Value = String> {
        css_leaf().prop_recursive(35, 256, 4, |inner| {
            prop_oneof![
                // function wrapping an inner value
                (css_function_name(), inner.clone()).prop_map(|(f, arg)| format!("{f}({arg})")),
                // token sequence with a grammar separator
                (
                    inner.clone(),
                    prop::sample::select(&[" ", ",", "/", "%"][..]),
                    inner
                )
                    .prop_map(|(a, sep, b)| format!("{a}{sep}{b}")),
            ]
        })
    }

    // Adversarial byte / injection-string strategy: reaches surfaces the
    // structured grammar never lands on — control bytes, unbalanced parens,
    // empty/whitespace, non-ASCII past `0x80`, and the injection sink substrings.
    fn css_value_adversarial() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::collection::vec(any::<u8>(), 0..64)
                .prop_filter_map("valid utf8", |b| String::from_utf8(b).ok()),
            prop::collection::vec(
                prop::sample::select(
                    &[
                        "<",
                        ">",
                        "{",
                        "}",
                        ";",
                        ":",
                        "(",
                        ")",
                        "\"",
                        "'",
                        "/",
                        "%",
                        "!",
                        "\\",
                        "@",
                        "#",
                        " ",
                        "javascript:",
                        "data:",
                        "expression",
                        "//",
                        "</style>",
                        "@import",
                        "url(",
                        "attr(",
                        "\\65 ",
                    ][..]
                ),
                0..12
            )
            .prop_map(|parts| parts.concat()),
        ]
    }

    proptest! {
        // Pins the SSOT equality the two hand-maintained CSS-value parsers promise:
        // the render-time `SafeCssValue::parse` accepts a value IFF the compile-time
        // `ipe_kernels::css_value_is_safe` does — over the whole grammar plus an
        // adversarial byte surface, not the 20 fixed corpus points. Any drift in
        // either allowlist, either `MAX_VALUE_DEPTH`, `css_unescape`, an `is_*_byte`
        // set, or a control-flow edge surfaces as a minimal shrunk counterexample.
        // A false-accept in the runtime mirror is a live XSS/exfiltration hole.
        #![proptest_config(ProptestConfig {
            cases: 512,
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            ..ProptestConfig::default()
        })]

        #[test]
        fn value_gate_mirrors_agree_over_generated_surface(
            v in prop_oneof![
                3 => css_value_structured(),
                1 => css_value_adversarial(),
            ],
        ) {
            prop_assert_eq!(
                SafeCssValue::parse(&v).is_some(),
                ipe_kernels::css_value_is_safe(&v),
                "runtime SafeCssValue and shared css_value_is_safe drift on {:?} \
                 — the hoist gate and the render gate must be one policy",
                v
            );
        }
    }
}
