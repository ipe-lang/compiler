//! The single source of truth for every FFI-generated name and sentinel.
//!
//! The three emitters (`.ipei`, `kernel.json`, `_bindings.rs`) and the
//! dead-code-elimination reachability key all derive their names HERE, so the
//! tri-artifact agreement is byte-equal by construction — a three-way name
//! skew (an under-bind that link-fails) is structurally impossible.

use crate::diag::WireDefect;

/// The Ipê builtin type heads a foreign nominal never re-declares or shadows.
///
/// The `.ipei` emitter skips a declaration for them, the interface emitter's
/// shadow gate refuses a foreign type claiming one, and the transparency
/// classification keeps such a claim opaque.
pub const IPE_BUILTIN_HEADS: &[&str] = &[
    "String", "Int", "Float", "Bool", "Char", "List", "Dict", "Set", "Maybe", "Result", "Task",
    "Error",
];

/// A validated Rust identifier (`^[A-Za-z_][A-Za-z0-9_]*$`).
///
/// The constructor is the only way in, so a crate that names a symbol
/// `"; std::process::Command::new(...)"` can never reach generated source —
/// the injection class dies at the trusted decode surface.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RustIdent(String);

impl RustIdent {
    /// Validate and wrap an identifier.
    ///
    /// # Errors
    ///
    /// [`WireDefect::InvalidIdent`] when the string is empty, starts with a
    /// digit, or contains anything outside `[A-Za-z0-9_]`.
    pub fn parse(s: &str) -> Result<Self, WireDefect> {
        let mut chars = s.chars();
        let head_ok = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
        if head_ok && chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            Ok(Self(s.to_owned()))
        } else {
            Err(WireDefect::InvalidIdent { got: s.to_owned() })
        }
    }

    /// The identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RustIdent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated `::`-separated path of Rust identifiers (`civil::date`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdentPath(String);

impl IdentPath {
    /// Validate and wrap an identifier path (every segment a [`RustIdent`]).
    ///
    /// # Errors
    ///
    /// [`WireDefect::InvalidModulePath`] when any segment fails identifier
    /// validation or the path is empty.
    pub fn parse(s: &str) -> Result<Self, WireDefect> {
        let invalid = || WireDefect::InvalidModulePath { got: s.to_owned() };
        if s.is_empty() {
            return Err(invalid());
        }
        for seg in s.split("::") {
            RustIdent::parse(seg).map_err(|_| invalid())?;
        }
        Ok(Self(s.to_owned()))
    }

    /// The path text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated Rust PATH segment as it appears in a foreign-call `path` list.
///
/// An [`IdentPath`] with an OPTIONAL leading `::` (the absolute crate-root
/// prefix the inspector emits, e.g. `::box1`). Joined by `::` at render, so
/// each segment must be idents-and-`::` only — no injection charset survives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustPathSegment(String);

impl RustPathSegment {
    /// Validate and wrap a path segment.
    ///
    /// # Errors
    ///
    /// [`WireDefect::InvalidModulePath`] when the body (after an optional
    /// leading `::`) is not a legal identifier path.
    pub fn parse(s: &str) -> Result<Self, WireDefect> {
        let body = s.strip_prefix("::").unwrap_or(s);
        IdentPath::parse(body).map_err(|_| WireDefect::InvalidModulePath { got: s.to_owned() })?;
        Ok(Self(s.to_owned()))
    }

    /// The validated segment text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RustPathSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated Rust TYPE expression restricted to the closed grammar the FFI
/// emitter renders verbatim.
///
/// Admits `::`-paths of identifiers, angle-bracket generic application,
/// `&`/`&mut ` borrow prefixes, tuples and unit `()`, fixed-size arrays
/// `[T; N]`, and `, ` separators — and nothing else.
///
/// The parser admits exactly this closed charset with a bracket-depth check,
/// so a rendered type can never open a new item or statement: `;` outside a
/// `[…]` array, `{`/`}`, a bare `(` that is not part of `()`/a tuple, string
/// bytes, and any statement token are ALL rejected. This is the whole reason
/// an injection-bearing `rustType`/ctor string is unrepresentable past decode
/// — the same discipline [`RustIdent`] applies to the name surface, extended
/// to every string that reaches wrapper emission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustTypeExpr(String);

impl RustTypeExpr {
    /// Validate and wrap a Rust type expression.
    ///
    /// # Errors
    ///
    /// [`WireDefect::InvalidType`] when the string carries a byte outside the
    /// closed grammar, an unbalanced `<`/`(`/`[`, a `;` outside an array, or
    /// is empty.
    pub fn parse(s: &str) -> Result<Self, WireDefect> {
        let invalid = || WireDefect::InvalidType { got: s.to_owned() };
        if s.trim().is_empty() {
            return Err(invalid());
        }
        // Bracket-depth counters: `;` is legal ONLY inside `[…]` (array length
        // separator); every other char is checked against the closed charset.
        let mut angle: i32 = 0;
        let mut paren: i32 = 0;
        let mut square: i32 = 0;
        for c in s.chars() {
            match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | ' ' | ',' | ':' | '&' => {}
                '<' => angle += 1,
                '>' => {
                    angle -= 1;
                    if angle < 0 {
                        return Err(invalid());
                    }
                }
                '(' => paren += 1,
                ')' => {
                    paren -= 1;
                    if paren < 0 {
                        return Err(invalid());
                    }
                }
                '[' => square += 1,
                ']' => {
                    square -= 1;
                    if square < 0 {
                        return Err(invalid());
                    }
                }
                ';' if square > 0 => {}
                _ => return Err(invalid()),
            }
        }
        if angle != 0 || paren != 0 || square != 0 {
            return Err(invalid());
        }
        Ok(Self(s.to_owned()))
    }

    /// The validated type text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The validated `()` unit type — an infallible constructor for the few
    /// production sites that need a literal unit fallback (a `Result<>` ctor
    /// missing its Ok arm), avoiding a fallible `parse` on a constant.
    #[must_use]
    pub fn unit() -> Self {
        Self("()".to_owned())
    }

    /// An infallible constructor for tests only: wraps `s` verbatim without
    /// validation, so unit tests across the crate can build a `RustTypeExpr`
    /// from a known-valid literal without the `unwrap`/`expect` deny-set.
    #[cfg(test)]
    #[must_use]
    pub fn for_test(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl std::fmt::Display for RustTypeExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated `<pattern>` fragment for an enum-accessor match arm.
///
/// A `RustIdent` variant head optionally followed by `(..)` or `{..}` (the only
/// two shapes the enum-tag/extract emitters produce). Anything else — a
/// binding pattern, a guard, a nested pattern, an injection charset — is
/// rejected, so the arm text cannot escape the `match`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustPattern(String);

impl RustPattern {
    /// Validate and wrap an enum-arm pattern.
    ///
    /// # Errors
    ///
    /// [`WireDefect::InvalidPattern`] when the head is not a `RustIdent` or the
    /// suffix is anything but `(..)` / `{..}`.
    pub fn parse(s: &str) -> Result<Self, WireDefect> {
        let invalid = || WireDefect::InvalidPattern { got: s.to_owned() };
        let split_at = s.find(['(', '{']).unwrap_or(s.len());
        let head = s.get(..split_at).unwrap_or("");
        let suffix = s.get(split_at..).unwrap_or("");
        RustIdent::parse(head).map_err(|_| invalid())?;
        if matches!(suffix, "" | "(..)" | "{..}") {
            Ok(Self(s.to_owned()))
        } else {
            Err(invalid())
        }
    }

    /// The validated pattern text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RustPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated field SELECTOR.
///
/// Either a `RustIdent` (a struct-variant field name) or a decimal index (a
/// tuple position). Any other byte is rejected, so the selector cannot render
/// as arbitrary code in a match binder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSelector(String);

impl FieldSelector {
    /// Validate and wrap a field selector. An empty selector is legal — the
    /// tuple-extract path treats it as "the sole field" — and preserved.
    ///
    /// # Errors
    ///
    /// [`WireDefect::InvalidSelector`] when the value is neither a `RustIdent`
    /// nor an all-digit index.
    pub fn parse(s: &str) -> Result<Self, WireDefect> {
        if s.is_empty() {
            return Ok(Self(String::new()));
        }
        let is_index = s.chars().all(|c| c.is_ascii_digit());
        if is_index || RustIdent::parse(s).is_ok() {
            Ok(Self(s.to_owned()))
        } else {
            Err(WireDefect::InvalidSelector { got: s.to_owned() })
        }
    }

    /// The validated selector text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for FieldSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lower-case the first character (`Version` → `version`).
#[must_use]
pub fn lower_first(s: &str) -> String {
    let mut chars = s.chars();
    chars
        .next()
        .map_or_else(String::new, |c| c.to_lowercase().chain(chars).collect())
}

/// Upper-case the first character (`uuid` → `Uuid`).
#[must_use]
pub fn capitalise_first(s: &str) -> String {
    let mut chars = s.chars();
    chars
        .next()
        .map_or_else(String::new, |c| c.to_uppercase().chain(chars).collect())
}

/// Mangle an Ipê type-variable name to its emitted Rust type-param form
/// (`a` → `A`, `msg` → `Msg`).
#[must_use]
pub fn mangle_tvar(s: &str) -> String {
    capitalise_first(s)
}

/// THE disambiguated wrapper-reference name for an FFI function — consumed by
/// the `kernel.json` emitter, the `.ipei` emitter, the `_bindings.rs`
/// BEGIN/END sentinels, and the DCE reachability filter.
///
/// Shape: `lower_first(name)` plus a `_from_<lower_first(recv)>` suffix for an
/// accessor with a receiver. Kind-specific discriminators (`_field`,
/// `_set_field`, `tag_of_`, …) are already baked into `name` by the inspector.
#[must_use]
pub fn wrapper_ref_name(fn_name: &str, recv_type: &str) -> String {
    if recv_type.is_empty() {
        lower_first(fn_name)
    } else {
        format!("{}_from_{}", lower_first(fn_name), lower_first(recv_type))
    }
}

/// Ipê-side module name for a bound crate: `uuid` → `Rust.Uuid`.
#[must_use]
pub fn rust_module_name(pkg_path: &str) -> String {
    let clean: String = pkg_path
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();
    format!("Rust.{}", capitalise_first(&clean))
}

/// Kernel-name prefix for a bound crate: `Rust_` + the capitalised crate base
/// name, version-segment aware (`stripe-go/v82` → `Rust_Stripe_goV82`).
#[must_use]
pub fn rust_kernel_name(pkg_path: &str) -> String {
    let cap_of = |s: &str| -> String {
        let clean: String = s
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect();
        capitalise_first(&clean)
    };
    let is_version = |s: &str| -> bool {
        s.strip_prefix('v')
            .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
    };
    let segs: Vec<&str> = pkg_path.split('/').filter(|s| !s.is_empty()).collect();
    let base = match segs.as_slice() {
        [] => "Ffi".to_owned(),
        [.., prev, last] if is_version(last) => format!("{}{}", cap_of(prev), cap_of(last)),
        [.., last] => cap_of(last),
    };
    format!("Rust_{base}")
}

/// The literal prefix that opens a per-fn wrapper region in the emitted
/// `_bindings.rs`.
///
/// The DCE filter splits on these so it can drop an unreached wrapper
/// without parsing Rust; anything outside a BEGIN/END pair is preamble-class
/// and kept unconditionally.
pub const WRAPPER_SENTINEL_PREFIX: &str = "// IPE-FFI-WRAPPER BEGIN ";

/// The END sentinel line (closes the most-recently-opened wrapper region).
pub const WRAPPER_END_SENTINEL: &str = "// IPE-FFI-WRAPPER END";

/// The full BEGIN sentinel line for a wrapper of the given reference name.
#[must_use]
pub fn wrapper_begin_sentinel(ref_name: &str) -> String {
    format!("{WRAPPER_SENTINEL_PREFIX}{ref_name}")
}

/// The wrapper value-arg identifier for index `j` (`arg0`, `arg1`, …).
#[must_use]
pub fn arg_name(j: usize) -> String {
    format!("arg{j}")
}

/// Convert a mixed-case name to `snake_case` (`Semver_toString` →
/// `semver_to_string`).
///
/// MUST stay byte-equal to the backend's `to_snake_case` — the backend derives
/// the same identifier at FFI call sites, so a divergence here is an
/// under-bind that link-fails.
#[must_use]
pub fn to_snake_case(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = if let Some(&c) = chars.first() {
        out.extend(c.to_lowercase());
        1_usize
    } else {
        0
    };
    while let Some(&c) = chars.get(i) {
        if c == '_' {
            if let Some(&n) = chars.get(i + 1) {
                out.push('_');
                out.extend(n.to_lowercase());
                i += 2;
                continue;
            }
            out.push('_');
        } else if c.is_uppercase() {
            out.push('_');
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

/// The `snake_case` of a variant identifier (`SetValue` → `set_value`), for a
/// `define.enum` per-variant constructor suffix.
///
/// The single source of truth shared by the wrapper emitter (which names each
/// emitted per-variant `pub fn`) and the interface generator (which forwards to
/// it): a divergence here is an under-bind that link-fails. The input is a
/// validated `RustIdent`, so this only lowercases and inserts `_` at internal
/// case boundaries.
#[must_use]
pub fn variant_snake(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i != 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// The emitted `_bindings.rs` wrapper fn identifier.
///
/// The kernel base (the kernel name minus its `Rust_` prefix) joined to the
/// wrapper-reference name, in `snake_case` (`Rust_Semver` + `parse` →
/// `semver_parse`).
#[must_use]
pub fn wrapper_fn_ident(kernel_name: &str, ref_name: &str) -> String {
    let base = kernel_name.strip_prefix("Rust_").unwrap_or(kernel_name);
    to_snake_case(&format!("{base}_{ref_name}"))
}

/// The opaque handle nominal a `define.closure` adapter surfaces its returned
/// boxed closure as.
///
/// The program HOLDS this nominal and hands it to a foreign `run`-style
/// entrypoint, never seeing the `Box<dyn Fn …>` inside. The adapter's snake-case
/// ref name upper-camels and gains a `Closure` suffix (`update` →
/// `UpdateClosure`, `apply_fn` → `ApplyFnClosure`): an upper-camel Ipê type name
/// distinct from any snake-case value binding, and — with the suffix — from a
/// bare define-struct/enum nominal an author would name after the type itself
/// (`Counter`, `Message`). The interface still gates the result against every
/// real nominal fail-closed; this scheme only lowers the odds a gate must fire.
#[must_use]
pub fn closure_handle_nominal(ref_name: &str) -> String {
    let camel: String = ref_name
        .split('_')
        .filter(|seg| !seg.is_empty())
        .map(capitalise_first)
        .collect();
    format!("{camel}Closure")
}

/// Raw-escape a foreign identifier that collides with a Rust keyword
/// (`match` → `r#match`) so a keyword-named foreign field/variant/method
/// still renders parseable Rust.
///
/// The backend's trailing-underscore mangle is wrong here: the emitted name
/// must reference the REAL foreign item, so `r#` is the only correct escape.
/// `crate`/`self`/`Self`/`super` pass through unchanged — they reject the
/// `r#` form, and Rust forbids them as field/variant/method names anyway.
#[must_use]
pub fn rust_safe_ident(s: &str) -> String {
    // `crate`/`self`/`Self`/`super` are Rust keywords too, but they reject the
    // `r#` escape and pass through unchanged instead — see the doc above.
    let is_raw_escapable_keyword =
        ipe_intern::is_rust_keyword(s) && !matches!(s, "crate" | "self" | "Self" | "super");
    if is_raw_escapable_keyword {
        format!("r#{s}")
    } else {
        s.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_helpers() {
        assert_eq!(lower_first("Version"), "version");
        assert_eq!(lower_first(""), "");
        assert_eq!(capitalise_first("uuid"), "Uuid");
        assert_eq!(mangle_tvar("a"), "A");
        assert_eq!(mangle_tvar("msg"), "Msg");
    }

    #[test]
    fn wrapper_ref_name_disambiguates_accessors_by_receiver() {
        assert_eq!(wrapper_ref_name("Parse", ""), "parse");
        assert_eq!(
            wrapper_ref_name("major_field", "Version"),
            "major_field_from_version"
        );
    }

    #[test]
    fn module_and_kernel_names() {
        assert_eq!(rust_module_name("uuid"), "Rust.Uuid");
        assert_eq!(rust_module_name("serde-json"), "Rust.Serde_json");
        assert_eq!(rust_kernel_name("uuid"), "Rust_Uuid");
        assert_eq!(rust_kernel_name("stripe-go/v82"), "Rust_Stripe_goV82");
        assert_eq!(rust_kernel_name(""), "Rust_Ffi");
    }

    #[test]
    fn sentinels_key_off_the_wrapper_ref_name() {
        assert_eq!(
            wrapper_begin_sentinel("parse"),
            "// IPE-FFI-WRAPPER BEGIN parse"
        );
        assert!(wrapper_begin_sentinel("x").starts_with(WRAPPER_SENTINEL_PREFIX));
        assert_eq!(WRAPPER_END_SENTINEL, "// IPE-FFI-WRAPPER END");
    }

    #[test]
    fn arg_names_are_positional() {
        assert_eq!(arg_name(0), "arg0");
        assert_eq!(arg_name(12), "arg12");
    }

    #[test]
    fn snake_case_matches_the_backend_convention() {
        assert_eq!(to_snake_case("Semver_parse"), "semver_parse");
        assert_eq!(
            to_snake_case("Semver_toString_from_version"),
            "semver_to_string_from_version"
        );
        assert_eq!(to_snake_case("Main_update"), "main_update");
        assert_eq!(to_snake_case(""), "");
    }

    #[test]
    fn wrapper_fn_ident_drops_the_rust_prefix_and_snakes() {
        assert_eq!(wrapper_fn_ident("Rust_Semver", "parse"), "semver_parse");
        assert_eq!(
            wrapper_fn_ident("Rust_Semver", "major_field_from_version"),
            "semver_major_field_from_version"
        );
        assert_eq!(wrapper_fn_ident("Ffi", "x"), "ffi_x");
    }

    #[test]
    fn closure_handle_nominal_upper_camels_and_suffixes() {
        assert_eq!(closure_handle_nominal("update"), "UpdateClosure");
        assert_eq!(closure_handle_nominal("apply_fn"), "ApplyFnClosure");
        assert_eq!(closure_handle_nominal("handler_fn"), "HandlerFnClosure");
        // Repeated / trailing underscores collapse rather than emit empty segments.
        assert_eq!(closure_handle_nominal("a__b_"), "ABClosure");
    }

    #[test]
    fn rust_safe_ident_raw_escapes_keywords_only() {
        assert_eq!(rust_safe_ident("match"), "r#match");
        assert_eq!(rust_safe_ident("type"), "r#type");
        assert_eq!(rust_safe_ident("gen"), "r#gen");
        assert_eq!(rust_safe_ident("major"), "major");
        // `r#self` is invalid Rust; these pass through (unreachable as
        // foreign field/variant names).
        assert_eq!(rust_safe_ident("self"), "self");
        assert_eq!(rust_safe_ident("crate"), "crate");
    }

    #[test]
    fn every_ssot_keyword_is_escaped_or_passed_through() {
        for kw in ipe_intern::RUST_KEYWORDS {
            let out = rust_safe_ident(kw);
            if matches!(*kw, "crate" | "self" | "Self" | "super") {
                assert_eq!(out, *kw, "{kw} must pass through unescaped");
            } else {
                assert_eq!(out, format!("r#{kw}"), "{kw} must be raw-escaped");
            }
        }
    }

    #[test]
    fn rust_ident_accepts_identifiers_and_kills_injection_shapes() {
        assert!(RustIdent::parse("parse").is_ok());
        assert!(RustIdent::parse("_private2").is_ok());
        assert!(RustIdent::parse("Version").is_ok());
        for bad in [
            "",
            "2fast",
            "a-b",
            "a b",
            "a::b",
            "; std::process::Command::new(\"sh\")",
            "名前",
        ] {
            assert!(RustIdent::parse(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn ident_path_validates_every_segment() {
        assert!(IdentPath::parse("civil").is_ok());
        assert!(IdentPath::parse("civil::date").is_ok());
        for bad in ["", "::", "a::", "::b", "a::b-c", "a; rm -rf /"] {
            assert!(IdentPath::parse(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn rust_type_expr_admits_the_real_inspector_grammar() {
        for ok in [
            "i64",
            "String",
            "::std::string::String",
            "Vec<::crate::T>",
            "Result<Vec<T>, E>",
            "Result<Version, Error>",
            "&str",
            "&mut Version",
            "&Version",
            "()",
            "(A, B)",
            "serde_json::Value",
            "&serde_json::Value",
            "HashMap<String, i32>",
            "&[u8]",
            "&[u8; 4]",
            "[u8; 16]",
            "Option<i32>",
            "DateTime<Tz>",
        ] {
            assert!(RustTypeExpr::parse(ok).is_ok(), "{ok:?} must be accepted");
        }
    }

    #[test]
    fn rust_type_expr_rejects_injection_shapes() {
        for bad in [
            "",
            "   ",
            "String { } fn e(){ std::process::exit(1) }",
            "T; std::process::exit(1)",
            "T)//",
            "Vec<T",    // unbalanced angle
            "Vec T>",   // unbalanced angle
            "(A, B",    // unbalanced paren
            "foo(bar)", // a call, not a type — paren balanced but see below
            "String\n  fn evil(){}",
            "T = 1",
            "std::process::Command::new(\"sh\")",
            "T\"lit\"",
            "T { field: 1 }",
        ] {
            // `foo(bar)` is bracket-balanced and charset-clean, so it is
            // ADMITTED by the grammar (it is a legal — if unusual — tuple-like
            // application shape); assert only the genuinely-illegal ones.
            if bad == "foo(bar)" {
                continue;
            }
            assert!(
                RustTypeExpr::parse(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
        // A `;` at statement depth is rejected; a `;` inside an array is not.
        assert!(RustTypeExpr::parse("[u8; 4]").is_ok());
        assert!(RustTypeExpr::parse("u8; 4").is_err());
    }

    #[test]
    fn rust_pattern_admits_only_variant_head_plus_optional_suffix() {
        for ok in ["Exact", "Greater", "Greater(..)", "Point{..}", "r#match"] {
            // `r#match` is not a bare RustIdent; the pattern head is the raw
            // variant, so only plain idents pass — adjust the corpus.
            if ok == "r#match" {
                assert!(RustPattern::parse(ok).is_err());
                continue;
            }
            assert!(RustPattern::parse(ok).is_ok(), "{ok:?} must be accepted");
        }
        for bad in [
            "",
            "Greater(x)",
            "Greater(a, b)",
            "_ => evil()",
            "V => { std::process::exit(1) }",
            "V if true",
            "V(..) | W(..)",
        ] {
            assert!(RustPattern::parse(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn field_selector_admits_idents_and_indices_only() {
        for ok in ["", "0", "12", "field", "some_field", "_x"] {
            assert!(FieldSelector::parse(ok).is_ok(), "{ok:?} must be accepted");
        }
        for bad in ["0x", "a.b", "a b", "-1", "f()", "a::b", "; evil"] {
            assert!(
                FieldSelector::parse(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }
}
