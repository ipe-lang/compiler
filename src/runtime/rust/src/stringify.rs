//! `IpeStringify` — the total Ipê value stringifier — and `IpeInterpolate`,
//! the closed scalar renderer behind `{{expr}}` interpolation and `Log.*With`.
//!
//! `IpeInterpolate` is sealed and implemented for exactly the five interpolable
//! scalars ([`INTERPOLABLE_IPE_TYPES`]); no record, ADT, container or opaque
//! runtime type can reach an interpolation or a log attribute, so neither path
//! has a `Debug` fallback.
//!
//! `IpeStringify` backs `Basics.errorToString` (and `Ipe.Test.debugShow`, which
//! is just `errorToString v`). Every type reachable from a generic `errorToString`
//! call implements this trait (runtime primitives below; every codegen-emitted
//! record/ADT gets an `IpeStringify` impl from the compiler's emitter).
//!
//! Why a trait, not `Debug`: `Debug` QUOTES a `String` (`"hi"`), diverging
//! from unquoted `hi`. A `Display` re-bind is not total (no codegen type
//! emits `Display`). `IpeStringify` is the total middle path.
//!
//! Totality contract: `ipe_show` NEVER panics — no `unwrap`/`expect`/indexing.
//! A type with no meaningful string analogue (function-typed fields) renders a
//! best-effort placeholder rather than failing.
//!
//! Rendering conventions:
//! - String: unquoted (`"hi"` → `hi`)
//! - Numbers/Bool: Display
//! - List: space-separated in brackets (`[1 2 3]`)
//! - Nested list: `[[1 2] [3 4]]`
//! - Tuple: space-separated in braces (`{1 a}`)
//! - Record: fields in `_fieldIndex` order, space-separated in braces
//! - Dict: `map[k1:v1 k2:v2]` with keys SORTED, space-separated

use crate::core::{IpeMaybe, IpeResult};
use std::collections::HashMap;

/// Total Ipê stringifier. One method, infallible, never panics.
pub trait IpeStringify {
    /// Render `self` byte-identically to  `Basics_errorToString` / `%v`.
    fn ipe_show(&self) -> String;
}

// ─── Autoref specialization: total field rendering ───────────────────────────
//
// A codegen-emitted `impl IpeStringify for <GeneratedType>` renders each field
// by calling the field's stringifier. If it called `field.ipe_show()` directly,
// a field of a RUNTIME type that doesn't impl `IpeStringify` (e.g.
// `http_stream::ChunkEvent`) would be a `type-checks ⇒ cargo-fails` E0599 — a
// soundness-floor regression, and a whack-a-mole (every unhandled runtime type
// is a latent failure).
//
// The dispatch makes field rendering TOTAL BY CONSTRUCTION via dtolnay's
// autoref-specialization: a field renders via `IpeStringify` IF its type impls
// it, ELSE falls back to `Debug`. EVERY codegen + runtime type derives `Debug`,
// so this can NEVER fail to compile, regardless of field type.
//
// Mechanism: codegen emits `(&Wrap(&value)).dispatch()` at a CONCRETE field
// type. `Wrap<&T>: ViaIpeStringify` (no autoref) is preferred over
// `&Wrap<T>: ViaDebug` (one autoref) when `T: IpeStringify`; otherwise only the
// `Debug` impl applies. The dispatch is concrete-type-only by design — a generic
// `fn<T>` frame can't select either arm (the same method name on both traits is
// ambiguous when T's bounds are unknown), so the dispatch is emitted INLINE at
// each field site (where the type is concrete or a `IpeStringify + Debug`-bounded
// generic), NOT routed through a generic free function.
// (`basics_error_to_string<T: IpeStringify>` keeps its bound: a top-level
// `errorToString aString` must stay unquoted, which the IpeStringify path
// guarantees; the autoref-`Debug` fallback would quote a String at a generic
// frame.)

/// Newtype carrier for the autoref-specialization receiver. Constructed only by
/// the codegen-emitted `(&Wrap(&field)).dispatch()` field-render expression (and
/// this module's own tests); not part of the user-facing surface.
#[doc(hidden)]
pub struct Wrap<T>(pub T);

/// Higher-priority arm: a `Wrap<&T>` where `T: IpeStringify` renders via the
/// trait (String unquoted, nested generated types via their own impl). Selected
/// with ZERO autoref, so it beats the `Debug` fallback.
#[doc(hidden)]
pub trait ViaIpeStringify {
    fn dispatch(&self) -> String;
}
impl<T: IpeStringify> ViaIpeStringify for Wrap<&T> {
    fn dispatch(&self) -> String {
        self.0.ipe_show()
    }
}

/// Lower-priority arm: ANY `Wrap<T>` where `T: Debug` renders via `Debug`.
/// Reached only by ONE autoref (`&Wrap<T>`), so it loses to `ViaIpeStringify`
/// whenever the field type impls `IpeStringify`. Every type derives `Debug`,
/// so this arm is always available — the dispatch can never E0599.
#[doc(hidden)]
pub trait ViaDebug {
    fn dispatch(&self) -> String;
}
impl<T: core::fmt::Debug> ViaDebug for &Wrap<T> {
    fn dispatch(&self) -> String {
        format!("{:?}", self.0)
    }
}

// ─── Interpolation: the closed scalar set ───────────────────────────────────

/// Renders an interpolable scalar for `{{expr}}` and `Log.*With` attributes.
///
/// Sealed and implemented for exactly the rows of the `interpolable_scalars!`
/// table below, each through the same function its `String.from*` conversion
/// uses, so an interpolation and the explicit conversion never disagree.
pub trait IpeInterpolate: sealed::Sealed {
    /// The rendered text of `self`.
    fn ipe_interpolate(&self) -> String;
}

/// One table — `Rust type => Ipê name, render` — generates the sealing impls,
/// the `IpeInterpolate` impls and [`INTERPOLABLE_IPE_TYPES`], so the name list
/// the compiler is checked against and the impl set cannot drift apart.
macro_rules! interpolable_scalars {
    ($($rust:ty => $ipe:literal, |$v:ident| $render:expr;)*) => {
        /// The Ipê types [`IpeInterpolate`] is implemented for, by Ipê name —
        /// the runtime side of the compiler's interpolable set, asserted equal
        /// to it at build time (`ipe-cli`) so the two cannot drift.
        pub const INTERPOLABLE_IPE_TYPES: [&str; [$($ipe),*].len()] = [$($ipe),*];

        mod sealed {
            /// Seals [`super::IpeInterpolate`]: only this module can implement it.
            pub trait Sealed {}
            $(impl Sealed for $rust {})*
        }

        $(
            impl IpeInterpolate for $rust {
                fn ipe_interpolate(&self) -> String {
                    let $v = self;
                    $render
                }
            }
        )*
    };
}

interpolable_scalars! {
    String => "String", |s| s.clone();
    i64 => "Int", |n| crate::string::string_from_int(*n);
    f64 => "Float", |x| crate::string::string_from_float(*x);
    bool => "Bool", |b| crate::string::string_from_bool(*b);
    char => "Char", |c| crate::string::string_from_char(*c);
}

// ─── Scalars ────────────────────────────────────────────────────────────────

impl IpeStringify for String {
    // A String returns verbatim (UNQUOTED).
    fn ipe_show(&self) -> String {
        self.clone()
    }
}

impl IpeStringify for str {
    fn ipe_show(&self) -> String {
        self.to_string()
    }
}

impl IpeStringify for i64 {
    fn ipe_show(&self) -> String {
        self.to_string()
    }
}

impl IpeStringify for f64 {
    //  `%v` on a float64 is `strconv.FormatFloat(f, 'g', -1, 64)`: the
    // shortest round-trippable digits, formatted with `%e` when the decimal
    // exponent is < -4 or >= 6 and `%f` otherwise, with `+Inf`/`-Inf`/`NaN`
    // for the non-finite values. Rust's `f64::to_string` matches  `%f`
    // branch exactly (42.5 -> "42.5", 1.0 -> "1", 0.0001 -> "0.0001"), but
    // diverges on infinities (`inf`/`-inf`) and never emits exponent form
    // (1e21 -> "1000000000000000000000" instead of "1e+21"). Bridge the
    // gap totally: handle the non-finite cases, then reformat Rust's shortest
    // scientific output to `%g`-`%e` shape when needed.
    fn ipe_show(&self) -> String {
        let f = *self;
        if f.is_nan() {
            return "NaN".to_string();
        }
        if f.is_infinite() {
            return if f > 0.0 { "+Inf" } else { "-Inf" }.to_string();
        }
        // `{:e}` gives the shortest mantissa + decimal exponent, lowercase `e`,
        // no `+` and no zero-padding on the exponent (e.g. "1e21", "1.5e-5").
        let sci = format!("{f:e}");
        match sci.split_once('e') {
            // Exponent form iff exp < -4 || exp >= 6 (shortest-mode cut, same
            // as `strconv.FormatFloat(f,'g',-1,64)`): 1e6 -> "1e+06", 1e15 ->
            // "1e+15", 999999 -> "999999" (see reference-audit.md item 27 for
            // the oracle probe).
            Some((mantissa, exp_str)) => match exp_str.parse::<i32>() {
                Ok(exp) if !(-4..6).contains(&exp) => {
                    //  `%e` exponent: explicit sign, minimum two digits.
                    // i64 widen so `-exp` can't overflow for any i32.
                    let (sign, mag) = if exp < 0 {
                        ('-', -i64::from(exp))
                    } else {
                        ('+', i64::from(exp))
                    };
                    format!("{mantissa}e{sign}{mag:02}")
                }
                _ => f.to_string(),
            },
            None => f.to_string(),
        }
    }
}

impl IpeStringify for bool {
    fn ipe_show(&self) -> String {
        crate::string::string_from_bool(*self)
    }
}

impl IpeStringify for () {
    // Ipê `()` is  empty struct; `%v` renders `{}`. Rare in errorToString,
    // kept total for completeness.
    fn ipe_show(&self) -> String {
        "{}".to_string()
    }
}

// ─── References / boxes (delegate) ───────────────────────────────────────────

impl<T: IpeStringify + ?Sized> IpeStringify for &T {
    fn ipe_show(&self) -> String {
        (**self).ipe_show()
    }
}

impl<T: IpeStringify + ?Sized> IpeStringify for Box<T> {
    fn ipe_show(&self) -> String {
        (**self).ipe_show()
    }
}

// ─── Lists ───────────────────────────────────────────────────────────────────

impl<T: IpeStringify> IpeStringify for Vec<T> {
    // List: space-separated, square brackets, empty -> `[]`.
    fn ipe_show(&self) -> String {
        let parts: Vec<String> = self.iter().map(IpeStringify::ipe_show).collect();
        format!("[{}]", parts.join(" "))
    }
}

impl<T: IpeStringify> IpeStringify for [T] {
    fn ipe_show(&self) -> String {
        let parts: Vec<String> = self.iter().map(IpeStringify::ipe_show).collect();
        format!("[{}]", parts.join(" "))
    }
}

// ─── Maps ────────────────────────────────────────────────────────────────────

impl<K: IpeStringify + Ord, V: IpeStringify> IpeStringify for HashMap<K, V> {
    // Dict: `map[k1:v1 k2:v2]` with keys SORTED, space-separated.
    fn ipe_show(&self) -> String {
        let mut entries: Vec<(&K, &V)> = self.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let parts: Vec<String> = entries
            .iter()
            .map(|(k, v)| format!("{}:{}", k.ipe_show(), v.ipe_show()))
            .collect();
        format!("map[{}]", parts.join(" "))
    }
}

// ─── Tuples (Ipê tuples render like  T2/T3 structs: `{a b ...}`) ─────────

impl<A: IpeStringify, B: IpeStringify> IpeStringify for (A, B) {
    fn ipe_show(&self) -> String {
        format!("{{{} {}}}", self.0.ipe_show(), self.1.ipe_show())
    }
}

impl<A: IpeStringify, B: IpeStringify, C: IpeStringify> IpeStringify for (A, B, C) {
    fn ipe_show(&self) -> String {
        format!(
            "{{{} {} {}}}",
            self.0.ipe_show(),
            self.1.ipe_show(),
            self.2.ipe_show()
        )
    }
}

impl<A, B, C, D> IpeStringify for (A, B, C, D)
where
    A: IpeStringify,
    B: IpeStringify,
    C: IpeStringify,
    D: IpeStringify,
{
    fn ipe_show(&self) -> String {
        format!(
            "{{{} {} {} {}}}",
            self.0.ipe_show(),
            self.1.ipe_show(),
            self.2.ipe_show(),
            self.3.ipe_show()
        )
    }
}

// ─── Ipê core ADTs ───────────────────────────────────────────────────────────

impl<T: IpeStringify> IpeStringify for IpeMaybe<T> {
    // Best-effort, total, human-useful: `Just <v>` / `Nothing`.
    fn ipe_show(&self) -> String {
        match self {
            IpeMaybe::Just(v) => format!("Just {}", v.ipe_show()),
            IpeMaybe::Nothing => "Nothing".to_string(),
        }
    }
}

impl<E: IpeStringify, A: IpeStringify> IpeStringify for IpeResult<E, A> {
    // Best-effort (same ADT-layout residual as IpeMaybe): `Ok <a>` / `Err <e>`.
    fn ipe_show(&self) -> String {
        match self {
            IpeResult::Ok(a) => format!("Ok {}", a.ipe_show()),
            IpeResult::Err(e) => format!("Err {}", e.ipe_show()),
        }
    }
}

// ─── Runtime opaque value types that flow into errorToString/debugShow ───────
// These are real runtime types (not codegen-emitted), so their IpeStringify
// impls live HERE. A generated ADT can carry them as a payload (e.g.
// `Money(Decimal, …)`, `Claims(Vec<(String, JsonVal)>)`); the codegen's enum
// `ipe_show` calls `.ipe_show()` on the payload, so the type must impl it.

// `decimal.rs` is behind the `decimal` feature, so this impl — the only
// `stringify.rs` reference to `crate::decimal::Decimal` — carries the same gate.
// A program without the feature has no `Decimal` type to render.
#[cfg(feature = "decimal")]
impl IpeStringify for crate::decimal::Decimal {
    // Reuse the canonical Decimal renderer (normalized, no trailing zeros) —
    // matches `Decimal.toString`. Total (no panic).
    fn ipe_show(&self) -> String {
        crate::decimal::decimal_to_string(*self)
    }
}

// `serde_json` is only in the dependency tree under the `json` feature; gate the
// impl so a project that doesn't enable `json` still compiles (the unconditional
// form was an E0433 `unresolved crate serde_json` on default features).
#[cfg(feature = "json")]
impl IpeStringify for serde_json::Value {
    // Best-effort, total: compact JSON text — human-useful and never panics.
    // `to_string` on `serde_json::Value` is infallible.
    fn ipe_show(&self) -> String {
        self.to_string()
    }
}

// `IpeError` is a typed enum (see error.rs) implementing `Display`, so the
// blanket `ipe_show` above (`self.to_string()`) already renders its message —
// no separate `Stringify` impl is needed.

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn string_unquoted() {
        assert_eq!("hi".to_string().ipe_show(), "hi");
    }
    #[test]
    fn str_unquoted() {
        assert_eq!("hi".ipe_show(), "hi");
    }
    #[test]
    fn empty_string() {
        assert_eq!(String::new().ipe_show(), "");
    }
    #[test]
    fn int_plain() {
        assert_eq!(42i64.ipe_show(), "42");
    }
    #[test]
    fn bool_plain() {
        assert_eq!(true.ipe_show(), "true");
    }
    #[test]
    fn float_plain() {
        assert_eq!(42.5f64.ipe_show(), "42.5");
    }
    #[test]
    fn float_whole() {
        assert_eq!(1.0f64.ipe_show(), "1");
    }

    #[test]
    fn float_go_v_parity() {
        // `strconv.FormatFloat(f,'g',-1,64)` format. The cut to scientific
        // notation is a FLAT decimal-exponent >= 6 (and < -4), NOT 21.
        // Positional class (exp in [-4, 6)):
        assert_eq!(99999.0f64.ipe_show(), "99999"); // exp 4
        assert_eq!(1e5f64.ipe_show(), "100000"); // exp 5
        assert_eq!(999_999.0_f64.ipe_show(), "999999"); // exp 5 (lower guard)
        assert_eq!(123_456.789_f64.ipe_show(), "123456.789");
        assert_eq!(0.0001f64.ipe_show(), "0.0001"); // exp -4 boundary
        // Scientific class (exp >= 6) — these DISCRIMINATE 6 from 21:
        assert_eq!(1e6f64.ipe_show(), "1e+06"); // exp 6 — 21 would print "1000000"
        assert_eq!(1_000_001.0_f64.ipe_show(), "1.000001e+06"); // not a 1e6 special-case
        assert_eq!(1_234_567.0_f64.ipe_show(), "1.234567e+06");
        assert_eq!(1e15f64.ipe_show(), "1e+15"); // 21 would print 16 zeros
        assert_eq!(1e20f64.ipe_show(), "1e+20"); // 21 would print 21 digits
        assert_eq!(1e21f64.ipe_show(), "1e+21");
        // Scientific class (exp <= -5):
        assert_eq!(1e-5f64.ipe_show(), "1e-05");
        // Negative zero: -0.0 -> "-0".
        assert_eq!((-0.0f64).ipe_show(), "-0");
        // Non-finite (shared branch):
        assert_eq!(f64::INFINITY.ipe_show(), "+Inf");
        assert_eq!(f64::NEG_INFINITY.ipe_show(), "-Inf");
        assert_eq!(f64::NAN.ipe_show(), "NaN");
        assert_eq!((-1.5f64).ipe_show(), "-1.5");
    }

    #[test]
    fn vec_int_space_separated() {
        assert_eq!(vec![1i64, 2, 3].ipe_show(), "[1 2 3]");
    }
    #[test]
    fn vec_string_unquoted() {
        assert_eq!(vec!["a".to_string(), "b".to_string()].ipe_show(), "[a b]");
    }
    #[test]
    fn vec_empty() {
        let v: Vec<i64> = vec![];
        assert_eq!(v.ipe_show(), "[]");
    }
    #[test]
    fn vec_nested() {
        assert_eq!(vec![vec![1i64, 2], vec![3, 4]].ipe_show(), "[[1 2] [3 4]]");
    }

    #[test]
    fn tuple2() {
        assert_eq!((1i64, "a".to_string()).ipe_show(), "{1 a}");
    }
    #[test]
    fn tuple3() {
        assert_eq!((1i64, "a".to_string(), true).ipe_show(), "{1 a true}");
    }

    #[test]
    fn map_sorted() {
        let mut m: HashMap<String, i64> = HashMap::new();
        m.insert("b".to_string(), 2);
        m.insert("a".to_string(), 1);
        m.insert("c".to_string(), 3);
        assert_eq!(m.ipe_show(), "map[a:1 b:2 c:3]");
    }

    #[test]
    fn maybe_just() {
        assert_eq!(IpeMaybe::Just(5i64).ipe_show(), "Just 5");
    }
    #[test]
    fn maybe_nothing() {
        let n: IpeMaybe<i64> = IpeMaybe::Nothing;
        assert_eq!(n.ipe_show(), "Nothing");
    }
    #[test]
    fn result_ok() {
        let r: IpeResult<String, i64> = IpeResult::Ok(7);
        assert_eq!(r.ipe_show(), "Ok 7");
    }
    #[test]
    fn result_err() {
        let r: IpeResult<String, i64> = IpeResult::Err("boom".to_string());
        assert_eq!(r.ipe_show(), "Err boom");
    }

    // ─── Autoref-specialization dispatch (total field rendering) ─────────────

    // (a) A `String` field renders UNQUOTED via the IpeStringify arm.
    #[test]
    fn dispatch_string_unquoted() {
        let s = "hi".to_string();
        assert_eq!(Wrap(&s).dispatch(), "hi");
    }

    // (b) A type that impls ONLY `Debug` (NOT IpeStringify) renders via the
    // Debug fallback — NO compile error (this is the whole point: total by
    // construction). Mirrors a runtime payload type like `http_stream::ChunkEvent`.
    #[derive(Debug)]
    #[allow(dead_code)] // read only via the derived Debug (the test's whole point)
    struct OnlyDebug {
        x: i64,
    }

    #[test]
    fn dispatch_debug_fallback() {
        let d = OnlyDebug { x: 42 };
        assert_eq!((&Wrap(&d)).dispatch(), "OnlyDebug { x: 42 }");
    }

    // (c) A generated-style struct whose impl renders fields via the dispatch:
    // its String field renders unquoted INSIDE the `{...}` wrap.
    struct GenStruct {
        name: String,
        debug_only: OnlyDebug,
    }
    impl IpeStringify for GenStruct {
        fn ipe_show(&self) -> String {
            // Exactly what codegen now emits per field.
            format!(
                "{{{} {}}}",
                Wrap(&self.name).dispatch(),
                (&Wrap(&self.debug_only)).dispatch()
            )
        }
    }

    // Interpolation renders each scalar exactly as its `String.from*` does.
    #[test]
    fn interpolate_matches_the_string_conversions() {
        for f in [42.5, 1e6, 1e21, -0.0, 0.0001, f64::INFINITY, f64::NAN] {
            assert_eq!(f.ipe_interpolate(), crate::string::string_from_float(f));
        }
        assert_eq!(7i64.ipe_interpolate(), "7");
        assert_eq!(true.ipe_interpolate(), "true");
        assert_eq!('x'.ipe_interpolate(), "x");
        assert_eq!("hi".to_string().ipe_interpolate(), "hi");
    }

    #[test]
    fn dispatch_generated_struct_mixed_fields() {
        let g = GenStruct {
            name: "alice".to_string(),
            debug_only: OnlyDebug { x: 7 },
        };
        // String field unquoted; Debug-only field via fallback — never E0599.
        assert_eq!(g.ipe_show(), "{alice OnlyDebug { x: 7 }}");
    }

    // (d) A generated-style record holding secret-bearing runtime values: the
    // Debug fallback renders them, and none of their secrets reach the output.
    #[cfg(feature = "server")]
    struct GenAuthed {
        req: crate::server::ServerRequest,
        cookie: crate::server::ServerCookie,
        who: crate::principal::Principal,
    }
    #[cfg(feature = "server")]
    impl IpeStringify for GenAuthed {
        fn ipe_show(&self) -> String {
            format!(
                "{{{} {} {}}}",
                (&Wrap(&self.req)).dispatch(),
                (&Wrap(&self.cookie)).dispatch(),
                (&Wrap(&self.who)).dispatch()
            )
        }
    }

    #[cfg(feature = "server")]
    #[test]
    fn debug_fallback_renders_no_secret_of_a_runtime_value() {
        use std::collections::{BTreeMap, HashMap};
        let pair = |k: &str, v: &str| HashMap::from([(k.to_owned(), v.to_owned())]);
        #[allow(clippy::expect_used)] // fixture: a non-empty cookie name always parses
        let cookie = match crate::server::server_cookie("sid".to_owned(), "T0K3N".to_owned()) {
            IpeResult::Ok(c) => Some(c),
            IpeResult::Err(_) => None,
        }
        .expect("a non-empty cookie name");
        let g = GenAuthed {
            req: crate::server::ServerRequest {
                method: "GET".to_owned(),
                path: "/me".to_owned(),
                body: String::new(),
                headers: pair("Authorization", "Bearer S3CR3T"),
                params: HashMap::new(),
                query: HashMap::new(),
                cookies: pair("sid", "T0K3N"),
                remoteAddr: String::new(),
            },
            cookie,
            who: crate::principal::principal_mint_with_claims(
                "user-S3CR3T".to_owned(),
                BTreeMap::from([("email".to_owned(), "T0K3N@example.com".to_owned())]),
            ),
        };
        let shown = g.ipe_show();
        assert!(!shown.contains("S3CR3T"), "{shown}");
        assert!(!shown.contains("T0K3N"), "{shown}");
        assert!(shown.contains("\"GET\""), "{shown}");
    }
}
