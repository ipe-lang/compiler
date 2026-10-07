//! `IpeStringify` — the total Ipê value stringifier — and `IpeInterpolate`,
//! the closed scalar renderer behind `{{expr}}` interpolation and `Log.*With`.
//!
//! `IpeInterpolate` is sealed and implemented for exactly the five interpolable
//! scalars ([`INTERPOLABLE_IPE_TYPES`]); no record, ADT, container or opaque
//! runtime type can reach an interpolation or a log attribute, so neither path
//! has a `Debug` fallback.
//!
//! `IpeStringify` backs `Basics.errorToString` (and `Ipe.Test.debugShow`, which
//! is just `errorToString v`). A value becomes text through this trait only:
//! there is no fallback to `Debug`, so a type with no impl cannot be shown and
//! the compiler refuses the program before the Rust build.
//!
//! Every lowered type leaf has exactly one [`ShowPolicy`], declared by the one
//! `show_row!` invocation that writes its impl, in the module that owns the
//! type. [`SHOWN_RUNTIME_TYPES`] lists every leaf in the compiler's leaf order;
//! the build asserts it equal to the compiler's leaf table (`ipe-cli`), each
//! `show_row!` asserts its leaf and policy are listed, and `tests/show_rows.rs`
//! pins every listed leaf to the runtime type that renders it. Carriers
//! (`Vec`, `HashMap`, `BTreeSet`, tuples, `IpeMaybe`, `IpeResult`, references,
//! boxes) are structural impls in this module.
//!
//! Why a trait, not `Debug`: `Debug` QUOTES a `String` (`"hi"`), diverging
//! from unquoted `hi`, and prints every field of a runtime struct, secrets
//! included.
//!
//! Totality contract: `ipe_show` NEVER panics — no `unwrap`/`expect`/indexing.
//!
//! Rendering conventions:
//! - String: unquoted (`"hi"` → `hi`)
//! - Numbers/Bool: Display
//! - List: space-separated in brackets (`[1 2 3]`)
//! - Nested list: `[[1 2] [3 4]]`
//! - Set: like a list, in ascending order
//! - Tuple: space-separated in braces (`{1 a}`)
//! - Record: fields in `_fieldIndex` order, space-separated in braces
//! - Dict: `map[k1:v1 k2:v2]` with keys SORTED, space-separated
//! - `Redacted` leaves: `<redacted>`; `Bytes`: `<N bytes>`
//! - `Internals` leaves: `<Module.Type>`

use crate::core::{IpeMaybe, IpeResult};
use std::collections::{BTreeSet, HashMap};

/// Total Ipê stringifier. One method, infallible, never panics.
///
/// A type with only a `Debug` impl has no rendering:
///
/// ```compile_fail
/// use ipe_runtime_rust::stringify::IpeStringify;
/// #[derive(Debug)]
/// struct OnlyDebug;
/// let _ = IpeStringify::ipe_show(&OnlyDebug);
/// ```
pub trait IpeStringify {
    /// Render `self` byte-identically to  `Basics_errorToString` / `%v`.
    fn ipe_show(&self) -> String;
}

/// How a lowered type leaf becomes text.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ShowPolicy {
    /// The value itself.
    Value,
    /// A fixed marker that never carries the value's content.
    Redacted,
    /// A `<Module.Type>` marker for opaque runtime machinery.
    Internals,
    /// No rendering: the compiler refuses to show the leaf.
    Refused,
}

impl ShowPolicy {
    /// The policy as a number, comparable in a `const` context.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Value => 0,
            Self::Redacted => 1,
            Self::Internals => 2,
            Self::Refused => 3,
        }
    }
}

/// A runtime type that a lowered leaf renders to, with that leaf's show policy.
///
/// Implemented only by `show_row!`, beside the type's `IpeStringify` impl.
pub trait ShownRow: IpeStringify {
    /// The compiler leaf name this type renders.
    const LEAF: &'static str;
    /// The leaf's show policy.
    const POLICY: ShowPolicy;
}

/// Write a type's `IpeStringify` impl and its [`ShownRow`] facts in one place.
///
/// `show_row!("Leaf", Policy, [generics] Type, |binder| body)`: `body` renders
/// `binder` (a `&Type`). Invoked in the module that owns `Type`, so the impl
/// exists in every build that has the type.
macro_rules! show_row {
    ($leaf:literal, $policy:ident, [$($gen:tt)*] $ty:ty, |$v:pat_param| $body:expr) => {
        impl<$($gen)*> $crate::stringify::IpeStringify for $ty {
            fn ipe_show(&self) -> String {
                let $v = self;
                $body
            }
        }
        impl<$($gen)*> $crate::stringify::ShownRow for $ty {
            const LEAF: &'static str = $leaf;
            const POLICY: $crate::stringify::ShowPolicy =
                $crate::stringify::ShowPolicy::$policy;
        }
        // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a show row's leaf or policy is missing from `SHOWN_RUNTIME_TYPES` [ledger #boundary]
        const _: () = assert!(
            $crate::stringify::leaf_listed($leaf, $crate::stringify::ShowPolicy::$policy),
            concat!("show row not listed with its policy: ", $leaf)
        );
    };
}
pub(crate) use show_row;

/// The marker a `Redacted` leaf renders.
pub const REDACTED_SHOW: &str = crate::redact::REDACTED;

/// Byte equality of two `&str` in a `const` context.
#[must_use]
pub const fn str_eq(a: &str, b: &str) -> bool {
    let mut a = a.as_bytes();
    let mut b = b.as_bytes();
    loop {
        match (a, b) {
            ([], []) => return true,
            ([x, a_rest @ ..], [y, b_rest @ ..]) if *x == *y => {
                a = a_rest;
                b = b_rest;
            }
            _ => return false,
        }
    }
}

/// Every compiler leaf and its show policy, in the compiler's leaf order:
/// `"Leaf" => Policy;`. Generates [`SHOWN_RUNTIME_TYPES`], asserted equal to
/// the compiler's table at build time (`ipe-cli`). The table names no runtime
/// type, so it compiles in every vendored module set; each `show_row!` asserts
/// its own leaf and policy are listed here, and `tests/show_rows.rs` pins every
/// listed leaf to the runtime type that renders it.
macro_rules! shown_leaves {
    ($($leaf:literal => $policy:ident;)*) => {
        /// Every compiler leaf and its show policy, in the compiler's leaf
        /// order.
        pub const SHOWN_RUNTIME_TYPES: [(&str, ShowPolicy); [$($leaf),*].len()] =
            [$(($leaf, ShowPolicy::$policy)),*];
    };
}

/// Whether [`SHOWN_RUNTIME_TYPES`] lists `leaf` with `policy`.
#[must_use]
pub const fn leaf_listed(leaf: &str, policy: ShowPolicy) -> bool {
    let mut rows: &[(&str, ShowPolicy)] = &SHOWN_RUNTIME_TYPES;
    while let [(name, listed), rest @ ..] = rows {
        if str_eq(name, leaf) && listed.tag() == policy.tag() {
            return true;
        }
        rows = rest;
    }
    false
}

shown_leaves! {
    "Int" => Value;
    "Float" => Value;
    "Bool" => Value;
    "String" => Value;
    "Char" => Value;
    "Unit" => Value;
    "Order" => Value;
    "BackoffStrategy" => Value;
    "HttpMethod" => Value;
    "RedirectPolicy" => Value;
    "Decimal" => Value;
    "ErrorKind" => Value;
    "Error" => Value;
    "ErrorDetails" => Value;
    "ErrorInfo" => Value;
    "PanicInfo" => Value;
    "TypeInfo" => Value;
    "DbFailure" => Value;
    "Path" => Value;
    "UrlRelative" => Value;
    "Locale" => Value;
    "EmailAddress" => Value;
    "CryptoMac" => Value;
    "Color" => Value;
    "ColorError" => Value;
    "WcagLevel" => Value;
    "TextSize" => Value;
    "Deficiency" => Value;
    "CsvDoc" => Value;
    "CacheStats" => Value;
    "StreamId" => Value;
    "Json" => Value;
    "Bytes" => Redacted;
    "Url" => Redacted;
    "Secret" => Redacted;
    "CryptoKey" => Redacted;
    "Principal" => Redacted;
    "Dsn" => Redacted;
    "SqlFragment" => Redacted;
    "ServerRequest" => Redacted;
    "ServerResponse" => Redacted;
    "ServerCookie" => Redacted;
    "WebReq" => Redacted;
    "HttpRequest" => Redacted;
    "AuthConfig" => Redacted;
    "TokenSource" => Redacted;
    "WebSocketClientCfg" => Redacted;
    "ProcessRunWithCfg" => Redacted;
    "ProcessRunInPtyCfg" => Redacted;
    "CacheCfg" => Redacted;
    "Regex" => Redacted;
    "EmailMessage" => Redacted;
    "EmailAttachment" => Redacted;
    "EmailSesConfig" => Redacted;
    "EmailSmtpConfig" => Redacted;
    "Task" => Internals;
    "Cmd" => Internals;
    "Sub" => Internals;
    "Decoder" => Internals;
    "Db" => Internals;
    "Connection" => Internals;
    "Setting" => Internals;
    "StreamWriter" => Internals;
    "ServerRoute" => Internals;
    "WebSocketServer" => Internals;
    "WebSocketServerCfg" => Internals;
    "WebApp" => Internals;
    "TuiApp" => Internals;
    "CliApp" => Internals;
    "WorkerApp" => Internals;
    "WebRoute" => Internals;
    "CustomElement" => Internals;
    "CacheHandle" => Internals;
    "ChunkEvent" => Internals;
    "EmailProvider" => Internals;
    "TermProfile" => Internals;
    "AnsiColor" => Internals;
    "Html" => Internals;
    "Element" => Internals;
    "Cells" => Internals;
    "UiAttribute" => Internals;
    "TuiAttribute" => Internals;
    "CliLines" => Internals;
    "CliAttribute" => Internals;
    "HtmlAttribute" => Internals;
    "HtmlEvent" => Internals;
    "Label" => Internals;
    "Placeholder" => Internals;
    "RadioOption" => Internals;
    "Length" => Internals;
    "HAlign" => Internals;
    "VAlign" => Internals;
    "Location" => Internals;
    "PseudoClass" => Internals;
    "Description" => Internals;
    "LayoutContext" => Internals;
    "ProjectionTerm" => Internals;
    "ProjectionOperand" => Internals;
    "ArithOp" => Internals;
    "Fun" => Refused;
    "SharedFun" => Refused;
    "FnOnceChain" => Refused;
    "Foreign" => Refused;
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

// A String returns verbatim (UNQUOTED).
show_row!("String", Value, [] String, |s| s.clone());
show_row!("Char", Value, [] char, |c| crate::string::string_from_char(*c));

impl IpeStringify for str {
    fn ipe_show(&self) -> String {
        self.to_string()
    }
}

show_row!("Int", Value, [] i64, |n| n.to_string());

show_row!("Float", Value, [] f64, |x| float_show(*x));

/// The `%g` rendering of a float.
fn float_show(f: f64) -> String {
    //  `%v` on a float64 is `strconv.FormatFloat(f, 'g', -1, 64)`: the
    // shortest round-trippable digits, formatted with `%e` when the decimal
    // exponent is < -4 or >= 6 and `%f` otherwise, with `+Inf`/`-Inf`/`NaN`
    // for the non-finite values. Rust's `f64::to_string` matches  `%f`
    // branch exactly (42.5 -> "42.5", 1.0 -> "1", 0.0001 -> "0.0001"), but
    // diverges on infinities (`inf`/`-inf`) and never emits exponent form
    // (1e21 -> "1000000000000000000000" instead of "1e+21"). Bridge the
    // gap totally: handle the non-finite cases, then reformat Rust's shortest
    // scientific output to `%g`-`%e` shape when needed.
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

show_row!("Bool", Value, [] bool, |b| crate::string::string_from_bool(*b));

// Ipê `()` renders `{}`, an empty tuple.
show_row!("Unit", Value, [](), |_| "{}".to_owned());

// Bytes often carry key material or a file body: the length is shown, never
// the content.
show_row!("Bytes", Redacted, [] Vec<u8>, |b| format!("<{} bytes>", b.len()));

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

// ─── Sets ────────────────────────────────────────────────────────────────────

impl<T: IpeStringify> IpeStringify for BTreeSet<T> {
    // Set: like a list, elements in ascending order.
    fn ipe_show(&self) -> String {
        let parts: Vec<String> = self.iter().map(IpeStringify::ipe_show).collect();
        format!("[{}]", parts.join(" "))
    }
}

// ─── Tuples (`{a b ...}`) ───────────────────────────────────────────────────

/// The widest tuple with a structural impl, the arity Rust's own trait impls
/// stop at; the compiler refuses to show a wider one.
pub const MAX_SHOWN_TUPLE_ARITY: usize = 12;

macro_rules! tuple_shows {
    ($(($($t:ident $i:tt),+);)*) => {
        $(
            impl<$($t: IpeStringify),+> IpeStringify for ($($t,)+) {
                fn ipe_show(&self) -> String {
                    let parts = [$(self.$i.ipe_show()),+];
                    format!("{{{}}}", parts.join(" "))
                }
            }
        )*
    };
}

tuple_shows! {
    (A 0, B 1);
    (A 0, B 1, C 2);
    (A 0, B 1, C 2, D 3);
    (A 0, B 1, C 2, D 3, E 4);
    (A 0, B 1, C 2, D 3, E 4, F 5);
    (A 0, B 1, C 2, D 3, E 4, F 5, G 6);
    (A 0, B 1, C 2, D 3, E 4, F 5, G 6, H 7);
    (A 0, B 1, C 2, D 3, E 4, F 5, G 6, H 7, I 8);
    (A 0, B 1, C 2, D 3, E 4, F 5, G 6, H 7, I 8, J 9);
    (A 0, B 1, C 2, D 3, E 4, F 5, G 6, H 7, I 8, J 9, K 10);
    (A 0, B 1, C 2, D 3, E 4, F 5, G 6, H 7, I 8, J 9, K 10, L 11);
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

    #[test]
    fn char_and_set_render_their_values() {
        assert_eq!('x'.ipe_show(), "x");
        assert_eq!(BTreeSet::from([3i64, 1, 2]).ipe_show(), "[1 2 3]");
    }

    #[test]
    fn a_twelve_tuple_renders_every_element() {
        let t = (
            1i64, 2i64, 3i64, 4i64, 5i64, 6i64, 7i64, 8i64, 9i64, 10i64, 11i64, 12i64,
        );
        assert_eq!(t.ipe_show(), "{1 2 3 4 5 6 7 8 9 10 11 12}");
    }

    // Bytes render their length, never a byte of their content.
    #[test]
    fn bytes_show_their_length_only() {
        let shown = vec![0x53u8, 0x33, 0x43].ipe_show();
        assert_eq!(shown, "<3 bytes>");
        assert!(!shown.contains("83"), "{shown}");
        assert!(!shown.contains("67"), "{shown}");
        assert_eq!(<Vec<u8> as ShownRow>::POLICY, ShowPolicy::Redacted);
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

    // Every leaf is listed once, so the compiler-side agreement is a bijection.
    #[test]
    fn every_leaf_is_listed_once() {
        for (i, (a, _)) in SHOWN_RUNTIME_TYPES.iter().enumerate() {
            for (b, _) in SHOWN_RUNTIME_TYPES.iter().skip(i + 1) {
                assert_ne!(a, b, "leaf listed twice");
            }
        }
    }

    // A record-shaped value holding secret-role runtime values renders none
    // of their secrets: each is a `Redacted` row.
    #[cfg(feature = "server")]
    #[test]
    fn redacted_rows_render_no_secret() {
        use std::collections::BTreeMap;
        let pair = |k: &str, v: &str| HashMap::from([(k.to_owned(), v.to_owned())]);
        #[allow(clippy::expect_used)] // fixture: a non-empty cookie name always parses
        let cookie = match crate::server::server_cookie("sid".to_owned(), "S3CR3T".to_owned()) {
            IpeResult::Ok(c) => Some(c),
            IpeResult::Err(_) => None,
        }
        .expect("a non-empty cookie name");
        let req = crate::server::ServerRequest {
            method: "S3CR3T".to_owned(),
            path: "/S3CR3T".to_owned(),
            body: "S3CR3T".to_owned(),
            headers: pair("Authorization", "Bearer S3CR3T"),
            params: pair("id", "S3CR3T"),
            query: pair("q", "S3CR3T"),
            cookies: pair("sid", "S3CR3T"),
            remoteAddr: "S3CR3T".to_owned(),
        };
        let who = crate::principal::principal_mint_with_claims(
            "user-S3CR3T".to_owned(),
            BTreeMap::from([("email".to_owned(), "S3CR3T@example.com".to_owned())]),
        );
        let shown = format!(
            "{{{} {} {}}}",
            IpeStringify::ipe_show(&req),
            IpeStringify::ipe_show(&cookie),
            IpeStringify::ipe_show(&who)
        );
        assert!(!shown.contains("S3CR3T"), "{shown}");
        assert_eq!(shown, "{<redacted> <redacted> <redacted>}");
    }

    // A `Secret` and a parsed `Dsn` shown directly render the marker only.
    #[cfg(all(feature = "secret", feature = "db"))]
    #[test]
    fn secret_and_dsn_rows_render_no_secret() {
        let secret = crate::secret::secret_from_string("S3CR3T".to_owned());
        #[allow(clippy::expect_used)] // fixture: a literal DSN always parses
        let dsn = match crate::dsn::dsn_parse::<String>(
            "postgres://user:S3CR3T@localhost/app".to_owned(),
        ) {
            IpeResult::Ok(d) => Some(d),
            IpeResult::Err(_) => None,
        }
        .expect("a literal DSN");
        let shown = format!(
            "{} {}",
            IpeStringify::ipe_show(&secret),
            IpeStringify::ipe_show(&dsn)
        );
        assert!(!shown.contains("S3CR3T"), "{shown}");
        assert_eq!(shown, "<redacted> <redacted>");
    }

    // A URL's userinfo, query and fragment never reach its implicit
    // rendering; its scheme, host, port and path do.
    #[cfg(feature = "url")]
    #[test]
    fn url_show_keeps_no_userinfo_query_or_fragment() {
        #[allow(clippy::expect_used)] // fixture: a literal absolute URL always parses
        let url = match crate::url::url_from_string::<String>(
            "https://S3CR3TUSER:S3CR3TPW@example.com:8443/a/b?token=S3CR3TQ#frag=S3CR3TF"
                .to_owned(),
        ) {
            IpeResult::Ok(u) => Some(u),
            IpeResult::Err(_) => None,
        }
        .expect("a literal absolute URL");
        let shown = url.ipe_show();
        assert!(!shown.contains("S3CR3T"), "{shown}");
        assert!(!shown.contains(['@', '?', '#']), "{shown}");
        assert_eq!(shown, "https://example.com:8443/a/b");
    }

    // A credential that spilled out of the userinfo — a scheme-confused
    // `user:pw@host`, a host read from the user name, an opaque payload — never
    // reaches a URL's implicit rendering: only a nameable scheme is shown.
    #[cfg(feature = "url")]
    #[test]
    fn url_show_withholds_a_spilled_credential() {
        let r = REDACTED_SHOW;
        let cases = [
            ("s3cr3tuser:S3CR3TPW@db.internal", r.to_owned()),
            ("data:text/plain,S3CR3T", format!("data:{r}")),
            ("mailto:S3CR3T@example.com", format!("mailto:{r}")),
            (
                "https://S3CR3TUSER:1/S3CR3TPW@example.com/x",
                format!("https:{r}"),
            ),
            (
                "https://S3CR3TUSER#S3CR3TPW@example.com",
                format!("https:{r}"),
            ),
            (
                "https://S3CR3TUSER?S3CR3TPW@example.com",
                format!("https:{r}"),
            ),
            ("s3cr3tuser://example.com/a", format!("{r}://example.com/a")),
        ];
        for (raw, expected) in cases {
            #[allow(clippy::expect_used)] // fixture: each literal is an absolute URL
            let url = match crate::url::url_from_string::<String>(raw.to_owned()) {
                IpeResult::Ok(u) => Some(u),
                IpeResult::Err(_) => None,
            }
            .expect("a literal absolute URL");
            let shown = url.ipe_show();
            assert!(
                !shown.to_ascii_lowercase().contains("s3cr3t"),
                "{raw}: {shown}"
            );
            assert_eq!(shown, expected, "{raw}");
        }
    }
}
