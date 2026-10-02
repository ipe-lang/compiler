//! The `<crate>_bindings.rs` wrapper emitter — the third artifact.
//!
//! Every binding renders as a `pub fn` bracketed by the BEGIN/END sentinels
//! from [`crate::naming`], keyed off the same `wrapper_ref_name` the `.ipei`
//! and `kernel.json` emitters use, so the DCE filter can drop an unreached
//! wrapper by name without parsing Rust.
//!
//! Soundness posture: every SYNC foreign call runs inside
//! `std::panic::catch_unwind` (a foreign panic becomes a typed `Err`, never a
//! process abort observed by well-typed Ipê); every ASYNC call runs through the
//! single `ffi_spawn_guarded` choke-point, which spawns the foreign future,
//! arms the `AbortOnDrop` cancel guard, and funnels the `JoinError` panic
//! boundary as one indivisible step — so no async binding shape can spawn a
//! foreign task without arming the guard.
//! `catch_unwind` is sound only under `panic = "unwind"`, so the module top
//! carries a `#[cfg(panic = "abort")] compile_error!` fence that fails the
//! build on the *effective* panic strategy — a manifest text-scan
//! ([`cargo_profile_panic_is_unwind`], kept as an advisory pre-check) cannot
//! see a workspace profile or a `RUSTFLAGS=-Cpanic=abort` override.
//!
//! The emitter is a total function over an already-validated [`PkgInfo`]: a
//! binding it cannot render soundly emits NOTHING (over-drop), never a
//! wrapper cargo would reject.

use std::collections::BTreeSet;

use ipe_intern::rust_str_lit;

use crate::carrier::{Carrier, ClosureRet, ClosureSig, EnumDef, StructDef};
use crate::emit::{foreign_to_ipe, param_ipe_type};
use crate::naming::{RustIdent, arg_name, rust_kernel_name, rust_safe_ident, wrapper_fn_ident};
use crate::num_coerce::{is_numeric_rust, num_saturate, num_widen_scalar};
use crate::pkginfo::{Effect, EnumArm, EnumVariantKind, FnInfo, FnShape, Param, PkgInfo};

/// A rendered coercion lifting an expression of the raw foreign type into the
/// wrapper's declared type.
pub type RetCoercion = Box<dyn Fn(&str) -> String>;

fn identity_coercion() -> RetCoercion {
    Box::new(str::to_owned)
}

// ── small text helpers ──────────────────────────────────────────────────────

/// Make an extern-crate reference absolute (`csv::X` → `::csv::X`).
///
/// An absolute path can never collide with a same-named runtime kernel module
/// re-exported at the app crate root. Rewrites `<crate>::` only at a path
/// start (preceded by a non-identifier char that is not `:`), so nested
/// generics (`Vec<csv::X>`) and already-absolute paths stay correct.
#[must_use]
pub fn absolutize_crate(krate: &str, s: &str) -> String {
    let pat = format!("{krate}::");
    let mut out = String::new();
    let mut prev = ' ';
    let mut rest = s;
    while !rest.is_empty() {
        let ident_prev = prev.is_alphanumeric() || prev == '_';
        if rest.starts_with(&pat) && !ident_prev && prev != ':' {
            out.push_str("::");
            out.push_str(&pat);
            prev = ':';
            rest = rest.get(pat.len()..).unwrap_or("");
        } else {
            let mut cs = rest.chars();
            if let Some(c) = cs.next() {
                out.push(c);
                prev = c;
            }
            rest = cs.as_str();
        }
    }
    out
}

/// If the type is `Wrapper<inner>`, return `inner` (trimmed).
fn strip_generic1<'a>(wrapper: &str, s: &'a str) -> Option<&'a str> {
    let rest = s.trim().strip_prefix(wrapper)?.strip_prefix('<')?;
    if rest.is_empty() {
        return None;
    }
    rest.strip_suffix('>').map(str::trim)
}

/// For a `Result<T, E>` string return the Ok type `T`; otherwise the input
/// unchanged. Respects nested angle brackets so `Result<Vec<T>, E>` works.
fn ok_type_of_result(s: &str) -> String {
    let t = s.trim();
    t.strip_prefix("Result<").map_or_else(
        || t.to_owned(),
        |rest| first_type_arg(rest).trim().to_owned(),
    )
}

/// The first top-level type argument of a comma/angle-delimited list.
fn first_type_arg(rest: &str) -> &str {
    let mut depth = 0_i32;
    for (i, c) in rest.char_indices() {
        match c {
            '<' | '(' => depth += 1,
            '>' | ')' | ',' if depth == 0 => return rest.get(..i).unwrap_or(rest),
            '>' | ')' => depth -= 1,
            _ => {}
        }
    }
    rest
}

/// Strip a leading `&`/`&mut ` borrow from a Rust type string.
fn strip_ref(s: &str) -> &str {
    let s1 = s.trim_start_matches(['&', ' ']);
    s1.strip_prefix("mut ").unwrap_or(s1).trim()
}

/// Convert a pkg path to the Rust crate import ident
/// (`some/crate-name` → `crate_name`).
#[must_use]
pub fn pkg_to_crate_import(path: &str) -> String {
    let last = path.split('/').rfind(|s| !s.is_empty()).unwrap_or(path);
    last.replace('-', "_")
}

// ── panic-profile advisory pre-check ────────────────────────────────────────

/// Advisory fast pre-check: `true` when the manifest text declares NO
/// `panic = "abort"` in any profile table.
///
/// The SOUND gate is the `#[cfg(panic = "abort")] compile_error!` fence
/// emitted in every bindings file — a text-scan cannot see a workspace-root
/// profile or a `RUSTFLAGS=-Cpanic=abort`; this merely produces a friendlier
/// early error when the emitted manifest itself selects abort.
#[must_use]
pub fn cargo_profile_panic_is_unwind(cargo_toml_text: &str) -> bool {
    !cargo_toml_text.lines().any(line_declares_abort)
}

fn line_declares_abort(line: &str) -> bool {
    let Some(rest) = line.trim_start_matches(' ').strip_prefix("panic") else {
        return false;
    };
    let Some(value) = rest.trim_start_matches([' ', '\t']).strip_prefix('=') else {
        return false;
    };
    let normalised: String = value
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '"' | '\''))
        .collect();
    normalised == "abort"
}

// ── Ipê-type → Rust-type mapping ────────────────────────────────────────────

/// Map an Ipê type string to the wrapper-side Rust type. Opaque names fall
/// back to `String`; callers that know the raw Rust type prefer it via
/// [`resolve_rust_type`].
fn ipe_type_to_rust(st: &str) -> String {
    if let Some(inner) = st.strip_prefix("List ") {
        return format!("Vec<{}>", ipe_type_to_rust(inner));
    }
    if let Some(inner) = st.strip_prefix("Maybe ") {
        return format!("IpeMaybe<{}>", ipe_type_to_rust(inner));
    }
    if let Some(rest) = st.strip_prefix("Result ") {
        let mut w = rest.split_whitespace();
        return match (w.next(), w.next(), w.next()) {
            (Some(e), Some(a), None) => format!(
                "IpeResult<{}, {}>",
                ipe_type_to_rust(e),
                ipe_type_to_rust(a)
            ),
            _ => "IpeResult<IpeError, String>".to_owned(),
        };
    }
    if let Some(rest) = st.strip_prefix("Dict String ") {
        return format!("HashMap<String, {}>", ipe_type_to_rust(rest));
    }
    if let Some(rest) = st.strip_prefix("Task Error ") {
        return format!("IpeTask<IpeError, {}>", ipe_type_to_rust(rest));
    }
    match st {
        "Int" => "i64",
        "Float" => "f64",
        "Bool" => "bool",
        "Char" => "char",
        "()" => "()",
        "Bytes" => "Vec<u8>",
        // The typed Ipê error lands on the runtime's `IpeError`, never the
        // opaque-fallback String.
        "Error" => "IpeError",
        // "String" maps to itself; every unrecognised opaque falls back to
        // String too (the raw-Rust-type override is preferred upstream).
        _ => "String",
    }
    .to_owned()
}

/// True when [`ipe_type_to_rust`] gives a faithful (non-fallback) mapping —
/// a primitive/container Ipê understands, not an opaque crate type that
/// merely defaults to `String`.
fn is_known_ipe(st: &str) -> bool {
    matches!(
        st,
        "String" | "Int" | "Float" | "Bool" | "Char" | "Bytes" | "()"
    ) || ["List ", "Maybe ", "Result ", "Dict String ", "Task Error "]
        .iter()
        .any(|p| st.starts_with(p))
}

/// Resolve an Ipê surface type to the Rust type used in a wrapper PARAMETER
/// (and static-method receiver) position. Known Ipê types use their direct
/// mapping (owned values — `String`, not `&str`; the call site borrows).
/// Genuinely-opaque types use the inspector's raw Rust type, absolutized.
fn resolve_rust_type(krate: &str, st: &str, rt_override: &str) -> String {
    let owned_inner = |raw: &str| -> String { absolutize_crate(krate, strip_ref(raw)) };
    // `Maybe <opaque>` / `List <opaque>`: the Ipê mapping would collapse the
    // opaque inner to `String` — take the inner from the raw override instead
    // so the declared container element is the real `::crate::T`.
    if let Some(rest) = st.strip_prefix("Maybe ")
        && !is_known_ipe(rest.trim())
        && let Some(opt_inner) = strip_generic1("Option", rt_override)
    {
        return format!("IpeMaybe<{}>", owned_inner(opt_inner));
    }
    if let Some(rest) = st.strip_prefix("List ")
        && !is_known_ipe(rest.trim())
        && let Some(vec_inner) = strip_generic1("Vec", rt_override)
    {
        return format!("Vec<{}>", owned_inner(vec_inner));
    }
    if is_known_ipe(st) {
        return ipe_type_to_rust(st);
    }
    if !rt_override.is_empty() {
        return absolutize_crate(krate, rt_override);
    }
    "String".to_owned()
}

/// True when the Rust type is a `Copy` primitive, so a field getter reads it
/// as `recv.field` (a `.clone()` on a Copy type is a clippy deny).
fn is_copy_rust(t: &str) -> bool {
    matches!(
        t.trim(),
        "i8" | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "isize"
            | "usize"
            | "f32"
            | "f64"
            | "bool"
            | "char"
    )
}

// ── sequence (slice/array/Vec) classification ───────────────────────────────

/// Shape of a slice/array Rust type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeqShape {
    Slice,
    Owned,
    Arr(usize),
    RefArr(usize),
}

/// Element kind: the byte fast path, or a general coercible element carrying
/// its (Rust type, Ipê type).
#[derive(Debug, Clone, PartialEq, Eq)]
enum SeqElem {
    U8,
    General { rust: String, ipe: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SeqKind {
    shape: SeqShape,
    elem: SeqElem,
}

/// Sane array-size ceiling: a pathological `[u8; 999999999999]` from
/// adversarial rustdoc JSON must not emit an absurd array type — above the
/// ceiling the caller falls through to the opaque path.
const MAX_ARRAY_LEN: usize = 65536;

fn parse_array_len(digits: &str) -> Option<usize> {
    let t = digits.trim();
    if t.is_empty() || !t.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    t.parse::<usize>().ok().filter(|&n| n <= MAX_ARRAY_LEN)
}

/// The `N]`-terminated length of a `[u8; N]` remainder.
fn digits_before_close(rest: &str) -> Option<usize> {
    let (digits, tail) = rest.split_once(']')?;
    if !tail.is_empty() {
        return None;
    }
    parse_array_len(digits)
}

/// A coercible List element: the closed numeric set, `bool`/`char`/`String`,
/// or a bare opaque name (Clone-ness already verified inspector-side).
/// `str`/`OsString`/`PathBuf` are denied explicitly.
fn is_coercible_elem(e: &str) -> bool {
    const ADMIT_PRIM: [&str; 15] = [
        "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
        "f32", "f64", "bool",
    ];
    let t = e.trim();
    if t.is_empty() || t.contains(['&', ' ', '<', '[', ',']) {
        return false;
    }
    ADMIT_PRIM.contains(&t)
        || t == "char"
        || t == "String"
        || (t
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
            && !matches!(t, "str" | "OsString" | "PathBuf"))
}

fn ipe_of_elem(e: &str) -> String {
    match e {
        "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32" | "i64" | "i128"
        | "isize" => "Int".to_owned(),
        "f32" | "f64" => "Float".to_owned(),
        "bool" => "Bool".to_owned(),
        "char" => "Char".to_owned(),
        _ => e.to_owned(),
    }
}

/// Classify a raw Rust type as an Ipê-coercible sequence (mirrors the
/// inspector's gate). `None` for `&mut [T]` and non-coercible elements.
fn seq_kind(raw: &str) -> Option<SeqKind> {
    let s = raw.trim();
    if s.starts_with("&mut ") {
        return None;
    }
    match s {
        "&[u8]" => {
            return Some(SeqKind {
                shape: SeqShape::Slice,
                elem: SeqElem::U8,
            });
        }
        "Vec<u8>" => {
            return Some(SeqKind {
                shape: SeqShape::Owned,
                elem: SeqElem::U8,
            });
        }
        _ => {}
    }
    if let Some(rest) = s.strip_prefix("&[u8; ")
        && let Some(n) = digits_before_close(rest)
    {
        return Some(SeqKind {
            shape: SeqShape::RefArr(n),
            elem: SeqElem::U8,
        });
    }
    if let Some(rest) = s.strip_prefix("[u8; ")
        && let Some(n) = digits_before_close(rest)
    {
        return Some(SeqKind {
            shape: SeqShape::Arr(n),
            elem: SeqElem::U8,
        });
    }
    seq_kind_general(s)
}

fn seq_kind_general(s: &str) -> Option<SeqKind> {
    let admit = |shape: SeqShape, e: &str| -> Option<SeqKind> {
        let t = e.trim();
        is_coercible_elem(t).then(|| SeqKind {
            shape,
            elem: SeqElem::General {
                rust: t.to_owned(),
                ipe: ipe_of_elem(t),
            },
        })
    };
    if let Some(rest) = s.strip_prefix("Vec<") {
        return rest
            .strip_suffix('>')
            .and_then(|e| admit(SeqShape::Owned, e));
    }
    if let Some(rest) = s.strip_prefix("&[") {
        let inner = rest.strip_suffix(']')?;
        return match inner.split_once(';') {
            Some((e, n)) => parse_array_len(n).and_then(|k| admit(SeqShape::RefArr(k), e)),
            None => admit(SeqShape::Slice, inner),
        };
    }
    if let Some(rest) = s.strip_prefix('[') {
        let inner = rest.strip_suffix(']')?;
        return match inner.split_once(';') {
            Some((e, n)) => parse_array_len(n).and_then(|k| admit(SeqShape::Arr(k), e)),
            None => None,
        };
    }
    None
}

// ── return-type translation ─────────────────────────────────────────────────

/// Translate a raw Rust (Ok-)type into the wrapper's declared inner return
/// type plus the coercion lifting an expression of the raw type into it.
///
/// Driven by the inspector's real Rust type — the source of truth for opaque
/// types — never the lossy Ipê type.
#[must_use]
pub fn translate_rust_ret(raw0: &str) -> (String, RetCoercion) {
    let raw = raw0.trim().to_owned();
    if raw.is_empty() || raw == "()" {
        return ("()".to_owned(), identity_coercion());
    }
    if let Some(comps) = tuple_components(&raw) {
        return translate_tuple_ret(&comps);
    }
    if let Some(sk) = seq_kind(&raw) {
        return translate_seq_ret(&sk);
    }
    if let Some(inner) = strip_generic1("Option", &raw) {
        let (dt, co) = translate_rust_ret(inner);
        let just = co("v");
        return (
            format!("IpeMaybe<{dt}>"),
            Box::new(move |e| {
                format!(
                    "match {e} {{ Some(v) => IpeMaybe::Just({just}), None => IpeMaybe::Nothing }}"
                )
            }),
        );
    }
    if let Some(inner) = strip_generic1("Vec", &raw) {
        let (dt, co) = translate_rust_ret(inner);
        let mapped = co("x");
        return (
            format!("Vec<{dt}>"),
            Box::new(move |e| {
                if mapped == "x" {
                    e.to_owned()
                } else {
                    format!("{e}.into_iter().map(|x| {mapped}).collect()")
                }
            }),
        );
    }
    if let Some(probe) = num_widen_scalar(&raw, "x") {
        let carrier = probe.carrier.to_owned();
        return (
            carrier,
            Box::new(move |e| num_widen_scalar(&raw, e).map_or_else(|| e.to_owned(), |w| w.expr)),
        );
    }
    if raw == "bool" || raw == "String" {
        return (raw, identity_coercion());
    }
    // A serde-bound return reduced to Value travels to Ipê as JSON text.
    // `to_string` on a Value is total; empty string is the safe floor for the
    // impossible failure.
    if raw == "serde_json::Value" {
        return (
            "String".to_owned(),
            Box::new(|e| format!("serde_json::to_string(&({e})).unwrap_or_default()")),
        );
    }
    if raw.starts_with('&') {
        let inner = strip_ref(&raw).to_owned();
        if inner == "str" || inner == "String" {
            return (
                "String".to_owned(),
                Box::new(|e| format!("{e}.to_string()")),
            );
        }
        let (dt, _) = translate_rust_ret(&inner);
        return (dt, Box::new(|e| format!("{e}.to_owned()")));
    }
    (raw, identity_coercion())
}

fn translate_seq_ret(sk: &SeqKind) -> (String, RetCoercion) {
    match &sk.elem {
        SeqElem::U8 => {
            // Owned/plain-array values are borrowed into the helper;
            // slice/ref-array values already are references.
            let borrow = matches!(sk.shape, SeqShape::Owned | SeqShape::Arr(_));
            (
                "Vec<i64>".to_owned(),
                Box::new(move |e| {
                    if borrow {
                        format!("from_u8_slice(&{e})")
                    } else {
                        format!("from_u8_slice({e})")
                    }
                }),
            )
        }
        SeqElem::General { rust, .. } => {
            let (elem_decl, elem_co) = translate_rust_ret(rust);
            let decl = format!("Vec<{elem_decl}>");
            if elem_decl == *rust {
                // Element maps to itself: owned is identity, borrowed clones.
                let owned = matches!(sk.shape, SeqShape::Owned);
                return (
                    decl,
                    Box::new(move |e| {
                        if owned {
                            e.to_owned()
                        } else {
                            format!("{e}.to_vec()")
                        }
                    }),
                );
            }
            // Per-element scalar coercion; slice/ref-array elements arrive as
            // `&T` — `|&x|` copies them out (all such elements are Copy).
            let by_value = matches!(sk.shape, SeqShape::Owned | SeqShape::Arr(_));
            let mapped = elem_co("x");
            (
                decl,
                Box::new(move |e| {
                    if by_value {
                        format!("{e}.into_iter().map(|x| {mapped}).collect::<Vec<_>>()")
                    } else {
                        format!("{e}.iter().map(|&x| {mapped}).collect::<Vec<_>>()")
                    }
                }),
            )
        }
    }
}

/// Split a Rust tuple type (`(A, B, ..)`) into its top-level component types,
/// respecting nested `<>`/`()` so `(u64, Result<T, E>)` yields two parts. A
/// non-tuple, the unit `()`, or a single-element `(T,)`/`(T)` group returns
/// `None` — only a genuine 2+-arity tuple is a multi-result carrier here.
fn tuple_components(raw: &str) -> Option<Vec<String>> {
    let t = raw.trim();
    let inner = t.strip_prefix('(')?.strip_suffix(')')?;
    // Reject a balanced-but-non-tuple parse like `(A, B) -> C` where the outer
    // parens do not wrap the whole type: the strip above only removes the first
    // `(` and last `)`, so verify the remaining depth never dips to zero early.
    let mut depth = 0_i32;
    let mut parts: Vec<String> = Vec::new();
    let mut start = 0usize;
    for (i, c) in inner.char_indices() {
        match c {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => {
                if depth == 0 {
                    return None; // unbalanced — the outer parens were not a wrapper
                }
                depth -= 1;
            }
            ',' if depth == 0 => {
                parts.push(inner.get(start..i).unwrap_or("").trim().to_owned());
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    let tail = inner.get(start..).unwrap_or("").trim();
    if !tail.is_empty() {
        parts.push(tail.to_owned());
    }
    // A 1-tuple `(T,)` leaves a trailing empty part that we skipped, so a single
    // real component means "not a multi-result tuple" — leave it to the scalar
    // paths. Only 2+ components are the multi-result shape.
    if parts.len() < 2 { None } else { Some(parts) }
}

/// Translate a multi-result Rust tuple into its wrapper-declared inner type and
/// a coercion that destructures the raw tuple and coerces each component. Each
/// component rides its own [`translate_rust_ret`], so a `(u64, u32)` becomes
/// `(i64, i64)` with per-slot saturating widening — matching the `(Int, Int)`
/// the Ipê signature declares.
fn translate_tuple_ret(comps: &[String]) -> (String, RetCoercion) {
    let mut decls: Vec<String> = Vec::with_capacity(comps.len());
    let mut coercers: Vec<RetCoercion> = Vec::with_capacity(comps.len());
    for c in comps {
        let (d, co) = translate_rust_ret(c);
        decls.push(d);
        coercers.push(co);
    }
    let decl = format!("({})", decls.join(", "));
    (
        decl,
        Box::new(move |e| {
            let binders: Vec<String> = (0..coercers.len()).map(|i| format!("t{i}")).collect();
            let coerced: Vec<String> = coercers
                .iter()
                .enumerate()
                .map(|(i, co)| co(&format!("t{i}")))
                .collect();
            format!(
                "{{ let ({}) = {e}; ({}) }}",
                binders.join(", "),
                coerced.join(", ")
            )
        }),
    )
}

/// The raw Rust Ok-type a binding's result carries, with the fallible/effectful
/// `Result<Ok, E>` layer peeled. Mirrors [`WrapperCx::effective_raw_result`] +
/// the Ok-peel so the interface admission gate reasons over the exact type the
/// wrapper body will coerce.
fn effective_ok_raw(f: &FnInfo) -> String {
    let raw = f.results().first().map_or("", Param::rust_type_str);
    let base = if raw.is_empty() {
        let ipe = f
            .results()
            .first()
            .map_or_else(|| "()".to_owned(), |r| foreign_to_ipe(&r.foreign_ty));
        ipe_type_to_rust(&ipe)
    } else {
        raw.to_owned()
    };
    match f.effect() {
        Effect::Fallible | Effect::Effectful => ok_type_of_result(&base),
        Effect::Pure => base,
    }
}

/// The Ipê carrier surface a soundly-coercible tuple component presents, or
/// [`None`] when the component is not one the tuple emitter can coerce.
///
/// The admissible set is exactly the components [`translate_rust_ret`] lifts
/// TOTALLY and OWNED with no lifetime/opaque wiring: every numeric width (a
/// saturating widen into `Int`/`Float`), owned `String` (identity), and `bool`
/// (identity). The `String`/`bool` match is EXACT — a `&str`/`&String` borrow
/// renders with a leading `&` and never as bare `String`, and a `Vec`/`Option`/
/// opaque/serde component never spells `String` or `bool` — so an exact compare
/// is what fails those closed.
fn tuple_component_carrier(c: &str) -> Option<&'static str> {
    let t = c.trim();
    match t {
        "String" => Some("String"),
        "bool" => Some("Bool"),
        "f32" | "f64" => Some("Float"),
        _ if is_numeric_rust(t) => Some("Int"),
        _ => None,
    }
}

/// Whether a binding's result is a multi-result tuple every component of which
/// the wrapper can soundly coerce — the admission predicate for the interface
/// tuple gate.
///
/// Two conditions must BOTH hold, or the tuple over-drops (fail closed):
///
/// * every Rust component is one [`tuple_component_carrier`] admits — a numeric
///   scalar (a total saturating widen into its `Int`/`Float` carrier), owned
///   `String`, or `bool` (each an identity coercion). A `&`-borrow, an opaque
///   handle, a nested container, or a serde value is NOT wired in the tuple
///   emitter, so it stays refused;
/// * the Ipê-side type the signature will DECLARE — the inspector's `ipe_type`
///   override on the result — is a present, same-arity tuple whose i-th head is
///   exactly the carrier the i-th Rust component coerces to. `foreign_to_ipe`
///   does NOT recurse into a tuple string, so without a matching override the
///   signature would carry the raw `(u64, String)` the backend cannot lower (an
///   `ipe`-exit-0 ⇒ cargo-fail SEAL breach). Requiring the override to agree
///   with the emitted Rust carriers makes that mismatch unrepresentable.
#[must_use]
pub fn multi_result_tuple_is_coercible(f: &FnInfo) -> bool {
    // A self-returning setter or a borrow-reader threads a handle, handled by
    // their own gates — this predicate is only for the plain multi-result case.
    if f.self_returning() || f.is_borrow_reader() {
        return false;
    }
    let raw = effective_ok_raw(f);
    let Some(comps) = tuple_components(&raw) else {
        return false;
    };
    let Some(carriers) = comps
        .iter()
        .map(|c| tuple_component_carrier(c))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    // The signature's tuple type is what `wrapper_ipe_signature` will DECLARE for
    // the sole non-error result — the inspector's `ipe_type` override, or the
    // `foreign_to_ipe` fallback (which does NOT recurse into a tuple string, so a
    // tuple survives only when it was already spelled in Ipê carriers). Read it
    // through the SAME `param_ipe_type` the emitter uses so the gate and the
    // signature cannot drift, then refuse unless it is a same-arity tuple whose
    // heads match the emitted Rust carriers exactly. Without this the signature
    // could carry the raw `(u64, String)` the backend cannot lower — an
    // `ipe`-exit-0 ⇒ cargo-fail SEAL breach.
    let non_err: Vec<&Param> = f
        .results()
        .iter()
        .filter(|r| r.foreign_ty != "error")
        .collect();
    let [single] = non_err.as_slice() else {
        return false;
    };
    ipe_tuple_heads(&crate::emit::param_ipe_type(single)).is_some_and(|heads| heads == carriers)
}

/// The top-level component heads of an Ipê tuple type string (`(Int, String)` →
/// `["Int", "String"]`), or [`None`] when the string is not a parenthesised
/// tuple of bare (single-token) component heads.
///
/// Only a flat tuple of bare heads is recognised — a nested container component
/// (`(Int, List String)`) yields `None`, which fails the admission gate, exactly
/// as the tuple emitter (which admits no container component) requires.
fn ipe_tuple_heads(sig: &str) -> Option<Vec<&'static str>> {
    let t = sig.trim();
    let inner = t.strip_prefix('(')?.strip_suffix(')')?;
    let mut heads: Vec<&'static str> = Vec::new();
    for part in inner.split(',') {
        let head = match part.trim() {
            "Int" => "Int",
            "Float" => "Float",
            "Bool" => "Bool",
            "String" => "String",
            _ => return None,
        };
        heads.push(head);
    }
    if heads.len() < 2 { None } else { Some(heads) }
}

// ── per-function wrapper context ────────────────────────────────────────────

/// Everything the per-shape emitters share for one binding, computed once.
struct WrapperCx<'a> {
    krate: &'a str,
    f: &'a FnInfo,
    /// `{kernel}_{ref_name}` — the human-facing label in the region comment.
    label: String,
    /// The emitted `pub fn` identifier.
    rust_name: String,
    /// Per-param raw Rust types (the inspector's `rustType` tier).
    raw_param_types: Vec<String>,
    /// Declared wrapper param types (own-ref params already de-borrowed).
    param_types: Vec<String>,
    /// Param slots declared owned whose call site re-borrows (`&argN`).
    own_ref_idx: Vec<usize>,
    is_instance: bool,
    is_static: bool,
    is_display_bridge: bool,
}

impl<'a> WrapperCx<'a> {
    fn new(krate: &'a str, kernel_name: &str, f: &'a FnInfo) -> Self {
        let ref_name = f.wrapper_ref_name();
        let surface_types: Vec<String> = f.params().iter().map(param_ipe_type).collect();
        let raw_param_types: Vec<String> = f
            .params()
            .iter()
            .map(|p| p.rust_type_str().to_owned())
            .collect();
        let declared_raw: Vec<String> = surface_types
            .iter()
            .enumerate()
            .map(|(j, st)| {
                let rt = raw_param_types.get(j).map_or("", String::as_str);
                resolve_rust_type(krate, st, rt)
            })
            .collect();
        let is_instance = !f.recv_type().is_empty()
            && !f.method_name().is_empty()
            && f.params().first().is_some_and(|p| p.name == "self");
        let is_static = !f.recv_type().is_empty() && !f.method_name().is_empty() && !is_instance;
        let is_display_bridge = f.method_name() == "to_string" && is_instance;
        // Opaque borrow param → own-by-value (async `'static` escape, or a
        // mono-produced owned Ipê surface behind a `&C` wrapper param); the
        // call site re-borrows.
        let own_ref_idx: Vec<usize> = declared_raw
            .iter()
            .enumerate()
            .filter(|&(j, t)| {
                is_own_ref_ty(t)
                    && (f.effect() == Effect::Effectful || {
                        let s = surface_types.get(j).map_or("", String::as_str);
                        !s.is_empty() && !s.starts_with('&') && !is_known_ipe(s)
                    })
            })
            .map(|(j, _)| j)
            .collect();
        let param_types: Vec<String> = declared_raw
            .iter()
            .enumerate()
            .map(|(j, t)| {
                if own_ref_idx.contains(&j) {
                    t.get(1..).unwrap_or("").trim().to_owned()
                } else {
                    t.clone()
                }
            })
            .collect();
        Self {
            krate,
            f,
            label: format!("{kernel_name}_{ref_name}"),
            rust_name: wrapper_fn_ident(kernel_name, &ref_name),
            raw_param_types,
            param_types,
            own_ref_idx,
            is_instance,
            is_static,
            is_display_bridge,
        }
    }

    fn n_params(&self) -> usize {
        self.f.params().len()
    }

    fn raw_param(&self, j: usize) -> &str {
        self.raw_param_types.get(j).map_or("", String::as_str)
    }

    fn decl_param(&self, j: usize) -> &str {
        self.param_types.get(j).map_or("", String::as_str)
    }

    /// The declared wrapper parameter list. The instance receiver is bound
    /// `mut` so `&mut self` methods auto-ref (`#![allow(unused_mut)]`
    /// silences the no-op case); a Display bridge takes `impl Display`.
    fn param_decl(&self) -> String {
        if self.is_display_bridge {
            return "arg0: impl std::fmt::Display".to_owned();
        }
        if self.param_types.is_empty() {
            return "_: ()".to_owned();
        }
        let decls: Vec<String> = self
            .param_types
            .iter()
            .enumerate()
            .map(|(j, t)| {
                if j == 0 && self.is_instance {
                    format!("mut arg0: {t}")
                } else {
                    format!("{}: {t}", arg_name(j))
                }
            })
            .collect();
        decls.join(", ")
    }

    /// Shape-aware argument coercion at the call site.
    fn arg_call(&self, j: usize) -> String {
        let base = arg_name(j);
        if self.own_ref_idx.contains(&j) {
            return format!("&{base}");
        }
        let raw_ty = self.raw_param(j);
        let decl_ty = self.decl_param(j);
        if let Some(sk) = seq_kind(raw_ty) {
            return match (sk.shape, &sk.elem) {
                (SeqShape::Slice, SeqElem::U8) => format!("&to_u8_vec(&{base})"),
                (SeqShape::Owned, SeqElem::U8) => format!("to_u8_vec(&{base})"),
                (SeqShape::Arr(_), _) => format!("b{j}"),
                (SeqShape::RefArr(_), _) => format!("&b{j}"),
                (SeqShape::Slice, SeqElem::General { .. }) => format!("{base}.as_slice()"),
                (SeqShape::Owned, SeqElem::General { .. }) => base,
            };
        }
        if let Some(inner) = strip_generic1("Option", raw_ty) {
            // The wrapper takes IpeMaybe<declInner>; adapt the inner value to
            // the foreign Option<rawInner>.
            let opt = format!("ipe_maybe_to_option({base})");
            return match inner {
                "&str" => format!("{opt}.as_deref()"),
                "&String" => format!("{opt}.as_ref()"),
                _ if is_numeric_rust(inner) => {
                    format!("{opt}.map(|x| {})", num_saturate(inner, "x"))
                }
                _ if inner.starts_with('&') => format!("{opt}.as_ref()"),
                _ => opt,
            };
        }
        // A serde-bound param names the deserialised local the prelude binds.
        if raw_ty == "serde_json::Value" && decl_ty == "String" {
            return format!("sv_{j}");
        }
        if decl_ty == "String" && (raw_ty == "String" || raw_ty == "str") {
            // Owned by value. A BARE `str` raw can only be a conversion/
            // generic-bound substitute (an unsized by-value `str` param is
            // unrepresentable in a real signature): the host param is generic
            // (`impl Into<Id>` / `impl AsRef<str>` / `impl Display`), so the
            // owned `String` satisfies the bound where a `&String` would not
            // (`String: Into<Id>` via `Id: From<String>`; no such impl for
            // `&String`).
            return base;
        }
        if decl_ty == "String" && raw_ty == "&str" {
            return format!("{base}.as_ref()"); // &str/&Path/&OsStr via AsRef
        }
        if decl_ty == "String" {
            return format!("&{base}"); // borrowed &String
        }
        if raw_ty.is_empty() || raw_ty == decl_ty {
            return base;
        }
        if is_numeric_rust(raw_ty) && (decl_ty == "i64" || decl_ty == "f64") {
            return num_saturate(raw_ty, &base);
        }
        base
    }

    fn call_args(&self, from: usize) -> String {
        let args: Vec<String> = (from..self.n_params()).map(|j| self.arg_call(j)).collect();
        args.join(", ")
    }

    /// The declared inner return type + the coercion into it, from the raw
    /// Rust result (falling back to the Ipê mapping for synthetic bridges).
    fn effective_raw_result(&self) -> String {
        let raw = self.f.results().first().map_or("", Param::rust_type_str);
        if raw.is_empty() {
            let ipe = self
                .f
                .results()
                .first()
                .map_or_else(|| "()".to_owned(), |r| foreign_to_ipe(&r.foreign_ty));
            ipe_type_to_rust(&ipe)
        } else {
            raw.to_owned()
        }
    }

    fn ret_inner_and_coerce(&self) -> (String, RetCoercion) {
        if self.f.self_returning() {
            // Owned-threading setter: the wrapper returns the receiver by
            // value; the raw `&mut Self`/`()` return is discarded in the body.
            let t = self
                .param_types
                .first()
                .cloned()
                .unwrap_or_else(|| "()".to_owned());
            return (t, identity_coercion());
        }
        let eff_raw = self.effective_raw_result();
        // Fallible AND effectful both unwrap the Result's Ok type — the body
        // binds the unwrapped Ok value, so the inner type is the Ok type.
        let (t, co) = match self.f.effect() {
            Effect::Fallible | Effect::Effectful => {
                translate_rust_ret(&ok_type_of_result(&eff_raw))
            }
            Effect::Pure => translate_rust_ret(&eff_raw),
        };
        (absolutize_crate(self.krate, &t), co)
    }

    fn resolve_recv(&self) -> String {
        resolve_rust_type(self.krate, self.f.recv_type(), self.f.recv_rust_type())
    }

    /// The foreign call expression (instance / static / bridge / free forms).
    fn call_expr(&self) -> String {
        let fn_name = rust_safe_ident(self.f.name());
        // A serde-reduced generic return needs the explicit turbofish or Rust
        // cannot infer the reduced `T` (E0283).
        let serde_turbofish = if self.effective_raw_result() == "serde_json::Value" {
            "::<serde_json::Value>"
        } else {
            ""
        };
        if self.is_instance {
            return format!("arg0.{fn_name}{serde_turbofish}({})", self.call_args(1));
        }
        if self.is_static && self.f.name() == "from_string" {
            // The Display/FromStr bridge renders UFCS.
            return format!(
                "<{} as std::str::FromStr>::from_str({})",
                self.resolve_recv(),
                self.call_args(0)
            );
        }
        if self.is_static {
            let recv = self.resolve_recv();
            // Turbofish-wrap a generic receiver so `Type<Param>::fn` is not
            // parsed as chained comparisons.
            let recv = if recv.contains('<') {
                format!("<{recv}>")
            } else {
                recv
            };
            return format!("{recv}::{fn_name}{serde_turbofish}({})", self.call_args(0));
        }
        // Free fn: absolute `::<crate>` path; a submodule fn uses its full
        // crate-relative call path.
        let call_target = if self.f.call_path().is_empty() {
            fn_name
        } else {
            self.f.call_path().to_owned()
        };
        format!(
            "::{}::{call_target}{serde_turbofish}({})",
            self.krate,
            self.call_args(0)
        )
    }

    /// Fixed-array params bind fallible conversions to `bN` locals; a length
    /// mismatch early-returns `Err` (no panic).
    fn arr_prelude(&self) -> Vec<String> {
        (0..self.n_params())
            .filter_map(|j| {
                let sk = seq_kind(self.raw_param(j))?;
                let n = match sk.shape {
                    SeqShape::Arr(n) | SeqShape::RefArr(n) => n,
                    SeqShape::Slice | SeqShape::Owned => return None,
                };
                Some(match sk.elem {
                    SeqElem::U8 => format!(
                        "let b{j}: [u8; {n}] = match to_u8_array::<IpeError, {n}>(&arg{j}) \
                         {{ IpeResult::Ok(a) => a, IpeResult::Err(e) => return IpeResult::Err(e), }};"
                    ),
                    SeqElem::General { rust, .. } => format!(
                        "let b{j}: [{rust}; {n}] = match to_array::<IpeError, {rust}, {n}>(&arg{j}) \
                         {{ IpeResult::Ok(a) => a, IpeResult::Err(e) => return IpeResult::Err(e), }};"
                    ),
                })
            })
            .collect()
    }

    /// Serde-bound params (`serde_json::Value` foreign type behind a `String`
    /// wrapper param) deserialise before the call, early-returning `Err` on
    /// malformed JSON. A `Value`-handle param (wrapper already takes `Value`)
    /// gets no prelude and passes through.
    fn serde_prelude(&self) -> Vec<String> {
        (0..self.n_params())
            .filter(|&j| self.raw_param(j) == "serde_json::Value" && self.decl_param(j) == "String")
            .map(|j| {
                format!(
                    "let sv_{j}: serde_json::Value = match \
                     serde_json::from_str::<serde_json::Value>(&arg{j}) \
                     {{ Ok(v) => v, Err(e) => return IpeResult::Err(ipe_error_from_foreign(e)), }};"
                )
            })
            .collect()
    }
}

/// Opaque borrow shape eligible for own-by-value declaration: `&T` where `T`
/// is not `str`/`String`/another borrow/a slice.
fn is_own_ref_ty(t: &str) -> bool {
    if !t.starts_with('&') || t.starts_with("&mut ") {
        return false;
    }
    let rest = t.get(1..).unwrap_or("").trim();
    rest != "str"
        && rest != "String"
        && !rest.starts_with('&')
        && !rest.starts_with('[')
        && !rest.is_empty()
}

/// Methods/statics on a receiver with an unresolved generic type parameter
/// (`DateTime<Tz>`) cannot be wrapped concretely — loose heuristic: `<` then
/// an uppercase char then `,`/`>`/end or a ≤2-char lowercase tail.
fn has_generic_recv_param(recv_rust_type: &str, is_display_bridge: bool) -> bool {
    if is_display_bridge {
        return false;
    }
    let Some(pos) = recv_rust_type.find('<') else {
        return false;
    };
    let after = recv_rust_type.get(pos + 1..).unwrap_or("");
    let mut cs = after.chars();
    let Some(c) = cs.next() else {
        return false;
    };
    let rest = cs.as_str();
    c.is_uppercase()
        && (rest.is_empty()
            || rest.starts_with(',')
            || rest.starts_with('>')
            || (rest.chars().next().is_some_and(char::is_lowercase) && rest.chars().count() <= 2))
}

// ── the emitter ─────────────────────────────────────────────────────────────

/// Emit the `<crate>_bindings.rs` wrapper module for one crate.
#[must_use]
pub fn emit_bindings(pkg: &PkgInfo) -> String {
    let kernel = rust_kernel_name(pkg.pkg_path());
    let krate = pkg_to_crate_import(pkg.pkg_path());
    let mut lines: Vec<String> = vec![
        format!(
            "// Code generated by ipe-ffi-inspector from {}. DO NOT EDIT.",
            pkg.pkg_path()
        ),
        format!("// Re-run `ipe add {}` to regenerate.", pkg.pkg_path()),
        String::new(),
        "#![allow(unused_imports, unused_mut, dead_code)]".to_owned(),
        String::new(),
        "// The catch_unwind boundary converts a foreign panic into a typed Err;".to_owned(),
        "// that conversion is sound only under panic=unwind, so refuse to build".to_owned(),
        "// under any configuration that selects panic=abort.".to_owned(),
        "#[cfg(panic = \"abort\")]".to_owned(),
        "compile_error!(\"ipe_ffi catch_unwind boundary requires panic=unwind\");".to_owned(),
        String::new(),
        "use crate::*;".to_owned(),
        "use std::collections::HashMap;".to_owned(),
        String::new(),
    ];
    let opaques = OpaqueResolver::from_pkg(pkg);
    for f in pkg.fns() {
        lines.extend(emit_fn_region(&krate, &kernel, f, &opaques));
    }
    lines.push(String::new());
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// The `wrapper_ref_name` set whose wrapper regions [`emit_bindings`] emits.
///
/// The survivor gate the interface emitter keys off. Runs the SAME region
/// emitter, so it cannot drift from the emitted text.
#[must_use]
pub fn surviving_ref_names(pkg: &PkgInfo) -> std::collections::BTreeSet<String> {
    let kernel = rust_kernel_name(pkg.pkg_path());
    let krate = pkg_to_crate_import(pkg.pkg_path());
    let opaques = OpaqueResolver::from_pkg(pkg);
    pkg.fns()
        .iter()
        .filter(|f| !emit_fn_region(&krate, &kernel, f, &opaques).is_empty())
        .map(super::pkginfo::FnInfo::wrapper_ref_name)
        .collect()
}

/// The synthesised wrapper for a closed (zero-type-param) generic instance,
/// or empty when the binding is not one / the synthesiser drops it.
fn closed_instance_lines(kernel_name: &str, f: &FnInfo) -> Vec<String> {
    let closed = f.generic().is_some_and(|g| g.params.is_empty());
    if !closed {
        return Vec::new();
    }
    match crate::instance::synthesise_generic_wrapper(kernel_name, f) {
        Some(crate::instance::WrapperResult::Emitted(w)) => {
            w.source.lines().map(str::to_owned).collect()
        }
        // A rejection on a closed instance is an over-drop at add time: the
        // binding is simply absent (no call site exists yet to blame).
        _ => Vec::new(),
    }
}

/// One binding's sentinel-bracketed wrapper region; empty when the binding is
/// dropped (degenerate method / unresolved-generic receiver / trait fn).
fn emit_fn_region(
    krate: &str,
    kernel_name: &str,
    f: &FnInfo,
    opaques: &OpaqueResolver,
) -> Vec<String> {
    let cx = WrapperCx::new(krate, kernel_name, f);
    let body = match f.shape() {
        FnShape::EnumCtor {
            variant,
            kind,
            struct_fields,
        } => enum_ctor_lines(&cx, variant.as_str(), *kind, struct_fields),
        FnShape::EnumTag { arms, wildcard } => enum_tag_lines(&cx, arms, *wildcard),
        FnShape::EnumExtract {
            variant,
            kind,
            selector,
            field_count,
            wildcard,
        } => enum_extract_lines(
            &cx,
            variant.as_str(),
            *kind,
            selector.as_str(),
            *field_count,
            *wildcard,
        ),
        FnShape::FieldGet => field_get_lines(&cx),
        FnShape::FieldSet => field_set_lines(&cx),
        FnShape::ClosureAdapter { sig } => closure_adapter_lines(&cx, sig, opaques),
        FnShape::StructCtor { def } => struct_ctor_lines(&cx, def, opaques),
        FnShape::EnumDefCtor { def } => enum_def_ctor_lines(&cx, def, opaques),
        FnShape::Plain | FnShape::PkgVar => plain_lines(&cx),
    };
    // A trait-qualified / turbofished binding with NO open type params is a
    // CLOSED instance — its one wrapper is fully determined at add time, so
    // it renders through the instance synthesiser (UFCS, serde reduction,
    // async spawn) into the same sentinel region the flat tier would own.
    // Open generics stay demand-driven at the call site.
    let body = if body.is_empty() {
        closed_instance_lines(kernel_name, f)
    } else {
        body
    };
    if body.is_empty() {
        return Vec::new();
    }
    let mut out = vec![crate::naming::wrapper_begin_sentinel(&f.wrapper_ref_name())];
    out.extend(body);
    out.push(crate::naming::WRAPPER_END_SENTINEL.to_owned());
    out
}

/// Resolves a `define.closure` carrier to the concrete owned Rust type the
/// emitted adapter names — the opaque-map threaded into the closure-adapter
/// emitter so an opaque return/param resolves to a path the wrapped `pub mod
/// <slug>` region can actually name.
///
/// An opaque handle in a `define.closure` signature is a BARE name (the author
/// writes `Fn(Model) -> Result<Element, E>`); resolving it soundly requires the
/// whole crate's type information, which a lone `ClosureSig` lacks. Three cases,
/// keyed only off the crate's inspected types + the author's own manifest — user
/// `.ipe` source never contributes:
///
/// * a name the crate's `[rust.define.struct/enum]` decls DEFINE resolves to
///   the BARE in-module name (the `pub struct`/`pub enum` lives in the same
///   `pub mod <slug>` region as the adapter, so a bare reference is in scope);
/// * an INSPECTED crate-opaque resolves to its absolute `::crate::path` (so it
///   can never fold onto a re-exported runtime kernel module);
/// * anything else — an unresolvable name, OR an opaque whose inspected type is
///   generic/lifetime-parameterised (`Element<'a, Message>`, whose stripped
///   path `::iced::Element` would be an E0107 arity error) — resolves to
///   [`None`], which OVER-DROPS the whole adapter (emit nothing, record a
///   coverage skip), never emit-and-cargo-fail.
///
/// The parameterised-opaque exclusion is why the marquee Iced `view : Model ->
/// Element Message` case stays refused: `Element` requires generic arguments the
/// bare-handle carrier cannot carry, so a sound emit is impossible and the
/// adapter over-drops rather than breach the SEAL.
struct OpaqueResolver {
    /// Bare opaque name → absolute `::crate::path` (inspected crate types only).
    inspected: std::collections::BTreeMap<String, String>,
    /// Bare names the crate's own `define.struct/enum` decls DEFINE **and whose
    /// own definition survives** — i.e. every opaque field/payload it holds is
    /// itself resolvable, computed to a fixed point. A define type absent here
    /// either is not defined or over-dropped (its own definition emits nothing),
    /// so a reference to it must over-drop too — otherwise the referencing
    /// definition would name a `pub struct`/`pub enum` that was never emitted (an
    /// E0425 the SEAL forbids).
    define_defined: BTreeSet<String>,
    /// Bare base names that appear generic/lifetime-parameterised (`Base<…>`)
    /// anywhere in the crate's inspected type strings — unsound to emit as a
    /// bare-arg path, so they over-drop.
    parameterised: BTreeSet<String>,
}

impl OpaqueResolver {
    /// Build the resolver purely from the package, so every `emit_bindings`
    /// call site derives the SAME map from the SAME `PkgInfo` (the warm-load
    /// byte-identical SEAL holds by construction — no per-site input to drift).
    fn from_pkg(pkg: &PkgInfo) -> Self {
        let mut inspected: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        let mut poisoned: BTreeSet<String> = BTreeSet::new();
        let mut parameterised: BTreeSet<String> = BTreeSet::new();
        // Every define-defined name → the opaque handles its own definition
        // holds (its fields/payloads). A def survives only when EVERY one of
        // these resolves, so this drives the survivor fixed point below.
        let mut define_opaque_deps: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        let mut visit = |raw: &str| {
            note_parameterised_bases(raw, &mut parameterised);
            for (base, path) in opaque_path_tokens(raw) {
                match inspected.get(&base) {
                    Some(prev) if *prev != path => {
                        poisoned.insert(base);
                    }
                    Some(_) => {}
                    None => {
                        inspected.insert(base, path);
                    }
                }
            }
        };
        for f in pkg.fns() {
            visit(f.recv_rust_type());
            for p in f.params().iter().chain(f.results().iter()) {
                visit(p.rust_type_str());
                visit(&p.foreign_ty);
            }
            match f.shape() {
                FnShape::StructCtor { def } => {
                    define_opaque_deps
                        .insert(def.name.as_str().to_owned(), struct_opaque_deps(def));
                }
                FnShape::EnumDefCtor { def } => {
                    define_opaque_deps.insert(def.name.as_str().to_owned(), enum_opaque_deps(def));
                }
                _ => {}
            }
        }
        // A name claimed by two distinct paths is genuinely ambiguous — drop it
        // so it resolves to `None` (over-drop), never an arbitrary wrong path.
        for name in &poisoned {
            inspected.remove(name);
        }
        let define_defined = surviving_define_defs(&define_opaque_deps, &inspected, &parameterised);
        Self {
            inspected,
            define_defined,
            parameterised,
        }
    }

    /// The owned Rust type this carrier lowers to in the emitted adapter, or
    /// [`None`] when an opaque carrier is unresolvable / parameterised (the
    /// signal to over-drop the whole adapter). A scalar always resolves.
    fn carrier_ty(&self, c: &Carrier) -> Option<String> {
        match c {
            Carrier::Opaque(id) => {
                let name = id.as_str();
                if self.parameterised.contains(name) {
                    return None;
                }
                if self.define_defined.contains(name) {
                    // Same-module `pub struct`/`pub enum` whose own definition
                    // SURVIVES: the bare name is in scope inside `pub mod <slug>`.
                    // A define name that over-dropped is absent from the set, so
                    // it falls through to `inspected` (empty for a pure define
                    // type) and returns `None` — the reference over-drops too.
                    return Some(name.to_owned());
                }
                self.inspected.get(name).cloned()
            }
            _ => Some(c.rust_owned().to_owned()),
        }
    }
}

/// The opaque handle names a `define.struct`'s fields hold (bare identifiers,
/// possibly other define types) — the dependency edges for the survivor fixed
/// point.
fn struct_opaque_deps(def: &StructDef) -> Vec<String> {
    def.fields
        .iter()
        .filter_map(|(_, c)| match c {
            Carrier::Opaque(id) => Some(id.as_str().to_owned()),
            _ => None,
        })
        .collect()
}

/// The opaque handle names a `define.enum`'s variant payloads hold.
fn enum_opaque_deps(def: &EnumDef) -> Vec<String> {
    def.variants
        .iter()
        .flat_map(|v| {
            v.payload.iter().filter_map(|c| match c {
                Carrier::Opaque(id) => Some(id.as_str().to_owned()),
                _ => None,
            })
        })
        .collect()
}

/// The set of define-defined names whose own definition SURVIVES emission,
/// computed to a fixed point.
///
/// A define def survives iff every opaque handle it holds resolves: an inspected
/// crate-opaque (a known `::crate::path`), or ANOTHER define-defined name that is
/// ITSELF surviving. A parameterised handle never resolves; a bare handle that is
/// neither inspected nor a surviving define type never resolves. Because a
/// dependency A→B→… can only ever REMOVE survivors, the fixpoint is monotone
/// decreasing from "all defined" and terminates in at most `defs.len()` passes.
fn surviving_define_defs(
    deps: &std::collections::BTreeMap<String, Vec<String>>,
    inspected: &std::collections::BTreeMap<String, String>,
    parameterised: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut surviving: BTreeSet<String> = deps.keys().cloned().collect();
    loop {
        let mut dropped: Vec<String> = Vec::new();
        for (name, handles) in deps {
            if !surviving.contains(name) {
                continue;
            }
            let all_resolve = handles.iter().all(|h| {
                !parameterised.contains(h) && (inspected.contains_key(h) || surviving.contains(h))
            });
            if !all_resolve {
                dropped.push(name.clone());
            }
        }
        if dropped.is_empty() {
            return surviving;
        }
        for name in dropped {
            surviving.remove(&name);
        }
    }
}

/// Record every base name that appears generic/lifetime-parameterised
/// (`Base<…>`) in a raw Rust type string, so the closure-adapter resolver can
/// over-drop it (a bare-arg path would be an E0107). A base is "parameterised"
/// iff a capitalised identifier is immediately followed by `<`.
fn note_parameterised_bases(raw: &str, out: &mut BTreeSet<String>) {
    let mut token = String::new();
    let flush = |token: &mut String, next: Option<char>, out: &mut BTreeSet<String>| {
        if next == Some('<')
            && token.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            out.insert(std::mem::take(token));
        } else {
            token.clear();
        }
    };
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            token.push(c);
        } else {
            flush(&mut token, Some(c), out);
        }
    }
    flush(&mut token, None, out);
}

/// Extract every `seg::…::Base` opaque path token from a Rust type string,
/// returning `(Base, ::seg::…::Base)` pairs — the bindings-emitter twin of the
/// interface's path-map, so an opaque return/param resolves to the same
/// absolute path the interface's opaque-type map records. A bare identifier
/// (no `::`) carries no path and is skipped (a define-defined type, resolved
/// separately in-module).
///
/// Only the BARE base name keys the map: a closure signature's opaque carrier
/// is always a bare Rust identifier (`Element`, `Regex`), never the interface's
/// composite submodule head (`BytesRegex`), so — unlike the interface path-map —
/// no composite key is needed here. An unresolvable carrier over-drops, so the
/// worst case of this narrower keying is a conservative over-drop, never a
/// wrong path.
fn opaque_path_tokens(raw: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut Vec<(String, String)>| {
        if token.contains("::") {
            let normalized = if token.starts_with("::") {
                token.clone()
            } else {
                format!("::{token}")
            };
            if let Some(base) = normalized.rsplit("::").next()
                && !base.is_empty()
                && base.chars().next().is_some_and(char::is_uppercase)
            {
                out.push((base.to_owned(), normalized.clone()));
            }
        }
        token.clear();
    };
    for c in raw.chars() {
        if c.is_alphanumeric() || c == '_' || c == ':' {
            token.push(c);
        } else {
            flush(&mut token, &mut out);
        }
    }
    flush(&mut token, &mut out);
    out
}

/// The `[rust.define.closure]` adapter wrapper.
///
/// The wrapper takes an Ipê function value — already a
/// `Box<dyn Fn(A0, …) -> R + Send + Sync + 'static>` on the app side — and
/// returns a boxed Rust closure of the EXACT author-declared signature. The
/// captured Ipê value is moved into an `Arc` so the returned closure is
/// `Clone` for multi-call `Fn` re-entry.
///
/// Per-call soundness (design §3.3): each call re-enters the Ipê closure inside
/// `std::panic::catch_unwind` (the module-top `panic="abort"` fence makes that
/// sound). A `Total` (scalar-only) return has NO error channel, so a panic
/// `std::process::abort()`s — fabricating a `Default` would launder a real Ipê
/// panic into a silently-consumed wrong value. A `Result`/`Option` return folds
/// the panic in-band to `Err`/`None`.
///
/// Everything renders from the parsed [`ClosureSig`] — no raw manifest string
/// reaches this emitted Rust.
///
/// An opaque param or `Result`/`Option` return carrier resolves through the
/// crate [`OpaqueResolver`]; an unresolvable or parameterised opaque OVER-DROPS
/// the whole adapter (returns an empty region — no emit-and-cargo-fail), so an
/// `Element<'a, Message>`-shaped return stays refused rather than breach the
/// SEAL. The received `Box<dyn Fn …>` type and the returned one render from the
/// SAME resolved carriers, so their opaque paths can never disagree (an E0308
/// otherwise).
fn closure_adapter_lines(
    cx: &WrapperCx<'_>,
    sig: &ClosureSig,
    opaques: &OpaqueResolver,
) -> Vec<String> {
    // The crate-facing closure's parameter list and the Ipê closure's parameter
    // list are the SAME carriers in the sync P2 case — the Ipê fn's arguments
    // ARE the crate's arguments. Resolve every param carrier; a single
    // unresolvable/parameterised opaque over-drops the whole adapter.
    let mut param_tys: Vec<String> = Vec::with_capacity(sig.params.len());
    for c in &sig.params {
        let Some(ty) = opaques.carrier_ty(c) else {
            return Vec::new();
        };
        param_tys.push(ty);
    }
    // The return carrier, resolved through the same map so the returned box
    // type and the received box type agree. A `Total` return is scalar-only by
    // construction (an opaque total return is unrepresentable in `ClosureSig`),
    // so it never over-drops here.
    let Some(inner_ret) = (match &sig.ret {
        ClosureRet::Total(sc) => Some(sc.rust_owned().to_owned()),
        ClosureRet::Result(c)
        | ClosureRet::Option(c)
        | ClosureRet::AsyncResult(c)
        | ClosureRet::AsyncOption(c) => opaques.carrier_ty(c),
    }) else {
        return Vec::new();
    };
    let params: Vec<(String, String)> = param_tys
        .iter()
        .enumerate()
        .map(|(j, ty)| (arg_name(j), ty.clone()))
        .collect();
    let crate_param_decls: Vec<String> = params
        .iter()
        .map(|(name, ty)| format!("{name}: {ty}"))
        .collect();
    let forwarded: Vec<String> = params.iter().map(|(name, _)| name.clone()).collect();
    let forwarded_args = forwarded.join(", ");
    // The output the awaited work yields, for an async return — the fallible
    // carrier the future resolves to (`Result<T, IpeError>` / `Option<T>`).
    let async_output = match &sig.ret {
        ClosureRet::AsyncResult(_) => Some(format!("Result<{inner_ret}, IpeError>")),
        ClosureRet::AsyncOption(_) => Some(format!("Option<{inner_ret}>")),
        _ => None,
    };
    // The return type the crate closure yields (and the Ipê fn value produces).
    // An async return is the concrete boxed future the `IpeTask` value carries;
    // its inner `Send + 'static` is part of the type, so the received box IS the
    // Send/'static-across-await proof — the adapter never re-derives it.
    let crate_ret = match &sig.ret {
        ClosureRet::Total(_) => inner_ret,
        ClosureRet::Result(_) => format!("Result<{inner_ret}, IpeError>"),
        ClosureRet::Option(_) => format!("Option<{inner_ret}>"),
        ClosureRet::AsyncResult(_) | ClosureRet::AsyncOption(_) => format!(
            "::std::pin::Pin<Box<dyn ::std::future::Future<Output = {}> + Send + 'static>>",
            async_output.as_deref().unwrap_or("")
        ),
    };
    let bounds = sig.bounds.rust_suffix();
    let dyn_fn = |ret: &str| -> String {
        if bounds.is_empty() {
            format!("dyn Fn({}) -> {ret}", param_ty_list(&params))
        } else {
            format!("dyn Fn({}) -> {ret} + {bounds}", param_ty_list(&params))
        }
    };
    // The Ipê function value the wrapper receives has this exact box type — the
    // SAME resolved params + return the crate closure carries, so an opaque
    // path is identical on both sides (no E0308).
    let ipe_fn_ty = format!("Box<{}>", dyn_fn(&crate_ret));
    let out_ty = format!("Box<{}>", dyn_fn(&crate_ret));
    let wrapper = &cx.rust_name;
    // The opaque handle nominal the interface surfaces this adapter's boxed
    // closure as. Emitting the `type <Handle> = <out_ty>;` alias INSIDE this
    // region — the same `Vec` the survivor oracle observes — makes over-drop
    // atomic: the interface admits the forwarder only when this region emits, so
    // it can never reference a `<Handle>` alias that was not also emitted. The
    // alias and the returned box share `out_ty`, so their types cannot skew.
    let handle = crate::naming::closure_handle_nominal(&cx.f.wrapper_ref_name());
    // The captured Ipê closure. `Arc` gives the returned closure `Clone` for
    // multi-call re-entry without cloning the Ipê value itself.
    let call = if forwarded_args.is_empty() {
        "(__ipe_fn)()".to_owned()
    } else {
        format!("(__ipe_fn)({forwarded_args})")
    };
    let crate_params_joined = crate_param_decls.join(", ");
    let body_lines = closure_per_call_body(&sig.ret, &call, wrapper);
    let mut out = vec![
        format!("pub type {handle} = {out_ty};"),
        format!("pub fn {wrapper}(__ipe_fn: {ipe_fn_ty}) -> {handle} {{"),
        "    let __ipe_fn = std::sync::Arc::new(__ipe_fn);".to_owned(),
        format!("    Box::new(move |{crate_params_joined}| {{"),
        "        let __ipe_fn = std::sync::Arc::clone(&__ipe_fn);".to_owned(),
    ];
    out.extend(body_lines);
    out.push("    })".to_owned());
    out.push("}".to_owned());
    out
}

/// The per-call closure body the adapter's returned closure runs each call.
///
/// A SYNC return is a single `catch_unwind` `match` expression: a `Total`
/// (scalar) return has no error channel so a panic ABORTS (never fabricating a
/// `Default` — that would launder a real Ipê panic into a wrong value); a
/// `Result`/`Option` return folds the panic in-band to `Err`/`None`.
///
/// An ASYNC return produces the `IpeTask` future under `catch_unwind` (a
/// production-panic yields an immediate-error future), then returns a boxed
/// future that awaits it under a spawned task — a poll-panic surfaces as a
/// `JoinError` folded to `Err`/`None`, and an `AbortOnDrop` guard cancels the
/// inner task if the outer one is dropped (no Ipê side effect after cancel). The
/// captured `Arc` is consumed PRODUCING the future, before the await, so only
/// `{JoinHandle, AbortHandle}` cross the await point and the returned future
/// stays `Send` even though `IpeTask` is `!Sync`.
fn closure_per_call_body(ret: &ClosureRet, call: &str, wrapper: &str) -> Vec<String> {
    match ret {
        ClosureRet::Total(_) => vec![format!(
            "        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {call})) \
             {{ Ok(v) => v, Err(__p) => {{ \
             note_foreign_panic(\"Ipê closure `{wrapper}` panicked; aborting \
             (total return has no error channel)\", __p); std::process::abort(); }} }}"
        )],
        ClosureRet::Result(_) => vec![format!(
            "        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {call})) \
             {{ Ok(inner) => inner, Err(__p) => Err(ipe_error_from_panic(\"foreign closure panicked\", __p)) }}"
        )],
        ClosureRet::Option(_) => vec![format!(
            "        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {call})) \
             {{ Ok(inner) => inner, Err(__p) => {{ note_foreign_panic(\"foreign closure panicked\", __p); None }} }}"
        )],
        ClosureRet::AsyncResult(_) | ClosureRet::AsyncOption(_) => {
            // The production seam (building the future) keeps its own
            // `catch_unwind`; the spawn + cancel-guard + join-error funnel is
            // the single `ffi_spawn_guarded` choke-point. Its `Err` is already
            // the funnelled outcome (a poll panic redacted, a cancel funnelled),
            // so the `Result` shape returns it verbatim and the `Option` shape
            // folds it to `None` (the funnel has already logged the detail).
            let (prod_fold, join_fold) = if matches!(ret, ClosureRet::AsyncResult(_)) {
                (
                    "{ let __e = ipe_error_from_panic(\"foreign closure panicked\", __p); \
                     return Box::pin(async move { Err(__e) }); }",
                    "Err(__e) => Err(__e)",
                )
            } else {
                (
                    "{ note_foreign_panic(\"foreign closure panicked\", __p); \
                     return Box::pin(async move { None }); }",
                    "Err(_) => None",
                )
            };
            vec![
                format!(
                    "        let __fut = match std::panic::catch_unwind(\
                     std::panic::AssertUnwindSafe(move || {call})) \
                     {{ Ok(f) => f, Err(__p) => {prod_fold} }};"
                ),
                "        Box::pin(async move {".to_owned(),
                format!(
                    "            match ffi_spawn_guarded(__fut).await {{ Ok(inner) => inner, {join_fold} }}"
                ),
                "        })".to_owned(),
            ]
        }
    }
}

/// The `[rust.define.struct]` definition + constructor wrapper.
///
/// Ipê DEFINES a nominal Rust type here: the emitter renders the `#[derive]`ed
/// struct definition, then a constructor wrapper that takes each field's owned
/// carrier value and builds the struct literal. This solves "define a Rust
/// type" with ZERO new trust surface — the body is built from decode-validated
/// carriers only, exactly like `enum_ctor_lines`. Everything renders from the
/// parsed [`StructDef`]; no raw manifest string reaches this emitted Rust.
///
/// An opaque field type resolves through the crate [`OpaqueResolver`] so the
/// defined struct names an absolute crate path (never colliding with a re-exported
/// runtime kernel module). An unresolvable or parameterised opaque field OVER-DROPS
/// the whole region (empty ⇒ the interface skips the forwarder), so an
/// `Element<'a, Msg>`-shaped field stays refused rather than breach the SEAL. The
/// definition and the constructor's parameter types render from the SAME resolved
/// carriers, so their opaque paths can never disagree (an E0308 otherwise).
fn struct_ctor_lines(cx: &WrapperCx<'_>, def: &StructDef, opaques: &OpaqueResolver) -> Vec<String> {
    // The struct definition, with each opaque field resolved through the crate
    // (a scalar field renders its owned Rust type directly). A single
    // unresolvable field over-drops the whole definition.
    let Some(mut out) =
        def.definition_lines(&|id| opaques.carrier_ty(&Carrier::Opaque(id.clone())))
    else {
        return Vec::new();
    };
    // The constructor: one owned-carrier parameter per field, in order, folded
    // into the struct literal. Each parameter's inbound coercion is the identity
    // for the closed carrier set (the owned Rust type IS the Ipê value's carrier
    // — no narrowing), mirroring the struct-variant `enum_ctor_lines` path. The
    // definition already established every opaque field is resolvable, so the
    // param resolve below cannot fail here — but it is threaded through the same
    // resolver to keep the two type renderings identical by construction.
    let struct_name = def.name.as_str();
    // A fieldless struct's constructor still takes the forwarder's unit value
    // (`_: ()`), the same convention every zero-param inspected wrapper uses —
    // the Ipê-side forwarder is a unary `() -> T` function, so its saturated
    // call always passes one argument.
    let mut params: Vec<String> = Vec::with_capacity(def.fields.len().max(1));
    for (j, (_, c)) in def.fields.iter().enumerate() {
        let Some(ty) = opaques.carrier_ty(c) else {
            return Vec::new();
        };
        params.push(format!("{}: {ty}", arg_name(j)));
    }
    if params.is_empty() {
        params.push("_: ()".to_owned());
    }
    let assigns: Vec<String> = def
        .fields
        .iter()
        .enumerate()
        .map(|(j, (fname, _))| format!("{}: {}", fname.as_str(), arg_name(j)))
        .collect();
    out.push(String::new());
    out.push(format!(
        "pub fn {}({}) -> {struct_name} {{",
        cx.rust_name,
        params.join(", ")
    ));
    out.push(format!("    {struct_name} {{ {} }}", assigns.join(", ")));
    out.push("}".to_owned());
    out
}

/// The `[rust.define.enum]` definition + one constructor per variant.
///
/// Ipê DEFINES a nominal Rust `enum` here: the emitter renders the `#[derive]`ed
/// enum definition once, then a constructor wrapper per variant. A unit variant
/// gets a nullary constructor (`E::V`); a tuple-payload variant gets one owned
/// carrier parameter per payload position, folded into `E::V(a0, …)`. This is
/// the `struct_ctor_lines` path generalised to a sum — the exact `EnumCtor`
/// inbound coercion an inspected enum already uses, applied to an author-defined
/// enum. Everything renders from the parsed [`EnumDef`]; no raw manifest string
/// reaches this emitted Rust.
///
/// An opaque payload resolves through the crate [`OpaqueResolver`] so the defined
/// enum names an absolute crate path (never colliding with a re-exported runtime
/// kernel module). An unresolvable or parameterised opaque payload OVER-DROPS the
/// whole region (empty ⇒ the interface skips every variant forwarder), so an
/// `Element<'a, Msg>`-shaped payload stays refused rather than breach the SEAL. The
/// definition and every constructor's parameter types render from the SAME
/// resolved carriers, so their opaque paths can never disagree (an E0308).
fn enum_def_ctor_lines(cx: &WrapperCx<'_>, def: &EnumDef, opaques: &OpaqueResolver) -> Vec<String> {
    // The enum definition, with each opaque payload resolved through the crate
    // (a scalar payload renders its owned Rust type directly). A single
    // unresolvable payload over-drops the whole definition.
    let Some(mut out) =
        def.definition_lines(&|id| opaques.carrier_ty(&Carrier::Opaque(id.clone())))
    else {
        return Vec::new();
    };
    let enum_name = def.name.as_str();
    // One constructor per variant, named `<ctor>_<snake(variant)>` off the
    // manifest ctor name (`cx.rust_name`). Each parameter's inbound coercion is
    // the identity for the closed carrier set (the owned Rust type IS the Ipê
    // value's carrier — no narrowing), mirroring the tuple-variant `EnumCtor`.
    for v in &def.variants {
        let ctor = format!(
            "{}_{}",
            cx.rust_name,
            crate::naming::variant_snake(v.name.as_str())
        );
        out.push(String::new());
        if v.payload.is_empty() {
            // A unit variant's constructor still takes the forwarder's unit
            // value (`_: ()`), the same convention every zero-param inspected
            // wrapper uses — the Ipê-side forwarder is a unary `() -> T`
            // function, so its saturated call always passes one argument.
            out.push(format!("pub fn {ctor}(_: ()) -> {enum_name} {{"));
            out.push(format!("    {enum_name}::{}", v.name.as_str()));
        } else {
            // The definition already established every opaque payload is
            // resolvable, so this resolve cannot fail here — threaded through the
            // same resolver to keep the two type renderings identical.
            let mut params: Vec<String> = Vec::with_capacity(v.payload.len());
            for (j, c) in v.payload.iter().enumerate() {
                let Some(ty) = opaques.carrier_ty(c) else {
                    return Vec::new();
                };
                params.push(format!("{}: {ty}", arg_name(j)));
            }
            let forwarded: Vec<String> = (0..v.payload.len()).map(arg_name).collect();
            out.push(format!(
                "pub fn {ctor}({}) -> {enum_name} {{",
                params.join(", ")
            ));
            out.push(format!(
                "    {enum_name}::{}({})",
                v.name.as_str(),
                forwarded.join(", ")
            ));
        }
        out.push("}".to_owned());
    }
    out
}

/// The comma-joined declared parameter TYPE list (`i64, bool`) for a boxed
/// `dyn Fn(...)` type position.
fn param_ty_list(params: &[(String, String)]) -> String {
    params
        .iter()
        .map(|(_, ty)| ty.clone())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Plain fn / method / static / pkg-var wrapper (the fallible-carrier tier).
#[allow(clippy::too_many_lines)] // one linear body-shape cascade (self-return / borrow-thread / effect arms)
fn plain_lines(cx: &WrapperCx<'_>) -> Vec<String> {
    let f = cx.f;
    // Degenerate method: a self-param entry whose concrete receiver the
    // inspector could not determine — the receiver-tagged variant survives.
    let is_degenerate_method =
        f.recv_type().is_empty() && f.params().first().is_some_and(|p| p.name == "self");
    let unresolved_generic_recv = (cx.is_instance || cx.is_static)
        && has_generic_recv_param(f.recv_rust_type(), cx.is_display_bridge);
    // A trait associated fn renders only as UFCS via the generic-instance
    // path; the flat wrapper would be a duplicate or an E0425.
    let is_trait_fn = f.generic().is_some_and(|g| g.call.has_trait_qualifier());
    if is_degenerate_method || unresolved_generic_recv || is_trait_fn {
        return Vec::new();
    }
    let (ret_inner, ret_coerce) = cx.ret_inner_and_coerce();
    // A by-borrow reader threads its receiver (`arg0`) back beside the result:
    // the inner return type gains a trailing receiver component and the body
    // returns `(value, arg0)`. The `&self`/`&mut self` call only borrows `arg0`,
    // so it is still live to return. Async (effectful) readers move the receiver
    // into the spawned task and cannot thread it back — they keep the
    // `IPE-L0130` linearity backstop.
    let thread_recv = f.is_borrow_reader() && f.effect() != Effect::Effectful;
    let recv_rust_ty = cx.param_types.first().cloned().unwrap_or_default();
    let ret_inner = if thread_recv {
        format!("({ret_inner}, {recv_rust_ty})")
    } else {
        ret_inner
    };
    let ret_type = if f.effect() == Effect::Effectful {
        format!("IpeTask<{ret_inner}>")
    } else {
        format!("IpeResult<IpeError, {ret_inner}>")
    };
    let call = cx.call_expr();
    let effect_tag = match f.effect() {
        Effect::Pure => "pure",
        Effect::Fallible => "fallible",
        Effect::Effectful => "effectful",
    };
    let mut preludes = cx.arr_prelude();
    preludes.extend(cx.serde_prelude());
    let body = if f.self_returning() {
        let own_thread_args = cx.call_args(1);
        let method = rust_safe_ident(f.name());
        format!(
            "match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {{ \
             arg0.{method}({own_thread_args}); arg0 }})) \
             {{ Ok(r) => ok_res(r), Err(__p) => IpeResult::Err(ipe_error_from_panic(\"foreign call panicked\", __p)) }}"
        )
    } else if thread_recv {
        // By-borrow reader: the closure owns `arg0`, calls the borrowing method,
        // then hands the receiver back so it flows out beside the result. A
        // Fallible reader folds its `Err` arm normally (the handle is spent on
        // failure — the Ipê `Result Error (R, T)` carries no tuple there).
        match f.effect() {
            Effect::Fallible => format!(
                "match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {{ let __r = {call}; (__r, arg0) }})) \
                 {{ Ok((Ok(v), recv)) => ok_res(({}, recv)), Ok((Err(e), _)) => IpeResult::Err(ipe_error_from_foreign(e)), \
                 Err(__p) => IpeResult::Err(ipe_error_from_panic(\"foreign call panicked\", __p)) }}",
                ret_coerce("v")
            ),
            // Pure (and, defensively, any non-fallible non-effectful shape).
            _ => format!(
                "match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {{ let __r = {call}; (__r, arg0) }})) \
                 {{ Ok((v, recv)) => ok_res(({}, recv)), Err(__p) => IpeResult::Err(ipe_error_from_panic(\"foreign call panicked\", __p)) }}",
                ret_coerce("v")
            ),
        }
    } else {
        match f.effect() {
            Effect::Effectful => {
                // The async panic boundary is the spawned task's JoinError.
                // A fallible async fn's Ok is itself a Result: three arms.
                let is_async_fallible = cx.effective_raw_result().starts_with("Result<");
                let prelude_inline = if preludes.is_empty() {
                    String::new()
                } else {
                    let mut s = preludes.join(" ");
                    s.push(' ');
                    s
                };
                preludes = Vec::new(); // moved inside the async block
                // The spawn + cancel-guard + join-error funnel is the single
                // `ffi_spawn_guarded` choke-point: it arms `AbortOnDrop` and
                // folds a poll-time panic to the redacted funnel as one
                // indivisible step, so this shape cannot spawn unguarded. A
                // non-panic `JoinError` is already the funnelled `Err`; only the
                // success value needs the shape's own lift.
                if is_async_fallible {
                    format!(
                        "Box::pin(async move {{ {prelude_inline}match ffi_spawn_guarded(async move {{ {call}.await }}).await \
                         {{ Ok(Ok(v)) => ok_res({}), Ok(Err(e)) => IpeResult::Err(ipe_error_from_foreign(e)), \
                         Err(e) => IpeResult::Err(e) }} }})",
                        ret_coerce("v")
                    )
                } else {
                    format!(
                        "Box::pin(async move {{ {prelude_inline}match ffi_spawn_guarded(async move {{ {call}.await }}).await \
                         {{ Ok(v) => ok_res({}), Err(e) => IpeResult::Err(e) }} }})",
                        ret_coerce("v")
                    )
                }
            }
            Effect::Fallible => format!(
                "match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {call})) \
                 {{ Ok(Ok(v)) => ok_res({}), Ok(Err(e)) => IpeResult::Err(ipe_error_from_foreign(e)), \
                 Err(__p) => IpeResult::Err(ipe_error_from_panic(\"foreign call panicked\", __p)) }}",
                ret_coerce("v")
            ),
            Effect::Pure => format!(
                "match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {})) \
                 {{ Ok(v) => ok_res(v), Err(__p) => IpeResult::Err(ipe_error_from_panic(\"foreign call panicked\", __p)) }}",
                ret_coerce(&call)
            ),
        }
    };
    let mut out = vec![
        format!("// [{effect_tag}] {}", cx.label),
        format!(
            "pub fn {}({}) -> {ret_type} {{",
            cx.rust_name,
            cx.param_decl()
        ),
    ];
    out.extend(preludes.into_iter().map(|p| format!("    {p}")));
    out.push(format!("    {body}"));
    out.push("}".to_owned());
    out
}

/// Struct-field getter: the projection/`.clone()` over the closed eligible
/// field set, returning the bare field type.
///
/// An OPAQUE-typed field is the one shape here whose `.clone()` runs foreign
/// code (the crate's own `Clone` impl), so that body executes inside
/// `catch_unwind`; the bare return has no error channel, so a caught foreign
/// panic funnel-logs and aborts — the same sanctioned no-error-channel
/// response as a total-return closure, never a laundered value and never an
/// unwind that some unrelated recovery layer could absorb over half-broken
/// foreign state. Scalar/`String`-family fields stay bare: their access runs
/// no foreign code, so they are infallible by construction.
fn field_get_lines(cx: &WrapperCx<'_>) -> Vec<String> {
    let f = cx.f;
    let recv_rust = cx.resolve_recv();
    let field = f.method_name();
    let raw_ty = f.results().first().map_or("", Param::rust_type_str);
    let well_formed = f.results().len() == 1
        && !raw_ty.trim().is_empty()
        && !field.is_empty()
        && !recv_rust.trim().is_empty();
    if !well_formed {
        return Vec::new();
    }
    let (inner0, co) = translate_rust_ret(raw_ty);
    let inner = absolutize_crate(cx.krate, &inner0);
    let projection = format!("arg0.{}", rust_safe_ident(field));
    let access = if is_copy_rust(raw_ty) {
        projection
    } else {
        format!("{projection}.clone()")
    };
    // A field access runs foreign code exactly when its `.clone()` can
    // dispatch into the crate's own `Clone` impl; such a body needs the panic
    // boundary. The classification is POSITIVE and fail-closed: only a type
    // proven std-owned all the way down (scalars, `String`, `Vec`/`Option`
    // over the same set) stays bare — anything unrecognised, qualified or
    // not, gets the boundary.
    let clone_runs_foreign_code = !is_copy_rust(raw_ty) && !std_owned_field_ty(raw_ty);
    let body = if clone_runs_foreign_code {
        format!(
            "    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {})) \
             {{ Ok(v) => v, Err(__p) => {{ \
             note_foreign_panic(\"foreign `Clone` panicked in field getter `{}`; aborting \
             (field getter has no error channel)\", __p); std::process::abort(); }} }}",
            co(&access),
            cx.rust_name
        )
    } else {
        format!("    {}", co(&access))
    };
    vec![
        format!("// [field] {}", cx.label),
        format!("pub fn {}(arg0: {recv_rust}) -> {inner} {{", cx.rust_name),
        body,
        "}".to_owned(),
    ]
}

/// Whether a field's Rust type is std-owned all the way down — Copy scalars,
/// `String`/`str`, and `Vec`/`Option` recursively over the same set — so its
/// `.clone()` provably runs no foreign code. Anything unrecognised is NOT
/// std-owned; the caller then applies the panic boundary (fail-closed).
fn std_owned_field_ty(raw: &str) -> bool {
    let t = raw.trim();
    if is_copy_rust(t) || matches!(t, "String" | "str" | "&str") {
        return true;
    }
    if let Some(inner) = strip_generic1("Vec", t).or_else(|| strip_generic1("Option", t)) {
        return std_owned_field_ty(inner);
    }
    false
}

/// Struct-field setter: a NEW receiver with one field replaced — Ipê
/// immutable-update value semantics, infallible by construction.
fn field_set_lines(cx: &WrapperCx<'_>) -> Vec<String> {
    let f = cx.f;
    let recv_rust = cx.resolve_recv();
    let field = f.method_name();
    let well_formed = !f.params().is_empty() && !field.is_empty() && !recv_rust.trim().is_empty();
    if !well_formed {
        return Vec::new();
    }
    let set_val_rust = cx
        .param_types
        .first()
        .cloned()
        .unwrap_or_else(|| "String".to_owned());
    // A FALLIBLE setter carries a narrowing integer field: convert with
    // `try_from` and fold an out-of-range value to `Err` (the checked
    // variant), never a silent truncation.
    if f.effect() == Effect::Fallible {
        return checked_field_set_lines(cx, &recv_rust, field, &set_val_rust);
    }
    let expr = owned_value_coercion(cx.raw_param(0), &set_val_rust, "arg0");
    vec![
        format!("// [field-set] {}", cx.label),
        format!(
            "pub fn {}(arg0: {set_val_rust}, arg1: {recv_rust}) -> {recv_rust} {{",
            cx.rust_name
        ),
        "    let mut r = arg1;".to_owned(),
        format!("    r.{} = {expr};", rust_safe_ident(field)),
        "    r".to_owned(),
        "}".to_owned(),
    ]
}

/// CHECKED setter body for a narrowing integer field (bare or `Option<>`):
/// `try_from` the Ipe `i64`, assign on `Ok`, fold out-of-range to a typed
/// `Err`. Any other raw shape fails closed (empty region — the binding drops).
fn checked_field_set_lines(
    cx: &WrapperCx<'_>,
    recv_rust: &str,
    field: &str,
    set_val_rust: &str,
) -> Vec<String> {
    let raw = cx.raw_param(0).trim();
    let is_checked_int = |t: &str| {
        matches!(
            t,
            "i8" | "i16"
                | "i32"
                | "u8"
                | "u16"
                | "u32"
                | "u64"
                | "u128"
                | "i128"
                | "usize"
                | "isize"
        )
    };
    let sig = format!(
        "pub fn {}(arg0: {set_val_rust}, arg1: {recv_rust}) -> IpeResult<IpeError, {recv_rust}> {{",
        cx.rust_name
    );
    let assign = |value_expr: &str| {
        vec![
            format!(
                "        Ok(v) => {{ let mut r = arg1; r.{} = {value_expr}; ok_res(r) }}",
                rust_safe_ident(field)
            ),
            "        Err(e) => IpeResult::Err(ipe_error_from_foreign(e)),".to_owned(),
        ]
    };
    if let Some(inner) = strip_generic1("Option", raw).map(str::trim)
        && is_checked_int(inner)
    {
        let mut out = vec![
            format!("// [field-set checked] {}", cx.label),
            sig,
            format!("    match ipe_maybe_to_option(arg0).map({inner}::try_from).transpose() {{"),
        ];
        out.extend(assign("v"));
        out.push("    }".to_owned());
        out.push("}".to_owned());
        return out;
    }
    if is_checked_int(raw) {
        let mut out = vec![
            format!("// [field-set checked] {}", cx.label),
            sig,
            format!("    match {raw}::try_from(arg0) {{"),
        ];
        out.extend(assign("v"));
        out.push("    }".to_owned());
        out.push("}".to_owned());
        return out;
    }
    Vec::new()
}

/// Owned inbound coercion: lift an Ipê-resolved wrapper value into the exact
/// raw foreign type, OWNED (never borrows — field assignments and enum ctors
/// move owned values in). Int narrowing saturates; a Float-source list keeps
/// the already-saturating bare `as`.
fn owned_value_coercion(raw_ty: &str, decl_ty: &str, base: &str) -> String {
    if let Some(sk) = seq_kind(raw_ty) {
        return match (sk.shape, &sk.elem) {
            (SeqShape::Owned, SeqElem::U8) => format!("to_u8_vec(&{base})"),
            (SeqShape::Owned, SeqElem::General { rust, ipe }) => {
                if rust == "i64" || rust == "f64" || !is_numeric_rust(rust) {
                    base.to_owned()
                } else if ipe == "Float" {
                    format!("{base}.into_iter().map(|x| x as {rust}).collect()")
                } else {
                    format!(
                        "{base}.into_iter().map(|x| {}).collect()",
                        num_saturate(rust, "x")
                    )
                }
            }
            // Slice/array field shapes are outside the closed eligible set.
            _ => base.to_owned(),
        };
    }
    if let Some(inner) = strip_generic1("Option", raw_ty) {
        let opt = format!("ipe_maybe_to_option({base})");
        return if is_numeric_rust(inner) {
            format!("{opt}.map(|x| {})", num_saturate(inner, "x"))
        } else {
            opt
        };
    }
    if raw_ty.is_empty() || raw_ty == decl_ty {
        return base.to_owned();
    }
    if is_numeric_rust(raw_ty) && (decl_ty == "i64" || decl_ty == "f64") {
        return num_saturate(raw_ty, base);
    }
    base.to_owned()
}

/// Enum-variant constructor: `E::Variant(args)` — infallible (the inspector
/// suppressed ctors for `non_exhaustive` enums/variants).
fn enum_ctor_lines(
    cx: &WrapperCx<'_>,
    variant: &str,
    kind: EnumVariantKind,
    struct_fields: &[RustIdent],
) -> Vec<String> {
    let recv_rust = cx.resolve_recv();
    if recv_rust.trim().is_empty() || variant.is_empty() {
        return Vec::new();
    }
    let path = format!("{recv_rust}::{}", rust_safe_ident(variant));
    let ctor_args: Vec<String> = (0..cx.n_params())
        .map(|j| owned_value_coercion(cx.raw_param(j), cx.decl_param(j), &arg_name(j)))
        .collect();
    let expr = match kind {
        EnumVariantKind::Unit => path,
        EnumVariantKind::Struct => {
            let assigns: Vec<String> = struct_fields
                .iter()
                .zip(&ctor_args)
                .map(|(field, a)| format!("{}: {a}", rust_safe_ident(field.as_str())))
                .collect();
            format!("{path} {{ {} }}", assigns.join(", "))
        }
        EnumVariantKind::Tuple => format!("{path}({})", ctor_args.join(", ")),
    };
    vec![
        format!("// [enum-ctor] {}", cx.label),
        format!(
            "pub fn {}({}) -> {recv_rust} {{",
            cx.rust_name,
            cx.param_decl()
        ),
        format!("    {expr}"),
        "}".to_owned(),
    ]
}

/// Enum tag accessor: an exhaustive `match` mapping each variant to its name
/// string; the wildcard arm appears only when the inspector flagged it.
fn enum_tag_lines(cx: &WrapperCx<'_>, arms: &[EnumArm], wildcard: bool) -> Vec<String> {
    let recv_rust = cx.resolve_recv();
    if recv_rust.trim().is_empty() || arms.is_empty() {
        return Vec::new();
    }
    let mut out = vec![
        format!("// [enum-tag] {}", cx.label),
        format!("pub fn {}(arg0: {recv_rust}) -> String {{", cx.rust_name),
        "    let t: &str = match arg0 {".to_owned(),
    ];
    for arm in arms {
        // The pattern is `<variant><suffix>`, suffix ∈ {"", "(..)", "{..}"};
        // raw-escape just the leading variant ident.
        let pat = arm.pattern.as_str();
        let split_at = pat.find(['(', '{']).unwrap_or(pat.len());
        let vid = pat.get(..split_at).unwrap_or("");
        let suffix = pat.get(split_at..).unwrap_or("");
        out.push(format!(
            "        {recv_rust}::{}{suffix} => {},",
            rust_safe_ident(vid),
            rust_str_lit(&arm.tag)
        ));
    }
    if wildcard {
        out.push(format!("        _ => {},", rust_str_lit("<unknown>")));
    }
    out.push("    };".to_owned());
    out.push("    t.to_string()".to_owned());
    out.push("}".to_owned());
    out
}

/// Single-field payload extractor: `E -> IpeMaybe<T>`. The by-value receiver
/// moves the selected owned field out; sibling positions bind `_` and drop.
fn enum_extract_lines(
    cx: &WrapperCx<'_>,
    variant: &str,
    kind: EnumVariantKind,
    selector: &str,
    field_count: u64,
    wildcard: bool,
) -> Vec<String> {
    let f = cx.f;
    let recv_rust = cx.resolve_recv();
    let raw_result = f.results().first().map_or("", Param::rust_type_str);
    let inner_raw = strip_generic1("Option", raw_result)
        .unwrap_or(raw_result)
        .trim()
        .to_owned();
    let well_formed = !recv_rust.trim().is_empty()
        && !variant.is_empty()
        && !inner_raw.is_empty()
        && (kind != EnumVariantKind::Struct || !selector.is_empty());
    if !well_formed {
        return Vec::new();
    }
    let (inner0, co) = translate_rust_ret(&inner_raw);
    let inner = absolutize_crate(cx.krate, &inner0);
    let path = format!("{recv_rust}::{}", rust_safe_ident(variant));
    let (pattern, binder) = match kind {
        EnumVariantKind::Struct => {
            let ident = rust_safe_ident(selector);
            (format!("{path} {{ {ident}, .. }}"), ident)
        }
        // Tuple (and the defensive unit fallback): bind only the selected
        // position; every other position is `_` so unmatched siblings drop
        // without an unused_variables warning.
        EnumVariantKind::Tuple | EnumVariantKind::Unit => {
            if selector.is_empty() {
                (format!("{path}(x)"), "x".to_owned())
            } else {
                let n = usize::try_from(field_count).unwrap_or(1).max(1);
                let idx = selector
                    .parse::<usize>()
                    .ok()
                    .filter(|&i| i < n)
                    .unwrap_or(0);
                let ret = format!("f{idx}");
                let binders: Vec<String> = (0..n)
                    .map(|i| {
                        if i == idx {
                            ret.clone()
                        } else {
                            "_".to_owned()
                        }
                    })
                    .collect();
                (format!("{path}({})", binders.join(", ")), ret)
            }
        }
    };
    let mut out = vec![
        format!("// [enum-extract] {}", cx.label),
        format!(
            "pub fn {}(arg0: {recv_rust}) -> IpeMaybe<{inner}> {{",
            cx.rust_name
        ),
        "    match arg0 {".to_owned(),
        format!("        {pattern} => IpeMaybe::Just({}),", co(&binder)),
    ];
    if wildcard {
        out.push("        _ => IpeMaybe::Nothing,".to_owned());
    }
    out.push("    }".to_owned());
    out.push("}".to_owned());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn decode(v: &serde_json::Value) -> PkgInfo {
        PkgInfo::decode_json(&v.to_string()).expect("decodes")
    }

    fn semver_pkg(functions: &serde_json::Value) -> PkgInfo {
        decode(&json!({
            "pkg": "semver",
            "name": "semver",
            "version": "1.0.26",
            "functions": functions,
            "errors": []
        }))
    }

    // ── helper units ────────────────────────────────────────────────────

    #[test]
    fn absolutize_rewrites_only_path_starts() {
        assert_eq!(absolutize_crate("csv", "csv::Reader"), "::csv::Reader");
        assert_eq!(
            absolutize_crate("csv", "Vec<csv::Reader>"),
            "Vec<::csv::Reader>"
        );
        assert_eq!(absolutize_crate("csv", "::csv::Reader"), "::csv::Reader");
        assert_eq!(absolutize_crate("csv", "mycsv::Reader"), "mycsv::Reader");
        assert_eq!(absolutize_crate("csv", "String"), "String");
    }

    #[test]
    fn ok_type_of_result_respects_nested_angles() {
        assert_eq!(ok_type_of_result("Result<Version, Error>"), "Version");
        assert_eq!(ok_type_of_result("Result<Vec<T>, E>"), "Vec<T>");
        assert_eq!(ok_type_of_result("String"), "String");
    }

    #[test]
    fn pkg_to_crate_import_takes_the_last_segment_underscored() {
        assert_eq!(pkg_to_crate_import("uuid"), "uuid");
        assert_eq!(pkg_to_crate_import("some/crate-name"), "crate_name");
    }

    #[test]
    fn seq_kind_classifies_shapes_and_rejects_mut_and_huge_arrays() {
        let u8_slice = seq_kind("&[u8]").expect("slice");
        assert_eq!(u8_slice.shape, SeqShape::Slice);
        assert_eq!(u8_slice.elem, SeqElem::U8);
        assert_eq!(seq_kind("[u8; 16]").expect("arr").shape, SeqShape::Arr(16));
        assert_eq!(
            seq_kind("&[u8; 4]").expect("ref arr").shape,
            SeqShape::RefArr(4)
        );
        let general_vec = seq_kind("Vec<f32>").expect("general vec");
        assert_eq!(
            general_vec.elem,
            SeqElem::General {
                rust: "f32".into(),
                ipe: "Float".into()
            }
        );
        assert_eq!(seq_kind("&mut [u8]"), None);
        assert_eq!(seq_kind("[u8; 999999999999]"), None);
        assert_eq!(seq_kind("Vec<str>"), None);
        assert_eq!(seq_kind("Vec<PathBuf>"), None);
    }

    #[test]
    fn translate_ret_covers_the_coercion_table() {
        let (t, co) = translate_rust_ret("u64");
        assert_eq!(t, "i64");
        assert_eq!(co("v"), "(v).min(i64::MAX as u64) as i64");
        let (t, co) = translate_rust_ret("Option<u32>");
        assert_eq!(t, "IpeMaybe<i64>");
        assert_eq!(
            co("e"),
            "match e { Some(v) => IpeMaybe::Just((v) as i64), None => IpeMaybe::Nothing }"
        );
        let (t, co) = translate_rust_ret("&str");
        assert_eq!(t, "String");
        assert_eq!(co("e"), "e.to_string()");
        let (t, co) = translate_rust_ret("Version");
        assert_eq!(t, "Version");
        assert_eq!(co("e"), "e");
        let (t, co) = translate_rust_ret("Vec<u8>");
        assert_eq!(t, "Vec<i64>");
        assert_eq!(co("e"), "from_u8_slice(&e)");
        let (t, co) = translate_rust_ret("Vec<u64>");
        assert_eq!(t, "Vec<i64>");
        assert_eq!(
            co("e"),
            "e.into_iter().map(|x| (x).min(i64::MAX as u64) as i64).collect::<Vec<_>>()"
        );
        let (t, co) = translate_rust_ret("Vec<String>");
        assert_eq!(t, "Vec<String>");
        assert_eq!(co("e"), "e");
        let (t, co) = translate_rust_ret("&[f32]");
        assert_eq!(t, "Vec<f64>");
        assert_eq!(co("e"), "e.iter().map(|&x| (x) as f64).collect::<Vec<_>>()");
        let (t, co) = translate_rust_ret("serde_json::Value");
        assert_eq!(t, "String");
        assert_eq!(co("e"), "serde_json::to_string(&(e)).unwrap_or_default()");
        let (t, co) = translate_rust_ret("&Version");
        assert_eq!(t, "Version");
        assert_eq!(co("e"), "e.to_owned()");
        let (t, co) = translate_rust_ret("");
        assert_eq!(t, "()");
        assert_eq!(co("e"), "e");
    }

    #[test]
    fn panic_profile_precheck_reads_any_quote_style() {
        assert!(cargo_profile_panic_is_unwind(
            "[profile.release]\nlto = true\n"
        ));
        assert!(cargo_profile_panic_is_unwind("panic = \"unwind\"\n"));
        assert!(!cargo_profile_panic_is_unwind("panic = \"abort\"\n"));
        assert!(!cargo_profile_panic_is_unwind("  panic='abort'\n"));
        assert!(!cargo_profile_panic_is_unwind("panic\t= 'abort'\n"));
    }

    // ── whole-file golden ───────────────────────────────────────────────

    #[test]
    fn golden_semver_bindings_file() {
        let pkg = semver_pkg(&json!([
            {
                "name": "parse",
                "params": [{"name": "text", "type": "String", "ipeType": "String", "rustType": "&str"}],
                "results": [{"name": "", "type": "Result Error Version", "rustType": "Result<Version, Error>"}],
                "effect": "fallible"
            },
            {
                "name": "major_field",
                "params": [{"name": "self", "type": "Version", "ipeType": "Version", "rustType": "&Version"}],
                "results": [{"name": "", "type": "Int", "rustType": "u64"}],
                "effect": "pure",
                "recvType": "Version",
                "recvRustType": "semver::Version",
                "methodName": "major",
                "isField": true
            }
        ]));
        let expected = r#"// Code generated by ipe-ffi-inspector from semver. DO NOT EDIT.
// Re-run `ipe add semver` to regenerate.

#![allow(unused_imports, unused_mut, dead_code)]

// The catch_unwind boundary converts a foreign panic into a typed Err;
// that conversion is sound only under panic=unwind, so refuse to build
// under any configuration that selects panic=abort.
#[cfg(panic = "abort")]
compile_error!("ipe_ffi catch_unwind boundary requires panic=unwind");

use crate::*;
use std::collections::HashMap;

// IPE-FFI-WRAPPER BEGIN parse
// [fallible] Rust_Semver_parse
pub fn semver_parse(arg0: String) -> IpeResult<IpeError, Version> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || ::semver::parse(arg0.as_ref()))) { Ok(Ok(v)) => ok_res(v), Ok(Err(e)) => IpeResult::Err(ipe_error_from_foreign(e)), Err(__p) => IpeResult::Err(ipe_error_from_panic("foreign call panicked", __p)) }
}
// IPE-FFI-WRAPPER END
// IPE-FFI-WRAPPER BEGIN major_field_from_version
// [field] Rust_Semver_major_field_from_version
pub fn semver_major_field_from_version(arg0: ::semver::Version) -> i64 {
    (arg0.major).min(i64::MAX as u64) as i64
}
// IPE-FFI-WRAPPER END

"#;
        assert_eq!(emit_bindings(&pkg), expected);
    }

    // ── wrapper-shape coverage ──────────────────────────────────────────

    fn closure_region(sig: &str) -> String {
        let pkg = semver_pkg(&json!([{
            "name": "update_fn",
            "effect": "pure",
            "isClosureAdapter": true,
            "closureSig": sig
        }]));
        emit_bindings(&pkg)
    }

    #[test]
    fn closure_adapter_total_return_aborts_on_panic_never_fabricates() {
        let out = closure_region("Fn(Int, Bool) -> Int + Send + Sync + 'static");
        // The returned boxed closure is surfaced as an opaque handle nominal, its
        // full `Box<dyn Fn …>` type carried by a `pub type` alias in the SAME
        // region (so the interface's forwarder + alias can never skew).
        assert!(
            out.contains(
                "pub type UpdateFnClosure = Box<dyn Fn(i64, bool) -> i64 + Send + Sync + 'static>;"
            ),
            "{out}"
        );
        // The wrapper receives the Ipê fn value as the exact app-side box type
        // and returns the handle nominal.
        assert!(
            out.contains(
                "pub fn semver_update_fn(__ipe_fn: Box<dyn Fn(i64, bool) -> i64 + Send + Sync + \
                 'static>) -> UpdateFnClosure {"
            ),
            "{out}"
        );
        // Multi-call Clone: the captured value is behind an Arc.
        assert!(out.contains("std::sync::Arc::new(__ipe_fn)"), "{out}");
        // Panic-isolated per-call re-entry.
        assert!(out.contains("std::panic::catch_unwind"), "{out}");
        // A total return has no error channel: abort, NEVER fabricate a Default.
        assert!(out.contains("std::process::abort()"), "{out}");
        assert!(!out.contains("Default::default"), "{out}");
        // Sentinel bracketing so DCE can drop an unreached adapter by name.
        assert!(out.contains("// IPE-FFI-WRAPPER BEGIN update_fn"), "{out}");
    }

    #[test]
    fn closure_adapter_result_return_folds_the_panic_in_band() {
        let out = closure_region("Fn(Int) -> Result<Int, Error> + Send + Sync + 'static");
        assert!(
            out.contains(
                "pub type UpdateFnClosure = \
                 Box<dyn Fn(i64) -> Result<i64, IpeError> + Send + Sync + 'static>;"
            ),
            "{out}"
        );
        assert!(out.contains("-> UpdateFnClosure {"), "{out}");
        // A fallible return folds a panic to Err — never aborts.
        assert!(
            out.contains(
                "Err(__p) => Err(ipe_error_from_panic(\"foreign closure panicked\", __p))"
            ),
            "{out}"
        );
        assert!(!out.contains("std::process::abort()"), "{out}");
    }

    #[test]
    fn closure_adapter_option_return_folds_the_panic_to_none() {
        let out = closure_region("Fn(Int) -> Option<Int> + Send + Sync + 'static");
        assert!(
            out.contains(
                "pub type UpdateFnClosure = \
                 Box<dyn Fn(i64) -> Option<i64> + Send + Sync + 'static>;"
            ),
            "{out}"
        );
        assert!(out.contains("-> UpdateFnClosure {"), "{out}");
        assert!(
            out.contains(
                "Err(__p) => { note_foreign_panic(\"foreign closure panicked\", __p); None }"
            ),
            "{out}"
        );
        assert!(!out.contains("std::process::abort()"), "{out}");
    }

    // ── async-returning closure adapters ───────────────────────────────────

    #[test]
    fn closure_adapter_async_result_return_spawns_and_folds_the_join_error() {
        let out = closure_region(
            "Fn(Int) -> impl Future<Output = Result<Int, Error>> + Send + Sync + 'static",
        );
        // Received box AND the handle alias carry the concrete boxed future the
        // `IpeTask` value holds — the SAME type on both sides (no E0308). The
        // inner `Send + 'static` is part of the type: it IS the
        // Send/'static-across-await proof, never re-derived.
        assert!(
            out.contains(
                "pub type UpdateFnClosure = Box<dyn Fn(i64) -> ::std::pin::Pin<Box<dyn \
                 ::std::future::Future<Output = Result<i64, IpeError>> + Send + 'static>> \
                 + Send + Sync + 'static>;"
            ),
            "{out}"
        );
        assert!(out.contains("-> UpdateFnClosure {"), "{out}");
        // The future is produced under catch_unwind (a production-panic yields an
        // immediate-error future), then awaited under the guarded spawn
        // choke-point so a poll-panic folds through its redacting join-error
        // funnel and a cancel aborts the inner task.
        assert!(out.contains("ffi_spawn_guarded(__fut)"), "{out}");
        // Both panic sites fold to Err — never abort, never fabricate: a
        // production-panic funnels the caught payload; a poll-panic rides the
        // choke-point's already-funnelled `Err`.
        assert!(
            out.contains(
                "let __e = ipe_error_from_panic(\"foreign closure panicked\", __p); \
                 return Box::pin(async move { Err(__e) });"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "match ffi_spawn_guarded(__fut).await { Ok(inner) => inner, Err(__e) => Err(__e) }"
            ),
            "{out}"
        );
        assert!(!out.contains("std::process::abort()"), "{out}");
    }

    #[test]
    fn closure_adapter_async_option_return_folds_the_join_error_to_none() {
        let out =
            closure_region("Fn(Int) -> impl Future<Output = Option<Int>> + Send + Sync + 'static");
        assert!(
            out.contains(
                "pub type UpdateFnClosure = Box<dyn Fn(i64) -> ::std::pin::Pin<Box<dyn \
                 ::std::future::Future<Output = Option<i64>> + Send + 'static>> \
                 + Send + Sync + 'static>;"
            ),
            "{out}"
        );
        assert!(out.contains("-> UpdateFnClosure {"), "{out}");
        assert!(out.contains("ffi_spawn_guarded(__fut)"), "{out}");
        // A production-panic and a poll-panic both fold to None. The poll-panic
        // is redacted+logged inside the choke-point's funnel, so the Option
        // shape just maps its `Err` to `None`.
        assert!(
            out.contains(
                "Err(__p) => { note_foreign_panic(\"foreign closure panicked\", __p); \
                 return Box::pin(async move { None }); }"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "match ffi_spawn_guarded(__fut).await { Ok(inner) => inner, Err(_) => None }"
            ),
            "{out}"
        );
    }

    // ── opaque-return closure adapters (opaque-map threaded) ───────────────

    /// A package with an inspected fn (which seeds the opaque-map) PLUS a
    /// closure adapter whose signature names that opaque. `opaque_rust` is the
    /// real inspected Rust type the fn returns (`semver::Version`,
    /// `iced::Element<'a, Message>`, …).
    fn closure_region_with_inspected_opaque(sig: &str, opaque_rust: &str) -> String {
        let pkg = semver_pkg(&json!([
            {
                "name": "make",
                "params": [],
                "results": [{ "name": "", "type": "Handle", "rustType": opaque_rust }],
                "effect": "pure"
            },
            {
                "name": "update_fn",
                "effect": "pure",
                "isClosureAdapter": true,
                "closureSig": sig
            }
        ]));
        emit_bindings(&pkg)
    }

    #[test]
    fn a_define_defined_opaque_return_resolves_to_the_in_module_name() {
        // A closure returning a define-DEFINED type (defined in the same
        // `pub mod <slug>` region) resolves to the bare in-module name — it is
        // in scope beside the emitted `pub struct`, so no path is needed.
        let pkg = semver_pkg(&json!([
            {
                "name": "counter_new",
                "effect": "pure",
                "isStructCtor": true,
                "structName": "Counter",
                "structFields": [{ "name": "value", "type": "i64" }],
                "structDerives": ["Clone"]
            },
            {
                "name": "update_fn",
                "effect": "pure",
                "isClosureAdapter": true,
                "closureSig": "Fn(Counter) -> Result<Counter, Error> + Send + Sync + 'static"
            }
        ]));
        let out = emit_bindings(&pkg);
        // The received box AND the handle alias both name the in-module `Counter`.
        assert!(
            out.contains(
                "pub type UpdateFnClosure = Box<dyn Fn(Counter) -> Result<Counter, \
                 IpeError> + Send + Sync + 'static>;"
            ),
            "the alias names the in-module `Counter`:\n{out}"
        );
        assert!(
            out.contains(
                "pub fn semver_update_fn(__ipe_fn: Box<dyn Fn(Counter) -> Result<Counter, \
                 IpeError> + Send + Sync + 'static>) -> UpdateFnClosure {"
            ),
            "the received box names the in-module `Counter`; the return is the handle:\n{out}"
        );
        assert!(
            out.contains(
                "Err(__p) => Err(ipe_error_from_panic(\"foreign closure panicked\", __p))"
            ),
            "{out}"
        );
    }

    #[test]
    fn an_inspected_non_generic_opaque_return_resolves_to_its_absolute_path() {
        // An INSPECTED crate-opaque (`semver::Version`, no generic args)
        // resolves to its absolute `::semver::Version` path — never a bare
        // `Version` that would fold onto a re-exported runtime kernel module.
        let out = closure_region_with_inspected_opaque(
            "Fn(Int) -> Option<Version> + Send + Sync + 'static",
            "semver::Version",
        );
        // The inspected opaque return absolutizes on BOTH the alias and the
        // received box — the same resolved carrier, so their paths cannot skew.
        assert!(
            out.contains(
                "pub type UpdateFnClosure = Box<dyn Fn(i64) -> \
                 Option<::semver::Version> + Send + Sync + 'static>;"
            ),
            "the alias absolutizes the opaque return:\n{out}"
        );
        assert!(
            out.contains(
                "pub fn semver_update_fn(__ipe_fn: Box<dyn Fn(i64) -> \
                 Option<::semver::Version> + Send + Sync + 'static>) -> UpdateFnClosure {"
            ),
            "the received box absolutizes the opaque return:\n{out}"
        );
        assert!(
            out.contains(
                "Err(__p) => { note_foreign_panic(\"foreign closure panicked\", __p); None }"
            ),
            "{out}"
        );
    }

    #[test]
    fn a_lifetime_parameterised_opaque_return_over_drops_the_whole_adapter() {
        // The marquee Iced `view : Model -> Element Message` case: `Element` is
        // inspected as `iced::Element<'a, Message>` — a generic, lifetime-
        // parameterised handle the bare-handle carrier cannot carry. Emitting
        // the stripped path `::iced::Element` would be an E0107, so the adapter
        // OVER-DROPS (emits nothing) rather than breach the SEAL.
        let out = closure_region_with_inspected_opaque(
            "Fn(Counter) -> Result<Element, Error> + Send + Sync + 'static",
            "iced::Element<'a, Message>",
        );
        assert!(
            !out.contains("semver_update_fn"),
            "a parameterised opaque return must over-drop the adapter:\n{out}"
        );
        assert!(
            !out.contains("// IPE-FFI-WRAPPER BEGIN update_fn"),
            "no wrapper region is emitted for the over-dropped adapter:\n{out}"
        );
        // The over-drop is silent — the survivor gate agrees (no phantom).
        let pkg = semver_pkg(&json!([
            {
                "name": "make",
                "params": [],
                "results": [{ "name": "", "type": "Handle",
                              "rustType": "iced::Element<'a, Message>" }],
                "effect": "pure"
            },
            {
                "name": "update_fn",
                "effect": "pure",
                "isClosureAdapter": true,
                "closureSig": "Fn(Counter) -> Result<Element, Error> + Send + Sync + 'static"
            }
        ]));
        assert!(
            !surviving_ref_names(&pkg).contains("update_fn"),
            "the survivor gate must not admit the over-dropped adapter"
        );
    }

    #[test]
    fn an_unresolvable_opaque_return_over_drops_the_whole_adapter() {
        // An opaque name that is neither define-defined nor inspected anywhere
        // in the crate cannot resolve to any nameable path — over-drop rather
        // than emit a bare handle no `pub mod <slug>` region can name.
        let out = closure_region("Fn(Int) -> Result<Ghost, Error> + Send + Sync + 'static");
        assert!(
            !out.contains("semver_update_fn"),
            "an unresolvable opaque return must over-drop the adapter:\n{out}"
        );
    }

    #[test]
    fn an_unresolvable_opaque_param_over_drops_the_whole_adapter() {
        // The over-drop covers opaque PARAMETERS too — a param the wrapper
        // could not name is as unbuildable as an unnameable return.
        let out = closure_region("Fn(Ghost) -> Int + Send + Sync + 'static");
        assert!(
            !out.contains("semver_update_fn"),
            "an unresolvable opaque param must over-drop the adapter:\n{out}"
        );
    }

    #[test]
    fn struct_ctor_emits_the_derived_definition_and_a_constructor() {
        let out = emit_bindings(&semver_pkg(&json!([{
            "name": "counter_new",
            "effect": "pure",
            "isStructCtor": true,
            "structName": "Counter",
            "structFields": [{ "name": "value", "type": "i64" }],
            "structDerives": ["Default", "Clone"]
        }])));
        // The `#[derive]`ed definition (canonical derive order).
        assert!(out.contains("#[derive(Clone, Default)]"), "{out}");
        assert!(out.contains("pub struct Counter {"), "{out}");
        assert!(out.contains("    pub value: i64,"), "{out}");
        // The constructor wrapper folds each owned-carrier arg into the literal.
        assert!(
            out.contains("pub fn semver_counter_new(arg0: i64) -> Counter {"),
            "{out}"
        );
        assert!(out.contains("Counter { value: arg0 }"), "{out}");
        // Sentinel bracketing so DCE can drop an unreached ctor by name.
        assert!(
            out.contains("// IPE-FFI-WRAPPER BEGIN counter_new"),
            "{out}"
        );
    }

    /// A param/result carrying only its foreign `type` (no `ipeType`, no
    /// `rustType`) takes the same Ipê type the interface signature declares
    /// (`emit::param_ipe_type`), so the wrapper and the `Rust.<Crate>`
    /// forwarder agree on `i64`, never the `String` opaque fallback.
    #[test]
    fn a_type_only_param_and_result_match_the_interface_signature() {
        let pkg = semver_pkg(&json!([{
            "name": "shift",
            "params": [{"name": "n", "type": "i64"}],
            "results": [{"name": "", "type": "i64"}],
            "effect": "pure"
        }]));
        let f = pkg.fns().first().expect("one fn");
        assert_eq!(
            crate::emit::wrapper_ipe_signature(f),
            "Int -> Result Error Int"
        );
        let out = emit_bindings(&pkg);
        assert!(
            out.contains("pub fn semver_shift(arg0: i64) -> IpeResult<IpeError, i64> {"),
            "{out}"
        );
        assert!(out.contains("::semver::shift(arg0)"), "{out}");
    }

    #[test]
    fn struct_ctor_with_an_opaque_field_over_drops_no_wrapper() {
        // An opaque field needs the crate opaque-map to resolve to a nameable
        // path; that plumbing is a follow-up, so the entry over-drops at decode
        // rather than emit an unresolvable bare handle and break the SEAL.
        let out = emit_bindings(&semver_pkg(&json!([{
            "name": "wrap_new",
            "effect": "pure",
            "isStructCtor": true,
            "structName": "Wrap",
            "structFields": [{ "name": "inner", "type": "Version" }],
            "structDerives": []
        }])));
        assert!(!out.contains("pub struct Wrap"), "{out}");
        assert!(!out.contains("semver_wrap_new"), "{out}");
    }

    #[test]
    fn struct_ctor_derive_free_scalar_struct_emits() {
        // The derive-free case: no `#[derive]` line, a scalar field, a ctor.
        let out = emit_bindings(&semver_pkg(&json!([{
            "name": "point_new",
            "effect": "pure",
            "isStructCtor": true,
            "structName": "Point",
            "structFields": [
                { "name": "x", "type": "i64" },
                { "name": "y", "type": "i64" }
            ],
            "structDerives": []
        }])));
        assert!(!out.contains("#[derive"), "{out}");
        assert!(out.contains("pub struct Point {"), "{out}");
        assert!(out.contains("    pub x: i64,"), "{out}");
        assert!(out.contains("    pub y: i64,"), "{out}");
        assert!(
            out.contains("pub fn semver_point_new(arg0: i64, arg1: i64) -> Point {"),
            "{out}"
        );
        assert!(out.contains("Point { x: arg0, y: arg1 }"), "{out}");
    }

    #[test]
    fn enum_def_emits_the_derived_definition_and_per_variant_constructors() {
        // The Iced/TEA `Message` shape: unit variants + a tuple-payload one.
        let out = emit_bindings(&semver_pkg(&json!([{
            "name": "message",
            "effect": "pure",
            "isEnumDef": true,
            "enumName": "Message",
            "enumVariants": [
                { "name": "Increment", "payload": [] },
                { "name": "Decrement", "payload": [] },
                { "name": "SetValue", "payload": ["i64"] }
            ],
            "enumDerives": ["Clone"]
        }])));
        assert!(out.contains("#[derive(Clone)]"), "{out}");
        assert!(out.contains("pub enum Message {"), "{out}");
        assert!(out.contains("    Increment,"), "{out}");
        assert!(out.contains("    SetValue(i64),"), "{out}");
        // One constructor per variant, `<ctor>_<snake(variant)>`.
        assert!(
            out.contains("pub fn semver_message_increment(_: ()) -> Message {"),
            "{out}"
        );
        assert!(out.contains("Message::Increment"), "{out}");
        assert!(
            out.contains("pub fn semver_message_set_value(arg0: i64) -> Message {"),
            "{out}"
        );
        assert!(out.contains("Message::SetValue(arg0)"), "{out}");
        // Sentinel bracketing so DCE can drop the region by name.
        assert!(out.contains("// IPE-FFI-WRAPPER BEGIN message"), "{out}");
    }

    #[test]
    fn enum_def_with_an_opaque_payload_over_drops_no_wrapper() {
        // An opaque payload needs the crate opaque-map to resolve to a nameable
        // path; that plumbing is a follow-up, so the entry over-drops at decode
        // rather than emit an unresolvable bare handle and break the SEAL.
        let out = emit_bindings(&semver_pkg(&json!([{
            "name": "wrap",
            "effect": "pure",
            "isEnumDef": true,
            "enumName": "Wrap",
            "enumVariants": [{ "name": "Hold", "payload": ["Version"] }],
            "enumDerives": []
        }])));
        assert!(!out.contains("pub enum Wrap"), "{out}");
        assert!(!out.contains("semver_wrap_hold"), "{out}");
    }

    #[test]
    fn pure_display_bridge_takes_impl_display_and_catches_unwind() {
        let pkg = semver_pkg(&json!([{
            "name": "to_string",
            "params": [{"name": "self", "type": "Version", "ipeType": "Version", "rustType": "&Version"}],
            "results": [{"name": "", "type": "String", "rustType": "String"}],
            "effect": "pure",
            "recvType": "Version",
            "recvRustType": "semver::Version",
            "methodName": "to_string"
        }]));
        let out = emit_bindings(&pkg);
        assert!(
            out.contains(
                "pub fn semver_to_string_from_version(arg0: impl std::fmt::Display) -> IpeResult<IpeError, String> {"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || arg0.to_string())) { Ok(v) => ok_res(v), Err(__p) => IpeResult::Err(ipe_error_from_panic(\"foreign call panicked\", __p)) }"
            ),
            "{out}"
        );
    }

    #[test]
    fn effectful_method_owns_the_borrowed_opaque_receiver_param_and_spawns() {
        let pkg = decode(&json!({
            "pkg": "db",
            "name": "db",
            "functions": [{
                "name": "get",
                "params": [
                    {"name": "self", "type": "Db", "ipeType": "Db", "rustType": "&Db"},
                    {"name": "key", "type": "String", "ipeType": "String", "rustType": "&str"}
                ],
                "results": [{"name": "", "type": "Result Error String", "rustType": "Result<String, Error>"}],
                "effect": "effectful",
                "recvType": "Db",
                "recvRustType": "db::Db",
                "methodName": "get"
            }],
            "errors": []
        }));
        let out = emit_bindings(&pkg);
        // The `&Db` foreign param is declared OWNED (async 'static escape).
        assert!(
            out.contains("pub fn db_get_from_db(mut arg0: Db, arg1: String) -> IpeTask<String> {"),
            "{out}"
        );
        // Fallible async: guarded spawn choke-point (arms the abort-on-drop and
        // funnels the JoinError as one step), three arms, typed foreign-error
        // fold, the funnelled JoinError riding the trailing `Err(e)` arm.
        assert!(
            out.contains(
                "Box::pin(async move { match ffi_spawn_guarded(async move { arg0.get(arg1.as_ref()).await }).await { Ok(Ok(v)) => ok_res(v), Ok(Err(e)) => IpeResult::Err(ipe_error_from_foreign(e)), Err(e) => IpeResult::Err(e) } })"
            ),
            "{out}"
        );
    }

    #[test]
    fn infallible_async_spawns_with_two_arms() {
        let pkg = decode(&json!({
            "pkg": "svc",
            "name": "svc",
            "functions": [{
                "name": "ping",
                "params": [],
                "results": [{"name": "", "type": "String", "rustType": "String"}],
                "effect": "effectful"
            }],
            "errors": []
        }));
        let out = emit_bindings(&pkg);
        assert!(
            out.contains(
                "Box::pin(async move { match ffi_spawn_guarded(async move { ::svc::ping().await }).await { Ok(v) => ok_res(v), Err(e) => IpeResult::Err(e) } })"
            ),
            "{out}"
        );
        assert!(
            out.contains("pub fn svc_ping(_: ()) -> IpeTask<String> {"),
            "{out}"
        );
    }

    #[test]
    fn self_returning_setter_threads_the_owned_receiver() {
        let pkg = decode(&json!({
            "pkg": "chrono",
            "name": "chrono",
            "functions": [{
                "name": "insert",
                "params": [
                    {"name": "self", "type": "WeekdaySet", "ipeType": "WeekdaySet", "rustType": "WeekdaySet"},
                    {"name": "day", "type": "Weekday", "ipeType": "Weekday", "rustType": "Weekday"}
                ],
                "results": [{"name": "", "type": "WeekdaySet", "rustType": "()"}],
                "effect": "pure",
                "recvType": "WeekdaySet",
                "recvRustType": "chrono::WeekdaySet",
                "methodName": "insert",
                "selfReturning": true
            }],
            "errors": []
        }));
        let out = emit_bindings(&pkg);
        assert!(
            out.contains(
                "match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || { arg0.insert(arg1); arg0 })) { Ok(r) => ok_res(r), Err(__p) => IpeResult::Err(ipe_error_from_panic(\"foreign call panicked\", __p)) }"
            ),
            "{out}"
        );
    }

    #[test]
    fn borrow_reader_threads_the_receiver_back_beside_the_result() {
        // A `&self` reader (receiver `rustType` begins with `&`) hands `arg0`
        // back beside the coerced result: the return type is `(i64, Widget)`
        // and the body pairs the value with the receiver.
        let pkg = decode(&json!({
            "pkg": "handle_demo",
            "name": "handle_demo",
            "functions": [{
                "name": "slot_count",
                "params": [
                    {"name": "self", "type": "Widget", "ipeType": "Widget", "rustType": "&handle_demo::Widget"}
                ],
                "results": [{"name": "", "type": "Int", "rustType": "usize"}],
                "effect": "pure",
                "recvType": "Widget",
                "recvRustType": "handle_demo::Widget",
                "methodName": "slot_count"
            }],
            "errors": []
        }));
        let out = emit_bindings(&pkg);
        assert!(
            out.contains(
                "pub fn handle_demo_slot_count_from_widget(mut arg0: ::handle_demo::Widget) -> IpeResult<IpeError, (i64, ::handle_demo::Widget)> {"
            ),
            "{out}"
        );
        assert!(
            out.contains("let __r = arg0.slot_count(); (__r, arg0)"),
            "{out}"
        );
        assert!(out.contains("Ok((v, recv)) => ok_res(("), "{out}");
    }

    #[test]
    fn tuple_return_coerces_every_component_to_its_carrier() {
        // `(u64, u32)` declares `(i64, i64)` and destructures the raw tuple,
        // widening each component: the wide unsigned saturates, the narrow one
        // is a plain `as i64`.
        let (decl, co) = translate_rust_ret("(u64, u32)");
        assert_eq!(decl, "(i64, i64)");
        assert_eq!(
            co("r"),
            "{ let (t0, t1) = r; ((t0).min(i64::MAX as u64) as i64, (t1) as i64) }"
        );
    }

    #[test]
    fn tuple_predicate_admits_owned_string_and_bool_components() {
        // Owned `String` and `bool` components ARE wired — each an identity
        // coercion whose declared carrier (`String` / `bool`) matches the Ipê
        // surface (`String` / `Bool`). A tuple mixing numeric + String + bool
        // whose `ipe_type` override agrees is admitted.
        let mixed = decode(&json!({
            "pkg": "grid", "name": "grid",
            "functions": [{
                "name": "labelled",
                "params": [],
                "results": [{"name": "", "type": "(Int, String, Bool)",
                             "rustType": "(u32, String, bool)"}],
                "effect": "pure",
                "methodName": ""
            }],
            "errors": []
        }));
        let mf = mixed.fns().first().expect("one fn");
        assert!(
            multi_result_tuple_is_coercible(mf),
            "owned String + bool components must admit"
        );
    }

    #[test]
    fn tuple_predicate_rejects_a_borrowed_or_opaque_component() {
        // A `&str` borrow, an opaque handle, and a nested container each stay
        // refused — none is an owned scalar/String/bool the tuple emitter can
        // coerce, so admitting them would break the SEAL.
        for (rust, ipe) in [
            ("(u32, &str)", "(Int, String)"),
            ("(u32, Version)", "(Int, Version)"),
            ("(u32, Vec<u8>)", "(Int, List Int)"),
        ] {
            let pkg = decode(&json!({
                "pkg": "grid", "name": "grid",
                "functions": [{
                    "name": "labelled",
                    "params": [],
                    "results": [{"name": "", "type": ipe, "rustType": rust}],
                    "effect": "pure",
                    "methodName": ""
                }],
                "errors": []
            }));
            let f = pkg.fns().first().expect("one fn");
            assert!(
                !multi_result_tuple_is_coercible(f),
                "component `{rust}` must not admit"
            );
        }
    }

    #[test]
    fn tuple_predicate_refuses_a_component_carrier_mismatch() {
        // The Ipê `ipe_type` override MUST agree with the emitted Rust carriers,
        // or the signature would declare a type the wrapper does not produce (an
        // exit-0-then-cargo-fail). Here the override claims `(Int, Int)` but the
        // Rust tuple is `(u64, String)` — refuse fail-closed.
        let pkg = decode(&json!({
            "pkg": "grid", "name": "grid",
            "functions": [{
                "name": "labelled",
                "params": [],
                "results": [{"name": "", "type": "", "ipeType": "(Int, Int)",
                             "rustType": "(u64, String)"}],
                "effect": "pure",
                "methodName": ""
            }],
            "errors": []
        }));
        let f = pkg.fns().first().expect("one fn");
        assert!(
            !multi_result_tuple_is_coercible(f),
            "a carrier/override mismatch must refuse fail-closed"
        );
    }

    #[test]
    fn tuple_predicate_refuses_a_tuple_with_no_ipe_override_it_cannot_synthesise() {
        // `foreign_to_ipe` does NOT recurse into a tuple string, so a tuple whose
        // `type`/`ipeType` is a RAW Rust spelling (no Ipê carriers) cannot yield a
        // lowerable signature — refuse rather than emit `(u64, u32)` into `.ipei`.
        let pkg = decode(&json!({
            "pkg": "grid", "name": "grid",
            "functions": [{
                "name": "raw_tuple",
                "params": [],
                "results": [{"name": "", "type": "(u64, u32)", "rustType": "(u64, u32)"}],
                "effect": "pure",
                "methodName": ""
            }],
            "errors": []
        }));
        let f = pkg.fns().first().expect("one fn");
        assert!(
            !multi_result_tuple_is_coercible(f),
            "a raw-Rust-spelled tuple with no Ipê carrier override must refuse"
        );
    }

    #[test]
    fn plain_multi_result_tuple_binds_with_per_component_coercion() {
        // A plain (non-reader, non-setter) free fn returning `(u64, u32)` now
        // binds: the wrapper declares `(i64, i64)` and coerces each slot.
        let pkg = decode(&json!({
            "pkg": "geo", "name": "geo",
            "functions": [{
                "name": "bounds",
                "params": [],
                "results": [{"name": "", "type": "(Int, Int)", "rustType": "(u64, u32)"}],
                "effect": "pure",
                "methodName": ""
            }],
            "errors": []
        }));
        let f = pkg.fns().first().expect("one fn");
        assert!(
            multi_result_tuple_is_coercible(f),
            "all-numeric tuple must admit"
        );
        let out = emit_bindings(&pkg);
        assert!(
            out.contains("-> IpeResult<IpeError, (i64, i64)> {"),
            "{out}"
        );
        assert!(
            out.contains(
                "{ let (t0, t1) = ::geo::bounds(); ((t0).min(i64::MAX as u64) as i64, (t1) as i64) }"
            ),
            "{out}"
        );
    }

    #[test]
    fn an_opaque_field_getter_contains_the_foreign_clone() {
        // A non-Copy opaque field's `.clone()` dispatches into the crate's own
        // `Clone` impl — foreign code — so the getter body runs under
        // catch_unwind and a caught panic funnel-logs then aborts (the bare
        // return has no error channel).
        let pkg = semver_pkg(&json!([{
            "name": "build_field",
            "params": [{"name": "self", "type": "Version", "ipeType": "Version", "rustType": "&Version"}],
            "results": [{"name": "", "type": "BuildMetadata", "rustType": "semver::BuildMetadata"}],
            "effect": "pure",
            "recvType": "Version",
            "recvRustType": "semver::Version",
            "methodName": "build",
            "isField": true
        }]));
        let out = emit_bindings(&pkg);
        assert!(
            out.contains(
                "pub fn semver_build_field_from_version(arg0: ::semver::Version) -> ::semver::BuildMetadata {"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || \
                 arg0.build.clone())) { Ok(v) => v, Err(__p) => { \
                 note_foreign_panic(\"foreign `Clone` panicked in field getter \
                 `semver_build_field_from_version`; aborting (field getter has no error \
                 channel)\", __p); std::process::abort(); } }"
            ),
            "{out}"
        );
    }

    #[test]
    fn an_unqualified_opaque_field_getter_still_gets_the_boundary() {
        // Fail-closed classification: a field type that is not provably
        // std-owned gets the panic boundary even when its rustType arrives
        // unqualified (no `::crate::` path to key off).
        let pkg = semver_pkg(&json!([{
            "name": "build_field",
            "params": [{"name": "self", "type": "Version", "ipeType": "Version", "rustType": "&Version"}],
            "results": [{"name": "", "type": "BuildMetadata", "rustType": "BuildMetadata"}],
            "effect": "pure",
            "recvType": "Version",
            "recvRustType": "semver::Version",
            "methodName": "build",
            "isField": true
        }]));
        let out = emit_bindings(&pkg);
        assert!(
            out.contains("note_foreign_panic(\"foreign `Clone` panicked in field getter"),
            "an unrecognised field type must not slip past the boundary:\n{out}"
        );
    }

    #[test]
    fn a_std_field_getter_stays_bare() {
        // A `String` field's `.clone()` runs no foreign code, so the getter
        // keeps its bare, boundary-free body.
        let pkg = semver_pkg(&json!([{
            "name": "pre_field",
            "params": [{"name": "self", "type": "Version", "ipeType": "Version", "rustType": "&Version"}],
            "results": [{"name": "", "type": "String", "rustType": "String"}],
            "effect": "pure",
            "recvType": "Version",
            "recvRustType": "semver::Version",
            "methodName": "pre",
            "isField": true
        }]));
        let out = emit_bindings(&pkg);
        assert!(
            out.contains(
                "pub fn semver_pre_field_from_version(arg0: ::semver::Version) -> String {\n    \
                 arg0.pre.clone()\n}"
            ),
            "{out}"
        );
    }

    #[test]
    fn field_setter_replaces_the_field_with_a_saturating_write() {
        let pkg = semver_pkg(&json!([{
            "name": "patch_set_field",
            "params": [
                {"name": "value", "type": "Int", "ipeType": "Int", "rustType": "u32"},
                {"name": "self", "type": "Version", "ipeType": "Version", "rustType": "semver::Version"}
            ],
            "results": [{"name": "", "type": "Version", "rustType": "semver::Version"}],
            "effect": "pure",
            "recvType": "Version",
            "recvRustType": "semver::Version",
            "methodName": "patch",
            "isFieldSet": true
        }]));
        let out = emit_bindings(&pkg);
        assert!(
            out.contains(
                "pub fn semver_patch_set_field_from_version(arg0: i64, arg1: ::semver::Version) -> ::semver::Version {"
            ),
            "{out}"
        );
        assert!(
            out.contains("    r.patch = (arg0).clamp(0, u32::MAX as i64) as u32;"),
            "{out}"
        );
        assert!(out.contains("    let mut r = arg1;"), "{out}");
    }

    #[test]
    fn fallible_field_setter_renders_checked_conversion() {
        // A narrowing integer field's setter is FALLIBLE: `try_from` + typed
        // Err on out-of-range, never a silent truncation. Both the bare and
        // the `Option<>`-wrapped shapes render checked bodies.
        let pkg = semver_pkg(&json!([
            {
                "name": "patch_set_field",
                "params": [
                    {"name": "value", "type": "Int", "ipeType": "Int", "rustType": "u32"},
                    {"name": "self", "type": "Version", "ipeType": "Version", "rustType": "semver::Version"}
                ],
                "results": [{"name": "", "type": "Version", "rustType": "semver::Version"}],
                "effect": "fallible",
                "recvType": "Version",
                "recvRustType": "semver::Version",
                "methodName": "patch",
                "isFieldSet": true
            },
            {
                "name": "build_set_field",
                "params": [
                    {"name": "value", "type": "Maybe Int", "ipeType": "Maybe Int", "rustType": "Option<u64>"},
                    {"name": "self", "type": "Version", "ipeType": "Version", "rustType": "semver::Version"}
                ],
                "results": [{"name": "", "type": "Version", "rustType": "semver::Version"}],
                "effect": "fallible",
                "recvType": "Version",
                "recvRustType": "semver::Version",
                "methodName": "build",
                "isFieldSet": true
            }
        ]));
        let out = emit_bindings(&pkg);
        assert!(
            out.contains(
                "pub fn semver_patch_set_field_from_version(arg0: i64, arg1: ::semver::Version) -> IpeResult<IpeError, ::semver::Version> {"
            ),
            "{out}"
        );
        assert!(out.contains("match u32::try_from(arg0) {"), "{out}");
        assert!(
            out.contains("Ok(v) => { let mut r = arg1; r.patch = v; ok_res(r) }"),
            "{out}"
        );
        assert!(
            out.contains("Err(e) => IpeResult::Err(ipe_error_from_foreign(e)),"),
            "{out}"
        );
        assert!(
            out.contains("match ipe_maybe_to_option(arg0).map(u64::try_from).transpose() {"),
            "{out}"
        );
    }

    #[test]
    fn enum_accessor_trio_renders_total_bodies() {
        let pkg = semver_pkg(&json!([
            {
                "name": "greater_new_variant",
                "params": [{"name": "f0", "type": "Int", "ipeType": "Int", "rustType": "u64"}],
                "results": [{"name": "", "type": "Op", "rustType": "semver::Op"}],
                "effect": "pure",
                "recvType": "Op",
                "recvRustType": "semver::Op",
                "isEnumCtor": true,
                "enumVariant": "Greater",
                "enumKind": "tuple"
            },
            {
                "name": "tag_of_op",
                "params": [{"name": "e", "type": "Op", "ipeType": "Op", "rustType": "semver::Op"}],
                "results": [{"name": "", "type": "String", "rustType": "String"}],
                "effect": "pure",
                "recvRustType": "semver::Op",
                "methodName": "tag_of_op",
                "isEnumTag": true,
                "enumArms": ["Exact\tExact", "Greater(..)\tGreater", "match\tmatch"],
                "enumWildcard": true
            },
            {
                "name": "value_as_greater",
                "params": [{"name": "e", "type": "Op", "ipeType": "Op", "rustType": "semver::Op"}],
                "results": [{"name": "", "type": "Maybe Int", "rustType": "Option<u64>"}],
                "effect": "pure",
                "recvType": "Op",
                "recvRustType": "semver::Op",
                "isEnumExtract": true,
                "enumVariant": "Greater",
                "enumKind": "tuple",
                "enumStructFields": ["1"],
                "enumFieldCount": 2,
                "enumWildcard": true
            }
        ]));
        let out = emit_bindings(&pkg);
        // Ctor: saturating owned arg, absolute enum path.
        assert!(
            out.contains("pub fn semver_greater_new_variant_from_op(arg0: i64) -> ::semver::Op {"),
            "{out}"
        );
        assert!(
            out.contains("    ::semver::Op::Greater((arg0).max(0) as u64)"),
            "{out}"
        );
        // Tag: one &str match with a keyword-safe arm and a gated wildcard.
        assert!(out.contains("    let t: &str = match arg0 {"), "{out}");
        assert!(
            out.contains("        ::semver::Op::Exact => \"Exact\","),
            "{out}"
        );
        assert!(
            out.contains("        ::semver::Op::Greater(..) => \"Greater\","),
            "{out}"
        );
        assert!(
            out.contains("        ::semver::Op::r#match => \"match\","),
            "{out}"
        );
        assert!(out.contains("        _ => \"<unknown>\","), "{out}");
        assert!(out.contains("    t.to_string()"), "{out}");
        // Extract: binds only the selected tuple position, widens the payload.
        assert!(
            out.contains(
                "        ::semver::Op::Greater(_, f1) => IpeMaybe::Just((f1).min(i64::MAX as u64) as i64),"
            ),
            "{out}"
        );
        assert!(out.contains("        _ => IpeMaybe::Nothing,"), "{out}");
        assert!(
            out.contains(
                "pub fn semver_value_as_greater_from_op(arg0: ::semver::Op) -> IpeMaybe<i64> {"
            ),
            "{out}"
        );
    }

    #[test]
    fn struct_variant_ctor_and_extract_use_named_fields() {
        let pkg = semver_pkg(&json!([
            {
                "name": "point_new_variant",
                "params": [
                    {"name": "x", "type": "Int", "ipeType": "Int", "rustType": "i64"},
                    {"name": "type", "type": "String", "ipeType": "String", "rustType": "String"}
                ],
                "results": [{"name": "", "type": "Shape", "rustType": "semver::Shape"}],
                "effect": "pure",
                "recvType": "Shape",
                "recvRustType": "semver::Shape",
                "isEnumCtor": true,
                "enumVariant": "Point",
                "enumKind": "struct",
                "enumStructFields": ["x", "type"]
            },
            {
                "name": "x_as_point",
                "params": [{"name": "e", "type": "Shape", "ipeType": "Shape", "rustType": "semver::Shape"}],
                "results": [{"name": "", "type": "Maybe Int", "rustType": "Option<i64>"}],
                "effect": "pure",
                "recvType": "Shape",
                "recvRustType": "semver::Shape",
                "isEnumExtract": true,
                "enumVariant": "Point",
                "enumKind": "struct",
                "enumStructFields": ["x"],
                "enumFieldCount": 2,
                "enumWildcard": true
            }
        ]));
        let out = emit_bindings(&pkg);
        assert!(
            out.contains("    ::semver::Shape::Point { x: arg0, r#type: arg1 }"),
            "{out}"
        );
        assert!(
            out.contains("        ::semver::Shape::Point { x, .. } => IpeMaybe::Just((x) as i64),"),
            "{out}"
        );
    }

    #[test]
    fn fixed_array_param_binds_a_fallible_prelude_local() {
        let pkg = decode(&json!({
            "pkg": "uuid",
            "name": "uuid",
            "functions": [{
                "name": "from_bytes",
                "params": [{"name": "b", "type": "List Int", "ipeType": "List Int", "rustType": "[u8; 16]"}],
                "results": [{"name": "", "type": "Uuid", "rustType": "Uuid"}],
                "effect": "pure"
            }],
            "errors": []
        }));
        let out = emit_bindings(&pkg);
        assert!(
            out.contains(
                "    let b0: [u8; 16] = match to_u8_array::<IpeError, 16>(&arg0) { IpeResult::Ok(a) => a, IpeResult::Err(e) => return IpeResult::Err(e), };"
            ),
            "{out}"
        );
        assert!(out.contains("::uuid::from_bytes(b0)"), "{out}");
        assert!(out.contains("(arg0: Vec<i64>)"), "{out}");
    }

    #[test]
    fn serde_param_deserialises_in_the_prelude_sync_and_inside_async() {
        let sync_pkg = decode(&json!({
            "pkg": "js",
            "name": "js",
            "functions": [{
                "name": "merge",
                "params": [{"name": "v", "type": "String", "ipeType": "String", "rustType": "serde_json::Value"}],
                "results": [{"name": "", "type": "String", "rustType": "serde_json::Value"}],
                "effect": "pure"
            }],
            "errors": []
        }));
        let out = emit_bindings(&sync_pkg);
        assert!(
            out.contains(
                "    let sv_0: serde_json::Value = match serde_json::from_str::<serde_json::Value>(&arg0) { Ok(v) => v, Err(e) => return IpeResult::Err(ipe_error_from_foreign(e)), };"
            ),
            "{out}"
        );
        // Serde-reduced return: turbofish + JSON-text lift.
        assert!(
            out.contains("::js::merge::<serde_json::Value>(sv_0)"),
            "{out}"
        );
        assert!(
            out.contains("serde_json::to_string(&(v)).unwrap_or_default()")
                || out.contains("serde_json::to_string"),
            "{out}"
        );

        let async_pkg = decode(&json!({
            "pkg": "js",
            "name": "js",
            "functions": [{
                "name": "push",
                "params": [{"name": "v", "type": "String", "ipeType": "String", "rustType": "serde_json::Value"}],
                "results": [{"name": "", "type": "Result Error ()", "rustType": "Result<(), Error>"}],
                "effect": "effectful"
            }],
            "errors": []
        }));
        let out = emit_bindings(&async_pkg);
        // The early-return prelude must live INSIDE the async block so its
        // `return IpeResult::Err` matches the block's type, not the IpeTask.
        assert!(
            out.contains("Box::pin(async move { let sv_0: serde_json::Value ="),
            "{out}"
        );
    }

    // ── drop cases: emit nothing, never a wrapper cargo rejects ─────────

    #[test]
    fn degenerate_and_generic_receivers_and_trait_fns_emit_nothing() {
        let pkg = decode(&json!({
            "pkg": "chrono",
            "name": "chrono",
            "functions": [
                {
                    "name": "orphan",
                    "params": [{"name": "self", "type": "Foo", "ipeType": "Foo", "rustType": "&Foo"}],
                    "results": [{"name": "", "type": "Int", "rustType": "i64"}],
                    "effect": "pure"
                },
                {
                    "name": "num_days",
                    "params": [{"name": "self", "type": "DateTime", "ipeType": "DateTime", "rustType": "&DateTime<Tz>"}],
                    "results": [{"name": "", "type": "Int", "rustType": "i64"}],
                    "effect": "pure",
                    "recvType": "DateTime",
                    "recvRustType": "chrono::DateTime<Tz>",
                    "methodName": "num_days"
                },
                {
                    "name": "keyed",
                    "params": [{"name": "v", "type": "Int", "ipeType": "Int", "rustType": "i64"}],
                    "results": [{"name": "", "type": "Int", "rustType": "i64"}],
                    "effect": "pure",
                    "generic": {
                        "params": ["a"],
                        "call": {
                            "kind": "function",
                            "path": ["::tm", "Circle"],
                            "method": "keyed",
                            "args": [0],
                            "argTypes": [{"param": 0}],
                            "ret": {"prim": "i64"},
                            "traitQualifier": ["::tm::Circle", "::tm::Scale"]
                        }
                    }
                },
                {
                    "name": "timestamp",
                    "params": [{"name": "self", "type": "DateTime", "ipeType": "DateTime", "rustType": "&DateTime<Utc>"}],
                    "results": [{"name": "", "type": "Int", "rustType": "i64"}],
                    "effect": "pure",
                    "recvType": "DateTime",
                    "recvRustType": "chrono::DateTime<Utc>",
                    "methodName": "timestamp"
                }
            ],
            "errors": []
        }));
        let out = emit_bindings(&pkg);
        assert!(!out.contains("orphan"), "{out}");
        assert!(!out.contains("num_days"), "{out}");
        assert!(!out.contains("keyed"), "{out}");
        // The CONCRETE generic receiver (DateTime<Utc>) is kept.
        assert!(out.contains("timestamp_from_dateTime"), "{out}");
    }

    /// A trait-qualified method with NO open type params (the async-trait
    /// surface: every param concrete, serde slots turbofished) is a CLOSED
    /// instance — it renders at add time through the instance synthesiser
    /// into a sentinel region, so the interface + DCE see a real wrapper.
    #[test]
    fn closed_trait_method_synthesises_into_a_sentinel_region() {
        let pkg = decode(&json!({
            "pkg": "firestore",
            "name": "firestore",
            "functions": [{
                "name": "get_obj",
                "params": [
                    {"name": "self", "type": "Db", "ipeType": "Db", "rustType": "&Db"},
                    {"name": "collection", "type": "String", "ipeType": "String", "rustType": "&str"},
                    {"name": "id", "type": "String", "ipeType": "String", "rustType": "&str"}
                ],
                "results": [{"name": "", "type": "String", "rustType": "serde_json::Value"}],
                "effect": "effectful",
                "recvType": "Db",
                "recvRustType": "firestore::Db",
                "methodName": "get_obj",
                "generic": {
                    "params": [],
                    "call": {
                        "kind": "method",
                        "path": ["::firestore", "Db"],
                        "method": "get_obj",
                        "receiver": {"arg": 0, "by": "ref"},
                        "args": [1, 2],
                        "argTypes": [
                            {"ctor": "::firestore::Db"},
                            {"prim": "String"},
                            {"prim": "String"}
                        ],
                        "ret": {"serdeValue": true},
                        "borrowAsRefArgs": [1, 2],
                        "traitQualifier": ["::firestore::Db", "::firestore::GetByIdSupport"],
                        "isAsync": true,
                        "methodTurbofish": [{"serdeValue": true}]
                    }
                }
            }],
            "errors": []
        }));
        let out = emit_bindings(&pkg);
        assert!(
            out.contains("// IPE-FFI-WRAPPER BEGIN get_obj_from_db"),
            "{out}"
        );
        assert!(
            out.contains("<::firestore::Db as ::firestore::GetByIdSupport>::get_obj"),
            "{out}"
        );
        // Async instance body: routed through the guarded spawn choke-point
        // (spawn + abort-on-drop + join-error funnel are its indivisible job).
        assert!(out.contains("ffi_spawn_guarded(async move {"), "{out}");
        assert!(
            surviving_ref_names(&pkg).contains("get_obj_from_db"),
            "the interface gate must see the synthesised region"
        );
    }

    #[test]
    fn static_generic_receiver_call_wraps_in_turbofish_angles() {
        let pkg = decode(&json!({
            "pkg": "chrono",
            "name": "chrono",
            "functions": [{
                "name": "now",
                "params": [{"name": "x", "type": "()", "ipeType": "()", "rustType": "()"}],
                "results": [{"name": "", "type": "DateTime", "rustType": "DateTime<Utc>"}],
                "effect": "pure",
                "recvType": "Utc",
                "recvRustType": "chrono::Utc",
                "methodName": "now"
            }],
            "errors": []
        }));
        let out = emit_bindings(&pkg);
        assert!(out.contains("::chrono::Utc::now("), "{out}");
    }

    // ── tri-artifact agreement ──────────────────────────────────────────

    #[test]
    fn sentinel_names_match_kernel_json_and_ipei_names() {
        let pkg = semver_pkg(&json!([
            {
                "name": "parse",
                "params": [{"name": "text", "type": "String", "ipeType": "String", "rustType": "&str"}],
                "results": [{"name": "", "type": "Result Error Version", "rustType": "Result<Version, Error>"}],
                "effect": "fallible"
            },
            {
                "name": "major_field",
                "params": [{"name": "self", "type": "Version", "ipeType": "Version", "rustType": "&Version"}],
                "results": [{"name": "", "type": "Int", "rustType": "u64"}],
                "effect": "pure",
                "recvType": "Version",
                "recvRustType": "semver::Version",
                "methodName": "major",
                "isField": true
            }
        ]));
        let bindings = emit_bindings(&pkg);
        let kernel: serde_json::Value =
            serde_json::from_str(&crate::emit::emit_kernel_json(&pkg)).expect("valid JSON");
        let ipei = crate::emit::emit_ipei(&pkg, &std::collections::BTreeMap::new());
        let functions = kernel
            .pointer("/functions")
            .and_then(serde_json::Value::as_array)
            .expect("functions");
        for f in functions {
            let name = f
                .pointer("/name")
                .and_then(serde_json::Value::as_str)
                .expect("name");
            assert!(
                bindings.contains(&crate::naming::wrapper_begin_sentinel(name)),
                "{name} must open a wrapper region"
            );
            assert!(
                ipei.contains(&format!("\n{name} : ")),
                "{name} must seed the .ipei"
            );
        }
    }

    #[test]
    fn duplicate_wrapper_ref_names_collapse_at_decode() {
        let pkg = semver_pkg(&json!([
            {
                "name": "to_string",
                "params": [{"name": "self", "type": "Version", "ipeType": "Version", "rustType": "&Version"}],
                "results": [{"name": "", "type": "String", "rustType": "String"}],
                "effect": "pure",
                "recvType": "Version",
                "recvRustType": "semver::Version",
                "methodName": "to_string"
            },
            {
                "name": "to_string",
                "params": [{"name": "self", "type": "Version", "ipeType": "Version", "rustType": "&Version"}],
                "results": [{"name": "", "type": "String", "rustType": "String"}],
                "effect": "pure",
                "recvType": "Version",
                "recvRustType": "semver::Version",
                "methodName": "to_string"
            }
        ]));
        assert_eq!(pkg.fns().len(), 1);
        let out = emit_bindings(&pkg);
        assert_eq!(
            out.matches("// IPE-FFI-WRAPPER BEGIN to_string_from_version")
                .count(),
            1,
            "{out}"
        );
    }

    #[test]
    fn pkg_var_getter_renders_as_a_free_call() {
        let pkg = decode(&json!({
            "pkg": "svc",
            "name": "svc",
            "functions": [{
                "name": "max_depth",
                "params": [],
                "results": [{"name": "", "type": "Int", "rustType": "usize"}],
                "effect": "pure",
                "isPkgVar": true
            }],
            "errors": []
        }));
        let out = emit_bindings(&pkg);
        assert!(
            out.contains("pub fn svc_max_depth(_: ()) -> IpeResult<IpeError, i64> {"),
            "{out}"
        );
        assert!(
            out.contains("(::svc::max_depth()).min(i64::MAX as usize) as i64"),
            "{out}"
        );
    }
}
