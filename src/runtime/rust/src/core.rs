#![allow(clippy::ptr_arg)]
// Ipê Runtime — Core types (always included)
// Generic over E (error type).  Builder.hs emits `use ipe_runtime::*;`
// and thin wrappers that instantiate E = IpeError.
//
// This module is the home for the core TYPES (IpeMaybe / IpeResult / IpeTask)
// and their combinators, plus the byte-sequence FFI coercion. The String and
// List kernels live in their named Ipê-module homes — `string.rs` and
// `list.rs` — re-exported through `mod.rs`'s glob so call sites are unaffected.

use std::future::Future;
use std::pin::Pin;

// ===========================================
// Task type (generic over error type E)
// ===========================================
// The `Send` bound backs tokio `spawn`/`block_on` on native hosts. On wasm32
// the runtime is single-threaded and browser futures (`JsFuture`, DOM-touching
// async) are `!Send`, so the bound is relaxed there — one type, cfg-split,
// never a fork or a `MaybeSend` trait (the native assertion in
// `tests/wasm_floor_scope.rs` pins the native half).
#[cfg(not(target_arch = "wasm32"))]
pub type IpeTask<E, A> = Pin<Box<dyn Future<Output = IpeResult<E, A>> + Send + 'static>>;
#[cfg(target_arch = "wasm32")]
pub type IpeTask<E, A> = Pin<Box<dyn Future<Output = IpeResult<E, A>> + 'static>>;

/// Construct Ok with generic error type.  Use `ok_res::<IpeError>` to
/// instantiate with the project's concrete error type.
pub fn ok_res<E, A>(a: A) -> IpeResult<E, A> {
    IpeResult::Ok(a)
}

/// Construct an error value from a string.  Requires `E: From<String>`.
/// When E = `IpeCoreErrorError`, the generated code provides the impl.
#[must_use]
pub fn str_err<E: From<String>>(s: &str) -> E {
    s.to_string().into()
}

/// Convert a foreign FFI error into the project's error type — REDACTED.
///
/// Used by the fallible(-async) FFI wrapper bodies to flatten a foreign
/// `Result<T, E>` Err arm into a Ipê-compatible error:
///
///   `Ok(Err(e)) => IpeResult::Err(ipe_error_from_foreign(e))`
///
/// C5: `tokio::task::spawn(...).await` already catches panics via `JoinError`;
/// this fn handles the non-panic `Err(e)` arm. Any `Debug`-able foreign error
/// type is accepted — `Debug` is universal and always available.
///
/// [B8 SECURITY — load-bearing] The foreign error's raw `Debug` is NEVER
/// surfaced to the Ipê side. A real network/auth client error (a reqwest/hyper
/// transport failure, a stripe API error) can echo the request URL, request
/// headers, a bearer token, or an API key in its `Debug`. So we follow
/// two-level error pattern: the raw `Debug` detail is logged SERVER-SIDE under a
/// fresh correlation id (operators can trace it), and ONLY a fixed generic
/// message carrying that id is returned to Ipê (`Error.toString` shows
/// `external operation failed (ref <id>)`, never the secret-bearing detail).
///
/// Same generic `E: From<String>` contract as `str_err` — the project provides
/// `impl From<String> for IpeCoreErrorError` so both arms of the fallible match
/// resolve to the same `IpeResult<E, A>`. Total — no unwrap/index/panic.
pub fn ipe_error_from_foreign<ForeignE: std::fmt::Debug, E: From<String>>(e: ForeignE) -> E {
    let err_id = note_foreign_error(e);
    format!("external operation failed (ref {err_id})").into()
}

/// Funnel-log a foreign error's raw `Debug` under a fresh correlation id and
/// return the id. The direct entry for wrapper arms with NO error channel (a
/// `Maybe`-fold, for example) that must still surface the failure to operators;
/// `ipe_error_from_foreign` builds its Ipê-visible message on top of this.
/// Total — no unwrap/index/panic.
pub fn note_foreign_error<ForeignE: std::fmt::Debug>(e: ForeignE) -> String {
    let err_id = short_err_id();
    log_foreign_kind("ForeignError", &err_id, &format!("{e:?}"));
    err_id
}

/// Convert a CAUGHT foreign panic payload into the project's error type —
/// REDACTED, same funnel as `ipe_error_from_foreign`.
///
/// The `catch_unwind` FFI wrapper arms hand the payload here. Its text is
/// foreign-controlled (it can carry secrets / PII / internal paths exactly like
/// a foreign error's `Debug`), so it is logged SERVER-SIDE only; the Ipê-visible
/// value is `context` — an emitter-owned constant such as
/// `"foreign call panicked"` — plus the correlation id, never the payload.
/// Total — no unwrap/index/panic.
pub fn ipe_error_from_panic<E: From<String>>(
    context: &str,
    payload: Box<dyn std::any::Any + Send>,
) -> E {
    let err_id = note_foreign_panic(context, payload);
    format!("{context} (ref {err_id})").into()
}

/// Funnel-log a caught foreign panic payload under a fresh correlation id and
/// return the id. The direct entry for wrapper arms with NO error channel (a
/// `Maybe`-fold, a total-return abort site); `ipe_error_from_panic` builds its
/// Ipê-visible message on top of this.
///
/// The payload is dropped inside its own `catch_unwind` guard: the payload is a
/// foreign value whose `Drop` may itself panic, and that panic must not
/// re-escape the boundary the caller just closed. Total — no
/// unwrap/index/panic of its own.
pub fn note_foreign_panic(context: &str, payload: Box<dyn std::any::Any + Send>) -> String {
    let err_id = short_err_id();
    let detail = panic_payload_message(payload.as_ref());
    log_foreign_kind("ForeignPanic", &err_id, &format!("{context}: {detail}"));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(payload)));
    err_id
}

/// [B8] Server-log a foreign FFI failure's raw detail under a correlation id,
/// honouring `IPE_LOG_FORMAT=json`. The detail is for OPERATORS ONLY — it can
/// carry secrets / PII / internal paths from a transport error or a panic
/// message — so it goes to the SERVER LOG (stderr), never to the Ipê-visible
/// message. Mirrors the `classify_and_log_panic` log shape. Total — no
/// unwrap/index/panic.
fn log_foreign_kind(kind: &str, err_id: &str, detail: &str) {
    let json =
        crate::system::read_env_var("IPE_LOG_FORMAT").is_ok_and(|v| v.eq_ignore_ascii_case("json"));
    if json {
        crate::system::write_stderr_line(&format!(
            "{{\"level\":\"error\",\"kind\":\"{kind}\",\"errId\":\"{}\",\"message\":\"{}\"}}",
            err_id,
            crate::telemetry::json_escape(detail)
        ));
    } else {
        crate::system::write_stderr_line(&format!(
            "[error] {kind} (ref {err_id}): {}",
            crate::system::scrub_log_controls(detail)
        ));
    }
}

/// Bake a config-derived default for an env var: set `key=val` ONLY when the
/// var is unset, so shell env / `.env` still win (precedence: process env >
/// baked default). the generated `init()`'s `rt.SetPortDefault` +
/// `tomlIpeEnv` family. Routed through the process-global env lock
/// (`locked_set_var_if_absent`) so it is sound by construction even if a thread
/// is already reading the environment.
pub fn set_env_default(key: &str, val: &str) {
    crate::system::locked_set_var_if_absent(key, val);
}

// ===========================================
// Disconnected-store placeholders (closure-Model `Default`)
// ===========================================
// A Ipe.Web Model with function-typed fields (`Arc<dyn Fn(..) -> IpeTask<..>>`,
// e.g. the console's `store`) can't be serialized, so the codegen serde-skips
// those fields and reconstructs them via `Default` from these helpers. Each is a
// closure of the right arity that yields a STRUCTURED `Task` error (never a
// panic / unwrap) — a closure-Model whose session is restored gets a disconnected
// store and the app re-fetches. Closure-Models are memory-store-only (the memory
// store never serialises, so these are never instantiated at runtime there); the
// codegen makes persisting a closure-Model a hard compile error.
const DISCONNECTED_MSG: &str = "disconnected store: a closure-Model session was restored — closure-Models require [live] store = memory";

#[must_use]
pub fn disconnected_fn0<T: Send + 'static, E: From<String> + Send + 'static>()
-> std::sync::Arc<dyn Fn() -> IpeTask<E, T> + Send + Sync> {
    std::sync::Arc::new(|| -> IpeTask<E, T> {
        Box::pin(std::future::ready(IpeResult::Err(str_err::<E>(
            DISCONNECTED_MSG,
        ))))
    })
}
#[must_use]
pub fn disconnected_fn1<A: 'static, T: Send + 'static, E: From<String> + Send + 'static>()
-> std::sync::Arc<dyn Fn(A) -> IpeTask<E, T> + Send + Sync> {
    std::sync::Arc::new(|_a| -> IpeTask<E, T> {
        Box::pin(std::future::ready(IpeResult::Err(str_err::<E>(
            DISCONNECTED_MSG,
        ))))
    })
}
#[must_use]
pub fn disconnected_fn2<
    A1: 'static,
    A2: 'static,
    T: Send + 'static,
    E: From<String> + Send + 'static,
>() -> std::sync::Arc<dyn Fn(A1, A2) -> IpeTask<E, T> + Send + Sync> {
    std::sync::Arc::new(|_a1, _a2| -> IpeTask<E, T> {
        Box::pin(std::future::ready(IpeResult::Err(str_err::<E>(
            DISCONNECTED_MSG,
        ))))
    })
}
#[must_use]
pub fn disconnected_fn3<
    A1: 'static,
    A2: 'static,
    A3: 'static,
    T: Send + 'static,
    E: From<String> + Send + 'static,
>() -> std::sync::Arc<dyn Fn(A1, A2, A3) -> IpeTask<E, T> + Send + Sync> {
    std::sync::Arc::new(|_a1, _a2, _a3| -> IpeTask<E, T> {
        Box::pin(std::future::ready(IpeResult::Err(str_err::<E>(
            DISCONNECTED_MSG,
        ))))
    })
}

// ===========================================
// Byte-sequence FFI coercion (Ipê List Int <-> Rust bytes)
// ===========================================

/// Ipê `List Int` (Vec<i64>) -> owned bytes. Each element is narrowed `as u8`,
/// mirroring the numeric param narrowing the FFI codegen already emits.
/// Used for `&[u8]` and `Vec<u8>` parameters.
#[must_use]
pub fn to_u8_vec(xs: &[i64]) -> Vec<u8> {
    xs.iter().map(|&x| x as u8).collect()
}

/// Owned/borrowed bytes -> Ipê `List Int` (Vec<i64>). Used for byte results.
#[must_use]
pub fn from_u8_slice(bs: &[u8]) -> Vec<i64> {
    bs.iter().map(|&b| i64::from(b)).collect()
}

/// Ipê `List Int` -> `[u8; N]`. A length mismatch returns `Err` and never
/// panics (honours "no runtime panic from well-typed Ipê code"). Used for
/// `[u8; N]` / `&[u8; N]` parameters; the generated wrapper instantiates
/// `E = IpeError` and the concrete `N`.
#[must_use]
pub fn to_u8_array<E: From<String>, const N: usize>(xs: &[i64]) -> IpeResult<E, [u8; N]> {
    if xs.len() != N {
        return IpeResult::Err(format!("expected {} bytes, got {}", N, xs.len()).into());
    }
    let mut a = [0u8; N];
    // len == N checked above; zip is total (no indexing).
    for (slot, &x) in a.iter_mut().zip(xs.iter()) {
        *slot = x as u8;
    }
    ok_res(a)
}

/// Ipê `List T` (Rust `&[T]`) -> fixed-size `[T; N]` with length check.
/// Mirrors `to_u8_array`'s never-panic discipline: returns `IpeResult::Err`
/// with a clear message on length mismatch. T: Clone is sufficient — the
/// elements are cloned out into the array.
pub fn to_array<E: From<String>, T: Clone, const N: usize>(xs: &[T]) -> IpeResult<E, [T; N]> {
    if xs.len() != N {
        return IpeResult::Err(format!("expected array of length {}, got {}", N, xs.len()).into());
    }
    let v: Vec<T> = xs.to_vec();
    match v.try_into() {
        Ok(a) => ok_res(a),
        Err(_) => IpeResult::Err("array length conversion failed".to_string().into()),
    }
}

// ===========================================
// Maybe
// ===========================================
// The serde derive is generic-BOUND (the macro emits `impl<T: Serialize> … for
// IpeMaybe<T>`), so a `IpeMaybe<NonSerde>` is unaffected — yet a Ipe.Web model
// carrying a `Maybe X` field (X serde-able) serialises for the session store.
// Without this, any model with a `Maybe`/`Result` field failed E0277. The derive
// is gated on the `serde` feature: a program that reaches no serializing surface
// (no Json/Web/Db/config) drops `serde` entirely, and `IpeMaybe` still compiles —
// it simply carries no serde impls. Every serializing surface implies `serde`, so
// the derive is always present where a floor type actually crosses a wire.
//
// `Deserialize` is NOT derived — we use a manual impl (see below) that accepts
// BOTH the externally-tagged repr (session-store round-trip) AND a bare value
// (form data: `note=hello` → `Just("hello")`). `Serialize` stays derived (tagged)
// so the session store writes `{"Just":"x"}` / `"Nothing"` and the manual
// `Deserialize` reads those back correctly.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum IpeMaybe<T> {
    Nothing,
    Just(T),
}

// Custom `Deserialize` for `IpeMaybe<T>`.
//
// Accepted input shapes:
//   - Externally-tagged map `{"Just": v}` → `Just(T::deserialize(v))`.
//     This is what `Serialize` emits → session-store round-trip is preserved.
//   - Externally-tagged string `"Nothing"` (unit variant) → `Nothing`.
//   - Bare non-null value `v` → `Just(T::deserialize(v))`.
//     This is the form-data case: `note=hello` → the urlencoded deserialiser
//     presents a bare string, which the tagged derive rejects.
//   - `null` / absent (handled by `Default` + `#[serde(default)]` at the struct
//     field level) → `Nothing`.
//
// The "Nothing" string-variant sentinel is accepted for backward compat with
// any stored sessions, even though the serialiser now no longer writes bare
// `"Nothing"` (it stays externally-tagged as the unit variant string).
//
// Edge case: a bare string value of exactly `"Nothing"` in form data decodes as
// `Nothing`, not `Just("Nothing")`. This is the same trade-off as the tagged
// derive and is acceptable — form fields named `note` with the literal value
// "Nothing" are pathological; real user notes should not hit this.
//
// Gated on `serde`: the whole hand-written deserializer disappears when no
// serializing surface is reached, mirroring the derived `Serialize` above.
#[cfg(feature = "serde")]
impl<'de, T: serde::de::Deserialize<'de>> serde::de::Deserialize<'de> for IpeMaybe<T> {
    fn deserialize<D: serde::de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(IpeMaybeVisitor(std::marker::PhantomData))
    }
}

#[cfg(feature = "serde")]
struct IpeMaybeVisitor<T>(std::marker::PhantomData<T>);

#[cfg(feature = "serde")]
impl<'de, T: serde::de::Deserialize<'de>> serde::de::Visitor<'de> for IpeMaybeVisitor<T> {
    type Value = IpeMaybe<T>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a IpeMaybe value: `{\"Just\": v}`, `\"Nothing\"`, or a bare value")
    }

    // --- bare unit / null → Nothing ---
    fn visit_unit<E: serde::de::Error>(self) -> Result<IpeMaybe<T>, E> {
        Ok(IpeMaybe::Nothing)
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<IpeMaybe<T>, E> {
        Ok(IpeMaybe::Nothing)
    }
    fn visit_some<D: serde::de::Deserializer<'de>>(self, d: D) -> Result<IpeMaybe<T>, D::Error> {
        T::deserialize(d).map(IpeMaybe::Just)
    }

    // --- bare string → "Nothing" sentinel OR Just(T) ---
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<IpeMaybe<T>, E> {
        if v == "Nothing" {
            return Ok(IpeMaybe::Nothing);
        }
        // Bare non-sentinel string: deserialize T from it.
        T::deserialize(serde::de::value::StrDeserializer::new(v)).map(IpeMaybe::Just)
    }

    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<IpeMaybe<T>, E> {
        if v == "Nothing" {
            return Ok(IpeMaybe::Nothing);
        }
        T::deserialize(serde::de::value::StringDeserializer::new(v)).map(IpeMaybe::Just)
    }

    // --- externally-tagged map `{"Just": v}` → Just(T) ---
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<IpeMaybe<T>, A::Error> {
        use serde::de::Error as _;
        let key: Option<String> = map.next_key()?;
        match key.as_deref() {
            Some("Just") => {
                let val: T = map.next_value()?;
                // Consume any remaining entries (defensive; tagged enums have one).
                while map.next_key::<serde::de::IgnoredAny>()?.is_some() {
                    let _: serde::de::IgnoredAny = map.next_value()?;
                }
                Ok(IpeMaybe::Just(val))
            }
            Some("Nothing") => {
                // Unit variant as a map key (edge case from some serialisers).
                while map.next_key::<serde::de::IgnoredAny>()?.is_some() {
                    let _: serde::de::IgnoredAny = map.next_value()?;
                }
                Ok(IpeMaybe::Nothing)
            }
            Some(other) => Err(A::Error::unknown_variant(other, &["Just", "Nothing"])),
            None => Err(A::Error::missing_field("Just")),
        }
    }

    // --- bare numerics / bool → Just(T) ---
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<IpeMaybe<T>, E> {
        T::deserialize(serde::de::value::BoolDeserializer::new(v)).map(IpeMaybe::Just)
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<IpeMaybe<T>, E> {
        T::deserialize(serde::de::value::I64Deserializer::new(v)).map(IpeMaybe::Just)
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<IpeMaybe<T>, E> {
        T::deserialize(serde::de::value::U64Deserializer::new(v)).map(IpeMaybe::Just)
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<IpeMaybe<T>, E> {
        T::deserialize(serde::de::value::F64Deserializer::new(v)).map(IpeMaybe::Just)
    }
}

impl<T> IpeMaybe<T> {
    pub fn with_default(self, def: T) -> T {
        match self {
            IpeMaybe::Just(v) => v,
            IpeMaybe::Nothing => def,
        }
    }
    pub fn is_just(&self) -> bool {
        matches!(self, IpeMaybe::Just(_))
    }
    pub fn is_nothing(&self) -> bool {
        matches!(self, IpeMaybe::Nothing)
    }
}

// `Nothing` is the natural zero of an absent `Maybe`, mirroring
// `json.Unmarshal` decoding a missing nullable field to nil. This MANUAL impl
// (the derive would demand `T: Default`, which a `IpeMaybe<NonDefault>` field
// cannot satisfy) lets a form-target record carrying a `Maybe X` field qualify
// for the lenient `#[serde(default)]` form-decode stamp without an E0277.
// Deliberately NOT provided for `IpeResult`: an absent `Result` has no canonical
// zero (`Ok` vs `Err` is undecidable), so a Result-typed form field keeps the
// strict (non-Default) emission instead — see Emitter.hs `allFieldsDefaultable`.
//
// NOT `#[derive(Default)]` (clippy::derivable_impls): the derive stamps a
// `T: Default` bound on EVERY type param, which would defeat the point — a
// `IpeMaybe<NonDefault>` field must still have a default (its inner `T` is never
// constructed in the `Nothing` zero). This MANUAL impl is unbounded in `T`.
#[allow(clippy::derivable_impls)]
impl<T> Default for IpeMaybe<T> {
    fn default() -> Self {
        IpeMaybe::Nothing
    }
}

pub fn ipe_maybe_map<T, U>(m: IpeMaybe<T>, f: impl FnOnce(T) -> U) -> IpeMaybe<U> {
    match m {
        IpeMaybe::Just(v) => IpeMaybe::Just(f(v)),
        IpeMaybe::Nothing => IpeMaybe::Nothing,
    }
}

pub fn ipe_maybe_and_then<T, U>(m: IpeMaybe<T>, f: impl FnOnce(T) -> IpeMaybe<U>) -> IpeMaybe<U> {
    match m {
        IpeMaybe::Just(v) => f(v),
        IpeMaybe::Nothing => IpeMaybe::Nothing,
    }
}

/// `IpeMaybe<T>` -> `Option<T>` for FFI parameter coercion: a Ipê `Maybe X`
/// argument reaches the wrapper as `IpeMaybe<X>` but the underlying crate fn
/// takes `Option<…>`. The generated wrapper calls this then adapts the inner
/// value (`.as_deref()` for `Option<&str>`, `.map(|x| x as u16)` for narrowed
/// numerics, identity otherwise). Total: `Just -> Some`, `Nothing -> None`.
pub fn ipe_maybe_to_option<T>(m: IpeMaybe<T>) -> Option<T> {
    match m {
        IpeMaybe::Just(v) => Some(v),
        IpeMaybe::Nothing => None,
    }
}

// ===========================================
// Result (generic over error type E)
// ===========================================
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IpeResult<E, A> {
    Ok(A),
    Err(E),
}

impl<E, A> IpeResult<E, A> {
    pub fn is_ok(&self) -> bool {
        matches!(self, IpeResult::Ok(_))
    }
    pub fn is_err(&self) -> bool {
        matches!(self, IpeResult::Err(_))
    }
    pub fn with_default(self, def: A) -> A {
        match self {
            IpeResult::Ok(v) => v,
            IpeResult::Err(_) => def,
        }
    }
}

pub fn ipe_result_map<E, A, B>(r: IpeResult<E, A>, f: impl FnOnce(A) -> B) -> IpeResult<E, B> {
    match r {
        IpeResult::Ok(v) => IpeResult::Ok(f(v)),
        IpeResult::Err(e) => IpeResult::Err(e),
    }
}

pub fn ipe_result_and_then<E, A, B>(
    r: IpeResult<E, A>,
    f: impl FnOnce(A) -> IpeResult<E, B>,
) -> IpeResult<E, B> {
    match r {
        IpeResult::Ok(v) => f(v),
        IpeResult::Err(e) => IpeResult::Err(e),
    }
}

/// `Result.mapError : (e -> f) -> Result e a -> Result f a`. Container-first in
/// the runtime (matching `ipe_result_map` / `ipe_result_and_then`); the emitter
/// reverses the Ipê `(fn, result)` order per the row's `ArgOrder::ContainerFirst`. Maps the
/// `Err` channel and leaves the `Ok` value untouched — total, no panic path.
pub fn ipe_result_map_error<E, F, A>(
    r: IpeResult<E, A>,
    f: impl FnOnce(E) -> F,
) -> IpeResult<F, A> {
    match r {
        IpeResult::Ok(v) => IpeResult::Ok(v),
        IpeResult::Err(e) => IpeResult::Err(f(e)),
    }
}

/// `Result.toMaybe : Result e a -> Maybe a` — `Ok v` → `Just v`, `Err _` →
/// `Nothing` (the error is discarded). Total.
pub fn ipe_result_to_maybe<E, A>(r: IpeResult<E, A>) -> IpeMaybe<A> {
    match r {
        IpeResult::Ok(v) => IpeMaybe::Just(v),
        IpeResult::Err(_) => IpeMaybe::Nothing,
    }
}

/// `Result.fromMaybe : e -> Maybe a -> Result e a` — `Just v` → `Ok v`,
/// `Nothing` → `Err err` (the supplied error fills the missing case). Total.
/// Takes its arguments in Ipê order (`err`, then `maybe`), so no emitter arg
/// swap is needed.
pub fn ipe_result_from_maybe<E, A>(err: E, m: IpeMaybe<A>) -> IpeResult<E, A> {
    match m {
        IpeMaybe::Just(v) => IpeResult::Ok(v),
        IpeMaybe::Nothing => IpeResult::Err(err),
    }
}

// ===========================================
// Maybe / Result default + traverse helpers
// ===========================================
pub fn result_with_default<E, A>(def: A, r: IpeResult<E, A>) -> A {
    match r {
        IpeResult::Ok(v) => v,
        IpeResult::Err(_) => def,
    }
}

pub fn maybe_with_default<A>(def: A, m: IpeMaybe<A>) -> A {
    match m {
        IpeMaybe::Just(v) => v,
        IpeMaybe::Nothing => def,
    }
}

pub fn maybe_is_just<A>(m: IpeMaybe<A>) -> bool {
    matches!(m, IpeMaybe::Just(_))
}

pub fn maybe_is_nothing<A>(m: IpeMaybe<A>) -> bool {
    matches!(m, IpeMaybe::Nothing)
}

// `Result.traverse : (a -> Result e b) -> List a -> Result e (List b)`. Maps
// `f` across the list, collecting the `Ok` values; the FIRST `Err` (in list
// order) short-circuits with the real error. No `Clone` bound — each element is
// MOVED into `f`, matching the Ipê pure-Ipê one-pass definition. Total: no
// unwrap/index/panic (`Vec::push` grows, never indexes).
pub fn result_traverse<T0, T1, E>(
    f: impl Fn(T0) -> IpeResult<E, T1>,
    items: Vec<T0>,
) -> IpeResult<E, Vec<T1>> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        match f(item) {
            IpeResult::Ok(v) => out.push(v),
            IpeResult::Err(e) => return IpeResult::Err(e),
        }
    }
    IpeResult::Ok(out)
}

// ===========================================
// Result / Maybe applicative combinators (mapN / andMap / combine)
// ===========================================
// FUNCTION-FIRST argument order (matches the Ipê call surface AND the JsonDec
// `decode_mapN` runtime shape), so the kernel rows declare `ArgOrder::IpeOrder`.
// The N-ary function is a MULTI-ARG Rust fn value — a Ipê arity-N function /
// record-alias auto-constructor lowers to `impl Fn(A, .., N) -> V`, so `f(a, b,
// ..)` type-checks. Each combinator is TOTAL: the first `Err` / `Nothing` in
// Ipê evaluation order short-circuits; the `Ok` / `Just` value type is never
// indexed or unwrapped. No panic, no `unsafe`, no allocation beyond the result.

/// `Result.map2 : (a -> b -> v) -> Result e a -> Result e b -> Result e v`.
/// First `Err` in (ra, rb) order wins — matches the nested-case `.ipe` def.
pub fn result_map2<E, A, B, V>(
    f: impl FnOnce(A, B) -> V,
    ra: IpeResult<E, A>,
    rb: IpeResult<E, B>,
) -> IpeResult<E, V> {
    let a = match ra {
        IpeResult::Ok(a) => a,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    let b = match rb {
        IpeResult::Ok(b) => b,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    IpeResult::Ok(f(a, b))
}

/// `Result.map3 : (a -> b -> c -> v) -> Result e a -> Result e b -> Result e c
/// -> Result e v`.
pub fn result_map3<E, A, B, C, V>(
    f: impl FnOnce(A, B, C) -> V,
    ra: IpeResult<E, A>,
    rb: IpeResult<E, B>,
    rc: IpeResult<E, C>,
) -> IpeResult<E, V> {
    let a = match ra {
        IpeResult::Ok(a) => a,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    let b = match rb {
        IpeResult::Ok(b) => b,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    let c = match rc {
        IpeResult::Ok(c) => c,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    IpeResult::Ok(f(a, b, c))
}

/// `Result.map4 : (a -> b -> c -> d -> v) -> Result e a -> .. -> Result e v`.
pub fn result_map4<E, A, B, C, D, V>(
    f: impl FnOnce(A, B, C, D) -> V,
    ra: IpeResult<E, A>,
    rb: IpeResult<E, B>,
    rc: IpeResult<E, C>,
    rd: IpeResult<E, D>,
) -> IpeResult<E, V> {
    let a = match ra {
        IpeResult::Ok(a) => a,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    let b = match rb {
        IpeResult::Ok(b) => b,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    let c = match rc {
        IpeResult::Ok(c) => c,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    let d = match rd {
        IpeResult::Ok(d) => d,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    IpeResult::Ok(f(a, b, c, d))
}

/// `Result.map5 : (a -> b -> c -> d -> e -> v) -> Result er a -> .. -> Result
/// er v`. (`er` is the shared error channel; `e` is the fifth `Ok` value.)
pub fn result_map5<Er, A, B, C, D, E, V>(
    f: impl FnOnce(A, B, C, D, E) -> V,
    ra: IpeResult<Er, A>,
    rb: IpeResult<Er, B>,
    rc: IpeResult<Er, C>,
    rd: IpeResult<Er, D>,
    re: IpeResult<Er, E>,
) -> IpeResult<Er, V> {
    let a = match ra {
        IpeResult::Ok(a) => a,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    let b = match rb {
        IpeResult::Ok(b) => b,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    let c = match rc {
        IpeResult::Ok(c) => c,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    let d = match rd {
        IpeResult::Ok(d) => d,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    let e_val = match re {
        IpeResult::Ok(v) => v,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    IpeResult::Ok(f(a, b, c, d, e_val))
}

/// `Result.andMap : Result e a -> Result e (a -> b) -> Result e b`. The `.ipe`
/// definition inspects the FUNCTION result first, so its `Err` wins over the
/// value's `Err`. The function is applied only when BOTH are `Ok`.
pub fn result_and_map<E, A, B, F: FnOnce(A) -> B>(
    ra: IpeResult<E, A>,
    rf: IpeResult<E, F>,
) -> IpeResult<E, B> {
    match rf {
        IpeResult::Ok(f) => match ra {
            IpeResult::Ok(a) => IpeResult::Ok(f(a)),
            IpeResult::Err(e) => IpeResult::Err(e),
        },
        IpeResult::Err(e) => IpeResult::Err(e),
    }
}

/// `Result.combine : List (Result e a) -> Result e (List a)`. Collects every
/// `Ok`; the first `Err` in list order short-circuits.
#[must_use]
pub fn result_combine<E, A>(results: Vec<IpeResult<E, A>>) -> IpeResult<E, Vec<A>> {
    let mut out = Vec::with_capacity(results.len());
    for r in results {
        match r {
            IpeResult::Ok(v) => out.push(v),
            IpeResult::Err(e) => return IpeResult::Err(e),
        }
    }
    IpeResult::Ok(out)
}

/// `Maybe.map2 : (a -> b -> v) -> Maybe a -> Maybe b -> Maybe v`.
pub fn maybe_map2<A, B, V>(
    f: impl FnOnce(A, B) -> V,
    ma: IpeMaybe<A>,
    mb: IpeMaybe<B>,
) -> IpeMaybe<V> {
    let a = match ma {
        IpeMaybe::Just(a) => a,
        IpeMaybe::Nothing => return IpeMaybe::Nothing,
    };
    let b = match mb {
        IpeMaybe::Just(b) => b,
        IpeMaybe::Nothing => return IpeMaybe::Nothing,
    };
    IpeMaybe::Just(f(a, b))
}

/// `Maybe.map3 : (a -> b -> c -> v) -> Maybe a -> Maybe b -> Maybe c -> Maybe v`.
pub fn maybe_map3<A, B, C, V>(
    f: impl FnOnce(A, B, C) -> V,
    ma: IpeMaybe<A>,
    mb: IpeMaybe<B>,
    mc: IpeMaybe<C>,
) -> IpeMaybe<V> {
    let a = match ma {
        IpeMaybe::Just(a) => a,
        IpeMaybe::Nothing => return IpeMaybe::Nothing,
    };
    let b = match mb {
        IpeMaybe::Just(b) => b,
        IpeMaybe::Nothing => return IpeMaybe::Nothing,
    };
    let c = match mc {
        IpeMaybe::Just(c) => c,
        IpeMaybe::Nothing => return IpeMaybe::Nothing,
    };
    IpeMaybe::Just(f(a, b, c))
}

/// `Maybe.map4 : (a -> b -> c -> d -> v) -> Maybe a -> .. -> Maybe v`.
pub fn maybe_map4<A, B, C, D, V>(
    f: impl FnOnce(A, B, C, D) -> V,
    ma: IpeMaybe<A>,
    mb: IpeMaybe<B>,
    mc: IpeMaybe<C>,
    md: IpeMaybe<D>,
) -> IpeMaybe<V> {
    let a = match ma {
        IpeMaybe::Just(a) => a,
        IpeMaybe::Nothing => return IpeMaybe::Nothing,
    };
    let b = match mb {
        IpeMaybe::Just(b) => b,
        IpeMaybe::Nothing => return IpeMaybe::Nothing,
    };
    let c = match mc {
        IpeMaybe::Just(c) => c,
        IpeMaybe::Nothing => return IpeMaybe::Nothing,
    };
    let d = match md {
        IpeMaybe::Just(d) => d,
        IpeMaybe::Nothing => return IpeMaybe::Nothing,
    };
    IpeMaybe::Just(f(a, b, c, d))
}

/// `Maybe.map5 : (a -> b -> c -> d -> e -> v) -> Maybe a -> .. -> Maybe v`.
pub fn maybe_map5<A, B, C, D, E, V>(
    f: impl FnOnce(A, B, C, D, E) -> V,
    ma: IpeMaybe<A>,
    mb: IpeMaybe<B>,
    mc: IpeMaybe<C>,
    md: IpeMaybe<D>,
    me: IpeMaybe<E>,
) -> IpeMaybe<V> {
    let a = match ma {
        IpeMaybe::Just(a) => a,
        IpeMaybe::Nothing => return IpeMaybe::Nothing,
    };
    let b = match mb {
        IpeMaybe::Just(b) => b,
        IpeMaybe::Nothing => return IpeMaybe::Nothing,
    };
    let c = match mc {
        IpeMaybe::Just(c) => c,
        IpeMaybe::Nothing => return IpeMaybe::Nothing,
    };
    let d = match md {
        IpeMaybe::Just(d) => d,
        IpeMaybe::Nothing => return IpeMaybe::Nothing,
    };
    let e = match me {
        IpeMaybe::Just(e) => e,
        IpeMaybe::Nothing => return IpeMaybe::Nothing,
    };
    IpeMaybe::Just(f(a, b, c, d, e))
}

/// `Maybe.andMap : Maybe a -> Maybe (a -> b) -> Maybe b`. Function-Maybe
/// inspected first (matches the `.ipe` definition).
pub fn maybe_and_map<A, B, F: FnOnce(A) -> B>(ma: IpeMaybe<A>, mf: IpeMaybe<F>) -> IpeMaybe<B> {
    match mf {
        IpeMaybe::Just(f) => match ma {
            IpeMaybe::Just(a) => IpeMaybe::Just(f(a)),
            IpeMaybe::Nothing => IpeMaybe::Nothing,
        },
        IpeMaybe::Nothing => IpeMaybe::Nothing,
    }
}

/// `Maybe.combine : List (Maybe a) -> Maybe (List a)`. Collects every `Just`;
/// the first `Nothing` short-circuits.
#[must_use]
pub fn maybe_combine<A>(maybes: Vec<IpeMaybe<A>>) -> IpeMaybe<Vec<A>> {
    let mut out = Vec::with_capacity(maybes.len());
    for m in maybes {
        match m {
            IpeMaybe::Just(v) => out.push(v),
            IpeMaybe::Nothing => return IpeMaybe::Nothing,
        }
    }
    IpeMaybe::Just(out)
}

// ===========================================
// Recursion depth guard
// ===========================================
// A user function that recurses without a reachable base case grows the native
// stack until it hits the guard page. A native stack overflow is an immediate
// `abort()` — it does NOT unwind, so every panic-containment mechanism the
// runtime has (the classifying panic hook, the `catch_unwind` task funnels, the
// server's per-request `CatchPanicLayer`) is bypassed and the whole process
// dies. On a long-lived server that is a one-request denial of service against
// every in-flight request.
//
// The guard converts that uncatchable abort into an ordinary classified panic.
// The emitter prepends `let _ipe_recursion_guard = crate::recursion_guard();`
// to every user function body; the RAII guard increments a per-thread depth
// counter on entry (and, on native targets, probes the remaining stack), trips
// with a fixed-message `panic!` when either bound is exceeded, and decrements on
// drop. Because a panic unwinds, the existing containment isolates the trip per
// request / per task / per process exit. The counter stays exact across the
// unwind: every frame between the trip and the catcher restores its decrement as
// it unwinds.
//
// Two independent bounds, either of which trips:
//
//   * Depth budget — a per-thread counter against a configurable limit. Fires
//     in the common case (typical emitted frames are small), so the failure is
//     reproducible at the same depth on every platform and the diagnostic is
//     teachable. Catches direct, mutual, and function-value-mediated recursion:
//     any unbounded chain re-enters some emitted function infinitely often, and
//     every emitted function is guarded.
//   * Remaining-stack red zone (native only) — the runtime records a stack floor
//     for every thread it owns; the guard compares the address of a local
//     against `floor + RED_ZONE`. This is the soundness backstop for frames of
//     any size: even a single hundred-kilobyte frame trips while a comfortable
//     margin remains for the panic/unwind machinery. A thread whose floor was
//     never recorded (a foreign thread calling into emitted code) degrades to
//     depth-only — fail-safe, never a false trip. Compiled out on wasm32 (no
//     native stack introspection); the depth budget remains.

/// The default recursion depth budget when `IPE_RECURSION_LIMIT` is unset,
/// unparseable, or zero. Calibrated against the 8 MiB runtime-owned stacks: at
/// ~100–800 bytes per emitted frame, 10 000 frames occupy ~1–8 MiB, so the depth
/// budget trips deterministically for typical frames and the red-zone probe
/// covers the fat-frame tail.
const DEFAULT_RECURSION_LIMIT: usize = 10_000;

/// The remaining-stack margin that must stay free when the guard admits a call.
/// Its contract: one emitted frame plus the deepest non-guarded call chain
/// beneath it must fit in this margin, so the panic/unwind machinery and any
/// runtime kernels beneath the last guarded entry always have room. An internal
/// soundness constant, not a user-facing tunable.
#[cfg(not(target_arch = "wasm32"))]
const RECURSION_RED_ZONE: usize = 256 * 1024;

/// The stack size the runtime requests for every thread it spawns, and the size
/// the recorded floor (`record_stack_floor`) is derived against. Uniform so the
/// same program trips at the same depth whether the recursion started from a CLI
/// `main`, an HTTP handler, or a live-session driver.
#[cfg(not(target_arch = "wasm32"))]
pub const RUNTIME_THREAD_STACK_SIZE: usize = 8 * 1024 * 1024;

thread_local! {
    /// The current guarded recursion depth on this thread. Incremented by
    /// `recursion_guard()`, decremented by `RecursionGuard::drop` — exact under
    /// both normal return and unwind.
    static RECURSION_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// The lowest stack address this thread may descend to before the guard
    /// trips (`stack base − stack size + red zone`, since every supported target
    /// grows the stack downward). `None` on a thread whose floor was never
    /// recorded — the probe then degrades to depth-only.
    #[cfg(not(target_arch = "wasm32"))]
    static STACK_FLOOR: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// The configured recursion depth budget, read once from `IPE_RECURSION_LIMIT`
/// and cached for the process lifetime. Unset, unparseable, or zero falls back
/// to [`DEFAULT_RECURSION_LIMIT`]; any positive value is accepted (the red-zone
/// probe still backstops a value set recklessly high, so raising the env var can
/// never reintroduce the abort).
fn recursion_limit() -> usize {
    use std::sync::OnceLock;
    static LIMIT: OnceLock<usize> = OnceLock::new();
    *LIMIT.get_or_init(|| {
        parse_recursion_limit(crate::system::read_env_var("IPE_RECURSION_LIMIT").ok())
    })
}

/// Interpret a raw `IPE_RECURSION_LIMIT` value into a depth budget. Unset
/// (`None`), unparseable, or zero yields [`DEFAULT_RECURSION_LIMIT`]; any
/// positive integer is accepted verbatim. Pure so the fallback ladder is unit
/// tested without touching the process environment or the cached read.
fn parse_recursion_limit(raw: Option<String>) -> usize {
    raw.and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_RECURSION_LIMIT)
}

/// An approximation of the current stack pointer: the address of a stack local.
/// Stacks grow downward on every supported native target, so a deeper call
/// yields a smaller address. Reading the address of a local — never
/// dereferencing a dangling pointer — is safe.
///
/// The floor recorded from this address and every later probe against it must
/// live on the SAME stack, or the descent comparison is meaningless. Under
/// AddressSanitizer's stack-use-after-return instrumentation, an ordinary
/// local is spilled to a per-frame heap "fake frame" whose address bears no
/// monotonic relation to real-stack depth — recording the floor there and
/// probing there would leave the red-zone backstop inert and let a runaway
/// recursion reach a native overflow. Excluding this one function from
/// instrumentation keeps `anchor` on the real stack, so the floor and every
/// probe share the real, downward-growing address space the guard reasons
/// about. `#[inline(never)]` is required with the exclusion: an inlined body
/// would take its caller's (instrumented) frame and the local would move back
/// onto the fake stack.
#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(ipe_asan, sanitize(address = "off"), inline(never))]
#[cfg_attr(not(ipe_asan), inline)]
fn approx_stack_pointer() -> usize {
    let anchor: u8 = 0;
    std::ptr::from_ref(&anchor) as usize
}

/// Record the calling thread's stack floor so the guard's red-zone probe has a
/// reference point. Called once, first thing, on every thread the runtime owns
/// (the main thread via the panic classifier, the `block_on` entry thread, and
/// each tokio worker via `on_thread_start`), passing that thread's known stack
/// size. The floor is `current stack pointer − usable_below + RED_ZONE`, where
/// `usable_below` is how far this thread may still descend; the guard then trips
/// once a probed pointer drops below the floor. Idempotent per thread: recording
/// again simply overwrites with an equivalent value.
///
/// `usable_below` is derived conservatively as `stack_size` minus the space
/// already consumed above the recording point, which is unknown here, so the
/// caller passes the full `stack_size` and the recording happens as early as
/// possible on the thread (where consumption above is minimal). A floor set a
/// little high only trips the guard slightly sooner — never later — so the
/// soundness direction is preserved.
#[cfg(not(target_arch = "wasm32"))]
pub fn record_stack_floor(stack_size: usize) {
    let sp = approx_stack_pointer();
    // Saturating throughout: on the (impossible for supported targets) chance
    // that `stack_size` exceeds the addressable space below `sp`, the floor
    // saturates to 0 and the probe simply never trips — depth-only, fail-safe.
    let floor = sp
        .saturating_sub(stack_size)
        .saturating_add(RECURSION_RED_ZONE);
    STACK_FLOOR.with(|c| c.set(Some(floor)));
}

/// Read this thread's recorded stack floor, if any. Test-only accessor for the
/// floor-recording regressions; production code never needs to read it directly.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn stack_floor_for_test() -> Option<usize> {
    STACK_FLOOR.with(std::cell::Cell::get)
}

/// Read the calling frame's approximate stack pointer.
///
/// Test-only accessor for the constant-stack-depth regressions, which compare
/// the pointer across the steps of a repeated task.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn stack_pointer_for_test() -> usize {
    approx_stack_pointer()
}

/// Read this thread's current guarded recursion depth. Test-only accessor for
/// the RAII-balance regressions.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn recursion_depth_for_test() -> usize {
    RECURSION_DEPTH.with(std::cell::Cell::get)
}

/// The typed payload of the recursion-guard trip panic. Zero-size: the fact that
/// the depth budget (or the stack red-zone probe) was exceeded IS the type — it
/// carries no data. Panicking with this value (`panic_any`) instead of a message
/// string lets the catch-layer classifier `downcast_ref` it rather than match a
/// substring of a free-form message, so the `RecursionLimit` classification is
/// driven by the type, not by the wording of a string.
///
/// [`RecursionLimit::MESSAGE`] is the single source of the human-facing text; the
/// classifier renders it back to `"maximum recursion depth exceeded"` so the
/// server log / 500-side line / CLI stderr are byte-identical to a string trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecursionLimit;

impl RecursionLimit {
    /// The fixed human-facing message for a recursion trip. Byte-stable (golden-
    /// and E2E-asserted) and deliberately omits the word "overflow" so no message
    /// path can misclassify it as an arithmetic overflow.
    pub const MESSAGE: &'static str = "maximum recursion depth exceeded";
}

impl std::fmt::Display for RecursionLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(Self::MESSAGE)
    }
}

/// The RAII recursion guard. Its construction (`recursion_guard`) enters one
/// level of guarded recursion; its `Drop` leaves it. The type carries no public
/// field — it exists only to tie the decrement to the caller's scope.
#[must_use = "the guard must be bound to a named local for the whole function body; \
              dropping it immediately (e.g. `let _ = recursion_guard();`) would decrement \
              the depth counter at once and defeat the guard"]
pub struct RecursionGuard {
    // Zero-sized: the depth lives in the thread-local, not here. A private field
    // keeps the type unconstructible outside this module.
    _private: (),
}

/// Enter one level of guarded recursion, returning a [`RecursionGuard`] whose
/// drop leaves it. Called at the top of every emitted user function body. Trips
/// by panicking with the typed [`RecursionLimit`] payload when the per-thread
/// depth budget is exceeded or — on native targets with a recorded floor — when
/// the remaining stack falls into the red zone. The classifier downcasts that
/// type (never a message substring), so the trip can never misclassify as
/// `ArithmeticOverflow`.
///
/// Total apart from the deliberate trip: the increment is a `Cell` bump, the
/// probe an address compare, and the trip a `panic_any` with a zero-size marker
/// — no allocation on the trip path beyond the panic itself, no unwrap, no
/// index. It runs on the panic path (a trip deeper in the same chain unwinds
/// through outer guards' drops), so it must stay total, and it is.
#[inline]
pub fn recursion_guard() -> RecursionGuard {
    let depth = RECURSION_DEPTH.with(|c| {
        let next = c.get().saturating_add(1);
        c.set(next);
        next
    });
    // On a trip, NO `RecursionGuard` is returned, so no `Drop` will restore this
    // frame's increment — the trip path must undo it itself before unwinding.
    // (Outer frames each own a guard whose drop restores their own increment as
    // the panic unwinds, so the counter returns exactly to zero once caught.)
    let trip = depth > recursion_limit() || {
        #[cfg(not(target_arch = "wasm32"))]
        {
            STACK_FLOOR
                .with(std::cell::Cell::get)
                .is_some_and(|floor| approx_stack_pointer() <= floor)
        }
        #[cfg(target_arch = "wasm32")]
        {
            false
        }
    };
    if trip {
        RECURSION_DEPTH.with(|c| c.set(c.get().saturating_sub(1)));
        // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — the deliberate, sole trip path: it converts an uncatchable stack-overflow abort into a classifiable, containable panic carrying the typed `RecursionLimit` payload (the classifier downcasts it, never a message substring) [ledger #boundary]
        #[allow(clippy::panic, clippy::disallowed_methods)]
        // panic_any is the trip: a typed payload the catch-layer downcasts, not a stringly-typed message
        std::panic::panic_any(RecursionLimit);
    }
    RecursionGuard { _private: () }
}

impl Drop for RecursionGuard {
    fn drop(&mut self) {
        RECURSION_DEPTH.with(|c| c.set(c.get().saturating_sub(1)));
    }
}

// ===========================================
// Synchronous-panic gate
// ===========================================
// The generated `fn main()` installs this FIRST so any panic that escapes the
// synchronous Ipê path — a div-by-zero (`a / 0`), an index-out-of-range, an
// arithmetic overflow, etc. — is CLASSIFIED into a Ipê error kind, logged
// structurally with a short correlation id, and the process exits 1 — instead of
// dumping a raw Rust backtrace. Implements `defer rt.LogPanicAndExit()` on
// every emitted `func main()` (AGENTS.md "Synchronous-panic gate"). The hook is
// total (no unwrap/index/panic of its own) and honours `IPE_LOG_FORMAT=json`.

/// Map a Rust panic message to a Ipê error classification ( panic-class
/// taxonomy, restricted to the kinds reachable from well-typed Ipê on the typed
/// Rust backend — TypeMismatch/CoerceFailure are compiler-only).
fn classify_panic(msg: &str) -> &'static str {
    let m = msg.to_ascii_lowercase();
    if m.contains("divide by zero") || m.contains("divisor of zero") {
        "DivisionByZero"
    } else if m.contains("index out of bounds") || m.contains("out of range") {
        "IndexOutOfRange"
    } else if m.contains("recursion depth") {
        // The live recursion trip is classified by its typed `RecursionLimit`
        // payload in `classify_and_log_panic`, before this message path is
        // reached. This arm remains the fallback for a panic that carries the
        // recursion wording only as a message string. Ordered before the
        // `"overflow"` arm, and the wording omits "overflow", so it can never
        // misclassify as `ArithmeticOverflow`.
        "RecursionLimit"
    } else if m.contains("overflow") {
        "ArithmeticOverflow"
    } else {
        "Unexpected"
    }
}

/// A panic payload's human-readable message: the typed [`RecursionLimit`] trip
/// renders to its fixed message, then the standard `&str` / `String` payload
/// downcasts, with a fixed fallback for any other payload type. Recognising the
/// typed trip here keeps the server log / 500-side line / CLI stderr byte-
/// identical to the message a string trip once carried. Total — no
/// unwrap/index/panic.
fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    if payload.downcast_ref::<RecursionLimit>().is_some() {
        RecursionLimit::MESSAGE.to_string()
    } else if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic".to_string()
    }
}

/// 8 hex chars (4 bytes) of correlation id — derives from the wall-clock
/// sub-second component so two panics in one process don't collide. Total: a
/// clock read failure falls back to `0`.
fn short_err_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    format!("{n:08x}")
}

/// Extract a panic payload's message, classify it, emit the structured/plain
/// server-side log line (honouring `IPE_LOG_FORMAT=json`), and RETURN the 8-hex
/// correlation errId. SHARED by the exit-on-panic hook (`install_panic_classifier`,
/// used for Ipe.Console/Tui binaries) and the server/live `CatchPanicLayer` responder
/// (`server::panic_response`).
///
/// Two load-bearing properties:
/// 1. **Total** — it runs in a panic-unwinding context; a panic of ITS OWN would
///    abort the process. Downcast falls back to `"panic"`; no unwrap/index.
/// 2. **Does NOT exit** — the raw message goes to the SERVER LOG only; the caller
///    decides the fate (the hook adds `process::exit(1)`; the HTTP layer returns a
///    500 carrying ONLY the errId, never the message — so a panic message that
///    happens to contain a secret / PII / internal path is never sent to a client).
pub fn classify_and_log_panic(payload: &(dyn std::any::Any + Send)) -> String {
    let msg = panic_payload_message(payload);
    // The recursion trip carries a typed [`RecursionLimit`] payload: classify it
    // by DOWNCASTING the type, never by matching the message wording. Every other
    // panic (a caught foreign `&str`/`String`, an arithmetic overflow, an index
    // out of bounds) has no typed payload here, so it falls through to the
    // message-based `classify_panic` unchanged.
    let kind = if payload.downcast_ref::<RecursionLimit>().is_some() {
        "RecursionLimit"
    } else {
        classify_panic(&msg)
    };
    let err_id = short_err_id();
    let json =
        crate::system::read_env_var("IPE_LOG_FORMAT").is_ok_and(|v| v.eq_ignore_ascii_case("json"));
    if json {
        crate::system::write_stderr_line(&format!(
            "{{\"level\":\"error\",\"kind\":\"{}\",\"errId\":\"{}\",\"message\":\"{}\"}}",
            kind,
            err_id,
            crate::telemetry::json_escape(&msg)
        ));
    } else {
        crate::system::write_stderr_line(&format!(
            "[error] {kind} (ref {err_id}): {}",
            crate::system::scrub_log_controls(&msg)
        ));
    }
    err_id
}

/// The JSON body for a server `CatchPanicLayer` 500: classifies + logs the panic
/// SERVER-SIDE (errId) via `classify_and_log_panic`, then returns a body carrying
/// ONLY the errId — NEVER the panic message. The SINGLE source of the 500 body
/// shape, shared by Ipe.Http.Server and Ipe.Web (each wraps it in a 500 Response
/// at its own `CatchPanicLayer::custom` site). Axum-free, so it lives in the
/// always-compiled `core` — the generated project includes `server.rs` only for
/// Ipe.Http.Server apps, so a Web-only app can't reference a server-module fn.
///
/// SECURITY: `err_id` (8 lowercase-hex chars) is the ONLY value interpolated; the
/// rest is a fixed literal. A panic message (free-form, may carry secrets / PII /
/// paths) never reaches this body.
pub fn panic_500_body(payload: &(dyn std::any::Any + Send)) -> String {
    let err_id = classify_and_log_panic(payload);
    format!("{{\"error\":\"internal server error\",\"ref\":\"{err_id}\"}}")
}

/// Install the classifying panic hook. Idempotent in effect (re-installing just
/// replaces the hook). Called at the top of generated `fn main()` for non-server
/// shapes (Ipe.Console/Tui); server/live binaries rely on the per-request
/// `CatchPanicLayer` instead (so a handler panic returns a 500, not exit).
///
/// **Design note — hook logs then RESUMES the unwind (never calls exit).** Calling
/// `process::exit(1)` from the hook would prevent `catch_unwind` anywhere in the
/// process from absorbing panics, which breaks two load-bearing mechanisms:
///
///   1. `tokio::task::spawn(...)` internally uses `catch_unwind` to turn a task
///      panic into a `JoinError`.  The async-FFI binding bodies use this to satisfy
///      C5 (foreign `async fn` panics → `IpeResult::Err`).
///
///   2. `block_on` polls the entry future on a thread started through
///      `std::thread::Builder::spawn`; its `.join()` catches a panicking entry
///      future at the OS-thread boundary and maps it to `IpeResult::Err`.
///
/// By resuming the unwind, both mechanisms can absorb the panic after the hook
/// has logged the classified error.  For a truly uncaught panic (nothing catches
/// it), the Rust runtime prints a backtrace and aborts/exits — still a clean
/// non-zero exit. The classified log line always fires first.
pub fn install_panic_classifier() {
    // The main thread carries the platform-default 8 MiB stack by convention; the
    // std-only and current-thread `block_on` entries poll on it, so record its
    // floor here — the one call every emitted `main()` already makes — giving the
    // recursion guard's red-zone probe a reference point on the main thread. A
    // shape that never installs the hook simply runs depth-only there.
    #[cfg(not(target_arch = "wasm32"))]
    record_stack_floor(RUNTIME_THREAD_STACK_SIZE);
    // A malformed `IPE_LOG_LEVEL` refuses the program before its first line.
    #[cfg(feature = "log")]
    if let Err(refusal) = super::log::startup_check() {
        eprint_task_error(&refusal.to_string());
        crate::system::system_exit(1);
    }
    std::panic::set_hook(Box::new(|info| {
        // Log (classified, with errId) — diagnostic fires regardless of whether
        // the panic is subsequently caught by catch_unwind / tokio::task::spawn.
        let _ = classify_and_log_panic(info.payload());
        // Do NOT call process::exit — let the panic unwind propagate so that
        // catch_unwind callers (tokio task spawn, block_on thread join, async-FFI
        // wrappers) can absorb it and map it to a Ipê Err value.
    }));
}

/// Two-space gutter matching the CLI's own `GUTTER` constant (2 spaces).
/// Duplicated here because the runtime must not depend on `ipe-cli`; the
/// drift test in `install_style_drift.rs` asserts these agree.
const EPRINT_GUTTER: &str = "  ";

/// Format a task-error message as styled text. Each line is guttered; the first
/// line is prefixed with the failure glyph. ANSI colour is applied only when
/// `use_color` is true.
///
/// The message can carry untrusted text (a peer's error body, a decoded
/// field), so each line passes through
/// [`scrub_log_controls`](crate::system::scrub_log_controls): the only escape
/// codes that reach stderr are this function's own colour codes.
pub(crate) fn format_task_error(msg: &str, use_color: bool) -> String {
    use crate::system::scrub_log_controls;
    let (red, reset) = if use_color {
        ("\x1b[31m", "\x1b[0m")
    } else {
        ("", "")
    };
    let mut out = String::new();
    let mut lines = msg.lines();
    if let Some(first) = lines.next() {
        let first = scrub_log_controls(first);
        out.push_str(&format!("{EPRINT_GUTTER}{red}✗{reset} {first}\n"));
        for rest in lines {
            let rest = scrub_log_controls(rest);
            out.push_str(&format!("{EPRINT_GUTTER}  {rest}\n"));
        }
    }
    out
}

/// Print a task-error message to stderr, styled like the CLI: a red `✗` glyph
/// on the first line with a 2-space gutter, then each continuation line
/// indented by the same gutter. When stderr is not a terminal or `NO_COLOR` is
/// set, the glyph and gutter are still printed but without ANSI colour codes.
///
/// Intended for the emitted app's `fn main` to replace the raw `{:?}` debug
/// print with a readable, consistently styled failure.
pub fn eprint_task_error(msg: &str) {
    use std::io::{IsTerminal as _, Write as _};
    let use_color = std::io::stderr().is_terminal()
        && matches!(
            super::system::read_env_var("NO_COLOR"),
            Err(std::env::VarError::NotPresent)
        );
    let formatted = format_task_error(msg, use_color);
    let _ = std::io::stderr().write_all(formatted.as_bytes());
}

// The whole test module exercises the `IpeMaybe` serde round-trip (its
// `Serialize` derive + hand-written `Deserialize` visitor), so it compiles only
// when the `serde` feature is on. `cargo test --features serde` (or `json`) runs
// them; a `--no-default-features` test build has no serde impls to exercise.
#[cfg(all(test, feature = "serde"))]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // IpeMaybe<T> Deserialize regressions — pinned in-tree for every T.
    // -----------------------------------------------------------------------

    // --- IpeMaybe<i64> ---

    #[test]
    fn ipe_maybe_i64_tagged_just() {
        let v: IpeMaybe<i64> = serde_json::from_str(r#"{"Just":5}"#).unwrap();
        assert_eq!(v, IpeMaybe::Just(5_i64));
    }

    #[test]
    fn ipe_maybe_i64_bare_int_becomes_just() {
        let v: IpeMaybe<i64> = serde_json::from_str("5").unwrap();
        assert_eq!(v, IpeMaybe::Just(5_i64));
    }

    #[test]
    fn ipe_maybe_i64_nothing_string() {
        let v: IpeMaybe<i64> = serde_json::from_str(r#""Nothing""#).unwrap();
        assert_eq!(v, IpeMaybe::Nothing);
    }

    #[test]
    fn ipe_maybe_i64_null_becomes_nothing() {
        let v: IpeMaybe<i64> = serde_json::from_str("null").unwrap();
        assert_eq!(v, IpeMaybe::Nothing);
    }

    #[test]
    fn ipe_maybe_i64_round_trip() {
        let original = IpeMaybe::Just(42_i64);
        let json = serde_json::to_string(&original).unwrap();
        let decoded: IpeMaybe<i64> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);

        let nothing: IpeMaybe<i64> = IpeMaybe::Nothing;
        let json2 = serde_json::to_string(&nothing).unwrap();
        let decoded2: IpeMaybe<i64> = serde_json::from_str(&json2).unwrap();
        assert_eq!(decoded2, nothing);
    }

    // --- IpeMaybe<bool> ---

    #[test]
    fn ipe_maybe_bool_bare_true_becomes_just() {
        let v: IpeMaybe<bool> = serde_json::from_str("true").unwrap();
        assert_eq!(v, IpeMaybe::Just(true));
    }

    #[test]
    fn ipe_maybe_bool_tagged_just() {
        let v: IpeMaybe<bool> = serde_json::from_str(r#"{"Just":false}"#).unwrap();
        assert_eq!(v, IpeMaybe::Just(false));
    }

    #[test]
    fn ipe_maybe_bool_null_becomes_nothing() {
        let v: IpeMaybe<bool> = serde_json::from_str("null").unwrap();
        assert_eq!(v, IpeMaybe::Nothing);
    }

    // --- IpeMaybe<f64> ---

    #[test]
    fn ipe_maybe_f64_bare_float_becomes_just() {
        let v: IpeMaybe<f64> = serde_json::from_str("1.5").unwrap();
        assert_eq!(v, IpeMaybe::Just(1.5_f64));
    }

    #[test]
    fn ipe_maybe_f64_tagged_just() {
        let v: IpeMaybe<f64> = serde_json::from_str(r#"{"Just":2.5}"#).unwrap();
        assert_eq!(v, IpeMaybe::Just(2.5_f64));
    }

    #[test]
    fn ipe_maybe_f64_round_trip() {
        let original = IpeMaybe::Just(0.25_f64);
        let json = serde_json::to_string(&original).unwrap();
        let decoded: IpeMaybe<f64> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);
    }

    // --- IpeMaybe<SmallStruct> ---
    //
    // The guardian confirmed that a bare map `{...}` is REJECTED (Err), NOT
    // mis-decoded as Just(struct).  A bare object arrives via visit_map; the
    // visitor matches on the first key — if it is not "Just"/"Nothing" it
    // returns unknown_variant Err, which is the correct safe behaviour.

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct SmallPoint {
        x: i32,
        y: i32,
    }

    #[test]
    fn ipe_maybe_struct_tagged_just() {
        let v: IpeMaybe<SmallPoint> = serde_json::from_str(r#"{"Just":{"x":1,"y":2}}"#).unwrap();
        assert_eq!(v, IpeMaybe::Just(SmallPoint { x: 1, y: 2 }));
    }

    #[test]
    fn ipe_maybe_struct_bare_map_is_rejected_not_mis_just() {
        // A bare `{"x":1,"y":2}` must NOT decode as Just(SmallPoint{1,2}).
        // The visitor's map arm checks the first key: "x" is not "Just"/"Nothing"
        // → unknown_variant error.  Correct, safe behaviour confirmed by guardian.
        let result: Result<IpeMaybe<SmallPoint>, _> = serde_json::from_str(r#"{"x":1,"y":2}"#);
        assert!(
            result.is_err(),
            "bare struct map must not silently decode as Just"
        );
    }

    #[test]
    fn ipe_maybe_struct_null_becomes_nothing() {
        let v: IpeMaybe<SmallPoint> = serde_json::from_str("null").unwrap();
        assert_eq!(v, IpeMaybe::Nothing);
    }

    #[test]
    fn ipe_maybe_struct_round_trip() {
        let original = IpeMaybe::Just(SmallPoint { x: 10, y: 20 });
        let json = serde_json::to_string(&original).unwrap();
        let decoded: IpeMaybe<SmallPoint> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);
    }

    // --- IpeMaybe<Vec<i64>> ---

    #[test]
    fn ipe_maybe_vec_i64_tagged_just() {
        let v: IpeMaybe<Vec<i64>> = serde_json::from_str(r#"{"Just":[1,2,3]}"#).unwrap();
        assert_eq!(v, IpeMaybe::Just(vec![1_i64, 2, 3]));
    }

    #[test]
    fn ipe_maybe_vec_i64_null_becomes_nothing() {
        let v: IpeMaybe<Vec<i64>> = serde_json::from_str("null").unwrap();
        assert_eq!(v, IpeMaybe::Nothing);
    }

    #[test]
    fn ipe_maybe_vec_i64_round_trip() {
        let original = IpeMaybe::Just(vec![10_i64, 20, 30]);
        let json = serde_json::to_string(&original).unwrap();
        let decoded: IpeMaybe<Vec<i64>> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);
    }

    // --- IpeMaybe<IpeMaybe<i64>> (nested) ---

    #[test]
    fn ipe_maybe_nested_just_just() {
        // {"Just":{"Just":5}} → Just(Just(5))
        let v: IpeMaybe<IpeMaybe<i64>> = serde_json::from_str(r#"{"Just":{"Just":5}}"#).unwrap();
        assert_eq!(v, IpeMaybe::Just(IpeMaybe::Just(5_i64)));
    }

    #[test]
    fn ipe_maybe_nested_just_nothing() {
        // {"Just":"Nothing"} → Just(Nothing)
        let v: IpeMaybe<IpeMaybe<i64>> = serde_json::from_str(r#"{"Just":"Nothing"}"#).unwrap();
        assert_eq!(v, IpeMaybe::Just(IpeMaybe::Nothing));
    }

    #[test]
    fn ipe_maybe_nested_nothing() {
        let v: IpeMaybe<IpeMaybe<i64>> = serde_json::from_str(r#""Nothing""#).unwrap();
        assert_eq!(v, IpeMaybe::Nothing);
    }

    #[test]
    fn ipe_maybe_nested_null_becomes_nothing() {
        let v: IpeMaybe<IpeMaybe<i64>> = serde_json::from_str("null").unwrap();
        assert_eq!(v, IpeMaybe::Nothing);
    }

    #[test]
    fn ipe_maybe_nested_round_trip() {
        let original: IpeMaybe<IpeMaybe<i64>> = IpeMaybe::Just(IpeMaybe::Just(99_i64));
        let json = serde_json::to_string(&original).unwrap();
        let decoded: IpeMaybe<IpeMaybe<i64>> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, original);
    }

    // -----------------------------------------------------------------------
    // Existing panic-classifier tests
    // -----------------------------------------------------------------------

    #[test]
    fn classify_and_log_panic_returns_8hex_errid_and_never_panics() {
        // &str, String, and a non-string payload all yield an 8-hex errId — and
        // the call itself never panics (it runs in a panic-unwinding context).
        let s: &str = "divide by zero";
        let e1 = classify_and_log_panic(&s);
        let owned: String = "index out of bounds: the len is 0".to_string();
        let e2 = classify_and_log_panic(&owned);
        let other: i32 = 42; // non-string payload → "panic" fallback
        let e3 = classify_and_log_panic(&other);
        for id in [&e1, &e2, &e3] {
            assert_eq!(id.len(), 8, "errId not 8 chars: {id}");
            // The errId is the ONLY value interpolated into the HTTP 500 body, so
            // its charset MUST be [0-9a-f] — proving the body can carry nothing
            // attacker-influenced.
            assert!(
                id.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "errId not lowercase hex: {id}"
            );
        }
    }

    #[test]
    fn classify_panic_maps_known_kinds() {
        assert_eq!(
            classify_panic("attempt to divide by zero"),
            "DivisionByZero"
        );
        assert_eq!(
            classify_panic("index out of bounds: the len is 3"),
            "IndexOutOfRange"
        );
        assert_eq!(
            classify_panic("attempt to add with overflow"),
            "ArithmeticOverflow"
        );
        assert_eq!(
            classify_panic("maximum recursion depth exceeded"),
            "RecursionLimit"
        );
        assert_eq!(classify_panic("something else entirely"), "Unexpected");
    }

    // The `RecursionLimit` arm is matched BEFORE the `"overflow"` arm and the trip
    // message omits "overflow", so a recursion trip can never misclassify as
    // `ArithmeticOverflow`, and a genuine overflow message is unaffected.
    #[test]
    fn recursion_trip_never_misclassifies_as_overflow() {
        assert_eq!(
            classify_panic("maximum recursion depth exceeded"),
            "RecursionLimit"
        );
        assert_eq!(
            classify_panic("attempt to multiply with overflow"),
            "ArithmeticOverflow"
        );
    }

    // The typed `RecursionLimit` payload renders to the fixed human message and is
    // recognised regardless of any wording — the classification is type-driven,
    // not string-driven. A genuine overflow, carried only as a message string,
    // still classifies as `ArithmeticOverflow`, unaffected by the typed path.
    #[test]
    fn typed_recursion_payload_renders_fixed_message() {
        let payload: Box<dyn std::any::Any + Send> = Box::new(RecursionLimit);
        assert_eq!(
            panic_payload_message(payload.as_ref()),
            "maximum recursion depth exceeded"
        );
        assert_eq!(RecursionLimit::MESSAGE, "maximum recursion depth exceeded");
        assert_eq!(
            RecursionLimit.to_string(),
            "maximum recursion depth exceeded"
        );

        let overflow: Box<dyn std::any::Any + Send> = Box::new("attempt to multiply with overflow");
        assert!(overflow.downcast_ref::<RecursionLimit>().is_none());
        assert_eq!(
            classify_panic(&panic_payload_message(overflow.as_ref())),
            "ArithmeticOverflow"
        );
    }

    // [B8] The Ipê-visible message NEVER contains the foreign error's Debug detail
    // (which can carry a bearer token / API key / URL from a transport error). It
    // is a fixed generic message + a correlation id only.
    #[derive(Debug)]
    struct SecretBearingError {
        #[allow(dead_code)]
        bearer: &'static str,
    }

    #[test]
    fn foreign_error_redacts_secret_from_ipe_message() {
        let e = SecretBearingError {
            bearer: "Bearer sk_live_SUPERSECRET_KEY",
        };
        let msg: String = ipe_error_from_foreign(e);
        assert!(
            !msg.contains("SUPERSECRET") && !msg.contains("Bearer") && !msg.contains("bearer"),
            "the foreign Debug detail (with the bearer token) must NOT reach the Ipe-visible \
             message — got: {msg:?}"
        );
        assert!(
            msg.starts_with("external operation failed (ref ") && msg.ends_with(')'),
            "the Ipe-visible message must be the fixed generic message + correlation id — \
             got: {msg:?}"
        );
        // The 8-hex correlation id is present between the fixed prefix and `)`.
        let id = msg
            .trim_start_matches("external operation failed (ref ")
            .trim_end_matches(')');
        assert_eq!(id.len(), 8, "correlation id is 8 hex chars — got: {id:?}");
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "id must be hex — got: {id:?}"
        );
    }

    #[test]
    fn panic_payload_redacts_secret_from_ipe_message() {
        // A foreign panic message is foreign-controlled free text — it must be
        // funnel-redacted exactly like a foreign error's Debug.
        let payload: Box<dyn std::any::Any + Send> =
            Box::new("token=sk_live_SUPERSECRET_KEY".to_string());
        let msg: String = ipe_error_from_panic("foreign call panicked", payload);
        assert!(
            !msg.contains("SUPERSECRET") && !msg.contains("token"),
            "the panic payload must NOT reach the Ipe-visible message — got: {msg:?}"
        );
        assert!(
            msg.starts_with("foreign call panicked (ref ") && msg.ends_with(')'),
            "the Ipe-visible message is the emitter-owned context + correlation id — got: {msg:?}"
        );
        let id = msg
            .trim_start_matches("foreign call panicked (ref ")
            .trim_end_matches(')');
        assert_eq!(id.len(), 8, "correlation id is 8 hex chars — got: {id:?}");
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "id must be hex — got: {id:?}"
        );
    }

    #[test]
    fn a_panicking_payload_drop_is_contained() {
        // A foreign panic payload can be an arbitrary type whose Drop panics;
        // disposing of it inside the funnel must not re-open the boundary the
        // wrapper just closed.
        struct PanicsOnDrop;
        impl Drop for PanicsOnDrop {
            fn drop(&mut self) {
                // Only the funnel's guarded drop may run this.
                if !std::thread::panicking() {
                    panic!("drop bomb");
                }
            }
        }
        let payload: Box<dyn std::any::Any + Send> = Box::new(PanicsOnDrop);
        let id = note_foreign_panic("foreign call panicked", payload);
        assert_eq!(id.len(), 8, "the funnel survives a panicking payload Drop");
    }

    #[test]
    fn non_string_panic_payload_falls_back_to_fixed_message() {
        let payload: Box<dyn std::any::Any + Send> = Box::new(42_u32);
        let msg: String = ipe_error_from_panic("foreign closure panicked", payload);
        assert!(
            msg.starts_with("foreign closure panicked (ref "),
            "a non-string payload still yields the generic context message — got: {msg:?}"
        );
    }

    // ── Result ↔ Maybe bridges — Elm-matching semantics ───────────────────

    #[test]
    fn result_to_maybe_matches_elm() {
        // Elm: toMaybe (Ok 5) == Just 5; toMaybe (Err e) == Nothing.
        let ok: IpeResult<String, i64> = IpeResult::Ok(5);
        assert_eq!(ipe_result_to_maybe(ok), IpeMaybe::Just(5));
        let err: IpeResult<String, i64> = IpeResult::Err("boom".to_string());
        assert_eq!(ipe_result_to_maybe(err), IpeMaybe::Nothing);
    }

    #[test]
    fn result_from_maybe_matches_elm() {
        // Elm: fromMaybe e (Just v) == Ok v; fromMaybe e Nothing == Err e.
        let just: IpeResult<String, i64> =
            ipe_result_from_maybe("missing".to_string(), IpeMaybe::Just(9));
        assert_eq!(just, IpeResult::Ok(9));
        let nothing: IpeResult<String, i64> =
            ipe_result_from_maybe("missing".to_string(), IpeMaybe::Nothing);
        assert_eq!(nothing, IpeResult::Err("missing".to_string()));
    }
}

// The recursion-guard tests need no serde impls, so they live in their own
// always-on module. Each depth-sensitive test runs on a dedicated thread so the
// thread-local depth counter and stack floor start clean and never race another
// test on the process's threads.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod recursion_guard_tests {
    use super::*;

    #[test]
    fn parse_recursion_limit_ladder() {
        // Unset / unparseable / zero → default; positive → verbatim.
        assert_eq!(parse_recursion_limit(None), DEFAULT_RECURSION_LIMIT);
        assert_eq!(
            parse_recursion_limit(Some("garbage".to_string())),
            DEFAULT_RECURSION_LIMIT
        );
        assert_eq!(
            parse_recursion_limit(Some("0".to_string())),
            DEFAULT_RECURSION_LIMIT
        );
        assert_eq!(
            parse_recursion_limit(Some("-5".to_string())),
            DEFAULT_RECURSION_LIMIT
        );
        assert_eq!(parse_recursion_limit(Some("  42  ".to_string())), 42);
        assert_eq!(parse_recursion_limit(Some("1".to_string())), 1);
    }

    // A balanced enter/leave returns the depth counter to where it started, and a
    // guard held across a nested guard sees a strictly deeper level.
    #[test]
    fn raii_decrement_balances_on_normal_return() {
        std::thread::Builder::new()
            .stack_size(RUNTIME_THREAD_STACK_SIZE)
            .spawn(|| {
                assert_eq!(recursion_depth_for_test(), 0);
                {
                    let _outer = recursion_guard();
                    assert_eq!(recursion_depth_for_test(), 1);
                    {
                        let _inner = recursion_guard();
                        assert_eq!(recursion_depth_for_test(), 2);
                    }
                    assert_eq!(recursion_depth_for_test(), 1);
                }
                assert_eq!(recursion_depth_for_test(), 0);
            })
            .expect("spawn test thread")
            .join()
            .expect("test thread panicked");
    }

    // The RAII decrement fires as the stack unwinds through a caught panic, so the
    // depth counter returns to zero even when a guarded call chain is torn down by
    // an unwind rather than a normal return.
    #[test]
    fn raii_decrement_balances_across_caught_unwind() {
        std::thread::Builder::new()
            .stack_size(RUNTIME_THREAD_STACK_SIZE)
            .spawn(|| {
                let r = std::panic::catch_unwind(|| {
                    let _g0 = recursion_guard();
                    let _g1 = recursion_guard();
                    let _g2 = recursion_guard();
                    assert_eq!(recursion_depth_for_test(), 3);
                    panic!("unwind through three guards");
                });
                assert!(r.is_err(), "the deliberate panic must propagate");
                assert_eq!(
                    recursion_depth_for_test(),
                    0,
                    "every guard's drop must restore its decrement across the unwind"
                );
            })
            .expect("spawn test thread")
            .join()
            .expect("test thread panicked");
    }

    // Unbounded recursion trips at the depth budget with the fixed message — a
    // clean, catchable panic, never a process abort. Driven with the real default
    // limit so the test pins the shipped budget.
    #[test]
    fn depth_budget_trips_with_fixed_message() {
        // Unbounded by construction — the guard, not a base case, is what stops it.
        #[allow(unconditional_recursion)]
        fn recurse() {
            let _g = recursion_guard();
            recurse();
        }
        // A stack large enough to hold DEFAULT_RECURSION_LIMIT guarded frames so
        // the DEPTH budget — not a native overflow — is what trips. No floor is
        // recorded on this thread, so the probe is inert (depth-only).
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let r = std::panic::catch_unwind(recurse);
                let payload = r.expect_err("unbounded recursion must trip the guard");
                // The trip carries the TYPED `RecursionLimit` payload, not a string.
                assert!(
                    payload.downcast_ref::<RecursionLimit>().is_some(),
                    "the trip must panic with the typed RecursionLimit payload"
                );
                // The human message the classifier renders stays byte-identical.
                assert_eq!(
                    panic_payload_message(payload.as_ref()),
                    "maximum recursion depth exceeded"
                );
                assert_eq!(
                    recursion_depth_for_test(),
                    0,
                    "the counter must unwind back to zero after the trip"
                );
            })
            .expect("spawn test thread")
            .join()
            .expect("test thread panicked");
    }

    // A correct bounded recursion well under the limit never trips — the guard is
    // invisible to working programs.
    #[test]
    fn bounded_recursion_under_limit_does_not_trip() {
        fn sum_to(n: u64) -> u64 {
            let _g = recursion_guard();
            if n == 0 { 0 } else { n + sum_to(n - 1) }
        }
        std::thread::Builder::new()
            .stack_size(RUNTIME_THREAD_STACK_SIZE)
            .spawn(|| {
                assert_eq!(sum_to(1_000), 500_500);
                assert_eq!(recursion_depth_for_test(), 0);
            })
            .expect("spawn test thread")
            .join()
            .expect("test thread panicked");
    }

    // On a deliberately small stack WITH a recorded floor, the red-zone probe
    // trips before the depth budget: a runaway recursion on a small stack fails
    // via the remaining-stack backstop, not a native overflow, and well below
    // DEFAULT_RECURSION_LIMIT frames.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn red_zone_probe_trips_below_depth_limit_on_small_stack() {
        // 512 KiB: above the 256 KiB red zone (so a floor can be recorded with
        // headroom), but far too small to hold 10 000 frames — the probe must
        // trip first.
        let small_stack = 512 * 1024;
        std::thread::Builder::new()
            .stack_size(small_stack)
            .spawn(move || {
                record_stack_floor(small_stack);
                assert!(stack_floor_for_test().is_some(), "floor must be recorded");
                // Unbounded by construction — the red-zone probe, not a base case,
                // is what stops it on this deliberately small stack.
                #[allow(unconditional_recursion)]
                fn recurse() -> usize {
                    let _g = recursion_guard();
                    // A non-trivial local array grows the frame so the probe is
                    // exercised well before 10 000 depth.
                    let pad = [0u8; 256];
                    std::hint::black_box(&pad);
                    recurse() + usize::from(pad[0])
                }
                let r = std::panic::catch_unwind(recurse);
                let payload = r.expect_err("small stack must trip the guard, not overflow");
                assert!(
                    payload.downcast_ref::<RecursionLimit>().is_some(),
                    "the red-zone trip must panic with the typed RecursionLimit payload"
                );
                assert_eq!(
                    panic_payload_message(payload.as_ref()),
                    "maximum recursion depth exceeded"
                );
                assert!(
                    recursion_depth_for_test() < DEFAULT_RECURSION_LIMIT,
                    "the probe must trip BELOW the depth budget on a small stack; \
                     tripped at depth {}",
                    recursion_depth_for_test()
                );
            })
            .expect("spawn test thread")
            .join()
            .expect("test thread panicked");
    }

    // A thread whose floor was never recorded runs depth-only: the probe is inert
    // (fail-safe, never a false trip), so a shallow guarded call always succeeds.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn floorless_thread_runs_depth_only() {
        std::thread::Builder::new()
            .stack_size(RUNTIME_THREAD_STACK_SIZE)
            .spawn(|| {
                assert!(
                    stack_floor_for_test().is_none(),
                    "a fresh thread has no recorded floor"
                );
                // Shallow guarded calls must succeed with no floor present.
                let _g0 = recursion_guard();
                let _g1 = recursion_guard();
                assert_eq!(recursion_depth_for_test(), 2);
            })
            .expect("spawn test thread")
            .join()
            .expect("test thread panicked");
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod eprint_tests {
    use super::*;

    /// In plain (no-colour) mode the first line is guttered with a ✗ glyph and
    /// continuation lines get the matching indent, with no ANSI escapes.
    #[test]
    fn eprint_task_error_plain_single_line() {
        let out = format_task_error("something went wrong", false);
        assert_eq!(out, "  ✗ something went wrong\n");
        assert!(!out.contains('\x1b'), "no ANSI in plain mode");
    }

    #[test]
    fn eprint_task_error_plain_multi_line() {
        let msg = "port 8000 is already in use.\nSet a different port.";
        let out = format_task_error(msg, false);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(
            lines[0].starts_with("  ✗ "),
            "first line has gutter + glyph"
        );
        assert!(
            lines[1].starts_with("    "),
            "continuation line is indented"
        );
        assert!(!out.contains('\x1b'), "no ANSI in plain mode");
    }

    #[test]
    fn eprint_task_error_colour_mode_has_ansi() {
        let out = format_task_error("error", true);
        assert!(out.contains('\x1b'), "colour mode carries ANSI escapes");
        assert!(out.contains("✗"), "failure glyph present");
    }

    #[test]
    fn eprint_task_error_empty_message_produces_no_output() {
        let out = format_task_error("", false);
        assert!(out.is_empty(), "empty message → no output");
    }

    /// Untrusted control text in the message cannot drive the terminal or
    /// forge a line: ESC, a bare CR, U+2028, and bidi controls are escaped on
    /// every line, while the gutter, glyph, and line split stay intact.
    #[test]
    fn eprint_task_error_scrubs_controls_in_every_line() {
        let msg = "bad \x1b[2Jpeer\rforged\u{2028}x\nnext \u{202e}rev\u{2066}\x07";
        let out = format_task_error(msg, false);
        assert_eq!(
            out,
            "  ✗ bad \\u{1b}[2Jpeer\\rforged\\u{2028}x\n    next \\u{202e}rev\\u{2066}\\u{7}\n"
        );
        assert!(!out.contains('\x1b'), "no escape survives in plain mode");
    }

    /// In colour mode the only escapes are the glyph's own red/reset pair.
    #[test]
    fn eprint_task_error_colour_mode_keeps_only_its_own_escapes() {
        let out = format_task_error("\x1b[31mfake\x1b[0m", true);
        assert_eq!(out, "  \x1b[31m✗\x1b[0m \\u{1b}[31mfake\\u{1b}[0m\n");
    }
}
