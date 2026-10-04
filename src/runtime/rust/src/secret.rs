//! `Ipe.Secret` — an opaque wrapper for sensitive strings (API keys,
//! passwords, tokens) that CANNOT be accidentally leaked via `Debug`,
//! stringification, logging, or serialization.
//!
//! Mirrors `Ipe.Db.Sql`'s `SqlFragment` "opaque newtype with typed
//! constructors" convention (`db.rs`'s `SqlFragment` doc block):
//! the ONLY way to obtain a `Secret` is through [`secret_from_string`] (the
//! seal), and the ONLY way to get the plaintext back out is through
//! [`secret_reveal`] (the single greppable un-parse). Every other path —
//! `Debug`, the Ipê-level `IpeStringify` (backing `toString` / interpolation /
//! `Log.*With`), equality — is **safe by construction**: each has a
//! hand-written impl on `Secret` itself, so there is no OTHER impl a caller
//! could accidentally reach that would expose the plaintext.
//!
//! # Design (see ADR 0003 for the `Secret` sealed-newtype decision;
//! docs/adr/0003-security-render-and-data-access-invariants.md for the sibling `SqlFragment`)
//!
//! * `Clone` — derived (a `Secret` may be stored, passed around, and used at
//!   more than one call site, same as any other opaque runtime value).
//! * `PartialEq` — hand-written, CONSTANT-TIME (`subtle::ConstantTimeEq`).
//!   This is the ONLY equality impl that exists on `Secret`, so `==` is safe
//!   by construction: there is no faster/leakier impl a caller could reach
//!   instead. Ipê's `Dict`-key / `Set`-element / ordering (`<`/`>`) bounds are
//!   ALREADY rejected with zero new type-checker code — `Secret` is a bare
//!   `Ty::Con` outside the 4-5-scalar `comparable`/`Ord` allowlist in
//!   `ipe_types::concrete_super_ok` / `emitted_bound_satisfied`.
//! * `Debug` — hand-written, ALWAYS returns the fixed redacted placeholder,
//!   regardless of the wrapped value.
//! * `IpeStringify` — hand-written, ALWAYS returns the same redacted
//!   placeholder. This is the trait that backs `Error.toString` / `Debug.log`
//!   (`ipe_runtime::stringify::IpeStringify`), so a `Secret` nested in a
//!   debug-rendered value never leaks.
//! * NO `IpeInterpolate` — a `Secret` is not an interpolable scalar, so
//!   `{{secret}}` and a `Secret` `Log.*With` attribute are refused at
//!   type-check; the explicit render is `Secret.redacted`.
//! * NO `Display`, NO `Hash`, NO `Ord`, NO `serde::Serialize` /
//!   `serde::Deserialize`. Never implementing these is itself part of the
//!   security property: any `std::fmt::Display`-based formatting and any
//!   `HashMap`/`BTreeMap` key use, and any serde round-trip, are Rust type
//!   errors at codegen time — a fail-CLOSED outcome, never a silent leak.
//!   NOT serde ALSO means `Secret` is unconditionally Model-inadmissible for
//!   `Ipe.Web` (`ir_type_is_serde` gates the Web Model — see
//!   `ipe_ir::ir_type_is_serde` — so a `Web` app storing a `Secret` in its
//!   Model is a compile-time `IPE-L0120`, never a session-store leak).
//! * `Drop` — zeroizes the backing buffer (`zeroize::Zeroize`) so the
//!   plaintext does not linger in freed heap memory after the `Secret` goes
//!   out of scope. Ships now, not deferred (security-tier hardening is
//!   pre-push per `PRINCIPLES.md`).
//!
//! Payload stays `String` in v1 — every current consumer (`Ipe.Auth`, env
//! vars) is string-shaped. A `Bytes`-payload variant is an additive,
//! filed-not-built follow-up.
//!
//! # WASM hydration-island boundary (out of scope, not gated here)
//!
//! `docs/adr/0005-delivery-shapes-runtimes-hosts-targets.md` §Q6 documents a future
//! `HydrationState` field-type gate that must reject any field whose type
//! transitively contains `Secret` (or any other server-only/secret-bearing
//! type) at the `HydrationState` declaration. That gate has NOTHING TO GATE
//! YET — the WASM target does not exist in this compiler (Target A per the
//! design doc is un-implemented). `Secret`'s `ir_type_is_serde = false`
//! classification IS the future predicate that gate will consult once the
//! WASM target lands; no code is added here on Secret's behalf.

use zeroize::Zeroize;

use super::stringify::IpeStringify;

// The fixed placeholder every stringification path returns, regardless of the
// wrapped value; one spelling shared with every redacting `Debug`.
use crate::redact::REDACTED;

/// `Ipe.Secret`'s opaque, sealed newtype. See the module doc for the
/// full design rationale.
///
/// Deliberately NOT `#[derive(Debug)]` — the derive would print the wrapped
/// `String` verbatim, exactly the leak this type exists to prevent. `Clone`
/// is safe to derive: cloning does not observe the payload.
#[derive(Clone)]
pub struct Secret(String);

// `PartialEq` is constant-time via the shared `ct_bytes_eq` predicate.
// Length mismatch short-circuits (length is non-secret metadata); the
// per-byte comparison, when lengths match, is constant-time via
// `subtle::ConstantTimeEq`. Adding `#[derive(PartialEq)]` alongside this
// invocation would be a hard E0119 compile error — the structural guarantee
// that the timing-safe impl is the only one that exists.
crate::ct_eq::impl_ct_eq!(Secret);

impl std::fmt::Debug for Secret {
    /// ALWAYS the fixed placeholder — never the wrapped value, never even
    /// the payload's length (unlike `PartialEq`, which treats length as
    /// non-secret metadata; `Debug` output is far more likely to end up in a
    /// log line or a `dbg!()` left in shipped code, so it stays maximally
    /// conservative).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

impl IpeStringify for Secret {
    /// Backs Ipê's `toString` / string interpolation / `Log.*With` attr
    /// stringification. ALWAYS the fixed placeholder — a caller that logs a
    /// `Secret` directly (forgetting to call `Secret.redacted` first) gets
    /// the safe redacted output automatically rather than a compile error
    /// whose only fix is remembering the very escape hatch they forgot.
    fn ipe_show(&self) -> String {
        REDACTED.to_owned()
    }
}

impl Drop for Secret {
    /// Zeroize the backing buffer so the plaintext does not linger in freed
    /// heap memory. Ships now (security-tier hardening is pre-push), not
    /// deferred.
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Secret {
    /// The payload's length in bytes, the non-secret metadata a bound reads.
    #[cfg_attr(not(feature = "db"), allow(dead_code))] // only `Db.Dsn` bounds a secret
    pub(crate) const fn byte_len(&self) -> usize {
        self.0.len()
    }
}

/// `Secret.fromString : String -> Secret` — THE seal. The only public
/// constructor: every `Secret` value in a Ipê program traces back to exactly
/// one of these calls, so a security reviewer can `grep` this one symbol to
/// audit every place a plaintext string becomes a typed secret.
///
/// # Sanctioned raw-secret escape hatch (config credentials)
///
/// This is the deliberate escape hatch for turning an already-in-hand plaintext
/// into a `Secret` — e.g. a value the program itself derived, or a test fixture.
/// For CONFIGURATION credentials (`Db.url`, a JWT secret) the RECOMMENDED source
/// is `App.fromEnv "VAR"`, which reads the value from the environment at startup:
/// it keeps the credential out of source entirely, whereas
/// `Secret.fromString "literal"` type-checks and would inline the plaintext. The
/// `fromString` path is kept (a program legitimately needs to seal a
/// runtime-obtained string), so it is greppable-by-design rather than removed —
/// a reviewer audits every literal-credential seal by searching this one symbol.
#[must_use]
pub fn secret_from_string(s: String) -> Secret {
    Secret(s)
}

/// `Secret.reveal : Secret -> String` — THE single greppable un-parse. The
/// only way to recover the plaintext. Consumes `s` (rather than borrowing)
/// so the caller cannot keep both the `Secret` and a live plaintext `&str`
/// derived from it around simultaneously by accident — the typed wrapper is
/// gone the moment the plaintext comes out.
///
/// `mem::take` (not `std::mem::replace(&mut s.0, String::new())` written
/// out) leaves `s.0` as an empty `String` for the structurally-required
/// `Drop` to zeroize (a no-op on empty) — avoids the `E0509` "cannot move
/// out of type that implements Drop" that a bare `s.0` move would hit.
#[must_use]
pub fn secret_reveal(mut s: Secret) -> String {
    std::mem::take(&mut s.0)
}

/// `Secret.use : Secret -> (String -> a) -> a` — the SCOPED consume. Reveals
/// the plaintext, hands it to `f`, and returns `f`'s result. A thin wrapper
/// over [`secret_reveal`]: `secret_use(s, f) == f(secret_reveal(s))`.
///
/// The revealed `String` is a local `moved` into `f` and touched nowhere else —
/// never logged, cached, stored, cloned, or `Debug`-printed here. It lives only
/// for the duration of the `f` call; once `f` returns, the local is dropped.
/// The whole body is a single `f(secret_reveal(s))` expression: no indexing, no
/// `unwrap`/`expect`, no `panic!` — it cannot fail on its own (any panic can
/// only come from inside the caller's `f`).
///
/// GUARANTEE BOUNDARY (honest): this is NOT a type-enforced non-escape. The
/// common scoped shape — build a header, compute an HMAC, compare, and return a
/// NON-secret `a` — keeps the plaintext inside `f`. But a determined caller can
/// write `Secret.use s (\x -> x)` (identity) and extract the raw `String` all
/// the same, exactly as `Ipe.Secret.Unsafe.unsafeReveal` does. That identity
/// form is a VISIBLE code smell at the call site, not a hidden bypass; the hard,
/// disclosed extract remains `unsafeReveal` (which discloses the `unsafe`
/// capability program-wide). The value of `use` is the greppable trust surface:
/// the common scoped uses stay OFF the `unsafe` axis, so the disclosed hatch is
/// reserved for the blunt raw-extract.
#[must_use]
pub fn secret_use<A>(s: Secret, f: impl FnOnce(String) -> A) -> A {
    f(secret_reveal(s))
}

/// `Secret.redacted : Secret -> String` — the EXPLICIT redaction accessor.
/// Also exactly what `toString` / interpolation gives automatically via
/// [`IpeStringify`] above; exists as a named, discoverable, non-`Debug`-
/// reliant way to get a display-safe placeholder string (e.g. to embed in a
/// user-facing message: `"using key " ++ Secret.redacted k`).
#[must_use]
pub fn secret_redacted(s: Secret) -> String {
    let _ = s; // never read — proves the placeholder never derives from the payload
    REDACTED.to_owned()
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    // ── (a) normal safe usage works end-to-end ──────────────────────────────

    #[test]
    fn seal_then_reveal_round_trips() {
        let s = secret_from_string("sk_live_abc123".to_owned());
        assert_eq!(secret_reveal(s), "sk_live_abc123");
    }

    #[test]
    fn use_applies_the_function_to_the_revealed_plaintext() {
        let s = secret_from_string("sk_live_abc123".to_owned());
        // The scoped function sees the exact revealed plaintext.
        let seen = secret_use(s, |plain| plain.len());
        assert_eq!(seen, "sk_live_abc123".len());
    }

    #[test]
    fn use_returns_a_non_secret_derived_value_without_the_payload() {
        // The common scoped shape: derive a NON-secret `a` (here a masked
        // prefix) inside the closure and return it. The returned value does
        // not contain the raw payload — the plaintext stayed in the closure.
        let s = secret_from_string("sk_live_super_secret".to_owned());
        let masked = secret_use(s, |plain| {
            let head: String = plain.chars().take(7).collect();
            format!("{head}…")
        });
        assert_eq!(masked, "sk_live…");
        assert!(!masked.contains("super_secret"));
    }

    #[test]
    fn use_reveal_equivalence() {
        // `secret_use(s, f) == f(secret_reveal(s))` — the wrapper is exactly a
        // scoped `reveal`. Two independently-sealed clones prove both paths
        // yield the same value.
        let a = secret_from_string("token-xyz".to_owned());
        let b = secret_from_string("token-xyz".to_owned());
        let via_use = secret_use(a, |p| format!("Bearer {p}"));
        let via_reveal = format!("Bearer {}", secret_reveal(b));
        assert_eq!(via_use, via_reveal);
    }

    #[test]
    fn redacted_never_returns_the_payload() {
        let s = secret_from_string("sk_live_abc123".to_owned());
        assert_eq!(secret_redacted(s), REDACTED);
    }

    #[test]
    fn equal_secrets_compare_equal() {
        let a = secret_from_string("same-value".to_owned());
        let b = secret_from_string("same-value".to_owned());
        assert_eq!(a, b);
    }

    #[test]
    fn different_secrets_compare_unequal() {
        let a = secret_from_string("value-one".to_owned());
        let b = secret_from_string("value-two-longer".to_owned());
        assert_ne!(a, b);
    }

    #[test]
    fn different_length_secrets_compare_unequal() {
        let a = secret_from_string("short".to_owned());
        let b = secret_from_string("a-lot-longer-value".to_owned());
        assert_ne!(a, b);
    }

    #[test]
    fn clone_is_independently_comparable() {
        let a = secret_from_string("clone-me".to_owned());
        let b = a.clone();
        assert_eq!(a, b);
        assert_eq!(secret_reveal(a), "clone-me");
        assert_eq!(secret_reveal(b), "clone-me");
    }

    // ── (b) every plausible accidental-stringification path is redacted ────
    //
    // `{:?}` (Debug), `.ipe_show()` (the trait backing Ipê's `toString` /
    // string interpolation / `Log.*With`), and `Secret.redacted` are the
    // THREE paths that exist on `Secret` and all three are tested here to
    // never expose the payload. The other two plausible leak paths —
    // `{}` (`Display`) and string concatenation (`+` / Ipê's `++`, which
    // requires `String` or `List`) — are not merely "redacted", they are
    // ABSENT: `Secret` implements neither `std::fmt::Display` nor
    // `std::ops::Add`, so `format!("{}", secret)` / `secret + "x"` are Rust
    // compile errors, not runtime redaction. This is verified by
    // construction (the impls below are the exhaustive list of traits
    // `Secret` implements) rather than by a `trybuild`-style negative
    // compile test — see the module doc's "NO `Display`" bullet. The
    // language-level (Ipê, not Rust) mirror of this fact is
    // `crates/ipe/tests/secret_gates.rs`'s `secret_concat_is_rejected`
    // golden, which proves `mySecret ++ "x"` is a `ipe` type error, not a
    // runtime concern.

    const PAYLOAD: &str = "sk_live_super_secret_value_12345";

    #[test]
    fn debug_never_exposes_the_payload() {
        let s = secret_from_string(PAYLOAD.to_owned());
        let shown = format!("{s:?}");
        assert_eq!(shown, REDACTED);
        assert!(!shown.contains(PAYLOAD));
    }

    #[test]
    fn ipe_show_never_exposes_the_payload() {
        let s = secret_from_string(PAYLOAD.to_owned());
        let shown = s.ipe_show();
        assert_eq!(shown, REDACTED);
        assert!(!shown.contains(PAYLOAD));
    }

    /// A `Vec<Secret>` (the shape `Log.*With`'s attr list lowers to) renders
    /// every element through [`IpeStringify`]'s blanket `Vec<T>` impl
    /// (`stringify.rs`) — proves the redaction survives the SAME container
    /// path real Ipê code takes when logging a list containing a secret.
    #[test]
    fn secret_inside_a_vec_stringifies_redacted() {
        let v = vec![secret_from_string(PAYLOAD.to_owned())];
        let shown = v.ipe_show();
        assert!(!shown.contains(PAYLOAD));
        assert!(shown.contains(REDACTED));
    }

    #[test]
    fn debug_is_identical_regardless_of_payload_content() {
        // Even a payload that LOOKS like the redacted placeholder, or is
        // empty, or contains format-string-hostile characters, renders
        // identically — proves the placeholder is a constant, never derived
        // from (or influenced by) the wrapped value.
        for payload in ["", "<redacted>", "{}", "{:?}", "a\nb\tc"] {
            let s = secret_from_string(payload.to_owned());
            assert_eq!(format!("{s:?}"), REDACTED);
            assert_eq!(s.ipe_show(), REDACTED);
        }
    }
}
