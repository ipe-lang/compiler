//! Form-data decoding for `Event::OnForm`.
//!
//! The browser posts a form submit as a `{name: value, …}` object; the event
//! handler turns it into a `FormData` (`HashMap<String, String>`). `decode_form`
//! narrows that into the typed Ipê record `T` the `onSubmit` handler expects.

use crate::html::FormData;

/// Why a browser `FormData` payload did not decode into the target record.
#[derive(Clone, Debug, PartialEq)]
pub enum FormDecodeError {
    /// The name/value pairs could not be re-encoded as `x-www-form-urlencoded`.
    Encode(serde_urlencoded::ser::Error),
    /// The pairs do not fit the target record (a missing required field, an
    /// unknown variant, a value the field's type does not parse).
    Decode(serde_urlencoded::de::Error),
}

impl core::fmt::Display for FormDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Encode(e) => write!(f, "form pairs could not be encoded: {e}"),
            Self::Decode(e) => write!(f, "form does not fit the record: {e}"),
        }
    }
}

impl std::error::Error for FormDecodeError {}

/// Decode a browser `FormData` payload into a typed Ipê record `T`.
///
/// Form values are always strings; `T`'s fields are matched by name (Ipê record
/// fields are camelCase, matching the HTML `name=` attributes the view emits).
/// The pairs are re-encoded as `x-www-form-urlencoded` and deserialized by the
/// target type, so a numeric or bool field parses `"42"`/`"true"` while a
/// `String` field keeps the value verbatim.
///
/// # Errors
///
/// [`FormDecodeError::Encode`] when the pairs cannot be encoded;
/// [`FormDecodeError::Decode`] when they do not fit `T` (a missing required
/// field makes the `OnForm` closure dispatch no Msg).
pub fn decode_form<T: serde::de::DeserializeOwned>(fd: FormData) -> Result<T, FormDecodeError> {
    let pairs: Vec<(String, String)> = fd.into_iter().collect();
    let encoded = serde_urlencoded::to_string(&pairs).map_err(FormDecodeError::Encode)?;
    // `encoded` is this function's own output: every escape is well-formed and
    // the bytes are UTF-8, so the lenient reader reproduces `pairs` exactly and
    // no URL component from the wire is decoded here.
    #[expect(
        clippy::disallowed_methods,
        reason = "re-reads this function's own encoder output, never a URL component from the wire"
    )]
    let decoded = serde_urlencoded::from_str::<T>(&encoded);
    decoded.map_err(FormDecodeError::Decode)
}

/// `decode_form` + a warn on failure. The `OnForm` closure is synchronous and
/// returns `Option<M>`, so a decode failure must surface here (not via the
/// async logger) — it logs a `[ipe.live]` warn line (the emitter scrubs control
/// characters) and returns `None` so the live loop dispatches no Msg.
/// The codegen-emitted `onSubmit` closure calls this.
#[must_use]
pub fn decode_form_or_warn<T: serde::de::DeserializeOwned>(fd: FormData) -> Option<T> {
    match decode_form::<T>(fd) {
        Ok(t) => Some(t),
        Err(e) => {
            // `e` embeds the attacker-supplied form value (e.g. "unknown
            // variant `<value>`"); the emitter neutralises its control bytes.
            crate::system::emit_runtime_log(
                "live",
                &format!("form decode failed, dispatching no Msg: {e}"),
            );
            None
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    // NB: form-target structs gain `#[derive(Default)] #[serde(default)]` in
    // codegen (Emitter.hs) so a missing form field decodes to the field's zero
    // value. These test structs mirror that.
    #[derive(serde::Deserialize, Default, PartialEq, Debug)]
    #[serde(default)]
    struct Creds {
        email: String,
        password: String,
    }

    #[test]
    fn decode_form_or_warn_some_and_none() {
        let mut fd = FormData::new();
        fd.insert("email".to_string(), "a@b.c".to_string());
        fd.insert("password".to_string(), "pw".to_string());
        let r: Option<Creds> = decode_form_or_warn(fd);
        assert_eq!(
            r,
            Some(Creds {
                email: "a@b.c".into(),
                password: "pw".into()
            })
        );

        // A form with NEITHER field still decodes — each field falls to its
        // zero value (via `#[serde(default)]`) — so the Msg dispatches (Some).
        let empty = FormData::new();
        let r2: Option<Creds> = decode_form_or_warn(empty);
        assert_eq!(
            r2,
            Some(Creds {
                email: String::new(),
                password: String::new()
            })
        );
    }

    // The contract record: a String + an i64. Exercises the three decode cases.
    #[derive(serde::Deserialize, Default, PartialEq, Debug)]
    #[serde(default)]
    struct RunPayload {
        code: String,
        count: i64,
    }

    #[test]
    fn decode_form_missing_field_defaults_not_error() {
        // Neither field present (only an UNKNOWN key, as the playground posts
        // `ace-mirror`): decode SUCCEEDS with zero values, Msg dispatches.
        let mut unknown_only = FormData::new();
        unknown_only.insert("ace-mirror".to_string(), "1+1".to_string());
        let r: Option<RunPayload> = decode_form_or_warn(unknown_only);
        assert_eq!(
            r,
            Some(RunPayload {
                code: String::new(),
                count: 0
            })
        );

        // `code` present, `count` absent → count defaults to 0.
        let mut partial = FormData::new();
        partial.insert("code".to_string(), "hello".to_string());
        let r2: Option<RunPayload> = decode_form_or_warn(partial);
        assert_eq!(
            r2,
            Some(RunPayload {
                code: "hello".into(),
                count: 0
            })
        );
    }

    #[test]
    fn decode_form_genuine_coercion_failure_still_none() {
        // A non-numeric string into an i64 field is a GENUINE type error — it
        // must still fail (None + warn), unchanged.Unmarshal also
        // errors on a malformed number). Only MISSING-field stopped being a
        // failure; present-but-malformed stays a failure.
        let mut bad = FormData::new();
        bad.insert("code".to_string(), "ok".to_string());
        bad.insert("count".to_string(), "abc".to_string());
        let r: Option<RunPayload> = decode_form_or_warn(bad);
        assert_eq!(r, None);
    }

    #[derive(serde::Deserialize, PartialEq, Debug)]
    struct Order {
        item: String,
        qty: i64,
        express: bool,
        price: f64,
    }

    #[test]
    fn decode_form_coerces_numeric_and_bool_fields() {
        // The old all-String serde_json path rejected these non-String fields.
        let mut fd = FormData::new();
        fd.insert("item".to_string(), "widget".to_string());
        fd.insert("qty".to_string(), "42".to_string());
        fd.insert("express".to_string(), "true".to_string());
        fd.insert("price".to_string(), "9.99".to_string());
        let r: Result<Order, FormDecodeError> = decode_form(fd);
        assert_eq!(
            r,
            Ok(Order {
                item: "widget".into(),
                qty: 42,
                express: true,
                price: 9.99
            })
        );
    }

    #[test]
    fn decode_form_ok_and_missing() {
        let mut fd = FormData::new();
        fd.insert("email".to_string(), "a@b.c".to_string());
        fd.insert("password".to_string(), "pw".to_string());
        let r: Result<Creds, FormDecodeError> = decode_form(fd);
        assert_eq!(
            r,
            Ok(Creds {
                email: "a@b.c".into(),
                password: "pw".into()
            })
        );

        // Missing `password` → "" (zero value via `#[serde(default)]`), Ok.
        let mut partial = FormData::new();
        partial.insert("email".to_string(), "a@b.c".to_string()); // missing password
        let r2: Result<Creds, FormDecodeError> = decode_form(partial);
        assert_eq!(
            r2,
            Ok(Creds {
                email: "a@b.c".into(),
                password: String::new()
            })
        );
    }

    // A form-target record with a `Maybe`-typed optional field
    // (`note : Maybe String` → `IpeMaybe<String>`) is idiomatic. The codegen
    // `#[derive(Default)]` on this struct requires `IpeMaybe<T>: Default`, which
    // `impl Default for IpeMaybe` (= `Nothing`) supplies, so a MISSING `note`
    // decodes to `Nothing` (the missing-field leniency,  `json.Unmarshal`
    // nil parity).
    //
    // NB on a PRESENT value: `IpeMaybe` derives serde's default (externally-
    // tagged) representation, so a bare urlencoded `note=hello` does NOT
    // round-trip into `IpeMaybe::Just("hello")` — serde expects a `Just`/
    // `Nothing` tag. Surfacing a present optional form value into `Just` is a
    // separate serde-representation concern (it would need `#[serde(untagged)]`
    // / a custom deserialize on `IpeMaybe`, which also touches the session-store
    // serialization contract). We assert the in-scope behaviour: missing
    // → Nothing (no cargo-fail, Msg dispatches), present-bare → decode declines.
    #[derive(serde::Deserialize, Default, PartialEq, Debug)]
    #[serde(default)]
    struct CredsWithNote {
        email: String,
        password: String,
        note: crate::core::IpeMaybe<String>,
    }

    #[test]
    fn decode_form_maybe_field_missing_is_nothing() {
        use crate::core::IpeMaybe;

        // `note` absent → Nothing , decode
        // SUCCEEDS, Msg dispatches. This relies on the struct's
        // `#[derive(Default)]` (which needs `IpeMaybe<T>: Default`, else E0277).
        let mut without_note = FormData::new();
        without_note.insert("email".to_string(), "a@b.c".to_string());
        without_note.insert("password".to_string(), "pw".to_string());
        let r: Option<CredsWithNote> = decode_form_or_warn(without_note);
        assert_eq!(
            r,
            Some(CredsWithNote {
                email: "a@b.c".into(),
                password: "pw".into(),
                note: IpeMaybe::Nothing,
            })
        );
    }

    #[test]
    fn ipe_maybe_default_is_nothing() {
        // Part A contract: the manual `Default` impl yields `Nothing`, and it is
        // UNBOUNDED in `T` — a `IpeMaybe<NonDefault>` field still has a default.
        struct NonDefault;
        assert!(crate::core::IpeMaybe::<String>::default().is_nothing());
        let _unbounded: crate::core::IpeMaybe<NonDefault> = crate::core::IpeMaybe::default();
    }

    // A form-target carrying a NON-Default field (here a `bool`-keyed ADT
    // modelled as a Rust enum) does NOT get the lenient `#[derive(Default)]`
    // stamp in codegen — it keeps the STRICT emission (plain
    // `serde::Deserialize`, no `Default`/`serde(default)`). That still compiles
    // and still decodes; it just lacks missing-field leniency. This struct
    // MIRRORS that strict emission (note: no `Default`, no `#[serde(default)]`).
    #[derive(serde::Deserialize, PartialEq, Debug)]
    enum Tier {
        Free,
        Pro,
    }

    #[derive(serde::Deserialize, PartialEq, Debug)]
    struct Subscription {
        email: String,
        tier: Tier,
    }

    #[test]
    fn strict_form_target_with_non_default_field_still_decodes() {
        // All fields present → Ok (strict path works).
        let mut fd = FormData::new();
        fd.insert("email".to_string(), "a@b.c".to_string());
        fd.insert("tier".to_string(), "Pro".to_string());
        let r: Result<Subscription, FormDecodeError> = decode_form(fd);
        assert_eq!(
            r,
            Ok(Subscription {
                email: "a@b.c".into(),
                tier: Tier::Pro
            })
        );

        // Missing the non-defaultable `tier` → strict decode ERRORS (no leniency),
        // exactly the behaviour the strict emission preserves. It does NOT
        // cargo-fail; it just returns Err — acceptable for the rare
        // enum/Result-field form.
        let mut partial = FormData::new();
        partial.insert("email".to_string(), "a@b.c".to_string());
        let r2: Result<Subscription, FormDecodeError> = decode_form(partial);
        assert!(r2.is_err());
    }

    // A PRESENT optional form field (`note=hello`) must decode to
    // `Just("hello")`, not decline the whole form. This complements the MISSING
    // case (absent field → Nothing) with the PRESENT case.
    //
    // Root cause: `IpeMaybe` derives serde with the default externally-tagged repr
    // (`{"Just":"hello"}` / `"Nothing"`); form data posts a bare string `"hello"`,
    // which serde_urlencoded passes to `IpeMaybe::deserialize` as a bare string
    // value — the tagged deserialiser rejects it, and `decode_form_or_warn` returns
    // None, declining the whole form. Fix: a custom `Deserialize` for `IpeMaybe<T>`
    // that first tries `Option<T>` (bare value → Some(v) → Just(v); null/absent →
    // None → Nothing) and falls back to the tagged enum repr for session-store
    // round-trips (stored `{"Just":"x"}` / `"Nothing"` still deserialise correctly).
    #[test]
    fn decode_form_maybe_field_present_is_just() {
        use crate::core::IpeMaybe;

        // Present `note=hello` → Just("hello").
        let mut with_note = FormData::new();
        with_note.insert("email".to_string(), "a@b.c".to_string());
        with_note.insert("password".to_string(), "pw".to_string());
        with_note.insert("note".to_string(), "hello".to_string());
        let r: Option<CredsWithNote> = decode_form_or_warn(with_note);
        assert_eq!(
            r,
            Some(CredsWithNote {
                email: "a@b.c".into(),
                password: "pw".into(),
                note: IpeMaybe::Just("hello".to_string()),
            })
        );

        // Absent `note` still → Nothing.
        let mut without_note = FormData::new();
        without_note.insert("email".to_string(), "a@b.c".to_string());
        without_note.insert("password".to_string(), "pw".to_string());
        let r2: Option<CredsWithNote> = decode_form_or_warn(without_note);
        assert_eq!(
            r2,
            Some(CredsWithNote {
                email: "a@b.c".into(),
                password: "pw".into(),
                note: IpeMaybe::Nothing,
            })
        );
    }

    // Session-store round-trip: serialize IpeMaybe → JSON → deserialize must
    // preserve the value. This guards the custom `IpeMaybe` Deserialize.
    #[test]
    fn ipe_maybe_session_store_round_trip() {
        use crate::core::IpeMaybe;

        let just_val: IpeMaybe<String> = IpeMaybe::Just("stored".to_string());
        let nothing_val: IpeMaybe<String> = IpeMaybe::Nothing;

        // Serialize (what the session store writes).
        let just_json = serde_json::to_string(&just_val).expect("serialize Just");
        let nothing_json = serde_json::to_string(&nothing_val).expect("serialize Nothing");

        // Deserialize (what the session store reads back).
        let just_rt: IpeMaybe<String> =
            serde_json::from_str(&just_json).expect("deserialize Just round-trip");
        let nothing_rt: IpeMaybe<String> =
            serde_json::from_str(&nothing_json).expect("deserialize Nothing round-trip");

        assert_eq!(just_rt, IpeMaybe::Just("stored".to_string()));
        assert_eq!(nothing_rt, IpeMaybe::Nothing);
    }
}
