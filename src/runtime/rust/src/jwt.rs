//! JWT kernels for Ipe.Jwt — HS256 / RS256 encode + decode.
//!
//! ## Token byte layout
//!
//! `Ipe.Jwt.encode` builds the compact JWS in pure Ipê on top of `Json.Encode`,
//! `Crypto`, and `Encoding`:
//!
//! * header  = `Json.Encode.encode 0 (object [("alg", …), ("typ", "JWT")])`
//! * payload = `Json.Encode.encode 0 <claims value>`
//! * sig(HS) = base64url( raw-bytes( hmacSha256 secret signingInput ) )
//! * sig(RS) = standardToUrl( rsaSha256Sign privKey signingInput )
//!
//! This file rebuilds the token through the same primitives — `json_enc_encode`
//! (sorted object keys + HTML-escape shape) and `crypto_*` — rather than
//! `jsonwebtoken::encode`, whose header field order (`typ` before `alg`) and
//! claims serialization differ and would yield a different signature.
//! See `tests/golden/jwt_hs256_bytes` / `jwt_rs256_bytes` for byte-equality
//! goldens, and `crates/ipe/tests/golden_m5b_uuid_jwt.rs` for the assertions.
//!
//! ## API surface
//!
//! `Ipe.Jwt` exposes a builder API —
//! `Jwt.encode (Jwt.hs256 secret) (Jwt.claims |> Jwt.subject … |> …)` and
//! `Jwt.decode (Jwt.hs256 secret) now token`. The flat kernels below
//! (`encodeHs256` / `decodeHs256` / `encodeRs256` / `decodeRs256`) taking a
//! claims JSON string directly are also exposed. The token bytes are identical
//! across both surfaces. See `docs/architecture/divergence-policy.md`
//! ("Ipe.Jwt API surface") for the recorded interim limitation.

use super::IpeResult;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::Value as JsonValue;
use std::collections::HashSet;

/// base64url, no padding (RFC 7515) — the encoding every JWS segment uses.
fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Convert standard base64 (with padding) to base64url with no padding.
/// Mirrors `Jwt.ipe`'s `standardToUrl`: `+`→`-`, `/`→`_`, strip `=`.
fn standard_to_url(b64: &str) -> String {
    b64.replace('+', "-").replace('/', "_").replace('=', "")
}

/// Render the JWS header `{"alg":"<alg>","typ":"JWT"}` through the deterministic
/// JSON encoder so the bytes have sorted keys (`alg` before `typ`).
fn header_json(alg: &str) -> String {
    let value = super::json_enc_object(vec![
        ("alg".to_string(), super::json_enc_string(alg.to_string())),
        ("typ".to_string(), super::json_enc_string("JWT".to_string())),
    ]);
    super::json_enc_encode(0, value)
}

/// Re-encode a claims JSON string as deterministic sorted-key canonical JSON so
/// the signed payload bytes (sorted object keys at every depth, HTML-escape shape)
/// are byte-stable, independent of the ambient object-order encoder setting.
/// Returns the bad-claims error message on a parse failure.
fn payload_json(claims_json: &str) -> Result<String, String> {
    let value: JsonValue =
        serde_json::from_str(claims_json).map_err(|e| format!("bad claims json: {}", e))?;
    Ok(super::json_enc_canonical(&value))
}

/// Why a token's claims set was refused before any claim in it was trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaimsRefusal {
    /// The payload is not a JSON object, so it has no claims to read
    /// (RFC 7519 §7.2).
    NotAnObject,
    /// A NumericDate claim is present but not a JSON number, so no clock check
    /// could read it.
    NonNumericDate {
        /// The claim's name.
        claim: &'static str,
    },
    /// The token is at or past its `exp`.
    Expired,
    /// The token is before its `nbf`.
    NotYetValid,
}

impl std::fmt::Display for ClaimsRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnObject => f.write_str("token claims set is not a JSON object"),
            Self::NonNumericDate { claim } => {
                write!(f, "token `{claim}` is not a NumericDate")
            }
            Self::Expired => f.write_str("token has expired"),
            Self::NotYetValid => f.write_str("token is not yet valid"),
        }
    }
}

impl std::error::Error for ClaimsRefusal {}

/// A JSON number as whole Unix seconds, flooring toward −∞ so a token is never
/// accepted longer than its fractional `exp` states. `None` when the number has
/// no `f64` reading.
///
/// Flooring is the conservative direction for both claims:
///   - `exp 0.4` → `0`  (already expired at epoch; rejected)
///   - `nbf 0.4` → `0`  (accepts slightly earlier than the fractional value,
///     matching integer-second oracle behaviour)
///   - `exp -0.1` → `-1` (negative, unconditionally in the past; rejected)
fn number_seconds(n: &serde_json::Number) -> Option<i64> {
    n.as_i64().or_else(|| n.as_f64().map(|f| f.floor() as i64))
}

/// Read the NumericDate claim `claim` (RFC 7519 §2: any JSON number, may be
/// fractional) of the claims set `claims` as whole seconds.
///
/// `Ok(None)` means the claim is absent, and only that: a present value that
/// is not a number the clock can read is refused, never passed over.
///
/// # Errors
///
/// [`ClaimsRefusal::NotAnObject`] when `claims` is not a JSON object;
/// [`ClaimsRefusal::NonNumericDate`] when the claim is present but not a
/// readable number (a string, `null`, a boolean, an array, an object).
pub(crate) fn read_numeric_date(
    claims: &JsonValue,
    claim: &'static str,
) -> Result<Option<i64>, ClaimsRefusal> {
    let object = claims.as_object().ok_or(ClaimsRefusal::NotAnObject)?;
    match object.get(claim) {
        None => Ok(None),
        Some(JsonValue::Number(n)) => number_seconds(n)
            .map(Some)
            .ok_or(ClaimsRefusal::NonNumericDate { claim }),
        Some(_) => Err(ClaimsRefusal::NonNumericDate { claim }),
    }
}

/// Admit the claims set `claims` at time `now` (Unix seconds): every registered
/// NumericDate claim (`exp`, `nbf`, `iat`, RFC 7519 §4.1.4–6) that is present
/// must be a number, `now` must be before `exp` and at or after `nbf`. An
/// absent `exp` or `nbf` sets no bound.
///
/// # Errors
///
/// The [`ClaimsRefusal`] naming the first check the claims set failed.
pub(crate) fn admit_time_claims(claims: &JsonValue, now: i64) -> Result<(), ClaimsRefusal> {
    let exp = read_numeric_date(claims, "exp")?;
    let nbf = read_numeric_date(claims, "nbf")?;
    // `iat` bounds nothing here, but a present non-number `iat` is a claims set
    // a reader of the decoded claims would misread.
    read_numeric_date(claims, "iat")?;
    if exp.is_some_and(|exp| now >= exp) {
        return Err(ClaimsRefusal::Expired);
    }
    if nbf.is_some_and(|nbf| now < nbf) {
        return Err(ClaimsRefusal::NotYetValid);
    }
    Ok(())
}

/// Lenient NumericDate reader: `None` when the claim is absent OR not a number.
///
/// It passes over a mistyped claim, so it must not decide admission: the
/// `Ipe.Jwt` decoders admit through [`admit_time_claims`], and `auth.rs` is to
/// adopt [`read_numeric_date`] in place of this reader for its `exp`/`nbf`/`cap`
/// checks.
pub(crate) fn numeric_date(value: &JsonValue, claim: &str) -> Option<i64> {
    match value.get(claim) {
        Some(JsonValue::Number(n)) => number_seconds(n),
        _ => None,
    }
}

/// Extract and base64url-decode the payload segment of a compact JWS token,
/// returning the parsed JSON value. Returns `None` on any parse failure.
/// Reading the unverified payload is safe: every caller only takes the
/// conservative action (reject) on the parsed value.
pub(crate) fn decode_payload(token: &str) -> Option<JsonValue> {
    let mut parts = token.splitn(3, '.');
    let _header = parts.next()?;
    let payload_seg = parts.next()?;
    let bytes = URL_SAFE_NO_PAD.decode(payload_seg).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Current wall-clock time as Unix seconds (i64). Used by the flat decoders to
/// pre-reject expired/not-yet-valid tokens before handing off to jsonwebtoken.
pub(crate) fn now_unix_seconds() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => 0,
    }
}

/// The HMAC-key floor for HS256, in bytes (256 bits — RFC 7518 §3.2).
pub(crate) const HS256_MIN_SECRET_BYTES: usize = 32;

/// Build the diagnostic for an HS256 secret below the 32-byte floor. Written to
/// be unmistakable that this is a deliberate policy, not a defect in the
/// caller's program: it names the actual length, says so in plain words, and
/// gives the one-line fix. `op` is the operation label (e.g. `"jwt-encode"`).
pub(crate) fn hs256_short_secret_msg(op: &str, actual_len: usize) -> String {
    format!(
        "{op}: the HS256 secret is {actual_len} byte(s), but Ipê requires at least \
         {HS256_MIN_SECRET_BYTES} (256 bits, RFC 7518 §3.2). This is an intentional Ipê \
         security policy, NOT a bug in your program: an HMAC key shorter than the \
         SHA-256 output is low-entropy and lets an attacker forge tokens. Use a \
         secret of at least {HS256_MIN_SECRET_BYTES} bytes (generate one with \
         `head -c 32 /dev/urandom | base64`), supplied via configuration such as an \
         environment variable rather than a short literal."
    )
}

/// Ipê `Jwt_encodeHs256 : String -> String -> Result Error String`
pub fn jwt_encode_hs256<E: From<String>>(
    secret: String,
    claims_json: String,
) -> IpeResult<E, String> {
    // An HMAC key shorter than 32 bytes (256 bits) is below the RFC 7518 §3.2
    // floor for HS256 and yields a low-entropy / forgeable signing secret —
    // a 1-byte key mints a token anyone can re-sign. Reject it rather than emit
    // a weakly-keyed token. This mirrors the 32-byte floor auth.rs enforces and
    // Ipe.Auth applies upstream, closing the gap for a direct misconfigured
    // Jwt.* caller that bypasses Ipe.Auth.
    if secret.len() < HS256_MIN_SECRET_BYTES {
        return IpeResult::Err(hs256_short_secret_msg("jwt-encode", secret.len()).into());
    }
    let payload = match payload_json(&claims_json) {
        Ok(p) => p,
        Err(e) => return IpeResult::Err(format!("jwt-encode: {}", e).into()),
    };
    let signing_input = format!(
        "{}.{}",
        b64u(header_json("HS256").as_bytes()),
        b64u(payload.as_bytes())
    );

    // Pipeline: `crypto_hmac_sha256` returns lowercase hex; hexDecode produces
    // the raw MAC bytes; base64url encodes them into the signature segment.
    let mac_hex = super::crypto_core::crypto_hmac_sha256(secret, signing_input.clone());
    let mac_bytes = match hex::decode(&mac_hex) {
        Ok(b) => b,
        // Unreachable: crypto_hmac_sha256 always returns valid lowercase hex.
        // Route to Err rather than panic to keep the kernel total.
        Err(e) => return IpeResult::Err(format!("jwt-encode: internal hmac decode: {}", e).into()),
    };
    let sig = b64u(&mac_bytes);
    IpeResult::Ok(format!("{}.{}", signing_input, sig))
}

/// Ipê `Jwt_decodeHs256 : String -> String -> Result Error String`
pub fn jwt_decode_hs256<E: From<String>>(secret: String, token: String) -> IpeResult<E, String> {
    // Reject verification under a sub-32-byte HMAC key — see jwt_encode_hs256.
    // A token "verified" with a low-entropy key carries no real authenticity
    // guarantee; mirror the 32-byte floor in auth.rs / Ipe.Auth (RFC 7518 §3.2).
    if secret.len() < HS256_MIN_SECRET_BYTES {
        return IpeResult::Err(hs256_short_secret_msg("jwt-decode", secret.len()).into());
    }
    // Pre-reject on the full RFC 7519 NumericDate domain (integer, negative,
    // fractional) before jsonwebtoken's `exp - 1` u64 subtraction can underflow.
    // `admit_time_claims` floors fractional values conservatively, so `exp 0.4 → 0`
    // (already past), `exp -1 → -1` (negative epoch, always past), enforcing
    // `now >= exp` / `now < nbf` on every numeric spelling, and refuses a
    // present date claim that is not a number (jsonwebtoken passes over one).
    if let Some(payload) = decode_payload(&token)
        && let Err(refusal) = admit_time_claims(&payload, now_unix_seconds())
    {
        return IpeResult::Err(format!("jwt-decode: {refusal}").into());
    }
    let key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    // `Ipe.Jwt` contract: `now >= exp` → expired; `now < nbf` → not yet valid.
    // jsonwebtoken's native boundary with leeway = 0 is `exp < now` — it rejects
    // only once `now` is STRICTLY past `exp`, so at the exact instant `now == exp`
    // it would ACCEPT an expired token. Setting reject_tokens_expiring_in_less_than
    // = 1 shifts the reject condition to `exp - 1 < now` (≡ `now >= exp`).
    // leeway stays 0 so no other skew is introduced; the pre-reject above guards the
    // underflow site. nbf needs no shift: both implementations reject at `now < nbf`
    // (accept at `now == nbf`) — already identical.
    validation.leeway = 0;
    validation.reject_tokens_expiring_in_less_than = 1;
    // exp/nbf are OPTIONAL per RFC 7519 §4.1.4-5: a token with no `exp` is
    // treated as non-expiring; a token with no `nbf` has no not-before constraint.
    // jsonwebtoken's Validation::new() puts "exp" in required_spec_claims by
    // default, which would reject any no-exp token. Clear the set so exp/nbf
    // are not required — but keep validate_exp/validate_nbf = true so that
    // WHEN these claims are present they are still validated (expired → Err,
    // nbf in the future → Err).
    validation.required_spec_claims = HashSet::new();
    validation.validate_exp = true;
    validation.validate_nbf = true;
    // These are GENERIC decoders with no expected-audience argument, so a specific
    // `aud` cannot be enforced here. jsonwebtoken's default `validate_aud = true`
    // would then REJECT any token that merely CARRIES an `aud` claim (error
    // InvalidAudience) — breaking the documented audience feature.
    // Disable aud validation; audience-scoped checks belong to a future
    // expected-audience decoder variant.
    validation.validate_aud = false;
    match decode::<JsonValue>(&token, &key, &validation) {
        // The verified claims are admitted again: the pre-reject above reads the
        // unverified payload and is skipped when that payload does not parse.
        Ok(data) => match admit_time_claims(&data.claims, now_unix_seconds()) {
            Err(refusal) => IpeResult::Err(format!("jwt-decode: {refusal}").into()),
            Ok(()) => match serde_json::to_string(&data.claims) {
                Ok(s) => IpeResult::Ok(s),
                Err(e) => IpeResult::Err(format!("jwt-decode: re-encode claims: {}", e).into()),
            },
        },
        Err(e) => IpeResult::Err(format!("jwt-decode: {}", e).into()),
    }
}

/// Ipê `Jwt_encodeRs256 : String -> String -> Result Error String`
pub fn jwt_encode_rs256<E: From<String>>(
    key_pem: String,
    claims_json: String,
) -> IpeResult<E, String> {
    let payload = match payload_json(&claims_json) {
        Ok(p) => p,
        Err(e) => return IpeResult::Err(format!("jwt-encode-rs: {}", e).into()),
    };
    let signing_input = format!(
        "{}.{}",
        b64u(header_json("RS256").as_bytes()),
        b64u(payload.as_bytes())
    );

    // `crypto_rsa_sha256_sign` signs the input and returns standard (padded)
    // base64; convert to base64url. Its Err already suppresses key-structure
    // detail (no key leak).
    let std_b64: String = match super::crypto_core::crypto_rsa_sha256_sign::<String>(
        key_pem,
        signing_input.clone(),
    ) {
        IpeResult::Ok(s) => s,
        // Keep the message generic so no structural hint about the key leaks.
        IpeResult::Err(_) => {
            return IpeResult::Err("jwt-encode-rs: invalid RSA key".to_string().into());
        }
    };
    let sig = standard_to_url(&std_b64);
    IpeResult::Ok(format!("{}.{}", signing_input, sig))
}

/// Ipê `Jwt_decodeRs256 : String -> String -> Result Error String`
pub fn jwt_decode_rs256<E: From<String>>(key_pem: String, token: String) -> IpeResult<E, String> {
    // Pre-reject on the full RFC 7519 NumericDate domain — mirrors the HS256
    // path; see `jwt_decode_hs256` for the detailed rationale.
    if let Some(payload) = decode_payload(&token)
        && let Err(refusal) = admit_time_claims(&payload, now_unix_seconds())
    {
        return IpeResult::Err(format!("jwt-decode-rs: {refusal}").into());
    }
    let key = match DecodingKey::from_rsa_pem(key_pem.as_bytes()) {
        Ok(k) => k,
        // Suppress the parse-error detail to avoid leaking structural hints
        // about the key material (e.g. PEM framing, DER structure).
        Err(_) => return IpeResult::Err("jwt-decode-rs: invalid RSA key".to_string().into()),
    };
    let mut validation = Validation::new(Algorithm::RS256);
    // `Ipe.Jwt` contract: `now >= exp` → expired; `now < nbf` → not yet valid.
    // jsonwebtoken's native boundary with leeway = 0 is `exp < now` — it rejects
    // only once `now` is STRICTLY past `exp`, so at the exact instant `now == exp`
    // it would ACCEPT an expired token. Setting reject_tokens_expiring_in_less_than
    // = 1 shifts the reject condition to `exp - 1 < now` (≡ `now >= exp`).
    // leeway stays 0; the exp == 0 underflow of `exp - 1` is guarded above.
    // nbf needs no shift: both implementations reject at `now < nbf`.
    validation.leeway = 0;
    validation.reject_tokens_expiring_in_less_than = 1;
    // exp/nbf are OPTIONAL per RFC 7519 §4.1.4-5: a token with no `exp` is
    // treated as non-expiring; a token with no `nbf` has no not-before constraint.
    // jsonwebtoken's Validation::new() puts "exp" in required_spec_claims by
    // default, which would reject any no-exp token. Clear the set so exp/nbf
    // are not required — but keep validate_exp/validate_nbf = true so that
    // WHEN these claims are present they are still validated (expired → Err,
    // nbf in the future → Err). The pre-reject above already handles the full
    // NumericDate domain.
    validation.required_spec_claims = HashSet::new();
    validation.validate_exp = true;
    validation.validate_nbf = true;
    // These are GENERIC decoders with no expected-audience argument, so a specific
    // `aud` cannot be enforced here. jsonwebtoken's default `validate_aud = true`
    // would then REJECT any token that merely CARRIES an `aud` claim (error
    // InvalidAudience) — breaking the documented audience feature.
    // Disable aud validation; audience-scoped checks belong to a future
    // expected-audience decoder variant.
    validation.validate_aud = false;
    match decode::<JsonValue>(&token, &key, &validation) {
        // The verified claims are admitted again — see `jwt_decode_hs256`.
        Ok(data) => match admit_time_claims(&data.claims, now_unix_seconds()) {
            Err(refusal) => IpeResult::Err(format!("jwt-decode-rs: {refusal}").into()),
            Ok(()) => match serde_json::to_string(&data.claims) {
                Ok(s) => IpeResult::Ok(s),
                Err(e) => IpeResult::Err(format!("jwt-decode-rs: re-encode: {}", e).into()),
            },
        },
        Err(e) => IpeResult::Err(format!("jwt-decode-rs: {}", e).into()),
    }
}

// ── Concrete aliases for generated Rust code ─────────────────────────────────
//
// The generic `jwt_encode_hs256<E: From<String>>` and friends cannot be
// called directly from generated code where the `Err` arm may be discarded —
// Rust cannot infer `E` in that context. These monomorphic aliases pin
// `E = IpeError` and are what `naming::kernel_name()` maps the Jwt kernels to,
// mirroring the `ipe_aes_gcm_encrypt` pattern in `crypto.rs`.
//
// SECURITY: only the error message crosses the `From<String>` boundary; no
// key material is included in error text (see the suppressed RSA key detail
// above). These wrappers add no new logging surface.

/// Generated-code alias for `jwt_encode_hs256` with `E = String`.
pub fn ipe_jwt_encode_hs256(
    secret: String,
    claims_json: String,
) -> IpeResult<crate::error::IpeError, String> {
    jwt_encode_hs256(secret, claims_json)
}

/// Generated-code alias for `jwt_decode_hs256` with `E = String`.
pub fn ipe_jwt_decode_hs256(
    secret: String,
    token: String,
) -> IpeResult<crate::error::IpeError, String> {
    jwt_decode_hs256(secret, token)
}

/// Generated-code alias for `jwt_encode_rs256` with `E = String`.
pub fn ipe_jwt_encode_rs256(
    key_pem: String,
    claims_json: String,
) -> IpeResult<crate::error::IpeError, String> {
    jwt_encode_rs256(key_pem, claims_json)
}

/// Generated-code alias for `jwt_decode_rs256` with `E = String`.
pub fn ipe_jwt_decode_rs256(
    key_pem: String,
    token: String,
) -> IpeResult<crate::error::IpeError, String> {
    jwt_decode_rs256(key_pem, token)
}

// ── Builder API (D-00) ─────────────────────────────────────────────────
//
// `Ipe.Jwt` exposes a builder pattern:
//   `Jwt.encode (Jwt.hs256 secret) (Jwt.claims |> Jwt.subject "alice" |> …)`
//
// `Claims` is represented as a `serde_json::Value` (the `IrType::Json` opaque).
// `Algorithm` is encoded as a `String` with a prefix: `"HS256:<secret>"` or
// `"RS256:<pem>"` (the `IrType::Str` opaque).  The encode / decode functions
// parse the prefix to dispatch to the appropriate flat kernel, using the same
// deterministic JSON encoder as the flat `encodeHs256` / `decodeHs256` kernels.

/// `Jwt.claims : Claims` — returns an empty JSON object to start the builder
/// chain.  Backed as `serde_json::Value::Object` (IrType::Json).
pub fn ipe_jwt_claims() -> JsonValue {
    JsonValue::Object(serde_json::Map::new())
}

/// `Jwt.hs256 : String -> Algorithm` — builds an HS256 algorithm descriptor.
/// The algorithm is encoded as `"HS256:<secret>"` and sealed inside a
/// [`super::secret::Secret`] so `Algorithm` (the `Ipe.Jwt` builder's IR type)
/// carries none of `Secret`'s excluded surfaces — no `Debug`/`Display`/
/// `IpeStringify`/serde — the moment the key leaves this function. Without
/// the seal, `Algorithm` shared the plain `String` IR representation, so a
/// well-typed program could `Io.println (Jwt.hs256 secret)` or log the
/// descriptor and leak the key verbatim. `ipe_jwt_encode` / `ipe_jwt_decode`
/// are the only two call sites that `secret_reveal` it, to parse out the
/// algorithm tag and the key in one pass.
pub fn ipe_jwt_hs256(secret: String) -> super::secret::Secret {
    super::secret::secret_from_string(format!("HS256:{}", secret))
}

/// `Jwt.rs256 : String -> Algorithm` — builds an RS256 algorithm descriptor.
/// Encoded as `"RS256:<pem>"` and sealed the same way as [`ipe_jwt_hs256`] —
/// an RS256 private key is exactly as sensitive as an HS256 shared secret.
pub fn ipe_jwt_rs256(key_pem: String) -> super::secret::Secret {
    super::secret::secret_from_string(format!("RS256:{}", key_pem))
}

/// Helper: insert (or overwrite) a key-value pair in a JSON object.
/// If `claims` is not an object, a new object is created containing only this
/// claim (defensive; the builder chain guarantees object inputs from `claims`).
fn claims_set(claims: JsonValue, key: &str, value: JsonValue) -> JsonValue {
    let mut map = match claims {
        JsonValue::Object(m) => m,
        other => {
            // Defensive: wrap the non-object in a fresh map.  This should
            // never happen in a well-typed builder chain.
            let mut m = serde_json::Map::new();
            m.insert("_value".to_string(), other);
            m
        }
    };
    map.insert(key.to_string(), value);
    JsonValue::Object(map)
}

/// `Jwt.subject : String -> Claims -> Claims` — sets the `sub` claim.
pub fn ipe_jwt_subject(sub: String, claims: JsonValue) -> JsonValue {
    claims_set(claims, "sub", JsonValue::String(sub))
}

/// `Jwt.issuer : String -> Claims -> Claims` — sets the `iss` claim.
pub fn ipe_jwt_issuer(iss: String, claims: JsonValue) -> JsonValue {
    claims_set(claims, "iss", JsonValue::String(iss))
}

/// `Jwt.audience : String -> Claims -> Claims` — sets the `aud` claim.
pub fn ipe_jwt_audience(aud: String, claims: JsonValue) -> JsonValue {
    claims_set(claims, "aud", JsonValue::String(aud))
}

/// `Jwt.expiresAt : Int -> Claims -> Claims` — sets the `exp` claim (Unix
/// seconds).  The Ipê stdlib documents `expiresAt` as accepting Unix
/// milliseconds but RFC 7519 uses Unix SECONDS.  The `Jwt.ipe` stdlib module
/// passes the value straight through as a JSON number; the caller is responsible
/// for providing the right unit.
pub fn ipe_jwt_expires_at(exp: i64, claims: JsonValue) -> JsonValue {
    claims_set(
        claims,
        "exp",
        JsonValue::Number(serde_json::Number::from(exp)),
    )
}

/// `Jwt.notBefore : Int -> Claims -> Claims` — sets the `nbf` claim.
pub fn ipe_jwt_not_before(nbf: i64, claims: JsonValue) -> JsonValue {
    claims_set(
        claims,
        "nbf",
        JsonValue::Number(serde_json::Number::from(nbf)),
    )
}

/// `Jwt.issuedAt : Int -> Claims -> Claims` — sets the `iat` claim.
pub fn ipe_jwt_issued_at(iat: i64, claims: JsonValue) -> JsonValue {
    claims_set(
        claims,
        "iat",
        JsonValue::Number(serde_json::Number::from(iat)),
    )
}

/// `Jwt.jwtId : String -> Claims -> Claims` — sets the `jti` claim.
pub fn ipe_jwt_jwt_id(jti: String, claims: JsonValue) -> JsonValue {
    claims_set(claims, "jti", JsonValue::String(jti))
}

/// `Jwt.withClaim : String -> JsonEnc.Value -> Claims -> Claims` — inserts an
/// arbitrary claim whose value is any encoded JSON node.  Matches the reference
/// `Ipê/Core/Jwt.ipe:79`: the value is a `JsonEnc.Value` (itself a
/// `serde_json::Value` at runtime, exactly like `Claims`), so it is inserted
/// directly — a string / int / bool / nested object all round-trip with the
/// correct token bytes.
pub fn ipe_jwt_with_claim(key: String, value: JsonValue, claims: JsonValue) -> JsonValue {
    claims_set(claims, &key, value)
}

/// `Jwt.encode : Algorithm -> Claims -> Result Error String` — signs the claims
/// using the algorithm encoded in `algorithm_descriptor`.
/// Delegates to `jwt_encode_hs256` / `jwt_encode_rs256` after serialising the
/// claims through the deterministic JSON encoder (sorted keys).
pub fn ipe_jwt_encode(
    algorithm_descriptor: super::secret::Secret,
    claims: JsonValue,
) -> IpeResult<crate::error::IpeError, String> {
    // Serialise the claims through the deterministic encoder (sorted keys).
    let claims_json = super::json_enc_encode(0, claims);
    // THE single reveal on this path — unwraps the sealed descriptor back to
    // a plain `String` only long enough to strip the algorithm-tag prefix and
    // hand the key material to the flat `jwt_encode_*` kernels below.
    let algorithm_descriptor = super::secret::secret_reveal(algorithm_descriptor);
    if let Some(secret) = algorithm_descriptor.strip_prefix("HS256:") {
        jwt_encode_hs256(secret.to_string(), claims_json)
    } else if let Some(pem) = algorithm_descriptor.strip_prefix("RS256:") {
        jwt_encode_rs256(pem.to_string(), claims_json)
    } else {
        // The unknown descriptor is caller-derived data, so it is never
        // byte-sliced or echoed into the message: slicing by byte offset can
        // land mid-codepoint on multibyte UTF-8 input and panic, and the tag
        // namespace is fixed, so the raw content adds no diagnostic value.
        IpeResult::Err(
            "jwt-encode: unknown algorithm descriptor (expected HS256:… or RS256:…)".into(),
        )
    }
}

/// `Jwt.decode : Algorithm -> Int -> String -> Result Error String`
///
/// Verifies the JWT signature and applies caller-supplied `now` (Unix seconds)
/// for exp/nbf validation, matching the reference `Ipe.Jwt.decode` contract:
///   pastClaim:   now >= exp  → Err "Jwt.decode: token has expired"
///   futureClaim: now <  nbf  → Err "Jwt.decode: token is not yet valid"
///   absent claim              → accept (optional)
///   present `exp`/`nbf`/`iat` that is not a JSON number
///                             → Err "Jwt.decode: token `<claim>` is not a NumericDate"
/// Returns the raw payload JSON string (base64url-decoded middle segment).
/// No wall-clock access; deterministic on `now`.
pub fn ipe_jwt_decode(
    algorithm_descriptor: super::secret::Secret,
    now: i64,
    token: String,
) -> IpeResult<crate::error::IpeError, String> {
    // 1. Split token into three segments.
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return IpeResult::Err("jwt-decode: malformed token (expected 3 segments)".into());
    }

    // THE single reveal on this path — see `ipe_jwt_encode`'s comment.
    let algorithm_descriptor = super::secret::secret_reveal(algorithm_descriptor);

    // 2. Verify the signature only — disable jsonwebtoken's built-in time checks.
    //    We apply reference-exact time validation manually below.
    if let Some(secret) = algorithm_descriptor.strip_prefix("HS256:") {
        if secret.len() < HS256_MIN_SECRET_BYTES {
            return IpeResult::Err(hs256_short_secret_msg("jwt-decode", secret.len()).into());
        }
        let key = DecodingKey::from_secret(secret.as_bytes());
        let mut val = Validation::new(Algorithm::HS256);
        val.validate_exp = false;
        val.validate_nbf = false;
        val.required_spec_claims = HashSet::new();
        val.validate_aud = false;
        if decode::<JsonValue>(&token, &key, &val).is_err() {
            return IpeResult::Err("jwt-decode: invalid signature".into());
        }
    } else if let Some(pem) = algorithm_descriptor.strip_prefix("RS256:") {
        let key = match DecodingKey::from_rsa_pem(pem.as_bytes()) {
            Ok(k) => k,
            Err(_) => return IpeResult::Err("jwt-decode: invalid RS256 public key".into()),
        };
        let mut val = Validation::new(Algorithm::RS256);
        val.validate_exp = false;
        val.validate_nbf = false;
        val.required_spec_claims = HashSet::new();
        val.validate_aud = false;
        if decode::<JsonValue>(&token, &key, &val).is_err() {
            return IpeResult::Err("jwt-decode: invalid signature".into());
        }
    } else {
        // See `ipe_jwt_encode`'s matching arm: never byte-slice or echo the
        // caller-derived descriptor into the message.
        return IpeResult::Err(
            "jwt-decode: unknown algorithm descriptor (expected HS256:… or RS256:…)".into(),
        );
    }

    // 3. Extract payload JSON via base64url-decode (parse, don't validate).
    // `parts.len() != 3` already returned above, but never index even when
    // provably safe — `.get` keeps this fail-closed instead of panicking.
    let Some(payload_segment) = parts.get(1) else {
        return IpeResult::Err("jwt-decode: malformed token (expected 3 segments)".into());
    };
    let payload_bytes = match URL_SAFE_NO_PAD.decode(payload_segment.as_bytes()) {
        Ok(b) => b,
        Err(_) => return IpeResult::Err("jwt-decode: payload base64url decode failed".into()),
    };
    let payload_json = match String::from_utf8(payload_bytes) {
        Ok(s) => s,
        Err(_) => return IpeResult::Err("jwt-decode: payload is not valid UTF-8".into()),
    };

    // 4. Manual time validation matching reference semantics exactly, on the
    //    payload parsed once into a claims set. `admit_time_claims` honours
    //    fractional and negative `exp`/`nbf` and refuses a present date claim
    //    that is not a number, never passing over it.
    let Ok(claims_val) = serde_json::from_str::<JsonValue>(&payload_json) else {
        return IpeResult::Err("jwt-decode: payload is not JSON".into());
    };
    if let Err(refusal) = admit_time_claims(&claims_val, now) {
        return IpeResult::Err(format!("Jwt.decode: {refusal}").into());
    }

    IpeResult::Ok(payload_json)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical HS256 token for the claims `{"sub":"alice","exp":9999999999}` with
    /// `secret = "test-secret-key-0123456789abcdef"`. Byte-equality golden: the
    /// flat `encodeHs256` kernel must reproduce this exactly.
    const GO_HS256_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTksInN1YiI6ImFsaWNlIn0.O6u4Zgjn9lL3myvfLfP5QFaGIHx-KBfzZ7lgkbJL_N0";

    #[test]
    fn hs256_token_matches_golden() {
        let secret = "test-secret-key-0123456789abcdef".to_string();
        let claims = r#"{"sub":"alice","exp":9999999999}"#.to_string();
        let token: IpeResult<String, String> = jwt_encode_hs256(secret, claims);
        match token {
            IpeResult::Ok(t) => assert_eq!(t, GO_HS256_TOKEN, "HS256 token must match golden"),
            IpeResult::Err(e) => panic!("encode: {}", e),
        }
    }

    // RSA-2048 PKCS#8 test key pair (test-only; never used outside tests) — the
    // same key embedded in tests/golden/jwt_rs256_roundtrip/Main.ipe.
    const RS256_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDKt5KX9AzdrNIl\nKj9WqLI1vI1E+s6ydOuFtJaX+3eyvByRf++qKeSca9WQhFWih6INNSPyHiI1w570\njeglmwcQe8WXyW15w/c3a/TkYJ6thqyFOBTColjuOv+nUkIyHkOFx4GTtTwjcIQ1\no+sgDy90NrIyjvZhKGxv/BoRsvmcPNcO95MC2lTZrhjIwPpTCDn/jD1DhNmRtcsv\ng0WmoXKGfFm+YYALT49Cs2hU2z8kQrlqo5q8Zzsxa3+wh4yF7W/O5aAoUBKtcYNS\nOvumvh7aBnuHZT45ZvYGCNdTPFX+4E27JWyAycp+4GqfvcbcfcDwjhpkphAhYozi\nZ9zgc+4FAgMBAAECggEAVoIbcXQpD2qCbXDHgdRQ5MS3prG/hoGFxtPHlkkujhxf\ntqnZnYzuLeCIzXjj0I3AFpHQarD4WWhHS8bJRE8RpzOioYFIkjeSJtkPs2wWGyhH\nNDy4A01j1RphYkak0B2BJDR89AtaBCeui/ONUeuZDSeQSSogM1scV3fGqjnt8oFz\nlhaOell+Z/csmbLW+YhJEpUuKmA/V4ehXKn6TvTWCvfYOupVauZeUcwAzMXCtWIx\n6CvEoe5We/0MafIeqwnUSeoAVXvmhx5QtTC2x3rYlSvr3RtGPFTH4wD+cBavFOW8\nzD1u6SC5mDQi0L5Z1tSdV8g8cF2sSyTf3peNXI2DKwKBgQDbfFt9Vg3gwBFJNSRk\nOhi59+KYisxFSEcOj9X+MdrCys8Zm/4XWtpU06rvuM3e8C1+ubK978BdLamZrnQO\n/w2XOzD3WNbX/eGSQci7BGFQBUBP98ABDWctjTHu7Ph3BZZqaj+b4ZWEBNsvrkkw\nfqNE3m5dx+JtbSAgThD1eq5elwKBgQDscQ5qZoXmlUChTpJzqvHm5eEiV+tOS/o8\noxaH2ygPqwAJkWtiFmXLIWUW+dx0hwYEocbKUkBx9HBS0yMDe2aJV5sZwo0fzUV2\nHCwxJ2cVB28bQ1mVETTuSE8Ok/Cb/zxHjlVx4NMDUEmf+KTaWQ2JXysI4yv4Vi2u\npkt0DIpHwwKBgQCABuYHEi8+Lkrm/QyhOhI6SBHxEOVedG6eW+BjSgllHo/3TDrG\nvMQmPuGyu4W6yTaAeSl+CV+X+o63ij9AkB4JXQmO/k8z5m+xtJW2ITPyTV3aR5XE\nB2Fr/LRnveqg4q1+nUNFViy0uXBxO6SNmRD7lxOhuHqngcP/lAnoZwtXOQKBgAuF\n7wfsezYjrASwiZ6thCCWr4Q2+LbWKRnvcNeqLKem09ejiLI9GTTvKbgW8VGUiwyK\nvd96Zr2nBhpjQ9+Vkge7h0mYG7yjCnGZKeYzX2i89gNEIweK0SOTzpaNSzqvE8cA\n/tUP+fi9Xvk26wHhOTGqu7QxLiFqQcuzOxYqzkp1AoGADuFoA0w4zwXsr/6sF1Vx\ne20UCYmRkiiE6CbgicFsMYhaD5w2F5Ss26Zb8f09oaAZw2xwDCNY7LX2OQSTgSuX\nzzBBQrEfmqxPLztxMa0e3qjSBMeo3m0m2Yoen67ie5b53snOT3t704JrE6kP6DxC\nkxJKRSX7IM4caBhDN+Khm2k=\n-----END PRIVATE KEY-----\n";

    /// SPKI public key matching `RS256_PRIV_PEM` — the RS256 decode path verifies
    /// with a public PEM (same key embedded in
    /// tests/golden/jwt_rs256_roundtrip/Main.ipe).
    const RS256_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyreSl/QM3azSJSo/Vqiy\nNbyNRPrOsnTrhbSWl/t3srwckX/vqinknGvVkIRVooeiDTUj8h4iNcOe9I3oJZsH\nEHvFl8ltecP3N2v05GCerYashTgUwqJY7jr/p1JCMh5DhceBk7U8I3CENaPrIA8v\ndDayMo72YShsb/waEbL5nDzXDveTAtpU2a4YyMD6Uwg5/4w9Q4TZkbXLL4NFpqFy\nhnxZvmGAC0+PQrNoVNs/JEK5aqOavGc7MWt/sIeMhe1vzuWgKFASrXGDUjr7pr4e\n2gZ7h2U+OWb2BgjXUzxV/uBNuyVsgMnKfuBqn73G3H3A8I4aZKYQIWKM4mfc4HPu\nBQIDAQAB\n-----END PUBLIC KEY-----\n";

    /// Canonical RS256 token for the claims `{"sub":"bob","exp":9999999999}` with
    /// `RS256_PRIV_PEM`. RS256 (PKCS#1 v1.5) is deterministic, so the flat
    /// `encodeRs256` kernel must reproduce this exactly.
    const GO_RS256_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTksInN1YiI6ImJvYiJ9.GJ29fLyt4u8M_CMSvhSizRpjWXEDsrVtDL92QOX27HwB9YvKI4_ksftEN8-wK1xiT5y1tmrWmUs3_UHPTepyCJ9Y02JDphZ5X4k0784CIKxNvdr1RcAn-V24Wyc_rTFOELDR9XeBPNIhYRzVuQnaQ27PbmpF3skoyH40eOI7emrTVlbPhkgnWsoULuKOEI3yF9VU62QFoPDEuio_59LMcuk2EZrnh-Rql1zF5cNixt30_Vu5mUwBHkYZ2J2ZEm_S2VIrXvIluIfp5pzNmOK1TdLv9yQHY1PPcfcvHizHK4IKnMNTXrkk8W0NCaP5faf4hzaZVPIoqJ7D220PHPgWEg";

    #[test]
    fn rs256_token_matches_golden() {
        let claims = r#"{"sub":"bob","exp":9999999999}"#.to_string();
        let token: IpeResult<String, String> = jwt_encode_rs256(RS256_PRIV_PEM.to_string(), claims);
        match token {
            IpeResult::Ok(t) => assert_eq!(t, GO_RS256_TOKEN, "RS256 token must match golden"),
            IpeResult::Err(e) => panic!("encode-rs: {}", e),
        }
    }

    #[test]
    fn test_hs256_roundtrip() {
        // >= 32 bytes to clear the RFC 7518 §3.2 HS256 secret floor.
        let secret = "roundtrip-secret-0123456789abcdef".to_string();
        let claims = r#"{"sub":"alice","exp":9999999999}"#.to_string();
        let token: IpeResult<String, String> = jwt_encode_hs256(secret.clone(), claims.clone());
        let token = match token {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("encode: {}", e),
        };
        let decoded: IpeResult<String, String> = jwt_decode_hs256(secret, token);
        let decoded = match decoded {
            IpeResult::Ok(s) => s,
            IpeResult::Err(e) => panic!("decode: {}", e),
        };
        assert!(decoded.contains("alice"));
    }

    #[test]
    fn test_hs256_wrong_secret_fails() {
        // Both secrets >= 32 bytes (RFC 7518 §3.2 floor); they differ so verify fails.
        let token: IpeResult<String, String> = jwt_encode_hs256(
            "right-secret-0123456789abcdef0123".to_string(),
            r#"{"sub":"x","exp":9999999999}"#.to_string(),
        );
        let token = match token {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("encode: {}", e),
        };
        let bad: IpeResult<String, String> =
            jwt_decode_hs256("wrong-secret-0123456789abcdef0123".to_string(), token);
        assert!(matches!(bad, IpeResult::Err(_)));
    }

    /// Seconds since the Unix epoch, for building boundary-exercising claims.
    fn now_unix() -> i64 {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(_) => 0,
        }
    }

    #[test]
    fn test_hs256_expired_token_rejected() {
        // exp 30s in the PAST. With jsonwebtoken's default 60s leeway this would
        // be ACCEPTED — zero clock skew rejects it. Guards `validation.leeway = 0`
        // against silent regression; every other golden uses a far-future exp.
        let secret = "expiry-secret-0123456789abcdef0123".to_string();
        let claims = format!(r#"{{"sub":"x","exp":{}}}"#, now_unix() - 30);
        let token: IpeResult<String, String> = jwt_encode_hs256(secret.clone(), claims);
        let token = match token {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("encode: {}", e),
        };
        let decoded: IpeResult<String, String> = jwt_decode_hs256(secret, token);
        assert!(
            matches!(decoded, IpeResult::Err(_)),
            "an HS256 token expired 30s ago must be rejected (no clock-skew leeway)"
        );
    }

    #[test]
    fn test_rs256_expired_token_rejected() {
        // exp 30s in the PAST — RS256 counterpart of the HS256 leeway guard.
        let claims = format!(r#"{{"sub":"bob","exp":{}}}"#, now_unix() - 30);
        let token: IpeResult<String, String> = jwt_encode_rs256(RS256_PRIV_PEM.to_string(), claims);
        let token = match token {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("encode-rs: {}", e),
        };
        // Verify with the matching SPKI public key (the decode path takes a
        // public PEM). A successful signature check then trips the expiry guard.
        let decoded: IpeResult<String, String> = jwt_decode_rs256(RS256_PUB_PEM.to_string(), token);
        assert!(
            matches!(decoded, IpeResult::Err(_)),
            "an RS256 token expired 30s ago must be rejected (no clock-skew leeway)"
        );
    }

    #[test]
    fn test_hs256_empty_secret_rejected() {
        // Empty HMAC secret → forgeable token; both encode and verify must refuse.
        let enc: IpeResult<String, String> =
            jwt_encode_hs256(String::new(), r#"{"sub":"x","exp":9999999999}"#.to_string());
        assert!(matches!(enc, IpeResult::Err(_)));
        let dec: IpeResult<String, String> = jwt_decode_hs256(String::new(), "a.b.c".to_string());
        assert!(matches!(dec, IpeResult::Err(_)));
    }

    /// Boundary: `now == exp` must REJECT (`now >= exp` → expired).
    /// jsonwebtoken's native leeway-0 boundary is `exp < now` (accepts at
    /// `now == exp`); `reject_tokens_expiring_in_less_than = 1` shifts it to
    /// `now >= exp`. Robust against the live clock: at decode jsonwebtoken's
    /// clock is `>= exp`, so the reject is stable.
    #[test]
    fn test_hs256_now_eq_exp_rejected() {
        let secret = "exp-edge-secret-0123456789abcdef0".to_string();
        let exp = now_unix(); // now == exp
        let claims = format!(r#"{{"sub":"x","exp":{}}}"#, exp);
        let token: IpeResult<String, String> = jwt_encode_hs256(secret.clone(), claims);
        let token = match token {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("encode: {}", e),
        };
        let decoded: IpeResult<String, String> = jwt_decode_hs256(secret, token);
        assert!(
            matches!(decoded, IpeResult::Err(_)),
            "now == exp must be rejected (now >= exp semantics)"
        );
    }

    /// Boundary: `now == exp - 1` (one second before expiry) must ACCEPT.
    /// Rejects at `now >= exp`, so one second earlier is still valid.
    /// We anchor `exp = now + 1`. A second-boundary tick between building the
    /// claim and jsonwebtoken's internal clock read would push `now` up to `exp`
    /// and flip the result, so retry on that rare straddle — each attempt is
    /// deterministic, the bounded loop only guards the cross-second race (5
    /// consecutive straddles is astronomically unlikely and keeps the test
    /// finite per the timeout principle).
    #[test]
    fn test_hs256_now_eq_exp_minus_1_accepted() {
        let secret = "exp-edge-secret-0123456789abcdef0".to_string();
        let mut accepted = false;
        for _ in 0..5 {
            let exp = now_unix() + 1; // now == exp - 1
            let claims = format!(r#"{{"sub":"x","exp":{}}}"#, exp);
            let token = match jwt_encode_hs256::<String>(secret.clone(), claims) {
                IpeResult::Ok(t) => t,
                IpeResult::Err(e) => panic!("encode: {}", e),
            };
            if matches!(
                jwt_decode_hs256::<String>(secret.clone(), token),
                IpeResult::Ok(_)
            ) {
                accepted = true;
                break;
            }
        }
        assert!(
            accepted,
            "now == exp - 1 must be accepted (one second before expiry is valid)"
        );
    }

    /// Boundary: `now == nbf` must ACCEPT (`now < nbf` rejects → `now >= nbf`
    /// accepts). Robust against the live clock: jsonwebtoken's clock at decode
    /// is `>= nbf`, so the accept is stable. No `exp` → non-expiring.
    #[test]
    fn test_hs256_now_eq_nbf_accepted() {
        let secret = "nbf-edge-secret-0123456789abcdef0".to_string();
        let nbf = now_unix(); // now == nbf
        let claims = format!(r#"{{"sub":"x","nbf":{}}}"#, nbf);
        let token: IpeResult<String, String> = jwt_encode_hs256(secret.clone(), claims);
        let token = match token {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("encode: {}", e),
        };
        let decoded: IpeResult<String, String> = jwt_decode_hs256(secret, token);
        assert!(
            matches!(decoded, IpeResult::Ok(_)),
            "now == nbf must be accepted (now >= nbf accepts)"
        );
    }

    /// Token with NO `exp` claim must be ACCEPTED: an absent `exp` means
    /// non-expiring per RFC 7519 §4.1.4. Guards against a regression where
    /// `required_spec_claims` includes "exp" (the jsonwebtoken default).
    #[test]
    fn test_hs256_no_exp_accepted() {
        let secret = "no-exp-secret-0123456789abcdef0123".to_string();
        // claims with only `sub` — no `exp`, no `nbf`.
        let claims = r#"{"sub":"alice"}"#.to_string();
        let token: IpeResult<String, String> = jwt_encode_hs256(secret.clone(), claims);
        let token = match token {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("encode: {}", e),
        };
        let decoded: IpeResult<String, String> = jwt_decode_hs256(secret, token);
        assert!(
            matches!(decoded, IpeResult::Ok(_)),
            "an HS256 token with no exp claim must be accepted (non-expiring)"
        );
        if let IpeResult::Ok(s) = decoded {
            assert!(s.contains("alice"), "decoded claims must include sub:alice");
        }
    }

    /// Token with `nbf` in the FUTURE must be REJECTED: `nbf` is validated when
    /// present with no clock slack. Guards `validation.validate_nbf = true` +
    /// `leeway = 0`.
    #[test]
    fn test_hs256_future_nbf_rejected() {
        let secret = "nbf-secret-0123456789abcdef0123456".to_string();
        // nbf 300s in the future, no exp (non-expiring).
        let claims = format!(r#"{{"sub":"x","nbf":{}}}"#, now_unix() + 300);
        let token: IpeResult<String, String> = jwt_encode_hs256(secret.clone(), claims);
        let token = match token {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("encode: {}", e),
        };
        let decoded: IpeResult<String, String> = jwt_decode_hs256(secret, token);
        assert!(
            matches!(decoded, IpeResult::Err(_)),
            "an HS256 token with nbf 300s in the future must be rejected (no leeway)"
        );
    }

    /// RS256: no-exp token must be ACCEPTED (non-expiring per RFC 7519 §4.1.4).
    #[test]
    fn test_rs256_no_exp_accepted() {
        let claims = r#"{"sub":"bob"}"#.to_string();
        let token: IpeResult<String, String> = jwt_encode_rs256(RS256_PRIV_PEM.to_string(), claims);
        let token = match token {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("encode-rs: {}", e),
        };
        let decoded: IpeResult<String, String> = jwt_decode_rs256(RS256_PUB_PEM.to_string(), token);
        assert!(
            matches!(decoded, IpeResult::Ok(_)),
            "an RS256 token with no exp claim must be accepted (non-expiring)"
        );
        if let IpeResult::Ok(s) = decoded {
            assert!(s.contains("bob"), "decoded claims must include sub:bob");
        }
    }

    /// RS256: future-nbf token must be REJECTED (no leeway).
    #[test]
    fn test_rs256_future_nbf_rejected() {
        let claims = format!(r#"{{"sub":"bob","nbf":{}}}"#, now_unix() + 300);
        let token: IpeResult<String, String> = jwt_encode_rs256(RS256_PRIV_PEM.to_string(), claims);
        let token = match token {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("encode-rs: {}", e),
        };
        let decoded: IpeResult<String, String> = jwt_decode_rs256(RS256_PUB_PEM.to_string(), token);
        assert!(
            matches!(decoded, IpeResult::Err(_)),
            "an RS256 token with nbf 300s in the future must be rejected (no leeway)"
        );
    }

    // ── ipe_jwt_decode (3-arg builder-API) unit tests ─────────────────────────

    fn make_token_with_time(exp: Option<i64>, nbf: Option<i64>) -> String {
        let secret = "test-secret-key-0123456789abcdef".to_string();
        let mut parts = vec![r#""sub":"x""#.to_string()];
        if let Some(e) = exp {
            parts.push(format!(r#""exp":{}"#, e));
        }
        if let Some(n) = nbf {
            parts.push(format!(r#""nbf":{}"#, n));
        }
        let claims = format!("{{{}}}", parts.join(","));
        match jwt_encode_hs256::<String>(secret, claims) {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("encode: {}", e),
        }
    }

    /// now=500, exp=1000, nbf=100 → Ok (valid window).
    #[test]
    fn ipe_jwt_decode_valid_window() {
        let tok = make_token_with_time(Some(1000), Some(100));
        let desc =
            crate::secret::secret_from_string("HS256:test-secret-key-0123456789abcdef".to_string());
        assert!(
            matches!(ipe_jwt_decode(desc, 500, tok), IpeResult::Ok(_)),
            "now=500 inside [nbf=100, exp=1000) must succeed"
        );
    }

    /// now=1000 >= exp=1000 → Err (expired; boundary: >= not >).
    #[test]
    fn ipe_jwt_decode_expired_at_boundary() {
        let tok = make_token_with_time(Some(1000), None);
        let desc =
            crate::secret::secret_from_string("HS256:test-secret-key-0123456789abcdef".to_string());
        assert!(
            matches!(ipe_jwt_decode(desc, 1000, tok), IpeResult::Err(_)),
            "now==exp must be rejected (now >= exp semantics)"
        );
    }

    /// now=99 < nbf=100 → Err (not yet valid).
    #[test]
    fn ipe_jwt_decode_nbf_future() {
        let tok = make_token_with_time(None, Some(100));
        let desc =
            crate::secret::secret_from_string("HS256:test-secret-key-0123456789abcdef".to_string());
        assert!(
            matches!(ipe_jwt_decode(desc, 99, tok), IpeResult::Err(_)),
            "now=99 < nbf=100 must be rejected"
        );
    }

    /// now=100 == nbf=100 → Ok (boundary: now < nbf is false → accept).
    #[test]
    fn ipe_jwt_decode_nbf_at_boundary() {
        let tok = make_token_with_time(Some(1000), Some(100));
        let desc =
            crate::secret::secret_from_string("HS256:test-secret-key-0123456789abcdef".to_string());
        assert!(
            matches!(ipe_jwt_decode(desc, 100, tok), IpeResult::Ok(_)),
            "now==nbf must be accepted (now < nbf is false)"
        );
    }

    /// Token with no exp/nbf → Ok for any now.
    #[test]
    fn ipe_jwt_decode_no_time_claims() {
        let tok = make_token_with_time(None, None);
        let desc =
            crate::secret::secret_from_string("HS256:test-secret-key-0123456789abcdef".to_string());
        assert!(
            matches!(ipe_jwt_decode(desc, 9999999999, tok), IpeResult::Ok(_)),
            "token without exp/nbf must be accepted regardless of now"
        );
    }

    /// Wrong key → Err (invalid signature, constant-time path).
    #[test]
    fn ipe_jwt_decode_wrong_key() {
        let tok = make_token_with_time(Some(9999999999), None);
        let desc =
            crate::secret::secret_from_string("HS256:wrong-secret-key-0123456789abcde".to_string());
        assert!(
            matches!(ipe_jwt_decode(desc, 500, tok), IpeResult::Err(_)),
            "wrong key must be rejected"
        );
    }

    /// Return value is the payload JSON string (verified base64url-decode).
    #[test]
    fn ipe_jwt_decode_returns_payload_json() {
        let tok = make_token_with_time(Some(9999999999), None);
        let desc =
            crate::secret::secret_from_string("HS256:test-secret-key-0123456789abcdef".to_string());
        match ipe_jwt_decode(desc, 500, tok) {
            IpeResult::Ok(payload) => {
                assert!(
                    payload.contains("\"sub\"") || payload.contains("\"exp\""),
                    "payload must be the decoded claims JSON: {payload}"
                );
            }
            IpeResult::Err(e) => panic!("unexpected err: {e}"),
        }
    }

    // ── RT-AUTH-001/002/003 regression tests ─────────────────────────────────
    //
    // These tests cover the full RFC 7519 NumericDate domain (negative integer,
    // fractional-zero, fractional-future) on both the flat HS256 path and the
    // builder (ipe_jwt_decode) path.

    /// Flat HS256: `exp = -1` (negative epoch) must be rejected.
    /// Was silently accepted before the `numeric_date` pre-reject because
    /// `as_u64()` returns None for negatives, bypassing the old `exp_is_zero`
    /// guard and letting jsonwebtoken's `exp - 1` underflow to `u64::MAX`.
    #[test]
    fn test_flat_decode_negative_exp_rejected() {
        let secret = "neg-exp-test-secret-0123456789abcde".to_string();
        let claims = r#"{"sub":"x","exp":-1}"#.to_string();
        let token: IpeResult<String, String> = jwt_encode_hs256(secret.clone(), claims);
        let token = match token {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("encode: {e}"),
        };
        let decoded: IpeResult<String, String> = jwt_decode_hs256(secret, token);
        assert!(
            matches!(decoded, IpeResult::Err(_)),
            "flat HS256: exp=-1 (negative epoch) must be rejected"
        );
    }

    /// Flat HS256: `exp = 0.4` (fractional, floors to 0, already past) must be
    /// rejected without triggering a `u64` underflow on `0 - 1`.
    /// `exp = 0.0` (fractional zero) must also be rejected.
    #[test]
    fn test_flat_decode_fractional_exp_zero_rejected() {
        let secret = "frac-exp-test-secret-0123456789abc".to_string();
        // Build the token by hand with a fractional exp (serde_json encodes it as
        // a float literal in the JSON payload).
        let claims_04 = r#"{"sub":"x","exp":0.4}"#.to_string();
        let tok04: IpeResult<String, String> = jwt_encode_hs256(secret.clone(), claims_04);
        let tok04 = match tok04 {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("encode 0.4: {e}"),
        };
        let dec04: IpeResult<String, String> = jwt_decode_hs256(secret.clone(), tok04);
        assert!(
            matches!(dec04, IpeResult::Err(_)),
            "flat HS256: exp=0.4 must be rejected (floors to 0, already expired)"
        );

        let claims_00 = r#"{"sub":"x","exp":0.0}"#.to_string();
        let tok00: IpeResult<String, String> = jwt_encode_hs256(secret.clone(), claims_00);
        let tok00 = match tok00 {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("encode 0.0: {e}"),
        };
        let dec00: IpeResult<String, String> = jwt_decode_hs256(secret, tok00);
        assert!(
            matches!(dec00, IpeResult::Err(_)),
            "flat HS256: exp=0.0 must be rejected"
        );
    }

    /// Both flat `jwt_decode_hs256` and builder `ipe_jwt_decode` must agree on
    /// a token with a fractional past exp (e.g. `<past>.5`). Previously the
    /// flat path accepted it (old guard missed floats) while the builder skipped
    /// the check (`as_i64()` returns None for floats). Both must now reject.
    #[test]
    fn test_flat_vs_builder_fractional_exp_agree() {
        let secret = "agree-exp-secret-0123456789abcdef0".to_string();
        // Use exp = 1.5 (past: Unix timestamp 1 is 1970-01-01, always expired).
        let claims = r#"{"sub":"x","exp":1.5}"#.to_string();
        let token: IpeResult<String, String> = jwt_encode_hs256(secret.clone(), claims);
        let token = match token {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("encode: {e}"),
        };

        let flat: IpeResult<String, String> = jwt_decode_hs256(secret.clone(), token.clone());
        assert!(
            matches!(flat, IpeResult::Err(_)),
            "flat HS256: exp=1.5 (past) must be rejected"
        );

        let desc = crate::secret::secret_from_string(format!("HS256:{secret}"));
        let builder = ipe_jwt_decode(desc, now_unix(), token); // now_unix() from test module
        assert!(
            matches!(builder, IpeResult::Err(_)),
            "builder ipe_jwt_decode: exp=1.5 (past) must be rejected"
        );
    }

    /// Flat HS256: a token with a fractional but far-FUTURE exp must still be
    /// ACCEPTED — the `numeric_date` floor must not over-reject valid tokens.
    #[test]
    fn test_flat_decode_fractional_future_exp_accepted() {
        let secret = "future-frac-secret-0123456789abcde".to_string();
        // Far-future fractional exp: year ~2286, floors to a still-future integer.
        let claims = r#"{"sub":"x","exp":9999999999.9}"#.to_string();
        let token: IpeResult<String, String> = jwt_encode_hs256(secret.clone(), claims);
        let token = match token {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("encode: {e}"),
        };
        let decoded: IpeResult<String, String> = jwt_decode_hs256(secret, token);
        assert!(
            matches!(decoded, IpeResult::Ok(_)),
            "flat HS256: far-future fractional exp must be accepted"
        );
    }

    /// An unrecognised descriptor whose byte 20 falls mid-codepoint must not
    /// panic. 19 ASCII bytes (indices 0..18) followed by 'é' (2 UTF-8 bytes
    /// at indices 19-20) means a byte-offset slice at `..20` lands on the
    /// second byte of 'é', which is not a char boundary and used to panic
    /// with "byte index 20 is not a char boundary".
    fn multibyte_boundary_descriptor() -> String {
        format!("{}é{}", "a".repeat(19), "trailing-tag-not-hs256-or-rs256")
    }

    #[test]
    fn ipe_jwt_encode_unknown_algorithm_multibyte_boundary_does_not_panic() {
        let desc = crate::secret::secret_from_string(multibyte_boundary_descriptor());
        let claims = JsonValue::Null;
        let result = ipe_jwt_encode(desc, claims);
        match result {
            IpeResult::Err(msg) => {
                let msg = msg.to_string();
                assert!(
                    msg.contains("unknown algorithm descriptor"),
                    "unexpected error message: {msg}"
                );
                // Never echo caller-derived descriptor content into the message.
                assert!(
                    !msg.contains('é'),
                    "error message must not echo caller-derived descriptor content: {msg}"
                );
            }
            IpeResult::Ok(_) => panic!("unknown algorithm descriptor must not succeed"),
        }
    }

    #[test]
    fn ipe_jwt_decode_unknown_algorithm_multibyte_boundary_does_not_panic() {
        let desc = crate::secret::secret_from_string(multibyte_boundary_descriptor());
        // Any 3-segment string clears the segment-count check so the unknown-
        // algorithm branch is actually reached.
        let token = "a.b.c".to_string();
        let result = ipe_jwt_decode(desc, 0, token);
        match result {
            IpeResult::Err(msg) => {
                let msg = msg.to_string();
                assert!(
                    msg.contains("unknown algorithm descriptor"),
                    "unexpected error message: {msg}"
                );
                assert!(
                    !msg.contains('é'),
                    "error message must not echo caller-derived descriptor content: {msg}"
                );
            }
            IpeResult::Ok(_) => panic!("unknown algorithm descriptor must not succeed"),
        }
    }

    // ── A present NumericDate claim must be a number ─────────────────────────
    //
    // jsonwebtoken's validation passes over a date claim it cannot parse as a
    // number, so a token whose future `nbf` (or past `exp`) is written as text
    // would verify unless the decoders refuse it themselves.

    const DATE_SECRET: &str = "date-claim-secret-0123456789abcdef";

    fn hs256_token(claims: &str) -> String {
        match jwt_encode_hs256::<String>(DATE_SECRET.to_string(), claims.to_string()) {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("encode: {e}"),
        }
    }

    fn flat_hs256(token: String) -> IpeResult<String, String> {
        jwt_decode_hs256(DATE_SECRET.to_string(), token)
    }

    fn builder_hs256(now: i64, token: String) -> IpeResult<crate::error::IpeError, String> {
        let desc = crate::secret::secret_from_string(format!("HS256:{DATE_SECRET}"));
        ipe_jwt_decode(desc, now, token)
    }

    /// The error text of a refused decode; panics when the decode succeeded.
    fn refusal<E: std::fmt::Display>(decoded: IpeResult<E, String>) -> String {
        match decoded {
            IpeResult::Err(e) => e.to_string(),
            IpeResult::Ok(payload) => panic!("decode must be refused, got Ok({payload})"),
        }
    }

    /// The flat HS256 decoder refuses a future `nbf`, a past `exp`, and an
    /// `iat` written as JSON strings.
    #[test]
    fn flat_hs256_text_date_claims_refused() {
        let future = now_unix() + 3600;
        for (claims, claim) in [
            (format!(r#"{{"sub":"x","nbf":"{future}"}}"#), "nbf"),
            (r#"{"sub":"x","exp":"1"}"#.to_string(), "exp"),
            (r#"{"sub":"x","iat":"1"}"#.to_string(), "iat"),
        ] {
            let msg = refusal(flat_hs256(hs256_token(&claims)));
            assert!(
                msg.contains(&format!("`{claim}` is not a NumericDate")),
                "{claims}: unexpected refusal {msg}"
            );
        }
    }

    /// The flat RS256 decoder refuses a text `nbf` and a text `exp`.
    #[test]
    fn flat_rs256_text_date_claims_refused() {
        let future = now_unix() + 3600;
        for (claims, claim) in [
            (format!(r#"{{"sub":"bob","nbf":"{future}"}}"#), "nbf"),
            (r#"{"sub":"bob","exp":"1"}"#.to_string(), "exp"),
        ] {
            let token = match jwt_encode_rs256::<String>(RS256_PRIV_PEM.to_string(), claims.clone())
            {
                IpeResult::Ok(t) => t,
                IpeResult::Err(e) => panic!("encode-rs: {e}"),
            };
            let msg = refusal(jwt_decode_rs256::<String>(RS256_PUB_PEM.to_string(), token));
            assert!(
                msg.contains(&format!("`{claim}` is not a NumericDate")),
                "{claims}: unexpected refusal {msg}"
            );
        }
    }

    /// `Jwt.decode` refuses every present date claim that is not a JSON number:
    /// text, `null`, boolean, array and object values.
    #[test]
    fn builder_non_numeric_date_claims_refused() {
        for (claims, claim) in [
            (r#"{"sub":"x","nbf":"1000"}"#, "nbf"),
            (r#"{"sub":"x","exp":"100"}"#, "exp"),
            (r#"{"sub":"x","iat":"100"}"#, "iat"),
            (r#"{"sub":"x","nbf":null}"#, "nbf"),
            (r#"{"sub":"x","exp":true}"#, "exp"),
            (r#"{"sub":"x","exp":[1]}"#, "exp"),
            (r#"{"sub":"x","nbf":{"at":1000}}"#, "nbf"),
        ] {
            let msg = refusal(builder_hs256(500, hs256_token(claims)));
            // `IpeError`'s display prefixes the error kind's label.
            assert!(
                msg.ends_with(&format!("Jwt.decode: token `{claim}` is not a NumericDate")),
                "{claims}: unexpected refusal {msg}"
            );
        }
    }

    /// Numeric date claims at their boundaries still decode on both paths, and
    /// a text value in a claim that is not a date is not refused.
    #[test]
    fn numeric_date_claims_at_boundary_accepted() {
        // Builder: now == nbf, now == exp - 1, numeric iat, fractional nbf.
        let token = hs256_token(r#"{"sub":"x","nbf":500,"exp":501,"iat":400,"jti":"100"}"#);
        assert!(matches!(builder_hs256(500, token), IpeResult::Ok(_)));
        let token = hs256_token(r#"{"sub":"x","nbf":500.9,"iat":0.5}"#);
        assert!(matches!(builder_hs256(500, token), IpeResult::Ok(_)));
        // Flat: a far-future exp and a numeric iat.
        let token = hs256_token(r#"{"sub":"x","exp":9999999999,"iat":1}"#);
        assert!(matches!(flat_hs256(token), IpeResult::Ok(_)));
    }

    /// The reader distinguishes an absent claim from a mistyped one and refuses
    /// a claims set that is not an object.
    #[test]
    fn read_numeric_date_absent_vs_mistyped() {
        let claims = serde_json::json!({"exp": 7, "nbf": "7", "frac": -0.1});
        assert_eq!(read_numeric_date(&claims, "exp"), Ok(Some(7)));
        assert_eq!(read_numeric_date(&claims, "frac"), Ok(Some(-1)));
        assert_eq!(read_numeric_date(&claims, "iat"), Ok(None));
        assert_eq!(
            read_numeric_date(&claims, "nbf"),
            Err(ClaimsRefusal::NonNumericDate { claim: "nbf" })
        );
        assert_eq!(
            read_numeric_date(&serde_json::json!([7]), "exp"),
            Err(ClaimsRefusal::NotAnObject)
        );
        assert_eq!(
            admit_time_claims(&serde_json::json!("exp"), 0),
            Err(ClaimsRefusal::NotAnObject)
        );
    }
}
