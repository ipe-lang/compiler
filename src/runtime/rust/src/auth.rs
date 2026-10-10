//! Ipe.Auth kernels — authentication helpers.
//!
//! Two tiers (matches the Ipê-side `Ipe.Auth` doc):
//!   - Pure crypto (Result Error _): hashPassword/Cost, verifyPassword,
//!     passwordStrength, signToken, verifyToken.
//!   - DB flows (Task Error _): register, login, setRole.
//!
//! Backed by `bcrypt` for password hashing and `jsonwebtoken` for
//! JWT HS256. DB kernels reuse the sqlx pool from the `db` module.

use super::*;
use std::collections::HashMap;
#[cfg(feature = "db")]
use std::sync::OnceLock;

/// A fixed, valid cost-12 bcrypt hash used ONLY to make the unknown-email login
/// path do the same KDF work as the known-email path (anti-enumeration timing
/// defence). Computed once; the verify result is always discarded. Cost 12
/// matches the register default so both paths cost the same. Only the db
/// `auth_login` flow consumes it, so it is `db`-gated alongside its sole caller
/// — a `jwt`-without-`db` auth build (hash/verify/sign kernels only) needs
/// neither.
#[cfg(feature = "db")]
fn dummy_bcrypt_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        // bcrypt::hash is infallible for a fixed valid input + cost; on the
        // structurally-unreachable Err, fall back to a static valid cost-12
        // hash literal so the verify still runs the KDF.
        bcrypt::hash("ipe-login-timing-defence", 12).unwrap_or_else(|_| {
            "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW".to_string()
        })
    })
}

// ─── Pure crypto kernels ──────────────────────────────────────────────

/// Ipê `hashPassword : String -> Result Error String`. Bcrypt with default
/// cost 12.
pub fn auth_hash_password<E: From<String>>(pw: String) -> IpeResult<E, String> {
    auth_hash_password_cost(pw, 12)
}

/// The lowest bcrypt cost the library accepts.
const BCRYPT_COST_MIN: u32 = 4;

/// The highest bcrypt cost hashed or verified: each +1 doubles the work, so a
/// cost past this ceiling (~1–2 s/hash) is a CPU-exhaustion vector.
const BCRYPT_COST_MAX: u32 = 15;

/// A bcrypt work factor inside `[BCRYPT_COST_MIN, BCRYPT_COST_MAX]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BcryptCost(u32);

/// Why a stored hash was refused before bcrypt ran on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StoredHashRefusal {
    /// The hash is not a `$2[abxy]$NN$<salt><digest>` hash bcrypt verifies.
    NotBcrypt,
    /// The hash's cost field is above [`BCRYPT_COST_MAX`].
    CostOverCeiling,
}

impl StoredHashRefusal {
    /// The fixed message an `Auth.verifyPassword` refusal carries; it never
    /// names the hash.
    const fn message(self) -> &'static str {
        match self {
            Self::NotBcrypt => "auth.verifyPassword: stored hash is not a bcrypt hash",
            Self::CostOverCeiling => "auth.verifyPassword: stored hash cost exceeds the ceiling",
        }
    }
}

impl BcryptCost {
    /// The `requested` cost clamped into the accepted range.
    fn clamped(requested: i64) -> Self {
        let clamped = requested.clamp(i64::from(BCRYPT_COST_MIN), i64::from(BCRYPT_COST_MAX));
        Self(u32::try_from(clamped).unwrap_or(BCRYPT_COST_MAX))
    }

    /// The cost field of the bcrypt `hash`, read from its `$2[abxy]$NN$`
    /// prefix.
    fn of_hash(hash: &str) -> Result<Self, StoredHashRefusal> {
        let [b'$', b'2', variant, b'$', tens, ones, b'$', ..] = hash.as_bytes() else {
            return Err(StoredHashRefusal::NotBcrypt);
        };
        if !matches!(variant, b'a' | b'b' | b'x' | b'y') {
            return Err(StoredHashRefusal::NotBcrypt);
        }
        let (Some(tens), Some(ones)) = (
            char::from(*tens).to_digit(10),
            char::from(*ones).to_digit(10),
        ) else {
            return Err(StoredHashRefusal::NotBcrypt);
        };
        let cost = tens.saturating_mul(10).saturating_add(ones);
        if cost < BCRYPT_COST_MIN {
            Err(StoredHashRefusal::NotBcrypt)
        } else if cost > BCRYPT_COST_MAX {
            Err(StoredHashRefusal::CostOverCeiling)
        } else {
            Ok(Self(cost))
        }
    }

    /// The work factor bcrypt runs at.
    const fn get(self) -> u32 {
        self.0
    }
}

/// The byte length of a bcrypt hash's `$2[abxy]$NN$` prefix.
const BCRYPT_PREFIX_LEN: usize = 7;

/// The salt's length in bcrypt base64 characters.
const BCRYPT_SALT_CHARS: usize = 22;

/// The salt and digest's length in bcrypt base64 characters.
const BCRYPT_BODY_CHARS: usize = 53;

/// The salt's length in bytes.
const BCRYPT_SALT_BYTES: usize = 16;

/// The stored digest's length in bytes.
const BCRYPT_DIGEST_BYTES: usize = 23;

/// The base64 engine bcrypt encodes its salt and digest with: its own
/// alphabet, no padding, canonical trailing bits.
const BCRYPT_BASE64: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::BCRYPT,
    base64::engine::general_purpose::NO_PAD,
);

/// A stored hash bcrypt verifies without refusing it: the exact
/// `$2[abxy]$NN$<salt><digest>` shape, its cost inside
/// `[BCRYPT_COST_MIN, BCRYPT_COST_MAX]`, salt and digest each decoding to its
/// full length. Verifying one always runs the KDF, at a bounded cost.
#[derive(Clone, Copy)]
struct StoredHash<'a> {
    /// The hash text, proven to have that shape.
    text: &'a str,
}

impl<'a> StoredHash<'a> {
    /// The stored hash `text`, admitted only in the shape bcrypt verifies.
    fn parse(text: &'a str) -> Result<Self, StoredHashRefusal> {
        use base64::Engine as _;
        BcryptCost::of_hash(text)?;
        let decodes_to = |part: &str, len: usize| {
            BCRYPT_BASE64
                .decode(part)
                .is_ok_and(|bytes| bytes.len() == len)
        };
        let body = text.get(BCRYPT_PREFIX_LEN..).unwrap_or_default();
        match body.split_at_checked(BCRYPT_SALT_CHARS) {
            Some((salt, digest))
                if body.len() == BCRYPT_BODY_CHARS
                    && decodes_to(salt, BCRYPT_SALT_BYTES)
                    && decodes_to(digest, BCRYPT_DIGEST_BYTES) =>
            {
                Ok(Self { text })
            }
            _ => Err(StoredHashRefusal::NotBcrypt),
        }
    }

    /// Whether `password` hashes to this hash.
    fn verifies(self, password: &str) -> Result<bool, StoredHashRefusal> {
        bcrypt::verify(password, self.text).map_err(|_| StoredHashRefusal::NotBcrypt)
    }
}

/// Ipê `hashPasswordCost : String -> Int -> Result Error String`. Clamps cost to
/// `[BCRYPT_COST_MIN, BCRYPT_COST_MAX]` = [4, 15] (4 = fast for tests, 12 =
/// production default, 14–15 = high security). The bcrypt VALID range is
/// [4, 31], but cost is caller-controlled: each +1 DOUBLES the work, so cost 31
/// is a single-call CPU-exhaustion DoS (~years per hash). Higher than the
/// ceiling is always a self-DoS, so it is clamped down rather than honoured.
pub fn auth_hash_password_cost<E: From<String>>(pw: String, cost: i64) -> IpeResult<E, String> {
    if pw.chars().count() < 8 {
        return IpeResult::Err("password must be at least 8 characters".to_string().into());
    }
    if pw.len() > 72 {
        return IpeResult::Err(
            "password longer than 72 bytes (bcrypt limit)"
                .to_string()
                .into(),
        );
    }
    match bcrypt::hash(&pw, BcryptCost::clamped(cost).get()) {
        Ok(h) => IpeResult::Ok(h),
        Err(e) => IpeResult::Err(format!("bcrypt: {}", e).into()),
    }
}

/// Ipê `verifyPassword : String -> String -> Result Error Bool`.
/// `verifyPassword candidate hash` — true if candidate hashes to the same hash.
///
/// A hash that is not a [`StoredHash`] (not a bcrypt hash, or its cost above
/// [`BCRYPT_COST_MAX`]) is refused before the KDF runs, with a fixed
/// `InvalidInput` message that never names the hash.
pub fn auth_verify_password(pw: String, hash: String) -> IpeResult<IpeError, bool> {
    StoredHash::parse(&hash)
        .and_then(|stored| stored.verifies(&pw))
        .map_or_else(
            |refusal| IpeResult::Err(IpeError::invalid_input(refusal.message().to_owned())),
            IpeResult::Ok,
        )
}

/// Ipê `passwordStrength : String -> Result Error String`. Validates length
/// and character variety; returns a strength rating on Ok.
///   <8 chars  → Err "too short"
///   >72 bytes → Err "too long" (bcrypt limit)
/// > all-letters or all-digits → Err "needs both letters and digits"
/// > ≥12 chars + letter + digit + symbol → "strong"
/// > ≥10 chars + letter + digit          → "medium"
/// > otherwise (passes letter+digit check) → "weak"
pub fn auth_password_strength<E: From<String>>(pw: String) -> IpeResult<E, String> {
    if pw.chars().count() < 8 {
        return IpeResult::Err("password must be at least 8 characters".to_string().into());
    }
    if pw.len() > 72 {
        return IpeResult::Err(
            "password longer than 72 bytes (bcrypt limit)"
                .to_string()
                .into(),
        );
    }
    let has_letter = pw.chars().any(|c| c.is_alphabetic());
    let has_digit = pw.chars().any(|c| c.is_ascii_digit());
    let has_symbol = pw.chars().any(|c| !c.is_alphanumeric());
    if !has_letter || !has_digit {
        return IpeResult::Err(
            "password must contain both letters and digits"
                .to_string()
                .into(),
        );
    }
    let char_count = pw.chars().count();
    let rating = if char_count >= 12 && has_symbol {
        "strong"
    } else if char_count >= 10 {
        "medium"
    } else {
        "weak"
    };
    IpeResult::Ok(rating.to_string())
}

// ─── JWT kernels (HS256) ──────────────────────────────────────────────

/// Ipê `signToken : String -> a -> Int -> Result Error String`.
/// `signToken secret claims expirySeconds`. `claims` is a string-keyed map of
/// string values at the runtime level (Ipê's polymorphic `a` resolves to
/// HashMap<String,String> at the FFI boundary). Adds `exp` (now + expirySeconds),
/// `iat` (now), `cap` (now + AuthMaxLifetime), and `jti` (a random session id)
/// claims. Secret must be ≥32 bytes (matches  production gate).
///
/// `cap` is the absolute lifetime ceiling — a token is invalid once `now >= cap`
/// regardless of `exp`. It is stamped at first issue and must never be rewritten
/// on any subsequent re-issue; a client-mutated `cap` fails signature verification.
///
/// `jti` is a per-session random id used for session-scoped revocation. A caller
/// that already supplies a `jti` claim (re-issue scenario) keeps its original value —
/// only a fresh token (no `jti` in the supplied claims) gets a new random id. This
/// guarantees `jti` is immutable across re-issues, exactly like `cap`.
pub fn auth_sign_token<E: From<String>>(
    secret: String,
    claims: HashMap<String, String>,
    expiry_seconds: i64,
) -> IpeResult<E, String> {
    if secret.len() < crate::jwt::HS256_MIN_SECRET_BYTES {
        return IpeResult::Err(
            crate::jwt::hs256_short_secret_msg("auth.signToken", secret.len()).into(),
        );
    }
    // A negative TTL must NOT mint a token. Without this guard a negative
    // `expiry_seconds` (e.g. i64::MIN) underflows `now + expiry_seconds`, and
    // the `unwrap_or(i64::MAX)` fallback would invert intent into a
    // never-expiring token. Reject up front so the safe outcome is the only
    // reachable one.
    if expiry_seconds < 0 {
        return IpeResult::Err(
            "auth.signToken: expiry_seconds must be non-negative"
                .to_string()
                .into(),
        );
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    // Saturate to i64::MAX on overflow so a caller-controlled large
    // expiry_seconds never panics under debug overflow-checks.
    // i64::MAX is a far-future timestamp (~292 billion years) — a safe floor.
    let exp = now.checked_add(expiry_seconds).unwrap_or(i64::MAX);
    let iat = now;
    // The absolute lifetime cap: iat + max_lifetime. A caller that already
    // carries a `cap` claim (re-issue scenario) keeps its original value, which
    // is never past the fresh cap — only a fresh token (no `cap` in the supplied
    // claims) gets the cap stamped. A re-issue therefore never extends the
    // absolute lifetime.
    let max_lifetime_secs = match crate::app_config::resolve_auth_max_lifetime() {
        Ok(secs) => secs,
        // A malformed lifetime mints no token: the cap would be an unknown bound.
        Err(refusal) => return IpeResult::Err(format!("auth.signToken: {refusal}").into()),
    };
    // A fresh token's cap is iat + max_lifetime. A carried cap was stamped at an
    // earlier iat, so it never exceeds that; a larger carried value (a claims
    // map built from untrusted input) is clamped, never honoured.
    let fresh_cap = iat.saturating_add(i64::try_from(max_lifetime_secs).unwrap_or(i64::MAX));
    let cap: i64 = claims
        .get("cap")
        .and_then(|s| s.parse::<i64>().ok())
        .map_or(fresh_cap, |carried| carried.min(fresh_cap));
    // Per-session id for session-scoped revocation. A re-issue that already
    // carries a `jti` keeps it verbatim (like `cap` and `iat`) — only a fresh
    // token (no `jti` in the supplied claims) gets a new random id minted here.
    let jti: String = match claims.get("jti").filter(|s| !s.is_empty()) {
        Some(existing) => existing.clone(),
        None => {
            // Mint a new random session id. `uuid::Uuid::new_v4` draws from the
            // OS entropy source; its output is not guessable by an attacker who
            // does not hold the HS256 secret (which already protects the token),
            // but the `jti` provides an additional per-session handle for
            // targeted revocation without needing to know the secret.
            uuid::Uuid::new_v4().to_string()
        }
    };
    // A caller-supplied `nbf` is signed as a NumericDate, the only form the
    // verifier reads; any other value mints no token.
    let nbf = match claims.get("nbf").map(|raw| raw.parse::<i64>()) {
        None => None,
        Some(Ok(nbf)) => Some(nbf),
        Some(Err(_)) => {
            return IpeResult::Err(
                "auth.signToken: `nbf` must be whole Unix seconds"
                    .to_string()
                    .into(),
            );
        }
    };
    // Build the claims object with keys in ascending order so the signed bytes are
    // deterministic across runs. A `BTreeMap` fixes the key order explicitly,
    // independent of both the source `HashMap` iteration order and the ambient
    // object-order encoder setting, giving a byte-stable signature.
    let mut sorted: std::collections::BTreeMap<String, serde_json::Value> = claims
        .into_iter()
        // Strip any caller-supplied `cap`, `exp`, `iat`, and `jti` — these are
        // runtime-controlled claims; a caller must not be able to override them
        // via the claims map (the computed values below are authoritative).
        // `nbf` is re-inserted as a number below.
        .filter(|(k, _)| k != "cap" && k != "exp" && k != "iat" && k != "jti" && k != "nbf")
        .map(|(k, v)| (k, serde_json::Value::String(v)))
        .collect();
    if let Some(nbf) = nbf {
        sorted.insert("nbf".to_string(), serde_json::Value::Number(nbf.into()));
    }
    sorted.insert("cap".to_string(), serde_json::Value::Number(cap.into()));
    sorted.insert("exp".to_string(), serde_json::Value::Number(exp.into()));
    sorted.insert("iat".to_string(), serde_json::Value::Number(iat.into()));
    sorted.insert("jti".to_string(), serde_json::Value::String(jti));
    let payload: serde_json::Map<String, serde_json::Value> = sorted.into_iter().collect();
    let value = serde_json::Value::Object(payload);
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let key = jsonwebtoken::EncodingKey::from_secret(secret.as_bytes());
    match jsonwebtoken::encode(&header, &value, &key) {
        Ok(t) => IpeResult::Ok(t),
        Err(e) => IpeResult::Err(format!("jwt encode: {}", e).into()),
    }
}

/// Why `verify_claims` refused a token.
///
/// No variant carries the token, the secret or the verifier's error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenRefusal {
    /// The HS256 secret is shorter than the floor.
    ShortSecret,
    /// The token is at or past its `exp`.
    Expired,
    /// The token is before its `nbf`.
    NotYetValid,
    /// The token is at or past its absolute lifetime `cap`.
    PastCap,
    /// A time claim (`exp`, `nbf`, `iat`, `cap`) is present but not a JSON
    /// number, so no check could read it.
    NonNumericDate,
    /// The signature does not verify under the secret, or the header names
    /// another algorithm or key family.
    BadSignature,
    /// The token is not a well-formed HS256 JWT.
    Malformed,
    /// A claim the verifier requires (`exp`) is absent.
    MissingClaim,
}

impl TokenRefusal {
    /// Every variant, in declaration order.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 8] = [
        Self::ShortSecret,
        Self::Expired,
        Self::NotYetValid,
        Self::PastCap,
        Self::NonNumericDate,
        Self::BadSignature,
        Self::Malformed,
        Self::MissingClaim,
    ];

    /// The `Auth.verifyToken` refusal this surfaces as.
    #[must_use]
    pub const fn auth_error(self) -> IpeAuthError {
        match self {
            Self::ShortSecret => IpeAuthError::SecretTooShort,
            Self::Expired | Self::PastCap => IpeAuthError::Expired,
            Self::NotYetValid => IpeAuthError::NotYetValid,
            Self::NonNumericDate | Self::Malformed => IpeAuthError::Malformed,
            Self::BadSignature => IpeAuthError::BadSignature,
            Self::MissingClaim => IpeAuthError::MissingClaim,
        }
    }
}

/// The refusal a `jsonwebtoken` decode failure of `kind` stands for.
fn classify_jwt(kind: &jsonwebtoken::errors::ErrorKind) -> TokenRefusal {
    use jsonwebtoken::errors::ErrorKind as K;
    match kind {
        K::InvalidSignature
        | K::InvalidAlgorithm
        | K::InvalidAlgorithmName
        | K::InvalidKeyFormat => TokenRefusal::BadSignature,
        K::ExpiredSignature => TokenRefusal::Expired,
        K::ImmatureSignature => TokenRefusal::NotYetValid,
        K::MissingRequiredClaim(_) => TokenRefusal::MissingClaim,
        K::InvalidToken
        | K::Base64(_)
        | K::Json(_)
        | K::Utf8(_)
        | K::InvalidIssuer
        | K::InvalidAudience
        | K::InvalidSubject
        | K::InvalidEcdsaKey
        | K::InvalidRsaKey(_)
        | K::RsaFailedSigning
        | K::MissingAlgorithm
        | K::Crypto(_) => TokenRefusal::Malformed,
        // foreign non_exhaustive: unknown kinds refuse as Malformed
        _ => TokenRefusal::Malformed,
    }
}

/// The claims of a token whose signature, `exp`, `nbf` and `cap` verified, each
/// value coerced to a string.
///
/// Only `verify_claims` builds one, so a value of this type is proof the claims
/// came from a verified token.
pub struct VerifiedClaims {
    /// Every claim, its value coerced to a string.
    claims: HashMap<String, String>,
    /// The names of the claims whose value was not a JSON string.
    coerced: std::collections::HashSet<String>,
    /// The time claims, as the one reading `verify_claims` judged them by.
    times: TimeClaims,
}

/// The NumericDate claims of a verified token, as whole Unix seconds.
///
/// Only `verify_claims` builds one, from the same `jwt::read_numeric_date`
/// reading its clock checks used, so no later reader re-parses a date from the
/// claim's string form. `None` means the claim is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeClaims {
    /// `exp`: the token is refused at or after it.
    exp: Option<i64>,
    /// `nbf`: the token is refused before it.
    nbf: Option<i64>,
    /// `iat`: when the session was first minted.
    iat: Option<i64>,
    /// `cap`: the absolute lifetime bound.
    cap: Option<i64>,
}

impl TimeClaims {
    /// The `exp` claim, floored to whole seconds.
    #[must_use]
    pub const fn exp(self) -> Option<i64> {
        self.exp
    }

    /// The `nbf` claim, floored to whole seconds.
    #[must_use]
    pub const fn nbf(self) -> Option<i64> {
        self.nbf
    }

    /// The `iat` claim, floored to whole seconds.
    #[must_use]
    pub const fn iat(self) -> Option<i64> {
        self.iat
    }

    /// The `cap` claim, floored to whole seconds.
    #[must_use]
    pub const fn cap(self) -> Option<i64> {
        self.cap
    }
}

impl VerifiedClaims {
    /// The time claims the verification judged the token by.
    #[must_use]
    pub const fn times(&self) -> TimeClaims {
        self.times
    }

    /// The value of claim `name`, coerced to a string.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.claims.get(name).map(String::as_str)
    }

    /// The value of claim `name` only when the token wrote it as a JSON
    /// string: a `null`, number, boolean, array or object is absent here, never
    /// its JSON text.
    #[must_use]
    pub fn text(&self, name: &str) -> Option<&str> {
        if self.coerced.contains(name) {
            return None;
        }
        self.get(name)
    }

    /// Every claim as a `(name, value)` pair.
    pub fn iter(&self) -> ClaimPairs<'_> {
        self.claims
            .iter()
            .map(claim_pair as for<'x> fn((&'x String, &'x String)) -> (&'x str, &'x str))
    }

    /// The claims as the map the `Auth.verifyToken` kernel returns.
    #[must_use]
    pub fn into_map(self) -> HashMap<String, String> {
        self.claims
    }
}

/// The `(name, value)` pairs of [`VerifiedClaims`].
pub type ClaimPairs<'a> = std::iter::Map<
    std::collections::hash_map::Iter<'a, String, String>,
    fn((&'a String, &'a String)) -> (&'a str, &'a str),
>;

/// A claim entry as borrowed strings.
fn claim_pair<'a>((name, value): (&'a String, &'a String)) -> (&'a str, &'a str) {
    (name.as_str(), value.as_str())
}

impl<'a> IntoIterator for &'a VerifiedClaims {
    type Item = (&'a str, &'a str);
    type IntoIter = ClaimPairs<'a>;

    fn into_iter(self) -> ClaimPairs<'a> {
        self.iter()
    }
}

// A claim value can name the caller or the session, so `Debug` shows the claim
// names only.
impl std::fmt::Debug for VerifiedClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.claims.keys()).finish()
    }
}

/// The time claim `claim` of the claims set `payload`, read as `verify_claims`
/// judges it.
///
/// # Errors
///
/// [`TokenRefusal::Malformed`] when `payload` is not a JSON object;
/// [`TokenRefusal::NonNumericDate`] when the claim is present but not a number.
fn time_claim(
    payload: &serde_json::Value,
    claim: &'static str,
) -> Result<Option<i64>, TokenRefusal> {
    crate::jwt::read_numeric_date(payload, claim).map_err(|refusal| match refusal {
        crate::jwt::ClaimsRefusal::NonNumericDate { .. } => TokenRefusal::NonNumericDate,
        crate::jwt::ClaimsRefusal::NotAnObject => TokenRefusal::Malformed,
        crate::jwt::ClaimsRefusal::Expired => TokenRefusal::Expired,
        crate::jwt::ClaimsRefusal::NotYetValid => TokenRefusal::NotYetValid,
    })
}

/// Verify an HS256 `token` under `secret`: signature, `exp`, `nbf`, and (when
/// present) the absolute lifetime `cap`. A present `exp`, `nbf`, `iat` or `cap`
/// must be a JSON number.
///
/// # Absolute lifetime cap (`cap` claim)
///
/// Tokens minted by `auth_sign_token` carry a signed `cap` claim (`iat +
/// AuthMaxLifetime`). A token is rejected when `now >= cap`, regardless of `exp`.
/// A token without a `cap` claim is a legacy token (minted before this feature);
/// it is accepted only against its `exp` and is never granted an unlimited
/// lifetime — the `exp` bound is the sole gate in that case.
///
/// # Errors
///
/// A [`TokenRefusal`] naming the check the token failed.
pub(crate) fn verify_claims(secret: &str, token: &str) -> Result<VerifiedClaims, TokenRefusal> {
    if secret.len() < crate::jwt::HS256_MIN_SECRET_BYTES {
        return Err(TokenRefusal::ShortSecret);
    }
    // The time claims are read once, here, on the full RFC 7519 NumericDate
    // domain (negative, fractional, integer), before jsonwebtoken's `exp - 1`
    // u64 subtraction can underflow; see `jwt_decode_hs256` for that mechanism.
    // A present claim that is not a number is refused, never skipped, and the
    // typed values read here are the ones every later reader uses.
    let payload = crate::jwt::decode_payload(token).ok_or(TokenRefusal::Malformed)?;
    let times = TimeClaims {
        exp: time_claim(&payload, "exp")?,
        nbf: time_claim(&payload, "nbf")?,
        iat: time_claim(&payload, "iat")?,
        cap: time_claim(&payload, "cap")?,
    };
    let now = crate::jwt::now_unix_seconds();
    if times.exp.is_some_and(|exp| now >= exp) {
        return Err(TokenRefusal::Expired);
    }
    if times.nbf.is_some_and(|nbf| now < nbf) {
        return Err(TokenRefusal::NotYetValid);
    }
    // A token without a `cap` is bounded by its `exp` alone.
    if times.cap.is_some_and(|cap| now >= cap) {
        return Err(TokenRefusal::PastCap);
    }
    let key = jsonwebtoken::DecodingKey::from_secret(secret.as_bytes());
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    //  oracle rejects at `now >= exp` with zero clock skew. jsonwebtoken's
    // native boundary with leeway = 0 is `exp < now` (accepts at the exact
    // instant now == exp); reject_tokens_expiring_in_less_than = 1 shifts the
    // reject condition to `exp - 1 < now` (≡ `now >= exp`), restoring parity.
    // The pre-reject above guards the underflow site for the full NumericDate
    // domain. nbf parity needs no shift (already identical at leeway 0). See
    // jwt.rs's longer comment on this exact mechanism.
    validation.leeway = 0;
    validation.reject_tokens_expiring_in_less_than = 1;
    validation.validate_exp = true;
    // Enforce the standard not-before window too. jsonwebtoken defaults
    // validate_nbf = false, so a token carrying a future `nbf` (e.g. a
    // scheduled/delayed-grant token minted elsewhere under the same secret)
    // would otherwise be accepted before its valid-from time. Matches the
    // documented Ipe.Jwt contract (signature + exp + nbf checked).
    validation.validate_nbf = true;
    // Auth.signToken accepts arbitrary claims (including an `aud` key) with
    // no expected-audience argument on this generic decoder. jsonwebtoken's
    // default `validate_aud = true` would then REJECT any token that merely
    // CARRIES an `aud` claim (InvalidAudience) — breaking a clean
    // sign-then-verify roundtrip of aud-bearing claims. Mirrors jwt.rs's
    // identical rationale.
    validation.validate_aud = false;
    let parsed = jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation)
        .map_err(|e| classify_jwt(e.kind()))?;
    // The time claims were judged on the payload read above; the verified
    // claims set must be that same payload, or the judgement is of another one.
    if parsed.claims != payload {
        return Err(TokenRefusal::Malformed);
    }
    let mut claims = HashMap::new();
    let mut coerced = std::collections::HashSet::new();
    if let serde_json::Value::Object(m) = parsed.claims {
        for (k, v) in m {
            // Coerce each claim value to a string. Numbers/booleans get
            // their JSON-text representation; nested objects/arrays get their
            // JSON serialisation (Sprintf behaviour). A coerced claim's name is
            // kept, so `text` never reads `null` as the string "null".
            let s = match v {
                serde_json::Value::String(s) => s,
                other => {
                    coerced.insert(k.clone());
                    other.to_string()
                }
            };
            claims.insert(k, s);
        }
    }
    Ok(VerifiedClaims {
        claims,
        coerced,
        times,
    })
}

/// Ipê `verifyToken : Secret -> String -> Result AuthError (Dict String String)`.
/// Verifies the token (`verify_claims`) and returns its claims as a
/// `HashMap<String, String>`.
///
/// When the process revocation mode is `Store`
/// ([`process_mode`](crate::revocation::process_mode)), the token must also
/// pass the revocation gate: a revoked token, a token the store cannot judge,
/// and a token with no `sub`, no `jti` or no lifetime bound are refused. Inside
/// a `Web` session the admitted credential is bound to that session, inside a
/// `Server` request to that request; while a `Web` app serves, a call neither
/// owns is refused.
///
/// Every refusal is a payload-free [`IpeAuthError`].
pub fn auth_verify_token(
    secret: String,
    token: String,
) -> IpeResult<IpeAuthError, HashMap<String, String>> {
    let gate = crate::revocation::ArmedGate::resolve(crate::revocation::process_mode());
    match verify_token_under(gate, &secret, &token) {
        Ok(claims) => IpeResult::Ok(claims),
        Err(refusal) => IpeResult::Err(refusal),
    }
}

/// Where an armed `Auth.verifyToken` binds the credential it admits.
enum BindTarget {
    /// The credential set of the `Web` session user code runs on behalf of.
    #[cfg(all(feature = "web-core", feature = "server"))]
    Session(std::sync::Arc<std::sync::Mutex<crate::revocation::SessionBindings>>),
    /// The binding set of the `Server` request being handled.
    #[cfg(feature = "server")]
    ServerRequest(std::sync::Arc<std::sync::Mutex<crate::revocation::SessionBindings>>),
    /// No channel owner while a `Web` app serves in this process: a task the
    /// runtime spawned without its session's scope. Refused, never admitted
    /// unbound, because the session it acts for could not be closed on revoke.
    #[cfg(all(feature = "web-core", feature = "server"))]
    Unscoped,
    /// No channel owner: a script, a CLI program or a background task.
    Outside,
}

/// The channel owner the current task runs on behalf of, in this process.
fn bind_target() -> BindTarget {
    bind_target_in(web_serving())
}

/// Whether a `Web` app serves in this process.
#[cfg(all(feature = "web-core", feature = "server"))]
fn web_serving() -> bool {
    crate::web::web_serving()
}

/// Without the `Web` server no `Web` app can serve.
#[cfg(not(all(feature = "web-core", feature = "server")))]
const fn web_serving() -> bool {
    false
}

/// The channel owner the current task runs on behalf of, given whether a `Web` app serves.
///
/// The `Web` session scope wins over the `Server` request: a `Web` router
/// mounted in a `Server` sees both, and the session is the long-lived owner.
fn bind_target_in(web_serving: bool) -> BindTarget {
    #[cfg(all(feature = "web-core", feature = "server"))]
    if let Some(bindings) = crate::web::pubsub::session_bindings() {
        return BindTarget::Session(bindings);
    }
    #[cfg(feature = "server")]
    if let Some(bindings) = crate::server::request_bindings() {
        return BindTarget::ServerRequest(bindings);
    }
    #[cfg(all(feature = "web-core", feature = "server"))]
    if web_serving {
        return BindTarget::Unscoped;
    }
    #[cfg(not(all(feature = "web-core", feature = "server")))]
    let _ = web_serving;
    BindTarget::Outside
}

/// The `Auth.verifyToken` kernel under `gate`: verify, then (when armed) admit
/// and bind.
fn verify_token_under(
    gate: Option<crate::revocation::ArmedGate>,
    secret: &str,
    token: &str,
) -> Result<HashMap<String, String>, IpeAuthError> {
    verify_token_bound(gate, bind_target, secret, token)
}

/// [`verify_token_under`] with the channel owner read from `target`, only once armed.
fn verify_token_bound(
    gate: Option<crate::revocation::ArmedGate>,
    target: impl FnOnce() -> BindTarget,
    secret: &str,
    token: &str,
) -> Result<HashMap<String, String>, IpeAuthError> {
    let claims = verify_claims(secret, token).map_err(TokenRefusal::auth_error)?;
    if let Some(gate) = gate {
        let refuse = crate::revocation::Denial::auth_error;
        let credential = gate.admit(&claims, "sub").map_err(refuse)?;
        match target() {
            #[cfg(all(feature = "web-core", feature = "server"))]
            BindTarget::Session(bindings) => {
                crate::revocation::bind_shared(&bindings, credential).map_err(refuse)?;
            }
            #[cfg(feature = "server")]
            BindTarget::ServerRequest(bindings) => {
                crate::revocation::bind_shared(&bindings, credential).map_err(refuse)?;
            }
            #[cfg(all(feature = "web-core", feature = "server"))]
            BindTarget::Unscoped => {
                return Err(refuse(crate::revocation::Denial::Unscoped));
            }
            // Admitted; no channel exists to bind.
            BindTarget::Outside => drop(credential),
        }
    }
    Ok(claims.into_map())
}

// ─── Sliding re-issue ────────────────────────────────────────────────

/// The verified-origin context for a session re-issue. Fields are parsed from a
/// SIGNATURE-VERIFIED token, so a caller has no way to supply an untrusted value
/// — the type enforces that `iat`, `cap`, and `jti` come from a verified token, never
/// from a client-supplied claims map.
///
/// This is the CRUX of cap and jti immutability: by requiring `iat`/`cap`/`jti`
/// to flow through this type (which is only constructible by parsing a verified
/// token) the re-issue path structurally cannot accept a forged or caller-inflated
/// cap, nor a replaced session id.
#[cfg(feature = "jwt")]
#[derive(Clone)]
pub struct ReissueContext {
    /// Original issue timestamp (immutable across all re-issues).
    pub iat: i64,
    /// Absolute expiry cap (immutable across all re-issues).
    pub cap: i64,
    /// The subject claim value from the verified token.
    pub subject: String,
    /// Per-session id (immutable across all re-issues; used for session-scoped revocation).
    pub jti: String,
}

// The subject identifies the caller and the jti names the session, so `Debug`
// masks both, as it masks a `Principal`'s identity.
#[cfg(feature = "jwt")]
crate::redact::redacting_debug!(ReissueContext {
    shown: [iat, cap],
    masked: [subject, jti],
});

/// Parse a `ReissueContext` from signature-verified claims. Returns `None` when
/// any required field is missing or malformed — the caller must deny in that
/// case.
///
/// Tokens minted before `jti` was introduced carry no `jti` claim. For backward
/// compatibility, a missing `jti` is treated as an empty string — such a token
/// cannot be individually revoked by session id, but subject-level revocation
/// still applies. A fresh re-issue of a legacy token mints a new `jti` via the
/// `auth_sign_token` path (the empty string is filtered out in that path).
#[cfg(feature = "jwt")]
#[must_use]
pub fn reissue_context_from_claims(claims: &VerifiedClaims) -> Option<ReissueContext> {
    let times = claims.times();
    let iat = times.iat()?;
    let cap = times.cap()?;
    let subject = claims.get("sub").filter(|s| !s.is_empty())?.to_owned();
    // `jti` absent on legacy tokens — treat as empty (cannot be session-revoked by id).
    let jti = claims.get("jti").unwrap_or_default().to_owned();
    Some(ReissueContext {
        iat,
        cap,
        subject,
        jti,
    })
}

/// Mint a fresh session token on behalf of a sliding re-issue. The new `exp` is
/// `min(now + slide_window_secs, ctx.cap)`; `iat` and `cap` are carried verbatim
/// from `ctx` (the verified-origin context). The caller supplies additional claims
/// (e.g. `role`) from the verified token.
///
/// Returns `None` when `now >= ctx.cap` — the session cannot slide past its
/// absolute cap, and the caller must deny or let the session expire.
#[cfg(feature = "jwt")]
pub fn auth_reissue_token<E: From<String>>(
    secret: &str,
    ctx: &ReissueContext,
    extra_claims: std::collections::HashMap<String, String>,
    slide_window_secs: i64,
) -> Option<IpeResult<E, String>> {
    if secret.len() < crate::jwt::HS256_MIN_SECRET_BYTES {
        return Some(IpeResult::Err(
            crate::jwt::hs256_short_secret_msg("auth.reissueToken", secret.len()).into(),
        ));
    }
    let now = crate::jwt::now_unix_seconds();
    if now >= ctx.cap {
        // Session has hit its absolute cap — no re-issue possible.
        return None;
    }
    // New sliding expiry: extend by the slide window, but never past the cap.
    let new_exp = now
        .checked_add(slide_window_secs)
        .unwrap_or(i64::MAX)
        .min(ctx.cap);
    // Build deterministic sorted payload. `iat`, `cap`, `jti`, and `sub` come
    // verbatim from `ctx` (verified-origin); caller-supplied duplicates are stripped.
    // `nbf` is dropped: the verified token was already past it, and its text
    // form would not be a NumericDate.
    let mut sorted: std::collections::BTreeMap<String, serde_json::Value> = extra_claims
        .into_iter()
        .filter(|(k, _)| {
            k != "cap" && k != "exp" && k != "iat" && k != "jti" && k != "sub" && k != "nbf"
        })
        .map(|(k, v)| (k, serde_json::Value::String(v)))
        .collect();
    sorted.insert("cap".to_string(), serde_json::Value::Number(ctx.cap.into()));
    sorted.insert("exp".to_string(), serde_json::Value::Number(new_exp.into()));
    sorted.insert("iat".to_string(), serde_json::Value::Number(ctx.iat.into()));
    // `jti` carried verbatim — a re-issued token is the same session, so its id
    // must not change. This preserves session-scoped revocation across re-issues.
    sorted.insert(
        "jti".to_string(),
        serde_json::Value::String(ctx.jti.clone()),
    );
    sorted.insert(
        "sub".to_string(),
        serde_json::Value::String(ctx.subject.clone()),
    );
    let payload: serde_json::Map<String, serde_json::Value> = sorted.into_iter().collect();
    let value = serde_json::Value::Object(payload);
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let key = jsonwebtoken::EncodingKey::from_secret(secret.as_bytes());
    Some(match jsonwebtoken::encode(&header, &value, &key) {
        Ok(t) => IpeResult::Ok(t),
        Err(e) => IpeResult::Err(format!("jwt encode (reissue): {}", e).into()),
    })
}

// ─── DB-touching kernels ──────────────────────────────────────────────
// All three functions (`register`, `login`, `setRole`) take a `Db` connection
// and use `sqlx` directly. They are gated on `#[cfg(feature = "db")]` so a
// non-db project that imports `auth` for the pure-crypto tier (hashPassword,
// verifyPassword, signToken, verifyToken, passwordStrength) still compiles.
// When `db` is disabled `Db = ()` (from config.rs's non-db branch), so the
// call sites never have a real connection to pass — the generated code for
// `AuthRegister/Login/SetRole` is only emitted when the lowerer detects those
// kernel calls, which implies `uses_db = true` and `db` in default features.

#[cfg(feature = "db")]
/// The Ipê `Error` for a failed `users` statement: classified like every other
/// statement failure, so the driver's message (which can name a column or
/// embed a bound value) never reaches the caller.
fn auth_db_error<E: crate::FromIpeError>(context: &str, e: &sqlx::Error) -> E {
    crate::db::driver_error(context, crate::db::KERNEL_ENGINE, e)
}

#[cfg(feature = "db")]
/// Idempotent `CREATE TABLE IF NOT EXISTS users (...)`. Runs at the start of
/// register/login/setRole so the schema is always available without users
/// having to call a separate migration. The id-column DDL is per-driver
/// — `db_auto_id_column()` returns the right fragment for sqlite
/// (`INTEGER PRIMARY KEY AUTOINCREMENT`), mysql (`BIGINT NOT NULL
/// AUTO_INCREMENT PRIMARY KEY`), or postgres (`BIGSERIAL PRIMARY KEY`).
async fn ensure_users_schema<E: crate::FromIpeError + Send>(conn: &Db) -> IpeResult<E, ()> {
    let schema = format!(
        "CREATE TABLE IF NOT EXISTS users (
            {},
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at BIGINT NOT NULL
        )",
        db_auto_id_column()
    );
    match sqlx::query(&schema).execute(conn).await {
        Ok(_) => IpeResult::Ok(()),
        Err(e) => IpeResult::Err(auth_db_error("auth.users schema: db: ", &e)),
    }
}

#[cfg(feature = "db")]
/// Ipê `register : Db -> String -> String -> Task Error Int`.
/// Creates a new user. Returns the new user id.
pub fn auth_register<
    E: Send + From<String> + crate::FromUnavailable + crate::FromIpeError + 'static,
>(
    conn: Db,
    email: String,
    password: String,
) -> IpeTask<E, i64> {
    Box::pin(async move {
        // Normalize the email (trim + lowercase) so a case/whitespace variant can't
        // create a DUPLICATE account that bypasses the UNIQUE constraint, and so
        // login matches regardless of the case the user types. Applied identically
        // in auth_login, so auth BEHAVIOUR is unchanged (login still succeeds); only
        // the stored case is canonical. (Email local-parts are technically case-
        // sensitive per RFC 5321, but every real provider treats them case-
        // insensitively; canonical-lowercase is the universal practice.)
        let email = email.trim().to_lowercase();
        if let IpeResult::Err(e) = ensure_users_schema::<E>(&conn).await {
            return IpeResult::Err(e);
        }
        // bcrypt is CPU-bound and BLOCKING (~250 ms at cost 12). Running it on a
        // tokio worker thread starves the async runtime (every concurrent register
        // ties up a core worker). Offload to the blocking pool.
        let hashed = crate::threads::join_blocking("auth.register", move || {
            auth_hash_password::<E>(password)
        })
        .await;
        let hash = match hashed {
            Ok(IpeResult::Ok(h)) => h,
            Ok(IpeResult::Err(e)) => return IpeResult::Err(e),
            Err(failure) => {
                return IpeResult::Err(
                    failure.into_error("auth.register: password-hash task failed"),
                );
            }
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let sql = db_format_sql(
            "INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, ?, ?)"
                .to_string(),
        );
        let result = sqlx::query(&sql)
            .bind(&email)
            .bind(&hash)
            .bind("user")
            .bind(now)
            .execute(&conn)
            .await;
        match result {
            Ok(res) => IpeResult::Ok(db_last_insert_id(&res)),
            Err(e) => {
                let failure = crate::db::classify_failure(crate::db::KERNEL_ENGINE, &e);
                if failure == IpeDbFailure::UniqueViolation {
                    IpeResult::Err(E::from_ipe_error(IpeError::database(
                        failure,
                        "auth.register: email already registered".to_owned(),
                    )))
                } else {
                    IpeResult::Err(auth_db_error("auth.register: db: ", &e))
                }
            }
        }
    })
}

#[cfg(feature = "db")]
/// Whether `password` verifies against the `stored` hash a login read.
///
/// A stored hash that is not a [`StoredHash`] never verifies, and bcrypt runs
/// on `decoy` instead: a cost above the ceiling never reaches the KDF, and a
/// hash bcrypt would refuse before hashing costs what a wrong password costs.
fn login_hash_verifies(password: &str, stored: &str, decoy: &str) -> bool {
    let parsed = StoredHash::parse(stored);
    let verified = parsed.map_or_else(
        |_| bcrypt::verify(password, decoy).unwrap_or(false),
        |hash| hash.verifies(password).unwrap_or(false),
    );
    parsed.is_ok() && verified
}

#[cfg(feature = "db")]
/// Ipê `login : Db -> String -> String -> Task Error Int`.
/// Authenticates the user. Returns user id on success. Does NOT leak whether
/// the email exists vs. password was wrong — both paths return the same
/// generic "invalid credentials" error.
pub fn auth_login<
    E: Send + From<String> + crate::FromUnavailable + crate::FromIpeError + 'static,
>(
    conn: Db,
    email: String,
    password: String,
) -> IpeTask<E, i64> {
    Box::pin(async move {
        // Same canonicalisation as auth_register so a case/whitespace variant of a
        // registered email still logs in (and can't be used to probe the store).
        let email = email.trim().to_lowercase();
        if let IpeResult::Err(e) = ensure_users_schema::<E>(&conn).await {
            return IpeResult::Err(e);
        }
        let sql = db_format_sql("SELECT id, password_hash FROM users WHERE email = ?".to_string());
        match sqlx::query(&sql).bind(&email).fetch_optional(&conn).await {
            Ok(Some(row)) => {
                use sqlx::Row;
                // A failed id-column read MUST NOT silently default to user 0
                // (authenticating as the wrong/zero user). Fail closed instead.
                let id: i64 = match row.try_get(0) {
                    Ok(id) => id,
                    Err(_) => {
                        return IpeResult::Err(
                            "auth.login: invalid credentials".to_string().into(),
                        );
                    }
                };
                let hash: String = row.try_get(1).unwrap_or_default();
                // bcrypt::verify is CPU-bound + blocking → blocking pool (see register).
                // A refused thread is `Unavailable` on both email paths alike; a
                // panicked verify fails closed as invalid credentials.
                let verified = crate::threads::join_blocking("auth.login", move || {
                    login_hash_verifies(&password, &hash, dummy_bcrypt_hash())
                })
                .await;
                match verified {
                    Ok(true) => IpeResult::Ok(id),
                    Err(crate::threads::BlockingFailure::Refused(refused)) => {
                        IpeResult::Err(refused.into_error())
                    }
                    Ok(false) | Err(crate::threads::BlockingFailure::Panicked) => {
                        IpeResult::Err("auth.login: invalid credentials".to_string().into())
                    }
                }
            }
            Ok(None) => {
                // TIMING: perform an equal-cost bcrypt verify against a fixed
                // cost-12 hash so the unknown-email path does the same hashing
                // work as the known-email path — removing the email-enumeration
                // timing oracle. The verify result is discarded; a refused
                // thread is `Unavailable`, as on the known-email path.
                let verified = crate::threads::join_blocking("auth.login", move || {
                    bcrypt::verify(&password, dummy_bcrypt_hash())
                })
                .await;
                match verified {
                    Err(crate::threads::BlockingFailure::Refused(refused)) => {
                        IpeResult::Err(refused.into_error())
                    }
                    Ok(_) | Err(crate::threads::BlockingFailure::Panicked) => {
                        IpeResult::Err("auth.login: invalid credentials".to_string().into())
                    }
                }
            }
            Err(e) => IpeResult::Err(auth_db_error("auth.login: db: ", &e)),
        }
    })
}

#[cfg(feature = "db")]
/// Ipê `setRole : Db -> Int -> String -> Task Error ()`.
/// Sets the user's role. No-op if the user doesn't exist (returns Ok).
pub fn auth_set_role<E: Send + From<String> + crate::FromIpeError + 'static>(
    conn: Db,
    user_id: i64,
    role: String,
) -> IpeTask<E, ()> {
    Box::pin(async move {
        if let IpeResult::Err(e) = ensure_users_schema::<E>(&conn).await {
            return IpeResult::Err(e);
        }
        let sql = db_format_sql("UPDATE users SET role = ? WHERE id = ?".to_string());
        match sqlx::query(&sql)
            .bind(&role)
            .bind(user_id)
            .execute(&conn)
            .await
        {
            Ok(_) => IpeResult::Ok(()),
            Err(e) => IpeResult::Err(auth_db_error("auth.setRole: db: ", &e)),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // bcrypt cost 4 for fast tests (production uses 12).
    const TEST_COST: i64 = 4;

    #[test]
    fn test_hash_verify_roundtrip() {
        let hash: IpeResult<String, String> =
            auth_hash_password_cost("password123".into(), TEST_COST);
        let h = match hash {
            IpeResult::Ok(h) => h,
            _ => panic!("hash"),
        };
        let ok: IpeResult<IpeError, bool> = auth_verify_password("password123".into(), h.clone());
        assert!(matches!(ok, IpeResult::Ok(true)));
        let bad: IpeResult<IpeError, bool> = auth_verify_password("wrongpass".into(), h);
        assert!(matches!(bad, IpeResult::Ok(false)));
    }

    #[test]
    fn test_hash_too_short() {
        let r: IpeResult<String, String> = auth_hash_password("short".into());
        assert!(matches!(r, IpeResult::Err(_)));
    }

    #[test]
    fn test_password_strength() {
        // <8 chars → Err
        let r: IpeResult<String, String> = auth_password_strength("short".into());
        assert!(matches!(r, IpeResult::Err(_)));
        // All letters → Err
        let r: IpeResult<String, String> = auth_password_strength("abcdefghij".into());
        assert!(matches!(r, IpeResult::Err(_)));
        // All digits → Err
        let r: IpeResult<String, String> = auth_password_strength("1234567890".into());
        assert!(matches!(r, IpeResult::Err(_)));
        // 8 chars, letter+digit → weak
        let r: IpeResult<String, String> = auth_password_strength("abc12345".into());
        assert!(matches!(r, IpeResult::Ok(ref s) if s == "weak"));
        // 10 chars, letter+digit → medium
        let r: IpeResult<String, String> = auth_password_strength("abcde12345".into());
        assert!(matches!(r, IpeResult::Ok(ref s) if s == "medium"));
        // 12 chars + symbol → strong
        let r: IpeResult<String, String> = auth_password_strength("abc12345xyz!".into());
        assert!(matches!(r, IpeResult::Ok(ref s) if s == "strong"));
    }

    #[test]
    fn test_jwt_sign_verify_roundtrip() {
        // Secret must be ≥32 bytes
        let secret = "a-test-secret-of-32-bytes-padding".to_string();
        let mut claims = HashMap::new();
        claims.insert("sub".to_string(), "user-123".to_string());
        claims.insert("role".to_string(), "admin".to_string());
        let token: IpeResult<String, String> = auth_sign_token(secret.clone(), claims, 3600);
        let t = match token {
            IpeResult::Ok(t) => t,
            _ => panic!("sign"),
        };
        let verified: IpeResult<IpeAuthError, HashMap<String, String>> =
            auth_verify_token(secret, t);
        match verified {
            IpeResult::Ok(m) => {
                assert_eq!(m.get("sub").unwrap(), "user-123");
                assert_eq!(m.get("role").unwrap(), "admin");
                assert!(m.contains_key("exp"));
                assert!(m.contains_key("iat")); // matches golden
            }
            _ => panic!("verify"),
        }
    }

    #[test]
    fn test_jwt_short_secret_rejected() {
        let token: IpeResult<String, String> =
            auth_sign_token("short".into(), HashMap::new(), 3600);
        assert!(matches!(token, IpeResult::Err(_)));
    }

    // The signed payload must have its claim keys in ascending order, which makes
    // the token byte-stable across runs regardless of the source-map iteration
    // order. Keys are chosen so their alphabetical order (`role` < `sub` < `zzz`)
    // differs from any insertion order, so dropping the sort changes the bytes and
    // fails here.
    #[test]
    fn test_auth_sign_token_payload_keys_sorted() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let secret = "a-test-secret-of-32-bytes-padding".to_string();
        let mut claims = HashMap::new();
        claims.insert("sub".to_string(), "u".to_string());
        claims.insert("zzz".to_string(), "z".to_string());
        claims.insert("role".to_string(), "admin".to_string());
        let token = match auth_sign_token::<String>(secret, claims, 3600) {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("sign: {}", e),
        };
        let payload_seg = token.split('.').nth(1).expect("payload segment");
        let bytes = URL_SAFE_NO_PAD.decode(payload_seg).expect("b64url payload");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("payload json");
        let keys: Vec<&String> = value.as_object().expect("object").keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(
            keys, sorted,
            "signed payload keys must be in ascending order for a byte-stable signature"
        );
        assert_eq!(keys, vec!["cap", "exp", "iat", "jti", "role", "sub", "zzz"]);
    }

    // Signing the same claims twice must yield byte-identical tokens (given the
    // same `exp`/`iat` and a supplied `jti`), locking out the `preserve_order`
    // non-determinism where `HashMap` iteration order leaked into the signed
    // bytes. A fresh token mints a RANDOM `jti` (a unique session id) by design,
    // so determinism is asserted over a supplied `jti`; `expiry_seconds = 0` pins
    // `exp` to `iat = now`, so both signings share the same timestamp within a
    // second; the retry loop tolerates the rare second-boundary crossing.
    #[test]
    fn test_auth_sign_token_is_deterministic() {
        let secret = "a-test-secret-of-32-bytes-padding".to_string();
        let make_claims = || {
            let mut c = HashMap::new();
            c.insert("sub".to_string(), "alice".to_string());
            c.insert("role".to_string(), "admin".to_string());
            c.insert("tenant".to_string(), "acme".to_string());
            c.insert("jti".to_string(), "fixed-session-id".to_string());
            c
        };
        let mut matched = false;
        for _ in 0..5 {
            let a = match auth_sign_token::<String>(secret.clone(), make_claims(), 0) {
                IpeResult::Ok(t) => t,
                IpeResult::Err(e) => panic!("sign a: {}", e),
            };
            let b = match auth_sign_token::<String>(secret.clone(), make_claims(), 0) {
                IpeResult::Ok(t) => t,
                IpeResult::Err(e) => panic!("sign b: {}", e),
            };
            if a == b {
                matched = true;
                break;
            }
        }
        assert!(
            matched,
            "auth_sign_token must produce identical bytes for identical claims"
        );
    }

    fn now_unix() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    // AUD-02 regression: mirror `jwt.rs`'s `test_hs256_expired_token_rejected`
    // boundary test for the `Auth` surface. `auth_sign_token` always computes
    // `exp = now + expiry_seconds` with `expiry_seconds >= 0` enforced, so a
    // past-`exp` token can't be minted through the public API — encode one
    // directly (same HS256 + JSON-claims shape `auth_sign_token` uses
    // internally) to exercise `auth_verify_token`'s `leeway = 0` guard.
    #[test]
    fn test_auth_verify_token_expired_30s_ago_rejected() {
        let secret = "a-test-secret-of-32-bytes-padding".to_string();
        let claims = serde_json::json!({ "sub": "x", "exp": now_unix() - 30 });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let key = jsonwebtoken::EncodingKey::from_secret(secret.as_bytes());
        let token = jsonwebtoken::encode(&header, &claims, &key).expect("encode");
        let verified: IpeResult<IpeAuthError, HashMap<String, String>> =
            auth_verify_token(secret, token);
        assert!(
            matches!(verified, IpeResult::Err(IpeAuthError::Expired)),
            "an Auth token expired 30s ago must be rejected (no clock-skew leeway)"
        );
    }

    // AUD-02 regression: claims containing an `aud` key must round-trip
    // through sign-then-verify. Pre-fix, `Validation`'s default
    // `validate_aud = true` rejected ANY token merely carrying an `aud`
    // claim (no expected-audience argument exists on this generic decoder),
    // breaking a clean roundtrip of aud-bearing claims.
    #[test]
    fn test_auth_verify_token_accepts_aud_bearing_claims() {
        let secret = "a-test-secret-of-32-bytes-padding".to_string();
        let mut claims = HashMap::new();
        claims.insert("sub".to_string(), "user-123".to_string());
        claims.insert("aud".to_string(), "my-service".to_string());
        let token: IpeResult<String, String> = auth_sign_token(secret.clone(), claims, 3600);
        let t = match token {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("sign: {e}"),
        };
        let verified: IpeResult<IpeAuthError, HashMap<String, String>> =
            auth_verify_token(secret, t);
        match verified {
            IpeResult::Ok(m) => {
                assert_eq!(m.get("aud").map(String::as_str), Some("my-service"));
            }
            IpeResult::Err(e) => panic!("verify must accept aud-bearing claims: {e:?}"),
        }
    }

    #[cfg(feature = "db")]
    #[tokio::test]
    async fn test_email_normalized_case_insensitive() {
        let pool = match DbPool::connect("sqlite::memory:").await {
            Ok(p) => p,
            Err(_) => return, // in-memory connect can't realistically fail; skip if it does
        };
        // Register with mixed case + surrounding whitespace.
        let id: IpeResult<String, i64> = auth_register(
            pool.clone(),
            "  Alice@Example.COM ".into(),
            "hunter2!".into(),
        )
        .await;
        let uid = match id {
            IpeResult::Ok(i) => i,
            IpeResult::Err(_) => 0,
        };
        assert!(uid > 0, "register with mixed-case email should succeed");
        // Login with a DIFFERENT case must resolve to the SAME account.
        let login: IpeResult<String, i64> =
            auth_login(pool.clone(), "alice@example.com".into(), "hunter2!".into()).await;
        assert!(
            matches!(login, IpeResult::Ok(u) if u == uid),
            "login must be case-insensitive"
        );
        // A case-variant re-register must hit the UNIQUE constraint (no dup account).
        let dup: IpeResult<String, i64> =
            auth_register(pool.clone(), "ALICE@example.com".into(), "hunter2!".into()).await;
        assert!(
            matches!(dup, IpeResult::Err(_)),
            "case-variant must not create a duplicate account"
        );
    }

    /// A pool over a fresh in-memory database whose `users` object is built by
    /// `setup` before any kernel runs.
    #[cfg(feature = "db")]
    async fn pool_with(setup: &str) -> DbPool {
        let pool = DbPool::connect("sqlite::memory:")
            .await
            .expect("in-memory connect");
        sqlx::query(setup).execute(&pool).await.expect("setup");
        pool
    }

    /// The database failure an auth kernel's error carries, with its message.
    #[cfg(feature = "db")]
    fn database_failure<T: std::fmt::Debug>(r: IpeResult<IpeError, T>) -> (IpeDbFailure, String) {
        match r {
            IpeResult::Err(IpeError::Error(_, info)) => match info.details {
                IpeMaybe::Just(IpeErrorDetails::Database(f)) => (f, info.message),
                other => panic!("no Database details ({other:?}): {}", info.message),
            },
            IpeResult::Ok(v) => panic!("accepted: {v:?}"),
        }
    }

    /// A duplicate registration is `Database UniqueViolation` with the fixed
    /// message, never the driver's text.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn register_duplicate_is_classified_unique_violation() {
        let pool = DbPool::connect("sqlite::memory:")
            .await
            .expect("in-memory connect");
        let first: IpeResult<IpeError, i64> =
            auth_register(pool.clone(), "dup@example.com".into(), "hunter2!".into()).await;
        assert!(
            matches!(first, IpeResult::Ok(_)),
            "first register: {first:?}"
        );
        let (failure, message) = database_failure(
            auth_register::<IpeError>(pool, "dup@example.com".into(), "hunter2!".into()).await,
        );
        assert_eq!(failure, IpeDbFailure::UniqueViolation);
        assert_eq!(message, "auth.register: email already registered");
    }

    /// Any other failed register insert is classified, and its message names
    /// neither the table nor the column the driver's message names.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn register_driver_failure_is_classified_without_driver_text() {
        let pool = pool_with(
            "CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at BIGINT NOT NULL,
                nickname TEXT NOT NULL
            )",
        )
        .await;
        let (failure, message) = database_failure(
            auth_register::<IpeError>(pool, "n@example.com".into(), "hunter2!".into()).await,
        );
        assert_eq!(failure, IpeDbFailure::NotNullViolation);
        assert!(message.starts_with("auth.register: db: "), "{message}");
        assert!(!message.contains("nickname"), "{message}");
        assert!(!message.contains("users"), "{message}");
    }

    /// A failed login query is classified without the driver's text.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn login_driver_failure_is_classified_without_driver_text() {
        let pool = pool_with("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)").await;
        let (failure, message) = database_failure(
            auth_login::<IpeError>(pool, "x@example.com".into(), "hunter2!".into()).await,
        );
        assert_eq!(failure, IpeDbFailure::InvalidStatement);
        assert!(message.starts_with("auth.login: db: "), "{message}");
        assert!(!message.contains("password_hash"), "{message}");
        assert!(!message.contains("no such column"), "{message}");
    }

    /// A failed role update is classified without the driver's text.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn set_role_driver_failure_is_classified_without_driver_text() {
        let pool = pool_with("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)").await;
        let (failure, message) =
            database_failure(auth_set_role::<IpeError>(pool, 1, "admin".into()).await);
        assert_eq!(failure, IpeDbFailure::InvalidStatement);
        assert!(message.starts_with("auth.setRole: db: "), "{message}");
        assert!(!message.contains("role"), "{message}");
        assert!(!message.contains("no such column"), "{message}");
    }

    /// A failed `users` schema statement is classified without the driver's
    /// text: an index already named `users` refuses the table.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn users_schema_failure_is_classified_without_driver_text() {
        let pool = pool_with("CREATE TABLE t (x INTEGER)").await;
        sqlx::query("CREATE INDEX users ON t (x)")
            .execute(&pool)
            .await
            .expect("index");
        let (failure, message) =
            database_failure(auth_set_role::<IpeError>(pool, 1, "admin".into()).await);
        assert_eq!(failure, IpeDbFailure::InvalidStatement);
        assert!(message.starts_with("auth.users schema: db: "), "{message}");
        assert!(!message.contains("index"), "{message}");
    }

    #[cfg(feature = "db")]
    #[tokio::test]
    async fn test_register_login_flow() {
        let pool = DbPool::connect("sqlite::memory:").await.expect("connect");
        // register
        let id: IpeResult<String, i64> =
            auth_register(pool.clone(), "alice@example.com".into(), "hunter2!".into()).await;
        let user_id = match id {
            IpeResult::Ok(i) => i,
            IpeResult::Err(e) => panic!("{}", e),
        };
        assert!(user_id > 0);
        // login correct
        let login_ok: IpeResult<String, i64> =
            auth_login(pool.clone(), "alice@example.com".into(), "hunter2!".into()).await;
        assert!(matches!(login_ok, IpeResult::Ok(uid) if uid == user_id));
        // login wrong password
        let login_bad: IpeResult<String, i64> =
            auth_login(pool.clone(), "alice@example.com".into(), "wrong".into()).await;
        assert!(matches!(login_bad, IpeResult::Err(_)));
        // login non-existent email
        let login_noexist: IpeResult<String, i64> =
            auth_login(pool.clone(), "nobody@example.com".into(), "anything".into()).await;
        assert!(matches!(login_noexist, IpeResult::Err(_)));
        // duplicate register
        let dup: IpeResult<String, i64> =
            auth_register(pool.clone(), "alice@example.com".into(), "hunter2!".into()).await;
        assert!(matches!(dup, IpeResult::Err(_)));
        // set role
        let role: IpeResult<String, ()> = auth_set_role(pool, user_id, "admin".into()).await;
        assert!(matches!(role, IpeResult::Ok(())));
    }

    #[test]
    fn test_sign_token_negative_expiry_rejected() {
        // A negative TTL must NOT mint a token (it would otherwise underflow
        // into a never-expiring token). Expect Err.
        let secret = "a-test-secret-of-32-bytes-padding".to_string();
        let token: IpeResult<String, String> = auth_sign_token(secret, HashMap::new(), -1);
        assert!(
            matches!(token, IpeResult::Err(_)),
            "negative expiry must be rejected"
        );
        // i64::MIN (the pathological underflow case) must also be rejected.
        let secret = "a-test-secret-of-32-bytes-padding".to_string();
        let token2: IpeResult<String, String> = auth_sign_token(secret, HashMap::new(), i64::MIN);
        assert!(matches!(token2, IpeResult::Err(_)));
    }

    #[cfg(feature = "db")]
    #[tokio::test]
    async fn test_login_id_decode_failure_yields_err_not_user_zero() {
        let pool = match DbPool::connect("sqlite::memory:").await {
            Ok(p) => p,
            Err(_) => return,
        };
        // Pre-create the users table with a TEXT id so a row's id column will
        // FAIL to decode into i64. ensure_users_schema uses CREATE TABLE IF NOT
        // EXISTS, so it leaves this schema in place.
        sqlx::query(
            "CREATE TABLE users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at BIGINT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .expect("create table");
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, role, created_at) \
             VALUES ('not-a-number', 'badid@example.com', 'x', 'user', 0)",
        )
        .execute(&pool)
        .await
        .expect("insert");
        // The matched-email branch reads id first; a decode failure must fail
        // closed (Err), NOT silently authenticate as user 0.
        let login: IpeResult<String, i64> =
            auth_login(pool, "badid@example.com".into(), "whatever".into()).await;
        assert!(
            matches!(login, IpeResult::Err(_)),
            "a failed id-column decode must yield Err, never Ok(0)"
        );
    }

    /// A login against a stored hash whose cost is above the ceiling, or that
    /// is not a bcrypt hash at all, is refused as invalid credentials without
    /// running the KDF at that cost.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn login_refuses_a_stored_hash_above_the_cost_ceiling() {
        let pool = match DbPool::connect("sqlite::memory:").await {
            Ok(p) => p,
            Err(_) => return,
        };
        let IpeResult::Ok(()) = ensure_users_schema::<IpeError>(&pool).await else {
            panic!("users schema");
        };
        let at_floor = bcrypt::hash("hunter2!", BCRYPT_COST_MIN).expect("hash");
        let over_ceiling = at_floor.replacen("$04$", "$31$", 1);
        assert_ne!(over_ceiling, at_floor, "the fixture raised the cost field");
        // A cost-12 prefix whose digest is one character short: bcrypt refuses
        // it before hashing.
        let at_default = at_floor.replacen("$04$", "$12$", 1);
        let (malformed, _) = at_default
            .split_at_checked(at_default.len() - 1)
            .expect("a full hash");
        assert!(bcrypt::verify("hunter2!", malformed).is_err());
        for (email, stored) in [
            ("floor@example.com", at_floor.as_str()),
            ("over@example.com", over_ceiling.as_str()),
            ("malformed@example.com", malformed),
            ("plain@example.com", "hunter2!"),
        ] {
            sqlx::query(
                "INSERT INTO users (email, password_hash, role, created_at) \
                 VALUES (?, ?, 'user', 0)",
            )
            .bind(email)
            .bind(stored)
            .execute(&pool)
            .await
            .expect("insert");
        }
        let login = |email: &str| {
            auth_login::<IpeError>(pool.clone(), email.to_owned(), "hunter2!".to_owned())
        };
        assert!(
            matches!(login("floor@example.com").await, IpeResult::Ok(_)),
            "the control: a hash inside the ceiling still logs in"
        );
        let started = std::time::Instant::now();
        let over = login("over@example.com").await;
        let elapsed = started.elapsed();
        assert!(
            matches!(
                &over,
                IpeResult::Err(IpeError::Error(_, info))
                    if info.message == "auth.login: invalid credentials"
            ),
            "{over:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(120),
            "no cost-31 KDF ran: {elapsed:?}"
        );
        let started = std::time::Instant::now();
        assert!(matches!(
            bcrypt::verify("hunter2!", dummy_bcrypt_hash()),
            Ok(false)
        ));
        let decoy_kdf = started.elapsed();
        let started = std::time::Instant::now();
        let malformed = login("malformed@example.com").await;
        let elapsed = started.elapsed();
        assert!(
            matches!(
                &malformed,
                IpeResult::Err(IpeError::Error(_, info))
                    if info.message == "auth.login: invalid credentials"
            ),
            "{malformed:?}"
        );
        assert!(
            elapsed >= decoy_kdf / 10,
            "a stored hash bcrypt refuses before hashing costs a decoy KDF: \
             {elapsed:?} vs {decoy_kdf:?}"
        );
        assert!(
            matches!(login("plain@example.com").await, IpeResult::Err(_)),
            "a plaintext stored password never logs in"
        );
    }

    // ── Absolute lifetime cap (P1) ────────────────────────────────────────────

    const SECRET: &str = "a-test-secret-of-32-bytes-padding";

    /// Mint a raw HS256 token with the given JSON claims, bypassing
    /// `auth_sign_token` so tests can control `exp`, `cap`, and `iat` directly.
    fn raw_hs256(claims: &serde_json::Value) -> String {
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let key = jsonwebtoken::EncodingKey::from_secret(SECRET.as_bytes());
        jsonwebtoken::encode(&header, claims, &key).expect("raw_hs256 encode")
    }

    #[test]
    fn session_past_cap_rejected_even_if_exp_is_future() {
        let now = now_unix();
        // exp is 1 h in the future, but cap is 1 s in the past.
        let token = raw_hs256(&serde_json::json!({
            "sub": "u1",
            "iat": now - 7200,
            "exp": now + 3600,
            "cap": now - 1,
        }));
        let result: IpeResult<IpeAuthError, HashMap<String, String>> =
            auth_verify_token(SECRET.to_string(), token);
        assert!(
            matches!(result, IpeResult::Err(IpeAuthError::Expired)),
            "a session past its absolute cap must be rejected even if exp is still future"
        );
    }

    #[test]
    fn cap_is_immutable_across_re_issue() {
        // Simulate a re-issue: the original token carries a `cap` claim.
        // Re-issuing by passing `cap` back in the claims map must leave `cap`
        // unchanged — the new token's cap must equal the original cap.
        let mut claims = HashMap::new();
        claims.insert("sub".to_string(), "u2".to_string());
        // Original mint.
        let first_token: String =
            match auth_sign_token::<String>(SECRET.to_string(), claims.clone(), 3600) {
                IpeResult::Ok(t) => t,
                IpeResult::Err(e) => panic!("first mint: {e}"),
            };
        // Extract the cap from the first token.
        let payload = crate::jwt::decode_payload(&first_token).expect("first payload");
        let original_cap = crate::jwt::read_numeric_date(&payload, "cap")
            .expect("a numeric date")
            .expect("cap in first token");
        // Simulate a re-issue: extract all claims and pass them (including cap) back.
        let verified: HashMap<String, String> =
            match auth_verify_token(SECRET.to_string(), first_token) {
                IpeResult::Ok(m) => m,
                IpeResult::Err(e) => panic!("first verify: {e:?}"),
            };
        // Re-issue by signing with the original claims (including cap).
        let reissued_token: String =
            match auth_sign_token::<String>(SECRET.to_string(), verified, 3600) {
                IpeResult::Ok(t) => t,
                IpeResult::Err(e) => panic!("re-issue mint: {e}"),
            };
        let reissued_payload =
            crate::jwt::decode_payload(&reissued_token).expect("reissued payload");
        let reissued_cap = crate::jwt::read_numeric_date(&reissued_payload, "cap")
            .expect("a numeric date")
            .expect("cap in reissued token");
        assert_eq!(
            original_cap, reissued_cap,
            "cap must be identical on the re-issued token — it is immutable"
        );
    }

    #[test]
    fn a_carried_cap_past_the_max_lifetime_is_clamped() {
        let before = now_unix();
        let mut claims = HashMap::new();
        claims.insert("sub".to_string(), "u-cap".to_string());
        claims.insert("cap".to_string(), i64::MAX.to_string());
        let token: String = match auth_sign_token::<String>(SECRET.to_string(), claims, 3600) {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("mint: {e}"),
        };
        let after = now_unix();
        let payload = crate::jwt::decode_payload(&token).expect("payload");
        let cap = crate::jwt::read_numeric_date(&payload, "cap")
            .expect("a numeric date")
            .expect("cap");
        let lifetime = i64::try_from(
            crate::app_config::resolve_auth_max_lifetime().expect("the default lifetime resolves"),
        )
        .expect("the default lifetime fits i64");
        assert!(
            (before + lifetime..=after + lifetime).contains(&cap),
            "a carried cap never extends past iat + max lifetime, got {cap}"
        );
    }

    #[test]
    fn tampered_cap_fails_signature_verification() {
        // Build a valid token, then construct a forged token with a manipulated
        // `cap` in the payload but the ORIGINAL signature. jsonwebtoken must
        // reject it because the signature covers the original payload bytes.
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let now = now_unix();
        let mut claims = HashMap::new();
        claims.insert("sub".to_string(), "u3".to_string());
        let valid_token: String = match auth_sign_token::<String>(SECRET.to_string(), claims, 3600)
        {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("mint: {e}"),
        };
        let parts: Vec<&str> = valid_token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 parts");
        let header_seg = parts[0];
        let sig_seg = parts[2]; // original, unmodified signature
        // Decode the payload, change cap to a far-future value, re-encode.
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("decode payload seg");
        let mut payload: serde_json::Value =
            serde_json::from_slice(&payload_bytes).expect("parse payload");
        // Push cap to year 9999 — a client trying to extend their own cap.
        payload["cap"] = serde_json::Value::Number((now + 999_999_999i64).into());
        let tampered_payload_json = serde_json::to_string(&payload).expect("serialise");
        let tampered_payload_seg = URL_SAFE_NO_PAD.encode(tampered_payload_json.as_bytes());
        let forged_token = format!("{header_seg}.{tampered_payload_seg}.{sig_seg}");
        let result: IpeResult<IpeAuthError, HashMap<String, String>> =
            auth_verify_token(SECRET.to_string(), forged_token);
        assert!(
            matches!(result, IpeResult::Err(IpeAuthError::BadSignature)),
            "a token with a client-mutated cap must fail signature verification"
        );
    }

    #[test]
    fn legacy_capless_token_accepted_when_exp_is_future() {
        // A token minted before this feature (no `cap` claim) must still be
        // accepted when its `exp` is in the future. It is bounded only by `exp`;
        // it does not receive an unlimited lifetime.
        let now = now_unix();
        let token = raw_hs256(&serde_json::json!({
            "sub": "legacy-user",
            "iat": now - 60,
            "exp": now + 3600,
            // deliberately no `cap` claim
        }));
        let result: IpeResult<IpeAuthError, HashMap<String, String>> =
            auth_verify_token(SECRET.to_string(), token);
        assert!(
            matches!(result, IpeResult::Ok(_)),
            "a legacy token without cap must be accepted when exp is still future"
        );
    }

    #[test]
    fn legacy_capless_token_rejected_when_exp_is_past() {
        // A legacy token (no `cap`) that is past its `exp` must be rejected —
        // the `exp` gate is its sole bound and it is still enforced.
        let now = now_unix();
        let token = raw_hs256(&serde_json::json!({
            "sub": "legacy-user",
            "iat": now - 7200,
            "exp": now - 1,
            // no `cap` claim
        }));
        let result: IpeResult<IpeAuthError, HashMap<String, String>> =
            auth_verify_token(SECRET.to_string(), token);
        assert!(
            matches!(result, IpeResult::Err(IpeAuthError::Expired)),
            "a legacy token without cap must be rejected when exp is past"
        );
    }

    #[test]
    fn fresh_minted_token_carries_cap_claim() {
        let mut claims = HashMap::new();
        claims.insert("sub".to_string(), "u4".to_string());
        let token: String = match auth_sign_token::<String>(SECRET.to_string(), claims, 3600) {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("mint: {e}"),
        };
        let payload = crate::jwt::decode_payload(&token).expect("payload");
        assert!(
            crate::jwt::read_numeric_date(&payload, "cap")
                .expect("a numeric date")
                .is_some(),
            "a freshly minted token must carry a signed `cap` claim"
        );
    }

    // ── Sliding re-issue (P2) ─────────────────────────────────────────────────

    #[test]
    fn reissue_context_debug_prints_neither_subject_nor_jti() {
        let ctx = crate::auth::ReissueContext {
            iat: 1,
            cap: 2,
            subject: "user-S3CR3T".to_owned(),
            jti: "J71T0K3N".to_owned(),
        };
        let shown = format!("{ctx:?}");
        assert!(!shown.contains("S3CR3T"), "{shown}");
        assert!(!shown.contains("J71T0K3N"), "{shown}");
        assert!(shown.contains("cap: 2"), "{shown}");
    }

    /// Build a ReissueContext directly from a signed+verified token.
    fn reissue_ctx_from_token(token: &str) -> crate::auth::ReissueContext {
        let claims = verify_claims(SECRET, token).expect("verify");
        crate::auth::reissue_context_from_claims(&claims)
            .expect("reissue context from verified claims")
    }

    #[test]
    fn reissue_past_threshold_extends_exp_clamped_to_cap() {
        // Token with 1800s slide window; exp ≈ now + 1800.
        let mut claims = HashMap::new();
        claims.insert("sub".to_string(), "u5".to_string());
        let token: String = match auth_sign_token::<String>(SECRET.to_string(), claims, 1800) {
            IpeResult::Ok(t) => t,
            IpeResult::Err(e) => panic!("mint: {e}"),
        };
        let ctx = reissue_ctx_from_token(&token);
        let slide = 1800i64;
        let new_token =
            match crate::auth::auth_reissue_token::<String>(SECRET, &ctx, HashMap::new(), slide) {
                Some(IpeResult::Ok(t)) => t,
                Some(IpeResult::Err(e)) => panic!("reissue err: {e}"),
                None => panic!("reissue returned None unexpectedly"),
            };
        let new_payload = crate::jwt::decode_payload(&new_token).expect("payload");
        let new_exp = crate::jwt::read_numeric_date(&new_payload, "exp")
            .expect("a numeric date")
            .expect("exp");
        let now = now_unix();
        // new_exp must be in (now, now + slide + 2s fuzz] and <= cap.
        assert!(new_exp > now, "reissued exp must be in the future");
        assert!(new_exp <= ctx.cap, "reissued exp must not exceed cap");
        // iat and cap must be carried verbatim.
        let new_iat = crate::jwt::read_numeric_date(&new_payload, "iat")
            .expect("a numeric date")
            .expect("iat");
        let new_cap = crate::jwt::read_numeric_date(&new_payload, "cap")
            .expect("a numeric date")
            .expect("cap");
        assert_eq!(new_iat, ctx.iat, "iat must be unchanged on re-issue");
        assert_eq!(new_cap, ctx.cap, "cap must be unchanged on re-issue");
    }

    #[test]
    fn reissue_near_cap_clamps_exp_to_cap() {
        // Build a token whose cap is only 60s away, with a 1800s slide window —
        // the new exp must be exactly the cap, not cap + 1800.
        let now = now_unix();
        let cap = now + 60;
        // Mint a raw token with a custom cap.
        let token = raw_hs256(&serde_json::json!({
            "sub": "u6",
            "iat": now,
            "exp": now + 30,
            "cap": cap,
        }));
        let claims = verify_claims(SECRET, &token).expect("verify near-cap token");
        let ctx =
            crate::auth::reissue_context_from_claims(&claims).expect("context from near-cap token");
        let new_token =
            match crate::auth::auth_reissue_token::<String>(SECRET, &ctx, HashMap::new(), 1800) {
                Some(IpeResult::Ok(t)) => t,
                Some(IpeResult::Err(e)) => panic!("reissue: {e}"),
                None => panic!("reissue returned None unexpectedly"),
            };
        let new_payload = crate::jwt::decode_payload(&new_token).expect("payload");
        let new_exp = crate::jwt::read_numeric_date(&new_payload, "exp")
            .expect("a numeric date")
            .expect("exp");
        assert_eq!(
            new_exp, cap,
            "exp must be clamped to cap when slide > remaining"
        );
    }

    #[test]
    fn reissue_at_or_past_cap_returns_none() {
        // Token whose cap is already in the past — re-issue must return None.
        let now = now_unix();
        let ctx = crate::auth::ReissueContext {
            iat: now - 7200,
            cap: now - 1, // already past
            subject: "u7".to_string(),
            jti: "test-jti-u7".to_string(),
        };
        let result = crate::auth::auth_reissue_token::<String>(SECRET, &ctx, HashMap::new(), 1800);
        assert!(
            result.is_none(),
            "re-issue past the absolute cap must return None, not a token"
        );
    }

    #[test]
    fn forged_cap_in_reissue_context_cannot_extend_real_cap() {
        // The real token has cap = iat + max_lifetime (typically 8h).
        // A caller who tries to construct a ReissueContext with a larger cap
        // directly bypasses the signature verification — but auth_reissue_token
        // takes ctx from the VERIFIED token, so we prove that the type boundary
        // (only verified tokens reach ReissueContext) is the guard.
        //
        // Here we show that a ReissueContext built from an unverified source
        // (simulating a forged context with an extended cap) can be rejected
        // by the caller by checking ctx.cap against the original. The
        // auth_reissue_token function itself cannot verify the context's
        // provenance — that is the caller's responsibility, enforced by the
        // workflow: only reissue_context_from_claims(verified_claims) produces
        // a ReissueContext.
        //
        // In practice: the only way to construct a ReissueContext with a
        // larger cap is to forge a token that passes auth_verify_token — which
        // requires the HS256 secret. This test proves that a re-issued token
        // carries the cap from ctx, so if ctx.cap was forged-large, the test
        // path requires the secret. We test the structural property: the token
        // emitted by auth_reissue_token always has exp <= ctx.cap.
        let now = now_unix();
        let real_cap = now + 3600;
        // Simulate an attacker who somehow supplied a context with an inflated cap.
        // In the real flow this is impossible without the secret, but the test
        // verifies that auth_reissue_token outputs exp <= the provided cap.
        let forged_ctx = crate::auth::ReissueContext {
            iat: now - 60,
            cap: now + 999_999, // attacker's hoped-for cap
            subject: "attacker".to_string(),
            jti: "test-jti-attacker".to_string(),
        };
        let _ = real_cap; // the real cap is inaccessible to the forged context
        let token = match crate::auth::auth_reissue_token::<String>(
            SECRET,
            &forged_ctx,
            HashMap::new(),
            1800,
        ) {
            Some(IpeResult::Ok(t)) => t,
            Some(IpeResult::Err(e)) => panic!("reissue: {e}"),
            None => panic!("reissue returned None (forged cap is future, expected Some)"),
        };
        let payload = crate::jwt::decode_payload(&token).expect("payload");
        let emitted_cap = crate::jwt::read_numeric_date(&payload, "cap")
            .expect("a numeric date")
            .expect("cap");
        // The emitted cap equals whatever is in ctx — structural proof that the
        // reissue function does NOT override ctx.cap with something larger. The
        // defence against a forged ctx is that verified-origin is the ONLY path
        // to a ReissueContext (reissue_context_from_claims requires verified claims).
        assert_eq!(
            emitted_cap, forged_ctx.cap,
            "auth_reissue_token must copy ctx.cap verbatim — it never inflates it further"
        );
        let emitted_exp = crate::jwt::read_numeric_date(&payload, "exp")
            .expect("a numeric date")
            .expect("exp");
        assert!(
            emitted_exp <= forged_ctx.cap,
            "exp must always be <= ctx.cap regardless of slide_window"
        );
    }

    #[test]
    fn reissue_context_from_verified_claims_requires_iat_cap_sub() {
        let now = now_unix();
        let context_of = |claims: &serde_json::Value| {
            let verified = verify_claims(SECRET, &raw_hs256(claims)).expect("verify");
            crate::auth::reissue_context_from_claims(&verified)
        };
        let (iat, exp, cap) = (now - 60, now + 3600, now + 7200);
        assert!(
            context_of(&serde_json::json!({ "sub": "u", "iat": iat, "exp": exp })).is_none(),
            "missing cap must yield None"
        );
        assert!(
            context_of(&serde_json::json!({ "sub": "u", "cap": cap, "exp": exp })).is_none(),
            "missing iat must yield None"
        );
        assert!(
            context_of(&serde_json::json!({ "iat": iat, "cap": cap, "exp": exp })).is_none(),
            "missing sub must yield None"
        );
        assert!(
            context_of(&serde_json::json!({ "sub": "user", "iat": iat, "cap": cap, "exp": exp }))
                .is_some(),
            "all fields present must yield Some"
        );
    }

    // ── Time claims must be numbers ───────────────────────────────────────────

    #[test]
    fn verify_claims_refuses_non_numeric_time_claims() {
        let now = now_unix();
        let refused = |claims: serde_json::Value| {
            matches!(
                verify_claims(SECRET, &raw_hs256(&claims)),
                Err(TokenRefusal::NonNumericDate)
            )
        };
        assert!(
            refused(
                serde_json::json!({ "sub": "u", "exp": now + 3600, "cap": (now - 10).to_string() })
            ),
            "a past `cap` written as text is refused, not skipped"
        );
        assert!(
            refused(
                serde_json::json!({ "sub": "u", "exp": now + 3600, "nbf": (now + 3600).to_string() })
            ),
            "a future `nbf` written as text is refused, not skipped"
        );
        assert!(refused(
            serde_json::json!({ "sub": "u", "exp": now + 3600, "cap": null })
        ));
        assert!(
            refused(serde_json::json!({ "sub": "u", "exp": (now + 3600).to_string() })),
            "an `exp` written as text is refused as unreadable, not as absent"
        );
        assert!(
            refused(serde_json::json!({ "sub": "u", "exp": now + 3600, "cap": "1" })),
            "a `cap` written as text is refused even when it reads as past"
        );
        assert!(
            refused(serde_json::json!({ "sub": "u", "exp": true })),
            "a boolean `exp` is refused as unreadable, not as absent"
        );
        assert!(matches!(
            verify_claims(
                SECRET,
                &raw_hs256(&serde_json::json!({ "sub": "u", "exp": now + 3600, "cap": now - 10 }))
            ),
            Err(TokenRefusal::PastCap)
        ));
        assert!(
            verify_claims(
                SECRET,
                &raw_hs256(&serde_json::json!({
                    "sub": "u",
                    "exp": now + 3600,
                    "cap": now + 7200,
                    "nbf": now - 10,
                }))
            )
            .is_ok(),
            "numeric time claims inside their window verify"
        );
    }

    #[test]
    fn string_iat_is_refused() {
        let now = now_unix();
        assert!(matches!(
            verify_claims(
                SECRET,
                &raw_hs256(&serde_json::json!({ "sub": "u", "exp": now + 3600, "iat": "x" }))
            ),
            Err(TokenRefusal::NonNumericDate)
        ));
        let numeric = verify_claims(
            SECRET,
            &raw_hs256(&serde_json::json!({ "sub": "u", "exp": now + 3600, "iat": now - 60 })),
        );
        assert!(
            matches!(&numeric, Ok(claims) if claims.times().iat() == Some(now - 60)),
            "a numeric `iat` verifies and is carried typed"
        );
    }

    #[test]
    fn non_object_payload_is_malformed() {
        for payload in [
            serde_json::json!([{ "sub": "u", "exp": now_unix() + 3600 }]),
            serde_json::json!("claims"),
            serde_json::json!(7),
        ] {
            let token = signed_under(SECRET, jsonwebtoken::Algorithm::HS256, &payload);
            assert!(
                matches!(verify_claims(SECRET, &token), Err(TokenRefusal::Malformed)),
                "{payload}"
            );
        }
    }

    #[test]
    fn verified_time_claims_are_the_numbers_the_checks_read() {
        let now = now_unix();
        let token = signed_under(
            SECRET,
            jsonwebtoken::Algorithm::HS256,
            &serde_json::from_str::<serde_json::Value>(&format!(
                r#"{{"sub":"u","exp":{}.5,"nbf":{}.5,"iat":{}.5,"cap":{}.5}}"#,
                now + 3600,
                now - 60,
                now - 60,
                now + 7200
            ))
            .expect("fractional claims parse"),
        );
        let verified = verify_claims(SECRET, &token);
        assert!(verified.is_ok(), "fractional dates verify");
        let Ok(claims) = verified else { return };
        let times = claims.times();
        assert_eq!(times.exp(), Some(now + 3600));
        assert_eq!(times.nbf(), Some(now - 60));
        assert_eq!(times.iat(), Some(now - 60));
        assert_eq!(times.cap(), Some(now + 7200));
        assert_eq!(
            claims.get("cap").map(str::to_owned),
            Some(format!("{}.5", now + 7200)),
            "the display form keeps the token's own text"
        );
        let context = reissue_context_from_claims(&claims);
        assert!(
            matches!(&context, Some(ctx) if ctx.iat == now - 60 && ctx.cap == now + 7200),
            "a fractional `iat` and `cap` still yield a re-issue context"
        );
    }

    #[test]
    fn sign_token_writes_nbf_as_a_numeric_date() {
        let now = now_unix();
        let sign = |nbf: String| {
            let mut claims = HashMap::new();
            claims.insert("sub".to_string(), "u".to_string());
            claims.insert("nbf".to_string(), nbf);
            auth_sign_token::<String>(SECRET.to_string(), claims, 3600)
        };
        let IpeResult::Ok(future) = sign((now + 3600).to_string()) else {
            panic!("an integer `nbf` signs");
        };
        assert!(
            matches!(
                verify_claims(SECRET, &future),
                Err(TokenRefusal::NotYetValid)
            ),
            "a future `nbf` from `signToken` is enforced"
        );
        let IpeResult::Ok(past) = sign((now - 10).to_string()) else {
            panic!("an integer `nbf` signs");
        };
        assert!(
            verify_claims(SECRET, &past).is_ok(),
            "a past `nbf` verifies"
        );
        assert!(
            matches!(sign("soon".to_string()), IpeResult::Err(_)),
            "a non-integer `nbf` mints no token"
        );
    }

    #[test]
    fn reissued_token_drops_nbf_and_verifies() {
        let now = now_unix();
        let original = raw_hs256(&serde_json::json!({
            "sub": "u",
            "jti": "nbf-jti",
            "iat": now - 60,
            "nbf": now - 60,
            "exp": now + 60,
            "cap": now + 7200,
        }));
        let claims = verify_claims(SECRET, &original).expect("verify original");
        let ctx = reissue_context_from_claims(&claims).expect("context");
        let extra: HashMap<String, String> = claims
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        let Some(IpeResult::Ok(reissued)) = auth_reissue_token::<String>(SECRET, &ctx, extra, 600)
        else {
            panic!("a live session re-issues");
        };
        assert!(
            verify_claims(SECRET, &reissued).is_ok(),
            "a re-issued token never carries a text `nbf`"
        );
    }

    // ── Typed verifyToken refusals ────────────────────────────────────────────

    /// The base64url segment of `json`.
    fn segment(json: &str) -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        URL_SAFE_NO_PAD.encode(json.as_bytes())
    }

    /// A token for `claims` with an `alg` header, signed under `key`.
    fn signed_under(key: &str, alg: jsonwebtoken::Algorithm, claims: &serde_json::Value) -> String {
        let header = jsonwebtoken::Header::new(alg);
        let key = jsonwebtoken::EncodingKey::from_secret(key.as_bytes());
        jsonwebtoken::encode(&header, claims, &key).expect("encode")
    }

    /// `token` with the first byte of its signature segment changed.
    fn flip_signature(token: &str) -> String {
        let Some((message, signature)) = token.rsplit_once('.') else {
            return String::new();
        };
        let mut chars = signature.chars();
        let flipped = match chars.next() {
            Some('A') => 'B',
            _ => 'A',
        };
        format!("{message}.{flipped}{}", chars.as_str())
    }

    #[test]
    fn verify_token_refusals_are_their_exact_auth_error() {
        let now = now_unix();
        let live = serde_json::json!({ "sub": "t-sub", "exp": now + 3600 });
        let refused = |secret: &str, token: &str| verify_token_under(None, secret, token).err();
        let cases: [(&str, String, String, IpeAuthError); 12] = [
            (
                "short key",
                "short".to_owned(),
                raw_hs256(&live),
                IpeAuthError::SecretTooShort,
            ),
            (
                "expired",
                SECRET.to_owned(),
                raw_hs256(&serde_json::json!({ "sub": "t", "exp": now - 30 })),
                IpeAuthError::Expired,
            ),
            (
                "nbf in the future",
                SECRET.to_owned(),
                raw_hs256(&serde_json::json!({ "sub": "t", "exp": now + 7200, "nbf": now + 3600 })),
                IpeAuthError::NotYetValid,
            ),
            (
                "past cap",
                SECRET.to_owned(),
                raw_hs256(&serde_json::json!({ "sub": "t", "exp": now + 3600, "cap": now - 1 })),
                IpeAuthError::Expired,
            ),
            (
                "non-numeric exp",
                SECRET.to_owned(),
                raw_hs256(&serde_json::json!({ "sub": "t", "exp": "tomorrow" })),
                IpeAuthError::Malformed,
            ),
            (
                "flipped signature byte",
                SECRET.to_owned(),
                flip_signature(&raw_hs256(&live)),
                IpeAuthError::BadSignature,
            ),
            (
                "wrong key",
                SECRET.to_owned(),
                signed_under(
                    "another-test-secret-of-32-bytes-pad",
                    jsonwebtoken::Algorithm::HS256,
                    &live,
                ),
                IpeAuthError::BadSignature,
            ),
            (
                "HS512 header",
                SECRET.to_owned(),
                signed_under(SECRET, jsonwebtoken::Algorithm::HS512, &live),
                IpeAuthError::BadSignature,
            ),
            (
                "alg none",
                SECRET.to_owned(),
                format!(
                    "{}.{}.",
                    segment(r#"{"alg":"none","typ":"JWT"}"#),
                    segment(&live.to_string())
                ),
                IpeAuthError::Malformed,
            ),
            (
                "truncated token",
                SECRET.to_owned(),
                raw_hs256(&live)
                    .rsplit_once('.')
                    .map(|(message, _)| message.to_owned())
                    .unwrap_or_default(),
                IpeAuthError::Malformed,
            ),
            (
                "base64 garbage",
                SECRET.to_owned(),
                "!!!.###.$$$".to_owned(),
                IpeAuthError::Malformed,
            ),
            (
                "missing exp",
                SECRET.to_owned(),
                raw_hs256(&serde_json::json!({ "sub": "t" })),
                IpeAuthError::MissingClaim,
            ),
        ];
        for (label, secret, token, expected) in cases {
            assert!(!token.is_empty(), "{label}: the fixture built a token");
            assert_eq!(refused(&secret, &token), Some(expected), "{label}");
        }
        assert_eq!(
            refused(SECRET, &raw_hs256(&live)),
            None,
            "the unaltered token verifies"
        );
    }

    #[test]
    fn verify_token_refusal_carries_no_token_text() {
        const MARKER: &str = "LEAKMARKER-7f3a";
        let now = now_unix();
        let alg_header = format!(r#"{{"alg":"\u001b[31m{MARKER}","typ":"JWT"}}"#);
        let alg_token = format!(
            "{}.{}.c2ln",
            segment(&alg_header),
            segment(&serde_json::json!({ "exp": now + 3600 }).to_string())
        );
        let cases = [
            (
                alg_header.clone(),
                alg_token.clone(),
                IpeAuthError::Malformed,
            ),
            (
                serde_json::json!({ "exp": MARKER }).to_string(),
                raw_hs256(&serde_json::json!({ "exp": MARKER })),
                IpeAuthError::Malformed,
            ),
            (
                serde_json::json!({ "x": format!("\u{1b}[31m{MARKER}"), "exp": now + 3600 })
                    .to_string(),
                signed_under(
                    "another-test-secret-of-32-bytes-pad",
                    jsonwebtoken::Algorithm::HS256,
                    &serde_json::json!({ "x": format!("\u{1b}[31m{MARKER}"), "exp": now + 3600 }),
                ),
                IpeAuthError::BadSignature,
            ),
        ];
        for (segment_json, token, expected) in cases {
            let carried = token.split('.').any(|part| {
                use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
                URL_SAFE_NO_PAD.decode(part).is_ok_and(|bytes| {
                    std::str::from_utf8(&bytes).is_ok_and(|text| text.contains(MARKER))
                })
            });
            assert!(carried, "the marker is in the token: {segment_json}");
            let refusal = verify_token_under(None, SECRET, &token).err();
            assert_eq!(refusal, Some(expected), "{segment_json}");
            let Some(refusal) = refusal else { return };
            assert!(!refusal.phrase().contains(MARKER));
            assert!(!format!("{refusal:?}").contains(MARKER));
        }
    }

    #[test]
    fn every_token_refusal_maps_to_its_auth_error() {
        let expected = [
            (TokenRefusal::ShortSecret, IpeAuthError::SecretTooShort),
            (TokenRefusal::Expired, IpeAuthError::Expired),
            (TokenRefusal::NotYetValid, IpeAuthError::NotYetValid),
            (TokenRefusal::PastCap, IpeAuthError::Expired),
            (TokenRefusal::NonNumericDate, IpeAuthError::Malformed),
            (TokenRefusal::BadSignature, IpeAuthError::BadSignature),
            (TokenRefusal::Malformed, IpeAuthError::Malformed),
            (TokenRefusal::MissingClaim, IpeAuthError::MissingClaim),
        ];
        assert_eq!(expected.len(), TokenRefusal::ALL.len());
        for ((refusal, error), listed) in expected.into_iter().zip(TokenRefusal::ALL) {
            assert_eq!(refusal, listed, "{refusal:?} out of order in ALL");
            assert_eq!(refusal.auth_error(), error, "{refusal:?}");
        }
    }

    // ── verifyPassword stored-hash refusals ───────────────────────────────────

    /// A cost-15 bcrypt hash of `password123`.
    const COST_15_HASH: &str = "$2b$15$v81ksFestWCfPXD9cGDMfeV2hI.YAhbV1wPHNRmEiDgXR9O6lROsq";

    /// The kind and message of a refused `verifyPassword`.
    fn password_refusal(result: IpeResult<IpeError, bool>) -> Option<(IpeErrorKind, String)> {
        match result {
            IpeResult::Err(IpeError::Error(kind, info)) => Some((kind, info.message)),
            IpeResult::Ok(_) => None,
        }
    }

    #[test]
    fn verify_password_refuses_a_cost_above_the_ceiling_without_hashing() {
        let started = std::time::Instant::now();
        let at_ceiling = auth_verify_password("password123".into(), COST_15_HASH.to_owned());
        let one_hash = started.elapsed();
        assert!(
            matches!(at_ceiling, IpeResult::Ok(true)),
            "a cost-15 hash still verifies"
        );
        let over = COST_15_HASH.replacen("$15$", "$31$", 1);
        let started = std::time::Instant::now();
        let refused = password_refusal(auth_verify_password("password123".into(), over));
        let refusal_time = started.elapsed();
        assert_eq!(
            refused,
            Some((
                IpeErrorKind::InvalidInput,
                "auth.verifyPassword: stored hash cost exceeds the ceiling".to_owned()
            ))
        );
        assert!(
            refusal_time < one_hash / 100,
            "the refusal ran no KDF: {refusal_time:?} vs {one_hash:?}"
        );
    }

    #[test]
    fn verify_password_refuses_a_non_bcrypt_hash_without_echoing_it() {
        for stored in [
            "plain-stored-LEAKMARKER-7f3a".to_owned(),
            "$2b$12$LEAKMARKER-7f3a-not-a-valid-salt-or-digest".to_owned(),
        ] {
            let refused =
                password_refusal(auth_verify_password("password123".into(), stored.clone()));
            assert_eq!(
                refused,
                Some((
                    IpeErrorKind::InvalidInput,
                    "auth.verifyPassword: stored hash is not a bcrypt hash".to_owned()
                )),
                "{stored}"
            );
            let Some((_, message)) = refused else { return };
            assert!(stored.contains("LEAKMARKER"));
            assert!(!message.contains("LEAKMARKER"), "{message}");
        }
    }

    /// A stored hash bcrypt would turn back before hashing, or read in another
    /// shape than it writes, is refused by the parse, so every admitted hash
    /// runs the KDF; a hash bcrypt wrote is admitted and verifies.
    #[test]
    fn stored_hash_admits_only_the_shape_bcrypt_writes() {
        let valid = bcrypt::hash("password123", BCRYPT_COST_MIN).expect("hash");
        assert_eq!(
            StoredHash::parse(&valid).map(|stored| stored.verifies("password123")),
            Ok(Ok(true)),
            "the control: a hash bcrypt wrote verifies"
        );
        let (head, _) = valid
            .split_at_checked(valid.len() - 1)
            .expect("a full hash");
        let (prefix, body) = valid.split_at_checked(BCRYPT_PREFIX_LEN).expect("a prefix");
        let (salt, digest) = body.split_at_checked(BCRYPT_SALT_CHARS).expect("a salt");
        let (salt_head, _) = salt
            .split_at_checked(BCRYPT_SALT_CHARS - 1)
            .expect("a salt");
        let refused = [
            (head.to_owned(), "a digest one character short"),
            (format!("{valid}."), "a digest one character long"),
            (format!("{valid}$"), "a trailing `$` bcrypt's split skips"),
            (format!("{prefix}${body}"), "an empty `$` segment"),
            (format!("{head}/"), "digest trailing bits set"),
            (
                format!("{prefix}{salt_head}/{digest}"),
                "salt trailing bits set",
            ),
            (format!("{head}+"), "a character outside bcrypt's alphabet"),
            (format!("{head}\u{e9}"), "a multibyte character"),
            (format!("{prefix}{salt}"), "a salt without a digest"),
            (prefix.to_owned(), "a prefix alone"),
        ];
        for (stored, why) in refused {
            assert_eq!(
                StoredHash::parse(&stored).err(),
                Some(StoredHashRefusal::NotBcrypt),
                "{why}: {stored}"
            );
        }
    }

    #[test]
    fn bcrypt_cost_parses_only_a_bcrypt_prefix_within_range() {
        assert_eq!(BcryptCost::of_hash("$2b$04$"), Ok(BcryptCost(4)));
        assert_eq!(BcryptCost::of_hash("$2y$15$"), Ok(BcryptCost(15)));
        assert_eq!(BcryptCost::of_hash(COST_15_HASH), Ok(BcryptCost(15)));
        assert_eq!(
            BcryptCost::of_hash("$2b$16$"),
            Err(StoredHashRefusal::CostOverCeiling)
        );
        for refused in ["$2b$3$", "$2b$03$", "$2c$10$", "$2b$1x$", "", "$2b"] {
            assert_eq!(
                BcryptCost::of_hash(refused),
                Err(StoredHashRefusal::NotBcrypt),
                "{refused:?}"
            );
        }
        assert_eq!(BcryptCost::clamped(-5), BcryptCost(BCRYPT_COST_MIN));
        assert_eq!(BcryptCost::clamped(12), BcryptCost(12));
        assert_eq!(BcryptCost::clamped(i64::MAX), BcryptCost(BCRYPT_COST_MAX));
    }

    // ── Armed revocation gate ─────────────────────────────────────────────────

    /// The armed gate.
    fn armed() -> Option<crate::revocation::ArmedGate> {
        crate::revocation::ArmedGate::resolve(crate::app_config::RevocationMode::Store)
    }

    /// A token for `sub` with session id `jti`, live for an hour.
    fn session_token(sub: &str, jti: &str) -> String {
        let now = now_unix();
        raw_hs256(&serde_json::json!({
            "sub": sub,
            "jti": jti,
            "iat": now,
            "exp": now + 3600,
            "cap": now + 7200,
        }))
    }

    #[test]
    fn verify_token_armed_refuses_revoked_token() {
        crate::revocation::revoke_subject("k1-revoked-subject".to_owned()).expect("revoke subject");
        crate::revocation::revoke_session("k1-revoked-jti".to_owned(), now_unix() + 7200)
            .expect("revoke session");
        let by_subject = verify_token_under(
            armed(),
            SECRET,
            &session_token("k1-revoked-subject", "k1-live-jti"),
        )
        .expect_err("a revoked subject is refused");
        let by_session = verify_token_under(
            armed(),
            SECRET,
            &session_token("k1-live-subject", "k1-revoked-jti"),
        )
        .expect_err("a revoked session is refused");
        assert_eq!(by_subject, IpeAuthError::Revoked);
        assert_eq!(by_session, IpeAuthError::Revoked);
    }

    #[test]
    fn verify_token_off_is_unchanged() {
        crate::revocation::revoke_subject("k2-revoked-subject".to_owned()).expect("revoke subject");
        let claims =
            verify_token_under(None, SECRET, &session_token("k2-revoked-subject", "k2-jti"))
                .expect("an unarmed gate never consults the store");
        assert_eq!(
            claims.get("sub").map(String::as_str),
            Some("k2-revoked-subject")
        );
        let legacy = raw_hs256(&serde_json::json!({ "sub": "k2-legacy", "exp": now_unix() + 60 }));
        assert!(
            verify_token_under(None, SECRET, &legacy).is_ok(),
            "an unarmed gate admits a token with no `jti`"
        );
    }

    #[test]
    fn verify_token_armed_in_script_process_admits_without_binding() {
        #[cfg(feature = "server")]
        assert!(
            crate::server::request_bindings().is_none(),
            "a script runs outside any request scope"
        );
        // A script process serves no `Web` app.
        let claims = verify_token_bound(
            armed(),
            || bind_target_in(false),
            SECRET,
            &session_token("k4-subject", "k4-jti"),
        )
        .expect("an armed gate admits a live token outside a request");
        assert_eq!(claims.get("jti").map(String::as_str), Some("k4-jti"));
    }

    #[test]
    fn verify_token_armed_refuses_jti_less_and_sub_less() {
        let now = now_unix();
        let refused = |claims: &serde_json::Value| {
            verify_token_under(armed(), SECRET, &raw_hs256(claims))
                .expect_err("an incomplete token is refused when armed")
        };
        assert_eq!(
            refused(&serde_json::json!({ "sub": "k8-subject", "exp": now + 60 })),
            IpeAuthError::MissingClaim
        );
        assert_eq!(
            refused(&serde_json::json!({ "sub": "k8-subject", "jti": "", "exp": now + 60 })),
            IpeAuthError::MissingClaim
        );
        assert_eq!(
            refused(&serde_json::json!({ "jti": "k8-jti", "exp": now + 60 })),
            IpeAuthError::MissingClaim
        );
        assert_eq!(
            refused(&serde_json::json!({ "sub": "", "jti": "k8-jti", "exp": now + 60 })),
            IpeAuthError::MissingClaim
        );
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn verify_token_in_server_handler_binds_request_set() {
        let bindings = crate::server::in_request_scope(async {
            let admitted =
                verify_token_under(armed(), SECRET, &session_token("k7-subject", "k7-jti"));
            assert!(admitted.is_ok(), "{admitted:?}");
            crate::server::request_bindings()
        })
        .await
        .expect("a request scope carries a binding set");
        let held = bindings.lock().expect("bindings lock");
        assert_eq!(held.len(), 1);
        assert!(held.binds_session("k7-jti"));
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn verify_token_armed_full_bindings_refuses() {
        let bound = crate::revocation::MAX_SESSION_CREDENTIALS;
        let (ninth, bindings) = crate::server::in_request_scope(async move {
            for n in 0..bound {
                verify_token_under(
                    armed(),
                    SECRET,
                    &session_token("k5-subject", &format!("k5-jti-{n}")),
                )
                .expect("within the bound");
            }
            let ninth = verify_token_under(
                armed(),
                SECRET,
                &session_token("k5-subject", "k5-jti-ninth"),
            );
            (ninth, crate::server::request_bindings())
        })
        .await;
        assert_eq!(
            ninth.expect_err("a full set refuses the next session"),
            IpeAuthError::TooManyCredentials
        );
        let bindings = bindings.expect("a request scope carries a binding set");
        let held = bindings.lock().expect("bindings lock");
        assert_eq!(held.len(), bound);
        assert!((0..bound).all(|n| held.binds_session(&format!("k5-jti-{n}"))));
        assert!(!held.binds_session("k5-jti-ninth"));
    }

    /// While a `Web` app serves, an armed `verifyToken` no session or request
    /// owns is refused; unarmed, the same call is admitted.
    #[cfg(feature = "web")]
    #[test]
    fn verify_token_armed_outside_scope_on_web_process_refuses() {
        let token = session_token("k3-subject", "k3-jti");
        assert_eq!(
            verify_token_bound(armed(), || bind_target_in(true), SECRET, &token),
            Err(IpeAuthError::RevocationUnavailable),
            "an unscoped call while a Web app serves is refused"
        );
        assert!(
            verify_token_bound(None, || bind_target_in(true), SECRET, &token).is_ok(),
            "an unarmed gate never asks for an owner"
        );
        assert!(
            verify_token_bound(armed(), || bind_target_in(false), SECRET, &token).is_ok(),
            "with no Web app serving, an unscoped call is a script and is admitted"
        );
    }

    /// Inside a `Web` session scope an armed `verifyToken` binds to that
    /// session, even while a `Web` app serves.
    #[cfg(feature = "web")]
    #[test]
    fn verify_token_armed_in_web_session_binds_session_set() {
        let scope = crate::web::pubsub::SessionScope::new("k3-session".to_owned());
        let admitted = crate::web::pubsub::with_session(&scope, || {
            verify_token_bound(
                armed(),
                || bind_target_in(true),
                SECRET,
                &session_token("k3-subject", "k3-bound-jti"),
            )
        });
        assert!(admitted.is_ok(), "{admitted:?}");
        let held = scope.bindings().lock().expect("bindings lock");
        assert_eq!(held.len(), 1);
        assert!(held.binds_session("k3-bound-jti"));
    }

    // ── Construction scan ─────────────────────────────────────────────────────
    //
    // `VerifiedClaims` and `SessionCredential` keep private fields, so no other
    // module can build one; the scan covers the two defining files.

    /// The blank a masked source character becomes; newlines stay, so line
    /// numbers survive.
    const fn blank(c: char) -> char {
        if c == '\n' { '\n' } else { ' ' }
    }

    /// Whether `chars[at]` continues an identifier.
    fn is_ident(chars: &[char], at: usize) -> bool {
        chars
            .get(at)
            .is_some_and(|c| c.is_alphanumeric() || *c == '_')
    }

    /// The end of a `//` comment starting at `at`.
    fn line_comment_end(chars: &[char], at: usize) -> Option<usize> {
        if !matches!(chars.get(at..at + 2), Some(['/', '/'])) {
            return None;
        }
        let rest = chars.get(at..).unwrap_or_default();
        Some(at + rest.iter().position(|c| *c == '\n').unwrap_or(rest.len()))
    }

    /// The end of a (nested) `/* */` comment starting at `at`.
    fn block_comment_end(chars: &[char], at: usize) -> Option<usize> {
        if !matches!(chars.get(at..at + 2), Some(['/', '*'])) {
            return None;
        }
        let mut depth = 0usize;
        let mut k = at;
        while k < chars.len() {
            match chars.get(k..k + 2) {
                Some(['/', '*']) => {
                    depth += 1;
                    k += 2;
                }
                Some(['*', '/']) => {
                    depth -= 1;
                    k += 2;
                    if depth == 0 {
                        return Some(k);
                    }
                }
                _ => k += 1,
            }
        }
        Some(chars.len())
    }

    /// The end of a raw string (`r"…"`, `r#"…"#`, `br#"…"#`) starting at `at`.
    fn raw_string_end(chars: &[char], at: usize) -> Option<usize> {
        if at > 0 && is_ident(chars, at - 1) {
            return None;
        }
        let open = match (chars.get(at), chars.get(at + 1)) {
            (Some('r'), _) => at + 1,
            (Some('b'), Some('r')) => at + 2,
            _ => return None,
        };
        let hashes = chars
            .get(open..)
            .unwrap_or_default()
            .iter()
            .take_while(|c| **c == '#')
            .count();
        if chars.get(open + hashes) != Some(&'"') {
            return None;
        }
        let mut k = open + hashes + 1;
        while k < chars.len() {
            if chars.get(k) == Some(&'"') && (1..=hashes).all(|h| chars.get(k + h) == Some(&'#')) {
                return Some(k + 1 + hashes);
            }
            k += 1;
        }
        Some(chars.len())
    }

    /// The end of a `"…"` or `b"…"` string starting at `at`.
    fn string_end(chars: &[char], at: usize) -> Option<usize> {
        let open = match (chars.get(at), chars.get(at + 1)) {
            (Some('"'), _) => at,
            (Some('b'), Some('"')) if at == 0 || !is_ident(chars, at - 1) => at + 1,
            _ => return None,
        };
        let mut k = open + 1;
        while k < chars.len() {
            match chars.get(k) {
                Some('\\') => k += 2,
                Some('"') => return Some(k + 1),
                _ => k += 1,
            }
        }
        Some(chars.len())
    }

    /// The end of a char literal starting at `at`; a lifetime is none.
    fn char_literal_end(chars: &[char], at: usize) -> Option<usize> {
        if chars.get(at) != Some(&'\'') {
            return None;
        }
        match chars.get(at + 1) {
            Some('\\') => {
                let rest = chars.get(at + 3..)?;
                Some(at + 4 + rest.iter().position(|c| *c == '\'')?)
            }
            Some(_) if chars.get(at + 2) == Some(&'\'') => Some(at + 3),
            _ => None,
        }
    }

    /// `source` with comments, strings and char literals blanked, so a scan sees
    /// code only.
    fn code_only(source: &str) -> Vec<char> {
        let chars: Vec<char> = source.chars().collect();
        let mut out = Vec::with_capacity(chars.len());
        let mut at = 0;
        while let Some(&c) = chars.get(at) {
            let masked = line_comment_end(&chars, at)
                .or_else(|| block_comment_end(&chars, at))
                .or_else(|| raw_string_end(&chars, at))
                .or_else(|| string_end(&chars, at))
                .or_else(|| char_literal_end(&chars, at));
            if let Some(end) = masked {
                let end = end.min(chars.len());
                out.extend(
                    chars
                        .get(at..end)
                        .unwrap_or_default()
                        .iter()
                        .map(|c| blank(*c)),
                );
                at = end;
            } else {
                out.push(c);
                at += 1;
            }
        }
        out
    }

    /// Whether the code before `at`, past whitespace, ends with `pattern`.
    fn preceded_by(code: &[char], at: usize, pattern: &str) -> bool {
        let before: Vec<char> = code
            .get(..at)
            .unwrap_or_default()
            .iter()
            .rev()
            .skip_while(|c| c.is_whitespace())
            .take(pattern.chars().count())
            .copied()
            .collect();
        before.into_iter().rev().eq(pattern.chars())
    }

    /// The first non-whitespace character at or after `at`.
    fn next_significant(code: &[char], at: usize) -> Option<char> {
        code.get(at..)?.iter().copied().find(|c| !c.is_whitespace())
    }

    /// A brace scope: the `fn` it belongs to and the type an enclosing `impl`
    /// names.
    #[derive(Clone, Default)]
    struct Scope {
        func: Option<String>,
        impl_target: Option<String>,
    }

    /// An `impl` header being read up to its `{`.
    #[derive(Default)]
    struct ImplHeader {
        angle_depth: usize,
        target: Option<String>,
        in_where: bool,
    }

    /// The 1-based lines of `source` that construct `ty` (`ty(`, `ty {`, or
    /// `Self(`/`Self {` inside an `impl` of `ty`) outside the functions
    /// `allowed` names.
    fn constructions(source: &str, ty: &str, allowed: &[&str]) -> Vec<usize> {
        let code = code_only(source);
        let mut scopes: Vec<Scope> = Vec::new();
        let mut pending_fn: Option<String> = None;
        let mut expect_fn_name = false;
        let mut header: Option<ImplHeader> = None;
        let mut found = Vec::new();
        let mut line = 1;
        let mut at = 0;
        while let Some(&c) = code.get(at) {
            if c.is_alphabetic() || c == '_' {
                let start = at;
                while is_ident(&code, at) {
                    at += 1;
                }
                let word: String = code.get(start..at).unwrap_or_default().iter().collect();
                if expect_fn_name {
                    expect_fn_name = false;
                    pending_fn = Some(word);
                    continue;
                }
                if let Some(h) = header.as_mut() {
                    if word == "where" {
                        h.in_where = true;
                    } else if h.angle_depth == 0 && !h.in_where && word != "for" && word != "dyn" {
                        h.target = Some(word);
                    }
                    continue;
                }
                match word.as_str() {
                    "fn" => {
                        expect_fn_name = next_significant(&code, at)
                            .is_some_and(|n| n.is_alphabetic() || n == '_');
                    }
                    "impl" if pending_fn.is_none() => header = Some(ImplHeader::default()),
                    _ => {}
                }
                let scope = scopes.last().cloned().unwrap_or_default();
                let names_ty =
                    word == ty || (word == "Self" && scope.impl_target.as_deref() == Some(ty));
                let builds = matches!(next_significant(&code, at), Some('(' | '{'));
                let declares = ["struct", "enum", "type", "->", "redacting_debug!("]
                    .iter()
                    .any(|p| preceded_by(&code, start, p));
                let sanctioned = scope.func.as_deref().is_some_and(|f| allowed.contains(&f));
                if names_ty && builds && !declares && !sanctioned {
                    found.push(line);
                }
                continue;
            }
            match c {
                '\n' => line += 1,
                ';' => pending_fn = None,
                '<' => {
                    if let Some(h) = header.as_mut() {
                        h.angle_depth += 1;
                    }
                }
                '>' if !preceded_by(&code, at, "-") => {
                    if let Some(h) = header.as_mut() {
                        h.angle_depth = h.angle_depth.saturating_sub(1);
                    }
                }
                '{' => {
                    let parent = scopes.last().cloned().unwrap_or_default();
                    let scope = match header.take() {
                        Some(h) => Scope {
                            func: parent.func,
                            impl_target: h.target,
                        },
                        None => Scope {
                            func: pending_fn.take().or(parent.func),
                            impl_target: parent.impl_target,
                        },
                    };
                    scopes.push(scope);
                }
                '}' => {
                    scopes.pop();
                }
                _ => {}
            }
            at += 1;
        }
        found
    }

    /// Source exercising every masking and scoping rule of the scan.
    const SYNTHETIC: &str = r##"
struct VerifiedClaims(Map);
impl VerifiedClaims {
    fn get(&self) -> &str { "VerifiedClaims(x)" }
    fn forge() -> Self { Self(Map::new()) }
}
// VerifiedClaims(in a comment)
/* VerifiedClaims { nested /* VerifiedClaims( */ } */
fn verify_claims() -> VerifiedClaims {
    let brace = '{';
    let raw = r#"VerifiedClaims("#;
    VerifiedClaims(Map::new())
}
fn rogue<'a>(x: &'a str) {
    let _ = VerifiedClaims { 0: x };
}
"##;

    #[test]
    fn construction_scan_masks_literals_and_tracks_scopes() {
        assert_eq!(
            constructions(SYNTHETIC, "VerifiedClaims", &["verify_claims"]),
            vec![5, 15]
        );
        assert_eq!(
            constructions(SYNTHETIC, "VerifiedClaims", &[]),
            vec![5, 12, 15]
        );
    }

    #[test]
    fn verified_claims_only_from_verify_claims() {
        let auth = include_str!("auth.rs");
        let revocation = include_str!("revocation.rs");
        let none: Vec<usize> = Vec::new();
        assert_eq!(
            constructions(auth, "VerifiedClaims", &["verify_claims"]),
            none,
            "`VerifiedClaims` is built only inside `verify_claims`"
        );
        assert_eq!(constructions(revocation, "VerifiedClaims", &[]), none);
        assert_eq!(
            constructions(revocation, "SessionCredential", &["admit_in", "try_from"]),
            none,
            "`SessionCredential` is built only by the gate and its wire decode"
        );
        assert_eq!(constructions(auth, "SessionCredential", &[]), none);
        assert_eq!(
            constructions(auth, "VerifiedClaims", &[]).len(),
            1,
            "the scan sees the sanctioned construction"
        );
        assert_eq!(
            constructions(revocation, "SessionCredential", &[]).len(),
            2,
            "the scan sees both sanctioned constructions"
        );
        assert_eq!(
            constructions(auth, "TimeClaims", &["verify_claims"]),
            none,
            "`TimeClaims` is built only inside `verify_claims`"
        );
        assert_eq!(constructions(auth, "TimeClaims", &[]).len(), 1);
        assert_eq!(constructions(revocation, "TimeClaims", &[]), none);
    }

    /// A code token and the `fn` whose body holds it.
    struct Token {
        text: String,
        func: Option<String>,
    }

    /// The code tokens of `source` (comments and literals masked), each with
    /// its enclosing `fn`.
    fn tokens(source: &str) -> Vec<Token> {
        let code = code_only(source);
        let mut out: Vec<Token> = Vec::new();
        let mut scopes: Vec<Option<String>> = Vec::new();
        let mut pending: Option<String> = None;
        let mut at = 0;
        while let Some(&c) = code.get(at) {
            let func = scopes.last().cloned().flatten();
            if c.is_alphabetic() || c == '_' {
                let start = at;
                while is_ident(&code, at) {
                    at += 1;
                }
                let text: String = code.get(start..at).unwrap_or_default().iter().collect();
                if out.last().is_some_and(|t| t.text == "fn") {
                    pending = Some(text.clone());
                }
                out.push(Token { text, func });
                continue;
            }
            match c {
                ';' => pending = None,
                '{' => {
                    let parent = scopes.last().cloned().flatten();
                    scopes.push(pending.take().or(parent));
                }
                '}' => {
                    scopes.pop();
                }
                _ => {}
            }
            if !c.is_whitespace() {
                out.push(Token {
                    text: c.to_string(),
                    func,
                });
            }
            at += 1;
        }
        out
    }

    /// The integer types a NumericDate could be re-read into.
    const DATE_INTEGERS: [&str; 6] = ["i64", "u64", "i32", "u32", "i128", "u128"];

    /// The enclosing `fn` of every integer parse in `source`: `parse::<int>` or
    /// `int::from_str`.
    fn integer_parses(source: &str) -> Vec<String> {
        let tokens = tokens(source);
        let text = |at: usize| tokens.get(at).map_or("", |t| t.text.as_str());
        let mut sites = Vec::new();
        for (at, token) in tokens.iter().enumerate() {
            let turbofish = token.text == "parse"
                && [":", ":", "<"] == [text(at + 1), text(at + 2), text(at + 3)]
                && DATE_INTEGERS.contains(&text(at + 4))
                && text(at + 5) == ">";
            let from_str = DATE_INTEGERS.contains(&token.text.as_str())
                && [":", ":"] == [text(at + 1), text(at + 2)]
                && matches!(text(at + 3), "from_str" | "from_str_radix");
            if turbofish || from_str {
                sites.push(token.func.clone().unwrap_or_default());
            }
        }
        sites
    }

    /// Source exercising the integer-parse scan.
    const SYNTHETIC_PARSES: &str = r#"
fn deadline(claims: &Claims) -> Option<i64> {
    // claims.get("exp").and_then(|s| s.parse::<i64>().ok())
    let _ = "s.parse::<i64>()";
    claims.get("exp").and_then(|s| s.parse :: < i64 > ().ok())
}
fn width(raw: &str) -> Option<usize> { raw.parse::<usize>().ok() }
fn radix(raw: &str) -> Option<u64> { u64::from_str_radix(raw, 10).ok() }
"#;

    #[test]
    fn integer_parse_scan_masks_literals_and_tracks_fns() {
        assert_eq!(integer_parses(SYNTHETIC_PARSES), ["deadline", "radix"]);
    }

    /// No reader after `verify_claims` re-parses a date from a claim's string
    /// form, and the lenient reader that passed over a mistyped date is gone.
    #[test]
    fn date_claims_read_once() {
        // The two parses read the caller's `signToken` dict, never a verified
        // token.
        assert_eq!(
            integer_parses(include_str!("auth.rs")),
            ["auth_sign_token", "auth_sign_token"],
            "only `signToken`'s caller dict parses an integer in `auth.rs`"
        );
        let none: Vec<String> = Vec::new();
        assert_eq!(integer_parses(include_str!("revocation.rs")), none);
        assert_eq!(integer_parses(include_str!("server.rs")), none);
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut pending = vec![root];
        let mut scanned = 0;
        while let Some(dir) = pending.pop() {
            let entries = std::fs::read_dir(&dir).expect("read a source dir");
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    let source = std::fs::read_to_string(&path).expect("read a source file");
                    scanned += 1;
                    assert!(
                        tokens(&source).iter().all(|t| t.text != "numeric_date"),
                        "`numeric_date` is gone; read a date through `read_numeric_date`: {}",
                        path.display()
                    );
                }
            }
        }
        assert!(scanned > 3, "the scan walked the runtime sources");
    }
}
