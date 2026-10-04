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

/// Ipê `hashPasswordCost : String -> Int -> Result Error String`. Clamps cost to
/// [4, 15] (4 = fast for tests, 12 = production default, 14–15 = high security).
/// The bcrypt VALID range is [4, 31], but cost is caller-controlled: each +1
/// DOUBLES the work, so cost 31 is a single-call CPU-exhaustion DoS (~years per
/// hash). 15 (~1–2 s/hash) is a generous operational ceiling; higher is always a
/// self-DoS, so it is clamped down rather than honoured.
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
    let clamped = cost.clamp(4, 15) as u32;
    match bcrypt::hash(&pw, clamped) {
        Ok(h) => IpeResult::Ok(h),
        Err(e) => IpeResult::Err(format!("bcrypt: {}", e).into()),
    }
}

/// Ipê `verifyPassword : String -> String -> Result Error Bool`.
/// `verifyPassword candidate hash` — true if candidate hashes to the same hash.
pub fn auth_verify_password<E: From<String>>(pw: String, hash: String) -> IpeResult<E, bool> {
    match bcrypt::verify(&pw, &hash) {
        Ok(b) => IpeResult::Ok(b),
        Err(e) => IpeResult::Err(format!("bcrypt verify: {}", e).into()),
    }
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
    // Build the claims object with keys in ascending order so the signed bytes are
    // deterministic across runs. A `BTreeMap` fixes the key order explicitly,
    // independent of both the source `HashMap` iteration order and the ambient
    // object-order encoder setting, giving a byte-stable signature.
    let mut sorted: std::collections::BTreeMap<String, serde_json::Value> = claims
        .into_iter()
        // Strip any caller-supplied `cap`, `exp`, `iat`, and `jti` — these are
        // runtime-controlled claims; a caller must not be able to override them
        // via the claims map (the computed values below are authoritative).
        .filter(|(k, _)| k != "cap" && k != "exp" && k != "iat" && k != "jti")
        .map(|(k, v)| (k, serde_json::Value::String(v)))
        .collect();
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

/// Ipê `verifyToken : String -> String -> Result Error a`. Verifies signature,
/// `exp`, and (when present) the absolute lifetime `cap`. Returns the claims as a
/// `HashMap<String, String>` (Ipê-side resolves polymorphic `a` to this shape at
/// the FFI boundary).
///
/// # Absolute lifetime cap (`cap` claim)
///
/// Tokens minted by `auth_sign_token` carry a signed `cap` claim (`iat +
/// AuthMaxLifetime`). A token is rejected when `now >= cap`, regardless of `exp`.
/// A token without a `cap` claim is a legacy token (minted before this feature);
/// it is accepted only against its `exp` and is never granted an unlimited
/// lifetime — the `exp` bound is the sole gate in that case.
pub fn auth_verify_token<E: From<String>>(
    secret: String,
    token: String,
) -> IpeResult<E, HashMap<String, String>> {
    if secret.len() < crate::jwt::HS256_MIN_SECRET_BYTES {
        return IpeResult::Err(
            crate::jwt::hs256_short_secret_msg("auth.verifyToken", secret.len()).into(),
        );
    }
    // Pre-reject on the full RFC 7519 NumericDate domain (negative, fractional,
    // integer) before jsonwebtoken's `exp - 1` u64 subtraction can underflow.
    // Mirrors jwt.rs's `jwt_decode_hs256` pre-reject; see that function's
    // comment for the detailed rationale.
    if let Some(payload) = crate::jwt::decode_payload(&token) {
        let now = crate::jwt::now_unix_seconds();
        if let Some(exp) = crate::jwt::numeric_date(&payload, "exp")
            && now >= exp
        {
            return IpeResult::Err("auth.verifyToken: token has expired".to_string().into());
        }
        if let Some(nbf) = crate::jwt::numeric_date(&payload, "nbf")
            && now < nbf
        {
            return IpeResult::Err(
                "auth.verifyToken: token is not yet valid"
                    .to_string()
                    .into(),
            );
        }
        // Absolute cap gate — checked on the unverified payload first for a fast
        // pre-reject path, then confirmed on the verified claims after signature
        // check below. A cap in the past denies immediately (the signature check
        // below is still required, but there is no point decoding claims we will
        // discard). Legacy tokens without a `cap` are not pre-rejected here — the
        // `exp` gate above is their sole bound.
        if let Some(cap) = crate::jwt::numeric_date(&payload, "cap")
            && now >= cap
        {
            return IpeResult::Err(
                "auth.verifyToken: token has exceeded its absolute lifetime cap"
                    .to_string()
                    .into(),
            );
        }
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
    let parsed = match jsonwebtoken::decode::<serde_json::Value>(&token, &key, &validation) {
        Ok(d) => d,
        Err(e) => return IpeResult::Err(format!("jwt verify: {}", e).into()),
    };
    // Re-check the absolute cap on the signature-verified claims. The pre-reject
    // above already denies past-cap tokens before the signature decode, but this
    // second check on the verified payload closes any edge where the pre-reject
    // payload and the verified payload diverge (they cannot in practice — the
    // signature covers both — but defence-in-depth here costs nothing).
    if let Some(cap) = crate::jwt::numeric_date(&parsed.claims, "cap") {
        let now = crate::jwt::now_unix_seconds();
        if now >= cap {
            return IpeResult::Err(
                "auth.verifyToken: token has exceeded its absolute lifetime cap"
                    .to_string()
                    .into(),
            );
        }
    }
    let mut out = HashMap::new();
    if let serde_json::Value::Object(m) = parsed.claims {
        for (k, v) in m {
            // Coerce each claim value to a string. Numbers/booleans get
            // their JSON-text representation; nested objects/arrays get their
            // JSON serialisation (Sprintf behaviour).
            let s = match v {
                serde_json::Value::String(s) => s,
                other => other.to_string(),
            };
            out.insert(k, s);
        }
    }
    IpeResult::Ok(out)
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

/// Parse a `ReissueContext` from a signature-verified claims map (the output of
/// `auth_verify_token`). Returns `None` when any required field is missing or
/// malformed — the caller must deny in that case.
///
/// Tokens minted before `jti` was introduced carry no `jti` claim. For backward
/// compatibility, a missing `jti` is treated as an empty string — such a token
/// cannot be individually revoked by session id, but subject-level revocation
/// still applies. A fresh re-issue of a legacy token mints a new `jti` via the
/// `auth_sign_token` path (the empty string is filtered out in that path).
#[cfg(feature = "jwt")]
#[must_use]
pub fn reissue_context_from_claims(
    claims: &std::collections::HashMap<String, String>,
) -> Option<ReissueContext> {
    let iat = claims.get("iat")?.parse::<i64>().ok()?;
    let cap = claims.get("cap")?.parse::<i64>().ok()?;
    let subject = claims.get("sub").filter(|s| !s.is_empty())?.clone();
    // `jti` absent on legacy tokens — treat as empty (cannot be session-revoked by id).
    let jti = claims.get("jti").cloned().unwrap_or_default();
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
    let mut sorted: std::collections::BTreeMap<String, serde_json::Value> = extra_claims
        .into_iter()
        .filter(|(k, _)| k != "cap" && k != "exp" && k != "iat" && k != "jti" && k != "sub")
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
/// Idempotent `CREATE TABLE IF NOT EXISTS users (...)`. Runs at the start of
/// register/login/setRole so the schema is always available without users
/// having to call a separate migration. The id-column DDL is per-driver
/// — `db_auto_id_column()` returns the right fragment for sqlite
/// (`INTEGER PRIMARY KEY AUTOINCREMENT`), mysql (`BIGINT NOT NULL
/// AUTO_INCREMENT PRIMARY KEY`), or postgres (`BIGSERIAL PRIMARY KEY`).
async fn ensure_users_schema<E: From<String> + Send>(conn: &Db) -> IpeResult<E, ()> {
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
        Err(e) => IpeResult::Err(format!("auth.users schema: {}", e).into()),
    }
}

#[cfg(feature = "db")]
/// Ipê `register : Db -> String -> String -> Task Error Int`.
/// Creates a new user. Returns the new user id.
pub fn auth_register<E: Send + From<String> + crate::FromUnavailable + 'static>(
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
            Err(sqlx::Error::Database(de)) if de.is_unique_violation() => {
                IpeResult::Err("auth.register: email already registered".to_string().into())
            }
            Err(e) => IpeResult::Err(format!("auth.register: {}", e).into()),
        }
    })
}

#[cfg(feature = "db")]
/// Ipê `login : Db -> String -> String -> Task Error Int`.
/// Authenticates the user. Returns user id on success. Does NOT leak whether
/// the email exists vs. password was wrong — both paths return the same
/// generic "invalid credentials" error.
pub fn auth_login<E: Send + From<String> + crate::FromUnavailable + 'static>(
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
                    bcrypt::verify(&password, &hash).unwrap_or(false)
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
            Err(e) => IpeResult::Err(format!("auth.login: {}", e).into()),
        }
    })
}

#[cfg(feature = "db")]
/// Ipê `setRole : Db -> Int -> String -> Task Error ()`.
/// Sets the user's role. No-op if the user doesn't exist (returns Ok).
pub fn auth_set_role<E: Send + From<String> + 'static>(
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
            Err(e) => IpeResult::Err(format!("auth.setRole: {}", e).into()),
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
        let ok: IpeResult<String, bool> = auth_verify_password("password123".into(), h.clone());
        assert!(matches!(ok, IpeResult::Ok(true)));
        let bad: IpeResult<String, bool> = auth_verify_password("wrongpass".into(), h);
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
        let verified: IpeResult<String, HashMap<String, String>> = auth_verify_token(secret, t);
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
        let verified: IpeResult<String, HashMap<String, String>> = auth_verify_token(secret, token);
        assert!(
            matches!(verified, IpeResult::Err(_)),
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
        let verified: IpeResult<String, HashMap<String, String>> = auth_verify_token(secret, t);
        match verified {
            IpeResult::Ok(m) => {
                assert_eq!(m.get("aud").map(String::as_str), Some("my-service"));
            }
            IpeResult::Err(e) => panic!("verify must accept aud-bearing claims: {e}"),
        }
    }

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
        let result: IpeResult<String, HashMap<String, String>> =
            auth_verify_token(SECRET.to_string(), token);
        assert!(
            matches!(result, IpeResult::Err(_)),
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
        let original_cap = crate::jwt::numeric_date(&payload, "cap").expect("cap in first token");
        // Simulate a re-issue: extract all claims and pass them (including cap) back.
        let verified: HashMap<String, String> =
            match auth_verify_token::<String>(SECRET.to_string(), first_token) {
                IpeResult::Ok(m) => m,
                IpeResult::Err(e) => panic!("first verify: {e}"),
            };
        // Re-issue by signing with the original claims (including cap).
        let reissued_token: String =
            match auth_sign_token::<String>(SECRET.to_string(), verified, 3600) {
                IpeResult::Ok(t) => t,
                IpeResult::Err(e) => panic!("re-issue mint: {e}"),
            };
        let reissued_payload =
            crate::jwt::decode_payload(&reissued_token).expect("reissued payload");
        let reissued_cap =
            crate::jwt::numeric_date(&reissued_payload, "cap").expect("cap in reissued token");
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
        let cap = crate::jwt::numeric_date(&payload, "cap").expect("cap");
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
        let result: IpeResult<String, HashMap<String, String>> =
            auth_verify_token(SECRET.to_string(), forged_token);
        assert!(
            matches!(result, IpeResult::Err(_)),
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
        let result: IpeResult<String, HashMap<String, String>> =
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
        let result: IpeResult<String, HashMap<String, String>> =
            auth_verify_token(SECRET.to_string(), token);
        assert!(
            matches!(result, IpeResult::Err(_)),
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
            crate::jwt::numeric_date(&payload, "cap").is_some(),
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
        let claims: HashMap<String, String> =
            match auth_verify_token::<String>(SECRET.to_string(), token.to_string()) {
                IpeResult::Ok(c) => c,
                IpeResult::Err(e) => panic!("verify: {e}"),
            };
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
        let new_exp = crate::jwt::numeric_date(&new_payload, "exp").expect("exp");
        let now = now_unix();
        // new_exp must be in (now, now + slide + 2s fuzz] and <= cap.
        assert!(new_exp > now, "reissued exp must be in the future");
        assert!(new_exp <= ctx.cap, "reissued exp must not exceed cap");
        // iat and cap must be carried verbatim.
        let new_iat = crate::jwt::numeric_date(&new_payload, "iat").expect("iat");
        let new_cap = crate::jwt::numeric_date(&new_payload, "cap").expect("cap");
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
        let claims: HashMap<String, String> =
            match auth_verify_token::<String>(SECRET.to_string(), token) {
                IpeResult::Ok(c) => c,
                IpeResult::Err(e) => panic!("verify near-cap token: {e}"),
            };
        let ctx =
            crate::auth::reissue_context_from_claims(&claims).expect("context from near-cap token");
        let new_token =
            match crate::auth::auth_reissue_token::<String>(SECRET, &ctx, HashMap::new(), 1800) {
                Some(IpeResult::Ok(t)) => t,
                Some(IpeResult::Err(e)) => panic!("reissue: {e}"),
                None => panic!("reissue returned None unexpectedly"),
            };
        let new_payload = crate::jwt::decode_payload(&new_token).expect("payload");
        let new_exp = crate::jwt::numeric_date(&new_payload, "exp").expect("exp");
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
        let emitted_cap = crate::jwt::numeric_date(&payload, "cap").expect("cap");
        // The emitted cap equals whatever is in ctx — structural proof that the
        // reissue function does NOT override ctx.cap with something larger. The
        // defence against a forged ctx is that verified-origin is the ONLY path
        // to a ReissueContext (reissue_context_from_claims requires verified claims).
        assert_eq!(
            emitted_cap, forged_ctx.cap,
            "auth_reissue_token must copy ctx.cap verbatim — it never inflates it further"
        );
        let emitted_exp = crate::jwt::numeric_date(&payload, "exp").expect("exp");
        assert!(
            emitted_exp <= forged_ctx.cap,
            "exp must always be <= ctx.cap regardless of slide_window"
        );
    }

    #[test]
    fn reissue_context_from_verified_claims_requires_iat_cap_sub() {
        // Missing `cap` → None.
        let mut claims = HashMap::new();
        claims.insert("sub".to_string(), "u".to_string());
        claims.insert("iat".to_string(), "1000".to_string());
        assert!(
            crate::auth::reissue_context_from_claims(&claims).is_none(),
            "missing cap must yield None"
        );
        // Missing `iat` → None.
        let mut claims2 = HashMap::new();
        claims2.insert("sub".to_string(), "u".to_string());
        claims2.insert("cap".to_string(), "9000".to_string());
        assert!(
            crate::auth::reissue_context_from_claims(&claims2).is_none(),
            "missing iat must yield None"
        );
        // Missing `sub` → None.
        let mut claims3 = HashMap::new();
        claims3.insert("iat".to_string(), "1000".to_string());
        claims3.insert("cap".to_string(), "9000".to_string());
        assert!(
            crate::auth::reissue_context_from_claims(&claims3).is_none(),
            "missing sub must yield None"
        );
        // All present → Some.
        let mut claims4 = HashMap::new();
        claims4.insert("sub".to_string(), "user".to_string());
        claims4.insert("iat".to_string(), "1000".to_string());
        claims4.insert("cap".to_string(), "9000".to_string());
        let ctx = crate::auth::reissue_context_from_claims(&claims4);
        assert!(ctx.is_some(), "all fields present must yield Some");
    }
}
