//! Runtime revocation store and the one revocation gate built on it.
//!
//! The store holds revoked subjects (every session of that user) and revoked
//! session ids (`jti`, one specific session). Its sole question is boolean.
//!
//! # The gate
//!
//! [`ArmedGate`] is the only code that turns verified claims plus the store into
//! "admitted". It exists only when the resolved [`RevocationMode`] is `Store`
//! ([`ArmedGate::resolve`]), so an "armed but unchecked" path has no
//! representation. [`ArmedGate::admit`] is the only constructor of a
//! [`SessionCredential`], and it takes [`VerifiedClaims`], which only
//! `auth::verify_claims` builds: a credential from unverified claims has no
//! representation either.
//!
//! - `admit` refuses a token with no subject, no `jti`, or no lifetime bound
//!   (`cap`, else `exp`), and a token the store names or cannot judge.
//! - [`ArmedGate::recheck`] re-proves a held credential: its deadline, then the
//!   store.
//! - Both take the store mutex a revocation write holds, so a write that has
//!   returned is seen by every later admission and recheck.
//! - A channel owner holds its credentials in one [`SessionBindings`] (at most
//!   [`MAX_SESSION_CREDENTIALS`]; a full set refuses the new token and evicts
//!   nothing).
//! - Every revocation write, refused or not, bumps a process generation
//!   ([`subscribe`]), so a long-lived channel can re-prove on change.
//!
//! [`process_mode`] is the process-wide mode the `Auth.verifyToken` kernel arms
//! under: the stricter of the installed `Web.withRevocation`, the
//! `IPE_AUTH_REVOCATION` floor, and any `Server` route built with `Store`
//! ([`arm_process`]). Every source can only arm.
//!
//! # Limits
//!
//! - The store is per process: a revocation on one replica does not reach
//!   another.
//! - Only `Auth.verifyToken` binds. A token checked another way (`Jwt.decode`,
//!   a raw compare) binds nothing.
//! - A channel that verifies another party's token is bound to it too, so
//!   revoking that token ends the channel (over-deny, fail closed).
//! - A script armed by the env starts with an empty store, so it refuses only
//!   tokens with no subject, `jti` or lifetime bound until something in the same
//!   process revokes.
//!
//! # Fail-closed
//!
//! `is_revoked` returns [`Verdict::Revoked`] on a positive hit, [`Verdict::Unknown`]
//! on any store error, and [`Verdict::Active`] only when the store is healthy and
//! the subject/session is absent from both maps. The gate denies on `Revoked`
//! **and** on `Unknown` — a degraded store denies, never admits.
//!
//! # Bounded by construction
//!
//! Each set is a `HashMap<id, cap_unix_secs>` capped at
//! [`REVOCATION_STORE_CAPACITY`](crate::app_config::REVOCATION_STORE_CAPACITY)
//! entries per map. Every insert goes through
//! [`RevocationStore::insert_bounded`], which:
//!
//! 1. Checks the count against the ceiling atomically inside the existing lock.
//! 2. On a full map, runs a lazy `retain` sweep that removes only entries whose
//!    absolute-cap timestamp is already past (`now >= expiry`). Such tokens are
//!    denied by the JWT `cap` gate regardless of the revocation map, so dropping
//!    them changes no verdict — redundancy-driven reclamation, never capacity eviction.
//! 3. If the sweep freed room, the insert proceeds; otherwise it returns
//!    [`RevocationError::AtCapacity`] WITHOUT touching any existing entry.
//!
//! This is the fail-closed rule: at the ceiling the store denies the *write*
//! (returns an error so the caller can escalate), never the *revocation invariant*
//! (never silently drops a live entry — that would re-admit a revoked token).
//!
//! # Entry expiry
//!
//! - **Session revocation**: the expiry is the token's `cap` claim (the absolute
//!   lifetime cap baked into the JWT at mint time).
//! - **Subject revocation**: the expiry is `now + AuthMaxLifetime` (the longest any
//!   token minted now could remain valid). A re-revoke takes the max, never shortening.
//!   See [`revoke_subject`] for an accepted edge case when the operator lowers
//!   `AuthMaxLifetime` across a process restart.
//!
//! Hot-path lookup (`is_revoked`) is O(1) — one `contains_key` per map, no scan.

use std::collections::HashMap;
#[cfg(feature = "server")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use super::*;
use crate::app_config::RevocationMode;
use crate::auth::VerifiedClaims;

/// The verdict `is_revoked` returns for a given subject + session pair.
///
/// The caller (`authed_route`) denies on both [`Verdict::Revoked`] and
/// [`Verdict::Unknown`] — only [`Verdict::Active`] allows the request through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The subject and session id are absent from both revocation maps.
    Active,
    /// The subject or session id is in a revocation map.
    Revoked,
    /// The store is unavailable (lock poisoned or internal error).
    Unknown,
}

/// Typed error returned by write operations on the bounded revocation store.
///
/// Both variants surface as a `Task Error ()` failure in the calling Ipê
/// kernel so the app can react — escalate to signing-key rotation when
/// `AtCapacity`, retry or alert on `Unavailable`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevocationError {
    /// The store lock is poisoned — the store is in an unknown state.
    Unavailable,
    /// The operator's `IPE_REVOCATION_CAPACITY` setting is refused, so no store
    /// runs under a capacity the operator did not set.
    Misconfigured(crate::system::EnvCeilingRefusal),
    /// The map is at its ceiling and no expired entries could be reclaimed.
    /// The new revocation was NOT recorded. The caller must escalate (e.g.
    /// rotate the signing key, which invalidates every session at once).
    AtCapacity,
}

impl std::fmt::Display for RevocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => write!(f, "revocation store unavailable"),
            Self::Misconfigured(refusal) => write!(f, "revocation store unavailable: {refusal}"),
            Self::AtCapacity => write!(
                f,
                "revocation store at capacity — no expired entries to reclaim; \
                 escalate to signing-key rotation"
            ),
        }
    }
}

/// The bounded revocation store.
///
/// Each map is `HashMap<id, cap_unix_secs>` where `cap_unix_secs` is the
/// absolute Unix-second timestamp past which the underlying token is expired.
/// The capacity ceiling is read once from config at first use and held here so
/// the `insert_bounded` critical section never calls out to config.
struct RevocationStore {
    /// Revoked subjects — every token for this user is denied. Maps subject
    /// string to `now + AuthMaxLifetime` at revocation time (the latest any
    /// current token can live). Re-revoke takes the max.
    subjects: HashMap<String, i64>,
    /// Revoked session ids (`jti`) — only this specific session is denied.
    /// Maps jti to the token's `cap` claim (absolute expiry baked into the JWT).
    sessions: HashMap<String, i64>,
    /// Per-map entry ceiling resolved from config at construction. Cached here
    /// so the hot-path critical section is pure in-memory arithmetic.
    capacity: usize,
}

impl RevocationStore {
    fn new(capacity: usize) -> Self {
        Self {
            subjects: HashMap::new(),
            sessions: HashMap::new(),
            capacity,
        }
    }

    /// Insert `id` with `expiry` into the selected map, respecting the ceiling.
    ///
    /// If the map is at capacity, a lazy sweep removes entries whose
    /// `expiry <= now` (redundant: the JWT `cap` gate denies them anyway).
    /// If room is freed the insert proceeds; otherwise returns
    /// [`RevocationError::AtCapacity`]. All of this runs in the same critical
    /// section as the caller's lock, so the count and the ceiling are checked
    /// atomically — no concurrent insert can bypass the bound.
    ///
    /// A re-insert of an existing `id` takes the max of the old and new expiry
    /// (never shortens a live revocation).
    fn insert_bounded(
        &mut self,
        map: MapSelector,
        id: String,
        expiry: i64,
        now: i64,
    ) -> Result<(), RevocationError> {
        let m = match map {
            MapSelector::Subjects => &mut self.subjects,
            MapSelector::Sessions => &mut self.sessions,
        };
        // Re-revoke path: update expiry (take max, never shorten) and return.
        if let Some(existing) = m.get_mut(&id) {
            *existing = (*existing).max(expiry);
            return Ok(());
        }
        // Fast path: room available.
        if m.len() < self.capacity {
            m.insert(id, expiry);
            return Ok(());
        }
        // At capacity — sweep out redundant (past-cap) entries.
        m.retain(|_, exp| now < *exp);
        if m.len() < self.capacity {
            m.insert(id, expiry);
            Ok(())
        } else {
            // No redundant entries found — fail closed. Do NOT evict a live entry.
            Err(RevocationError::AtCapacity)
        }
    }
}

/// Selects which map inside [`RevocationStore`] an operation targets.
enum MapSelector {
    Subjects,
    Sessions,
}

/// A store, or the refusal of the operator's capacity setting.
type StoreSlot = Result<Mutex<RevocationStore>, crate::system::EnvCeilingRefusal>;

/// The process store, or the refusal of the operator's capacity setting.
fn store() -> &'static StoreSlot {
    static STORE: OnceLock<StoreSlot> = OnceLock::new();
    STORE.get_or_init(|| store_with(crate::app_config::resolve_revocation_capacity()))
}

/// A store of the resolved capacity; a refused capacity yields no store at all.
///
/// The store never runs under a capacity the operator did not set. The refusal
/// is raised at `Server.listen`; past it, every verdict is [`Verdict::Unknown`]
/// and every write is [`RevocationError::Misconfigured`].
fn store_with(capacity: Result<usize, crate::system::EnvCeilingRefusal>) -> StoreSlot {
    capacity.map(|capacity| Mutex::new(RevocationStore::new(capacity)))
}

/// Acquire the lock of `store`: a refused capacity is
/// [`RevocationError::Misconfigured`], a poisoned lock
/// [`RevocationError::Unavailable`]. The per-request gate maps either to
/// [`Verdict::Unknown`], which denies the request.
fn guard_of(store: &StoreSlot) -> Result<MutexGuard<'_, RevocationStore>, RevocationError> {
    match store {
        Ok(store) => store.lock().map_err(|_| RevocationError::Unavailable),
        Err(refusal) => Err(RevocationError::Misconfigured(refusal.clone())),
    }
}

/// Acquire the process store's lock (see [`guard_of`]).
fn lock() -> Result<MutexGuard<'static, RevocationStore>, RevocationError> {
    guard_of(store())
}

/// Query whether `subject` or `jti` is revoked.
///
/// Returns [`Verdict::Active`] only when the store is healthy and neither the
/// subject nor the session id appears in either revocation map. Any lock error
/// yields [`Verdict::Unknown`], which the middleware treats as a denial.
///
/// Hot path: one `contains_key` per map — O(1), no scan. Expired-but-not-yet-swept
/// entries are harmless: they still say "revoked", and the JWT `cap` gate
/// independently denies the token, so a stale entry can only over-deny, never
/// under-deny.
#[must_use]
pub fn is_revoked(subject: &str, jti: &str) -> Verdict {
    verdict_in(store(), subject, jti)
}

/// The verdict of `store` for `subject` and `jti` (see [`is_revoked`]).
fn verdict_in(store: &StoreSlot, subject: &str, jti: &str) -> Verdict {
    let Ok(guard) = guard_of(store) else {
        return Verdict::Unknown;
    };
    if guard.subjects.contains_key(subject) || guard.sessions.contains_key(jti) {
        Verdict::Revoked
    } else {
        Verdict::Active
    }
}

/// Mark every session of `subject` as revoked.
///
/// The entry expiry is `now + AuthMaxLifetime` — the longest any currently live
/// token for this subject could remain valid. A re-revoke takes the max, never
/// shortening the window. The generation bumps whether or not the write is
/// recorded, so every open channel re-proves even after a refused write.
///
/// # Errors
///
/// [`RevocationError`] when the store is refused, poisoned or full.
pub fn revoke_subject(subject: String) -> Result<(), RevocationError> {
    revoke_subject_in(store(), subject)
}

/// [`revoke_subject`] against `store`.
fn revoke_subject_in(store: &StoreSlot, subject: String) -> Result<(), RevocationError> {
    let outcome = record_subject(store, subject);
    bump_generation();
    outcome
}

/// Record the subject revocation in `store`, without the generation bump.
fn record_subject(store: &StoreSlot, subject: String) -> Result<(), RevocationError> {
    let mut guard = guard_of(store)?;
    let now = crate::jwt::now_unix_seconds();
    // A refused lifetime setting leaves the longest live token unknown, so the
    // entry never expires: the revocation is still recorded and can only
    // over-deny. The refusal itself surfaces at `Server.listen`, `signToken`
    // and the re-issue path.
    let max_lifetime = crate::app_config::resolve_auth_max_lifetime()
        .map_or(i64::MAX, |secs| i64::try_from(secs).unwrap_or(i64::MAX));
    // Expiry anchored to the *current* AuthMaxLifetime (ML): any token minted
    // right now could live at most `now + ML`, so this entry stays in the store
    // until all currently mintable tokens have expired.
    //
    // Accepted edge case: if an operator lowers ML and restarts the process, a
    // token minted by the prior process may carry a signed `cap > now + new_ML`.
    // A subject-revocation entry written after the restart uses the new (shorter)
    // ML, so its store expiry is earlier than that old token's `cap`. If the
    // store also happens to be saturated and runs a sweep during that gap, the
    // entry is reclaimed while the old token is still JWT-live — silently lifting
    // the revocation for it.
    //
    // All four conditions must hold simultaneously: ML lowered + process restart,
    // an old long-cap token still in circulation, the store at capacity, and the
    // sweep falling inside the ML-gap window. This is an accepted marginal risk:
    // a stateless session design carries no live-cap registry, so there is no
    // cheap way to clamp the expiry against the actual cap of each outstanding
    // token. Operators with strict requirements should rotate the signing key on
    // a ML change, which invalidates every prior token unconditionally.
    let expiry = now.saturating_add(max_lifetime);
    guard.insert_bounded(MapSelector::Subjects, subject, expiry, now)
}

/// Mark the specific session `jti` as revoked.
///
/// `cap_unix_secs` is the token's `cap` claim — the absolute-lifetime cap baked
/// into the JWT at mint time. The store holds this value so the lazy sweep can
/// drop the entry once the cap has passed (the JWT gate denies the token anyway
/// from that point, making the revocation entry redundant). The generation
/// bumps whether or not the write is recorded.
///
/// # Errors
///
/// [`RevocationError`] when the store is refused, poisoned or full.
pub fn revoke_session(jti: String, cap_unix_secs: i64) -> Result<(), RevocationError> {
    revoke_session_in(store(), jti, cap_unix_secs)
}

/// [`revoke_session`] against `store`.
fn revoke_session_in(
    store: &StoreSlot,
    jti: String,
    cap_unix_secs: i64,
) -> Result<(), RevocationError> {
    let outcome = guard_of(store).and_then(|mut guard| {
        let now = crate::jwt::now_unix_seconds();
        guard.insert_bounded(MapSelector::Sessions, jti, cap_unix_secs, now)
    });
    bump_generation();
    outcome
}

/// Clear the subject revocation for `subject`. After this call a new token for
/// that subject passes the revocation gate (existing `jti`-scoped entries are
/// unaffected — restoring the subject does not un-revoke specific sessions that
/// were independently revoked via `revoke_session`).
pub fn restore_subject(subject: &str) -> Result<(), RevocationError> {
    let mut guard = lock()?;
    guard.subjects.remove(subject);
    Ok(())
}

/// Query whether `subject` is in the subject-revocation map. Does not check
/// session-scoped entries (a subject not in the map may still have a revoked
/// `jti`). Intended for the `isRevoked` app-facing kernel (an admin UI query),
/// not for the per-request auth gate (which calls [`is_revoked`]).
pub fn subject_is_revoked(subject: &str) -> Result<bool, RevocationError> {
    let guard = lock()?;
    Ok(guard.subjects.contains_key(subject))
}

// ─── The gate ─────────────────────────────────────────────────────────────────

/// A subject claim value; never empty.
#[derive(Clone, PartialEq, Eq)]
struct Subject(String);

impl Subject {
    /// The subject `raw` names, or `None` for an empty value.
    fn parse(raw: &str) -> Option<Self> {
        (!raw.is_empty()).then(|| Self(raw.to_owned()))
    }
}

/// A session id (`jti`) claim value; never empty, and never a [`Subject`].
#[derive(Clone, PartialEq, Eq)]
struct SessionJti(String);

impl SessionJti {
    /// The session id `raw` names, or `None` for an empty value.
    fn parse(raw: &str) -> Option<Self> {
        (!raw.is_empty()).then(|| Self(raw.to_owned()))
    }
}

/// An absolute Unix-second instant past which a credential is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixSecs(i64);

impl UnixSecs {
    /// The instant as Unix seconds.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Why the gate refused a token or a held credential.
///
/// Each variant displays one fixed phrase that never names the subject or the
/// session id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial {
    /// The token carries no subject, or an empty one.
    SubjectAbsent,
    /// The token carries no session id (`jti`), or an empty one.
    SessionIdAbsent,
    /// The token carries no lifetime bound (`cap`, else `exp`).
    NoDeadline,
    /// The store names the subject or the session id.
    Revoked,
    /// The store cannot answer (refused capacity or poisoned lock).
    StoreUnavailable,
    /// The credential reached its lifetime bound.
    PastDeadline,
    /// The channel already holds [`MAX_SESSION_CREDENTIALS`] credentials.
    BindingsFull,
}

impl std::fmt::Display for Denial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::SubjectAbsent => "token carries no subject",
            Self::SessionIdAbsent => "token carries no session id (`jti`)",
            Self::NoDeadline => "token carries no lifetime bound (`cap` or `exp`)",
            Self::Revoked => "credential revoked",
            Self::StoreUnavailable => "revocation store unavailable",
            Self::PastDeadline => "credential past its lifetime bound",
            Self::BindingsFull => "too many credentials bound to this channel",
        })
    }
}

impl std::error::Error for Denial {}

/// The denial a store verdict carries, if any.
const fn verdict_denial(verdict: Verdict) -> Result<(), Denial> {
    match verdict {
        Verdict::Active => Ok(()),
        Verdict::Revoked => Err(Denial::Revoked),
        Verdict::Unknown => Err(Denial::StoreUnavailable),
    }
}

/// A credential the gate admitted: a subject, a session id and a deadline.
///
/// Only [`ArmedGate::admit`] builds one from verified claims, and the persisted
/// form re-parses the same non-empty invariants on read.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(into = "CredentialWire", try_from = "CredentialWire")]
pub struct SessionCredential {
    subject: Subject,
    session: SessionJti,
    deadline: UnixSecs,
}

// The subject identifies the caller and the jti names the session, so `Debug`
// masks both.
crate::redact::redacting_debug!(SessionCredential {
    shown: [deadline],
    masked: [subject, session],
});

impl SessionCredential {
    /// The instant past which the credential is invalid.
    #[must_use]
    pub const fn deadline(&self) -> UnixSecs {
        self.deadline
    }
}

/// The persisted form of a [`SessionCredential`].
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialWire {
    sub: String,
    jti: String,
    deadline: i64,
}

impl From<SessionCredential> for CredentialWire {
    fn from(credential: SessionCredential) -> Self {
        Self {
            sub: credential.subject.0,
            jti: credential.session.0,
            deadline: credential.deadline.0,
        }
    }
}

impl TryFrom<CredentialWire> for SessionCredential {
    type Error = Denial;

    fn try_from(wire: CredentialWire) -> Result<Self, Denial> {
        Ok(Self {
            subject: Subject::parse(&wire.sub).ok_or(Denial::SubjectAbsent)?,
            session: SessionJti::parse(&wire.jti).ok_or(Denial::SessionIdAbsent)?,
            deadline: UnixSecs(wire.deadline),
        })
    }
}

/// The deadline of verified claims: `cap`, else `exp` for a token minted with
/// no `cap`. A present but unreadable `cap` is no deadline.
fn deadline_of(claims: &VerifiedClaims) -> Option<UnixSecs> {
    claims
        .get("cap")
        .or_else(|| claims.get("exp"))
        .and_then(|raw| raw.parse::<i64>().ok())
        .map(UnixSecs)
}

/// The armed revocation gate; it exists only when the resolved mode is `Store`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArmedGate(());

impl ArmedGate {
    /// The gate `mode` arms: `Some` for [`RevocationMode::Store`], `None` for
    /// [`RevocationMode::Off`].
    #[must_use]
    pub const fn resolve(mode: RevocationMode) -> Option<Self> {
        match mode {
            RevocationMode::Store => Some(Self(())),
            RevocationMode::Off => None,
        }
    }

    /// Admit verified claims as a credential, reading the subject from
    /// `subject_claim`.
    ///
    /// # Errors
    ///
    /// [`Denial::SubjectAbsent`], [`Denial::SessionIdAbsent`] or
    /// [`Denial::NoDeadline`] for a claim the token lacks; [`Denial::Revoked`]
    /// when the store names it; [`Denial::StoreUnavailable`] when the store
    /// cannot answer.
    pub fn admit(
        self,
        claims: &VerifiedClaims,
        subject_claim: &str,
    ) -> Result<SessionCredential, Denial> {
        self.admit_in(store(), claims, subject_claim)
    }

    /// [`ArmedGate::admit`] against `store`.
    fn admit_in(
        self,
        store: &StoreSlot,
        claims: &VerifiedClaims,
        subject_claim: &str,
    ) -> Result<SessionCredential, Denial> {
        let subject = claims
            .get(subject_claim)
            .and_then(Subject::parse)
            .ok_or(Denial::SubjectAbsent)?;
        let session = claims
            .get("jti")
            .and_then(SessionJti::parse)
            .ok_or(Denial::SessionIdAbsent)?;
        let deadline = deadline_of(claims).ok_or(Denial::NoDeadline)?;
        verdict_denial(verdict_in(store, &subject.0, &session.0))?;
        Ok(SessionCredential {
            subject,
            session,
            deadline,
        })
    }

    /// Re-prove a held credential at `now_unix`: its deadline, then the store.
    ///
    /// # Errors
    ///
    /// [`Denial::PastDeadline`] once `now_unix >= deadline`; [`Denial::Revoked`]
    /// or [`Denial::StoreUnavailable`] as for [`ArmedGate::admit`].
    pub fn recheck(self, credential: &SessionCredential, now_unix: i64) -> Result<(), Denial> {
        self.recheck_in(store(), credential, now_unix)
    }

    /// [`ArmedGate::recheck`] against `store`.
    fn recheck_in(
        self,
        store: &StoreSlot,
        credential: &SessionCredential,
        now_unix: i64,
    ) -> Result<(), Denial> {
        if now_unix >= credential.deadline.0 {
            return Err(Denial::PastDeadline);
        }
        verdict_denial(verdict_in(
            store,
            &credential.subject.0,
            &credential.session.0,
        ))
    }
}

/// The most credentials one channel owner holds.
pub const MAX_SESSION_CREDENTIALS: usize = 8;

/// The credentials a channel owner (a Web session, a `Server` request) is bound
/// to; at most [`MAX_SESSION_CREDENTIALS`], one per session id.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SessionBindings {
    credentials: Vec<SessionCredential>,
}

// The held credentials name callers and sessions, so `Debug` masks the set.
crate::redact::redacting_debug!(SessionBindings {
    shown: [],
    masked: [credentials],
});

impl SessionBindings {
    /// Bind `credential`. A credential of a session id already held keeps one
    /// entry with the earlier deadline.
    ///
    /// # Errors
    ///
    /// [`Denial::BindingsFull`] when the set is full; nothing is evicted.
    pub fn bind(&mut self, credential: SessionCredential) -> Result<(), Denial> {
        if let Some(held) = self
            .credentials
            .iter_mut()
            .find(|held| held.session == credential.session)
        {
            held.deadline = held.deadline.min(credential.deadline);
            return Ok(());
        }
        if self.credentials.len() >= MAX_SESSION_CREDENTIALS {
            return Err(Denial::BindingsFull);
        }
        self.credentials.push(credential);
        Ok(())
    }

    /// How many credentials are bound.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.credentials.len()
    }

    /// Whether no credential is bound.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    /// Whether a credential of session id `jti` is bound.
    #[must_use]
    pub fn binds_session(&self, jti: &str) -> bool {
        self.credentials.iter().any(|held| held.session.0 == jti)
    }

    /// The earliest deadline of the bound credentials.
    #[must_use]
    pub fn earliest_deadline(&self) -> Option<UnixSecs> {
        self.credentials.iter().map(|held| held.deadline).min()
    }

    /// Re-prove every bound credential at `now_unix`.
    ///
    /// # Errors
    ///
    /// The first [`Denial`] any credential's [`ArmedGate::recheck`] returns.
    pub fn recheck_all(&self, gate: ArmedGate, now_unix: i64) -> Result<(), Denial> {
        self.credentials
            .iter()
            .try_for_each(|held| gate.recheck(held, now_unix))
    }
}

/// Bind `credential` into a shared set.
///
/// # Errors
///
/// [`Denial::BindingsFull`] for a full set; [`Denial::StoreUnavailable`] for a
/// poisoned lock.
pub fn bind_shared(
    bindings: &Mutex<SessionBindings>,
    credential: SessionCredential,
) -> Result<(), Denial> {
    bindings
        .lock()
        .map_err(|_| Denial::StoreUnavailable)?
        .bind(credential)
}

/// Why persisted bindings did not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingsDecodeRefusal {
    /// The bytes are not a credential list, or a credential has an empty field.
    Malformed,
    /// The list holds more than [`MAX_SESSION_CREDENTIALS`] credentials.
    TooMany,
    /// Two credentials share a session id.
    DuplicateSession,
}

impl std::fmt::Display for BindingsDecodeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "persisted credentials are malformed",
            Self::TooMany => "persisted credentials exceed the per-channel bound",
            Self::DuplicateSession => "persisted credentials repeat a session id",
        })
    }
}

impl std::error::Error for BindingsDecodeRefusal {}

/// The persisted form of `bindings`. An encoding failure yields empty bytes,
/// which [`decode_bindings`] refuses.
#[must_use]
pub fn encode_bindings(bindings: &SessionBindings) -> Vec<u8> {
    serde_json::to_vec(&bindings.credentials).unwrap_or_default()
}

/// Parse persisted bindings, re-proving every credential invariant.
///
/// # Errors
///
/// [`BindingsDecodeRefusal`] for malformed bytes, an empty field, more than
/// [`MAX_SESSION_CREDENTIALS`] credentials, or a repeated session id.
pub fn decode_bindings(bytes: &[u8]) -> Result<SessionBindings, BindingsDecodeRefusal> {
    let credentials: Vec<SessionCredential> =
        serde_json::from_slice(bytes).map_err(|_| BindingsDecodeRefusal::Malformed)?;
    if credentials.len() > MAX_SESSION_CREDENTIALS {
        return Err(BindingsDecodeRefusal::TooMany);
    }
    let mut bindings = SessionBindings::default();
    for credential in credentials {
        if bindings
            .credentials
            .iter()
            .any(|held| held.session == credential.session)
        {
            return Err(BindingsDecodeRefusal::DuplicateSession);
        }
        bindings.credentials.push(credential);
    }
    Ok(bindings)
}

// ─── Generation ───────────────────────────────────────────────────────────────

/// The process revocation generation; every revocation write bumps it.
#[cfg(feature = "tokio")]
fn generation() -> &'static tokio::sync::watch::Sender<u64> {
    static GENERATION: OnceLock<tokio::sync::watch::Sender<u64>> = OnceLock::new();
    GENERATION.get_or_init(|| tokio::sync::watch::Sender::new(0))
}

/// Bump the generation so every subscriber re-proves its credentials.
#[cfg(feature = "tokio")]
fn bump_generation() {
    generation().send_modify(|generation| *generation = generation.wrapping_add(1));
}

/// No subscriber exists without `tokio`.
#[cfg(not(feature = "tokio"))]
const fn bump_generation() {}

/// A receiver that observes every later generation bump; `watch` keeps only
/// the latest value, so no bump is lost to a full buffer.
#[cfg(feature = "tokio")]
#[must_use]
pub fn subscribe() -> tokio::sync::watch::Receiver<u64> {
    generation().subscribe()
}

// ─── Process mode ─────────────────────────────────────────────────────────────

/// Set once any `Server` route is built with [`RevocationMode::Store`]; never
/// cleared.
#[cfg(feature = "server")]
static SERVER_ARMED: AtomicBool = AtomicBool::new(false);

/// Arm the process: every later [`process_mode`] is `Store`.
#[cfg(feature = "server")]
pub fn arm_process() {
    SERVER_ARMED.store(true, Ordering::Release);
}

/// The mode armed `Server` routes impose on the process.
#[cfg(feature = "server")]
fn server_floor() -> RevocationMode {
    if SERVER_ARMED.load(Ordering::Acquire) {
        RevocationMode::Store
    } else {
        RevocationMode::Off
    }
}

/// No `Server` route exists without `server`.
#[cfg(not(feature = "server"))]
const fn server_floor() -> RevocationMode {
    RevocationMode::Off
}

/// The process-wide revocation mode: the stricter of the installed
/// `Web.withRevocation`, the `IPE_AUTH_REVOCATION` floor (read once), and any
/// armed `Server` route.
#[must_use]
pub fn process_mode() -> RevocationMode {
    static ENV_FLOOR: OnceLock<RevocationMode> = OnceLock::new();
    let env_floor = *ENV_FLOOR.get_or_init(crate::app_config::env_revocation_floor);
    crate::app_config::installed_revocation_mode()
        .stricter(env_floor)
        .stricter(server_floor())
}

// ─── Kernel implementations ───────────────────────────────────────────────────
//
// These are the Ipê-facing Task-returning functions that correspond to the
// `Ipe.Auth.Revocation` stdlib surface:
//   revokeUser    : Principal -> String -> Task Error ()
//   revokeSession : Principal -> String -> Int -> Task Error ()
//   restoreUser   : Principal -> String -> Task Error ()
//   isRevoked     : String -> Task Error Bool
//
// The `Principal` parameter enforces that only an authenticated caller can write
// to the store — an unauthenticated Ipê term cannot produce a `Principal`.

/// `Ipe.Auth.Revocation.revokeUser : Principal -> String -> Task Error ()`.
/// Marks every session of `subject` revoked. Requires an authenticated `Principal`
/// (only an authenticated caller can revoke).
pub fn auth_revocation_revoke_user<E: From<String> + Send + 'static>(
    _caller: crate::principal::Principal,
    subject: String,
) -> IpeTask<E, ()> {
    Box::pin(async move {
        match revoke_subject(subject) {
            Ok(()) => IpeResult::Ok(()),
            Err(e) => IpeResult::Err(format!("Auth.Revocation.revokeUser: {e}").into()),
        }
    })
}

/// `Ipe.Auth.Revocation.revokeSession : Principal -> String -> Int -> Task Error ()`.
/// Marks the specific session `jti` revoked. `cap_unix_secs` is the token's
/// absolute-lifetime cap claim — required so the store can later reclaim the
/// entry once it is provably redundant (the JWT `cap` gate denies it anyway).
/// Requires an authenticated `Principal`.
pub fn auth_revocation_revoke_session<E: From<String> + Send + 'static>(
    _caller: crate::principal::Principal,
    jti: String,
    cap_unix_secs: i64,
) -> IpeTask<E, ()> {
    Box::pin(async move {
        match revoke_session(jti, cap_unix_secs) {
            Ok(()) => IpeResult::Ok(()),
            Err(e) => IpeResult::Err(format!("Auth.Revocation.revokeSession: {e}").into()),
        }
    })
}

/// `Ipe.Auth.Revocation.restoreUser : Principal -> String -> Task Error ()`.
/// Clears the subject-level revocation. Requires an authenticated `Principal`.
pub fn auth_revocation_restore_user<E: From<String> + Send + 'static>(
    _caller: crate::principal::Principal,
    subject: String,
) -> IpeTask<E, ()> {
    Box::pin(async move {
        match restore_subject(&subject) {
            Ok(()) => IpeResult::Ok(()),
            Err(e) => IpeResult::Err(format!("Auth.Revocation.restoreUser: {e}").into()),
        }
    })
}

/// `Ipe.Auth.Revocation.isRevoked : String -> Task Error Bool`.
/// Queries whether `subject` is in the subject-revocation map. No `Principal`
/// required — this is a read-only query intended for admin/UI flows.
pub fn auth_revocation_is_revoked<E: From<String> + Send + 'static>(
    subject: String,
) -> IpeTask<E, bool> {
    Box::pin(async move {
        match subject_is_revoked(&subject) {
            Ok(b) => IpeResult::Ok(b),
            Err(e) => IpeResult::Err(format!("Auth.Revocation.isRevoked: {e}").into()),
        }
    })
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::principal::principal_mint;

    // Each test uses unique subject/jti strings to avoid cross-test state
    // contamination (the store is process-global). Tests that need a small
    // capacity bound operate on a local RevocationStore directly.

    const FAR_FUTURE: i64 = i64::MAX / 2;

    #[test]
    fn a_refused_capacity_builds_no_store_and_names_its_variable() {
        crate::system::locked_set_var("IPE_REVOCATION_CAPACITY", "1k");
        let refused = store_with(crate::app_config::resolve_revocation_capacity());
        crate::system::locked_set_var("IPE_REVOCATION_CAPACITY", "16");
        let accepted = store_with(crate::app_config::resolve_revocation_capacity());
        crate::system::locked_remove_var("IPE_REVOCATION_CAPACITY");
        assert!(accepted.is_ok(), "a well-formed capacity builds a store");
        match guard_of(&refused) {
            Err(RevocationError::Misconfigured(refusal)) => {
                assert_eq!(refusal.name(), "IPE_REVOCATION_CAPACITY");
            }
            Err(other) => panic!("a refused capacity must name its variable, got {other}"),
            Ok(_) => panic!("a malformed capacity must build no store"),
        }
        let shown = guard_of(&refused).err().map(|e| e.to_string());
        assert!(
            shown.is_some_and(|s| s.contains("IPE_REVOCATION_CAPACITY")),
            "the write error names the refused variable"
        );
    }

    #[test]
    fn a_refused_lifetime_still_records_a_never_expiring_revocation() {
        let subject = "refused-lifetime-subject-001";
        crate::system::locked_set_var("IPE_AUTH_MAX_LIFETIME", "8h");
        let outcome = revoke_subject(subject.to_string());
        crate::system::locked_remove_var("IPE_AUTH_MAX_LIFETIME");
        assert_eq!(outcome, Ok(()), "a revocation is never dropped");
        assert_eq!(is_revoked(subject, "any-jti"), Verdict::Revoked);
        let expiry = lock().ok().and_then(|g| g.subjects.get(subject).copied());
        assert_eq!(
            expiry,
            Some(i64::MAX),
            "an unknown lifetime keeps the entry until restored"
        );
    }

    // ─── Existing behaviour tests (updated for new signatures) ────────────────

    #[test]
    fn active_when_not_revoked() {
        let v = is_revoked("fresh-user", "fresh-jti-001");
        assert!(
            matches!(v, Verdict::Active),
            "an unknown subject/jti must be Active"
        );
    }

    #[test]
    fn revoked_subject_denied() {
        revoke_subject("revoked-subject-001".to_string()).unwrap();
        assert!(
            matches!(
                is_revoked("revoked-subject-001", "any-jti"),
                Verdict::Revoked
            ),
            "a revoked subject must yield Revoked"
        );
    }

    #[test]
    fn revoked_session_denied_other_sessions_unaffected() {
        revoke_session("revoked-jti-001".to_string(), FAR_FUTURE).unwrap();
        assert!(
            matches!(is_revoked("subj-001", "revoked-jti-001"), Verdict::Revoked),
            "a revoked session must yield Revoked"
        );
        assert!(
            matches!(is_revoked("subj-001", "other-jti-001"), Verdict::Active),
            "other sessions of the same subject must remain Active"
        );
    }

    #[test]
    fn restore_clears_subject_revocation() {
        revoke_subject("restore-subj-001".to_string()).unwrap();
        assert!(
            matches!(is_revoked("restore-subj-001", "any-jti"), Verdict::Revoked),
            "must be Revoked before restore"
        );
        restore_subject("restore-subj-001").unwrap();
        assert!(
            matches!(is_revoked("restore-subj-001", "any-jti-b"), Verdict::Active),
            "must be Active after restore"
        );
    }

    #[tokio::test]
    async fn revoke_user_kernel_requires_principal() {
        let p = principal_mint("admin".to_string());
        let result: IpeResult<String, ()> =
            auth_revocation_revoke_user(p, "kernel-subj-001".to_string()).await;
        assert!(
            matches!(result, IpeResult::Ok(())),
            "revokeUser with a Principal must succeed"
        );
        assert!(
            matches!(is_revoked("kernel-subj-001", "jti"), Verdict::Revoked),
            "subject must be Revoked after kernel call"
        );
    }

    #[tokio::test]
    async fn restore_user_kernel_re_allows() {
        let p = principal_mint("admin".to_string());
        let p2 = principal_mint("admin".to_string());
        let _: IpeResult<String, ()> =
            auth_revocation_revoke_user(p, "restore-kernel-subj-001".to_string()).await;
        let r: IpeResult<String, ()> =
            auth_revocation_restore_user(p2, "restore-kernel-subj-001".to_string()).await;
        assert!(matches!(r, IpeResult::Ok(())), "restoreUser must succeed");
        assert!(
            matches!(
                is_revoked("restore-kernel-subj-001", "jti"),
                Verdict::Active
            ),
            "subject must be Active after restoreUser"
        );
    }

    #[tokio::test]
    async fn is_revoked_kernel_reflects_store() {
        let p = principal_mint("admin".to_string());
        let _: IpeResult<String, ()> =
            auth_revocation_revoke_user(p, "is-revoked-subj-001".to_string()).await;
        let r: IpeResult<String, bool> =
            auth_revocation_is_revoked("is-revoked-subj-001".to_string()).await;
        assert!(
            matches!(r, IpeResult::Ok(true)),
            "isRevoked must return true for a revoked subject"
        );
        let r2: IpeResult<String, bool> =
            auth_revocation_is_revoked("not-revoked-subj-999".to_string()).await;
        assert!(
            matches!(r2, IpeResult::Ok(false)),
            "isRevoked must return false for a non-revoked subject"
        );
    }

    // ─── Bounded-store unit tests (operate on a local RevocationStore) ────────

    fn local_store(capacity: usize) -> RevocationStore {
        RevocationStore::new(capacity)
    }

    fn now_approx() -> i64 {
        crate::jwt::now_unix_seconds()
    }

    // Test 1 — ceiling reached → live revoke still denied.
    //
    // Fill a small store to capacity with non-expired sessions, attempt one more
    // insert, assert it returns AtCapacity, and assert every already-recorded id
    // is still present. The store denied the write, not the invariant.
    #[test]
    fn ceiling_reached_live_revoke_still_denied() {
        let cap = 4usize;
        let mut s = local_store(cap);
        let now = now_approx();
        let live_expiry = now + 99_999;

        for i in 0..cap {
            let jti = format!("ceil-live-jti-{i:04}");
            s.insert_bounded(MapSelector::Sessions, jti, live_expiry, now)
                .expect("insert must succeed while under capacity");
        }
        let overflow = "ceil-overflow-jti".to_string();
        let result = s.insert_bounded(MapSelector::Sessions, overflow, live_expiry, now);
        assert!(
            matches!(result, Err(RevocationError::AtCapacity)),
            "insert beyond capacity must return AtCapacity"
        );
        for i in 0..cap {
            let jti = format!("ceil-live-jti-{i:04}");
            assert!(
                s.sessions.contains_key(&jti),
                "live entry {jti} must still be present after AtCapacity"
            );
        }
    }

    // Test 2 — does-not-drop-a-live-revoke property.
    //
    // Over a sequence of inserts (all with future expiries) up to and past the
    // ceiling, assert that no id that was successfully inserted ever disappears.
    #[test]
    fn does_not_drop_a_live_revocation() {
        let cap = 5usize;
        let mut s = local_store(cap);
        let now = now_approx();
        let live_expiry = now + 99_999;
        let mut recorded: Vec<String> = Vec::new();

        for i in 0..(cap * 2) {
            let jti = format!("no-drop-jti-{i:04}");
            let outcome = s.insert_bounded(MapSelector::Sessions, jti.clone(), live_expiry, now);
            if outcome.is_ok() {
                recorded.push(jti);
            }
            for prior in &recorded {
                assert!(
                    s.sessions.contains_key(prior),
                    "live entry {prior} must not be dropped — invariant violated"
                );
            }
        }
    }

    // Test 3 — reclamation frees room for a real insert.
    #[test]
    fn reclamation_frees_room_for_new_insert() {
        let cap = 3usize;
        let mut s = local_store(cap);
        let now = now_approx();
        let live_expiry = now + 99_999;
        let past_expiry = now - 1;

        s.insert_bounded(
            MapSelector::Sessions,
            "reclaim-expired-jti".to_string(),
            past_expiry,
            now,
        )
        .expect("expired entry insert must succeed");

        for i in 0..(cap - 1) {
            let jti = format!("reclaim-live-jti-{i:04}");
            s.insert_bounded(MapSelector::Sessions, jti, live_expiry, now)
                .expect("live insert must succeed");
        }
        let result = s.insert_bounded(
            MapSelector::Sessions,
            "reclaim-new-jti".to_string(),
            live_expiry,
            now,
        );
        assert!(
            result.is_ok(),
            "insert after reclamation of expired entry must succeed"
        );
        assert!(
            !s.sessions.contains_key("reclaim-expired-jti"),
            "expired entry must have been swept out"
        );
        assert!(
            s.sessions.contains_key("reclaim-new-jti"),
            "newly inserted entry must be present"
        );
    }

    // Test 4 — sweep drops only expired entries.
    #[test]
    fn sweep_drops_only_expired_entries() {
        let cap = 6usize;
        let mut s = local_store(cap);
        let now = now_approx();
        let live_expiry = now + 99_999;
        let past_expiry = now - 1;

        for i in 0..3usize {
            s.insert_bounded(
                MapSelector::Sessions,
                format!("sweep-expired-jti-{i:04}"),
                past_expiry,
                now,
            )
            .expect("insert must succeed");
            s.insert_bounded(
                MapSelector::Sessions,
                format!("sweep-live-jti-{i:04}"),
                live_expiry,
                now,
            )
            .expect("insert must succeed");
        }
        s.insert_bounded(
            MapSelector::Sessions,
            "sweep-trigger-jti".to_string(),
            live_expiry,
            now,
        )
        .expect("sweep must reclaim the three expired entries and admit this one");

        for i in 0..3usize {
            assert!(
                !s.sessions
                    .contains_key(&format!("sweep-expired-jti-{i:04}")),
                "expired entry sweep-expired-jti-{i:04} must have been removed"
            );
        }
        for i in 0..3usize {
            assert!(
                s.sessions.contains_key(&format!("sweep-live-jti-{i:04}")),
                "live entry sweep-live-jti-{i:04} must still be present"
            );
        }
        assert!(
            s.sessions.contains_key("sweep-trigger-jti"),
            "newly inserted trigger entry must be present"
        );
    }

    // Test 5 — AtCapacity error surfaces correctly (maps to Task Error ()).
    #[test]
    fn at_capacity_error_surfaces_as_task_error() {
        let cap = 2usize;
        let mut s = local_store(cap);
        let now = now_approx();
        let live_expiry = now + 99_999;

        for i in 0..cap {
            s.insert_bounded(
                MapSelector::Sessions,
                format!("task-err-jti-{i:04}"),
                live_expiry,
                now,
            )
            .expect("insert must succeed");
        }
        let err = s
            .insert_bounded(
                MapSelector::Sessions,
                "task-err-overflow".to_string(),
                live_expiry,
                now,
            )
            .expect_err("must return AtCapacity");
        assert_eq!(err, RevocationError::AtCapacity);
        assert!(!err.to_string().is_empty());
    }

    // Test 6 — subject expiry covers all live sessions.
    #[test]
    fn subject_expiry_covers_live_sessions() {
        let mut s = local_store(8);
        let now = now_approx();
        let max_lifetime = i64::try_from(
            crate::app_config::resolve_auth_max_lifetime().expect("the default lifetime resolves"),
        )
        .unwrap_or(i64::MAX);
        let subject_expiry = now.saturating_add(max_lifetime);

        s.insert_bounded(
            MapSelector::Subjects,
            "cover-subj-001".to_string(),
            subject_expiry,
            now,
        )
        .expect("subject insert must succeed");

        // Fill the remaining 7 slots.
        for i in 0..7usize {
            s.insert_bounded(
                MapSelector::Subjects,
                format!("cover-filler-{i:04}"),
                subject_expiry + 1,
                now,
            )
            .expect("filler insert must succeed");
        }
        // Trigger sweep at sweep_now = subject_expiry - 1.
        // All entries have expiry >= subject_expiry > sweep_now → nothing swept → AtCapacity.
        let sweep_now = subject_expiry - 1;
        let result = s.insert_bounded(
            MapSelector::Subjects,
            "cover-trigger".to_string(),
            subject_expiry + 1,
            sweep_now,
        );
        assert!(
            matches!(result, Err(RevocationError::AtCapacity)),
            "no entries are past expiry at sweep_now == subject_expiry - 1"
        );
        assert!(
            s.subjects.contains_key("cover-subj-001"),
            "subject entry must survive sweep at boundary"
        );
    }

    // Test 7 — re-revoke takes the max expiry, never shortens.
    #[test]
    fn re_revoke_takes_max_expiry() {
        let mut s = local_store(8);
        let now = now_approx();
        let first_expiry = now + 1_000;
        let later_expiry = now + 9_999;

        s.insert_bounded(
            MapSelector::Sessions,
            "rerevoke-jti".to_string(),
            first_expiry,
            now,
        )
        .expect("first insert must succeed");
        s.insert_bounded(
            MapSelector::Sessions,
            "rerevoke-jti".to_string(),
            later_expiry,
            now,
        )
        .expect("re-revoke must succeed");
        assert_eq!(
            *s.sessions.get("rerevoke-jti").expect("must be present"),
            later_expiry,
            "re-revoke must take the max expiry"
        );

        s.insert_bounded(
            MapSelector::Sessions,
            "rerevoke-jti".to_string(),
            first_expiry,
            now,
        )
        .expect("re-revoke with shorter expiry must succeed");
        assert_eq!(
            *s.sessions.get("rerevoke-jti").expect("must be present"),
            later_expiry,
            "re-revoke with shorter expiry must not shorten the stored expiry"
        );
    }

    // ─── proptest: no live revocation is ever dropped ────────────────────────

    use proptest::prelude::*;

    proptest! {
        /// For an arbitrary sequence of session inserts with future expiries,
        /// no id that was successfully inserted ever disappears from the map
        /// while its expiry is still in the future.
        #[test]
        fn prop_no_live_revocation_dropped(
            inserts in proptest::collection::vec((0u8..16, 1u32..100_000), 1..20)
        ) {
            let cap = 8usize;
            let mut s = local_store(cap);
            let now = now_approx();
            let mut recorded: Vec<String> = Vec::new();

            for (suffix, offset) in inserts {
                let jti = format!("prop-jti-{suffix:02x}");
                let expiry = now + i64::from(offset);
                let outcome = s.insert_bounded(MapSelector::Sessions, jti.clone(), expiry, now);
                if outcome.is_ok() && !recorded.contains(&jti) {
                    recorded.push(jti.clone());
                }
                // Invariant: every successfully recorded live id must still be present.
                for id in &recorded {
                    prop_assert!(
                        s.sessions.contains_key(id),
                        "live revocation {id} was dropped — invariant violated"
                    );
                }
            }
        }
    }

    // ─── The gate ─────────────────────────────────────────────────────────────

    const GATE_SECRET: &str = "a-test-secret-of-32-bytes-padding";

    /// A lifetime bound far past any test run.
    const LIVE_UNTIL: i64 = 9_999_999_999;

    fn gate() -> ArmedGate {
        ArmedGate::resolve(RevocationMode::Store).expect("`Store` arms the gate")
    }

    fn healthy_store() -> StoreSlot {
        store_with(Ok(16))
    }

    /// The verified claims of a token signed with `claims`.
    fn claims_of(claims: &serde_json::Value) -> VerifiedClaims {
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let key = jsonwebtoken::EncodingKey::from_secret(GATE_SECRET.as_bytes());
        let token = jsonwebtoken::encode(&header, claims, &key).expect("encode");
        crate::auth::verify_claims(GATE_SECRET, &token).expect("verify")
    }

    /// The verified claims of a live token for `sub` with session id `jti`.
    fn live_claims(sub: &str, jti: &str) -> VerifiedClaims {
        claims_of(&serde_json::json!({ "sub": sub, "jti": jti, "exp": LIVE_UNTIL }))
    }

    /// A credential the gate admitted from a healthy store.
    fn admitted(sub: &str, jti: &str) -> SessionCredential {
        gate()
            .admit_in(&healthy_store(), &live_claims(sub, jti), "sub")
            .expect("a live token is admitted")
    }

    /// A store whose capacity setting the runtime refused.
    fn refused_store() -> StoreSlot {
        crate::system::locked_set_var("IPE_REVOCATION_CAPACITY", "1k");
        let refused = store_with(crate::app_config::resolve_revocation_capacity());
        crate::system::locked_remove_var("IPE_REVOCATION_CAPACITY");
        assert!(refused.is_err(), "a malformed capacity builds no store");
        refused
    }

    #[test]
    fn admit_denies_revoked_subject() {
        let store = healthy_store();
        revoke_subject_in(&store, "g1-subject".to_owned()).expect("revoke");
        assert_eq!(
            gate().admit_in(&store, &live_claims("g1-subject", "g1-jti"), "sub"),
            Err(Denial::Revoked)
        );
        assert!(
            gate()
                .admit_in(&store, &live_claims("g1-other", "g1-jti"), "sub")
                .is_ok(),
            "another subject is unaffected"
        );
    }

    #[test]
    fn admit_denies_revoked_session() {
        let store = healthy_store();
        revoke_session_in(&store, "g1-session".to_owned(), LIVE_UNTIL).expect("revoke");
        assert_eq!(
            gate().admit_in(&store, &live_claims("g1-subject", "g1-session"), "sub"),
            Err(Denial::Revoked)
        );
        let credential = admitted("g1-subject", "g1-session");
        assert_eq!(
            gate().recheck_in(&store, &credential, 0),
            Err(Denial::Revoked),
            "a held credential of a revoked session fails its recheck"
        );
    }

    #[test]
    fn admit_denies_when_store_unavailable() {
        let claims = live_claims("g2-subject", "g2-jti");
        let credential = admitted("g2-subject", "g2-jti");
        let refused = refused_store();
        assert_eq!(
            gate().admit_in(&refused, &claims, "sub"),
            Err(Denial::StoreUnavailable)
        );
        assert_eq!(
            gate().recheck_in(&refused, &credential, 0),
            Err(Denial::StoreUnavailable)
        );
        let poisoned = healthy_store();
        if let Ok(mutex) = &poisoned {
            std::thread::scope(|scope| {
                let poisoner = std::thread::Builder::new().spawn_scoped(scope, || {
                    let _held = mutex.lock();
                    std::panic::resume_unwind(Box::new("poison the store lock"));
                });
                if let Ok(handle) = poisoner {
                    assert!(handle.join().is_err(), "the poisoner unwinds");
                }
            });
        }
        assert!(
            poisoned.as_ref().is_ok_and(Mutex::is_poisoned),
            "the store lock is poisoned"
        );
        assert_eq!(
            gate().admit_in(&poisoned, &claims, "sub"),
            Err(Denial::StoreUnavailable)
        );
        assert_eq!(
            gate().recheck_in(&poisoned, &credential, 0),
            Err(Denial::StoreUnavailable)
        );
    }

    #[test]
    fn admit_refuses_absent_or_empty_subject() {
        let store = healthy_store();
        for claims in [
            serde_json::json!({ "jti": "g3-jti", "exp": LIVE_UNTIL }),
            serde_json::json!({ "sub": "", "jti": "g3-jti", "exp": LIVE_UNTIL }),
        ] {
            assert_eq!(
                gate().admit_in(&store, &claims_of(&claims), "sub"),
                Err(Denial::SubjectAbsent)
            );
        }
        assert_eq!(
            gate().admit_in(&store, &live_claims("g3-subject", "g3-jti"), "uid"),
            Err(Denial::SubjectAbsent),
            "the subject is read from the configured claim only"
        );
    }

    #[test]
    fn admit_refuses_absent_or_empty_jti() {
        let store = healthy_store();
        for claims in [
            serde_json::json!({ "sub": "g3-subject", "exp": LIVE_UNTIL }),
            serde_json::json!({ "sub": "g3-subject", "jti": "", "exp": LIVE_UNTIL }),
        ] {
            assert_eq!(
                gate().admit_in(&store, &claims_of(&claims), "sub"),
                Err(Denial::SessionIdAbsent)
            );
        }
    }

    #[test]
    fn admit_refuses_no_deadline() {
        // A verified token always carries `exp`, so the reachable no-deadline
        // case is an unreadable `cap`, which `exp` never stands in for.
        let claims = claims_of(&serde_json::json!({
            "sub": "g3-subject",
            "jti": "g3-jti",
            "exp": LIVE_UNTIL,
            "cap": "soon",
        }));
        assert_eq!(
            gate().admit_in(&healthy_store(), &claims, "sub"),
            Err(Denial::NoDeadline)
        );
    }

    #[test]
    fn recheck_denies_at_deadline_exactly() {
        let deadline = LIVE_UNTIL - 1000;
        let credential = gate()
            .admit_in(
                &healthy_store(),
                &claims_of(&serde_json::json!({
                    "sub": "g4-subject",
                    "jti": "g4-jti",
                    "exp": LIVE_UNTIL,
                    "cap": deadline,
                })),
                "sub",
            )
            .expect("admitted");
        assert_eq!(
            credential.deadline(),
            UnixSecs(deadline),
            "`cap` is the deadline"
        );
        let store = healthy_store();
        assert_eq!(
            gate().recheck_in(&store, &credential, deadline),
            Err(Denial::PastDeadline)
        );
        assert_eq!(gate().recheck_in(&store, &credential, deadline - 1), Ok(()));
        let exp_only = admitted("g4-subject", "g4-exp-jti");
        assert_eq!(
            exp_only.deadline(),
            UnixSecs(LIVE_UNTIL),
            "`exp` is the deadline of a token with no `cap`"
        );
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn refused_revocation_write_still_bumps_generation() {
        let full = store_with(Ok(1));
        revoke_session_in(&full, "g5-first".to_owned(), LIVE_UNTIL).expect("room for one");
        let mut changes = subscribe();
        assert_eq!(
            revoke_session_in(&full, "g5-second".to_owned(), LIVE_UNTIL),
            Err(RevocationError::AtCapacity)
        );
        assert!(
            changes.has_changed().expect("the sender lives"),
            "a refused write bumps the generation"
        );
        changes.mark_unchanged();
        assert!(revoke_subject_in(&refused_store(), "g5-subject".to_owned()).is_err());
        assert!(
            changes.has_changed().expect("the sender lives"),
            "a write to a refused store bumps the generation"
        );
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn restore_does_not_bump_generation() {
        revoke_subject("g6-subject".to_owned()).expect("revoke");
        let changes = subscribe();
        restore_subject("g6-subject").expect("restore");
        assert!(
            !changes.has_changed().expect("the sender lives"),
            "a restore re-admits nothing held, so it bumps nothing"
        );
    }

    #[test]
    fn session_credential_debug_masks_subject_and_jti() {
        let credential = admitted("g7-S3CR3T-subject", "g7-J71-session");
        let shown = format!("{credential:?}");
        assert!(!shown.contains("S3CR3T"), "{shown}");
        assert!(!shown.contains("J71"), "{shown}");
        assert!(shown.contains(&LIVE_UNTIL.to_string()), "{shown}");
    }

    #[test]
    fn session_credential_deserialize_refuses_empty_fields() {
        let parse = serde_json::from_str::<SessionCredential>;
        assert!(parse(r#"{"sub":"","jti":"g8-jti","deadline":1}"#).is_err());
        assert!(parse(r#"{"sub":"g8-subject","jti":"","deadline":1}"#).is_err());
        assert!(parse(r#"{"sub":"g8-subject","jti":"g8-jti"}"#).is_err());
        assert!(parse(r#"{"sub":"g8-subject","jti":"g8-jti","deadline":1,"role":"x"}"#).is_err());
        let parsed = parse(r#"{"sub":"g8-subject","jti":"g8-jti","deadline":1}"#)
            .expect("a complete credential parses");
        assert_eq!(parsed.deadline(), UnixSecs(1));
    }

    #[test]
    fn encode_decode_bindings_round_trip() {
        let empty = SessionBindings::default();
        assert_eq!(decode_bindings(&encode_bindings(&empty)), Ok(empty));
        let mut bindings = SessionBindings::default();
        bindings
            .bind(admitted("g9-subject", "g9-jti-a"))
            .expect("bind");
        bindings
            .bind(admitted("g9-subject", "g9-jti-b"))
            .expect("bind");
        assert_eq!(
            decode_bindings(&encode_bindings(&bindings)),
            Ok(bindings.clone())
        );
        assert_eq!(bindings.len(), 2);
    }

    /// The persisted form of credentials named `jtis`.
    fn wire_of(jtis: &[String]) -> Vec<u8> {
        let wire: Vec<serde_json::Value> = jtis
            .iter()
            .map(|jti| serde_json::json!({ "sub": "g9-subject", "jti": jti, "deadline": LIVE_UNTIL }))
            .collect();
        serde_json::to_vec(&wire).expect("encode")
    }

    #[test]
    fn decode_bindings_refuses_nine_and_empty_fields() {
        let jtis: Vec<String> = (0..=MAX_SESSION_CREDENTIALS)
            .map(|n| format!("g9-jti-{n}"))
            .collect();
        assert_eq!(
            decode_bindings(&wire_of(&jtis)),
            Err(BindingsDecodeRefusal::TooMany)
        );
        let bound = jtis.get(..MAX_SESSION_CREDENTIALS).expect("eight ids");
        assert_eq!(
            decode_bindings(&wire_of(bound)).map(|b| b.len()),
            Ok(MAX_SESSION_CREDENTIALS),
            "the last legal count decodes"
        );
        assert_eq!(
            decode_bindings(&wire_of(&[String::new()])),
            Err(BindingsDecodeRefusal::Malformed)
        );
        assert_eq!(
            decode_bindings(&wire_of(&["g9-twice".to_owned(), "g9-twice".to_owned()])),
            Err(BindingsDecodeRefusal::DuplicateSession)
        );
        assert_eq!(decode_bindings(b""), Err(BindingsDecodeRefusal::Malformed));
    }

    #[test]
    fn bind_keeps_the_earlier_deadline_and_refuses_the_ninth() {
        let mut bindings = SessionBindings::default();
        for n in 0..MAX_SESSION_CREDENTIALS {
            bindings
                .bind(admitted("bind-subject", &format!("bind-jti-{n}")))
                .expect("within the bound");
        }
        assert_eq!(
            bindings.bind(admitted("bind-subject", "bind-jti-ninth")),
            Err(Denial::BindingsFull)
        );
        assert_eq!(bindings.len(), MAX_SESSION_CREDENTIALS);
        assert!(!bindings.binds_session("bind-jti-ninth"));
        let early = gate()
            .admit_in(
                &healthy_store(),
                &claims_of(&serde_json::json!({
                    "sub": "bind-subject",
                    "jti": "bind-jti-0",
                    "exp": LIVE_UNTIL,
                    "cap": LIVE_UNTIL - 5,
                })),
                "sub",
            )
            .expect("admitted");
        bindings.bind(early).expect("a held session id rebinds");
        assert_eq!(bindings.len(), MAX_SESSION_CREDENTIALS);
        assert_eq!(bindings.earliest_deadline(), Some(UnixSecs(LIVE_UNTIL - 5)));
    }
}
