//! Runtime revocation store — the session-layer fail-closed gate.
//!
//! The store holds revoked subjects (every session of that user) and revoked
//! session ids (`jti`, one specific session). Its sole question is boolean.
//!
//! # Fail-closed
//!
//! `is_revoked` returns [`Verdict::Revoked`] on a positive hit, [`Verdict::Unknown`]
//! on any store error, and [`Verdict::Active`] only when the store is healthy and
//! the subject/session is absent from both maps. The `authed_route` middleware
//! denies on `Revoked` **and** on `Unknown` — a degraded store denies, never admits.
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
use std::sync::{Mutex, MutexGuard, OnceLock};

use super::*;

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
    /// The map is at its ceiling and no expired entries could be reclaimed.
    /// The new revocation was NOT recorded. The caller must escalate (e.g.
    /// rotate the signing key, which invalidates every session at once).
    AtCapacity,
}

impl std::fmt::Display for RevocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => write!(f, "revocation store unavailable"),
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

fn store() -> &'static Mutex<RevocationStore> {
    static STORE: OnceLock<Mutex<RevocationStore>> = OnceLock::new();
    STORE.get_or_init(|| {
        let capacity = crate::app_config::resolve_revocation_capacity();
        Mutex::new(RevocationStore::new(capacity))
    })
}

/// Acquire the store lock. Returns `None` on lock poison (fail-closed: the
/// caller treats `None` as [`Verdict::Unknown`] and denies the request).
fn lock() -> Option<MutexGuard<'static, RevocationStore>> {
    store().lock().ok()
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
    let Some(guard) = lock() else {
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
/// shortening the window.
pub fn revoke_subject(subject: String) -> Result<(), RevocationError> {
    let Some(mut guard) = lock() else {
        return Err(RevocationError::Unavailable);
    };
    let now = crate::jwt::now_unix_seconds();
    let max_lifetime =
        i64::try_from(crate::app_config::resolve_auth_max_lifetime()).unwrap_or(i64::MAX);
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
/// from that point, making the revocation entry redundant).
pub fn revoke_session(jti: String, cap_unix_secs: i64) -> Result<(), RevocationError> {
    let Some(mut guard) = lock() else {
        return Err(RevocationError::Unavailable);
    };
    let now = crate::jwt::now_unix_seconds();
    guard.insert_bounded(MapSelector::Sessions, jti, cap_unix_secs, now)
}

/// Clear the subject revocation for `subject`. After this call a new token for
/// that subject passes the revocation gate (existing `jti`-scoped entries are
/// unaffected — restoring the subject does not un-revoke specific sessions that
/// were independently revoked via `revoke_session`).
pub fn restore_subject(subject: &str) -> Result<(), RevocationError> {
    let Some(mut guard) = lock() else {
        return Err(RevocationError::Unavailable);
    };
    guard.subjects.remove(subject);
    Ok(())
}

/// Query whether `subject` is in the subject-revocation map. Does not check
/// session-scoped entries (a subject not in the map may still have a revoked
/// `jti`). Intended for the `isRevoked` app-facing kernel (an admin UI query),
/// not for the per-request auth gate (which calls [`is_revoked`]).
pub fn subject_is_revoked(subject: &str) -> Result<bool, RevocationError> {
    let Some(guard) = lock() else {
        return Err(RevocationError::Unavailable);
    };
    Ok(guard.subjects.contains_key(subject))
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
        let max_lifetime =
            i64::try_from(crate::app_config::resolve_auth_max_lifetime()).unwrap_or(i64::MAX);
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
}
