//! Session stores — the `SessionStore` abstraction + backends.
//!
//! A session's LIVE state (the tokio driver, SSE channel, rebuilt `HandlerIndex`)
//! is always per-process. A persistent backend additionally keeps a serialized
//! **checkpoint** of the model (+ metadata) so a returning cookie / a restart can
//! reconstruct the session. `get` returns only the in-process live handle
//! (which owns its driver); a checkpoint is decoded only by a claimed
//! `get_reconstructing`, which hands the caller the cold model beside the
//! claim that admits it, and the caller spawns a fresh driver seeded with it.

use super::SessionEntry;
use crate::retained::Bytes;
use crate::tea::IpeCmd;
use async_trait::async_trait;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Hard ceiling on a decoded checkpoint body. A persisted blob's length is
/// attacker-influenceable at the storage boundary (a corrupt / crafted at-rest
/// row); parsing an unbounded body would let a crafted length drive allocation
/// before any structural error. [`split_checkpoint`] turns any body length
/// beyond this into a clean miss (→ `None`, the same fail-soft path a corrupt
/// blob always took), refused BEFORE serde walks it (PRINCIPLES §3: a decode of
/// an absurd length is turned back). Mirrors [`super::additive`]'s own ceiling
/// so both decode boundaries share one limit. 64 MiB is far above any realistic
/// serialized Model yet far below a memory-pressure risk.
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
const MAX_CHECKPOINT_BYTES: u64 = 64 * 1024 * 1024;

/// Wire-format epoch for the Model schema tag (H24). Must equal the
/// backend's `emit_model_schema::WIRE_EPOCH` — the epoch is folded into the
/// compile-time `IPE_WEB_MODEL_SCHEMA_TAG` each generated Ipe.Web binary
/// carries. Bumped ONLY when the tag framing / blob encoding itself changes
/// shape (domain-separation convention), never for a Model change — the
/// Model's own shape is covered by the structural half of the hash.
///
/// `v2` framing carries a SELF-DESCRIBING (field-keyed JSON) Model body, so an
/// additive-superset checkpoint can be spliced onto a new Model's `init` (see
/// [`super::additive`]); `v1`'s positional bincode body could not be. Because
/// this epoch is folded into every binary's schema tag, a `v1` blob's leading
/// tag can never equal a `v2` binary's — an old-format checkpoint fails the
/// reject-before-deserialize gate and takes the clean re-init path, never a
/// mis-decode of positional bytes as JSON.
///
/// The credential section a checkpoint may carry is versioned by its in-band
/// marker ([`split_checkpoint`]), not by this epoch.
pub const WEB_MODEL_SCHEMA_WIRE_VERSION: &str = "ipe-live-model-schema-v2";

/// A checkpoint's persisted credential section, framed but never parsed here.
///
/// The Web session layer decodes and re-proves a `Present` section before a
/// row restores; this module only splits it off by its length.
#[derive(Clone, PartialEq, Eq)]
pub enum CredSection {
    /// The row carries no section: it was written by an unarmed process, or
    /// before rows carried one.
    Absent,
    /// The section's bytes, as the writer stored them.
    Present(Vec<u8>),
}

// The section names subjects and session ids, so `Debug` shows only its length.
impl std::fmt::Debug for CredSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent => f.write_str("Absent"),
            Self::Present(bytes) => f.debug_tuple("Present").field(&bytes.len()).finish(),
        }
    }
}

/// The longest subject or session id a persisted credential carries, in bytes.
pub const MAX_CRED_FIELD_BYTES: usize = 512;

/// The most credentials one persisted section holds.
pub const MAX_CRED_SECTION_CREDENTIALS: usize = 8;

/// The most bytes one input byte of a JSON string encodes to (`\u00XX`).
const MAX_JSON_ESCAPE_BYTES: usize = 6;

/// The bytes one encoded credential spends beyond its two text fields.
///
/// The keys and punctuation, and the longest `i64` deadline.
const CRED_ENTRY_FRAME_BYTES: usize =
    r#"{"sub":"","jti":"","deadline":}"#.len() + "-9223372036854775808".len();

/// The longest credential section a checkpoint carries.
///
/// A JSON list of [`MAX_CRED_SECTION_CREDENTIALS`] credentials whose subject
/// and session id are each [`MAX_CRED_FIELD_BYTES`] fully escaped bytes.
pub const MAX_CRED_SECTION_BYTES: usize = "[]".len()
    + MAX_CRED_SECTION_CREDENTIALS
        * (2 * MAX_JSON_ESCAPE_BYTES * MAX_CRED_FIELD_BYTES + CRED_ENTRY_FRAME_BYTES)
    + (MAX_CRED_SECTION_CREDENTIALS - 1);

// The section length travels as a `u16`, so every legal section fits it.
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the largest credential section outgrows its `u16` length prefix [ledger #boundary]
const _: () = assert!(MAX_CRED_SECTION_BYTES <= u16::MAX as usize);

/// The byte that opens a credential section after the tag.
///
/// No JSON text starts with it, so a sectionless body can never be read as
/// sectioned.
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
const CRED_SECTION_MARKER: u8 = 0x00;

/// The width of the big-endian section length after [`CRED_SECTION_MARKER`].
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
const CRED_SECTION_LEN_BYTES: usize = 2;

/// Encode one Model checkpoint, with the credential `section` when one is given.
///
/// Without a section the blob is `base64(schema_tag(32) ++ serde_json(model))`;
/// with one it is `base64(schema_tag(32) ++ 0x00 ++ u16_be(len) ++ section ++
/// serde_json(model))`. The blob is self-contained (the tag travels inside it)
/// and TEXT-column-safe on every backend (base64 never emits NUL or invalid
/// UTF-8, so no `ALTER TABLE` or BYTEA migration is ever needed). The body is
/// field-keyed JSON so a purely additive Model change can splice the old
/// fields onto the new `init` (see [`decode_or_reconstruct_checkpoint`]).
/// [`split_checkpoint`] is the one reader of this framing.
///
/// # Errors
///
/// The [`CheckpointRefusal`] naming what could not be framed; the caller reports
/// it as a write that did not land.
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
fn encode_checkpoint<Model: serde::Serialize>(
    schema_tag: &[u8; 32],
    section: Option<&[u8]>,
    model: &Model,
) -> Result<String, CheckpointRefusal> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let body = serde_json::to_vec(model).map_err(|_| CheckpointRefusal::Model)?;
    let framing = section.map_or(0, |bytes| 1 + CRED_SECTION_LEN_BYTES + bytes.len());
    let mut framed = Vec::with_capacity(32 + framing + body.len());
    framed.extend_from_slice(schema_tag);
    if let Some(bytes) = section {
        if bytes.len() > MAX_CRED_SECTION_BYTES {
            return Err(CheckpointRefusal::CredentialSectionOverCeiling);
        }
        let len = u16::try_from(bytes.len())
            .map_err(|_| CheckpointRefusal::CredentialSectionOverCeiling)?;
        framed.push(CRED_SECTION_MARKER);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(bytes);
    }
    framed.extend_from_slice(&body);
    Ok(B64.encode(framed))
}

/// The framed checkpoint of `parts`, or the fault a write of it reports.
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
fn frame_checkpoint<Model: serde::Serialize>(
    schema_tag: &[u8; 32],
    parts: &(Model, Option<Vec<u8>>),
) -> Result<String, WriteFault> {
    let (model, section) = parts;
    encode_checkpoint(schema_tag, section.as_deref(), model).map_err(WriteFault::Encode)
}

/// Why a checkpoint could not be framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointRefusal {
    /// Serde refused the model.
    Model,
    /// The credential section is longer than [`MAX_CRED_SECTION_BYTES`].
    CredentialSectionOverCeiling,
}

impl std::fmt::Display for CheckpointRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Model => "model not serializable",
            Self::CredentialSectionOverCeiling => "credential section over ceiling",
        })
    }
}

/// Why a session-store write did not land.
///
/// Credential-free by construction: every variant carries a typed, phrase-only
/// fault, never a driver message, the map path or the connection URL.
#[derive(Debug, Clone)]
pub enum WriteFault {
    /// The checkpoint could not be framed.
    Encode(CheckpointRefusal),
    /// The on-disk map was not rewritten.
    #[cfg(feature = "web")]
    File(Arc<PersistError>),
    /// The sqlx driver refused the statement.
    #[cfg(feature = "db")]
    Driver(crate::db::DriverFailure),
    /// The Redis command failed with this error kind.
    #[cfg(feature = "redis_store")]
    Redis(redis::ErrorKind),
}

impl std::fmt::Display for WriteFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session store write failed: ")?;
        match self {
            Self::Encode(refusal) => write!(f, "encode ({refusal})"),
            #[cfg(feature = "web")]
            Self::File(persist) => write!(f, "map write ({persist})"),
            #[cfg(feature = "db")]
            Self::Driver(failure) => write!(f, "statement ({failure})"),
            #[cfg(feature = "redis_store")]
            Self::Redis(kind) => write!(f, "command ({kind:?})"),
        }
    }
}

impl std::error::Error for WriteFault {}

#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
/// Logs the first failure after a success and the first success after a failure.
///
/// A failing backend yields one line per streak, not one per write.
struct FaultStreak(AtomicBool);

#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
impl FaultStreak {
    const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Whether the last observed write failed.
    #[cfg(test)]
    fn failing(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    /// The line this observation opens, when it starts or ends a streak.
    ///
    /// The text is `backend` and the fault's [`WriteFault`] Display only.
    fn transition(&self, backend: &'static str, failed: Option<&WriteFault>) -> Option<String> {
        let was_failing = self.0.swap(failed.is_some(), Ordering::Relaxed);
        match (failed, was_failing) {
            (Some(fault), false) => Some(format!(
                "session store ({backend}): write failed, sessions kept live and unevictable: {fault}"
            )),
            (None, true) => Some(format!("session store ({backend}): writes recovered")),
            (Some(_), true) | (None, false) => None,
        }
    }

    /// Pass a driver result through, logging the streak it starts or ends.
    fn observe<T>(
        &self,
        backend: &'static str,
        result: Result<T, WriteFault>,
    ) -> Result<T, WriteFault> {
        if let Some(line) = self.transition(backend, result.as_ref().err()) {
            crate::system::emit_runtime_log("live", &line);
        }
        result
    }
}

#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
/// Upper bound on the sids whose persisted row a `delete` could not remove.
///
/// Past it the store seals cold rejoin rather than restore a forgotten row.
const MAX_TOMBSTONES: NonZeroUsize = NonZeroUsize::MIN.saturating_add(4095);

#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
/// The sids held back from cold rejoin, and the last time one did not fit.
#[derive(Debug, Default)]
struct HeldBack {
    sids: std::collections::BTreeSet<String>,
    /// Unix seconds of the latest delete that failed while the set was full.
    ///
    /// That sid's row is not tracked, but its `last_seen` is no later than
    /// this instant, so every such row is idle-expired once the TTL cutoff
    /// passes it; until then every cold read misses.
    overflowed_at: Option<i64>,
}

#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
/// Sids whose persisted row a `delete` could not remove.
///
/// A tombstoned sid is never restored: its cold read re-attempts the delete
/// and answers a miss. A failed delete that finds the set at
/// [`MAX_TOMBSTONES`] seals the whole store's cold gate until every row it
/// could not track is past the idle TTL.
#[derive(Debug)]
struct Tombstones {
    held_back: Mutex<HeldBack>,
    ttl: Duration,
}

#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
/// What a cold read of a sid may do, judged by the store's tombstones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColdRead {
    /// Read the persisted row.
    Row,
    /// Re-attempt the delete the tombstone records, then miss.
    RetryDelete,
    /// Miss without touching the backend: the gate is sealed.
    Miss,
}

#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
impl Tombstones {
    fn new(ttl: Duration) -> Self {
        Self {
            held_back: Mutex::new(HeldBack::default()),
            ttl,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HeldBack> {
        self.held_back
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Hold `sid` back from cold rejoin; a full set seals the gate instead.
    fn record(&self, sid: &str) {
        self.record_at(sid, now_secs());
    }

    fn record_at(&self, sid: &str, now: i64) {
        let mut held = self.lock();
        if held.sids.contains(sid) {
            return;
        }
        if held.sids.len() >= MAX_TOMBSTONES.get() {
            held.overflowed_at = Some(now);
        } else {
            held.sids.insert(sid.to_owned());
        }
    }

    /// The row for `sid` is gone.
    fn landed(&self, sid: &str) {
        self.lock().sids.remove(sid);
    }

    fn cold_read(&self, sid: &str) -> ColdRead {
        self.cold_read_at(sid, now_secs())
    }

    fn cold_read_at(&self, sid: &str, now: i64) -> ColdRead {
        let held = self.lock();
        let cutoff = ttl_cutoff(now, self.ttl);
        if held.overflowed_at.is_some_and(|at| at >= cutoff) {
            ColdRead::Miss
        } else if held.sids.contains(sid) {
            ColdRead::RetryDelete
        } else {
            ColdRead::Row
        }
    }

    /// Every tombstoned sid, for a sweep's retries (at most [`MAX_TOMBSTONES`]).
    fn snapshot(&self) -> Vec<String> {
        self.lock().sids.iter().cloned().collect()
    }

    /// Settle a delete attempt for `sid` whose persisted step returned `removed`.
    ///
    /// A landed delete drops the tombstone; a failed one records it.
    fn retry(&self, sid: &str, removed: &Result<(), WriteFault>) {
        match removed {
            Ok(()) => self.landed(sid),
            Err(_) => self.record(sid),
        }
    }

    /// The outcome of a delete whose persisted step returned `removed`.
    fn deleted(&self, sid: &str, removed: Result<(), WriteFault>) -> Deleted {
        self.retry(sid, &removed);
        match removed {
            Ok(()) => Deleted::Removed,
            Err(fault) => Deleted::Pending(fault),
        }
    }
}

/// Split a persisted checkpoint blob into `(stored_tag, section, body)`.
///
/// The reader of [`encode_checkpoint`]'s framing. A body that opens with
/// [`CRED_SECTION_MARKER`] carries a section: its length must be present, at
/// most [`MAX_CRED_SECTION_BYTES`], and within the blob. The section is split
/// off by its length and never parsed here. The body length is bounded at
/// [`MAX_CHECKPOINT_BYTES`]. `None` on bad base64 (including a pre-`v2` row),
/// a blob shorter than the 32-byte tag, a section whose framing fails, or a
/// body past the ceiling — every one the same fail-soft miss the whole store
/// family takes. The tag is NOT compared here; the caller decides accept /
/// reconstruct / reject from the returned tag.
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
fn split_checkpoint(blob: &str) -> Option<([u8; 32], CredSection, Vec<u8>)> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let framed = B64.decode(blob.as_bytes()).ok()?;
    let tag: [u8; 32] = framed.get(..32)?.try_into().ok()?;
    let rest = framed.get(32..)?;
    let (section, body) = match rest.split_first() {
        Some((&CRED_SECTION_MARKER, framed_section)) => {
            let (len, after) = framed_section.split_first_chunk::<CRED_SECTION_LEN_BYTES>()?;
            let len = usize::from(u16::from_be_bytes(*len));
            if len > MAX_CRED_SECTION_BYTES {
                return None;
            }
            let (section, body) = after.split_at_checked(len)?;
            (CredSection::Present(section.to_vec()), body)
        }
        _ => (CredSection::Absent, rest),
    };
    // A body past the ceiling is turned back BEFORE any deserialize walks it —
    // a crafted at-rest length can never drive an allocation spike.
    if body.len() as u64 > MAX_CHECKPOINT_BYTES {
        return None;
    }
    Some((tag, section, body.to_vec()))
}

/// The model and credential section a checkpoint of `entry` writes.
///
/// Read under one lock, so the section belongs to the model beside it.
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
fn checkpoint_parts<Model: Clone, Msg>(
    entry: &SessionEntry<Model, Msg>,
) -> (Model, Option<Vec<u8>>) {
    (entry.model.clone(), entry.checkpoint_section())
}

/// Decode a persisted checkpoint, with an additive-superset fallback when the
/// stored tag does NOT match the live one.
///
/// Exact-tag match → the fast path: the stored fields decode straight into
/// `Model`, state preserved verbatim, and `init` is never evaluated.
///
/// Tag mismatch → the Model schema changed. Instead of unconditionally
/// dropping the session, attempt [`super::additive::reconstruct`] with the
/// caller-supplied live `init_model`: it succeeds ONLY on a PROVEN additive
/// superset (every persisted field still present by name; only new fields
/// added) whose merged object decodes strictly, so old state is kept and each
/// new field takes its `init` value. Any non-additive change (a removed or
/// retyped field), bad base64, a short blob, a corrupt / non-object /
/// oversized body, or a pre-`v2` row → `None` (the caller re-inits cleanly).
/// Never panics; the persisted body is untrusted and every failure is a
/// typed `None`.
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
fn decode_or_reconstruct_checkpoint<Model, Seed>(
    schema_tag: &[u8; 32],
    blob: &str,
    make_init: &(dyn Fn() -> (Model, Seed) + Sync),
) -> Option<Decoded<Model, Seed>>
where
    Model: serde::Serialize + serde::de::DeserializeOwned,
{
    // The section is split off before either path, so a rebuilt row keeps
    // its credentials: they do not depend on the Model's shape.
    let (tag, section, body) = split_checkpoint(blob)?;
    if &tag == schema_tag {
        // Fast path: exact schema match, decode verbatim. `init` is never
        // invoked here — an unchanged-schema restore pays no `init` cost.
        return serde_json::from_slice(&body)
            .ok()
            .map(|model| Decoded::Verbatim { model, section });
    }
    // A different tag is an additive candidate. Produce the live `init` pair
    // (ONLY now — a matched restore never runs it) and splice the persisted
    // fields onto its model, keeping state ONLY on a proven additive superset.
    // The seed travels with the rebuilt model; a failed splice drops both.
    let (init_model, seed) = make_init();
    super::additive::reconstruct(&body, &init_model).map(|model| Decoded::Rebuilt {
        model,
        seed,
        section,
    })
}

/// A decoded checkpoint: restored verbatim, or rebuilt onto a fresh `init`.
///
/// `Rebuilt` carries the seed `make_init` returned beside the model it
/// produced, so a rebuilt model cannot be separated from its `init` effect.
/// Both carry the row's credential section.
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
enum Decoded<Model, Seed> {
    Verbatim {
        model: Model,
        section: CredSection,
    },
    Rebuilt {
        model: Model,
        seed: Seed,
        section: CredSection,
    },
}

#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
impl<Model, Msg> Decoded<Model, IpeCmd<Msg>> {
    /// The rejoin this checkpoint seeds, held under `claim` until its driver is published.
    fn into_rejoin(self, claim: SidClaim) -> Rejoin<Model, Msg> {
        match self {
            Self::Verbatim { model, section } => Rejoin::Restored {
                claim,
                section,
                model,
            },
            Self::Rebuilt {
                model,
                seed,
                section,
            } => Rejoin::Rebuilt {
                claim,
                section,
                model,
                init_cmd: seed,
            },
        }
    }
}

/// The in-process live session (owns its driver goroutine + SSE channel).
pub type SessionHandle<Model, Msg> = Arc<Mutex<SessionEntry<Model, Msg>>>;

/// Result of a claimed page-entry lookup that may rebuild a session across a Model change.
///
/// `Live` = the in-process session. `Restored` = a checkpoint decoded verbatim
/// (no `init`). `Rebuilt` = a checkpoint spliced onto a fresh `init` model;
/// it carries that `init`'s Cmd, which the caller must run under the session's
/// sid. `Miss` = no usable session for the sid. A cold model (`Restored` or
/// `Rebuilt`) exists only beside the [`SidClaim`] that admitted it, so no
/// second request for the sid can seed a driver from it while the claim is
/// held; a rebuilt model without its Cmd has no representation. Each cold
/// model carries its row's credential section, which the caller proves under
/// the armed gate before the model restores.
pub enum Rejoin<Model, Msg> {
    Live(SessionHandle<Model, Msg>),
    Restored {
        claim: SidClaim,
        section: CredSection,
        model: Model,
    },
    Rebuilt {
        claim: SidClaim,
        section: CredSection,
        model: Model,
        init_cmd: IpeCmd<Msg>,
    },
    Miss,
}

// ─── Per-session single flight: one cold-to-live transition per sid at a time ───

/// Length in bytes of a session id: lowercase hex digits only.
pub const SESSION_ID_LEN: usize = 32;

/// Longest a request waits behind another request's claim on the same session.
pub const CLAIM_WAIT: Duration = Duration::from_secs(5);

/// Requests that may wait behind one session's claim holder before the next is refused.
pub const MAX_CLAIM_WAITERS: NonZeroUsize = NonZeroUsize::MIN.saturating_add(7);

/// Distinct sessions whose claims one process holds or awaits at once.
pub const MAX_CLAIMS_IN_FLIGHT: usize = 4096;

/// A session id parsed from a cookie: exactly [`SESSION_ID_LEN`] lowercase hex digits.
///
/// The only key a [`SidAdmission`] admits, so a cookie of any other length
/// or alphabet never reaches the claim table or a store lookup. Its `Debug`
/// never prints the id.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SessionKey(String);

impl SessionKey {
    /// Parse `raw` as a session id.
    ///
    /// `None` unless it is exactly [`SESSION_ID_LEN`] lowercase hex digits.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        (raw.len() == SESSION_ID_LEN && raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
            .then(|| Self(raw.to_owned()))
    }

    /// The id as the stores key it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKey(<redacted>)")
    }
}

/// Why a [`SidAdmission::claim`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimRefusal {
    /// The holder kept the session's claim past [`CLAIM_WAIT`].
    InFlight,
    /// The session already has a holder and [`MAX_CLAIM_WAITERS`] waiters.
    Crowded,
    /// A new session's slot would push the table past [`MAX_CLAIMS_IN_FLIGHT`].
    Saturated,
}

/// One session's entry in the claim table.
struct Slot {
    /// One permit: the claim itself.
    sem: Arc<Semaphore>,
    /// The holder plus every waiter; the slot is removed when the last one leaves.
    users: usize,
}

/// Claim slots keyed by session id.
type ClaimTable = Mutex<HashMap<SessionKey, Slot>>;

/// A store's per-session claim table: at most one cold rejoin per sid at a time.
///
/// The table lock is a `std` mutex, never held across an await.
///
/// The claim is per process. Replicas sharing one persistent backend
/// (Postgres, Redis) each hold their own table, so two replicas can still
/// rebuild the same sid concurrently, each seeding its own driver and running
/// a rebuilt session's init Cmd once. Within one process the cold-to-live
/// transition is single-flight; across replicas it is not, until a backend
/// overrides [`SessionStore::claim`] with a shared lease.
#[derive(Default)]
pub struct SidAdmission(Arc<ClaimTable>);

impl SidAdmission {
    /// An empty claim table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Claim session `key`, waiting at most [`CLAIM_WAIT`] behind a current holder.
    ///
    /// # Errors
    ///
    /// [`ClaimRefusal::Saturated`] when a new slot would exceed
    /// [`MAX_CLAIMS_IN_FLIGHT`], [`ClaimRefusal::Crowded`] when the slot
    /// already has a holder and [`MAX_CLAIM_WAITERS`] waiters, and
    /// [`ClaimRefusal::InFlight`] when the wait runs out.
    pub async fn claim(&self, key: SessionKey) -> Result<SidClaim, ClaimRefusal> {
        let sem = {
            let mut table = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            let full = table.len() >= MAX_CLAIMS_IN_FLIGHT;
            match table.entry(key.clone()) {
                Entry::Occupied(mut held) => {
                    let slot = held.get_mut();
                    if slot.users > MAX_CLAIM_WAITERS.get() {
                        return Err(ClaimRefusal::Crowded);
                    }
                    slot.users = slot.users.saturating_add(1);
                    Arc::clone(&slot.sem)
                }
                Entry::Vacant(free) => {
                    if full {
                        return Err(ClaimRefusal::Saturated);
                    }
                    let sem = Arc::new(Semaphore::new(1));
                    free.insert(Slot {
                        sem: Arc::clone(&sem),
                        users: 1,
                    });
                    sem
                }
            }
        };
        // Built before the wait, so a waiter cancelled mid-wait still leaves its slot.
        let mut lease = SlotLease {
            key,
            table: Arc::clone(&self.0),
            permit: None,
        };
        // The semaphore is never closed; an `AcquireError` is refused like a timeout.
        match tokio::time::timeout(CLAIM_WAIT, sem.acquire_owned()).await {
            Ok(Ok(permit)) => {
                lease.permit = Some(permit);
                Ok(SidClaim { lease })
            }
            Ok(Err(_)) | Err(_) => Err(ClaimRefusal::InFlight),
        }
    }

    /// Whether this table issued `claim`; a claim from another store never unlocks this one.
    #[must_use]
    pub fn admits(&self, claim: &SidClaim) -> bool {
        Arc::ptr_eq(&self.0, &claim.lease.table)
    }
}

/// A holder's or waiter's place in one slot, given back on drop.
struct SlotLease {
    key: SessionKey,
    table: Arc<ClaimTable>,
    /// `Some` once the lease holds the claim; `None` while it waits.
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for SlotLease {
    fn drop(&mut self) {
        let mut table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
        drop(self.permit.take());
        if let Some(slot) = table.get_mut(&self.key) {
            slot.users = slot.users.saturating_sub(1);
            if slot.users == 0 {
                table.remove(&self.key);
            }
        }
    }
}

/// The exclusive right to turn session [`SidClaim::key`] from cold to live.
///
/// Released on drop on every exit: return, `?`, cancellation or unwind.
pub struct SidClaim {
    lease: SlotLease,
}

impl SidClaim {
    /// The claimed session id.
    #[must_use]
    pub const fn key(&self) -> &SessionKey {
        &self.lease.key
    }
}

impl std::fmt::Debug for SidClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidClaim")
            .field("key", &self.lease.key)
            .finish_non_exhaustive()
    }
}

/// Async so persistent backends (sqlite/postgres via sqlx, redis) can do I/O;
/// memory impls have sync bodies. The driver + axum handlers are already async,
/// so call sites just `.await`.
#[async_trait]
pub trait SessionStore<Model, Msg>: Send + Sync {
    /// Look up the live in-process session for `sid`.
    ///
    /// `None` when this process holds none. A persisted checkpoint is never
    /// returned here: only a claimed
    /// [`get_reconstructing`](SessionStore::get_reconstructing) turns one into
    /// a session.
    async fn get(&self, sid: &str) -> Option<SessionHandle<Model, Msg>>;

    /// This store's per-session claim table.
    fn admission(&self) -> &SidAdmission;

    /// Claim session `key` for a page entry; see [`SidAdmission::claim`].
    ///
    /// The provided claim is per process (see [`SidAdmission`]); a backend
    /// shared by several replicas overrides it to make the claim cross-replica.
    ///
    /// # Errors
    ///
    /// The [`ClaimRefusal`] the claim table returns.
    async fn claim(&self, key: SessionKey) -> Result<SidClaim, ClaimRefusal> {
        self.admission().claim(key).await
    }

    /// Look up the claimed session, reconstructing across a purely-additive Model change.
    ///
    /// A live handle is `Live`; an exact-schema checkpoint decodes verbatim
    /// as `Restored`. When a PERSISTED checkpoint's schema tag no longer
    /// matches this binary's (the Model changed), it attempts an
    /// additive-superset splice — decode the persisted fields, overlay them
    /// onto the model `make_init` produces, and return `Rebuilt` (that model
    /// plus the Cmd `make_init` returned beside it) ONLY if the merge is a
    /// proven additive superset that decodes strictly (old state kept, new
    /// fields filled from `init`). Any non-additive change, corrupt / oversized
    /// body, or pre-`v2` row → `Miss` (the caller re-inits cleanly). A claim
    /// this store's [`admission`](SessionStore::admission) did not issue is a
    /// `Miss` too. A cold result carries `claim` back to the caller; a `Live`
    /// or `Miss` result releases it.
    ///
    /// `make_init` is a live `init` producer, invoked LAZILY — only on a
    /// schema-mismatched cold row, never on a live hit or a matched restore —
    /// so the hot paths pay no `init` cost. Building its Cmd fires no effect;
    /// the effect runs only when the caller runs the returned `init_cmd`.
    ///
    /// The default delegates to [`get`](SessionStore::get): a store with no
    /// persisted body (the memory store) has nothing to restore or
    /// reconstruct FROM, so it answers only `Live` or `Miss`.
    async fn get_reconstructing(
        &self,
        claim: SidClaim,
        _make_init: &(dyn Fn() -> (Model, IpeCmd<Msg>) + Sync),
    ) -> Rejoin<Model, Msg> {
        if !self.admission().admits(&claim) {
            return Rejoin::Miss;
        }
        self.get(claim.key().as_str())
            .await
            .map_or(Rejoin::Miss, Rejoin::Live)
    }
    /// Insert/refresh the live handle (and, for persistent backends, checkpoint
    /// the model). Called on session create and write-through on every commit.
    ///
    /// The handle is visible to [`get`](SessionStore::get) before the
    /// persistence I/O starts, so a claim released after `set` returns hands
    /// the next request for the sid a `Live` session, never a cold one.
    ///
    /// A handle the store no longer holds because another one was installed
    /// under the sid writes nothing and is [`Installed::Displaced`], so one sid
    /// never has two writers. A checkpoint that did not land is
    /// [`Installed::Refused`] for a handle the store just took (and gave back)
    /// or [`Installed::Diverged`] for one it already held.
    async fn set(&self, sid: &str, handle: SessionHandle<Model, Msg>) -> Installed;
    /// Drop a session; a persisted row that stayed is [`Deleted::Pending`].
    async fn delete(&self, sid: &str) -> Deleted;
    /// Evict idle-expired sessions (called periodically by the eviction task).
    ///
    /// # Errors
    ///
    /// The persisted prune or a tombstone retry did not land; the live-cache
    /// prune always runs.
    async fn sweep(&self) -> Result<(), WriteFault> {
        Ok(())
    }

    /// Every session handle THIS PROCESS currently holds live (i.e. has an
    /// in-memory driver + possibly an open SSE connection). Deliberately
    /// scoped to the LOCAL mem-cache, never the full persisted table: a
    /// persisted row (another replica's session, or one this process
    /// simply hasn't touched yet) has no SSE connection in THIS process to
    /// push anything to, so it is out of scope for what this method is for.
    /// Returns handles directly (not bare sids) — the caller
    /// (`push_reload_to_web_sessions`) needs each handle's `sse_tx` and
    /// would otherwise have to re-`get()` every id, opening a TOCTOU-ish gap
    /// where a session evicted between the enumerate and the re-fetch is
    /// silently skipped OR (worse) touches its TTL a second time for no
    /// reason. No default body (unlike `sweep`) — every backend has an
    /// opinion; a future backend without an in-process cache must make an
    /// explicit, reviewed choice, not silently inherit a possibly-wrong one.
    async fn web_sessions(&self) -> Vec<SessionHandle<Model, Msg>>;

    /// Evict the least recently seen quiescent live sessions no SSE channel
    /// holds until their charges sum to `need`, returning the bytes they held.
    ///
    /// Only THIS process's live handles are evicted: a persisted row stays,
    /// so a later visit restores it. A session with a Cmd in flight or an
    /// input queued is skipped, so a restored row never stands for a session
    /// whose pending completion was dropped. No default body, as with
    /// [`web_sessions`](SessionStore::web_sessions).
    async fn evict_unconnected(&self, need: Bytes) -> Bytes;

    /// Whether `handle` is the live session this process holds under `sid`.
    ///
    /// An SSE attach reads it under the session's lock, the lock an eviction
    /// holds while it removes the session, so the attach either finds its
    /// session evicted or keeps the eviction from taking it.
    fn holds(&self, sid: &str, handle: &SessionHandle<Model, Msg>) -> bool;
}

/// Evict from `sessions` the least recently seen evictable entries, oldest
/// first, until their charges sum to `need`; returns the bytes they held.
///
/// An entry is removed only under its own lock, while it is still
/// [`evictable`] and the map still holds that same handle, checkpointed: a
/// stream attached or a Cmd started since the snapshot keeps its session, a
/// session re-set meanwhile is never evicted in its place, and a session whose
/// persisted copy lags its live model is never evicted to that stale copy. The
/// map lock is only ever taken inside an entry lock, never the other way
/// round. The bytes return once the last holder of an evicted handle drops it.
fn evict_unconnected_from<Model, Msg>(
    sessions: &RwLock<SessionMap<Model, Msg>>,
    need: Bytes,
) -> Bytes {
    let held: Vec<(String, SessionHandle<Model, Msg>, Instant)> = sessions
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter(|(_, live)| live.is_checkpointed())
        .map(|(sid, live)| (sid.clone(), Arc::clone(&live.handle), live.seen))
        .collect();
    let mut idle: Vec<(String, SessionHandle<Model, Msg>, Instant)> = held
        .into_iter()
        .filter(|(_, handle, _)| evictable(&handle.lock().unwrap_or_else(PoisonError::into_inner)))
        .collect();
    idle.sort_by_key(|(_, _, seen)| *seen);
    let mut freed = Bytes::ZERO;
    for (sid, handle, _) in idle {
        if freed.get() >= need.get() {
            break;
        }
        let entry = handle.lock().unwrap_or_else(PoisonError::into_inner);
        if !evictable(&entry) {
            continue;
        }
        let mut map = sessions.write().unwrap_or_else(PoisonError::into_inner);
        if let Entry::Occupied(slot) = map.entry(sid)
            && slot.get().holds(&handle)
            && slot.get().is_checkpointed()
        {
            slot.remove();
            freed = freed
                .checked_add(entry.charge.held())
                .unwrap_or(Bytes::new(u64::MAX));
        }
        drop(map);
        drop(entry);
    }
    freed
}

/// Whether an eviction may take `entry`: no SSE channel holds it and nothing
/// on its way to its `update` would be lost.
fn evictable<Model, Msg>(entry: &SessionEntry<Model, Msg>) -> bool {
    entry.sse_tx.is_none() && entry.is_quiescent()
}

/// What a [`SessionStore::set`] did with the handle it was given.
#[must_use = "a handle the store did not keep or did not persist must be acted on"]
#[derive(Debug)]
pub enum Installed {
    /// Live under its sid; the checkpoint landed (nothing to land for memory).
    Held,
    /// Live under its sid (the slot already held this handle); the checkpoint
    /// did NOT land. The map entry is marked diverged, so it is never evicted.
    Diverged(WriteFault),
    /// The slot was vacant and the checkpoint did not land: the handle was
    /// taken back out of the map. The store holds nothing for this sid.
    Refused(WriteFault),
    /// Another live handle holds the sid; nothing was written.
    Displaced,
}

/// What a [`SessionStore::delete`] left behind.
#[must_use = "a delete that did not land leaves a restorable row"]
#[derive(Debug)]
pub enum Deleted {
    /// Neither a live entry nor a persisted row remains.
    Removed,
    /// The live entry is gone; the persisted row may remain. The sid is
    /// tombstoned until a retry lands.
    Pending(WriteFault),
}

/// Whether the persisted copy of a live session matches its live model.
///
/// The fault itself was already returned to the writer and logged by the
/// store's [`FaultStreak`]; the entry only records that its copy lags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Durability {
    /// The persisted copy (if the backend has one) matches the live model.
    Checkpointed,
    /// The last checkpoint, touch or encode failed; the persisted copy lags.
    Diverged,
}

/// A live session this process holds: its handle, when it was last seen, and
/// whether its persisted copy is current.
struct Live<Model, Msg> {
    handle: SessionHandle<Model, Msg>,
    seen: Instant,
    durability: Durability,
}

impl<Model, Msg> Live<Model, Msg> {
    fn fresh(handle: &SessionHandle<Model, Msg>) -> Self {
        Self {
            handle: Arc::clone(handle),
            seen: Instant::now(),
            durability: Durability::Checkpointed,
        }
    }

    fn holds(&self, handle: &SessionHandle<Model, Msg>) -> bool {
        Arc::ptr_eq(&self.handle, handle)
    }

    const fn is_checkpointed(&self) -> bool {
        matches!(self.durability, Durability::Checkpointed)
    }
}

/// How [`install_in`] placed the handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// The slot was vacant: the handle was inserted.
    Fresh,
    /// The slot already held this handle: its last-seen was reset.
    Reset,
}

/// Put `handle` under `sid` unless `sessions` holds another handle there, and
/// read what its checkpoint writes.
///
/// Judged and written under `handle`'s lock with the map lock inside it, the
/// order an eviction takes them in, so a driver whose session was evicted and
/// then restored under a second handle never replaces that handle. A vacant
/// slot takes the handle back: a session evicted while its driver still ran
/// is alive. `None` when displaced.
fn install_in<Model, Msg, Parts>(
    sessions: &RwLock<SessionMap<Model, Msg>>,
    sid: &str,
    handle: &SessionHandle<Model, Msg>,
    read: impl FnOnce(&SessionEntry<Model, Msg>) -> Parts,
) -> Option<(Placement, Parts)> {
    let entry = handle.lock().unwrap_or_else(PoisonError::into_inner);
    let mut map = sessions.write().unwrap_or_else(PoisonError::into_inner);
    let slot = match map.entry(sid.to_owned()) {
        Entry::Occupied(mut slot) if slot.get().holds(handle) => {
            slot.get_mut().seen = Instant::now();
            Placement::Reset
        }
        Entry::Occupied(_) => return None,
        Entry::Vacant(slot) => {
            slot.insert(Live::fresh(handle));
            Placement::Fresh
        }
    };
    drop(map);
    Some((slot, read(&entry)))
}

/// Settle an installed handle's checkpoint `written` into its map entry.
///
/// A landed write marks the entry checkpointed. A failed one takes a freshly
/// inserted handle back out (the store then holds nothing for the sid) and
/// marks a held one diverged, so it is never evicted to its stale copy. Both
/// are judged under the entry lock then the map lock, and only while the map
/// still holds this handle.
fn settle_in<Model, Msg>(
    sessions: &RwLock<SessionMap<Model, Msg>>,
    sid: &str,
    handle: &SessionHandle<Model, Msg>,
    slot: Placement,
    written: Result<(), WriteFault>,
) -> Installed {
    let entry = handle.lock().unwrap_or_else(PoisonError::into_inner);
    let mut map = sessions.write().unwrap_or_else(PoisonError::into_inner);
    let installed = match (map.entry(sid.to_owned()), written, slot) {
        (Entry::Occupied(mut held), Ok(()), _) if held.get().holds(handle) => {
            held.get_mut().durability = Durability::Checkpointed;
            Installed::Held
        }
        (Entry::Occupied(held), Err(fault), Placement::Fresh) if held.get().holds(handle) => {
            held.remove();
            Installed::Refused(fault)
        }
        (Entry::Occupied(mut held), Err(fault), Placement::Reset) if held.get().holds(handle) => {
            held.get_mut().durability = Durability::Diverged;
            Installed::Diverged(fault)
        }
        // Displaced or evicted between the install and the settle: the slot
        // is another handle's or nobody's, so this handle writes no more.
        (_, Ok(()), _) => Installed::Displaced,
        (_, Err(fault), _) => Installed::Refused(fault),
    };
    drop(map);
    drop(entry);
    installed
}

/// Mark the entry under `sid` `durability`, iff `sessions` still holds `handle` there.
fn mark_in<Model, Msg>(
    sessions: &RwLock<SessionMap<Model, Msg>>,
    sid: &str,
    handle: &SessionHandle<Model, Msg>,
    durability: Durability,
) {
    let entry = handle.lock().unwrap_or_else(PoisonError::into_inner);
    let mut map = sessions.write().unwrap_or_else(PoisonError::into_inner);
    if let Some(live) = map.get_mut(sid)
        && live.holds(handle)
    {
        live.durability = durability;
    }
    drop(map);
    drop(entry);
}

/// The live handle under `sid`, its last-seen touched so an active session stays alive.
fn touch_in<Model, Msg>(
    sessions: &RwLock<SessionMap<Model, Msg>>,
    sid: &str,
) -> Option<SessionHandle<Model, Msg>> {
    let mut map = sessions.write().unwrap_or_else(PoisonError::into_inner);
    map.get_mut(sid).map(|live| {
        live.seen = Instant::now();
        Arc::clone(&live.handle)
    })
}

/// Drop the live entry under `sid`, whatever handle it holds.
fn remove_in<Model, Msg>(sessions: &RwLock<SessionMap<Model, Msg>>, sid: &str) {
    sessions
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(sid);
}

/// Drop every live entry not seen within `ttl`.
///
/// Bounds the in-RAM handle cache by idle-TTL: without it every distinct sid
/// ever seen (a flood of cookie-less requests) would leave a live handle
/// forever (session-DoS). A persisted session re-hydrates on its next
/// claimed request.
fn prune_in<Model, Msg>(sessions: &RwLock<SessionMap<Model, Msg>>, ttl: Duration) {
    let now = Instant::now();
    sessions
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .retain(|_, live| now.duration_since(live.seen) <= ttl);
}

/// Every live handle in `sessions`.
fn handles_in<Model, Msg>(
    sessions: &RwLock<SessionMap<Model, Msg>>,
) -> Vec<SessionHandle<Model, Msg>> {
    sessions
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .values()
        .map(|live| Arc::clone(&live.handle))
        .collect()
}

/// Whether `sessions` holds `handle` under `sid`.
fn holds_in<Model, Msg>(
    sessions: &RwLock<SessionMap<Model, Msg>>,
    sid: &str,
    handle: &SessionHandle<Model, Msg>,
) -> bool {
    sessions
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .get(sid)
        .is_some_and(|live| live.holds(handle))
}

// ─── Memory store — default; in-process, lost on restart ────────────────────

/// In-process session table: sid → the live session under it.
type SessionMap<Model, Msg> = HashMap<String, Live<Model, Msg>>;

/// In-process store with idle-TTL eviction. `get` touches the entry's last-seen
/// so active sessions don't expire.

pub struct MemoryStore<Model, Msg> {
    sessions: RwLock<SessionMap<Model, Msg>>,
    ttl: Duration,
    admission: SidAdmission,
}

impl<Model, Msg> MemoryStore<Model, Msg> {
    pub fn new(ttl: Duration) -> Self {
        MemoryStore {
            sessions: RwLock::new(HashMap::new()),
            ttl,
            admission: SidAdmission::new(),
        }
    }
}

#[async_trait]
impl<Model: Send + 'static, Msg: Send + 'static> SessionStore<Model, Msg>
    for MemoryStore<Model, Msg>
{
    async fn get(&self, sid: &str) -> Option<SessionHandle<Model, Msg>> {
        touch_in(&self.sessions, sid)
    }
    fn admission(&self) -> &SidAdmission {
        &self.admission
    }
    async fn set(&self, sid: &str, handle: SessionHandle<Model, Msg>) -> Installed {
        // Nothing to persist: a held handle is checkpointed by definition.
        install_in(&self.sessions, sid, &handle, |_| ())
            .map_or(Installed::Displaced, |(_, ())| Installed::Held)
    }
    async fn delete(&self, sid: &str) -> Deleted {
        remove_in(&self.sessions, sid);
        Deleted::Removed
    }
    async fn sweep(&self) -> Result<(), WriteFault> {
        prune_in(&self.sessions, self.ttl);
        Ok(())
    }
    async fn web_sessions(&self) -> Vec<SessionHandle<Model, Msg>> {
        handles_in(&self.sessions)
    }
    async fn evict_unconnected(&self, need: Bytes) -> Bytes {
        evict_unconnected_from(&self.sessions, need)
    }
    fn holds(&self, sid: &str, handle: &SessionHandle<Model, Msg>) -> bool {
        holds_in(&self.sessions, sid, handle)
    }
}

// ─── File store — persistent checkpoint with NO sqlx, for the dev handoff ────

/// A dependency-light persistent store: a `mem_cache` of live handles (same
/// process, owns the driver) PLUS a single on-disk JSON map (`sid → framed
/// checkpoint blob`) so a checkpoint survives a process swap WITHOUT pulling in
/// sqlx/redis. This is what makes `ipe dev watch`'s blue-green Model handoff work
/// for a plain `Web.tea` — such an app reaches no DB kernel, so the emitted
/// crate carries no `db` feature and the sqlite store compiles out; this store
/// rides the `web` feature every web build already has (`base64` + `bincode` +
/// `serde`), reusing the SAME `encode_checkpoint`/`decode_or_reconstruct_checkpoint` codec and
/// the SAME H24 schema-tag reject-before-deserialize gate as the sqlite/redis
/// backends. A structurally different (Model-type-changed) checkpoint is
/// rejected before deserialize → fail-soft fresh `init`, never a torn Model.
///
/// The on-disk map is the whole file rewritten on each mutation — bounded and
/// simple, matched to a DEV loop's low session count, not a production store.
#[cfg(feature = "web")]
pub struct FileStore<Model, Msg> {
    /// Path to the JSON map file (`sid → blob`), its stale write siblings
    /// reclaimed at construction so no write scans the directory.
    path: crate::scratch_core::ReclaimedTarget,
    /// The persisted `sid → framed-checkpoint-blob` map, mirrored in memory and
    /// rewritten to `path` on every mutation. `last_seen` (unix secs) rides
    /// alongside for idle-TTL eviction.
    disk: Mutex<HashMap<String, (String, i64)>>,
    /// Live same-process handles (own the running driver + SSE channel).
    mem_cache: RwLock<SessionMap<Model, Msg>>,
    ttl: Duration,
    /// The live process's Model schema tag (H24) — a stored blob whose leading
    /// tag differs is rejected identically to "no row" (fresh `init`).
    schema_tag: [u8; 32],
    streak: FaultStreak,
    tombstones: Tombstones,
    admission: SidAdmission,
}

/// Why a checkpoint-map persist attempt failed, one variant per step.
///
/// The wrapped I/O error can carry the on-disk map path in its message (a
/// [`crate::scratch_core::ScratchError`] displays the path it refused), so
/// [`PersistError`]'s own `Display` names the step and the I/O error's
/// [`std::io::ErrorKind`] (a fixed phrase), never that message — the same
/// credential-free posture [`StoreOpenError`] keeps for a driver error that
/// could echo the connection URL.
#[cfg(feature = "web")]
#[derive(Debug)]
pub enum PersistError {
    /// Encoding the in-memory map as JSON failed (not an I/O error).
    Encode(serde_json::Error),
    /// Creating the private atomic-replace sibling failed (open or verify).
    CreateTemp(std::io::Error),
    /// Writing the encoded map into the sibling failed.
    WriteTemp(std::io::Error),
    /// Flushing or renaming the sibling over the map file failed.
    ///
    /// [`crate::scratch_core::AtomicSibling::commit`] reports both as one step.
    Commit(std::io::Error),
}

#[cfg(feature = "web")]
impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (step, io) = match self {
            Self::Encode(_) => ("encode", None),
            Self::CreateTemp(e) => ("create temp file", Some(e)),
            Self::WriteTemp(e) => ("write temp file", Some(e)),
            Self::Commit(e) => ("commit (flush/rename)", Some(e)),
        };
        write!(f, "session store persist failed at step: {step}")?;
        if let Some(e) = io {
            write!(f, " ({})", e.kind())?;
        }
        Ok(())
    }
}

#[cfg(feature = "web")]
impl std::error::Error for PersistError {}

#[cfg(feature = "web")]
impl<Model, Msg> FileStore<Model, Msg> {
    /// Open (or create) the map at `path`, loading any existing checkpoints.
    /// A missing / unreadable / malformed file starts empty — never an error,
    /// never a panic: a dev handoff that cannot read a stale map simply begins
    /// fresh (the same fail-soft posture the whole store family keeps).
    #[must_use]
    pub fn new(path: &str, ttl: Duration, schema_tag: [u8; 32]) -> Self {
        let path = std::path::PathBuf::from(path);
        // A symlink at the map path is never read through: the store starts
        // empty, and `persist`'s rename later replaces the link itself.
        let is_link = std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink());
        let disk = (!is_link)
            .then(|| std::fs::read_to_string(&path).ok())
            .flatten()
            .and_then(|s| serde_json::from_str::<HashMap<String, (String, i64)>>(&s).ok())
            .unwrap_or_default();
        FileStore {
            path: crate::scratch_core::ReclaimedTarget::new(&path),
            disk: Mutex::new(disk),
            mem_cache: RwLock::new(HashMap::new()),
            ttl,
            schema_tag,
            streak: FaultStreak::new(),
            tombstones: Tombstones::new(ttl),
            admission: SidAdmission::new(),
        }
    }

    /// Atomically rewrite the on-disk map from `disk`, observing the outcome.
    ///
    /// A write failure leaves the in-memory map as the source of truth for
    /// this process; the next mutation or sweep retries the whole map. Writes
    /// to a sibling temp file then renames, so a crash mid-write never leaves
    /// a truncated map a later `new` would fail to parse (and thus silently
    /// drop every session).
    ///
    /// The temp file is an [`AtomicSibling`](crate::scratch_core::AtomicSibling):
    /// an unguessable hidden name, created exclusively, never through a symlink,
    /// and verified `0600` (owner-only) BEFORE any bytes are written, so the
    /// checkpoint map — which may hold Model secrets — is never world-readable,
    /// not even momentarily. The rename carries the mode to the final path, and
    /// a refused or failed write removes the temp file.
    ///
    /// # Errors
    ///
    /// The step that failed, as a [`WriteFault::File`]; the streak logs it
    /// once, naming the step and its I/O error kind but never the map path.
    fn persist(&self, disk: &HashMap<String, (String, i64)>) -> Result<(), WriteFault> {
        self.streak.observe(
            "file",
            self.write_map(disk)
                .map_err(|failed| WriteFault::File(Arc::new(failed))),
        )
    }

    /// Serialize `disk` and atomically replace the map file with it.
    fn write_map(&self, disk: &HashMap<String, (String, i64)>) -> Result<(), PersistError> {
        let json = serde_json::to_string(disk).map_err(PersistError::Encode)?;
        let mut sibling = crate::scratch_core::AtomicSibling::create_reclaimed(&self.path)
            .map_err(PersistError::CreateTemp)?;
        sibling
            .write_all(json.as_bytes())
            .map_err(PersistError::WriteTemp)?;
        sibling.commit().map_err(PersistError::Commit)
    }

    /// Prune the map by TTL and rewrite it when it changed or a tombstoned sid
    /// awaits its removal from disk; every tombstone shares the one outcome.
    fn sweep_map(&self) -> Result<(), WriteFault> {
        let tombstoned = self.tombstones.snapshot();
        let cutoff = ttl_cutoff(now_secs(), self.ttl);
        let written = {
            let mut disk = self.disk.lock().unwrap_or_else(PoisonError::into_inner);
            let before = disk.len();
            disk.retain(|_, (_, seen)| *seen >= cutoff);
            if disk.len() == before && tombstoned.is_empty() {
                Ok(())
            } else {
                self.persist(&disk)
            }
        };
        for sid in &tombstoned {
            self.tombstones.retry(sid, &written);
        }
        written
    }
}

#[cfg(feature = "web")]
#[async_trait]
impl<Model, Msg> SessionStore<Model, Msg> for FileStore<Model, Msg>
where
    Model: serde::Serialize + serde::de::DeserializeOwned + Clone + Send + Sync + 'static,
    Msg: Send + Sync + 'static,
{
    async fn get(&self, sid: &str) -> Option<SessionHandle<Model, Msg>> {
        // Only the same-process live handle (it owns the running driver).
        touch_in(&self.mem_cache, sid)
    }
    fn admission(&self) -> &SidAdmission {
        &self.admission
    }
    async fn get_reconstructing(
        &self,
        claim: SidClaim,
        make_init: &(dyn Fn() -> (Model, IpeCmd<Msg>) + Sync),
    ) -> Rejoin<Model, Msg> {
        if !self.admission.admits(&claim) {
            return Rejoin::Miss;
        }
        let sid = claim.key().as_str();
        // Live handle wins — no `init`, no reconstruction.
        if let Some(h) = self.get(sid).await {
            return Rejoin::Live(h);
        }
        match self.tombstones.cold_read(sid) {
            ColdRead::Miss => return Rejoin::Miss,
            // The in-memory map already lacks the sid; what lags is the disk.
            ColdRead::RetryDelete => {
                let persisted =
                    self.persist(&self.disk.lock().unwrap_or_else(PoisonError::into_inner));
                self.tombstones.retry(sid, &persisted);
                return Rejoin::Miss;
            }
            ColdRead::Row => {}
        }
        // Cold: on an exact tag the checkpoint decodes verbatim; on a
        // schema-changed tag it is spliced onto `init` iff additive-superset.
        // An idle-expired row is a miss whether or not the sweep ran.
        let cutoff = ttl_cutoff(now_secs(), self.ttl);
        let blob = {
            let disk = self.disk.lock().unwrap_or_else(PoisonError::into_inner);
            disk.get(sid)
                .filter(|(_, seen)| *seen >= cutoff)
                .map(|(b, _)| b.clone())
        };
        let decoded = blob
            .and_then(|blob| decode_or_reconstruct_checkpoint(&self.schema_tag, &blob, make_init));
        decoded.map_or(Rejoin::Miss, |d| d.into_rejoin(claim))
    }
    async fn set(&self, sid: &str, handle: SessionHandle<Model, Msg>) -> Installed {
        let Some((slot, parts)) = install_in(&self.mem_cache, sid, &handle, checkpoint_parts)
        else {
            return Installed::Displaced;
        };
        let written = frame_checkpoint(&self.schema_tag, &parts).and_then(|blob| {
            let mut disk = self.disk.lock().unwrap_or_else(PoisonError::into_inner);
            let prior = disk.insert(sid.to_owned(), (blob, now_secs()));
            let persisted = self.persist(&disk);
            // A refused fresh handle leaves nothing behind: the in-memory map
            // goes back to what the disk holds for this sid, so a later write
            // of another session never persists a row no live session owns.
            if persisted.is_err() && slot == Placement::Fresh {
                match prior {
                    Some(row) => disk.insert(sid.to_owned(), row),
                    None => disk.remove(sid),
                };
            }
            persisted
        });
        settle_in(&self.mem_cache, sid, &handle, slot, written)
    }
    async fn delete(&self, sid: &str) -> Deleted {
        remove_in(&self.mem_cache, sid);
        let removed = {
            let mut disk = self.disk.lock().unwrap_or_else(PoisonError::into_inner);
            disk.remove(sid).is_some().then(|| self.persist(&disk))
        };
        removed.map_or(Deleted::Removed, |removed| {
            self.tombstones.deleted(sid, removed)
        })
    }
    async fn sweep(&self) -> Result<(), WriteFault> {
        let swept = self.sweep_map();
        prune_in(&self.mem_cache, self.ttl);
        swept
    }
    async fn web_sessions(&self) -> Vec<SessionHandle<Model, Msg>> {
        handles_in(&self.mem_cache)
    }
    async fn evict_unconnected(&self, need: Bytes) -> Bytes {
        evict_unconnected_from(&self.mem_cache, need)
    }
    fn holds(&self, sid: &str, handle: &SessionHandle<Model, Msg>) -> bool {
        holds_in(&self.mem_cache, sid, handle)
    }
}

/// Current unix time in whole seconds, saturating (never panics on a clock
/// before the epoch).
#[cfg(any(feature = "db", feature = "web"))]
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// The oldest `last_seen` a persisted row may carry and still be live under `ttl`.
///
/// Total: `try_from` saturates an absurd `IPE_WEB_TTL` to `i64::MAX` and
/// `saturating_sub` clamps, so an oversized TTL degrades to "never expire"
/// instead of wrapping negative. The cold read and the sweep share it, so a
/// row the sweep would prune is a miss before the sweep runs.
#[cfg(any(feature = "db", feature = "web"))]
fn ttl_cutoff(now: i64, ttl: Duration) -> i64 {
    now.saturating_sub(i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX))
}

/// Upper bound on connections one sqlx-backed session-store pool holds.
#[cfg(feature = "db")]
const SESSION_STORE_MAX_CONNECTIONS: u32 = 10;

/// Why a persistent session store could not open.
///
/// Credential-free by construction: no variant holds a driver error, whose
/// message can echo the connection URL, so the fallback log line cannot leak it.
#[cfg(any(feature = "db", feature = "redis_store"))]
#[derive(Debug)]
pub enum StoreOpenError {
    /// [`crate::db::VettedPool::connect`] refused the pool.
    #[cfg(feature = "db")]
    Connect(crate::db::DbConnectError),
    /// Creating the session table failed.
    #[cfg(feature = "db")]
    Schema(crate::db::DriverFailure),
    /// The Redis client could not connect or answer `PING`.
    #[cfg(feature = "redis_store")]
    Redis(redis::ErrorKind),
}

#[cfg(any(feature = "db", feature = "redis_store"))]
impl std::fmt::Display for StoreOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "db")]
            Self::Connect(refused) => write!(f, "{refused}"),
            #[cfg(feature = "db")]
            Self::Schema(failure) => write!(f, "session table setup failed: {failure}"),
            #[cfg(feature = "redis_store")]
            Self::Redis(kind) => write!(f, "redis error ({kind:?})"),
        }
    }
}

#[cfg(any(feature = "db", feature = "redis_store"))]
impl std::error::Error for StoreOpenError {}

#[cfg(feature = "db")]
impl StoreOpenError {
    /// Whether a connect-time policy gate refused the store.
    ///
    /// A refused host, an unvettable URL, or an unsupported engine is a
    /// policy refusal, so [`choose_store`] refuses startup on it rather than
    /// degrade to memory. That includes a host the SSRF gate could not
    /// resolve or resolved too slowly: such a failure may be transient DNS,
    /// but a host the gate never vetted is not dialled, and falling back would
    /// silently run without the configured store, so it fails closed. So is a
    /// relay the pinned TLS dial needs that could not be opened. A
    /// driver failure after the gate admitted the target (unreachable server,
    /// failed version query, table setup) is not a policy refusal.
    ///
    /// Every variant is classified by name, with no wildcard, so a new refusal
    /// variant is a compile error here until it is classified, never a silent
    /// fallback to memory.
    const fn is_policy_refusal(&self) -> bool {
        use crate::db::{DbConnectError, EngineVersionError};
        use crate::ssrf::SsrfRefusal;
        match self {
            Self::Connect(failure) => match failure {
                DbConnectError::InvalidUrl
                | DbConnectError::MisplacedUserinfo
                | DbConnectError::TooManyDialTargets { .. }
                | DbConnectError::UnsupportedScheme
                | DbConnectError::EngineMismatch { .. } => true,
                DbConnectError::HostRefused(refusal) => match refusal {
                    SsrfRefusal::Blocked { .. }
                    | SsrfRefusal::Unresolvable { .. }
                    | SsrfRefusal::NoAddresses { .. }
                    | SsrfRefusal::Timeout { .. }
                    | SsrfRefusal::Deadline(_)
                    | SsrfRefusal::LocalSocket
                    | SsrfRefusal::UnprovenTarget
                    | SsrfRefusal::UnpinnableTlsName { .. } => true,
                },
                DbConnectError::EngineRefused(refused) => match refused {
                    EngineVersionError::UnknownEngine
                    | EngineVersionError::Unparseable { .. }
                    | EngineVersionError::BelowFloor { .. } => true,
                },
                // Without the relay the deny-private policy refuses the dial,
                // and its cause (no private socket directory) is environmental.
                DbConnectError::RelayUnavailable => true,
                DbConnectError::Unreachable(_) | DbConnectError::VersionUnreadable(_) => false,
            },
            Self::Schema(_) => false,
            #[cfg(feature = "redis_store")]
            Self::Redis(_) => false,
        }
    }
}

/// The fail-closed startup error for a `backend` store a policy gate refused.
#[cfg(feature = "db")]
fn store_refused_error(backend: &'static str, refused: &StoreOpenError) -> StoreConfigError {
    StoreConfigError::Refused {
        backend,
        cause: crate::system::RefusedText::new(&refused.to_string()),
    }
}

/// The `[ipe.live]` message logged when a persistent `backend` store falls back
/// to memory.
#[cfg(any(feature = "db", feature = "redis_store"))]
fn store_unavailable_message(backend: &str, refused: &StoreOpenError) -> String {
    format!("{backend} store unavailable ({refused}); falling back to memory")
}

// ─── SQLite store — persistent model checkpoint + live mem-cache ─────────────

/// Persistent store: keeps a `mem_cache` of live handles (same-process, owns the
/// driver) AND a `ipe_sessions(sid, blob, last_seen)` table holding the
/// serde-JSON model checkpoint. `get` returns the live handle on a cache hit;
/// a claimed `get_reconstructing` decodes the blob into a cold model (the
/// caller hydrates a fresh driver). Requires `Model: Serialize + DeserializeOwned` (the codegen derives
/// it). Implements `sqliteStore`.
#[cfg(feature = "db")]
pub struct SqliteStore<Model, Msg> {
    pool: sqlx::SqlitePool,
    mem_cache: RwLock<SessionMap<Model, Msg>>,
    ttl: Duration,
    /// The live process's Model schema tag (H24): a checkpoint row whose
    /// stored tag differs is rejected BEFORE deserialization — treated
    /// identically to "no row" (fail-soft to a fresh `init`).
    schema_tag: [u8; 32],
    streak: FaultStreak,
    tombstones: Tombstones,
    admission: SidAdmission,
}

#[cfg(feature = "db")]
impl<Model, Msg> SqliteStore<Model, Msg> {
    /// Open (creating if missing) the SQLite session store at `path`.
    ///
    /// # Errors
    ///
    /// [`StoreOpenError`] when the pool is refused or the table cannot be created.
    pub async fn new(
        path: &str,
        ttl: Duration,
        schema_tag: [u8; 32],
    ) -> Result<Self, StoreOpenError> {
        let url = crate::db::DbUrl::parse(&format!("sqlite:{path}?mode=rwc"))
            .map_err(StoreOpenError::Connect)?;
        let pool =
            crate::db::VettedPool::<sqlx::Sqlite>::connect(&url, SESSION_STORE_MAX_CONNECTIONS)
                .await
                .map_err(StoreOpenError::Connect)?
                .into_pool();
        // A pre-existing table from before the schema-tag column existed is
        // left as-is by IF NOT EXISTS; statements referencing the missing
        // column then fail as a typed write fault the caller matches on — the
        // store degrades fail-closed (new sessions refused, held ones kept
        // live), never crashes and never mis-decodes.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS ipe_sessions (\
             sid TEXT PRIMARY KEY, blob TEXT NOT NULL, last_seen INTEGER NOT NULL, \
             schema_tag TEXT NOT NULL)",
        )
        .execute(&pool)
        .await
        .map_err(|e| StoreOpenError::Schema(Self::failure(&e)))?;
        crate::db::own_pool(crate::db::PoolRole::SessionStore, &pool);
        Ok(SqliteStore {
            pool,
            mem_cache: RwLock::new(HashMap::new()),
            ttl,
            schema_tag,
            streak: FaultStreak::new(),
            tombstones: Tombstones::new(ttl),
            admission: SidAdmission::new(),
        })
    }

    fn failure(e: &sqlx::Error) -> crate::db::DriverFailure {
        crate::db::DriverFailure::of(crate::db::DbEngine::Sqlite, e)
    }

    /// Settle one statement's outcome into the streak, as a typed fault.
    fn settle(
        &self,
        done: Result<sqlx::sqlite::SqliteQueryResult, sqlx::Error>,
    ) -> Result<(), WriteFault> {
        self.streak.observe(
            "sqlite",
            done.map(drop)
                .map_err(|e| WriteFault::Driver(Self::failure(&e))),
        )
    }

    async fn write_row(&self, sid: &str, blob: String) -> Result<(), WriteFault> {
        let done = sqlx::query(
            "INSERT INTO ipe_sessions (sid, blob, last_seen, schema_tag) VALUES (?, ?, ?, ?) \
             ON CONFLICT(sid) DO UPDATE SET blob=excluded.blob, \
             last_seen=excluded.last_seen, schema_tag=excluded.schema_tag",
        )
        .bind(sid)
        .bind(blob)
        .bind(now_secs())
        .bind(hex::encode(self.schema_tag))
        .execute(&self.pool)
        .await;
        self.settle(done)
    }

    async fn touch_row(&self, sid: &str) -> Result<(), WriteFault> {
        let done = sqlx::query("UPDATE ipe_sessions SET last_seen = ? WHERE sid = ?")
            .bind(now_secs())
            .bind(sid)
            .execute(&self.pool)
            .await;
        self.settle(done)
    }

    async fn delete_row(&self, sid: &str) -> Result<(), WriteFault> {
        let done = sqlx::query("DELETE FROM ipe_sessions WHERE sid = ?")
            .bind(sid)
            .execute(&self.pool)
            .await;
        self.settle(done)
    }

    async fn prune_rows(&self) -> Result<(), WriteFault> {
        let done = sqlx::query("DELETE FROM ipe_sessions WHERE last_seen < ?")
            .bind(ttl_cutoff(now_secs(), self.ttl))
            .execute(&self.pool)
            .await;
        self.settle(done)
    }

    /// The persisted blob under `sid`, if its row is within the idle TTL.
    async fn read_row(&self, sid: &str) -> Option<String> {
        let row = sqlx::query_as::<_, (String,)>(
            "SELECT blob FROM ipe_sessions WHERE sid = ? AND last_seen >= ?",
        )
        .bind(sid)
        .bind(ttl_cutoff(now_secs(), self.ttl))
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| WriteFault::Driver(Self::failure(&e)));
        self.streak
            .observe("sqlite", row)
            .ok()
            .flatten()
            .map(|(blob,)| blob)
    }
}

#[cfg(feature = "db")]
#[async_trait]
impl<Model, Msg> SessionStore<Model, Msg> for SqliteStore<Model, Msg>
where
    Model: serde::Serialize + serde::de::DeserializeOwned + Clone + Send + Sync + 'static,
    Msg: Send + Sync + 'static,
{
    async fn get(&self, sid: &str) -> Option<SessionHandle<Model, Msg>> {
        // Only the same-process live handle (it owns the running driver). A
        // failed touch leaves the row's `last_seen` behind the live session,
        // so the entry diverges until a checkpoint lands.
        let cached = touch_in(&self.mem_cache, sid)?;
        if self.touch_row(sid).await.is_err() {
            mark_in(&self.mem_cache, sid, &cached, Durability::Diverged);
        }
        Some(cached)
    }
    fn admission(&self) -> &SidAdmission {
        &self.admission
    }
    async fn get_reconstructing(
        &self,
        claim: SidClaim,
        make_init: &(dyn Fn() -> (Model, IpeCmd<Msg>) + Sync),
    ) -> Rejoin<Model, Msg> {
        if !self.admission.admits(&claim) {
            return Rejoin::Miss;
        }
        let sid = claim.key().as_str();
        if let Some(h) = self.get(sid).await {
            return Rejoin::Live(h);
        }
        match self.tombstones.cold_read(sid) {
            ColdRead::Miss => return Rejoin::Miss,
            ColdRead::RetryDelete => {
                self.tombstones.retry(sid, &self.delete_row(sid).await);
                return Rejoin::Miss;
            }
            ColdRead::Row => {}
        }
        // Cold (post-restart / other replica): the blob is self-contained
        // (`base64(tag ++ json)`), and its tag picks a verbatim decode or an
        // additive splice. The legacy `schema_tag` column is still written
        // (NOT NULL) but never read. The row is not touched here: the first
        // checkpoint of the restored session rewrites `last_seen`.
        let decoded = self
            .read_row(sid)
            .await
            .and_then(|blob| decode_or_reconstruct_checkpoint(&self.schema_tag, &blob, make_init));
        decoded.map_or(Rejoin::Miss, |d| d.into_rejoin(claim))
    }
    async fn set(&self, sid: &str, handle: SessionHandle<Model, Msg>) -> Installed {
        let Some((slot, parts)) = install_in(&self.mem_cache, sid, &handle, checkpoint_parts)
        else {
            return Installed::Displaced;
        };
        let written = match frame_checkpoint(&self.schema_tag, &parts) {
            Ok(blob) => self.write_row(sid, blob).await,
            Err(fault) => Err(fault),
        };
        settle_in(&self.mem_cache, sid, &handle, slot, written)
    }
    async fn delete(&self, sid: &str) -> Deleted {
        remove_in(&self.mem_cache, sid);
        self.tombstones.deleted(sid, self.delete_row(sid).await)
    }
    async fn sweep(&self) -> Result<(), WriteFault> {
        // Every tombstone is retried before the TTL prune; the first fault is
        // the sweep's, the rest still ran.
        let mut swept: Result<(), WriteFault> = Ok(());
        for sid in self.tombstones.snapshot() {
            let removed = self.delete_row(&sid).await;
            self.tombstones.retry(&sid, &removed);
            swept = swept.and(removed);
        }
        let pruned = self.prune_rows().await;
        // Bound the in-RAM handle cache by idle-TTL too. Without this, every
        // distinct sid ever seen (e.g. a flood of cookie-less requests) leaves a
        // live handle in mem_cache forever → unbounded growth → OOM (session-DoS).
        // An evicted-but-still-valid session simply re-hydrates from the
        // checkpoint blob on its next claimed request.
        prune_in(&self.mem_cache, self.ttl);
        swept.and(pruned)
    }
    async fn web_sessions(&self) -> Vec<SessionHandle<Model, Msg>> {
        handles_in(&self.mem_cache)
    }
    async fn evict_unconnected(&self, need: Bytes) -> Bytes {
        evict_unconnected_from(&self.mem_cache, need)
    }
    fn holds(&self, sid: &str, handle: &SessionHandle<Model, Msg>) -> bool {
        holds_in(&self.mem_cache, sid, handle)
    }
}

// ─── Postgres store — multi-instance deployments ─────────────────────────────

/// Same shape as `SqliteStore` (mem-cache of live handles + a `ipe_sessions`
/// blob table + idle-TTL sweep) but over a `PgPool`, for horizontally-scaled
/// deployments (Cloud Run / ECS / k8s) where a returning request can land on a
/// different replica than the one that created the session. `connStr` is a
/// `postgres://user:pass@host/db` URL. Implements `postgresStore`.
#[cfg(feature = "db")]
pub struct PostgresStore<Model, Msg> {
    pool: sqlx::PgPool,
    mem_cache: RwLock<SessionMap<Model, Msg>>,
    ttl: Duration,
    /// See [`SqliteStore::schema_tag`] — same H24 reject-before-deserialize gate.
    schema_tag: [u8; 32],
    streak: FaultStreak,
    tombstones: Tombstones,
    admission: SidAdmission,
}

#[cfg(feature = "db")]
impl<Model, Msg> PostgresStore<Model, Msg> {
    /// Open the PostgreSQL session store at `conn_str`.
    ///
    /// # Errors
    ///
    /// [`StoreOpenError`] when the pool is refused or the table cannot be created.
    pub async fn new(
        conn_str: &str,
        ttl: Duration,
        schema_tag: [u8; 32],
    ) -> Result<Self, StoreOpenError> {
        let url = crate::db::DbUrl::parse(conn_str).map_err(StoreOpenError::Connect)?;
        let pool =
            crate::db::VettedPool::<sqlx::Postgres>::connect(&url, SESSION_STORE_MAX_CONNECTIONS)
                .await
                .map_err(StoreOpenError::Connect)?
                .into_pool();
        // Pre-existing tables keep their old column set (IF NOT EXISTS) —
        // same fail-closed degradation as SqliteStore::new.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS ipe_sessions (\
             sid TEXT PRIMARY KEY, blob TEXT NOT NULL, last_seen BIGINT NOT NULL, \
             schema_tag TEXT NOT NULL)",
        )
        .execute(&pool)
        .await
        .map_err(|e| StoreOpenError::Schema(Self::failure(&e)))?;
        crate::db::own_pool(crate::db::PoolRole::SessionStore, &pool);
        Ok(PostgresStore {
            pool,
            mem_cache: RwLock::new(HashMap::new()),
            ttl,
            schema_tag,
            streak: FaultStreak::new(),
            tombstones: Tombstones::new(ttl),
            admission: SidAdmission::new(),
        })
    }

    fn failure(e: &sqlx::Error) -> crate::db::DriverFailure {
        crate::db::DriverFailure::of(crate::db::DbEngine::Postgres, e)
    }

    /// Settle one statement's outcome into the streak, as a typed fault.
    fn settle(
        &self,
        done: Result<sqlx::postgres::PgQueryResult, sqlx::Error>,
    ) -> Result<(), WriteFault> {
        self.streak.observe(
            "postgres",
            done.map(drop)
                .map_err(|e| WriteFault::Driver(Self::failure(&e))),
        )
    }

    async fn write_row(&self, sid: &str, blob: String) -> Result<(), WriteFault> {
        let done = sqlx::query(
            "INSERT INTO ipe_sessions (sid, blob, last_seen, schema_tag) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (sid) DO UPDATE SET blob = EXCLUDED.blob, \
             last_seen = EXCLUDED.last_seen, schema_tag = EXCLUDED.schema_tag",
        )
        .bind(sid)
        .bind(blob)
        .bind(now_secs())
        .bind(hex::encode(self.schema_tag))
        .execute(&self.pool)
        .await;
        self.settle(done)
    }

    async fn touch_row(&self, sid: &str) -> Result<(), WriteFault> {
        let done = sqlx::query("UPDATE ipe_sessions SET last_seen = $1 WHERE sid = $2")
            .bind(now_secs())
            .bind(sid)
            .execute(&self.pool)
            .await;
        self.settle(done)
    }

    async fn delete_row(&self, sid: &str) -> Result<(), WriteFault> {
        let done = sqlx::query("DELETE FROM ipe_sessions WHERE sid = $1")
            .bind(sid)
            .execute(&self.pool)
            .await;
        self.settle(done)
    }

    async fn prune_rows(&self) -> Result<(), WriteFault> {
        let done = sqlx::query("DELETE FROM ipe_sessions WHERE last_seen < $1")
            .bind(ttl_cutoff(now_secs(), self.ttl))
            .execute(&self.pool)
            .await;
        self.settle(done)
    }

    /// The persisted blob under `sid`, if its row is within the idle TTL.
    async fn read_row(&self, sid: &str) -> Option<String> {
        let row = sqlx::query_as::<_, (String,)>(
            "SELECT blob FROM ipe_sessions WHERE sid = $1 AND last_seen >= $2",
        )
        .bind(sid)
        .bind(ttl_cutoff(now_secs(), self.ttl))
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| WriteFault::Driver(Self::failure(&e)));
        self.streak
            .observe("postgres", row)
            .ok()
            .flatten()
            .map(|(blob,)| blob)
    }
}

#[cfg(feature = "db")]
#[async_trait]
impl<Model, Msg> SessionStore<Model, Msg> for PostgresStore<Model, Msg>
where
    Model: serde::Serialize + serde::de::DeserializeOwned + Clone + Send + Sync + 'static,
    Msg: Send + Sync + 'static,
{
    async fn get(&self, sid: &str) -> Option<SessionHandle<Model, Msg>> {
        let cached = touch_in(&self.mem_cache, sid)?;
        if self.touch_row(sid).await.is_err() {
            mark_in(&self.mem_cache, sid, &cached, Durability::Diverged);
        }
        Some(cached)
    }
    fn admission(&self) -> &SidAdmission {
        &self.admission
    }
    async fn get_reconstructing(
        &self,
        claim: SidClaim,
        make_init: &(dyn Fn() -> (Model, IpeCmd<Msg>) + Sync),
    ) -> Rejoin<Model, Msg> {
        if !self.admission.admits(&claim) {
            return Rejoin::Miss;
        }
        let sid = claim.key().as_str();
        if let Some(h) = self.get(sid).await {
            return Rejoin::Live(h);
        }
        match self.tombstones.cold_read(sid) {
            ColdRead::Miss => return Rejoin::Miss,
            ColdRead::RetryDelete => {
                self.tombstones.retry(sid, &self.delete_row(sid).await);
                return Rejoin::Miss;
            }
            ColdRead::Row => {}
        }
        // Cold: the sqlite store's self-contained framed blob. The legacy
        // `schema_tag` column is still written (NOT NULL) but never read.
        let decoded = self
            .read_row(sid)
            .await
            .and_then(|blob| decode_or_reconstruct_checkpoint(&self.schema_tag, &blob, make_init));
        decoded.map_or(Rejoin::Miss, |d| d.into_rejoin(claim))
    }
    async fn set(&self, sid: &str, handle: SessionHandle<Model, Msg>) -> Installed {
        let Some((slot, parts)) = install_in(&self.mem_cache, sid, &handle, checkpoint_parts)
        else {
            return Installed::Displaced;
        };
        let written = match frame_checkpoint(&self.schema_tag, &parts) {
            Ok(blob) => self.write_row(sid, blob).await,
            Err(fault) => Err(fault),
        };
        settle_in(&self.mem_cache, sid, &handle, slot, written)
    }
    async fn delete(&self, sid: &str) -> Deleted {
        remove_in(&self.mem_cache, sid);
        self.tombstones.deleted(sid, self.delete_row(sid).await)
    }
    async fn sweep(&self) -> Result<(), WriteFault> {
        let mut swept: Result<(), WriteFault> = Ok(());
        for sid in self.tombstones.snapshot() {
            let removed = self.delete_row(&sid).await;
            self.tombstones.retry(&sid, &removed);
            swept = swept.and(removed);
        }
        let pruned = self.prune_rows().await;
        // Bound the in-RAM handle cache by idle-TTL too (see SqliteStore::sweep)
        // — otherwise a cookie-less request flood grows mem_cache without bound.
        prune_in(&self.mem_cache, self.ttl);
        swept.and(pruned)
    }
    async fn web_sessions(&self) -> Vec<SessionHandle<Model, Msg>> {
        handles_in(&self.mem_cache)
    }
    async fn evict_unconnected(&self, need: Bytes) -> Bytes {
        evict_unconnected_from(&self.mem_cache, need)
    }
    fn holds(&self, sid: &str, handle: &SessionHandle<Model, Msg>) -> bool {
        holds_in(&self.mem_cache, sid, handle)
    }
}

// ─── Redis store — multi-instance, native TTL, no sweep ─────────────────────

/// Namespace session ids under a fixed prefix.
#[cfg(feature = "redis_store")]
fn redis_key(sid: &str) -> String {
    format!("ipe:sess:{sid}")
}

/// Cross-instance store backed by Redis. Sessions live under `ipe:sess:<sid>`
/// as a HASH (`blob` = the serde-JSON checkpoint, `tag` = the hex Model schema
/// tag — one key, one native Redis TTL, so the tag and blob can never expire
/// out of sync). Expiry is the server's job; there's no sweep loop for the
/// persisted side. A `mem_cache` keeps the same-process live handle (owns the
/// driver) so a hit on the originating replica reuses it. `addr` is a full
/// `redis://[:pass@]host:port/db` URL or a bare `host:port`. Mirrors
/// `redisStore` plus the H24 schema-tag gate.
#[cfg(feature = "redis_store")]
pub struct RedisStore<Model, Msg> {
    conn: redis::aio::MultiplexedConnection,
    mem_cache: RwLock<SessionMap<Model, Msg>>,
    ttl_secs: u64,
    /// See [`SqliteStore::schema_tag`] — same H24 reject-before-deserialize gate.
    schema_tag: [u8; 32],
    streak: FaultStreak,
    tombstones: Tombstones,
    admission: SidAdmission,
}

#[cfg(feature = "redis_store")]
impl<Model, Msg> RedisStore<Model, Msg> {
    /// Open the Redis session store at `addr`.
    ///
    /// # Errors
    ///
    /// [`StoreOpenError::Redis`] when the client cannot connect or answer `PING`;
    /// it keeps only the error kind, never the driver message.
    pub async fn new(
        addr: &str,
        ttl: Duration,
        schema_tag: [u8; 32],
    ) -> Result<Self, StoreOpenError> {
        let refused = |e: redis::RedisError| StoreOpenError::Redis(e.kind());
        let client = if addr.contains("://") {
            redis::Client::open(addr)
        } else {
            redis::Client::open(format!("redis://{addr}"))
        }
        .map_err(refused)?;
        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(refused)?;
        // Ping so a misconfigured URL fails at startup, not on first write.
        redis::cmd("PING")
            .query_async::<()>(&mut conn)
            .await
            .map_err(refused)?;
        Ok(RedisStore {
            conn,
            mem_cache: RwLock::new(HashMap::new()),
            ttl_secs: ttl.as_secs().max(1),
            schema_tag,
            streak: FaultStreak::new(),
            tombstones: Tombstones::new(Duration::from_secs(ttl.as_secs().max(1))),
            admission: SidAdmission::new(),
        })
    }

    /// Settle one command's outcome into the streak, keeping only the error kind.
    fn settle<T>(&self, done: Result<T, redis::RedisError>) -> Result<T, WriteFault> {
        self.streak
            .observe("redis", done.map_err(|e| WriteFault::Redis(e.kind())))
    }

    /// Write the framed `blob` as the session HASH and refresh its native TTL.
    async fn write_key(&self, sid: &str, blob: String) -> Result<(), WriteFault> {
        let mut conn = self.conn.clone();
        // HASH per session, one key + one TTL; the tag lives INSIDE the
        // framed blob, so nothing can drift apart.
        let key = redis_key(sid);
        let done = redis::pipe()
            .cmd("HSET")
            .arg(&key)
            .arg("blob")
            .arg(blob)
            .ignore()
            .cmd("EXPIRE")
            .arg(&key)
            .arg(self.ttl_secs)
            .ignore()
            .query_async::<()>(&mut conn)
            .await;
        self.settle(done)
    }

    /// Refresh the native TTL so an active session does not expire mid-conversation.
    async fn touch_key(&self, sid: &str) -> Result<(), WriteFault> {
        use redis::AsyncCommands;
        let mut conn = self.conn.clone();
        let secs = i64::try_from(self.ttl_secs).unwrap_or(i64::MAX);
        let done: Result<(), redis::RedisError> = conn.expire(redis_key(sid), secs).await;
        self.settle(done)
    }

    async fn delete_key(&self, sid: &str) -> Result<(), WriteFault> {
        use redis::AsyncCommands;
        let mut conn = self.conn.clone();
        let done: Result<(), redis::RedisError> = conn.del(redis_key(sid)).await;
        self.settle(done)
    }

    /// The session HASH's `blob` field: the self-contained framed checkpoint.
    ///
    /// A pre-HASH string key errs WRONGTYPE and takes the miss path. The
    /// legacy companion `tag` field is neither written nor read.
    async fn read_key(&self, sid: &str) -> Option<String> {
        let mut conn = self.conn.clone();
        let read = redis::cmd("HGET")
            .arg(redis_key(sid))
            .arg("blob")
            .query_async::<Option<String>>(&mut conn)
            .await;
        self.settle(read).ok().flatten()
    }
}

#[cfg(feature = "redis_store")]
#[async_trait]
impl<Model, Msg> SessionStore<Model, Msg> for RedisStore<Model, Msg>
where
    Model: serde::Serialize + serde::de::DeserializeOwned + Clone + Send + Sync + 'static,
    Msg: Send + Sync + 'static,
{
    async fn get(&self, sid: &str) -> Option<SessionHandle<Model, Msg>> {
        let cached = touch_in(&self.mem_cache, sid)?;
        if self.touch_key(sid).await.is_err() {
            mark_in(&self.mem_cache, sid, &cached, Durability::Diverged);
        }
        Some(cached)
    }
    fn admission(&self) -> &SidAdmission {
        &self.admission
    }
    async fn get_reconstructing(
        &self,
        claim: SidClaim,
        make_init: &(dyn Fn() -> (Model, IpeCmd<Msg>) + Sync),
    ) -> Rejoin<Model, Msg> {
        if !self.admission.admits(&claim) {
            return Rejoin::Miss;
        }
        let sid = claim.key().as_str();
        if let Some(h) = self.get(sid).await {
            return Rejoin::Live(h);
        }
        match self.tombstones.cold_read(sid) {
            ColdRead::Miss => return Rejoin::Miss,
            ColdRead::RetryDelete => {
                self.tombstones.retry(sid, &self.delete_key(sid).await);
                return Rejoin::Miss;
            }
            ColdRead::Row => {}
        }
        // Cold: Redis expires the key natively, so the row is live by
        // construction; it is not touched here — the restored session's first
        // checkpoint refreshes the TTL.
        let decoded = self
            .read_key(sid)
            .await
            .and_then(|blob| decode_or_reconstruct_checkpoint(&self.schema_tag, &blob, make_init));
        decoded.map_or(Rejoin::Miss, |d| d.into_rejoin(claim))
    }
    async fn set(&self, sid: &str, handle: SessionHandle<Model, Msg>) -> Installed {
        let Some((slot, parts)) = install_in(&self.mem_cache, sid, &handle, checkpoint_parts)
        else {
            return Installed::Displaced;
        };
        let written = match frame_checkpoint(&self.schema_tag, &parts) {
            Ok(blob) => self.write_key(sid, blob).await,
            Err(fault) => Err(fault),
        };
        settle_in(&self.mem_cache, sid, &handle, slot, written)
    }
    async fn delete(&self, sid: &str) -> Deleted {
        remove_in(&self.mem_cache, sid);
        self.tombstones.deleted(sid, self.delete_key(sid).await)
    }
    async fn sweep(&self) -> Result<(), WriteFault> {
        // Redis evicts the persisted blob natively; the sweep retries the
        // tombstones and bounds the in-RAM handle cache by idle-TTL —
        // otherwise a cookie-less request flood grows mem_cache without bound
        // → OOM (session-DoS). An evicted-but-valid session re-hydrates from
        // Redis on its next claimed request.
        let mut swept: Result<(), WriteFault> = Ok(());
        for sid in self.tombstones.snapshot() {
            let removed = self.delete_key(&sid).await;
            self.tombstones.retry(&sid, &removed);
            swept = swept.and(removed);
        }
        prune_in(&self.mem_cache, Duration::from_secs(self.ttl_secs));
        swept
    }
    async fn web_sessions(&self) -> Vec<SessionHandle<Model, Msg>> {
        handles_in(&self.mem_cache)
    }
    async fn evict_unconnected(&self, need: Bytes) -> Bytes {
        evict_unconnected_from(&self.mem_cache, need)
    }
    fn holds(&self, sid: &str, handle: &SessionHandle<Model, Msg>) -> bool {
        holds_in(&self.mem_cache, sid, handle)
    }
}

/// The session-store backend an operator asked for, parsed ONCE from the raw
/// `IPE_WEB_STORE` string into a closed set. Parsing is where the
/// prod-fail-closed decision lives: a backend whose feature this build lacks is
/// a [`StoreConfigError`], never a silent swap to a different backend. Making
/// "operator asked for sqlite, silently got file" unrepresentable means there is
/// no variant that stands for "asked-for-X-serving-Y"; a request this build
/// cannot honour does not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreBackend {
    Memory,
    /// The sqlx-free on-disk checkpoint map (the `ipe dev watch` dev-handoff store).
    File,
    Sqlite,
    Postgres,
    Redis,
}

/// A requested backend this build cannot serve — a fail-closed startup error.
///
/// The only text it quotes from outside the runtime, a connect refusal's
/// cause, is held as [`crate::system::RefusedText`], so its `Display` is safe
/// for a log line as is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreConfigError {
    /// `IPE_WEB_STORE` names a backend this build was compiled without.
    FeatureAbsent {
        /// The requested backend, as `IPE_WEB_STORE` spells it.
        backend: &'static str,
        /// The cargo feature that backend needs.
        feature: &'static str,
    },
    /// A connect-time policy gate refused the persistent backend.
    Refused {
        /// The requested backend, as `IPE_WEB_STORE` spells it.
        backend: &'static str,
        /// The gate's credential-free report.
        cause: crate::system::RefusedText,
    },
}

impl std::fmt::Display for StoreConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FeatureAbsent { backend, feature } => write!(
                f,
                "IPE_WEB_STORE={backend} requested but this build has no `{feature}` feature; \
                 build with `{feature}` or set IPE_WEB_STORE=file|memory"
            ),
            Self::Refused { backend, cause } => write!(
                f,
                "IPE_WEB_STORE={backend} refused at connect ({cause}); fix the connection URL \
                 or the server, or set IPE_WEB_STORE=file|memory"
            ),
        }
    }
}

impl std::error::Error for StoreConfigError {}

impl StoreBackend {
    /// Parse `IPE_WEB_STORE`. `sqlite`/`postgres` require the `db` feature;
    /// `redis` requires `redis_store`. A request this build cannot honour is a
    /// hard error (fail-closed), NEVER a silent downgrade — the operator asked
    /// for a persisted, possibly-remote store; quietly serving a different one
    /// (or losing state) is the failure mode this closes. An unrecognised value
    /// falls back to `memory` (the historical default for a typo / unset).
    ///
    /// Dev (`ipe dev watch`) is unaffected: it sets `IPE_WEB_STORE=file` explicitly,
    /// which every web build honours; it never asks for `sqlite`.
    fn parse(kind: &str) -> Result<StoreBackend, StoreConfigError> {
        match kind {
            "memory" => Ok(StoreBackend::Memory),
            "file" => Ok(StoreBackend::File),
            "sqlite" => {
                if cfg!(feature = "db") {
                    Ok(StoreBackend::Sqlite)
                } else {
                    Err(StoreConfigError::FeatureAbsent {
                        backend: "sqlite",
                        feature: "db",
                    })
                }
            }
            "postgres" => {
                if cfg!(feature = "db") {
                    Ok(StoreBackend::Postgres)
                } else {
                    Err(StoreConfigError::FeatureAbsent {
                        backend: "postgres",
                        feature: "db",
                    })
                }
            }
            "redis" => {
                if cfg!(feature = "redis_store") {
                    Ok(StoreBackend::Redis)
                } else {
                    Err(StoreConfigError::FeatureAbsent {
                        backend: "redis",
                        feature: "redis_store",
                    })
                }
            }
            _ => Ok(StoreBackend::Memory),
        }
    }
}

/// Select and open the session store named by the parsed `IPE_WEB_STORE`.
///
/// Fail-closed cases are a [`StoreConfigError`] (surfaced by the caller as a
/// task error, then stderr + exit 1, or a 503 mount route), NEVER a silent swap:
/// a backend this build cannot serve, and a persistent backend a connect-time
/// policy gate refuses (an SSRF-refused or unvettable connection URL, or an
/// engine below its version floor), since neither changes on retry. A persistent
/// backend that fails to connect for a transient reason (an unreachable server,
/// a failed version query or table setup) degrades to memory with a
/// credential-free log line: that is an environment fault, not an operator
/// mis-request. The `Model: Serialize` bound is for the persistent backends;
/// memory needs none, but a single signature keeps the codegen call uniform (it
/// derives serde on the model when emitting this). `schema_tag` (the
/// compile-time Model schema fingerprint, H24) is forwarded to the persistent
/// backends only; memory never round-trips through bytes.
pub async fn choose_store<Model, Msg>(
    kind: &str,
    path: &str,
    ttl: Duration,
    schema_tag: [u8; 32],
) -> Result<Arc<dyn SessionStore<Model, Msg>>, StoreConfigError>
where
    Model: serde::Serialize + serde::de::DeserializeOwned + Clone + Send + Sync + 'static,
    Msg: Send + Sync + 'static,
{
    let backend = StoreBackend::parse(kind)?;
    match backend {
        #[cfg(feature = "db")]
        StoreBackend::Sqlite => match SqliteStore::new(path, ttl, schema_tag).await {
            Ok(s) => {
                crate::system::emit_runtime_log("live", &format!("session store: sqlite @ {path}"));
                return Ok(Arc::new(s));
            }
            Err(e) if e.is_policy_refusal() => return Err(store_refused_error("sqlite", &e)),
            Err(e) => {
                crate::system::emit_runtime_log("live", &store_unavailable_message("sqlite", &e));
            }
        },
        #[cfg(feature = "db")]
        StoreBackend::Postgres => match PostgresStore::new(path, ttl, schema_tag).await {
            Ok(s) => {
                crate::system::emit_runtime_log("live", "session store: postgres");
                return Ok(Arc::new(s));
            }
            Err(e) if e.is_policy_refusal() => return Err(store_refused_error("postgres", &e)),
            Err(e) => {
                crate::system::emit_runtime_log("live", &store_unavailable_message("postgres", &e));
            }
        },
        #[cfg(feature = "redis_store")]
        StoreBackend::Redis => match RedisStore::new(path, ttl, schema_tag).await {
            Ok(s) => {
                crate::system::emit_runtime_log("live", "session store: redis");
                return Ok(Arc::new(s));
            }
            Err(e) => {
                crate::system::emit_runtime_log("live", &store_unavailable_message("redis", &e));
            }
        },
        #[cfg(feature = "web")]
        StoreBackend::File => {
            crate::system::emit_runtime_log("live", &format!("session store: file @ {path}"));
            return Ok(Arc::new(FileStore::new(path, ttl, schema_tag)));
        }
        // A parsed-but-feature-absent persistent backend is impossible
        // (`parse` fail-closes it); this arm catches `Memory` and — in a build
        // that parsed a persistent backend but whose feature cfg is off for
        // THIS arm's match (e.g. `File` without `web`) — falls to memory.
        _ => {}
    }
    // Memory store logs with a timestamp + human-readable TTL duration;
    // persistent backends log bare lines above (no duration needed).
    emit_memory_store_log(ttl);
    Ok(Arc::new(MemoryStore::new(ttl)))
}

/// The `session store: memory (ttl=…)` message with a human-readable TTL.
fn memory_store_message(ttl: Duration) -> String {
    format!("session store: memory (ttl={})", go_duration_string(ttl))
}

/// Emit the `[ipe.live] YYYY/MM/DD HH:MM:SS session store: memory (ttl=…)`
/// startup line. Shared so the in-process console sub-app mount emits the same
/// line format.
pub(crate) fn emit_memory_store_log(ttl: Duration) {
    crate::system::emit_runtime_log_stamped(
        &go_log_timestamp(),
        "live",
        &memory_store_message(ttl),
    );
}

/// Render the current local time as `YYYY/MM/DD HH:MM:SS`.
fn go_log_timestamp() -> String {
    chrono::Local::now().format("%Y/%m/%d %H:%M:%S").to_string()
}

/// Render a whole-second `Duration` as `1h0m0s`, `30m0s`, `45s`, `0s`.
/// Sub-second remainder is dropped (TTLs are whole seconds — `IPE_WEB_TTL`
/// parses to `u64` seconds).
fn go_duration_string(d: Duration) -> String {
    let total = d.as_secs();
    if total == 0 {
        return "0s".to_string();
    }
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let seconds = total % 60;
    if hours > 0 {
        format!("{hours}h{minutes}m{seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m{seconds}s")
    } else {
        format!("{seconds}s")
    }
}

#[cfg(test)]
mod format_tests {
    use super::{go_duration_string, go_log_timestamp, memory_store_message};
    use std::time::Duration;

    #[test]
    fn duration_string_format() {
        assert_eq!(go_duration_string(Duration::from_secs(3600)), "1h0m0s");
        assert_eq!(go_duration_string(Duration::from_secs(1800)), "30m0s");
        assert_eq!(go_duration_string(Duration::from_secs(90)), "1m30s");
        assert_eq!(go_duration_string(Duration::from_secs(45)), "45s");
        assert_eq!(go_duration_string(Duration::from_secs(0)), "0s");
        // Sub-second remainder dropped (whole-second TTL granularity).
        assert_eq!(go_duration_string(Duration::from_millis(1500)), "1s");
    }

    #[test]
    fn memory_line_shape() {
        let line = crate::system::runtime_log_line(
            crate::system::LogStream::Stderr,
            Some(&go_log_timestamp()),
            "live",
            &memory_store_message(Duration::from_secs(3600)),
        );
        let line = line.trim_start();
        // Tag first, then the `YYYY/MM/DD HH:MM:SS ` stamp, then the message.
        let after_tag = line.strip_prefix("[ipe.live] ");
        assert!(after_tag.is_some(), "the tag must lead the line: {line:?}");
        let stamp = after_tag
            .and_then(|rest| rest.strip_suffix("session store: memory (ttl=1h0m0s)"))
            .unwrap_or_default();
        assert_eq!(
            stamp.len(),
            20,
            "stamp `YYYY/MM/DD HH:MM:SS ` is 20 chars: {stamp:?}"
        );
        assert_eq!(stamp.matches('/').count(), 2);
        assert_eq!(stamp.matches(':').count(), 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::Html;
    use tokio::sync::mpsc::channel;

    // A minimal SessionEntry<(), ()> for exercising the store's TTL/touch logic.
    fn handle() -> SessionHandle<(), ()> {
        let (tx, _rx) = channel::<()>(1);
        let tree: Html<()> = Html::HText(String::new());
        Arc::new(Mutex::new(SessionEntry {
            model: (),
            rendered: crate::web::Rendered::first(crate::web::SessionKeys::distinct(), tree),
            tabs: crate::web::TabSeqs::default(),
            seq: 0,
            sse_tx: None,
            msg_tx: tx,
            event_tx: tokio::sync::mpsc::channel(1).0,
            entered_path: None,
            enter_tx: tokio::sync::mpsc::channel(1).0,
            #[cfg(feature = "debugger")]
            history: crate::debugger::RecordBuffer::measured(
                (),
                crate::debugger::DEFAULT_HISTORY_CAP,
            ),
            #[cfg(feature = "debugger")]
            debug_cursor: None,
            liveness: crate::web::SessionLiveness::default(),
            charge: crate::web::budget::Charge::detached(),
            cmds: Arc::new(crate::web::budget::SessionCmds::new()),
        }))
    }

    // A checkpointed live entry for `handle`, last seen at `seen`.
    fn live_at<Model, Msg>(handle: &SessionHandle<Model, Msg>, seen: Instant) -> Live<Model, Msg> {
        Live {
            seen,
            ..Live::fresh(handle)
        }
    }

    // Sids the claimed checkpoint lookups below parse.
    #[cfg(feature = "db")]
    const COLD_SID: &str = "c01dc01dc01dc01dc01dc01dc01dc01d";
    #[cfg(feature = "db")]
    const OLD_SID: &str = "01d001d001d001d001d001d001d001d0";

    // A per-process sid for test `lane`, so concurrent runs on one shared server never collide.
    #[cfg(any(feature = "db", feature = "redis_store"))]
    fn test_sid(lane: u16) -> String {
        format!("{lane:04x}{:028x}", std::process::id())
    }

    // The model a claimed lookup of `sid` restores verbatim, if any.
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    async fn restored_i32(s: &impl SessionStore<i32, ()>, sid: &str) -> Option<i32> {
        let init = || (0, IpeCmd::<()>::None);
        match reconstruct(s, sid, &init).await {
            Rejoin::Restored { model, .. } => Some(model),
            Rejoin::Live(_) | Rejoin::Rebuilt { .. } | Rejoin::Miss => None,
        }
    }

    /// Evicting for `need` bytes removes unconnected sessions oldest first,
    /// stops once `need` is freed, keeps a connected one, and gives the
    /// evicted bytes back to the budget.
    #[test]
    #[allow(clippy::expect_used)] // test: each fixed charge fits the budget; a second past now is representable
    fn evict_unconnected_oldest_first_keeps_connected() {
        use crate::web::budget::SessionBudget;
        let process = SessionBudget::process(Bytes::new(1000));
        let charged = |bytes: u64| {
            let h = handle();
            h.lock().unwrap_or_else(PoisonError::into_inner).charge = process
                .try_charge(Bytes::new(bytes))
                .expect("fits the budget");
            h
        };
        let base = Instant::now();
        let at = |secs| {
            base.checked_add(Duration::from_secs(secs))
                .expect("a second past now is representable")
        };
        let (sse, _sse_rx) = channel(1);
        let live = charged(100);
        live.lock().unwrap_or_else(PoisonError::into_inner).sse_tx = Some(sse);
        let map: SessionMap<(), ()> = HashMap::from([
            ("live".to_owned(), live_at(&live, base)),
            ("old".to_owned(), live_at(&charged(100), at(1))),
            ("mid".to_owned(), live_at(&charged(100), at(2))),
            ("new".to_owned(), live_at(&charged(100), at(3))),
        ]);
        let sessions = RwLock::new(map);
        assert_eq!(process.used(), Bytes::new(400));
        let freed = evict_unconnected_from(&sessions, Bytes::new(150));
        assert_eq!(freed, Bytes::new(200));
        let left = sessions.read().unwrap_or_else(PoisonError::into_inner);
        assert!(
            left.contains_key("live"),
            "a connected session is never evicted"
        );
        assert!(
            left.contains_key("new"),
            "eviction stops once `need` is freed"
        );
        assert!(!left.contains_key("old") && !left.contains_key("mid"));
        drop(left);
        assert_eq!(process.used(), Bytes::new(200));
    }

    /// Eviction skips a session with a Cmd holding a unit of its budget or a
    /// Msg queued for its driver, and takes it once both have drained.
    #[test]
    #[allow(clippy::expect_used)] // test: a fresh budget admits one Cmd; an empty queue takes one Msg
    fn evict_unconnected_skips_a_session_with_work_on_its_way() {
        let (msg_tx, mut msg_rx) = channel::<()>(1);
        let busy = handle();
        busy.lock().unwrap_or_else(PoisonError::into_inner).msg_tx = msg_tx;
        let permit = busy
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .cmds
            .try_permit()
            .expect("a fresh session admits a Cmd");
        let map: SessionMap<(), ()> = HashMap::from([("busy".to_owned(), Live::fresh(&busy))]);
        let sessions = RwLock::new(map);
        let everything = Bytes::new(u64::MAX);
        let _ = evict_unconnected_from(&sessions, everything);
        assert!(
            holds_in(&sessions, "busy", &busy),
            "a Cmd in flight keeps its session"
        );
        let queued = busy
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .msg_tx
            .clone();
        queued.try_send(()).expect("the queue has room");
        drop(permit);
        let _ = evict_unconnected_from(&sessions, everything);
        assert!(
            holds_in(&sessions, "busy", &busy),
            "a queued Msg keeps its session"
        );
        assert!(msg_rx.try_recv().is_ok());
        let _ = evict_unconnected_from(&sessions, everything);
        assert!(
            !holds_in(&sessions, "busy", &busy),
            "a drained session is evictable"
        );
    }

    /// A handle whose sid another handle took never writes over it: its
    /// checkpoint is refused, and the map and the row keep the installed one.
    #[cfg(feature = "db")]
    #[tokio::test]
    #[allow(clippy::expect_used)] // test: the temp store opens
    async fn sqlite_displaced_handle_never_overwrites_the_installed_one() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_displaced_{}.db", std::process::id()));
        let p = path.to_str().expect("a UTF-8 temp path");
        let _ = std::fs::remove_file(p);
        {
            let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), TEST_TAG)
                .await
                .expect("the temp SQLite store opens");
            let displaced = handle_i32(1);
            assert!(matches!(
                s.set(SID, Arc::clone(&displaced)).await,
                Installed::Held
            ));
            let _ = s.evict_unconnected(Bytes::new(u64::MAX)).await;
            assert!(!s.holds(SID, &displaced), "the idle session was evicted");
            let installed = handle_i32(2);
            assert!(matches!(
                s.set(SID, Arc::clone(&installed)).await,
                Installed::Held
            ));
            displaced
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .model = 99;
            assert!(matches!(
                s.set(SID, Arc::clone(&displaced)).await,
                Installed::Displaced
            ));
            assert!(
                s.holds(SID, &installed),
                "the installed handle keeps its sid"
            );
            assert!(!s.holds(SID, &displaced));
        }
        {
            let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), TEST_TAG)
                .await
                .expect("the temp SQLite store reopens");
            assert_eq!(
                restored_i32(&s, SID).await,
                Some(2),
                "the row holds the installed handle's checkpoint"
            );
        }
        let _ = std::fs::remove_file(p);
    }

    #[tokio::test]
    async fn memory_store_get_set_delete() {
        let s: MemoryStore<(), ()> = MemoryStore::new(Duration::from_secs(60));
        assert!(s.get("a").await.is_none());
        assert!(matches!(s.set("a", handle()).await, Installed::Held));
        assert!(s.get("a").await.is_some());
        assert!(matches!(s.delete("a").await, Deleted::Removed));
        assert!(s.get("a").await.is_none());
    }

    // A SessionEntry<i32, ()> with a given model, for the checkpoint tests.
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    fn handle_i32(model: i32) -> SessionHandle<i32, ()> {
        let (tx, _rx) = channel::<()>(1);
        let tree: Html<()> = Html::HText(String::new());
        Arc::new(Mutex::new(SessionEntry {
            model,
            rendered: crate::web::Rendered::first(crate::web::SessionKeys::distinct(), tree),
            tabs: crate::web::TabSeqs::default(),
            seq: 0,
            sse_tx: None,
            msg_tx: tx,
            event_tx: tokio::sync::mpsc::channel(1).0,
            entered_path: None,
            enter_tx: tokio::sync::mpsc::channel(1).0,
            #[cfg(feature = "debugger")]
            history: crate::debugger::RecordBuffer::measured(
                model,
                crate::debugger::DEFAULT_HISTORY_CAP,
            ),
            #[cfg(feature = "debugger")]
            debug_cursor: None,
            liveness: crate::web::SessionLiveness::default(),
            charge: crate::web::budget::Charge::detached(),
            cmds: Arc::new(crate::web::budget::SessionCmds::new()),
        }))
    }

    /// A fixed tag for tests that only exercise same-schema behaviour.
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    const TEST_TAG: [u8; 32] = [7u8; 32];

    /// Neither the fallback log line nor the `Debug` form of a store refusal
    /// carries the password or user its URL held.
    #[cfg(any(feature = "db", feature = "redis_store"))]
    fn assert_store_refusal_credential_free(backend: &str, refused: &StoreOpenError) {
        for rendered in [
            store_unavailable_message(backend, refused),
            format!("{refused:?}"),
        ] {
            assert!(
                !rendered.contains("s3cr3t-pw"),
                "password leaked: {rendered}"
            );
            assert!(!rendered.contains("admin"), "user leaked: {rendered}");
        }
    }

    /// A PostgreSQL store whose URL the driver rejects falls back without
    /// logging the credentials the URL carried.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn postgres_store_refusal_log_is_credential_free() {
        let url = "postgres://admin:s3cr3t-pw@db.internal/prod?sslmode=s3cr3t-pw";
        let opened: Result<PostgresStore<i32, ()>, _> =
            PostgresStore::new(url, Duration::from_secs(60), TEST_TAG).await;
        let refused = opened.err();
        assert!(refused.is_some(), "an invalid sslmode must be refused");
        if let Some(refused) = refused {
            assert_store_refusal_credential_free("postgres", &refused);
        }
    }

    /// A SQLite store that cannot open its file falls back without logging
    /// the driver's message.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn sqlite_store_refusal_log_is_credential_free() {
        let path = "/nonexistent-admin-s3cr3t-pw/sessions.db";
        let opened: Result<SqliteStore<i32, ()>, _> =
            SqliteStore::new(path, Duration::from_secs(60), TEST_TAG).await;
        let refused = opened.err();
        assert!(
            refused.is_some(),
            "a file in a missing directory must be refused"
        );
        if let Some(refused) = refused {
            assert!(matches!(refused, StoreOpenError::Connect(_)));
            assert_store_refusal_credential_free("sqlite", &refused);
        }
    }

    /// A PostgreSQL store the SSRF gate refuses fails startup instead of
    /// silently degrading to in-memory sessions, and the error is credential-free.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn postgres_store_policy_refusal_refuses_startup() {
        crate::system::locked_set_var("IPE_HTTP_DENY_PRIVATE", "1");
        for url in [
            "postgres://admin:s3cr3t-pw@127.0.0.1/prod",
            "postgres:///prod?user=admin&password=s3cr3t-pw",
            "postgres:///prod?host=/var/run/postgresql&password=s3cr3t-pw",
        ] {
            let refused =
                choose_store::<i32, ()>("postgres", url, Duration::from_secs(60), TEST_TAG)
                    .await
                    .err();
            assert!(
                refused.is_some(),
                "{url:?} must refuse startup, not fall back to memory"
            );
            if let Some(refused) = refused {
                assert!(
                    matches!(
                        refused,
                        StoreConfigError::Refused {
                            backend: "postgres",
                            ..
                        }
                    ),
                    "{refused:?}"
                );
                let msg = refused.to_string();
                assert!(msg.contains("refused"), "unexpected refusal: {msg}");
                assert!(!msg.contains("s3cr3t-pw"), "password leaked: {msg}");
                assert!(!msg.contains("admin"), "user leaked: {msg}");
            }
        }
        crate::system::locked_remove_var("IPE_HTTP_DENY_PRIVATE");
    }

    /// A transient connect failure is not a policy refusal: it keeps the
    /// documented fallback to memory.
    #[cfg(feature = "db")]
    #[test]
    fn transient_store_failures_are_not_policy_refusals() {
        use crate::db::{
            DbConnectError, DbEngine, DriverFailure, EngineVersion, EngineVersionError,
        };
        use crate::ssrf::{BlockedHost, BlockedRange, HostShown, SsrfRefusal};
        use std::net::{IpAddr, Ipv4Addr};
        let transient = [
            StoreOpenError::Connect(DbConnectError::Unreachable(DriverFailure::of(
                DbEngine::Sqlite,
                &sqlx::Error::Io(std::io::Error::other("io")),
            ))),
            StoreOpenError::Connect(DbConnectError::VersionUnreadable(DriverFailure::of(
                DbEngine::Sqlite,
                &sqlx::Error::PoolTimedOut,
            ))),
            StoreOpenError::Schema(DriverFailure::of(
                DbEngine::Sqlite,
                &sqlx::Error::RowNotFound,
            )),
        ];
        for e in &transient {
            assert!(!e.is_policy_refusal(), "{e} must fall back, not refuse");
        }
        let policy = [
            StoreOpenError::Connect(DbConnectError::RelayUnavailable),
            StoreOpenError::Connect(DbConnectError::HostRefused(SsrfRefusal::LocalSocket)),
            StoreOpenError::Connect(DbConnectError::InvalidUrl),
            StoreOpenError::Connect(DbConnectError::MisplacedUserinfo),
            StoreOpenError::Connect(DbConnectError::TooManyDialTargets { limit: 8 }),
            StoreOpenError::Connect(DbConnectError::UnsupportedScheme),
            StoreOpenError::Connect(DbConnectError::EngineMismatch {
                url: DbEngine::Sqlite,
                driver: DbEngine::Postgres,
            }),
            StoreOpenError::Connect(DbConnectError::HostRefused(SsrfRefusal::Blocked {
                host: BlockedHost::Named {
                    host: "10.0.0.1".to_owned(),
                    ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                },
                range: BlockedRange::Private,
            })),
            StoreOpenError::Connect(DbConnectError::HostRefused(SsrfRefusal::Unresolvable {
                host: HostShown::Named("db.invalid".to_owned()),
                kind: std::io::ErrorKind::NotFound,
            })),
            StoreOpenError::Connect(DbConnectError::HostRefused(SsrfRefusal::NoAddresses {
                host: HostShown::Named("db.invalid".to_owned()),
            })),
            StoreOpenError::Connect(DbConnectError::HostRefused(SsrfRefusal::Timeout {
                host: HostShown::Named("db.invalid".to_owned()),
                after: Duration::from_secs(1),
            })),
            StoreOpenError::Connect(DbConnectError::HostRefused(SsrfRefusal::Deadline(
                crate::system::EnvCeiling::new(
                    "IPE_HTTP_DNS_TIMEOUT_MS",
                    5_000,
                    crate::system::ZeroCeiling::Refused,
                    "decimal millisecond count",
                )
                .parse(Ok("5s".to_owned()))
                .expect_err("a suffixed deadline is refused"),
            ))),
            StoreOpenError::Connect(DbConnectError::HostRefused(SsrfRefusal::UnprovenTarget)),
            StoreOpenError::Connect(DbConnectError::HostRefused(
                SsrfRefusal::UnpinnableTlsName {
                    host: crate::ssrf::ConfiguredHost::from_config("db.example".to_owned()),
                },
            )),
            StoreOpenError::Connect(DbConnectError::EngineRefused(
                EngineVersionError::UnknownEngine,
            )),
            StoreOpenError::Connect(DbConnectError::EngineRefused(
                EngineVersionError::Unparseable {
                    engine: DbEngine::Postgres,
                },
            )),
            StoreOpenError::Connect(DbConnectError::EngineRefused(
                EngineVersionError::BelowFloor {
                    engine: DbEngine::Sqlite,
                    found: EngineVersion::new(1, 0),
                },
            )),
        ];
        for e in &policy {
            assert!(e.is_policy_refusal(), "{e} must refuse startup");
        }
    }

    /// A Redis store that cannot connect falls back logging only the error kind.
    #[cfg(feature = "redis_store")]
    #[tokio::test]
    async fn redis_store_refusal_log_is_credential_free() {
        let url = "redis://admin:s3cr3t-pw@127.0.0.1:1/";
        let opened: Result<RedisStore<i32, ()>, _> =
            RedisStore::new(url, Duration::from_secs(60), TEST_TAG).await;
        let refused = opened.err();
        assert!(refused.is_some(), "a closed port must be refused");
        if let Some(refused) = refused {
            assert_store_refusal_credential_free("redis", &refused);
        }
    }

    /// A SQLite session store registers its pool, so a served app's stop closes
    /// it (and its WAL) before the exit.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn a_sqlite_session_store_registers_its_pool_for_the_stop() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_owned_{}.db", std::process::id()));
        let p = path.to_str().expect("the temp path is UTF-8");
        let _ = std::fs::remove_file(p);
        let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), TEST_TAG)
            .await
            .expect("the store opens");
        assert!(
            crate::db::process_pools().open_in(crate::db::PoolRole::SessionStore) >= 1,
            "the session store's pool is never closed by the stop"
        );
        s.pool.close().await;
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{p}{suffix}"));
        }
    }

    /// Restart survival: a store writes a checkpoint, a FRESH store over the same
    /// file (no mem-cache) restores it verbatim through a claimed lookup.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn sqlite_store_checkpoint_survives_restart() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_p5_{}.db", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        {
            let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), TEST_TAG)
                .await
                .unwrap();
            assert!(matches!(s.set(SID, handle_i32(42)).await, Installed::Held));
            // same-process get is a Web cache hit
            assert!(s.get(SID).await.is_some());
        }
        {
            // "restart": new store, empty mem-cache → decodes the checkpoint
            let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), TEST_TAG)
                .await
                .unwrap();
            assert_eq!(
                restored_i32(&s, SID).await,
                Some(42),
                "the checkpoint restores verbatim after a restart"
            );
        }
        let _ = std::fs::remove_file(p);
    }

    /// H24: a checkpoint written under a DIFFERENT Model schema tag is
    /// never restored — a claimed lookup is a miss (fresh `init`), never a
    /// stale shape.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn sqlite_store_rejects_a_row_written_by_a_different_schema_tag() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_h24_{}.db", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        {
            let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), [0xAA; 32])
                .await
                .unwrap();
            assert!(matches!(s.set(SID, handle_i32(42)).await, Installed::Held));
        }
        {
            // "redeploy with a changed Model": same file, different tag.
            let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), [0xBB; 32])
                .await
                .unwrap();
            assert!(
                restored_i32(&s, SID).await.is_none(),
                "a foreign-schema checkpoint must be rejected before deserialize"
            );
        }
        let _ = std::fs::remove_file(p);
    }

    /// The gate isn't "always reject": the SAME tag on both sides still
    /// restores the checkpoint verbatim.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn sqlite_store_accepts_a_row_written_by_the_same_schema_tag() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_h24ok_{}.db", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        {
            let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), [0xAA; 32])
                .await
                .unwrap();
            assert!(matches!(s.set(SID, handle_i32(42)).await, Installed::Held));
        }
        {
            let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), [0xAA; 32])
                .await
                .unwrap();
            assert_eq!(
                restored_i32(&s, SID).await,
                Some(42),
                "the checkpoint restores verbatim under the same schema tag"
            );
        }
        let _ = std::fs::remove_file(p);
    }

    /// Postgres mirror of the reject test — `IPE_TEST_PG_URL`-gated.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn postgres_store_rejects_a_row_written_by_a_different_schema_tag() {
        let Ok(url) = crate::system::read_env_var("IPE_TEST_PG_URL") else {
            return;
        };
        let sid = test_sid(1);
        {
            let s: PostgresStore<i32, ()> =
                PostgresStore::new(&url, Duration::from_secs(60), [0xAA; 32])
                    .await
                    .unwrap();
            assert!(matches!(s.delete(&sid).await, Deleted::Removed));
            assert!(matches!(s.set(&sid, handle_i32(7)).await, Installed::Held));
        }
        {
            let s: PostgresStore<i32, ()> =
                PostgresStore::new(&url, Duration::from_secs(60), [0xBB; 32])
                    .await
                    .unwrap();
            assert!(
                restored_i32(&s, &sid).await.is_none(),
                "a foreign-schema checkpoint must be rejected before deserialize"
            );
            assert!(matches!(s.delete(&sid).await, Deleted::Removed));
        }
    }

    /// Redis mirror of the reject test (HASH-per-session shape) —
    /// `IPE_TEST_REDIS_URL`-gated.
    #[cfg(feature = "redis_store")]
    #[tokio::test]
    async fn redis_store_rejects_a_row_written_by_a_different_schema_tag() {
        let Ok(url) = crate::system::read_env_var("IPE_TEST_REDIS_URL") else {
            return;
        };
        let sid = test_sid(2);
        {
            let s: RedisStore<i32, ()> = RedisStore::new(&url, Duration::from_secs(60), [0xAA; 32])
                .await
                .unwrap();
            assert!(matches!(s.delete(&sid).await, Deleted::Removed));
            assert!(matches!(s.set(&sid, handle_i32(9)).await, Installed::Held));
        }
        {
            let s: RedisStore<i32, ()> = RedisStore::new(&url, Duration::from_secs(60), [0xBB; 32])
                .await
                .unwrap();
            assert!(
                restored_i32(&s, &sid).await.is_none(),
                "a foreign-schema checkpoint must be rejected before deserialize"
            );
            assert!(matches!(s.delete(&sid).await, Deleted::Removed));
        }
    }

    #[cfg(feature = "redis_store")]
    #[test]
    fn redis_key_is_namespaced() {
        assert_eq!(redis_key("abc"), "ipe:sess:abc");
    }

    /// Postgres restart survival — gated on `IPE_TEST_PG_URL` (a reachable
    /// `postgres://…` URL). Skipped when unset so CI without a PG server stays
    /// green; run locally with the env var to exercise the real round-trip.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn postgres_store_checkpoint_survives_restart() {
        let Ok(url) = crate::system::read_env_var("IPE_TEST_PG_URL") else {
            return;
        };
        let sid = test_sid(3);
        {
            let s: PostgresStore<i32, ()> =
                PostgresStore::new(&url, Duration::from_secs(60), TEST_TAG)
                    .await
                    .unwrap();
            assert!(matches!(s.delete(&sid).await, Deleted::Removed));
            assert!(matches!(s.set(&sid, handle_i32(7)).await, Installed::Held));
            assert!(s.get(&sid).await.is_some());
        }
        {
            let s: PostgresStore<i32, ()> =
                PostgresStore::new(&url, Duration::from_secs(60), TEST_TAG)
                    .await
                    .unwrap();
            assert_eq!(
                restored_i32(&s, &sid).await,
                Some(7),
                "the checkpoint restores verbatim after a restart"
            );
            assert!(matches!(s.delete(&sid).await, Deleted::Removed));
        }
    }

    /// Redis restart survival — gated on `IPE_TEST_REDIS_URL`. Skipped when unset.
    #[cfg(feature = "redis_store")]
    #[tokio::test]
    async fn redis_store_checkpoint_survives_restart() {
        let Ok(url) = crate::system::read_env_var("IPE_TEST_REDIS_URL") else {
            return;
        };
        let sid = test_sid(4);
        {
            let s: RedisStore<i32, ()> = RedisStore::new(&url, Duration::from_secs(60), TEST_TAG)
                .await
                .unwrap();
            assert!(matches!(s.delete(&sid).await, Deleted::Removed));
            assert!(matches!(s.set(&sid, handle_i32(9)).await, Installed::Held));
            assert!(s.get(&sid).await.is_some());
        }
        {
            let s: RedisStore<i32, ()> = RedisStore::new(&url, Duration::from_secs(60), TEST_TAG)
                .await
                .unwrap();
            assert_eq!(
                restored_i32(&s, &sid).await,
                Some(9),
                "the checkpoint restores verbatim after a restart"
            );
            assert!(matches!(s.delete(&sid).await, Deleted::Removed));
        }
    }

    /// `web_sessions()` lists exactly the locally-live handles: empty on a
    /// fresh store, grows with `set()`, shrinks with `delete()`.
    #[tokio::test]
    async fn memory_store_web_sessions_lists_only_locally_cached_handles() {
        let s: MemoryStore<(), ()> = MemoryStore::new(Duration::from_secs(60));
        assert!(s.web_sessions().await.is_empty());
        assert!(matches!(s.set("a", handle()).await, Installed::Held));
        assert!(matches!(s.set("b", handle()).await, Installed::Held));
        assert_eq!(s.web_sessions().await.len(), 2);
        assert!(matches!(s.delete("a").await, Deleted::Removed));
        assert_eq!(s.web_sessions().await.len(), 1);
    }

    /// A persisted row with NO in-process handle (another replica's session,
    /// seeded via raw SQL bypassing `set()`) is NOT a live session — only the
    /// locally-`set()` one is returned.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn sqlite_store_web_sessions_excludes_cold_rows() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_webs_{}.db", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), TEST_TAG)
            .await
            .unwrap();
        // Cross-replica cold row: valid framed blob, but no mem_cache entry.
        sqlx::query(
            "INSERT INTO ipe_sessions (sid, blob, last_seen, schema_tag) VALUES (?, ?, ?, ?)",
        )
        .bind(COLD_SID)
        .bind(encode_checkpoint(&TEST_TAG, None, &41_i32).unwrap())
        .bind(now_secs())
        .bind(hex::encode(TEST_TAG))
        .execute(&s.pool)
        .await
        .unwrap();
        assert!(matches!(
            s.set("web_sid", handle_i32(42)).await,
            Installed::Held
        ));

        let live = s.web_sessions().await;
        assert_eq!(
            live.len(),
            1,
            "only the locally-set session has a live handle; the cold row \
             (no SSE connection in this process) must be excluded"
        );
        // The cold row is still a valid checkpoint through a claimed lookup.
        assert_eq!(restored_i32(&s, COLD_SID).await, Some(41));
        let _ = std::fs::remove_file(p);
    }

    /// `v2` wire format: the raw persisted blob is
    /// `base64(schema_tag(32) ++ serde_json(model))` — the JSON body is
    /// field-keyed and self-describing (what makes an additive splice
    /// possible) — and a fresh store still restores it verbatim.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn sqlite_store_new_format_round_trips_model_through_json() {
        use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_json_{}.db", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        let model: i32 = 42;
        {
            let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), TEST_TAG)
                .await
                .unwrap();
            assert!(matches!(
                s.set(SID, handle_i32(model)).await,
                Installed::Held
            ));
            // Read the raw column back and assert the format identity.
            let row: (String,) = sqlx::query_as("SELECT blob FROM ipe_sessions WHERE sid = ?")
                .bind(SID)
                .fetch_one(&s.pool)
                .await
                .unwrap();
            let framed = B64
                .decode(row.0.as_bytes())
                .expect("the persisted blob must be valid base64");
            let body_len = serde_json::to_vec(&model).unwrap().len();
            assert_eq!(
                framed.len(),
                32 + body_len,
                "blob must be exactly schema_tag(32) ++ serde_json(model)"
            );
            assert_eq!(framed.get(..32).unwrap(), TEST_TAG);
        }
        {
            let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), TEST_TAG)
                .await
                .unwrap();
            assert_eq!(
                restored_i32(&s, SID).await,
                Some(42),
                "the checkpoint restores verbatim through the json path"
            );
        }
        let _ = std::fs::remove_file(p);
    }

    /// A non-base64 garbage row (seeded directly, bypassing `set()`) is
    /// rejected cleanly by a claimed lookup — a miss, NEVER a panic: it fails base64
    /// decode (or the tag prefix) and takes the same fail-soft path a
    /// corrupt blob always took.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn sqlite_store_garbage_row_is_rejected_not_crashed() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_garbage_{}.db", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), TEST_TAG)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO ipe_sessions (sid, blob, last_seen, schema_tag) VALUES (?, ?, ?, ?)",
        )
        .bind(OLD_SID)
        .bind("!! not base64 !!")
        .bind(now_secs())
        .bind(hex::encode(TEST_TAG))
        .execute(&s.pool)
        .await
        .unwrap();
        assert!(
            restored_i32(&s, OLD_SID).await.is_none(),
            "a garbage row ages out via the fail-soft miss path"
        );
        let _ = std::fs::remove_file(p);
    }

    /// Postgres mirrors of the json round-trip + garbage-row fail-soft —
    /// `IPE_TEST_PG_URL`-gated.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn postgres_store_new_format_round_trips_and_rejects_garbage_rows() {
        let Ok(url) = crate::system::read_env_var("IPE_TEST_PG_URL") else {
            return;
        };
        let sid = test_sid(5);
        let old_sid = test_sid(6);
        {
            let s: PostgresStore<i32, ()> =
                PostgresStore::new(&url, Duration::from_secs(60), TEST_TAG)
                    .await
                    .unwrap();
            assert!(matches!(s.delete(&sid).await, Deleted::Removed));
            assert!(matches!(s.delete(&old_sid).await, Deleted::Removed));
            assert!(matches!(s.set(&sid, handle_i32(7)).await, Installed::Held));
            sqlx::query(
                "INSERT INTO ipe_sessions (sid, blob, last_seen, schema_tag) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(&old_sid)
            .bind("!! not base64 !!")
            .bind(now_secs())
            .bind(hex::encode(TEST_TAG))
            .execute(&s.pool)
            .await
            .unwrap();
        }
        {
            let s: PostgresStore<i32, ()> =
                PostgresStore::new(&url, Duration::from_secs(60), TEST_TAG)
                    .await
                    .unwrap();
            assert_eq!(
                restored_i32(&s, &sid).await,
                Some(7),
                "the checkpoint restores verbatim through the json path"
            );
            assert!(restored_i32(&s, &old_sid).await.is_none());
            assert!(matches!(s.delete(&sid).await, Deleted::Removed));
            assert!(matches!(s.delete(&old_sid).await, Deleted::Removed));
        }
    }

    /// Redis mirrors of the json round-trip + garbage-row fail-soft —
    /// `IPE_TEST_REDIS_URL`-gated.
    #[cfg(feature = "redis_store")]
    #[tokio::test]
    async fn redis_store_new_format_round_trips_and_rejects_garbage_rows() {
        let Ok(url) = crate::system::read_env_var("IPE_TEST_REDIS_URL") else {
            return;
        };
        let sid = test_sid(7);
        let old_sid = test_sid(8);
        {
            let s: RedisStore<i32, ()> = RedisStore::new(&url, Duration::from_secs(60), TEST_TAG)
                .await
                .unwrap();
            assert!(matches!(s.delete(&sid).await, Deleted::Removed));
            assert!(matches!(s.delete(&old_sid).await, Deleted::Removed));
            assert!(matches!(s.set(&sid, handle_i32(9)).await, Installed::Held));
            // Garbage row: non-base64 text in the blob field.
            let mut conn = s.conn.clone();
            let _: () = redis::cmd("HSET")
                .arg(redis_key(&old_sid))
                .arg("blob")
                .arg("!! not base64 !!")
                .arg("tag")
                .arg(hex::encode(TEST_TAG))
                .query_async(&mut conn)
                .await
                .unwrap();
        }
        {
            let s: RedisStore<i32, ()> = RedisStore::new(&url, Duration::from_secs(60), TEST_TAG)
                .await
                .unwrap();
            assert_eq!(
                restored_i32(&s, &sid).await,
                Some(9),
                "the checkpoint restores verbatim through the json path"
            );
            assert!(restored_i32(&s, &old_sid).await.is_none());
            assert!(matches!(s.delete(&sid).await, Deleted::Removed));
            assert!(matches!(s.delete(&old_sid).await, Deleted::Removed));
        }
    }

    /// Postgres mirror of the cold-row exclusion — `IPE_TEST_PG_URL`-gated.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn postgres_store_web_sessions_excludes_cold_rows() {
        let Ok(url) = crate::system::read_env_var("IPE_TEST_PG_URL") else {
            return;
        };
        let cold_sid = format!("pgtest_cold_{}", std::process::id());
        let web_sid = format!("pgtest_web_{}", std::process::id());
        let s: PostgresStore<i32, ()> = PostgresStore::new(&url, Duration::from_secs(60), TEST_TAG)
            .await
            .unwrap();
        assert!(matches!(s.delete(&cold_sid).await, Deleted::Removed));
        assert!(matches!(s.delete(&web_sid).await, Deleted::Removed));
        sqlx::query(
            "INSERT INTO ipe_sessions (sid, blob, last_seen, schema_tag) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&cold_sid)
        .bind("41")
        .bind(now_secs())
        .bind(hex::encode(TEST_TAG))
        .execute(&s.pool)
        .await
        .unwrap();
        assert!(matches!(
            s.set(&web_sid, handle_i32(42)).await,
            Installed::Held
        ));
        assert_eq!(s.web_sessions().await.len(), 1);
        assert!(matches!(s.delete(&cold_sid).await, Deleted::Removed));
        assert!(matches!(s.delete(&web_sid).await, Deleted::Removed));
    }

    /// Redis mirror of the cold-row exclusion — `IPE_TEST_REDIS_URL`-gated.
    #[cfg(feature = "redis_store")]
    #[tokio::test]
    async fn redis_store_web_sessions_excludes_cold_rows() {
        let Ok(url) = crate::system::read_env_var("IPE_TEST_REDIS_URL") else {
            return;
        };
        let cold_sid = format!("redistest_cold_{}", std::process::id());
        let web_sid = format!("redistest_web_{}", std::process::id());
        let s: RedisStore<i32, ()> = RedisStore::new(&url, Duration::from_secs(60), TEST_TAG)
            .await
            .unwrap();
        assert!(matches!(s.delete(&cold_sid).await, Deleted::Removed));
        assert!(matches!(s.delete(&web_sid).await, Deleted::Removed));
        // Cross-replica cold row: HASH written directly, no mem_cache entry.
        let mut conn = s.conn.clone();
        let _: () = redis::cmd("HSET")
            .arg(redis_key(&cold_sid))
            .arg("blob")
            .arg("41")
            .arg("tag")
            .arg(hex::encode(TEST_TAG))
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(matches!(
            s.set(&web_sid, handle_i32(42)).await,
            Installed::Held
        ));
        assert_eq!(s.web_sessions().await.len(), 1);
        assert!(matches!(s.delete(&cold_sid).await, Deleted::Removed));
        assert!(matches!(s.delete(&web_sid).await, Deleted::Removed));
    }

    /// Symlinks planted at the map path and its temp name are never followed.
    ///
    /// The persisted map replaces the links, and their targets survive.
    #[cfg(all(feature = "web", unix))]
    #[tokio::test]
    async fn file_store_never_writes_through_planted_symlinks() {
        let dir = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_file_links_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(std::fs::create_dir_all(&dir).is_ok(), "make scratch dir");
        let victim = dir.join("victim.txt");
        assert!(std::fs::write(&victim, "keep").is_ok(), "write victim");
        let map = dir.join("sessions.json");
        assert!(
            std::os::unix::fs::symlink(&victim, &map).is_ok(),
            "map link"
        );
        assert!(
            std::os::unix::fs::symlink(&victim, dir.join("sessions.tmp")).is_ok(),
            "temp link"
        );
        let Some(p) = map.to_str() else {
            assert!(map.to_str().is_some(), "utf-8 temp path");
            return;
        };
        let s: FileStore<i32, ()> = FileStore::new(p, Duration::from_secs(60), TEST_TAG);
        assert!(matches!(s.set("s1", handle_i32(7)).await, Installed::Held));
        assert_eq!(
            std::fs::read_to_string(&victim).ok().as_deref(),
            Some("keep")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A checkpoint persists no style nonce, so a restored session is stamped
    /// with keys of its own, never the ones its predecessor served.
    #[cfg(feature = "web")]
    #[tokio::test]
    async fn checkpoint_carries_no_style_nonce() {
        let dir = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_file_nonce_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(std::fs::create_dir_all(&dir).is_ok(), "make scratch dir");
        let map = dir.join("sessions.json");
        let Some(p) = map.to_str() else {
            assert!(map.to_str().is_some(), "utf-8 temp path");
            return;
        };
        let sid = "5e55105e55105e55105e55105e551050";
        let handle = handle_i32(42);
        let (token, epoch) = {
            let e = handle.lock().unwrap_or_else(PoisonError::into_inner);
            (e.rendered.stamp().as_token(), e.rendered.epoch().to_token())
        };
        let raw: Vec<u8> = (0..token.len())
            .step_by(2)
            .filter_map(|i| token.get(i..i + 2))
            .filter_map(|pair| u8::from_str_radix(pair, 16).ok())
            .collect();
        assert_eq!(raw.len(), 16, "{token}");
        assert!(matches!(
            FileStore::<i32, ()>::new(p, Duration::from_secs(60), TEST_TAG)
                .set(sid, handle.clone())
                .await,
            Installed::Held
        ));

        let file = std::fs::read_to_string(p).unwrap_or_default();
        let blobs: HashMap<String, (String, i64)> = serde_json::from_str(&file).unwrap_or_default();
        let blob = blobs.get(sid).map(|(b, _)| b.clone()).unwrap_or_default();
        assert!(
            split_checkpoint(&blob).is_some(),
            "the checkpoint is written: {file}"
        );
        let framed = {
            use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
            B64.decode(&blob).unwrap_or_default()
        };
        assert!(!framed.is_empty(), "{blob}");
        assert!(!file.contains(&token), "{file}");
        assert!(
            !framed.windows(raw.len()).any(|w| w == raw.as_slice())
                && !framed.windows(token.len()).any(|w| w == token.as_bytes()),
            "the checkpoint holds no nonce"
        );

        let restarted: FileStore<i32, ()> = FileStore::new(p, Duration::from_secs(60), TEST_TAG);
        assert_eq!(restored_i32(&restarted, sid).await, Some(42));
        #[allow(clippy::expect_used)] // the test host's CSPRNG yields entropy
        let keys = crate::web::SessionKeys::mint().expect("fresh session keys");
        let fresh = crate::web::Rendered::first(keys, Html::<()>::HText(String::new()));
        assert_ne!(
            fresh.stamp().as_token(),
            token,
            "a restored session has its own nonce"
        );
        assert_ne!(fresh.epoch().to_token(), epoch, "and its own incarnation");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every write, successful or failed, leaves only the map itself in its directory.
    #[cfg(feature = "web")]
    #[tokio::test]
    async fn file_store_leaves_no_temp_file_behind() {
        let dir = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_file_notmp_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(std::fs::create_dir_all(&dir).is_ok(), "make scratch dir");
        let entries = |d: &std::path::Path| {
            std::fs::read_dir(d).map_or_else(
                |_| Vec::new(),
                |it| {
                    it.filter_map(|e| e.ok().map(|e| e.file_name()))
                        .collect::<Vec<_>>()
                },
            )
        };
        let map = dir.join("sessions.json");
        let Some(p) = map.to_str() else {
            assert!(map.to_str().is_some(), "utf-8 temp path");
            return;
        };
        let s: FileStore<i32, ()> = FileStore::new(p, Duration::from_secs(60), TEST_TAG);
        assert!(matches!(s.set("s1", handle_i32(7)).await, Installed::Held));
        assert!(matches!(s.delete("s1").await, Deleted::Removed));
        assert_eq!(
            entries(&dir),
            vec![std::ffi::OsString::from("sessions.json")]
        );

        // The map path is a non-empty directory: every rename fails.
        let blocked = dir.join("blocked.json");
        assert!(std::fs::create_dir_all(blocked.join("x")).is_ok(), "block");
        let Some(bp) = blocked.to_str() else {
            return;
        };
        let s: FileStore<i32, ()> = FileStore::new(bp, Duration::from_secs(60), TEST_TAG);
        assert!(matches!(
            s.set("s1", handle_i32(7)).await,
            Installed::Refused(_)
        ));
        assert!(matches!(
            s.set("s2", handle_i32(8)).await,
            Installed::Refused(_)
        ));
        assert!(s.streak.failing(), "the failure is recorded");
        let mut left = entries(&dir);
        left.sort();
        assert_eq!(
            left,
            vec![
                std::ffi::OsString::from("blocked.json"),
                std::ffi::OsString::from("sessions.json")
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `write_map` names the step that failed, never a bare `io::Error`: a
    /// rename blocked by a non-empty directory is `Commit`, a missing parent
    /// directory for the sibling itself is `CreateTemp`.
    #[cfg(feature = "web")]
    #[tokio::test]
    async fn file_store_write_map_names_the_failing_step() {
        let dir = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_file_persisterr_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(std::fs::create_dir_all(&dir).is_ok(), "make scratch dir");

        let blocked = dir.join("blocked.json");
        assert!(std::fs::create_dir_all(blocked.join("x")).is_ok(), "block");
        let Some(bp) = blocked.to_str() else {
            let _ = std::fs::remove_dir_all(&dir);
            return;
        };
        let s: FileStore<i32, ()> = FileStore::new(bp, Duration::from_secs(60), TEST_TAG);
        let disk = s.disk.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let err = s.write_map(&disk).err();
        assert!(matches!(err, Some(PersistError::Commit(_))), "{err:?}");

        let missing = dir.join("missing_parent").join("sessions.json");
        let Some(mp) = missing.to_str() else {
            let _ = std::fs::remove_dir_all(&dir);
            return;
        };
        let s2: FileStore<i32, ()> = FileStore::new(mp, Duration::from_secs(60), TEST_TAG);
        let disk2 = s2.disk.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let err2 = s2.write_map(&disk2).err();
        assert!(
            matches!(err2, Some(PersistError::CreateTemp(_))),
            "{err2:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `PersistError`'s `Display` (the text the persist log line carries) names
    /// the step and the error kind, never the inner message — a refused
    /// scratch location displays the path it refused.
    #[cfg(feature = "web")]
    #[test]
    fn persist_error_display_omits_the_inner_message() {
        let secret_path = "/srv/app/ipe-sessions/private-map.json";
        let inner = || std::io::Error::other(format!("refusing scratch location {secret_path}"));
        let shown = [
            PersistError::CreateTemp(inner()),
            PersistError::WriteTemp(inner()),
            PersistError::Commit(inner()),
        ]
        .map(|e| e.to_string());
        for text in &shown {
            assert!(!text.contains(secret_path), "path leaked: {text}");
            assert!(!text.contains("refusing"), "inner message leaked: {text}");
        }
        assert_eq!(
            shown,
            [
                "session store persist failed at step: create temp file (other error)",
                "session store persist failed at step: write temp file (other error)",
                "session store persist failed at step: commit (flush/rename) (other error)",
            ]
        );
    }

    /// A fresh handle whose map write fails is refused and taken back; once
    /// the map writes it is held, and a held handle whose next write fails
    /// diverges and is never evicted to its stale row.
    #[cfg(feature = "web")]
    #[tokio::test]
    async fn file_store_set_on_a_blocked_map_is_refused_then_diverges() {
        let dir = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_file_refused_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(std::fs::create_dir_all(&dir).is_ok(), "make scratch dir");
        let map = dir.join("sessions.json");
        let Some(p) = map.to_str() else {
            let _ = std::fs::remove_dir_all(&dir);
            return;
        };
        let bounded = tokio::time::timeout(Duration::from_secs(30), async {
            // The map path is a non-empty directory: the rename fails.
            assert!(std::fs::create_dir_all(map.join("x")).is_ok(), "block");
            let s: FileStore<i32, ()> = FileStore::new(p, Duration::from_secs(60), TEST_TAG);
            let h = handle_i32(1);
            let refused = s.set(SID, Arc::clone(&h)).await;
            assert!(
                matches!(&refused, Installed::Refused(WriteFault::File(e)) if matches!(**e, PersistError::Commit(_))),
                "{refused:?}"
            );
            assert!(s.get(SID).await.is_none(), "the refused handle was taken back");
            assert!(!s.holds(SID, &h));

            assert!(std::fs::remove_dir_all(&map).is_ok(), "unblock");
            assert!(matches!(s.set(SID, Arc::clone(&h)).await, Installed::Held));
            assert!(s.holds(SID, &h));

            assert!(std::fs::remove_file(&map).is_ok(), "drop the written map");
            assert!(std::fs::create_dir_all(map.join("x")).is_ok(), "re-block");
            assert!(matches!(
                s.set(SID, Arc::clone(&h)).await,
                Installed::Diverged(WriteFault::File(_))
            ));
            let _ = s.evict_unconnected(Bytes::new(u64::MAX)).await;
            assert!(
                s.holds(SID, &h),
                "a diverged session is never evicted to its stale row"
            );
        })
        .await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(bounded.is_ok(), "the file store answers within the bound");
    }

    /// The streak opens on the first failure, stays silent while writes keep
    /// failing, and closes on the first success; each line names only the
    /// backend and the fault's phrase.
    #[cfg(feature = "web")]
    #[tokio::test]
    async fn file_store_streak_logs_once_then_recovery() {
        let streak = FaultStreak::new();
        let fault = WriteFault::Encode(CheckpointRefusal::Model);
        assert_eq!(
            streak.transition("file", Some(&fault)).as_deref(),
            Some(
                "session store (file): write failed, sessions kept live and unevictable: \
                 session store write failed: encode (model not serializable)"
            )
        );
        assert!(streak.failing());
        assert_eq!(
            streak.transition("file", Some(&fault)),
            None,
            "one line per streak"
        );
        assert_eq!(
            streak.transition("file", None).as_deref(),
            Some("session store (file): writes recovered")
        );
        assert!(!streak.failing());
        assert_eq!(streak.transition("file", None), None);

        let dir = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_file_streak_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(std::fs::create_dir_all(&dir).is_ok(), "make scratch dir");
        let map = dir.join("sessions.json");
        let Some(p) = map.to_str() else {
            let _ = std::fs::remove_dir_all(&dir);
            return;
        };
        assert!(std::fs::create_dir_all(map.join("x")).is_ok(), "block");
        let s: FileStore<i32, ()> = FileStore::new(p, Duration::from_secs(60), TEST_TAG);
        assert!(matches!(
            s.set("s1", handle_i32(1)).await,
            Installed::Refused(_)
        ));
        assert!(s.streak.failing(), "failure recorded");
        assert!(std::fs::remove_dir_all(&map).is_ok(), "unblock");
        assert!(matches!(s.set("s2", handle_i32(2)).await, Installed::Held));
        assert!(!s.streak.failing(), "streak cleared on the next success");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// File-store restart survival: a store writes a checkpoint, a FRESH store
    /// over the same file (empty mem-cache) restores it verbatim — the
    /// dev-handoff persistence path, with NO sqlx.
    #[cfg(feature = "web")]
    #[tokio::test]
    async fn file_store_checkpoint_survives_restart() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_file_{}.json", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        {
            let s: FileStore<i32, ()> = FileStore::new(p, Duration::from_secs(60), TEST_TAG);
            assert!(matches!(s.set(SID, handle_i32(42)).await, Installed::Held));
            assert!(s.get(SID).await.is_some());
        }
        {
            // "rebuild": a new store, empty mem-cache → decodes the checkpoint.
            let s: FileStore<i32, ()> = FileStore::new(p, Duration::from_secs(60), TEST_TAG);
            assert_eq!(
                restored_i32(&s, SID).await,
                Some(42),
                "the checkpoint must survive a rebuild on disk"
            );
        }
        let _ = std::fs::remove_file(p);
    }

    /// H24 for the file store: a checkpoint written under a DIFFERENT Model
    /// schema tag (a Model-type change across a rebuild) is REJECTED before
    /// deserialize — a claimed lookup is a miss (fresh `init`), never a torn Model.
    #[cfg(feature = "web")]
    #[tokio::test]
    async fn file_store_rejects_a_row_written_by_a_different_schema_tag() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_fileh24_{}.json", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        {
            let s: FileStore<i32, ()> = FileStore::new(p, Duration::from_secs(60), [0xAA; 32]);
            assert!(matches!(s.set(SID, handle_i32(42)).await, Installed::Held));
        }
        {
            // "rebuild with a changed Model": same file, different tag.
            let s: FileStore<i32, ()> = FileStore::new(p, Duration::from_secs(60), [0xBB; 32]);
            assert!(
                restored_i32(&s, SID).await.is_none(),
                "a foreign-schema checkpoint must be rejected before deserialize"
            );
        }
        let _ = std::fs::remove_file(p);
    }

    /// A malformed / truncated on-disk map does NOT crash `new` — it starts
    /// empty (fail-soft), so a dev handoff over a corrupt map begins fresh
    /// rather than faulting.
    #[cfg(feature = "web")]
    #[tokio::test]
    async fn file_store_starts_empty_on_a_corrupt_map() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_filecorrupt_{}.json", std::process::id()));
        let p = path.to_str().unwrap();
        std::fs::write(p, b"{ this is not valid json").unwrap();
        let s: FileStore<i32, ()> = FileStore::new(p, Duration::from_secs(60), TEST_TAG);
        assert!(
            restored_i32(&s, SID).await.is_none(),
            "a corrupt map must yield an empty store, not a panic"
        );
        let _ = std::fs::remove_file(p);
    }

    #[tokio::test]
    async fn memory_store_ttl_eviction_and_touch() {
        let s: MemoryStore<(), ()> = MemoryStore::new(Duration::from_millis(40));
        assert!(matches!(s.set("idle", handle()).await, Installed::Held));
        assert!(matches!(s.set("active", handle()).await, Installed::Held));
        std::thread::sleep(Duration::from_millis(60));
        // touch "active" so it survives the sweep
        let _ = s.get("active").await;
        assert!(s.sweep().await.is_ok());
        assert!(
            s.get("active").await.is_some(),
            "touched session should survive"
        );
        assert!(
            s.get("idle").await.is_none(),
            "idle session should be evicted"
        );
    }

    /// Bounded decode: a framed blob whose BODY exceeds MAX_CHECKPOINT_BYTES is
    /// turned back cleanly (→ `None`) by `split_checkpoint` BEFORE serde walks
    /// it — a crafted at-rest length can never drive an allocation spike. The
    /// oversized body here is one byte past the ceiling.
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    #[test]
    fn decode_checkpoint_rejects_an_oversized_body_without_oom() {
        use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
        // framed = tag(32) ++ body, body one byte past the ceiling. The bytes
        // are never parsed: the length gate fires first.
        let mut framed = Vec::new();
        framed.extend_from_slice(&TEST_TAG);
        framed.resize(32 + MAX_CHECKPOINT_BYTES as usize + 1, b'0');
        let blob = B64.encode(&framed);
        let init = || (serde_json::Value::Null, ());
        let decoded = decode_or_reconstruct_checkpoint(&TEST_TAG, &blob, &init);
        assert!(
            decoded.is_none(),
            "an oversized body must decode to None, never OOM"
        );
    }

    /// A within-limit blob still round-trips — the bound rejects only absurd
    /// lengths, not legitimate payloads (guards against an over-tight cap).
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    #[test]
    fn decode_checkpoint_accepts_a_within_limit_body() {
        let payload: Vec<u8> = vec![1, 2, 3, 4, 5];
        let blob = encode_checkpoint(&TEST_TAG, None, &payload);
        assert!(blob.is_ok(), "encoding a small Vec<u8> cannot fail");
        if let Ok(blob) = blob {
            let init = || (Vec::<u8>::new(), ());
            let decoded = decode_or_reconstruct_checkpoint(&TEST_TAG, &blob, &init);
            assert!(
                matches!(decoded, Some(Decoded::Verbatim { model: p, section: CredSection::Absent }) if p == payload)
            );
        }
    }

    /// `base64(tag ++ rest)` for a hand-framed checkpoint.
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    fn framed_blob(rest: &[u8]) -> String {
        use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
        let mut framed = TEST_TAG.to_vec();
        framed.extend_from_slice(rest);
        B64.encode(framed)
    }

    /// A marker, a big-endian `len`, then `section` and `body`.
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    fn sectioned(len: usize, section: &[u8], body: &[u8]) -> Vec<u8> {
        let mut rest = vec![CRED_SECTION_MARKER];
        rest.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
        rest.extend_from_slice(section);
        rest.extend_from_slice(body);
        rest
    }

    /// Every credential-section framing failure is a miss, and the last legal
    /// section length still splits.
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    #[test]
    fn checkpoint_credential_section_refusals() {
        let body = b"41";
        let init = || (0_i32, ());
        let refused: [(&str, Vec<u8>); 5] = [
            ("a marker with no length", vec![CRED_SECTION_MARKER]),
            ("a truncated length", vec![CRED_SECTION_MARKER, 0x00]),
            (
                "a length past the section ceiling",
                sectioned(
                    MAX_CRED_SECTION_BYTES + 1,
                    &vec![b' '; MAX_CRED_SECTION_BYTES + 1],
                    body,
                ),
            ),
            ("a length past the blob", sectioned(3, b"[]", b"")),
            (
                "an unknown leading byte",
                [&[0x01_u8][..], &body[..]].concat(),
            ),
        ];
        for (case, rest) in refused {
            let blob = framed_blob(&rest);
            assert!(
                decode_or_reconstruct_checkpoint(&TEST_TAG, &blob, &init).is_none(),
                "{case} must be a miss"
            );
        }
        let longest = vec![b' '; MAX_CRED_SECTION_BYTES];
        let split = split_checkpoint(&framed_blob(&sectioned(
            MAX_CRED_SECTION_BYTES,
            &longest,
            body,
        )));
        assert!(
            matches!(&split, Some((_, CredSection::Present(section), rest))
                if *section == longest && rest == body),
            "the longest legal section splits off by its length"
        );
        assert_eq!(
            encode_checkpoint(
                &TEST_TAG,
                Some(&[b' '; MAX_CRED_SECTION_BYTES + 1]),
                &41_i32
            )
            .err(),
            Some(CheckpointRefusal::CredentialSectionOverCeiling),
            "the writer refuses a section past the ceiling"
        );
    }

    /// No JSON value's encoding starts with the section marker, so a
    /// sectionless body always splits as `Absent`, and a sectioned one round-trips.
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    #[test]
    fn json_body_never_starts_with_marker() {
        let kinds = [
            serde_json::json!({ "k": 1 }),
            serde_json::json!([1]),
            serde_json::json!("text"),
            serde_json::json!(7),
            serde_json::json!(-7),
            serde_json::json!(true),
            serde_json::json!(false),
            serde_json::Value::Null,
        ];
        for value in kinds {
            let encoded = serde_json::to_vec(&value).unwrap_or_default();
            assert!(
                encoded
                    .first()
                    .is_some_and(|first| *first != CRED_SECTION_MARKER),
                "{value} must not open with the marker"
            );
            let bare = encode_checkpoint(&TEST_TAG, None, &value)
                .ok()
                .and_then(|b| split_checkpoint(&b));
            assert!(
                matches!(&bare, Some((tag, CredSection::Absent, rest)) if *tag == TEST_TAG && *rest == encoded),
                "{value} without a section splits as `Absent`"
            );
            let with = encode_checkpoint(&TEST_TAG, Some(b"[]"), &value)
                .ok()
                .and_then(|b| split_checkpoint(&b));
            assert!(
                matches!(&with, Some((_, CredSection::Present(section), rest))
                    if section.as_slice() == b"[]" && *rest == encoded),
                "{value} with a section round-trips it"
            );
        }
    }

    /// A tag mismatch rebuilds the model and keeps the row's credential section.
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    #[test]
    fn additive_rebuild_keeps_the_credential_section() {
        let old = OldModel {
            count: 3,
            name: "kept".to_owned(),
        };
        let blob = encode_checkpoint(&OLD_TAG, Some(b"[]"), &old).ok();
        let init = || {
            (
                NewModel {
                    count: 0,
                    name: String::new(),
                    scroll: 5,
                },
                (),
            )
        };
        let decoded =
            blob.and_then(|blob| decode_or_reconstruct_checkpoint(&NEW_TAG, &blob, &init));
        assert!(
            matches!(&decoded, Some(Decoded::Rebuilt { model, section: CredSection::Present(section), .. })
                if model.count == 3 && section.as_slice() == b"[]"),
            "the rebuilt row carries its section"
        );
    }

    /// The file store hands a sectioned row's section to the caller and turns
    /// a mis-framed row into a miss.
    #[cfg(feature = "web")]
    #[tokio::test]
    async fn file_store_carries_the_credential_section() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_credsection_{}.json", std::process::id()));
        let Some(p) = path.to_str() else {
            return;
        };
        let _ = std::fs::remove_file(p);
        let seed = |blob: String| {
            let mut map: HashMap<String, (String, i64)> = HashMap::new();
            map.insert(SID.to_owned(), (blob, now_secs()));
            std::fs::write(p, serde_json::to_string(&map).unwrap_or_default()).is_ok()
        };
        let init = || (0_i32, IpeCmd::<()>::None);
        let blob = encode_checkpoint(&TEST_TAG, Some(b"[]"), &41_i32).unwrap_or_default();
        assert!(seed(blob), "seed the sectioned row");
        let s: FileStore<i32, ()> = FileStore::new(p, Duration::from_secs(60), TEST_TAG);
        assert!(matches!(
            reconstruct(&s, SID, &init).await,
            Rejoin::Restored { model: 41, section: CredSection::Present(section), .. }
                if section.as_slice() == b"[]"
        ));
        assert!(
            seed(framed_blob(&sectioned(3, b"[]", b""))),
            "seed the mis-framed row"
        );
        let s: FileStore<i32, ()> = FileStore::new(p, Duration::from_secs(60), TEST_TAG);
        assert!(matches!(reconstruct(&s, SID, &init).await, Rejoin::Miss));
        let _ = std::fs::remove_file(p);
    }

    /// Prod fail-closed: `IPE_WEB_STORE=sqlite` in a build WITHOUT the `db`
    /// feature is a hard config error at store selection — never a silent
    /// `FileStore`. Only meaningful when `db` is absent; a `db` build parses
    /// `sqlite` to the real backend, exercised by the other tests.
    #[cfg(all(feature = "web", not(feature = "db")))]
    #[tokio::test]
    async fn choose_store_fails_closed_on_prod_sqlite_without_db_feature() {
        let r = choose_store::<i32, ()>("sqlite", "", Duration::from_secs(60), TEST_TAG).await;
        let err = r.err();
        assert!(
            err.is_some(),
            "a sqlite request without `db` must fail closed, not serve a store"
        );
        assert_eq!(
            err,
            Some(StoreConfigError::FeatureAbsent {
                backend: "sqlite",
                feature: "db"
            })
        );
        let msg = err.map(|e| e.to_string()).unwrap_or_default();
        assert!(
            msg.contains("sqlite") && msg.contains("`db`"),
            "the error must name the missing feature: {msg:?}"
        );
    }

    /// The dev path is untouched: `file` always parses to a real `FileStore`,
    /// and `memory`/unknown still yield a memory store (never an error).
    #[cfg(feature = "web")]
    #[tokio::test]
    async fn choose_store_honours_file_and_memory_without_error() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_choose_{}.json", std::process::id()));
        let p = path.to_string_lossy().into_owned();
        let _ = std::fs::remove_file(&p);
        assert!(
            choose_store::<i32, ()>("file", &p, Duration::from_secs(60), TEST_TAG)
                .await
                .is_ok(),
            "dev `file` must select a store, never fail closed"
        );
        assert!(
            choose_store::<i32, ()>("memory", "", Duration::from_secs(60), TEST_TAG)
                .await
                .is_ok()
        );
        assert!(
            choose_store::<i32, ()>("totally-unknown", "", Duration::from_secs(60), TEST_TAG)
                .await
                .is_ok(),
            "an unrecognised value falls back to memory, not an error"
        );
        let _ = std::fs::remove_file(&p);
    }

    /// 0600 perms: the file store's on-disk map is owner-only on unix — a
    /// session blob may hold Model secrets and must never be world-readable.
    #[cfg(all(feature = "web", unix))]
    #[tokio::test]
    async fn file_store_map_is_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_perms_{}.json", std::process::id()));
        let p = path.to_string_lossy().into_owned();
        let _ = std::fs::remove_file(&p);
        let s: FileStore<i32, ()> = FileStore::new(&p, Duration::from_secs(60), TEST_TAG);
        assert!(matches!(s.set(SID, handle_i32(42)).await, Installed::Held));
        let meta = std::fs::metadata(&p);
        assert!(
            meta.is_ok(),
            "the map file must exist after a write: {:?}",
            meta.as_ref().err()
        );
        if let Ok(meta) = meta {
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the session map must be 0600 (owner-only)");
        }
        let _ = std::fs::remove_file(&p);
    }

    // ── Additive-superset reconstruction through the real restore path ──────
    //
    // These exercise `get_reconstructing`: a checkpoint is written under an OLD
    // Model type (its own schema tag), then a store opened over the SAME file /
    // db under a NEW Model type (a different tag) restores it — keeping old
    // state on a proven additive superset, cleanly re-initing otherwise.

    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    use serde::{Deserialize, Serialize};

    // The well-formed sid every claimed lookup below is keyed under.
    const SID: &str = "0123456789abcdef0123456789abcdef";

    // Claim `sid` on `s` and look it up, reconstructing across a Model change.
    async fn reconstruct<M: Send + 'static, C: Send + 'static>(
        s: &impl SessionStore<M, C>,
        sid: &str,
        init: &(dyn Fn() -> (M, IpeCmd<C>) + Sync),
    ) -> Rejoin<M, C> {
        let key = SessionKey::parse(sid).expect("a test sid is well formed");
        let claim = s.claim(key).await.expect("an idle sid is claimed at once");
        s.get_reconstructing(claim, init).await
    }

    // The OLD Model: two fields. A checkpoint persists JSON of this under
    // `OLD_TAG`.
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct OldModel {
        count: i64,
        name: String,
    }

    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    impl crate::retained::RetainedBytes for OldModel {
        fn retained_bytes(&self) -> Option<Bytes> {
            Bytes::inline::<Self>()?.plus_count(self.name.capacity())
        }
    }

    // The NEW Model: the old two fields PLUS an appended `scroll` — a purely
    // additive change, so a returning OLD checkpoint must keep count/name and
    // fill scroll from init.
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct NewModel {
        count: i64,
        name: String,
        scroll: i64,
    }

    // A retyped Model: `count` Int -> String (same name, new type) — a
    // non-additive change that must clean re-init.
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct RetypedModel {
        count: String,
        name: String,
    }

    // A field-removed Model: `name` dropped — not a superset, must re-init.
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct RemovedModel {
        count: i64,
    }

    // Two DISTINCT fixed tags standing in for the old and new binaries' schema
    // fingerprints — a Model change rotates the tag, which is exactly the
    // mismatch that triggers a reconstruction attempt.
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    const OLD_TAG: [u8; 32] = [0xA1; 32];
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    const NEW_TAG: [u8; 32] = [0xB2; 32];

    // The Cmd every reconstruction test's `init` returns: distinguishable from
    // `IpeCmd::None`, so a test proves a rebuilt model carries init's own Cmd.
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    fn init_marker() -> IpeCmd<()> {
        IpeCmd::Batch(vec![IpeCmd::None])
    }

    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    fn is_init_marker(cmd: &IpeCmd<()>) -> bool {
        matches!(cmd, IpeCmd::Batch(cmds) if matches!(cmds.as_slice(), [IpeCmd::None]))
    }

    // A SessionEntry for an arbitrary model, for the reconstruction tests.
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    fn handle_model<M: Clone + Send + crate::retained::RetainedBytes + 'static>(
        model: M,
    ) -> SessionHandle<M, ()> {
        let (tx, _rx) = channel::<()>(1);
        let tree: Html<()> = Html::HText(String::new());
        Arc::new(Mutex::new(SessionEntry {
            #[cfg(feature = "debugger")]
            history: crate::debugger::RecordBuffer::measured(
                model.clone(),
                crate::debugger::DEFAULT_HISTORY_CAP,
            ),
            #[cfg(feature = "debugger")]
            debug_cursor: None,
            liveness: crate::web::SessionLiveness::default(),
            charge: crate::web::budget::Charge::detached(),
            cmds: Arc::new(crate::web::budget::SessionCmds::new()),
            model,
            rendered: crate::web::Rendered::first(crate::web::SessionKeys::distinct(), tree),
            tabs: crate::web::TabSeqs::default(),
            seq: 0,
            sse_tx: None,
            msg_tx: tx,
            event_tx: tokio::sync::mpsc::channel(1).0,
            entered_path: None,
            enter_tx: tokio::sync::mpsc::channel(1).0,
        }))
    }

    /// File store (the `ipe dev watch` dev-handoff path): a checkpoint written by
    /// the OLD two-field Model is restored under the NEW three-field Model
    /// across a rebuild — old state (count/name) preserved, the new `scroll`
    /// filled from `init`. This is state PRESERVED across an additive Model
    /// change through the real store restore path, not a clean re-init.
    #[cfg(feature = "web")]
    #[tokio::test]
    async fn file_store_reconstructs_across_an_additive_model_change() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_addfile_{}.json", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        {
            // OLD binary: persist a two-field checkpoint under OLD_TAG.
            let s: FileStore<OldModel, ()> = FileStore::new(p, Duration::from_secs(60), OLD_TAG);
            assert!(matches!(
                s.set(
                    SID,
                    handle_model(OldModel {
                        count: 7,
                        name: "alice".to_string(),
                    }),
                )
                .await,
                Installed::Held
            ));
        }
        {
            // NEW binary: three-field Model, NEW_TAG; `get_reconstructing` splices it.
            let s: FileStore<NewModel, ()> = FileStore::new(p, Duration::from_secs(60), NEW_TAG);
            let init = || {
                (
                    NewModel {
                        count: 0,
                        name: String::new(),
                        scroll: 99,
                    },
                    init_marker(),
                )
            };
            let rejoin = reconstruct(&s, SID, &init).await;
            assert!(
                matches!(rejoin, Rejoin::Rebuilt { .. }),
                "expected a rebuilt model across the additive change"
            );
            let Rejoin::Rebuilt {
                model, init_cmd, ..
            } = rejoin
            else {
                return;
            };
            assert_eq!(
                model,
                NewModel {
                    count: 7,             // preserved from the checkpoint
                    name: "alice".into(), // preserved from the checkpoint
                    scroll: 99,           // filled from init (the new field)
                },
                "an additive change must keep old state and fill the new field from init"
            );
            assert!(
                is_init_marker(&init_cmd),
                "the rebuilt model carries the Cmd init returned beside it"
            );
        }
        let _ = std::fs::remove_file(p);
    }

    /// File store: a NON-additive change (a retyped field) through
    /// `get_reconstructing` falls back to a clean re-init (`Miss`), never a
    /// coerced Model.
    #[cfg(feature = "web")]
    #[tokio::test]
    async fn file_store_retyped_field_falls_back_to_reinit() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_addretype_{}.json", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        {
            let s: FileStore<OldModel, ()> = FileStore::new(p, Duration::from_secs(60), OLD_TAG);
            assert!(matches!(
                s.set(
                    SID,
                    handle_model(OldModel {
                        count: 7,
                        name: "alice".to_string(),
                    }),
                )
                .await,
                Installed::Held
            ));
        }
        {
            let s: FileStore<RetypedModel, ()> =
                FileStore::new(p, Duration::from_secs(60), NEW_TAG);
            let init = || {
                (
                    RetypedModel {
                        count: String::new(),
                        name: String::new(),
                    },
                    init_marker(),
                )
            };
            assert!(
                matches!(reconstruct(&s, SID, &init).await, Rejoin::Miss),
                "a retyped field must re-init cleanly, never coerce the old value"
            );
        }
        let _ = std::fs::remove_file(p);
    }

    /// File store: a REMOVED field (persisted set is not a subset of the live
    /// one) falls back to a clean re-init through `get_reconstructing`.
    #[cfg(feature = "web")]
    #[tokio::test]
    async fn file_store_removed_field_falls_back_to_reinit() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_addremove_{}.json", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        {
            let s: FileStore<OldModel, ()> = FileStore::new(p, Duration::from_secs(60), OLD_TAG);
            assert!(matches!(
                s.set(
                    SID,
                    handle_model(OldModel {
                        count: 7,
                        name: "alice".to_string(),
                    }),
                )
                .await,
                Installed::Held
            ));
        }
        {
            let s: FileStore<RemovedModel, ()> =
                FileStore::new(p, Duration::from_secs(60), NEW_TAG);
            let init = || (RemovedModel { count: 0 }, init_marker());
            assert!(
                matches!(reconstruct(&s, SID, &init).await, Rejoin::Miss),
                "a removed field is not an additive superset — must re-init"
            );
        }
        let _ = std::fs::remove_file(p);
    }

    /// File store: an UNCHANGED schema still restores verbatim through
    /// `get_reconstructing` — the fast (exact-tag) path keeps the state and
    /// never consults `init`.
    #[cfg(feature = "web")]
    #[tokio::test]
    async fn file_store_reconstructing_unchanged_schema_restores_verbatim() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_addsame_{}.json", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        {
            let s: FileStore<OldModel, ()> = FileStore::new(p, Duration::from_secs(60), OLD_TAG);
            assert!(matches!(
                s.set(
                    SID,
                    handle_model(OldModel {
                        count: 7,
                        name: "alice".to_string(),
                    }),
                )
                .await,
                Installed::Held
            ));
        }
        {
            let s: FileStore<OldModel, ()> = FileStore::new(p, Duration::from_secs(60), OLD_TAG);
            // `init` here would be WRONG if consulted (different values); the
            // exact-tag fast path must ignore it entirely.
            let init = || {
                (
                    OldModel {
                        count: -1,
                        name: "wrong".to_string(),
                    },
                    init_marker(),
                )
            };
            let rejoin = reconstruct(&s, SID, &init).await;
            assert!(
                matches!(rejoin, Rejoin::Restored { .. }),
                "expected the checkpoint restored verbatim under the same tag, never rebuilt"
            );
            let Rejoin::Restored { model: m, .. } = rejoin else {
                return;
            };
            assert_eq!(
                m,
                OldModel {
                    count: 7,
                    name: "alice".into(),
                },
                "an unchanged schema restores verbatim, ignoring init"
            );
        }
        let _ = std::fs::remove_file(p);
    }

    /// File store: a CORRUPT persisted body (non-base64) re-inits cleanly
    /// through `get_reconstructing` — `Miss`, never a panic.
    #[cfg(feature = "web")]
    #[tokio::test]
    async fn file_store_reconstructing_corrupt_body_falls_back_to_reinit() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_addcorrupt_{}.json", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        // Seed a raw corrupt row directly in the on-disk map, bypassing `set`.
        let mut seed: HashMap<String, (String, i64)> = HashMap::new();
        seed.insert(SID.to_string(), ("!! not base64 !!".to_string(), 0));
        std::fs::write(p, serde_json::to_string(&seed).unwrap()).unwrap();
        let s: FileStore<NewModel, ()> = FileStore::new(p, Duration::from_secs(60), NEW_TAG);
        let init = || {
            (
                NewModel {
                    count: 0,
                    name: String::new(),
                    scroll: 0,
                },
                init_marker(),
            )
        };
        assert!(
            matches!(reconstruct(&s, SID, &init).await, Rejoin::Miss),
            "a corrupt body must re-init cleanly, never panic"
        );
        let _ = std::fs::remove_file(p);
    }

    /// Sqlite store: the durable-backend mirror of the additive restore — an
    /// OLD-Model checkpoint is reconstructed under the NEW Model across a
    /// "redeploy", proving the wiring is not file-store-only.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn sqlite_store_reconstructs_across_an_additive_model_change() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_addsql_{}.db", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        {
            let s: SqliteStore<OldModel, ()> =
                SqliteStore::new(p, Duration::from_secs(60), OLD_TAG)
                    .await
                    .unwrap();
            assert!(matches!(
                s.set(
                    SID,
                    handle_model(OldModel {
                        count: 7,
                        name: "alice".to_string(),
                    }),
                )
                .await,
                Installed::Held
            ));
        }
        {
            let s: SqliteStore<NewModel, ()> =
                SqliteStore::new(p, Duration::from_secs(60), NEW_TAG)
                    .await
                    .unwrap();
            let init = || {
                (
                    NewModel {
                        count: 0,
                        name: String::new(),
                        scroll: 99,
                    },
                    init_marker(),
                )
            };
            let rejoin = reconstruct(&s, SID, &init).await;
            assert!(
                matches!(rejoin, Rejoin::Rebuilt { .. }),
                "expected a rebuilt model across the additive change"
            );
            let Rejoin::Rebuilt {
                model, init_cmd, ..
            } = rejoin
            else {
                return;
            };
            assert_eq!(
                model,
                NewModel {
                    count: 7,
                    name: "alice".into(),
                    scroll: 99,
                }
            );
            assert!(
                is_init_marker(&init_cmd),
                "the rebuilt model carries the Cmd init returned beside it"
            );
            // A non-additive (retyped) change on the SAME durable row re-inits.
            let s2: SqliteStore<RetypedModel, ()> =
                SqliteStore::new(p, Duration::from_secs(60), NEW_TAG)
                    .await
                    .unwrap();
            let init2 = || {
                (
                    RetypedModel {
                        count: String::new(),
                        name: String::new(),
                    },
                    init_marker(),
                )
            };
            assert!(
                matches!(reconstruct(&s2, SID, &init2).await, Rejoin::Miss),
                "a retyped field on a durable row must re-init, never coerce"
            );
        }
        let _ = std::fs::remove_file(p);
    }

    /// The memory store's default `get_reconstructing` never reconstructs (it
    /// has no persisted body): it is exactly `get`, so a miss stays a miss and
    /// `init` is never consulted.
    #[tokio::test]
    async fn memory_store_get_reconstructing_is_plain_get() {
        let s: MemoryStore<(), ()> = MemoryStore::new(Duration::from_secs(60));
        let init = || ((), IpeCmd::None);
        assert!(
            matches!(reconstruct(&s, SID, &init).await, Rejoin::Miss),
            "a memory-store miss has nothing to reconstruct from"
        );
        assert!(matches!(s.set(SID, handle()).await, Installed::Held));
        assert!(
            matches!(reconstruct(&s, SID, &init).await, Rejoin::Live(_)),
            "a live memory handle is returned unchanged, never rebuilt"
        );
    }

    // ── Per-session claims: one cold rejoin per sid at a time ───────────────

    // The `i`-th well-formed sid.
    fn key(i: usize) -> SessionKey {
        SessionKey::parse(&format!("{i:032x}")).expect("a 32-hex sid parses")
    }

    // Slots a claim table holds (held or awaited sids).
    fn slots(admission: &SidAdmission) -> usize {
        admission
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    // Whether a claim future is still waiting after one poll.
    fn waits<F: std::future::Future + Unpin>(claim: &mut F) -> bool {
        futures_util::FutureExt::now_or_never(claim).is_none()
    }

    /// A second claim on a held sid waits, then joins the session the holder published.
    #[tokio::test(start_paused = true)]
    async fn claim_second_waits_then_joins_live() {
        let s: MemoryStore<(), ()> = MemoryStore::new(Duration::from_secs(60));
        let first = s
            .claim(key(1))
            .await
            .expect("an idle sid is claimed at once");
        let mut second = s.claim(key(1));
        assert!(waits(&mut second), "a held sid's second claim waits");
        assert!(matches!(
            s.set(first.key().as_str(), handle()).await,
            Installed::Held
        ));
        drop(first);
        let second = second.await.expect("a released claim passes to its waiter");
        let init = || ((), IpeCmd::<()>::None);
        assert!(
            matches!(s.get_reconstructing(second, &init).await, Rejoin::Live(_)),
            "the waiter joins the published session live"
        );
        assert_eq!(
            slots(s.admission()),
            0,
            "every released claim leaves the table"
        );
    }

    /// A claim waiting past `CLAIM_WAIT` is refused `InFlight`; one tick short it still waits.
    #[tokio::test(start_paused = true)]
    async fn claim_wait_expires_in_flight() {
        let s: MemoryStore<(), ()> = MemoryStore::new(Duration::from_secs(60));
        let _held = s
            .claim(key(1))
            .await
            .expect("an idle sid is claimed at once");
        let mut waiter = s.claim(key(1));
        assert!(waits(&mut waiter), "a held sid's claim waits");
        let tick = Duration::from_millis(1);
        tokio::time::advance(CLAIM_WAIT.saturating_sub(tick)).await;
        assert!(
            waits(&mut waiter),
            "a claim still inside the wait keeps waiting"
        );
        tokio::time::advance(tick.saturating_mul(2)).await;
        assert_eq!(waiter.await.err(), Some(ClaimRefusal::InFlight));
        assert_eq!(
            slots(s.admission()),
            1,
            "the expired waiter leaves only the holder"
        );
    }

    /// The waiter one past `MAX_CLAIM_WAITERS` is refused `Crowded` at once.
    #[tokio::test(start_paused = true)]
    async fn claim_crowded_past_waiters() {
        let s: MemoryStore<(), ()> = MemoryStore::new(Duration::from_secs(60));
        let _held = s
            .claim(key(1))
            .await
            .expect("an idle sid is claimed at once");
        let mut waiters: Vec<_> = (0..MAX_CLAIM_WAITERS.get())
            .map(|_| s.claim(key(1)))
            .collect();
        for waiter in &mut waiters {
            assert!(waits(waiter), "a waiter up to the limit queues");
        }
        assert_eq!(
            s.claim(key(1)).await.err(),
            Some(ClaimRefusal::Crowded),
            "the waiter past the limit is refused"
        );
    }

    /// A new sid past `MAX_CLAIMS_IN_FLIGHT` is refused `Saturated`; a held sid still queues.
    #[tokio::test(start_paused = true)]
    async fn claim_saturated_past_table_cap() {
        let s: MemoryStore<(), ()> = MemoryStore::new(Duration::from_secs(60));
        let mut held = Vec::with_capacity(MAX_CLAIMS_IN_FLIGHT);
        for i in 0..MAX_CLAIMS_IN_FLIGHT {
            held.push(
                s.claim(key(i))
                    .await
                    .expect("a sid under the cap is claimed"),
            );
        }
        assert_eq!(
            s.claim(key(MAX_CLAIMS_IN_FLIGHT)).await.err(),
            Some(ClaimRefusal::Saturated),
            "a new sid past the cap is refused"
        );
        let mut joining = s.claim(key(0));
        assert!(
            waits(&mut joining),
            "a held sid still queues its waiter at the cap"
        );
        drop(held);
        assert!(joining.await.is_ok(), "the waiter takes the released claim");
        assert!(
            s.claim(key(MAX_CLAIMS_IN_FLIGHT)).await.is_ok(),
            "a freed table admits a new sid again"
        );
    }

    /// A claim future dropped while it waits gives its waiter place back.
    #[tokio::test(start_paused = true)]
    async fn dropped_claim_future_releases_slot() {
        let s: MemoryStore<(), ()> = MemoryStore::new(Duration::from_secs(60));
        let held = s
            .claim(key(1))
            .await
            .expect("an idle sid is claimed at once");
        for _ in 0..MAX_CLAIM_WAITERS.get().saturating_mul(2) {
            let mut cancelled = s.claim(key(1));
            assert!(waits(&mut cancelled), "a waiter under the limit queues");
        }
        let mut waiters: Vec<_> = (0..MAX_CLAIM_WAITERS.get())
            .map(|_| s.claim(key(1)))
            .collect();
        for waiter in &mut waiters {
            assert!(
                waits(waiter),
                "cancelled waiters never count against the limit"
            );
        }
        drop(waiters);
        drop(held);
        assert_eq!(slots(s.admission()), 0, "no cancelled waiter pins the slot");
    }

    /// A holder's drop, on return or unwind, frees the sid and removes its slot.
    #[tokio::test(start_paused = true)]
    async fn holder_drop_releases_and_removes_slot() {
        let s: MemoryStore<(), ()> = MemoryStore::new(Duration::from_secs(60));
        let held = s
            .claim(key(1))
            .await
            .expect("an idle sid is claimed at once");
        assert_eq!(slots(s.admission()), 1);
        drop(held);
        assert_eq!(slots(s.admission()), 0, "a dropped holder removes its slot");
        let held = s
            .claim(key(1))
            .await
            .expect("a freed sid is claimed at once");
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _held = held;
            let nothing: Option<()> = std::hint::black_box(None);
            nothing.expect("unwinds while holding the claim");
        }));
        assert!(unwound.is_err(), "the holder unwound");
        assert_eq!(
            slots(s.admission()),
            0,
            "an unwound holder removes its slot"
        );
        assert!(
            s.claim(key(1)).await.is_ok(),
            "an unwound holder's sid is claimed at once"
        );
    }

    /// Only exactly 32 lowercase hex digits parse as a session id.
    #[test]
    fn malformed_sid_never_parses() {
        assert!(SessionKey::parse(&"a".repeat(SESSION_ID_LEN)).is_some());
        let multibyte = format!("{}é", "a".repeat(SESSION_ID_LEN.saturating_sub(2)));
        assert_eq!(multibyte.len(), SESSION_ID_LEN);
        for bad in [
            String::new(),
            "a".repeat(SESSION_ID_LEN.saturating_sub(1)),
            "a".repeat(SESSION_ID_LEN.saturating_add(1)),
            "A".repeat(SESSION_ID_LEN),
            "g".repeat(SESSION_ID_LEN),
            "-".repeat(SESSION_ID_LEN),
            multibyte,
        ] {
            assert!(SessionKey::parse(&bad).is_none(), "{bad:?} must not parse");
        }
    }

    /// Neither a key's nor a claim's `Debug` prints the session id.
    #[tokio::test(start_paused = true)]
    async fn session_key_debug_redacts() {
        let k = key(0xabc);
        let sid = k.as_str().to_owned();
        assert!(!format!("{k:?}").contains(&sid));
        let s: MemoryStore<(), ()> = MemoryStore::new(Duration::from_secs(60));
        let claim = s.claim(k).await.expect("an idle sid is claimed at once");
        assert!(!format!("{claim:?}").contains(&sid));
    }

    /// A claim another store issued looks up nothing, even for a live sid.
    #[tokio::test(start_paused = true)]
    async fn foreign_claim_is_miss() {
        let owner: MemoryStore<(), ()> = MemoryStore::new(Duration::from_secs(60));
        let other: MemoryStore<(), ()> = MemoryStore::new(Duration::from_secs(60));
        assert!(matches!(owner.set(SID, handle()).await, Installed::Held));
        let foreign = other
            .claim(key_of(SID))
            .await
            .expect("an idle sid is claimed");
        let init = || ((), IpeCmd::<()>::None);
        assert!(matches!(
            owner.get_reconstructing(foreign, &init).await,
            Rejoin::Miss
        ));
    }

    // `sid` as a key.
    fn key_of(sid: &str) -> SessionKey {
        SessionKey::parse(sid).expect("a test sid is well formed")
    }

    /// File store: a foreign claim is a miss, and a set session rejoins live.
    #[cfg(feature = "web")]
    #[tokio::test]
    async fn set_then_rejoin_is_live_file() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_claimfile_{}.json", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        let s: FileStore<i32, ()> = FileStore::new(p, Duration::from_secs(60), TEST_TAG);
        let other: MemoryStore<i32, ()> = MemoryStore::new(Duration::from_secs(60));
        assert!(matches!(s.set(SID, handle_i32(7)).await, Installed::Held));
        let init = || (0, IpeCmd::<()>::None);
        let foreign = other
            .claim(key_of(SID))
            .await
            .expect("an idle sid is claimed");
        assert!(matches!(
            s.get_reconstructing(foreign, &init).await,
            Rejoin::Miss
        ));
        assert!(matches!(reconstruct(&s, SID, &init).await, Rejoin::Live(_)));
        let _ = std::fs::remove_file(p);
    }

    /// Sqlite store: a foreign claim is a miss, and a set session rejoins live.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn set_then_rejoin_is_live_sqlite() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_claimsql_{}.db", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(p);
        let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), TEST_TAG)
            .await
            .unwrap();
        assert_rejoins_live(&s).await;
        let _ = std::fs::remove_file(p);
    }

    /// Postgres store: a foreign claim is a miss, and a set session rejoins live.
    /// Gated on `IPE_TEST_PG_URL`.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn set_then_rejoin_is_live_postgres() {
        let Ok(url) = crate::system::read_env_var("IPE_TEST_PG_URL") else {
            return;
        };
        let s: PostgresStore<i32, ()> = PostgresStore::new(&url, Duration::from_secs(60), TEST_TAG)
            .await
            .unwrap();
        assert_rejoins_live(&s).await;
        assert!(matches!(s.delete(SID).await, Deleted::Removed));
    }

    /// Redis store: a foreign claim is a miss, and a set session rejoins live.
    /// Gated on `IPE_TEST_REDIS_URL`.
    #[cfg(feature = "redis_store")]
    #[tokio::test]
    async fn set_then_rejoin_is_live_redis() {
        let Ok(url) = crate::system::read_env_var("IPE_TEST_REDIS_URL") else {
            return;
        };
        let s: RedisStore<i32, ()> = RedisStore::new(&url, Duration::from_secs(60), TEST_TAG)
            .await
            .unwrap();
        assert_rejoins_live(&s).await;
        assert!(matches!(s.delete(SID).await, Deleted::Removed));
    }

    // A foreign claim on `s` is a miss; once `SID` is set, a claimed lookup is live.
    #[cfg(any(feature = "db", feature = "redis_store"))]
    async fn assert_rejoins_live(s: &impl SessionStore<i32, ()>) {
        let other: MemoryStore<i32, ()> = MemoryStore::new(Duration::from_secs(60));
        let init = || (0, IpeCmd::<()>::None);
        assert!(matches!(s.set(SID, handle_i32(7)).await, Installed::Held));
        let foreign = other
            .claim(key_of(SID))
            .await
            .expect("an idle sid is claimed");
        assert!(matches!(
            s.get_reconstructing(foreign, &init).await,
            Rejoin::Miss
        ));
        assert!(matches!(reconstruct(s, SID, &init).await, Rejoin::Live(_)));
    }

    // Remove a SQLite store's file and its WAL siblings.
    #[cfg(feature = "db")]
    fn remove_sqlite(p: &str) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{p}{suffix}"));
        }
    }

    // The rows `s` persists under `sid`.
    #[cfg(feature = "db")]
    async fn sqlite_rows<Model, Msg>(s: &SqliteStore<Model, Msg>, sid: &str) -> i64 {
        sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM ipe_sessions WHERE sid = ?")
            .bind(sid)
            .fetch_one(&s.pool)
            .await
            .unwrap()
            .0
    }

    // Run `sql` against `s`'s own pool.
    #[cfg(feature = "db")]
    async fn sqlite_exec<Model, Msg>(s: &SqliteStore<Model, Msg>, sql: &str) {
        sqlx::query(sql).execute(&s.pool).await.unwrap();
    }

    // A trigger that refuses every delete, so the row stays readable.
    #[cfg(feature = "db")]
    const HOLD_ROWS: &str = "CREATE TRIGGER ipe_sessions_held BEFORE DELETE ON ipe_sessions \
                             BEGIN SELECT RAISE(ABORT, 'held'); END";

    /// A fresh handle whose checkpoint the closed pool refuses is taken back.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn sqlite_set_on_a_closed_pool_is_refused_for_a_fresh_handle() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_refused_{}.db", std::process::id()));
        let p = path.to_str().unwrap();
        remove_sqlite(p);
        let bounded = tokio::time::timeout(Duration::from_secs(30), async {
            let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), TEST_TAG)
                .await
                .unwrap();
            s.pool.close().await;
            let h = handle_i32(1);
            let refused = s.set(SID, Arc::clone(&h)).await;
            assert!(
                matches!(refused, Installed::Refused(WriteFault::Driver(_))),
                "{refused:?}"
            );
            assert!(
                s.get(SID).await.is_none(),
                "the refused handle was taken back"
            );
            assert!(!s.holds(SID, &h));
        })
        .await;
        remove_sqlite(p);
        assert!(bounded.is_ok(), "the store answers within the bound");
    }

    /// A held handle whose checkpoint the closed pool refuses diverges.
    ///
    /// It stays live and is never evicted to its stale row.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn sqlite_set_on_a_closed_pool_diverges_a_held_handle() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_diverged_{}.db", std::process::id()));
        let p = path.to_str().unwrap();
        remove_sqlite(p);
        let bounded = tokio::time::timeout(Duration::from_secs(30), async {
            let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), TEST_TAG)
                .await
                .unwrap();
            let h = handle_i32(1);
            assert!(matches!(s.set(SID, Arc::clone(&h)).await, Installed::Held));
            s.pool.close().await;
            let diverged = s.set(SID, Arc::clone(&h)).await;
            assert!(
                matches!(diverged, Installed::Diverged(WriteFault::Driver(_))),
                "{diverged:?}"
            );
            assert!(s.get(SID).await.is_some(), "the live session is kept");
            let _ = s.evict_unconnected(Bytes::new(u64::MAX)).await;
            assert!(
                s.holds(SID, &h),
                "a diverged session is never evicted to its stale row"
            );
        })
        .await;
        remove_sqlite(p);
        assert!(bounded.is_ok(), "the store answers within the bound");
    }

    /// A diverged entry becomes evictable again once a checkpoint lands.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn sqlite_diverged_entry_is_evictable_again_after_a_landed_checkpoint() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_healed_{}.db", std::process::id()));
        let p = path.to_str().unwrap();
        remove_sqlite(p);
        let bounded = tokio::time::timeout(Duration::from_secs(30), async {
            let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), TEST_TAG)
                .await
                .unwrap();
            let h = handle_i32(1);
            assert!(matches!(s.set(SID, Arc::clone(&h)).await, Installed::Held));
            sqlite_exec(&s, "DROP TABLE ipe_sessions").await;
            assert!(matches!(
                s.set(SID, Arc::clone(&h)).await,
                Installed::Diverged(_)
            ));
            let _ = s.evict_unconnected(Bytes::new(u64::MAX)).await;
            assert!(s.holds(SID, &h), "diverged: not evicted");
            sqlite_exec(
                &s,
                "CREATE TABLE ipe_sessions (sid TEXT PRIMARY KEY, blob TEXT NOT NULL, \
                 last_seen INTEGER NOT NULL, schema_tag TEXT NOT NULL)",
            )
            .await;
            assert!(matches!(s.set(SID, Arc::clone(&h)).await, Installed::Held));
            let _ = s.evict_unconnected(Bytes::new(u64::MAX)).await;
            assert!(
                !s.holds(SID, &h),
                "a landed checkpoint makes the session evictable again"
            );
            assert_eq!(restored_i32(&s, SID).await, Some(1));
        })
        .await;
        remove_sqlite(p);
        assert!(bounded.is_ok(), "the store answers within the bound");
    }

    /// A delete whose row stays is pending, and the row is never restored.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn sqlite_delete_that_does_not_land_is_pending_and_tombstones_the_sid() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_pending_{}.db", std::process::id()));
        let p = path.to_str().unwrap();
        remove_sqlite(p);
        let bounded = tokio::time::timeout(Duration::from_secs(30), async {
            let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), TEST_TAG)
                .await
                .unwrap();
            assert!(matches!(s.set(SID, handle_i32(7)).await, Installed::Held));
            sqlite_exec(&s, HOLD_ROWS).await;
            let deleted = s.delete(SID).await;
            assert!(
                matches!(deleted, Deleted::Pending(WriteFault::Driver(_))),
                "{deleted:?}"
            );
            assert!(s.get(SID).await.is_none(), "the live entry is gone");
            assert_eq!(sqlite_rows(&s, SID).await, 1, "the row stayed");
            let init = || (0, IpeCmd::<()>::None);
            assert!(
                matches!(reconstruct(&s, SID, &init).await, Rejoin::Miss),
                "a tombstoned sid is never restored"
            );
        })
        .await;
        remove_sqlite(p);
        assert!(bounded.is_ok(), "the store answers within the bound");
    }

    /// The sweep retries a tombstoned delete; once it lands the row is gone.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn tombstone_retry_removes_the_row_on_the_next_sweep() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_retried_{}.db", std::process::id()));
        let p = path.to_str().unwrap();
        remove_sqlite(p);
        let bounded = tokio::time::timeout(Duration::from_secs(30), async {
            let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), TEST_TAG)
                .await
                .unwrap();
            assert!(matches!(s.set(SID, handle_i32(7)).await, Installed::Held));
            sqlite_exec(&s, HOLD_ROWS).await;
            assert!(matches!(s.delete(SID).await, Deleted::Pending(_)));
            assert!(s.sweep().await.is_err(), "the retry is refused too");
            assert_eq!(s.tombstones.snapshot(), vec![SID.to_owned()]);
            sqlite_exec(&s, "DROP TRIGGER ipe_sessions_held").await;
            assert!(s.sweep().await.is_ok());
            assert!(
                s.tombstones.snapshot().is_empty(),
                "the landed retry drops it"
            );
            assert_eq!(sqlite_rows(&s, SID).await, 0);
            let other: SqliteStore<i32, ()> =
                SqliteStore::new(p, Duration::from_secs(60), TEST_TAG)
                    .await
                    .unwrap();
            assert_eq!(restored_i32(&other, SID).await, None);
        })
        .await;
        remove_sqlite(p);
        assert!(bounded.is_ok(), "the store answers within the bound");
    }

    /// A failed delete past the tombstone ceiling seals every cold read.
    ///
    /// The seal holds until each row the set could not track is past the TTL.
    #[test]
    fn tombstones_over_the_ceiling_seal_cold_rejoin() {
        let t = Tombstones::new(Duration::from_secs(60));
        let now = 1_000_000;
        for n in 0..MAX_TOMBSTONES.get() {
            t.record_at(&format!("held-{n}"), now);
        }
        assert_eq!(t.cold_read_at("held-0", now), ColdRead::RetryDelete);
        assert_eq!(
            t.cold_read_at("fresh", now),
            ColdRead::Row,
            "at the cap nothing is sealed yet"
        );
        t.record_at("one-past", now);
        assert_eq!(
            t.snapshot().len(),
            MAX_TOMBSTONES.get(),
            "the set never grows past the cap"
        );
        assert_eq!(t.cold_read_at("fresh", now), ColdRead::Miss);
        assert_eq!(t.cold_read_at("one-past", now), ColdRead::Miss);
        for n in 0..MAX_TOMBSTONES.get() {
            t.landed(&format!("held-{n}"));
        }
        assert_eq!(
            t.cold_read_at("fresh", now + 60),
            ColdRead::Miss,
            "draining does not reopen: the untracked row may still be live"
        );
        assert_eq!(
            t.cold_read_at("fresh", now + 61),
            ColdRead::Row,
            "the untracked row is past its TTL"
        );
    }

    /// A row idle past the TTL is a miss before any sweep runs.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn sqlite_cold_row_past_ttl_is_a_miss_without_a_sweep() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_ttlread_{}.db", std::process::id()));
        let p = path.to_str().unwrap();
        remove_sqlite(p);
        let bounded = tokio::time::timeout(Duration::from_secs(30), async {
            let s: SqliteStore<i32, ()> = SqliteStore::new(p, Duration::from_secs(60), TEST_TAG)
                .await
                .unwrap();
            let now = now_secs();
            for (sid, seen) in [(COLD_SID, now - 61), (OLD_SID, now - 50)] {
                sqlx::query(
                    "INSERT INTO ipe_sessions (sid, blob, last_seen, schema_tag) \
                     VALUES (?, ?, ?, ?)",
                )
                .bind(sid)
                .bind(encode_checkpoint(&TEST_TAG, None, &41_i32).unwrap())
                .bind(seen)
                .bind(hex::encode(TEST_TAG))
                .execute(&s.pool)
                .await
                .unwrap();
            }
            let init = || (0, IpeCmd::<()>::None);
            assert!(matches!(
                reconstruct(&s, COLD_SID, &init).await,
                Rejoin::Miss
            ));
            assert_eq!(restored_i32(&s, OLD_SID).await, Some(41));
        })
        .await;
        remove_sqlite(p);
        assert!(bounded.is_ok(), "the store answers within the bound");
    }

    /// A map entry idle past the TTL is a miss before any sweep runs.
    #[cfg(feature = "web")]
    #[tokio::test]
    async fn file_store_cold_row_past_ttl_is_a_miss_without_a_sweep() {
        const STALE: &str = "abcdefabcdefabcdefabcdefabcdef01";
        const RECENT: &str = "fedcbafedcbafedcbafedcbafedcba02";
        let dir = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_file_ttlread_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(std::fs::create_dir_all(&dir).is_ok(), "make scratch dir");
        let map = dir.join("sessions.json");
        let blob = encode_checkpoint(&TEST_TAG, None, &41_i32).unwrap();
        let now = now_secs();
        let rows: HashMap<String, (String, i64)> = HashMap::from([
            (STALE.to_owned(), (blob.clone(), now - 61)),
            (RECENT.to_owned(), (blob, now - 50)),
        ]);
        assert!(std::fs::write(&map, serde_json::to_string(&rows).unwrap()).is_ok());
        let p = map.to_str().unwrap();
        let s: FileStore<i32, ()> = FileStore::new(p, Duration::from_secs(60), TEST_TAG);
        let init = || (0, IpeCmd::<()>::None);
        assert!(matches!(reconstruct(&s, STALE, &init).await, Rejoin::Miss));
        assert_eq!(restored_i32(&s, RECENT).await, Some(41));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A model serde refuses, so every checkpoint of it fails to frame.
    #[cfg(feature = "db")]
    #[derive(Clone, Debug, Deserialize)]
    struct Unserializable;

    #[cfg(feature = "db")]
    impl Serialize for Unserializable {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("refused"))
        }
    }

    #[cfg(feature = "db")]
    impl crate::retained::RetainedBytes for Unserializable {
        fn retained_bytes(&self) -> Option<Bytes> {
            Bytes::inline::<Self>()
        }
    }

    /// A checkpoint that cannot be framed is a typed refusal, never a held write.
    #[cfg(feature = "db")]
    #[tokio::test]
    async fn encode_refusal_is_a_typed_fault() {
        let oversized = (41_i32, Some(vec![b' '; MAX_CRED_SECTION_BYTES + 1]));
        assert!(matches!(
            frame_checkpoint(&TEST_TAG, &oversized),
            Err(WriteFault::Encode(
                CheckpointRefusal::CredentialSectionOverCeiling
            ))
        ));

        let dir = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_encode_refused_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(std::fs::create_dir_all(&dir).is_ok(), "make scratch dir");
        let bounded = tokio::time::timeout(Duration::from_secs(30), async {
            let map = dir.join("sessions.json");
            let file: FileStore<Unserializable, ()> =
                FileStore::new(map.to_str().unwrap(), Duration::from_secs(60), TEST_TAG);
            let refused = file.set(SID, handle_model(Unserializable)).await;
            assert!(
                matches!(
                    refused,
                    Installed::Refused(WriteFault::Encode(CheckpointRefusal::Model))
                ),
                "{refused:?}"
            );
            assert!(file.get(SID).await.is_none());

            let db = dir.join("sessions.db");
            let sqlite: SqliteStore<Unserializable, ()> =
                SqliteStore::new(db.to_str().unwrap(), Duration::from_secs(60), TEST_TAG)
                    .await
                    .unwrap();
            let refused = sqlite.set(SID, handle_model(Unserializable)).await;
            assert!(
                matches!(
                    refused,
                    Installed::Refused(WriteFault::Encode(CheckpointRefusal::Model))
                ),
                "{refused:?}"
            );
            assert!(sqlite.get(SID).await.is_none());
            sqlite.pool.close().await;
        })
        .await;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(bounded.is_ok(), "the stores answer within the bound");
    }

    /// A write fault displays its step and a fixed phrase.
    ///
    /// Never a path, a URL or a driver message.
    #[cfg(all(feature = "db", feature = "redis_store"))]
    #[test]
    fn write_fault_display_is_credential_free() {
        let shown = [
            WriteFault::Driver(crate::db::DriverFailure::of(
                crate::db::DbEngine::Sqlite,
                &sqlx::Error::PoolClosed,
            )),
            WriteFault::File(Arc::new(PersistError::Commit(std::io::Error::other(
                "refusing scratch location /srv/x",
            )))),
            WriteFault::Redis(redis::ErrorKind::IoError),
            WriteFault::Encode(CheckpointRefusal::Model),
            WriteFault::Encode(CheckpointRefusal::CredentialSectionOverCeiling),
        ]
        .map(|fault| ToString::to_string(&fault));
        for text in &shown {
            assert!(!text.contains("/srv/x"), "path leaked: {text}");
            assert!(!text.contains("refusing"), "inner message leaked: {text}");
        }
        assert_eq!(
            shown,
            [
                "session store write failed: statement (database unreachable)",
                "session store write failed: map write (session store persist failed at step: \
                 commit (flush/rename) (other error))",
                "session store write failed: command (IoError)",
                "session store write failed: encode (model not serializable)",
                "session store write failed: encode (credential section over ceiling)",
            ]
        );
    }

    // The first word of the RESP command at the head of `buf`, and the bytes it spans.
    #[cfg(feature = "redis_store")]
    fn resp_command(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
        let header = |at: usize| -> Option<(usize, usize)> {
            let rest = buf.get(at..)?;
            let end = rest.windows(2).position(|w| w == b"\r\n")?;
            let n = std::str::from_utf8(rest.get(1..end)?).ok()?.parse().ok()?;
            Some((n, at + end + 2))
        };
        let (args, mut at) = header(0)?;
        let mut name = None;
        for _ in 0..args {
            let (len, start) = header(at)?;
            let word = buf.get(start..start + len)?;
            name.get_or_insert_with(|| word.to_ascii_uppercase());
            at = start + len + 2;
            if buf.len() < at {
                return None;
            }
        }
        name.map(|name| (name, at))
    }

    /// A Redis server that drops the connection refuses a fresh checkpoint.
    ///
    /// The refused handle is taken back.
    #[cfg(feature = "redis_store")]
    #[tokio::test]
    async fn redis_set_against_a_server_that_closes_is_refused() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Answers the connection setup and `PING`, then closes on the next command.
        let server = tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut pending = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                while let Some((name, used)) = resp_command(&pending) {
                    pending.drain(..used);
                    let reply: &[u8] = match name.as_slice() {
                        b"CLIENT" => b"+OK\r\n",
                        b"PING" => b"+PONG\r\n",
                        _ => return,
                    };
                    if socket.write_all(reply).await.is_err() {
                        return;
                    }
                }
                match socket.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => pending.extend_from_slice(chunk.get(..n).unwrap_or_default()),
                }
            }
        });
        let bounded = tokio::time::timeout(Duration::from_secs(5), async {
            let s: RedisStore<i32, ()> =
                RedisStore::new(&addr.to_string(), Duration::from_secs(60), TEST_TAG)
                    .await
                    .unwrap();
            let h = handle_i32(1);
            let refused = s.set(SID, Arc::clone(&h)).await;
            assert!(
                matches!(refused, Installed::Refused(WriteFault::Redis(_))),
                "{refused:?}"
            );
            assert!(
                s.get(SID).await.is_none(),
                "the refused handle was taken back"
            );
            assert!(!s.holds(SID, &h));
        })
        .await;
        server.abort();
        assert!(bounded.is_ok(), "the store answers within the bound");
    }
}
