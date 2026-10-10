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
use crate::tea::IpeCmd;
use async_trait::async_trait;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::num::NonZeroUsize;
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
/// [`split_checkpoint`] is the one reader of this framing. `None` when
/// serialization fails or the section is longer than
/// [`MAX_CRED_SECTION_BYTES`]; the caller then skips the checkpoint write.
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
fn encode_checkpoint<Model: serde::Serialize>(
    schema_tag: &[u8; 32],
    section: Option<&[u8]>,
    model: &Model,
) -> Option<String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let body = serde_json::to_vec(model).ok()?;
    let framing = section.map_or(0, |bytes| 1 + CRED_SECTION_LEN_BYTES + bytes.len());
    let mut framed = Vec::with_capacity(32 + framing + body.len());
    framed.extend_from_slice(schema_tag);
    if let Some(bytes) = section {
        if bytes.len() > MAX_CRED_SECTION_BYTES {
            return None;
        }
        let len = u16::try_from(bytes.len()).ok()?;
        framed.push(CRED_SECTION_MARKER);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(bytes);
    }
    framed.extend_from_slice(&body);
    Some(B64.encode(framed))
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

/// The model and credential section a checkpoint of `handle` writes.
///
/// Read under one lock, so the section belongs to the model beside it.
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
fn checkpoint_parts<Model: Clone, Msg>(
    handle: &SessionHandle<Model, Msg>,
) -> (Model, Option<Vec<u8>>) {
    let entry = handle.lock().unwrap_or_else(PoisonError::into_inner);
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
        make_init: &(dyn Fn() -> (Model, IpeCmd<Msg>) + Sync),
    ) -> Rejoin<Model, Msg> {
        let _ = make_init;
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
    async fn set(&self, sid: &str, handle: SessionHandle<Model, Msg>);
    /// Drop a session.
    async fn delete(&self, sid: &str);
    /// Evict idle-expired sessions (called periodically by the eviction task).
    async fn sweep(&self) {}

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
}

// ─── Memory store — default; in-process, lost on restart ────────────────────

/// In-process store with idle-TTL eviction. `get` touches the entry's last-seen
/// so active sessions don't expire.
/// In-process session table: sid → (live handle, last-seen instant).
type SessionMap<Model, Msg> = HashMap<String, (SessionHandle<Model, Msg>, Instant)>;

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
        let mut w = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        w.get_mut(sid).map(|(h, seen)| {
            *seen = Instant::now(); // touch — keep active sessions alive
            h.clone()
        })
    }
    fn admission(&self) -> &SidAdmission {
        &self.admission
    }
    async fn set(&self, sid: &str, handle: SessionHandle<Model, Msg>) {
        self.sessions
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(sid.to_string(), (handle, Instant::now()));
    }
    async fn delete(&self, sid: &str) {
        self.sessions
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(sid);
    }
    async fn sweep(&self) {
        let now = Instant::now();
        let ttl = self.ttl;
        self.sessions
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, (_, seen)| now.duration_since(*seen) <= ttl);
    }
    async fn web_sessions(&self) -> Vec<SessionHandle<Model, Msg>> {
        self.sessions
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|(h, _)| h.clone())
            .collect()
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
    /// Whether the last map write failed, so a failure streak is logged once.
    persist_failing: std::sync::atomic::AtomicBool,
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
            persist_failing: std::sync::atomic::AtomicBool::new(false),
            admission: SidAdmission::new(),
        }
    }

    /// Atomically rewrite the on-disk map from `disk`. Best-effort: a write
    /// failure (e.g. a transient FS error) leaves the in-memory map as the
    /// source of truth for this process and is never fatal — the next mutation
    /// retries the whole map. Writes to a sibling temp file then renames, so a
    /// crash mid-write never leaves a truncated map a later `new` would fail to
    /// parse (and thus silently drop every session).
    ///
    /// The temp file is an [`AtomicSibling`](crate::scratch_core::AtomicSibling):
    /// an unguessable hidden name, created exclusively, never through a symlink,
    /// and verified `0600` (owner-only) BEFORE any bytes are written, so the
    /// checkpoint map — which may hold Model secrets — is never world-readable,
    /// not even momentarily. The rename carries the mode to the final path, and
    /// a refused or failed write removes the temp file.
    ///
    /// The first failure after a success is logged, naming the failed step and
    /// its I/O error kind but never the map path; repeats stay silent until a
    /// write succeeds again, so a persistently failing disk yields one line,
    /// not one per mutation.
    fn persist(&self, disk: &HashMap<String, (String, i64)>) {
        let failed = self.write_map(disk).err();
        let was_failing = self
            .persist_failing
            .swap(failed.is_some(), std::sync::atomic::Ordering::Relaxed);
        if let (Some(err), false) = (failed, was_failing) {
            crate::system::emit_runtime_log(
                "live",
                &format!("session store: map not written, sessions kept in memory: {err}"),
            );
        }
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
        let mut w = self.mem_cache.write().unwrap_or_else(|e| e.into_inner());
        w.get_mut(sid).map(|(h, seen)| {
            *seen = Instant::now();
            h.clone()
        })
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
        // Cold: on an exact tag the checkpoint decodes verbatim; on a
        // schema-changed tag it is spliced onto `init` iff additive-superset.
        let blob = {
            let disk = self.disk.lock().unwrap_or_else(|e| e.into_inner());
            disk.get(sid).map(|(b, _)| b.clone())
        };
        let decoded = blob
            .and_then(|blob| decode_or_reconstruct_checkpoint(&self.schema_tag, &blob, make_init));
        decoded.map_or(Rejoin::Miss, |d| d.into_rejoin(claim))
    }
    async fn set(&self, sid: &str, handle: SessionHandle<Model, Msg>) {
        let (model, section) = checkpoint_parts(&handle);
        self.mem_cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(sid.to_string(), (handle, Instant::now()));
        if let Some(blob) = encode_checkpoint(&self.schema_tag, section.as_deref(), &model) {
            let mut disk = self.disk.lock().unwrap_or_else(|e| e.into_inner());
            disk.insert(sid.to_string(), (blob, file_now_secs()));
            self.persist(&disk);
        }
    }
    async fn delete(&self, sid: &str) {
        self.mem_cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(sid);
        let mut disk = self.disk.lock().unwrap_or_else(|e| e.into_inner());
        if disk.remove(sid).is_some() {
            self.persist(&disk);
        }
    }
    async fn sweep(&self) {
        let cutoff =
            file_now_secs().saturating_sub(i64::try_from(self.ttl.as_secs()).unwrap_or(i64::MAX));
        {
            let mut disk = self.disk.lock().unwrap_or_else(|e| e.into_inner());
            let before = disk.len();
            disk.retain(|_, (_, seen)| *seen >= cutoff);
            if disk.len() != before {
                self.persist(&disk);
            }
        }
        // Bound the in-RAM handle cache by idle-TTL too (session-DoS guard).
        let now = Instant::now();
        let ttl = self.ttl;
        self.mem_cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, (_, seen)| now.duration_since(*seen) <= ttl);
    }
    async fn web_sessions(&self) -> Vec<SessionHandle<Model, Msg>> {
        self.mem_cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|(h, _)| h.clone())
            .collect()
    }
}

/// Current unix time in whole seconds, saturating (never panics on a clock
/// before the epoch). The `web`-feature file store's own time helper — the
/// sqlx stores' `now_secs` is `#[cfg(feature = "db")]` and unavailable here.
#[cfg(feature = "web")]
fn file_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

// Used only by the sqlx-backed Sqlite/Postgres session stores (all
// `#[cfg(feature = "db")]`); the memory + redis stores don't call it, so a
// memory-only live build (no db) would orphan it.
#[cfg(feature = "db")]
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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
fn store_refused_error(backend: &str, refused: &StoreOpenError) -> StoreConfigError {
    StoreConfigError(format!(
        "IPE_WEB_STORE={backend} refused at connect ({refused}); fix the connection URL \
         or the server, or set IPE_WEB_STORE=file|memory"
    ))
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
        // column then error and are swallowed by the callers' existing
        // best-effort handling — the store degrades fail-soft (sessions
        // restart fresh), never crashes and never mis-decodes.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS ipe_sessions (\
             sid TEXT PRIMARY KEY, blob TEXT NOT NULL, last_seen INTEGER NOT NULL, \
             schema_tag TEXT NOT NULL)",
        )
        .execute(&pool)
        .await
        .map_err(|e| {
            StoreOpenError::Schema(crate::db::DriverFailure::of(
                crate::db::DbEngine::Sqlite,
                &e,
            ))
        })?;
        Ok(SqliteStore {
            pool,
            mem_cache: RwLock::new(HashMap::new()),
            ttl,
            schema_tag,
            admission: SidAdmission::new(),
        })
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
        // Only the same-process live handle (it owns the running driver).
        let cached = {
            let mut w = self.mem_cache.write().unwrap_or_else(|e| e.into_inner());
            w.get_mut(sid).map(|(h, seen)| {
                *seen = Instant::now(); // touch — keep active sessions in cache
                h.clone()
            })
        };
        if cached.is_some() {
            let _ = sqlx::query("UPDATE ipe_sessions SET last_seen = ? WHERE sid = ?")
                .bind(now_secs())
                .bind(sid)
                .execute(&self.pool)
                .await;
        }
        cached
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
        // Cold (post-restart / other replica): the blob is self-contained
        // (`base64(tag ++ json)`), and its tag picks a verbatim decode or an
        // additive splice. The legacy `schema_tag` column is still written
        // (NOT NULL) but never read.
        let row: Option<(String,)> = sqlx::query_as("SELECT blob FROM ipe_sessions WHERE sid = ?")
            .bind(sid)
            .fetch_optional(&self.pool)
            .await
            .ok()
            .flatten();
        let Some(decoded) = row.and_then(|(blob,)| {
            decode_or_reconstruct_checkpoint(&self.schema_tag, &blob, make_init)
        }) else {
            return Rejoin::Miss;
        };
        let _ = sqlx::query("UPDATE ipe_sessions SET last_seen = ? WHERE sid = ?")
            .bind(now_secs())
            .bind(sid)
            .execute(&self.pool)
            .await;
        decoded.into_rejoin(claim)
    }
    async fn set(&self, sid: &str, handle: SessionHandle<Model, Msg>) {
        let (model, section) = checkpoint_parts(&handle);
        self.mem_cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(sid.to_string(), (handle, Instant::now()));
        if let Some(blob) = encode_checkpoint(&self.schema_tag, section.as_deref(), &model) {
            let _ = sqlx::query(
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
        }
    }
    async fn delete(&self, sid: &str) {
        self.mem_cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(sid);
        let _ = sqlx::query("DELETE FROM ipe_sessions WHERE sid = ?")
            .bind(sid)
            .execute(&self.pool)
            .await;
    }
    async fn sweep(&self) {
        // Total cutoff: an absurd `IPE_WEB_TTL` (u64 near 2^63) would make a bare
        // `now_secs() - (ttl as i64)` debug-panic / wrap-to-negative (caller-controlled
        // arithmetic). `try_from` → i64::MAX on overflow, then saturating_sub clamps,
        // so an oversized TTL degrades to "never expire" instead of faulting. For all
        // realistic TTLs this is byte-identical to the old expression.
        let cutoff =
            now_secs().saturating_sub(i64::try_from(self.ttl.as_secs()).unwrap_or(i64::MAX));
        let _ = sqlx::query("DELETE FROM ipe_sessions WHERE last_seen < ?")
            .bind(cutoff)
            .execute(&self.pool)
            .await;
        // Bound the in-RAM handle cache by idle-TTL too. Without this, every
        // distinct sid ever seen (e.g. a flood of cookie-less requests) leaves a
        // live handle in mem_cache forever → unbounded growth → OOM (session-DoS).
        // An evicted-but-still-valid session simply re-hydrates from the
        // checkpoint blob on its next claimed request.
        let now = Instant::now();
        let ttl = self.ttl;
        self.mem_cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, (_, seen)| now.duration_since(*seen) <= ttl);
    }
    async fn web_sessions(&self) -> Vec<SessionHandle<Model, Msg>> {
        self.mem_cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|(h, _)| h.clone())
            .collect()
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
        // same fail-soft degradation as SqliteStore::new.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS ipe_sessions (\
             sid TEXT PRIMARY KEY, blob TEXT NOT NULL, last_seen BIGINT NOT NULL, \
             schema_tag TEXT NOT NULL)",
        )
        .execute(&pool)
        .await
        .map_err(|e| {
            StoreOpenError::Schema(crate::db::DriverFailure::of(
                crate::db::DbEngine::Postgres,
                &e,
            ))
        })?;
        Ok(PostgresStore {
            pool,
            mem_cache: RwLock::new(HashMap::new()),
            ttl,
            schema_tag,
            admission: SidAdmission::new(),
        })
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
        let cached = {
            let mut w = self.mem_cache.write().unwrap_or_else(|e| e.into_inner());
            w.get_mut(sid).map(|(h, seen)| {
                *seen = Instant::now(); // touch — keep active sessions in cache
                h.clone()
            })
        };
        if cached.is_some() {
            let _ = sqlx::query("UPDATE ipe_sessions SET last_seen = $1 WHERE sid = $2")
                .bind(now_secs())
                .bind(sid)
                .execute(&self.pool)
                .await;
        }
        cached
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
        // Cold: the sqlite store's self-contained framed blob. The legacy
        // `schema_tag` column is still written (NOT NULL) but never read.
        let row: Option<(String,)> = sqlx::query_as("SELECT blob FROM ipe_sessions WHERE sid = $1")
            .bind(sid)
            .fetch_optional(&self.pool)
            .await
            .ok()
            .flatten();
        let Some(decoded) = row.and_then(|(blob,)| {
            decode_or_reconstruct_checkpoint(&self.schema_tag, &blob, make_init)
        }) else {
            return Rejoin::Miss;
        };
        let _ = sqlx::query("UPDATE ipe_sessions SET last_seen = $1 WHERE sid = $2")
            .bind(now_secs())
            .bind(sid)
            .execute(&self.pool)
            .await;
        decoded.into_rejoin(claim)
    }
    async fn set(&self, sid: &str, handle: SessionHandle<Model, Msg>) {
        let (model, section) = checkpoint_parts(&handle);
        self.mem_cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(sid.to_string(), (handle, Instant::now()));
        if let Some(blob) = encode_checkpoint(&self.schema_tag, section.as_deref(), &model) {
            let _ = sqlx::query(
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
        }
    }
    async fn delete(&self, sid: &str) {
        self.mem_cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(sid);
        let _ = sqlx::query("DELETE FROM ipe_sessions WHERE sid = $1")
            .bind(sid)
            .execute(&self.pool)
            .await;
    }
    async fn sweep(&self) {
        // Total cutoff: an absurd `IPE_WEB_TTL` (u64 near 2^63) would make a bare
        // `now_secs() - (ttl as i64)` debug-panic / wrap-to-negative (caller-controlled
        // arithmetic). `try_from` → i64::MAX on overflow, then saturating_sub clamps,
        // so an oversized TTL degrades to "never expire" instead of faulting. For all
        // realistic TTLs this is byte-identical to the old expression.
        let cutoff =
            now_secs().saturating_sub(i64::try_from(self.ttl.as_secs()).unwrap_or(i64::MAX));
        let _ = sqlx::query("DELETE FROM ipe_sessions WHERE last_seen < $1")
            .bind(cutoff)
            .execute(&self.pool)
            .await;
        // Bound the in-RAM handle cache by idle-TTL too (see SqliteStore::sweep)
        // — otherwise a cookie-less request flood grows mem_cache without bound.
        let now = Instant::now();
        let ttl = self.ttl;
        self.mem_cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, (_, seen)| now.duration_since(*seen) <= ttl);
    }
    async fn web_sessions(&self) -> Vec<SessionHandle<Model, Msg>> {
        self.mem_cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|(h, _)| h.clone())
            .collect()
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
            admission: SidAdmission::new(),
        })
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
        use redis::AsyncCommands;
        let cached = {
            let mut w = self.mem_cache.write().unwrap_or_else(|e| e.into_inner());
            w.get_mut(sid).map(|(h, seen)| {
                *seen = Instant::now(); // touch — keep active sessions in cache
                h.clone()
            })
        };
        if cached.is_some() {
            // Touch native TTL so an active session doesn't expire mid-conversation.
            let mut conn = self.conn.clone();
            let _: Result<(), _> = conn.expire(redis_key(sid), self.ttl_secs as i64).await;
        }
        cached
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
        use redis::AsyncCommands;
        let sid = claim.key().as_str();
        if let Some(h) = self.get(sid).await {
            return Rejoin::Live(h);
        }
        // Cold: the session HASH's `blob` field is the self-contained framed
        // checkpoint; a pre-HASH string key errs WRONGTYPE and takes the miss
        // path. The legacy companion `tag` field is neither written nor read.
        let mut conn = self.conn.clone();
        let blob: Option<String> = redis::cmd("HGET")
            .arg(redis_key(sid))
            .arg("blob")
            .query_async(&mut conn)
            .await
            .ok()
            .flatten();
        let Some(decoded) = blob
            .and_then(|blob| decode_or_reconstruct_checkpoint(&self.schema_tag, &blob, make_init))
        else {
            return Rejoin::Miss;
        };
        let _: Result<(), _> = conn.expire(redis_key(sid), self.ttl_secs as i64).await;
        decoded.into_rejoin(claim)
    }
    async fn set(&self, sid: &str, handle: SessionHandle<Model, Msg>) {
        let (model, section) = checkpoint_parts(&handle);
        self.mem_cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(sid.to_string(), (handle, Instant::now()));
        if let Some(blob) = encode_checkpoint(&self.schema_tag, section.as_deref(), &model) {
            let mut conn = self.conn.clone();
            // HASH per session, one key + one TTL; the tag lives INSIDE the
            // framed blob, so nothing can drift apart.
            let key = redis_key(sid);
            let _: Result<(), _> = redis::pipe()
                .cmd("HSET")
                .arg(&key)
                .arg("blob")
                .arg(blob)
                .ignore()
                .cmd("EXPIRE")
                .arg(&key)
                .arg(self.ttl_secs)
                .ignore()
                .query_async(&mut conn)
                .await;
        }
    }
    async fn delete(&self, sid: &str) {
        use redis::AsyncCommands;
        self.mem_cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(sid);
        let mut conn = self.conn.clone();
        let _: Result<(), _> = conn.del(redis_key(sid)).await;
    }
    async fn sweep(&self) {
        // Redis evicts the persisted blob natively, but the in-RAM handle cache
        // still needs idle-TTL eviction — otherwise a cookie-less request flood
        // grows mem_cache without bound → OOM (session-DoS). An evicted-but-valid
        // session re-hydrates from Redis on its next claimed request.
        let now = Instant::now();
        let ttl = Duration::from_secs(self.ttl_secs);
        self.mem_cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, (_, seen)| now.duration_since(*seen) <= ttl);
    }
    async fn web_sessions(&self) -> Vec<SessionHandle<Model, Msg>> {
        self.mem_cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|(h, _)| h.clone())
            .collect()
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

/// A requested backend this build cannot serve — a fail-closed startup error,
/// carrying the operator-facing message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreConfigError(pub String);

impl std::fmt::Display for StoreConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
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
                    Err(StoreConfigError(
                        "IPE_WEB_STORE=sqlite requested but this build has no `db` \
                         feature; build with `db` or set IPE_WEB_STORE=file|memory"
                            .to_string(),
                    ))
                }
            }
            "postgres" => {
                if cfg!(feature = "db") {
                    Ok(StoreBackend::Postgres)
                } else {
                    Err(StoreConfigError(
                        "IPE_WEB_STORE=postgres requested but this build has no `db` \
                         feature; build with `db` or set IPE_WEB_STORE=file|memory"
                            .to_string(),
                    ))
                }
            }
            "redis" => {
                if cfg!(feature = "redis_store") {
                    Ok(StoreBackend::Redis)
                } else {
                    Err(StoreConfigError(
                        "IPE_WEB_STORE=redis requested but this build has no \
                         `redis_store` feature; build with `redis_store` or set \
                         IPE_WEB_STORE=file|memory"
                            .to_string(),
                    ))
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
    let _ = (path, schema_tag);
    // Memory store logs with a timestamp + human-readable TTL duration;
    // persistent backends log bare lines above (no duration needed).
    emit_memory_store_log(ttl);
    Ok(Arc::new(MemoryStore::new(ttl)))
}

/// The `session store: memory (ttl=…)` message with a human-readable TTL.
fn memory_store_message(ttl: Duration) -> String {
    format!("session store: memory (ttl={})", go_duration_string(ttl))
}

/// Emit the `YYYY/MM/DD HH:MM:SS [ipe.live] session store: memory (ttl=…)`
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
            Some(&go_log_timestamp()),
            "live",
            &memory_store_message(Duration::from_secs(3600)),
        );
        let line = line.trim_start();
        assert!(
            line.ends_with("[ipe.live] session store: memory (ttl=1h0m0s)"),
            "got {line:?}"
        );
        // Timestamp prefix `YYYY/MM/DD HH:MM:SS ` precedes it.
        let prefix = line
            .strip_suffix("[ipe.live] session store: memory (ttl=1h0m0s)")
            .unwrap_or("");
        assert_eq!(
            prefix.len(),
            20,
            "timestamp prefix `YYYY/MM/DD HH:MM:SS ` is 20 chars: {prefix:?}"
        );
        assert_eq!(prefix.matches('/').count(), 2);
        assert_eq!(prefix.matches(':').count(), 2);
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
            rendered: crate::web::Rendered::first(crate::web::new_incarnation(), tree),
            tabs: crate::web::TabSeqs::default(),
            seq: 0,
            sse_tx: None,
            msg_tx: tx,
            entered_path: None,
            enter_tx: tokio::sync::mpsc::channel(1).0,
            #[cfg(feature = "debugger")]
            history: crate::debugger::RecordBuffer::new((), crate::debugger::DEFAULT_HISTORY_CAP),
            #[cfg(feature = "debugger")]
            debug_cursor: None,
            liveness: crate::web::SessionLiveness::default(),
        }))
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

    #[tokio::test]
    async fn memory_store_get_set_delete() {
        let s: MemoryStore<(), ()> = MemoryStore::new(Duration::from_secs(60));
        assert!(s.get("a").await.is_none());
        s.set("a", handle()).await;
        assert!(s.get("a").await.is_some());
        s.delete("a").await;
        assert!(s.get("a").await.is_none());
    }

    // A SessionEntry<i32, ()> with a given model, for the checkpoint tests.
    #[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
    fn handle_i32(model: i32) -> SessionHandle<i32, ()> {
        let (tx, _rx) = channel::<()>(1);
        let tree: Html<()> = Html::HText(String::new());
        Arc::new(Mutex::new(SessionEntry {
            model,
            rendered: crate::web::Rendered::first(crate::web::new_incarnation(), tree),
            tabs: crate::web::TabSeqs::default(),
            seq: 0,
            sse_tx: None,
            msg_tx: tx,
            entered_path: None,
            enter_tx: tokio::sync::mpsc::channel(1).0,
            #[cfg(feature = "debugger")]
            history: crate::debugger::RecordBuffer::new(
                model,
                crate::debugger::DEFAULT_HISTORY_CAP,
            ),
            #[cfg(feature = "debugger")]
            debug_cursor: None,
            liveness: crate::web::SessionLiveness::default(),
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
            if let Some(StoreConfigError(msg)) = refused {
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
            s.set(SID, handle_i32(42)).await;
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
            s.set(SID, handle_i32(42)).await;
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
            s.set(SID, handle_i32(42)).await;
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
            s.delete(&sid).await;
            s.set(&sid, handle_i32(7)).await;
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
            s.delete(&sid).await;
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
            s.delete(&sid).await;
            s.set(&sid, handle_i32(9)).await;
        }
        {
            let s: RedisStore<i32, ()> = RedisStore::new(&url, Duration::from_secs(60), [0xBB; 32])
                .await
                .unwrap();
            assert!(
                restored_i32(&s, &sid).await.is_none(),
                "a foreign-schema checkpoint must be rejected before deserialize"
            );
            s.delete(&sid).await;
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
            s.delete(&sid).await;
            s.set(&sid, handle_i32(7)).await;
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
            s.delete(&sid).await;
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
            s.delete(&sid).await;
            s.set(&sid, handle_i32(9)).await;
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
            s.delete(&sid).await;
        }
    }

    /// `web_sessions()` lists exactly the locally-live handles: empty on a
    /// fresh store, grows with `set()`, shrinks with `delete()`.
    #[tokio::test]
    async fn memory_store_web_sessions_lists_only_locally_cached_handles() {
        let s: MemoryStore<(), ()> = MemoryStore::new(Duration::from_secs(60));
        assert!(s.web_sessions().await.is_empty());
        s.set("a", handle()).await;
        s.set("b", handle()).await;
        assert_eq!(s.web_sessions().await.len(), 2);
        s.delete("a").await;
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
        s.set("web_sid", handle_i32(42)).await;

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
            s.set(SID, handle_i32(model)).await;
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
            s.delete(&sid).await;
            s.delete(&old_sid).await;
            s.set(&sid, handle_i32(7)).await;
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
            s.delete(&sid).await;
            s.delete(&old_sid).await;
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
            s.delete(&sid).await;
            s.delete(&old_sid).await;
            s.set(&sid, handle_i32(9)).await;
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
            s.delete(&sid).await;
            s.delete(&old_sid).await;
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
        s.delete(&cold_sid).await;
        s.delete(&web_sid).await;
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
        s.set(&web_sid, handle_i32(42)).await;
        assert_eq!(s.web_sessions().await.len(), 1);
        s.delete(&cold_sid).await;
        s.delete(&web_sid).await;
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
        s.delete(&cold_sid).await;
        s.delete(&web_sid).await;
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
        s.set(&web_sid, handle_i32(42)).await;
        assert_eq!(s.web_sessions().await.len(), 1);
        s.delete(&cold_sid).await;
        s.delete(&web_sid).await;
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
        s.set("s1", handle_i32(7)).await;
        assert_eq!(
            std::fs::read_to_string(&victim).ok().as_deref(),
            Some("keep")
        );
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
        s.set("s1", handle_i32(7)).await;
        s.delete("s1").await;
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
        s.set("s1", handle_i32(7)).await;
        s.set("s2", handle_i32(8)).await;
        assert!(
            s.persist_failing.load(std::sync::atomic::Ordering::Relaxed),
            "the failure is recorded"
        );
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

    /// A persist failure sets the streak flag once; a later successful
    /// persist on the same store clears it.
    #[cfg(feature = "web")]
    #[tokio::test]
    async fn file_store_persist_failing_clears_on_success() {
        let dir = crate::scratch_core::test_temp_root()
            .join(format!("ipetest_file_clearflag_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(std::fs::create_dir_all(&dir).is_ok(), "make scratch dir");
        let map = dir.join("sessions.json");
        let Some(p) = map.to_str() else {
            let _ = std::fs::remove_dir_all(&dir);
            return;
        };

        // The map path starts life as a non-empty directory: the first
        // mutation's rename fails and the streak flag is set.
        assert!(std::fs::create_dir_all(map.join("x")).is_ok(), "block");
        let s: FileStore<i32, ()> = FileStore::new(p, Duration::from_secs(60), TEST_TAG);
        s.set("s1", handle_i32(1)).await;
        assert!(
            s.persist_failing.load(std::sync::atomic::Ordering::Relaxed),
            "failure recorded"
        );

        // Unblock: the rename can now land, so the next mutation succeeds.
        assert!(std::fs::remove_dir_all(&map).is_ok(), "unblock");
        s.set("s2", handle_i32(2)).await;
        assert!(
            !s.persist_failing.load(std::sync::atomic::Ordering::Relaxed),
            "streak cleared on the next success"
        );

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
            s.set(SID, handle_i32(42)).await;
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
            s.set(SID, handle_i32(42)).await;
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
        s.set("idle", handle()).await;
        s.set("active", handle()).await;
        std::thread::sleep(Duration::from_millis(60));
        // touch "active" so it survives the sweep
        let _ = s.get("active").await;
        s.sweep().await;
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
        assert!(blob.is_some(), "encoding a small Vec<u8> cannot fail");
        if let Some(blob) = blob {
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
        assert!(
            encode_checkpoint(
                &TEST_TAG,
                Some(&[b' '; MAX_CRED_SECTION_BYTES + 1]),
                &41_i32
            )
            .is_none(),
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
            let bare =
                encode_checkpoint(&TEST_TAG, None, &value).and_then(|b| split_checkpoint(&b));
            assert!(
                matches!(&bare, Some((tag, CredSection::Absent, rest)) if *tag == TEST_TAG && *rest == encoded),
                "{value} without a section splits as `Absent`"
            );
            let with = encode_checkpoint(&TEST_TAG, Some(b"[]"), &value)
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
        let blob = encode_checkpoint(&OLD_TAG, Some(b"[]"), &old);
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
            map.insert(SID.to_owned(), (blob, file_now_secs()));
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
        if let Some(StoreConfigError(msg)) = err {
            assert!(
                msg.contains("sqlite") && msg.contains("db"),
                "the error must name the missing feature: {msg:?}"
            );
        }
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
        s.set(SID, handle_i32(42)).await;
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
    fn handle_model<M: Clone + Send + 'static>(model: M) -> SessionHandle<M, ()> {
        let (tx, _rx) = channel::<()>(1);
        let tree: Html<()> = Html::HText(String::new());
        Arc::new(Mutex::new(SessionEntry {
            #[cfg(feature = "debugger")]
            history: crate::debugger::RecordBuffer::new(
                model.clone(),
                crate::debugger::DEFAULT_HISTORY_CAP,
            ),
            #[cfg(feature = "debugger")]
            debug_cursor: None,
            liveness: crate::web::SessionLiveness::default(),
            model,
            rendered: crate::web::Rendered::first(crate::web::new_incarnation(), tree),
            tabs: crate::web::TabSeqs::default(),
            seq: 0,
            sse_tx: None,
            msg_tx: tx,
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
            s.set(
                SID,
                handle_model(OldModel {
                    count: 7,
                    name: "alice".to_string(),
                }),
            )
            .await;
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
            s.set(
                SID,
                handle_model(OldModel {
                    count: 7,
                    name: "alice".to_string(),
                }),
            )
            .await;
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
            s.set(
                SID,
                handle_model(OldModel {
                    count: 7,
                    name: "alice".to_string(),
                }),
            )
            .await;
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
            s.set(
                SID,
                handle_model(OldModel {
                    count: 7,
                    name: "alice".to_string(),
                }),
            )
            .await;
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
            s.set(
                SID,
                handle_model(OldModel {
                    count: 7,
                    name: "alice".to_string(),
                }),
            )
            .await;
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
        s.set(SID, handle()).await;
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
        s.set(first.key().as_str(), handle()).await;
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
        owner.set(SID, handle()).await;
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
        s.set(SID, handle_i32(7)).await;
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
        s.delete(SID).await;
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
        s.delete(SID).await;
    }

    // A foreign claim on `s` is a miss; once `SID` is set, a claimed lookup is live.
    #[cfg(any(feature = "db", feature = "redis_store"))]
    async fn assert_rejoins_live(s: &impl SessionStore<i32, ()>) {
        let other: MemoryStore<i32, ()> = MemoryStore::new(Duration::from_secs(60));
        let init = || (0, IpeCmd::<()>::None);
        s.set(SID, handle_i32(7)).await;
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
}
