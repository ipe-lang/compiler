//! Ipe.Cache — a bounded LRU cache with optional TTL + running stats.
//!
//! Handle-based: `cache_new_raw` returns an `i64` handle wrapped in the opaque
//! `IpeCacheHandle` (the Ipê `Cache k v` lowers to this non-generic enum — the
//! handle carries no type args; `k`/`v` live only on the kernel calls). The
//! other kernels take the unwrapped `i64`.
//!
//! Each handle holds a `K`-typed `Vec<CacheEntry<K>>` whose entries carry a
//! value-erased `Box<dyn Any + Send>`, downcast to `V` only on `get` (where the
//! Ipê `getRaw : … -> Task Error (Maybe v)` return makes `V` available). Keys
//! are matched by `PartialEq` (already in the codegen's standard generic bounds)
//! via a linear scan — no `Eq`/`Hash` needed, so the generic stdlib wrappers
//! type-check without any bound-threading. Entry lookup within a handle is O(n)
//! in that handle's entry count, fine for the small caches Ipê uses; a future
//! codegen `Eq+Hash` bound would allow an O(1) `HashMap`.
//!
//! The registry itself keys handles in a `HashMap<i64, Slot>` (O(1) lookup) and
//! is bounded by construction: `MAX_LIVE_CACHES` caps the number of live caches
//! and `cache_destroy` reclaims a handle's `Slot`. Two independent bounds — a
//! fail-closed ceiling at construction and caller-driven reclamation — so a
//! long-lived server calling `cache_new_raw` per request cannot leak `Slot`s
//! without limit.
//!
//! Both the `Vec<CacheEntry<K>>` downcast (by `K`) and the value downcast (by
//! `V`) are **correct by construction** — every op on a handle uses the same
//! `(K, V)`, enforced by Ipê's opaque `Cache k v` — so neither can fail; a
//! mismatch / missing handle degrades to a miss / no-op, never a panic. The same
//! sanctioned-seam discipline as the pub/sub broker; strictly safer than  reflect
//! cache (the cast cannot fail). See the README `dyn Any` register.

use super::*;
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// The opaque Ipê `Cache k v` — a non-generic handle wrapper. The variant name
/// `Cache` matches the Ipê constructor so the codegen lowers `Cache.Cache raw`
/// to `IpeCacheHandle::Cache(raw)` and `case c of Cache raw -> …` to a match.
#[derive(Clone, Debug, PartialEq)]
pub enum IpeCacheHandle {
    Cache(i64),
}

crate::stringify::show_row!("CacheHandle", Internals, [] IpeCacheHandle, |_| "<Ipe.Cache.Cache>".to_owned());

/// Mirrors Ipê's `CacheCfg` record (field names match → the codegen folds the
/// `{ maxEntries, ttlMs, maxBytes }` record shape to this struct, so a
/// `Cache.defaultCfg` literal constructs it directly — `IrType::CacheCfg`).
/// `Debug + PartialEq` so the emitted-side nominal type is fully derivable
/// (mirrors `CsvDoc`), matching the compiler's `ir_type_is_derivable` decision.
#[allow(non_snake_case)]
#[derive(Clone, Debug, PartialEq)]
pub struct CacheCfg {
    pub maxEntries: i64,
    pub ttlMs: i64,
    pub maxBytes: i64,
}

crate::stringify::show_row!("CacheCfg", Redacted, [] CacheCfg, |_| crate::stringify::REDACTED_SHOW.to_owned());

/// Mirrors Ipê's `stats` return record `{ hits, misses, evictions }`
/// (`IrType::CacheStats`). `Debug + PartialEq` for the same fully-derivable
/// reason as `CacheCfg`.
#[allow(non_snake_case)]
#[derive(Clone, Debug, PartialEq)]
pub struct CacheStats {
    pub hits: i64,
    pub misses: i64,
    pub evictions: i64,
}

crate::stringify::show_row!("CacheStats", Value, [] CacheStats, |s| format!(
    "{{{} {} {}}}",
    s.hits, s.misses, s.evictions
));

struct CacheEntry<K> {
    key: K,
    // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel, 2026-06-13) — Cache_remove carries no V; value erased, downcast to V only on get (per-handle V-consistent); miss → Nothing [ledger #4]
    value: Box<dyn Any + Send>, // the cache value `V`, downcast on get
    expires_at: Option<Instant>,
    last_seq: u64, // for LRU eviction
}

struct Slot {
    cfg: CacheCfg,
    hits: i64,
    misses: i64,
    evictions: i64,
    entries: i64, // tracked here so sizeRaw needs neither K nor V
    seq: u64,     // monotonic access counter
    // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel, 2026-06-13) — Cache_size/clear carry no V; per-handle store downcast by K (every op uses same K); mismatch → no-op [ledger #4]
    store: Option<Box<dyn Any + Send>>, // Vec<CacheEntry<K>>, created lazily on first K-bearing op
}

/// Declared ceiling on the number of simultaneously live caches — the SSOT for
/// the registry bound. `cache_new_raw` fails closed once `live` reaches it, so
/// the registry is bounded by construction even against a caller that never
/// calls `cache_destroy`.
const MAX_LIVE_CACHES: i64 = 4096;

/// The global cache registry: a monotonic handle counter plus the live caches
/// keyed by handle. Keying by the exact `i64` handle makes every op O(1) and
/// never observes `HashMap` iteration order, so output stays deterministic.
struct Registry {
    next: i64,
    live: HashMap<i64, Slot>,
}

fn registry() -> &'static Mutex<Registry> {
    static R: OnceLock<Mutex<Registry>> = OnceLock::new();
    R.get_or_init(|| {
        Mutex::new(Registry {
            next: 0,
            live: HashMap::new(),
        })
    })
}

fn with_slot<R>(handle: i64, default: R, f: impl FnOnce(&mut Slot) -> R) -> R {
    let mut g = registry().lock().unwrap_or_else(|e| e.into_inner());
    match g.live.get_mut(&handle) {
        Some(slot) => f(slot),
        None => default,
    }
}

/// `Cache.newRaw : CacheCfg -> Task Error Int` — allocate a cache, return its handle.
pub fn cache_new_raw<E: Send + From<String> + 'static>(cfg: CacheCfg) -> IpeTask<E, i64> {
    Box::pin(async move {
        // Bounded by construction (PRINCIPLES §3): the type's contract is
        // "bounded by entry count" (Ipe.Cache header). A non-positive
        // `maxEntries` would leave `cache_put`'s `max > 0` LRU cap inert — an
        // unbounded, caller-driven allocation. Reject it at the sole
        // construction boundary (fail-closed) rather than silently disabling
        // the bound. (`ttlMs` is documented "0 disables"; an entry ceiling is
        // not — an unbounded entry count has no legitimate "disabled" meaning
        // for an LRU cache.)
        if cfg.maxEntries <= 0 {
            return IpeResult::Err(
                format!(
                    "Cache.new: maxEntries must be positive (got {}); an LRU cache is bounded by entry count",
                    cfg.maxEntries
                )
                .into(),
            );
        }
        // A byte bound is a value the runtime must enforce or refuse: values are
        // stored erased (no size-measuring bound), so no byte accounting exists.
        // A requested cap is refused at the construction boundary rather than
        // accepted and ignored; `0` means no byte bound was requested.
        if cfg.maxBytes < 0 {
            return IpeResult::Err(
                format!(
                    "Cache.new: maxBytes must be non-negative (got {}); a byte cap is a byte count",
                    cfg.maxBytes
                )
                .into(),
            );
        }
        if cfg.maxBytes > 0 {
            return IpeResult::Err(
                "Cache.new: maxBytes is not enforced by this runtime; bound the cache with withMaxEntries"
                    .to_string()
                    .into(),
            );
        }
        let h = {
            let mut g = registry().lock().unwrap_or_else(|e| e.into_inner());
            // Fail-closed ceiling (PRINCIPLES §1/§3): refuse a new cache once the
            // registry is full rather than growing without bound or silently
            // evicting a cache another task still holds a handle to. Reclamation
            // is caller-driven (`cache_destroy`); this is the hard backstop.
            if g.live.len() as i64 >= MAX_LIVE_CACHES {
                return IpeResult::Err(
                    format!(
                        "Cache.new: live cache limit reached ({MAX_LIVE_CACHES}); destroy unused caches before creating more"
                    )
                    .into(),
                );
            }
            // Saturating: monotonic handle counter — `+= 1` would debug-panic on
            // i64 overflow. (Saturating at i64::MAX is benign: reaching it needs
            // ~2^63 cache allocations; the cap merely keeps the op total.)
            g.next = g.next.saturating_add(1);
            let h = g.next;
            g.live.insert(
                h,
                Slot {
                    cfg,
                    hits: 0,
                    misses: 0,
                    evictions: 0,
                    entries: 0,
                    seq: 0,
                    store: None,
                },
            );
            h
        };
        ok_res(h)
    })
}

/// `Cache.putRaw : Int -> k -> v -> Task Error ()`.
pub fn cache_put<E, K, V>(handle: i64, key: K, value: V) -> IpeTask<E, ()>
where
    E: Send + From<String> + 'static,
    K: PartialEq + Send + 'static,
    V: Send + 'static,
{
    Box::pin(async move {
        with_slot(handle, (), |slot| {
            slot.seq = slot.seq.saturating_add(1);
            let seq = slot.seq;
            let max = slot.cfg.maxEntries;
            let ttl = slot.cfg.ttlMs;
            let expires_at = if ttl > 0 {
                // Saturate instead of panicking: a Ipê caller passing a near-i64::MAX ttl
                // (e.g. `withTTL Int.maxInt`) must not cause "overflow when adding duration
                // to instant". ttl > 0 is already guarded above, so the cast is lossless.
                Some(
                    Instant::now()
                        .checked_add(Duration::from_millis(ttl as u64))
                        .unwrap_or_else(|| {
                            Instant::now() + Duration::from_secs(60 * 60 * 24 * 365 * 30)
                        }),
                )
            } else {
                None // ttl <= 0 → no expiry
            };
            let (added, evicted) = {
                let store = slot
                    .store
                    .get_or_insert_with(|| Box::new(Vec::<CacheEntry<K>>::new()));
                match store.downcast_mut::<Vec<CacheEntry<K>>>() {
                    None => (0i64, 0i64), // impossible per per-handle (K,V) consistency
                    Some(vec) => {
                        let mut added = 1i64;
                        if let Some(e) = vec.iter_mut().find(|e| e.key == key) {
                            e.value = Box::new(value);
                            e.expires_at = expires_at;
                            e.last_seq = seq;
                            added = 0;
                        } else {
                            vec.push(CacheEntry {
                                key,
                                value: Box::new(value),
                                expires_at,
                                last_seq: seq,
                            });
                        }
                        let mut evicted = 0i64;
                        if max > 0 && vec.len() as i64 > max {
                            // evict the least-recently-used (smallest last_seq)
                            if let Some((idx, _)) =
                                vec.iter().enumerate().min_by_key(|(_, e)| e.last_seq)
                            {
                                vec.remove(idx);
                                evicted = 1;
                            }
                        }
                        (added, evicted)
                    }
                }
            };
            slot.entries = slot.entries.saturating_add(added).saturating_sub(evicted);
            slot.evictions = slot.evictions.saturating_add(evicted);
        });
        ok_res(())
    })
}

/// `Cache.getRaw : Int -> k -> Task Error (Maybe v)`.
pub fn cache_get<E, K, V>(handle: i64, key: K) -> IpeTask<E, IpeMaybe<V>>
where
    E: Send + From<String> + 'static,
    K: PartialEq + Send + 'static,
    V: Clone + Send + 'static,
{
    Box::pin(async move {
        let out = with_slot(handle, IpeMaybe::Nothing, |slot| {
            slot.seq = slot.seq.saturating_add(1);
            let seq = slot.seq;
            let now = Instant::now();
            enum Outcome<V> {
                Hit(V),
                Expired,
                Miss,
            }
            let outcome = match slot
                .store
                .as_mut()
                .and_then(|s| s.downcast_mut::<Vec<CacheEntry<K>>>())
            {
                None => Outcome::Miss,
                Some(vec) => match vec.iter().position(|e| e.key == key) {
                    None => Outcome::Miss,
                    Some(idx) => {
                        // index is in-bounds (just found); guard with .get anyway
                        let expired = vec
                            .get(idx)
                            .is_some_and(|e| e.expires_at.is_some_and(|x| now >= x));
                        if expired {
                            vec.remove(idx);
                            Outcome::Expired
                        } else {
                            match vec.get_mut(idx) {
                                Some(e) => {
                                    e.last_seq = seq; // LRU touch
                                    match e.value.downcast_ref::<V>().cloned() {
                                        Some(v) => Outcome::Hit(v),
                                        None => Outcome::Miss, // impossible; total fallback
                                    }
                                }
                                None => Outcome::Miss,
                            }
                        }
                    }
                },
            };
            match outcome {
                Outcome::Hit(v) => {
                    slot.hits = slot.hits.saturating_add(1);
                    IpeMaybe::Just(v)
                }
                Outcome::Expired => {
                    slot.misses = slot.misses.saturating_add(1);
                    slot.entries = slot.entries.saturating_sub(1);
                    IpeMaybe::Nothing
                }
                Outcome::Miss => {
                    slot.misses = slot.misses.saturating_add(1);
                    IpeMaybe::Nothing
                }
            }
        });
        ok_res(out)
    })
}

/// `Cache.removeRaw : Int -> k -> Task Error ()`.
pub fn cache_remove<E, K>(handle: i64, key: K) -> IpeTask<E, ()>
where
    E: Send + From<String> + 'static,
    K: PartialEq + Send + 'static,
{
    Box::pin(async move {
        with_slot(handle, (), |slot| {
            let before = slot
                .store
                .as_ref()
                .and_then(|s| s.downcast_ref::<Vec<CacheEntry<K>>>())
                .map_or(0, |v| v.len());
            if let Some(vec) = slot
                .store
                .as_mut()
                .and_then(|s| s.downcast_mut::<Vec<CacheEntry<K>>>())
            {
                vec.retain(|e| e.key != key);
                let removed = (before - vec.len()) as i64;
                slot.entries = slot.entries.saturating_sub(removed);
            }
        });
        ok_res(())
    })
}

/// `Cache.clearRaw : Int -> Task Error ()`.
pub fn cache_clear<E: Send + From<String> + 'static>(handle: i64) -> IpeTask<E, ()> {
    Box::pin(async move {
        with_slot(handle, (), |slot| {
            slot.store = None;
            slot.entries = 0;
        });
        ok_res(())
    })
}

/// `Cache.destroyRaw : Int -> Task Error ()` — reclaim a cache's `Slot`,
/// freeing a registry slot against the `MAX_LIVE_CACHES` ceiling. Idempotent:
/// destroying an unknown or already-destroyed handle is a no-op `Ok(())` (the
/// same convention as `cache_remove`). After destroy, every op on the handle
/// takes the missing-handle `default` branch.
pub fn cache_destroy<E: Send + From<String> + 'static>(handle: i64) -> IpeTask<E, ()> {
    Box::pin(async move {
        registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .live
            .remove(&handle);
        ok_res(())
    })
}

/// `Cache.sizeRaw : Int -> Task Error Int`.
pub fn cache_size<E: Send + From<String> + 'static>(handle: i64) -> IpeTask<E, i64> {
    Box::pin(async move { ok_res(with_slot(handle, 0, |slot| slot.entries)) })
}

/// `Cache.statsRaw : Int -> Task Error { hits, misses, evictions }`.
pub fn cache_stats<E: Send + From<String> + 'static>(handle: i64) -> IpeTask<E, CacheStats> {
    Box::pin(async move {
        let s = with_slot(
            handle,
            CacheStats {
                hits: 0,
                misses: 0,
                evictions: 0,
            },
            |slot| CacheStats {
                hits: slot.hits,
                misses: slot.misses,
                evictions: slot.evictions,
            },
        );
        ok_res(s)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run<T: Send + 'static>(t: IpeTask<IpeError, T>) -> T {
        match crate::task::block_on(t) {
            IpeResult::Ok(v) => v,
            IpeResult::Err(_) => panic!("cache task failed"),
        }
    }

    fn try_new(cfg: CacheCfg) -> IpeResult<IpeError, i64> {
        crate::task::block_on(cache_new_raw::<IpeError>(cfg))
    }

    /// Bounded by construction (PRINCIPLES §3): a non-positive `maxEntries`
    /// would leave the LRU cap inert (unbounded growth), so `Cache.new` refuses
    /// it at the construction boundary — fail-closed — rather than silently
    /// creating an unbounded cache. A positive `maxEntries` still succeeds.
    #[test]
    fn new_rejects_non_positive_max_entries() {
        for bad in [0, -1, i64::MIN] {
            assert!(
                matches!(
                    try_new(CacheCfg {
                        maxEntries: bad,
                        ttlMs: 0,
                        maxBytes: 0,
                    }),
                    IpeResult::Err(_)
                ),
                "maxEntries = {bad} must be refused (unbounded LRU is not representable)"
            );
        }
        assert!(matches!(
            try_new(CacheCfg {
                maxEntries: 1,
                ttlMs: 0,
                maxBytes: 0,
            }),
            IpeResult::Ok(_)
        ));
    }

    /// A byte cap the runtime cannot enforce is refused at construction, never
    /// accepted and ignored; `maxBytes = 0` (no byte cap requested) still builds.
    #[test]
    fn new_refuses_a_byte_cap() {
        for bad in [1, i64::MAX, -1, i64::MIN] {
            assert!(
                matches!(
                    try_new(CacheCfg {
                        maxEntries: 8,
                        ttlMs: 0,
                        maxBytes: bad,
                    }),
                    IpeResult::Err(_)
                ),
                "maxBytes = {bad} must be refused (no byte accounting exists)"
            );
        }
        assert!(matches!(
            try_new(CacheCfg {
                maxEntries: 8,
                ttlMs: 0,
                maxBytes: 0,
            }),
            IpeResult::Ok(_)
        ));
    }

    #[test]
    fn put_get_size_remove_stats() {
        let h = run(cache_new_raw::<IpeError>(CacheCfg {
            maxEntries: 8,
            ttlMs: 0,
            maxBytes: 0,
        }));
        run(cache_put::<IpeError, String, String>(
            h,
            "a".into(),
            "1".into(),
        ));
        run(cache_put::<IpeError, String, String>(
            h,
            "b".into(),
            "2".into(),
        ));
        assert_eq!(run(cache_size::<IpeError>(h)), 2);
        assert_eq!(
            run(cache_get::<IpeError, String, String>(h, "a".into())),
            IpeMaybe::Just("1".into())
        );
        assert_eq!(
            run(cache_get::<IpeError, String, String>(h, "z".into())),
            IpeMaybe::Nothing
        );
        run(cache_remove::<IpeError, String>(h, "a".into()));
        assert_eq!(
            run(cache_get::<IpeError, String, String>(h, "a".into())),
            IpeMaybe::Nothing
        );
        assert_eq!(run(cache_size::<IpeError>(h)), 1);
        let st = run(cache_stats::<IpeError>(h));
        assert_eq!(st.hits, 1);
        assert_eq!(st.misses, 2);
    }

    #[test]
    fn lru_eviction_over_capacity() {
        let h = run(cache_new_raw::<IpeError>(CacheCfg {
            maxEntries: 2,
            ttlMs: 0,
            maxBytes: 0,
        }));
        run(cache_put::<IpeError, String, i64>(h, "a".into(), 1));
        run(cache_put::<IpeError, String, i64>(h, "b".into(), 2));
        let _ = run(cache_get::<IpeError, String, i64>(h, "a".into())); // touch a (b now LRU)
        run(cache_put::<IpeError, String, i64>(h, "c".into(), 3)); // evicts b
        assert_eq!(run(cache_size::<IpeError>(h)), 2);
        assert_eq!(
            run(cache_get::<IpeError, String, i64>(h, "b".into())),
            IpeMaybe::Nothing
        );
        assert_eq!(
            run(cache_get::<IpeError, String, i64>(h, "a".into())),
            IpeMaybe::Just(1)
        );
        assert_eq!(run(cache_stats::<IpeError>(h)).evictions, 1);
    }

    fn tiny_cfg() -> CacheCfg {
        CacheCfg {
            maxEntries: 1,
            ttlMs: 0,
            maxBytes: 0,
        }
    }

    /// Registry bounded by construction (PRINCIPLES §1/§3): after `MAX_LIVE_CACHES`
    /// live caches, the next `cache_new_raw` fails closed rather than growing the
    /// registry without bound. Pins the exhaustion backstop. Destroys the caches
    /// created here so the shared process-wide registry is left at its prior size.
    #[test]
    fn registry_bounded_by_ceiling() {
        // Bring the live count up to the ceiling from wherever it currently sits
        // (the registry is process-global and other tests may hold caches), then
        // assert the boundary. Track our own handles to reclaim them afterwards.
        let mut ours = Vec::new();
        loop {
            let live = {
                let g = registry().lock().unwrap_or_else(|e| e.into_inner());
                g.live.len() as i64
            };
            if live >= MAX_LIVE_CACHES {
                break;
            }
            match try_new(tiny_cfg()) {
                IpeResult::Ok(h) => ours.push(h),
                IpeResult::Err(_) => break,
            }
        }
        // At (or above) the ceiling, a further allocation is refused.
        assert!(
            matches!(try_new(tiny_cfg()), IpeResult::Err(_)),
            "cache_new_raw must fail closed at the MAX_LIVE_CACHES ceiling"
        );
        for h in ours {
            run(cache_destroy::<IpeError>(h));
        }
    }

    /// `cache_destroy` reclaims the handle's `Slot`: subsequent ops take the
    /// missing-handle `default` branch, and a fresh `cache_new_raw` succeeds again
    /// (a freed slot is reusable against the ceiling).
    #[test]
    fn destroy_reclaims_handle() {
        let h = run(cache_new_raw::<IpeError>(CacheCfg {
            maxEntries: 8,
            ttlMs: 0,
            maxBytes: 0,
        }));
        run(cache_put::<IpeError, String, String>(
            h,
            "a".into(),
            "1".into(),
        ));
        assert_eq!(run(cache_size::<IpeError>(h)), 1);
        run(cache_destroy::<IpeError>(h));
        // Destroyed handle resolves to the default branch: size 0, get Nothing.
        assert_eq!(run(cache_size::<IpeError>(h)), 0);
        assert_eq!(
            run(cache_get::<IpeError, String, String>(h, "a".into())),
            IpeMaybe::Nothing
        );
        // A fresh cache still allocates after reclamation.
        assert!(matches!(try_new(tiny_cfg()), IpeResult::Ok(_)));
    }

    /// `cache_destroy` is idempotent — destroying twice, and destroying an unknown
    /// handle, both succeed (matches the `remove`-idempotent convention).
    #[test]
    fn destroy_is_idempotent() {
        let h = run(cache_new_raw::<IpeError>(tiny_cfg()));
        run(cache_destroy::<IpeError>(h));
        run(cache_destroy::<IpeError>(h)); // second destroy on same handle
        run(cache_destroy::<IpeError>(i64::MAX)); // unknown handle
    }

    /// Behavioral proxy for the map-keyed (not scan-based) registry: with several
    /// live caches, destroying an early handle leaves later handles resolvable and
    /// the destroyed one unresolvable. Every op keys by the exact handle.
    #[test]
    fn lookup_is_map_keyed_not_scan() {
        let a = run(cache_new_raw::<IpeError>(tiny_cfg()));
        let b = run(cache_new_raw::<IpeError>(tiny_cfg()));
        let c = run(cache_new_raw::<IpeError>(tiny_cfg()));
        run(cache_put::<IpeError, String, i64>(c, "k".into(), 9));
        run(cache_destroy::<IpeError>(a)); // destroy an early handle
        // The late handle still resolves; the destroyed early one does not.
        assert_eq!(
            run(cache_get::<IpeError, String, i64>(c, "k".into())),
            IpeMaybe::Just(9)
        );
        assert_eq!(run(cache_size::<IpeError>(a)), 0);
        run(cache_destroy::<IpeError>(b));
        run(cache_destroy::<IpeError>(c));
    }
}
