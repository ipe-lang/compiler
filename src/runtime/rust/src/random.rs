// Random kernel stubs — generic over E.
//
// SECURITY INVARIANT — this module is a NON-CRYPTOGRAPHIC PRNG (a 64-bit LCG
// seeded from the wall clock), implementing Ipê's `Random.*` surface with the
// SAME contract as the  `math/rand`. Its output is fully predictable
// and MUST NEVER back a secret, token, session id, nonce, salt, or any value an
// attacker must not guess. Every security-bearing draw in this runtime already
// uses the OS CSPRNG (`OsRng` / `getrandom`) instead:
//   - session ids        → live/mod.rs `new_sid` (OsRng, 128-bit)
//   - tokens / entropy    → crypto.rs `crypto_random_token` / `crypto_random_bytes`
//   - AEAD nonces, keys   → crypto.rs (OsRng)
//   - CSRF token          → live/csrf.rs `gen_token` (OsRng)
//   - UUID v4             → `uuid::new_v4` (getrandom)
// When adding a new security-bearing random value, route it through `OsRng`, NOT
// through any `lcg_*` / `random_*` fn here. (Audit finding: low/weak-crypto —
// recorded as an invariant so a future change can't silently violate it.)
use super::{EffectSend, IpeMaybe, IpeResult, IpeTask, ok_res, str_err};
use std::sync::atomic::{AtomicU64, Ordering};

static LCG_STATE: AtomicU64 = AtomicU64::new(0);

/// Wall-clock nanos seed the LCG on native. `SystemTime::now()` COMPILES on
/// `wasm32-unknown-unknown` (part of std) but TRAPS at runtime — no clock
/// without the `wasmbind` feature this target does not carry. The M4 browser
/// substitute (`Random.*` — Q3: "SUBSTITUTE | `crypto.getRandomValues`")
/// seeds from `getrandom(js)` instead: real entropy, not merely a
/// platform-safe stand-in, and the same source `crypto_random_bytes` uses.
#[cfg(not(target_arch = "wasm32"))]
fn lcg_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(target_arch = "wasm32")]
fn lcg_seed() -> u64 {
    let mut buf = [0u8; 8];
    // A `getrandom` failure is vanishingly rare (no browser entropy source);
    // falling back to a fixed non-zero constant keeps `lcg_init` infallible
    // (its callers are non-Task pure kernels) rather than panicking — the LCG
    // is documented non-cryptographic regardless, so a degraded-but-total
    // fallback is sound here specifically.
    if getrandom::getrandom(&mut buf).is_err() {
        return 0x9E37_79B9_7F4A_7C15;
    }
    u64::from_le_bytes(buf)
}

pub(crate) fn lcg_init() {
    LCG_STATE
        .compare_exchange(0, lcg_seed(), Ordering::Relaxed, Ordering::Relaxed)
        .ok();
}

pub(crate) fn lcg_next() -> u64 {
    // Atomic RMW (CAS loop) so two threads under `task_parallel` can't read the
    // same state and emit identical sequences (lost-update / duplicate-randomness
    // race). The non-atomic load→compute→store this replaces was racy.
    let mut state = LCG_STATE.load(Ordering::Relaxed);
    loop {
        let next = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        match LCG_STATE.compare_exchange_weak(state, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(observed) => state = observed,
        }
    }
}

// ── Deterministic seeded PRNG (splitmix64) — byte-for-byte parity with
//    seedStep / Random_seededInt/Float/Choice (). Pure. ──

fn seed_step(z_in: i64) -> i64 {
    let mut z = (z_in as u64).wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z = z ^ (z >> 31);
    z as i64
}

/// Reduce a splitmix64 draw uniformly into `[0, width)` by rejection sampling,
/// re-stepping the seed on rejection. Returns `(offset, final_seed)` so callers
/// can thread the advanced seed. `width` is always ≥ 1 at every call site.
/// Bounded in expectation (< 2 iterations); each redraw advances the seed, so
/// the loop cannot be driven unbounded by any input.
fn seeded_reduce(mut sample: u64, width: u128, mut seed: i64) -> (u128, i64) {
    // Largest multiple of `width` that fits the u64 sample space; samples at or
    // above it would bias the low residues, so redraw them.
    let space = 1u128 << 64;
    let limit = space - (space % width);
    while u128::from(sample) >= limit {
        seed = seed_step(seed);
        sample = seed as u64;
    }
    (u128::from(sample) % width, seed)
}

/// `Random.seededIntRaw : Int -> Int -> Int -> (Int, Int)` → (value, newSeed).
#[must_use]
pub fn random_seeded_int(s: i64, lo: i64, hi: i64) -> (i64, i64) {
    let next = seed_step(s);
    if hi <= lo {
        return (lo, next);
    }
    // i128 width so `hi - lo + 1` never overflows i64 (hi=MAX, lo=MIN panicked).
    let width = (i128::from(hi) - i128::from(lo) + 1) as u128;
    // Full 64 bits of the splitmix64 output feed the reduction: splitmix64 is
    // well-distributed across every bit, so a high-bit shift would only shrink
    // the reachable offset space (a width past 2^31 would leave its upper half
    // unreachable). Rejection sampling removes modulo bias — the naive `% width`
    // over-represents low residues when `width` does not divide the sample space
    // evenly. The rejection loop is bounded in expectation (< 2 iterations: at
    // least half of every `[0, k*width)` block is accepted) and each redraw
    // advances the seed, so no input dictates unbounded work.
    let (off, next) = seeded_reduce(next as u64, width, next);
    let v = (i128::from(lo) + off as i128) as i64; // in [lo, hi] -> fits i64
    (if v < lo { lo } else { v }, next)
}

/// `Random.seededFloatRaw : Int -> (Float, Int)` → (value in [0,1), newSeed).
#[must_use]
pub fn random_seeded_float(s: i64) -> (f64, i64) {
    let next = seed_step(s);
    let f = (next as u64 >> 11) as f64 / (1u64 << 53) as f64;
    (f, next)
}

/// `Random.seededChoiceRaw : Int -> List a -> (Maybe a, Int)`.
#[must_use]
pub fn random_seeded_choice<T: Clone>(s: i64, items: Vec<T>) -> (IpeMaybe<T>, i64) {
    let next = seed_step(s);
    if items.is_empty() {
        return (IpeMaybe::Nothing, next);
    }
    // Full 64 bits + rejection sampling, consistent with `random_seeded_int`
    // (the `>> 33` reduction was harmless here — lists are never 2^31 long — but
    // one reduction path is easier to reason about than two).
    let width = items.len() as u128;
    let (idx, _next) = seeded_reduce(next as u64, width, next);
    let idx = idx as usize;
    match items.get(idx) {
        Some(x) => (IpeMaybe::Just(x.clone()), next),
        None => (IpeMaybe::Nothing, next), // unreachable (idx < len), but total
    }
}

#[must_use]
pub fn random_int<E: Send + 'static>(lo: i64, hi: i64) -> IpeTask<E, i64> {
    Box::pin(async move {
        lcg_init();
        // Inclusive [lo, hi] semantics matching  `mrand.Intn(hi-lo+1)`.
        // Do the modulo in u64 and add to lo so the result can never fall below
        // lo (the previous `lcg_next() as i64 % range` produced negative
        // remainders → out-of-range draws). `wrapping_*`/u64 width avoid the
        // `i64::MIN.abs()` overflow-panic on extreme `lo`/`hi`.
        if hi < lo {
            return ok_res(lo);
        }
        let span = (hi.wrapping_sub(lo)) as u64;
        // Full-width span (hi==i64::MAX && lo==i64::MIN): span == u64::MAX, so
        // `span + 1` wraps to 0 and the modulo path would degenerate to a
        // constant `lo`. Draw uniformly over all 2^64 values instead — each maps
        // 1:1 into the inclusive [lo, hi] range.
        if span == u64::MAX {
            return ok_res(lo.wrapping_add(lcg_next() as i64));
        }
        let range = span.wrapping_add(1).max(1);
        // Rejection sampling removes modulo bias: reject the tail of the u64
        // sample space that does not divide evenly by `range`, so every value in
        // [lo, hi] is equiprobable. Bounded in expectation (< 2 iterations — at
        // least half of every block is accepted) and each redraw advances the
        // generator, so no input drives the loop unbounded.
        let limit = u64::MAX - (u64::MAX % range);
        let mut sample = lcg_next();
        while sample >= limit {
            sample = lcg_next();
        }
        let v = lo.wrapping_add((sample % range) as i64);
        ok_res(v)
    })
}

#[must_use]
pub fn random_float<E: Send + 'static>(lo: f64, hi: f64) -> IpeTask<E, f64> {
    Box::pin(async move {
        lcg_init();
        // Uniform float in [lo, hi) — matches the stdlib contract
        // `float : Float -> Float -> Task Error Float` and
        // `Random_floatT` (lo + Float64()*(hi-lo)).
        // Unit draw is the 53-bit mantissa trick → [0, 1); never
        // `/ u64::MAX` (which rounds to 1.0 and could emit `hi`,
        // breaking the half-open upper bound).
        let unit = (lcg_next() >> 11) as f64 / (1u64 << 53) as f64;
        // Degenerate bounds: returns a value < lo when
        // hi < lo. We clamp to lo instead (sound, no negative-range
        // footgun) — same defensive choice as random_int's `hi < lo`
        // guard above.
        if hi <= lo {
            return ok_res(lo);
        }
        ok_res(lo + unit * (hi - lo))
    })
}

#[must_use]
pub fn random_choice<E: Send + From<String> + 'static>(items: Vec<String>) -> IpeTask<E, String> {
    Box::pin(async move {
        lcg_init();
        if items.is_empty() {
            return IpeResult::Err(str_err("Random.choice: empty list"));
        }
        let idx = lcg_next() as usize % items.len();
        ok_res(items.get(idx).cloned().unwrap_or_default())
    })
}

/// `Random.choice : List a -> Task Error (Maybe a)` (kernel name `Random_choiceMaybe`).
/// Returns `Ok Nothing` on empty list, `Ok (Just elem)` otherwise — never Err.
/// Matches  `Random_choiceMaybe` which uses `Ok(makeMaybeNothing())` /
/// `Ok(makeMaybeJust(...))`.
#[must_use]
pub fn random_choice_maybe<E: EffectSend, T: Clone + EffectSend>(
    items: Vec<T>,
) -> IpeTask<E, IpeMaybe<T>> {
    Box::pin(async move {
        lcg_init();
        let out = if items.is_empty() {
            IpeMaybe::Nothing
        } else {
            let idx = lcg_next() as usize % items.len();
            // get() is always Some here: idx < items.len()
            match items.get(idx) {
                Some(x) => IpeMaybe::Just(x.clone()),
                None => IpeMaybe::Nothing, // unreachable by construction
            }
        };
        ok_res(out)
    })
}

/// `Random.shuffle : List a -> Task Error (List a)` — Fisher-Yates.
/// Matches  `Random_shuffle` which uses `mrand.Shuffle` over a copy of
/// the list (input not mutated).
#[must_use]
pub fn random_shuffle<E: EffectSend, T: Clone + EffectSend>(items: Vec<T>) -> IpeTask<E, Vec<T>> {
    Box::pin(async move {
        lcg_init();
        let mut result = items;
        let n = result.len();
        // LCG-based Fisher-Yates (Knuth shuffle): iterate from the last element
        // backward and swap with a random element at or before it.
        for i in (1..n).rev() {
            let j = lcg_next() as usize % (i + 1);
            result.swap(i, j);
        }
        ok_res(result)
    })
}

/// `Random.weighted : List (Float, a) -> Task Error (Maybe a)`.
/// Each tuple is `(weight, value)`; picks proportionally by weight. Non-positive
/// weights are skipped. Returns `Ok Nothing` when every weight is ≤ 0 or the
/// list is empty — matches  `Random_weighted`.
#[must_use]
pub fn random_weighted<E: EffectSend, T: Clone + EffectSend>(
    items: Vec<(f64, T)>,
) -> IpeTask<E, IpeMaybe<T>> {
    Box::pin(async move {
        lcg_init();
        // Filter to positive-weight entries and compute total.
        let positive: Vec<(f64, &T)> = items
            .iter()
            .filter(|(w, _)| *w > 0.0)
            .map(|(w, v)| (*w, v))
            .collect();
        if positive.is_empty() {
            return ok_res(IpeMaybe::Nothing);
        }
        let total: f64 = positive.iter().map(|(w, _)| w).sum();
        // A finite-but-huge set of weights can sum to `+inf` (or produce a NaN),
        // which would make `r` non-finite so `r < cum` never fires and every draw
        // collapses to the last entry — a silent non-proportional result. When
        // the total is not a usable positive finite number, fall back to a uniform
        // pick over the positive entries: still total, still a sensible draw, and
        // never NaN/always-last.
        if !total.is_finite() || total <= 0.0 {
            let idx = lcg_next() as usize % positive.len();
            return match positive.get(idx) {
                Some((_, v)) => ok_res(IpeMaybe::Just((*v).clone())),
                None => ok_res(IpeMaybe::Nothing), // unreachable: idx < len
            };
        }
        // Map LCG output to [0.0, 1.0) then scale.
        let r = (lcg_next() >> 11) as f64 * (1.0 / 9_007_199_254_740_992.0) * total;
        let mut cum = 0.0;
        for (w, v) in &positive {
            cum += w;
            if r < cum {
                return ok_res(IpeMaybe::Just((*v).clone()));
            }
        }
        // Floating-point rounding fallthrough — return last (matches  fallthrough).
        let last = positive.last().map(|(_, v)| (*v).clone());
        match last {
            Some(v) => ok_res(IpeMaybe::Just(v)),
            None => ok_res(IpeMaybe::Nothing),
        }
    })
}
