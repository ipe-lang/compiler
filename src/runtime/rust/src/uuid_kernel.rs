//! Ipe.Uuid kernels — v4 / v7 / parse over the `uuid` crate's builders.
//!
//! Module is `uuid_kernel` (not `uuid`) to avoid clashing with the `uuid`
//! crate; functions use the `::uuid::` extern path.
//!
//! # Entropy is an EFFECT, not a pure value
//!
//! `v4` / `v7` draw fresh entropy on every call, so they are typed on the
//! effect tier — `Ipe.Uuid.{v4,v7} : () -> Task Error String`, called
//! `Uuid.v4 ()` exactly like `Time.now ()` / `Crypto.randomToken n`. This makes
//! "entropy typed as a memoizable pure `String`" UNREPRESENTABLE: a pure
//! `String` is eligible for CSE / memoization / reordering, so two `Uuid.v4`
//! references could collapse to one shared value. The generation runs INSIDE
//! the returned future's body, so each `.run()` of the task re-evaluates and
//! yields a distinct id — proved by the `v4_two_runs_differ` unit test here
//! and the `uuid_distinct` E2E golden.
//!
//! # A draw can fail
//!
//! Every id's random bits come from [`crate::entropy::fill_entropy`]. A host
//! without entropy fails the task with kind `Unavailable`, the retryable kind;
//! no id is produced from a weaker source. `v7` ids come from [`V7Clock`], a
//! per-process monotonic generator (RFC 9562 §6.2 method 1), so ids minted in
//! one process sort in mint order.
//!
//! `parse` stays PURE (`String -> Maybe String`): it inspects an existing
//! string with no entropy and no side effect — a genuine parser, not the
//! arity-0 codegen artifact.

use super::{FromUnavailable, IpeMaybe, IpeResult, IpeTask, ok_res};
use crate::entropy::{EntropyError, fill_entropy};
use std::sync::{Mutex, PoisonError};

/// Ipe.Uuid.v4 : () -> Task Error String
///
/// The random draw happens inside the future body so every `.run()` yields a
/// FRESH id — entropy is not memoizable. Fails with kind `Unavailable` when
/// the OS random source is unavailable.
#[must_use]
pub fn uuid_v4<E: From<String> + FromUnavailable + Send + 'static>(_: ()) -> IpeTask<E, String> {
    Box::pin(async move { v4_with(fill_entropy) })
}

/// A v4 id from 16 bytes `fill` draws.
fn v4_with<E: FromUnavailable>(
    fill: impl FnOnce(&mut [u8]) -> Result<(), EntropyError>,
) -> IpeResult<E, String> {
    let mut bytes = [0_u8; 16];
    match fill(&mut bytes) {
        Ok(()) => ok_res(
            ::uuid::Builder::from_random_bytes(bytes)
                .into_uuid()
                .to_string(),
        ),
        Err(EntropyError) => IpeResult::Err(E::from_unavailable(
            "Uuid.v4: the OS random source is unavailable".to_owned(),
        )),
    }
}

/// Ipe.Uuid.v7 : () -> Task Error String  (time-ordered)
///
/// SECURITY: a v7 UUID embeds a millisecond timestamp and is SORTABLE/guessable
/// by design — it is NOT a secret. Use it for ordered ids, never as a bearer
/// token / session id / password-reset nonce (use `crypto_random_token` for
/// those). `v4` is random (CSPRNG) but UUIDs are still only 122 bits of
/// formatted entropy — prefer `crypto_random_token` for security tokens.
///
/// Fails with kind `Unavailable` when the OS random source or the clock is
/// unavailable, or the clock reads outside the UUIDv7 range.
#[must_use]
pub fn uuid_v7<E: From<String> + FromUnavailable + Send + 'static>(_: ()) -> IpeTask<E, String> {
    Box::pin(async move { v7_with(&V7_CLOCK, now_millis, fill_entropy) })
}

/// The process's one v7 generator.
static V7_CLOCK: V7Clock = V7Clock::new();

/// A v7 id from `clock`, the time `now` reads and 16 bytes `fill` draws.
///
/// The draw happens first, so a refused draw leaves the generator untouched.
fn v7_with<E: FromUnavailable>(
    clock: &V7Clock,
    now: impl FnOnce() -> Option<u64>,
    fill: impl FnOnce(&mut [u8]) -> Result<(), EntropyError>,
) -> IpeResult<E, String> {
    let mut draw = [0_u8; 16];
    if fill(&mut draw).is_err() {
        return IpeResult::Err(E::from_unavailable(
            "Uuid.v7: the OS random source is unavailable".to_owned(),
        ));
    }
    let Some(now_ms) = now() else {
        return IpeResult::Err(E::from_unavailable(
            "Uuid.v7: the clock is unavailable".to_owned(),
        ));
    };
    match clock.next(now_ms, draw) {
        Ok(id) => ok_res(id.to_string()),
        Err(V7Refusal::ClockOutsideRange) => IpeResult::Err(E::from_unavailable(
            "Uuid.v7: clock outside the UUIDv7 range".to_owned(),
        )),
    }
}

/// The largest counter value a v7 id holds (42 bits).
const MAX_COUNTER: u64 = (1 << 42) - 1;

/// The largest Unix-millisecond timestamp a v7 id holds (48 bits).
const MAX_TIMESTAMP_MS: u64 = (1 << 48) - 1;

/// The reseed mask: a fresh counter keeps its top bit clear.
///
/// So a reseeded counter has `2^41` increments before it overflows.
const RESEED_MASK: u64 = (1 << 41) - 1;

/// The low 30 counter bits, stored after the variant.
const COUNTER_LOW_MASK: u64 = (1 << 30) - 1;

/// Why [`V7Clock::next`] produced no id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V7Refusal {
    /// The timestamp the id would carry exceeds 48 bits.
    ClockOutsideRange,
}

/// The generator's last timestamp and counter.
struct V7State {
    last_ms: u64,
    counter: u64,
}

/// A monotonic UUIDv7 generator: a 48-bit timestamp, a 42-bit counter, a random tail.
///
/// Within one millisecond, or when the clock steps back, the counter
/// increments under the last timestamp; a counter overflow advances the
/// timestamp by one and reseeds. Ids from one generator are strictly
/// increasing.
pub struct V7Clock {
    state: Mutex<V7State>,
}

impl V7Clock {
    /// A generator that has minted nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(V7State {
                last_ms: 0,
                counter: 0,
            }),
        }
    }

    /// The next id at clock reading `now_ms`, from the 16 random bytes `draw`.
    ///
    /// Bytes 0..8 reseed the counter; bytes 8..16 fill the random tail.
    ///
    /// # Errors
    ///
    /// [`V7Refusal::ClockOutsideRange`] when the id's timestamp would exceed
    /// 48 bits; the generator is then left unchanged.
    pub fn next(&self, now_ms: u64, draw: [u8; 16]) -> Result<::uuid::Uuid, V7Refusal> {
        let [
            r0,
            r1,
            r2,
            r3,
            r4,
            r5,
            r6,
            r7,
            t0,
            t1,
            t2,
            t3,
            t4,
            t5,
            t6,
            t7,
        ] = draw;
        let reseed = u64::from_be_bytes([r0, r1, r2, r3, r4, r5, r6, r7]) & RESEED_MASK;
        let tail = u64::from_be_bytes([t0, t1, t2, t3, t4, t5, t6, t7]);
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let (ms, counter) = if now_ms > state.last_ms {
            (now_ms, reseed)
        } else {
            match state.counter.checked_add(1).filter(|c| *c <= MAX_COUNTER) {
                Some(counter) => (state.last_ms, counter),
                None => (
                    state
                        .last_ms
                        .checked_add(1)
                        .ok_or(V7Refusal::ClockOutsideRange)?,
                    reseed,
                ),
            }
        };
        if ms > MAX_TIMESTAMP_MS {
            return Err(V7Refusal::ClockOutsideRange);
        }
        state.last_ms = ms;
        state.counter = counter;
        drop(state);
        // The 80 bits after the timestamp: 4 version bits, the counter's top
        // 12 bits, 2 variant bits, its low 30 bits, then 32 random bits. The
        // builder overwrites the version and variant positions.
        let field = (u128::from(counter >> 30) << 64)
            | (u128::from(counter & COUNTER_LOW_MASK) << 32)
            | u128::from(tail >> 32);
        let [_, _, _, _, _, _, b0, b1, b2, b3, b4, b5, b6, b7, b8, b9] = field.to_be_bytes();
        Ok(::uuid::Builder::from_unix_timestamp_millis(
            ms,
            &[b0, b1, b2, b3, b4, b5, b6, b7, b8, b9],
        )
        .into_uuid())
    }
}

impl Default for V7Clock {
    fn default() -> Self {
        Self::new()
    }
}

/// The wall clock in Unix milliseconds, or `None` when it cannot be read.
#[cfg(not(all(target_arch = "wasm32", feature = "wasm-client")))]
fn now_millis() -> Option<u64> {
    // A bare `wasm32-unknown-unknown` build has no clock: `SystemTime::now`
    // traps there, so the read is refused instead.
    if cfg!(all(target_arch = "wasm32", target_os = "unknown")) {
        return None;
    }
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    u64::try_from(since_epoch.as_millis()).ok()
}

/// The browser clock (`Date.now()`) in Unix milliseconds, or `None`.
///
/// A negative, non-finite or inexact reading is refused.
#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
fn now_millis() -> Option<u64> {
    millis_from_f64(js_sys::Date::now())
}

/// The whole milliseconds in `t`, exact, or `None`.
///
/// `None` when `t` is negative, non-finite or at least `2^53`, where an `f64`
/// no longer holds every integer.
#[cfg_attr(
    not(all(target_arch = "wasm32", feature = "wasm-client")),
    allow(dead_code)
)]
fn millis_from_f64(t: f64) -> Option<u64> {
    const MANTISSA_BITS: u64 = 52;
    const EXPONENT_BIAS: u64 = 1023;
    if !t.is_finite() || t < 0.0 {
        return None;
    }
    let bits = t.trunc().to_bits();
    let biased = (bits >> MANTISSA_BITS) & 0x7ff;
    if biased == 0 {
        return Some(0);
    }
    let exponent = biased.checked_sub(EXPONENT_BIAS)?;
    let shift = MANTISSA_BITS.checked_sub(exponent)?;
    let mantissa = (bits & ((1 << MANTISSA_BITS) - 1)) | (1 << MANTISSA_BITS);
    mantissa.checked_shr(u32::try_from(shift).ok()?)
}

/// Ipe.Uuid.parse : String -> Maybe String  (canonicalise or Nothing)
///
/// PURE: no entropy, no effect — a real parser over an existing string. Kept off
/// the Task tier deliberately (it is not the arity-0 entropy artifact).
#[must_use]
pub fn uuid_parse(s: String) -> IpeMaybe<String> {
    match ::uuid::Uuid::parse_str(&s) {
        Ok(u) => IpeMaybe::Just(u.to_string()),
        Err(_) => IpeMaybe::Nothing,
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::{IpeError, IpeErrorKind};

    /// Run one entropy Task to completion, keeping the Ok payload.
    async fn run(task: IpeTask<String, String>) -> Option<String> {
        match task.await {
            IpeResult::Ok(v) => Some(v),
            IpeResult::Err(_) => None,
        }
    }

    /// The Unix-millisecond timestamp a v7 id carries.
    fn millis_of(id: ::uuid::Uuid) -> u64 {
        let [a, b, c, d, e, f, ..] = *id.as_bytes();
        u64::from_be_bytes([0, 0, a, b, c, d, e, f])
    }

    /// A clock whose last id carried `last_ms` and `counter`.
    fn clock_at(last_ms: u64, counter: u64) -> V7Clock {
        V7Clock {
            state: Mutex::new(V7State { last_ms, counter }),
        }
    }

    fn is_unavailable(r: &IpeResult<IpeError, String>) -> bool {
        matches!(
            r,
            IpeResult::Err(IpeError::Error(IpeErrorKind::Unavailable, _))
        )
    }

    #[tokio::test]
    async fn v4_shape_and_parse() {
        let id = run(uuid_v4(())).await;
        assert!(id.is_some(), "the test host's CSPRNG yields entropy");
        let Some(id) = id else { return };
        assert_eq!(id.len(), 36); // 8-4-4-4-12
        assert_eq!(id.get(14..15), Some("4"), "v4 version nibble");
        assert!(matches!(uuid_parse(id), IpeMaybe::Just(_)));
        assert!(matches!(
            uuid_parse("not-a-uuid".to_string()),
            IpeMaybe::Nothing
        ));
    }

    /// SOUNDNESS: two runs of a `Uuid.v4` Task yield DISTINCT ids. Entropy is an
    /// effect, not a memoizable pure value — if `v4` were typed `String` the
    /// optimizer could collapse two references into one shared value.
    #[tokio::test]
    async fn v4_two_runs_differ() {
        let a = run(uuid_v4(())).await;
        let b = run(uuid_v4(())).await;
        assert!(a.is_some(), "the test host's CSPRNG yields entropy");
        assert_ne!(a, b, "two Uuid.v4 runs must produce different ids");
    }

    #[tokio::test]
    async fn v7_is_valid_and_fresh() {
        let a = run(uuid_v7(())).await;
        let b = run(uuid_v7(())).await;
        assert!(a.is_some(), "the test host's CSPRNG and clock are readable");
        let Some(a) = a else { return };
        assert_eq!(a.get(14..15), Some("7"), "v7 version nibble");
        assert!(matches!(uuid_parse(a.clone()), IpeMaybe::Just(_)));
        assert_ne!(Some(a), b, "two Uuid.v7 runs must produce different ids");
    }

    /// A v4 mint on a host without entropy fails with kind `Unavailable`.
    #[test]
    fn v4_refuses_without_entropy() {
        let refused: IpeResult<IpeError, String> = v4_with(|_| Err(EntropyError));
        assert!(is_unavailable(&refused), "{refused:?}");
    }

    /// A refused draw leaves the generator unchanged: the next id at the same
    /// millisecond still sorts after the previous one.
    #[test]
    fn v7_refusal_leaves_state() {
        let clock = V7Clock::new();
        let first = clock.next(1_000, [0xff; 16]);
        let refused: IpeResult<IpeError, String> =
            v7_with(&clock, || Some(1_000), |_| Err(EntropyError));
        assert!(is_unavailable(&refused), "{refused:?}");
        let second = clock.next(1_000, [0; 16]);
        assert!(first.is_ok() && second.is_ok());
        assert!(
            second.ok() > first.ok(),
            "the counter continues after a refusal"
        );
    }

    /// Ids minted within one millisecond are strictly increasing.
    #[test]
    fn v7_same_ms_strictly_increasing() {
        let clock = V7Clock::new();
        let mut previous = None;
        for i in 0..1_000_u16 {
            let [hi, lo] = i.to_be_bytes();
            let draw = [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, hi, lo,
            ];
            let id = clock.next(5_000, draw);
            assert!(id.is_ok());
            let Ok(id) = id else { return };
            assert_eq!(millis_of(id), 5_000);
            assert!(previous < Some(id), "id {i} sorts after its predecessor");
            previous = Some(id);
        }
    }

    /// A counter overflow advances the timestamp by one and reseeds, still
    /// ascending.
    #[test]
    fn v7_counter_overflow_advances_ms() {
        let clock = clock_at(7_000, MAX_COUNTER - 1);
        let last = clock.next(7_000, [0xff; 16]);
        assert!(last.is_ok_and(|id| millis_of(id) == 7_000));
        let next = clock.next(7_000, [0xff; 16]);
        assert!(next.is_ok_and(|id| millis_of(id) == 7_001));
        assert!(
            next.ok() > last.ok(),
            "the overflowed id sorts after the last one"
        );
    }

    /// A clock that steps backwards keeps the last timestamp and order.
    #[test]
    fn v7_clock_backwards_keeps_order() {
        let clock = V7Clock::new();
        let later = clock.next(9_000, [0x11; 16]);
        let earlier = clock.next(8_000, [0x11; 16]);
        assert!(later.is_ok());
        assert!(earlier.is_ok_and(|id| millis_of(id) == 9_000));
        assert!(
            earlier.ok() > later.ok(),
            "a backwards clock never reorders ids"
        );
    }

    /// A timestamp past 48 bits is refused, never truncated; the last legal
    /// one is accepted.
    #[test]
    fn v7_refuses_past_48_bits() {
        assert_eq!(
            V7Clock::new().next(1 << 48, [0; 16]),
            Err(V7Refusal::ClockOutsideRange)
        );
        let edge = V7Clock::new().next(MAX_TIMESTAMP_MS, [0; 16]);
        assert!(edge.is_ok_and(|id| millis_of(id) == MAX_TIMESTAMP_MS));
        let overflowing = clock_at(MAX_TIMESTAMP_MS, MAX_COUNTER);
        assert_eq!(
            overflowing.next(MAX_TIMESTAMP_MS, [0; 16]),
            Err(V7Refusal::ClockOutsideRange)
        );
        let refused: IpeResult<IpeError, String> =
            v7_with(&V7Clock::new(), || Some(1 << 48), |_| Ok(()));
        assert!(is_unavailable(&refused), "{refused:?}");
    }

    /// The browser clock's reading converts exactly, and an unusable one is
    /// refused.
    #[test]
    fn millis_from_f64_is_exact_and_checked() {
        assert_eq!(millis_from_f64(0.0), Some(0));
        assert_eq!(millis_from_f64(0.75), Some(0));
        assert_eq!(millis_from_f64(1.0), Some(1));
        assert_eq!(
            millis_from_f64(1_700_000_000_123.9),
            Some(1_700_000_000_123)
        );
        assert_eq!(
            millis_from_f64(9_007_199_254_740_991.0),
            Some(9_007_199_254_740_991)
        );
        assert_eq!(millis_from_f64(9_007_199_254_740_992.0), None);
        assert_eq!(millis_from_f64(-1.0), None);
        assert_eq!(millis_from_f64(f64::NAN), None);
        assert_eq!(millis_from_f64(f64::INFINITY), None);
    }
}
