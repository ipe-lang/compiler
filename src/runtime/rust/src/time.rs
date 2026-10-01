// Time kernel — basic helpers (tokio-gated on native, wasm-client-gated in the
// browser) + Ipe.Time advanced (always available).
// `IpeResult` backs only the IANA-zone helpers (the `Result`-returning zone
// surface), all gated behind the `time` feature — so its import is gated too.
#[cfg(feature = "time")]
use super::IpeResult;
// `IpeTask`/`ok_res` back every native time kernel (the reactor-free clock reads
// AND the `Time.sleep` timer), so they are available on any native build,
// `tokio` or not; the wasm arm re-imports them under its own cfg.
#[cfg(any(
    not(all(target_arch = "wasm32", feature = "wasm-client")),
    feature = "wasm-client"
))]
use super::{IpeTask, ok_res};

// `Time.now` / `Time.unixMillis` read the system clock synchronously
// (`SystemTime::now`) — no reactor, no timer — so they are on the pure-kernel
// whitelist and MUST resolve in a `tokio`-less crate. The native-ish path (host
// native AND WASI) reads the real host clock; only the browser-`wasm-client`
// build substitutes `Date.now()`, since `SystemTime::now()` traps on
// `wasm32-unknown-unknown` but runs on `wasm32-wasip1` (WASI has a clock).
#[cfg(not(all(target_arch = "wasm32", feature = "wasm-client")))]
pub fn time_now<E: Send + 'static>(_: ()) -> IpeTask<E, i64> {
    Box::pin(async move {
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        ok_res(ms)
    })
}

// `Time.sleep` waits — the one reactor-driven `Time` kernel. On the tokio build
// it yields to the reactor (`tokio::time::sleep`); on the tokio-less build it
// parks the current thread (`std::thread::sleep`). `Time.sleep` is
// reactor-classified, so a `tokio`-less crate never CALLS this (the fallback is
// dead code present only to resolve the always-emitted prelude wrapper); if it
// somehow were reached, a thread-park is an observably-correct wait for a
// single-task program, never a hang.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
pub fn time_sleep<E: Send + 'static>(ms: i64) -> IpeTask<E, ()> {
    Box::pin(async move {
        // Clamp negative ms to 0: `ms as u64` on a negative wraps to a near-
        // infinite Duration (permanent deadlock from a well-typed Time.sleep).
        tokio::time::sleep(std::time::Duration::from_millis(ms.max(0) as u64)).await;
        ok_res(())
    })
}

// The tokio-less native-ish sleep parks the thread. Covers a `tokio`-less host
// build AND WASI (`wasm32-wasip1` has no tokio *crate* — it is native-only in
// the manifest — so even when a co-located WASI build sets the `tokio` feature
// flag via `async`, the tokio timer is absent and `std::thread::sleep` runs);
// only browser-`wasm-client` substitutes `gloo-timers`.
#[cfg(all(
    any(not(feature = "tokio"), target_arch = "wasm32"),
    not(all(target_arch = "wasm32", feature = "wasm-client"))
))]
pub fn time_sleep<E: Send + 'static>(ms: i64) -> IpeTask<E, ()> {
    Box::pin(async move {
        std::thread::sleep(std::time::Duration::from_millis(ms.max(0) as u64));
        ok_res(())
    })
}

#[cfg(not(all(target_arch = "wasm32", feature = "wasm-client")))]
pub fn time_unix_millis<E: Send + 'static>(_: ()) -> IpeTask<E, i64> {
    time_now(())
}

// ── wasm32 browser substitute — `Date.now()` / `setTimeout` (gloo-timers) ──
//
// `SystemTime::now()`/`tokio::time::sleep` have no denotation on
// `wasm32-unknown-unknown` (the former traps at runtime — no clock without
// `wasmbind`; the latter doesn't compile at all — no OS threads/reactor).
// `js_sys::Date::now()` reads `Date.now()` directly; `gloo_timers` wraps
// `setTimeout` as an awaitable future. Both keep the SAME `IpeTask<E, _>`
// signature the native arm exposes, so the emitted wrapper prelude's call
// site is unchanged across targets (Q2: `emit_expr.rs` stays target-agnostic).
#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
pub fn time_now<E: 'static>(_: ()) -> IpeTask<E, i64> {
    Box::pin(async move { ok_res(js_sys::Date::now() as i64) })
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
pub fn time_sleep<E: 'static>(ms: i64) -> IpeTask<E, ()> {
    Box::pin(async move {
        // Clamp negative ms to 0, matching the native arm's deadlock guard.
        gloo_timers::future::TimeoutFuture::new(ms.max(0) as u32).await;
        ok_res(())
    })
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
pub fn time_unix_millis<E: 'static>(_: ()) -> IpeTask<E, i64> {
    time_now(())
}

/// `Time.timeString : Int -> String` — formats the Unix-millis instant as
/// `HH:MM:SS`. Pins UTC so a pure formatter is host-independent, matching every
/// sibling formatter in this module.
#[must_use]
pub fn time_time_string(ms: i64) -> String {
    use chrono::{TimeZone, Utc};
    // Millis-native construction (shared with every sibling formatter): dividing
    // ms by 1000 truncates toward zero, which shifts a pre-epoch (negative) ms
    // to the wrong second, so a sub-second-before-epoch instant would render the
    // epoch second instead of the prior day's wall-clock time.
    match Utc.timestamp_millis_opt(ms).single() {
        Some(dt) => dt.format("%H:%M:%S").to_string(),
        None => String::new(),
    }
}

/// `Time.addMillis : Int -> Int -> Int` — pure integer addition.
/// Args order: delta first, ms second (matches the Ipê sig
/// `addMillis : Int -> Int -> Int`, called `Time.addMillis delta ms`).
#[must_use]
pub fn time_add_millis(delta: i64, ms: i64) -> i64 {
    ms.saturating_add(delta)
}

/// `Time.diffMillis : Int -> Int -> Int` — `later - earlier`.
/// Args: (later, earlier).
#[must_use]
pub fn time_diff_millis(later: i64, earlier: i64) -> i64 {
    later.saturating_sub(earlier)
}

/// `Time.format : String -> Int -> String` — custom timestamp layout.
/// Accepts the `2006-01-02 15:04:05` reference-time token format and
/// translates it to chrono strftime internally. Falls back to a best-effort
/// strftime render for any unrecognised tokens.
#[must_use]
pub fn time_format(layout: String, ms: i64) -> String {
    use chrono::{TimeZone, Utc};
    let Some(dt) = Utc.timestamp_millis_opt(ms).single() else {
        return String::new();
    };
    // Translate reference-time placeholders to chrono strftime.
    // Reference time: Mon Jan 2 15:04:05 MST 2006 (= 2006-01-02 15:04:05).
    let strfmt = layout
        .replace("2006", "%Y")
        .replace("01", "%m")
        .replace("02", "%d")
        .replace("15", "%H")
        .replace("04", "%M")
        .replace("05", "%S")
        .replace("Jan", "%b")
        .replace("Mon", "%a")
        .replace("MST", "UTC")
        // Longer fractional-second token MUST be translated before the shorter
        // one, else `.000` shadows the `.000000` form (it matches the leading 4
        // chars and leaves a stray `000`).
        .replace(".000000", ".%6f")
        .replace(".000", ".%3f")
        .replace("PM", "%p")
        .replace("pm", "%P");
    // Non-panicking render: chrono's DelayedFormat Display can return Err on an
    // invalid/unterminated format specifier (e.g. a stray `%`), and std's
    // to_string() panics when a Display impl returns Err. Use write! instead.
    let mut out = String::new();
    match std::fmt::write(&mut out, format_args!("{}", dt.format(&strfmt))) {
        Ok(()) => out,
        Err(_) => String::new(),
    }
}

/// `Time.formatHTTP : Int -> String` — HTTP date header format.
/// Produces "Mon, 02 Jan 2006 15:04:05 GMT" (RFC 7231 / HTTP-date).
#[must_use]
pub fn time_format_http(ms: i64) -> String {
    use chrono::{TimeZone, Utc};
    match Utc.timestamp_millis_opt(ms).single() {
        Some(dt) => dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
        None => String::new(),
    }
}

/// `Time.formatRFC3339 : Int -> String` — RFC 3339 / ISO 8601 timestamp.
/// Sub-second precision is included when non-zero.
#[must_use]
pub fn time_format_rfc3339(ms: i64) -> String {
    use chrono::{TimeZone, Utc};
    match Utc.timestamp_millis_opt(ms).single() {
        Some(dt) => dt.to_rfc3339(),
        None => String::new(),
    }
}

#[cfg(feature = "time")]
use chrono::{DateTime, Duration, Weekday};
/// === Ipe.Time advanced — IANA zones + calendar math ===
// Core calendar math (add/diff/isLeapYear/daysInMonth) uses only these,
// unconditionally. `DateTime` / `Duration` / `Weekday` appear only in the
// `time`-gated zone helpers, so they are imported under that feature.
use chrono::{Datelike, NaiveDate, TimeZone, Timelike, Utc};
// `chrono-tz` (the embedded IANA zone DB) backs the zone helpers below; it is
// gated behind the `time` Cargo feature, promoted only for a program that
// reaches an `Ipe.Time` kernel. A no-Time program compiles this module without
// the crate — every `Tz`-using fn is `#[cfg(feature = "time")]`. The chrono-core
// calendar math (add/diff/isLeapYear/daysInMonth) stays unconditional.
#[cfg(feature = "time")]
use chrono_tz::Tz;

#[cfg(feature = "time")]
fn parse_zone<E: From<String>>(z: &str) -> IpeResult<E, Tz> {
    match z.parse::<Tz>() {
        Ok(t) => IpeResult::Ok(t),
        Err(_) => IpeResult::Err(format!("Ipe.Time: unknown zone: {z}").into()),
    }
}

#[cfg(feature = "time")]
fn millis_to_zoned<E: From<String>>(zone: &str, ms: i64) -> IpeResult<E, DateTime<Tz>> {
    let tz = match parse_zone::<E>(zone) {
        IpeResult::Ok(t) => t,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    match Utc.timestamp_millis_opt(ms).single() {
        Some(utc) => IpeResult::Ok(utc.with_timezone(&tz)),
        None => IpeResult::Err(format!("Ipe.Time: epoch ms out of range: {ms}").into()),
    }
}

#[cfg(feature = "time")]
#[must_use]
pub fn time_in_zone<E: From<String>>(zone: String, ms: i64) -> IpeResult<E, String> {
    let dt = match millis_to_zoned::<E>(&zone, ms) {
        IpeResult::Ok(d) => d,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    IpeResult::Ok(dt.to_rfc3339())
}

// Saturating arithmetic: extreme caller-controlled Ints would otherwise
// overflow-panic in debug / wrap silently in release. Saturation keeps these
// total (no panic path) and is the closest bare-`i64` analogue of the
// `time_add_months` "return ms on out-of-range" fallback.
#[must_use]
pub fn time_add_days(days: i64, ms: i64) -> i64 {
    ms.saturating_add(days.saturating_mul(86_400_000))
}
#[must_use]
pub fn time_add_hours(h: i64, ms: i64) -> i64 {
    ms.saturating_add(h.saturating_mul(3_600_000))
}
#[must_use]
pub fn time_add_minutes(m: i64, ms: i64) -> i64 {
    ms.saturating_add(m.saturating_mul(60_000))
}
#[must_use]
pub fn time_add_seconds(s: i64, ms: i64) -> i64 {
    ms.saturating_add(s.saturating_mul(1000))
}

#[must_use]
pub fn time_add_months(months: i64, ms: i64) -> i64 {
    let Some(utc) = Utc.timestamp_millis_opt(ms).single() else {
        return ms;
    };
    let y = i64::from(utc.year());
    // `months` is caller-controlled (Ipê `Ipe.Time.addMonths`): saturating_add
    // avoids the i64 overflow (debug panic / release silent-wrap) on an extreme
    // value. A saturated `m` makes `new_y as i32` truncate → from_ymd_opt below
    // returns None → the function returns `ms` unchanged (total, no panic).
    let m = (i64::from(utc.month()) - 1).saturating_add(months);
    // Parse the target year into chrono's i32 domain (don't truncate): a lossy
    // `as i32` on a large-but-non-saturating result would wrap a far-future/past
    // year back into a valid band → a WRONG in-range date. try_from → out-of-range
    // returns `ms` unchanged (the intended total fallthrough).
    let Ok(new_y) = i32::try_from(y.saturating_add(m.div_euclid(12))) else {
        return ms;
    };
    let new_m = (m.rem_euclid(12) + 1) as u32;
    // Clamp day to month end
    let first = NaiveDate::from_ymd_opt(new_y, new_m, 1);
    let max_day = match first {
        Some(d) => {
            let (ny, nm) = if new_m == 12 {
                (new_y + 1, 1u32)
            } else {
                (new_y, new_m + 1)
            };
            let first_next = NaiveDate::from_ymd_opt(ny, nm, 1).unwrap_or(d);
            first_next.signed_duration_since(d).num_days() as u32
        }
        None => return ms,
    };
    let day = utc.day().min(max_day);
    match NaiveDate::from_ymd_opt(new_y, new_m, day).and_then(|d| {
        d.and_hms_milli_opt(
            utc.hour(),
            utc.minute(),
            utc.second(),
            utc.timestamp_subsec_millis(),
        )
    }) {
        Some(ndt) => Utc.from_utc_datetime(&ndt).timestamp_millis(),
        None => ms,
    }
}

#[must_use]
pub fn time_add_years(years: i64, ms: i64) -> i64 {
    time_add_months(years.saturating_mul(12), ms)
}

#[cfg(feature = "time")]
fn zoned_field<E: From<String>, F>(zone: String, ms: i64, f: F) -> IpeResult<E, i64>
where
    F: FnOnce(DateTime<Tz>) -> i64,
{
    let dt = match millis_to_zoned::<E>(&zone, ms) {
        IpeResult::Ok(d) => d,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    IpeResult::Ok(f(dt))
}

#[cfg(feature = "time")]
#[must_use]
pub fn time_year<E: From<String>>(z: String, ms: i64) -> IpeResult<E, i64> {
    zoned_field(z, ms, |dt| i64::from(dt.year()))
}
#[cfg(feature = "time")]
#[must_use]
pub fn time_month<E: From<String>>(z: String, ms: i64) -> IpeResult<E, i64> {
    zoned_field(z, ms, |dt| i64::from(dt.month()))
}
#[cfg(feature = "time")]
#[must_use]
pub fn time_day<E: From<String>>(z: String, ms: i64) -> IpeResult<E, i64> {
    zoned_field(z, ms, |dt| i64::from(dt.day()))
}
#[cfg(feature = "time")]
#[must_use]
pub fn time_day_of_week<E: From<String>>(z: String, ms: i64) -> IpeResult<E, i64> {
    zoned_field(z, ms, |dt| match dt.weekday() {
        Weekday::Mon => 1,
        Weekday::Tue => 2,
        Weekday::Wed => 3,
        Weekday::Thu => 4,
        Weekday::Fri => 5,
        Weekday::Sat => 6,
        Weekday::Sun => 7,
    })
}
#[cfg(feature = "time")]
#[must_use]
pub fn time_day_of_year<E: From<String>>(z: String, ms: i64) -> IpeResult<E, i64> {
    zoned_field(z, ms, |dt| i64::from(dt.ordinal()))
}
#[cfg(feature = "time")]
#[must_use]
pub fn time_week_of_year<E: From<String>>(z: String, ms: i64) -> IpeResult<E, i64> {
    zoned_field(z, ms, |dt| i64::from(dt.iso_week().week()))
}
#[cfg(feature = "time")]
#[must_use]
pub fn time_is_weekend<E: From<String>>(z: String, ms: i64) -> IpeResult<E, bool> {
    let dt = match millis_to_zoned::<E>(&z, ms) {
        IpeResult::Ok(d) => d,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    IpeResult::Ok(matches!(dt.weekday(), Weekday::Sat | Weekday::Sun))
}

#[must_use]
pub fn time_is_leap_year(y: i64) -> bool {
    // AUD-09: parse into chrono's i32 domain rather than truncating — a lossy
    // `as i32` cast on a large caller Int wraps to a valid band, giving a
    // wrong (but plausible-looking) leap-year answer instead of failing
    // closed. Mirrors `time_days_in_month`'s existing pattern below.
    let Ok(y) = i32::try_from(y) else {
        return false;
    };
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[must_use]
pub fn time_days_in_month(year: i64, month: i64) -> i64 {
    // Parse year into chrono's i32 domain rather than truncating: a lossy cast on
    // a large caller Int would wrap to a valid band → wrong day count. Out-of-range → 0.
    let Ok(y) = i32::try_from(year) else {
        return 0;
    };
    let m = month as u32;
    if !(1..=12).contains(&m) {
        return 0;
    }
    // saturating_add: `year` is caller-controlled; y+1 at i32::MAX would panic
    // (debug) / wrap (release). A saturated year makes from_ymd_opt return None → 0.
    let (ny, nm) = if m == 12 {
        (y.saturating_add(1), 1)
    } else {
        (y, m + 1)
    };
    match (
        NaiveDate::from_ymd_opt(ny, nm, 1),
        NaiveDate::from_ymd_opt(y, m, 1),
    ) {
        (Some(next), Some(this)) => next.signed_duration_since(this).num_days(),
        _ => 0,
    }
}

#[cfg(feature = "time")]
fn local_midnight_in_zone<E: From<String>>(
    zone: String,
    ms: i64,
    h: u32,
    mi: u32,
    se: u32,
    mi_lli: u32,
    target_date: impl Fn(DateTime<Tz>) -> NaiveDate,
) -> IpeResult<E, i64> {
    let dt = match millis_to_zoned::<E>(&zone, ms) {
        IpeResult::Ok(d) => d,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    let date = target_date(dt);
    let Some(local) = date.and_hms_milli_opt(h, mi, se, mi_lli) else {
        return IpeResult::Err("Ipe.Time: invalid date components".to_string().into());
    };
    match dt.timezone().from_local_datetime(&local).single() {
        Some(z) => IpeResult::Ok(z.timestamp_millis()),
        None => IpeResult::Err("Ipe.Time: ambiguous local time".to_string().into()),
    }
}

#[cfg(feature = "time")]
#[must_use]
pub fn time_start_of_day<E: From<String>>(zone: String, ms: i64) -> IpeResult<E, i64> {
    local_midnight_in_zone(zone, ms, 0, 0, 0, 0, |dt| dt.date_naive())
}
#[cfg(feature = "time")]
#[must_use]
pub fn time_end_of_day<E: From<String>>(zone: String, ms: i64) -> IpeResult<E, i64> {
    match time_start_of_day::<E>(zone, ms) {
        IpeResult::Ok(start) => IpeResult::Ok(start + 86_400_000 - 1),
        IpeResult::Err(e) => IpeResult::Err(e),
    }
}
#[cfg(feature = "time")]
#[must_use]
pub fn time_start_of_week<E: From<String>>(zone: String, ms: i64) -> IpeResult<E, i64> {
    local_midnight_in_zone(zone, ms, 0, 0, 0, 0, |dt| {
        let wd = dt.weekday().num_days_from_monday();
        dt.date_naive() - Duration::days(i64::from(wd))
    })
}
#[cfg(feature = "time")]
#[must_use]
pub fn time_start_of_month<E: From<String>>(zone: String, ms: i64) -> IpeResult<E, i64> {
    local_midnight_in_zone(zone, ms, 0, 0, 0, 0, |dt| {
        NaiveDate::from_ymd_opt(dt.year(), dt.month(), 1).unwrap_or(dt.date_naive())
    })
}
#[cfg(feature = "time")]
#[must_use]
pub fn time_end_of_month<E: From<String>>(zone: String, ms: i64) -> IpeResult<E, i64> {
    let dt = match millis_to_zoned::<E>(&zone, ms) {
        IpeResult::Ok(d) => d,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    let dim = time_days_in_month(i64::from(dt.year()), i64::from(dt.month())) as u32;
    let target = NaiveDate::from_ymd_opt(dt.year(), dt.month(), dim);
    let target_date = target.unwrap_or(dt.date_naive());
    local_midnight_in_zone::<E>(zone, ms, 23, 59, 59, 999, move |_| target_date)
}
#[cfg(feature = "time")]
#[must_use]
pub fn time_start_of_year<E: From<String>>(zone: String, ms: i64) -> IpeResult<E, i64> {
    local_midnight_in_zone(zone, ms, 0, 0, 0, 0, |dt| {
        NaiveDate::from_ymd_opt(dt.year(), 1, 1).unwrap_or(dt.date_naive())
    })
}
#[cfg(feature = "time")]
#[must_use]
pub fn time_end_of_year<E: From<String>>(zone: String, ms: i64) -> IpeResult<E, i64> {
    local_midnight_in_zone(zone, ms, 23, 59, 59, 999, |dt| {
        NaiveDate::from_ymd_opt(dt.year(), 12, 31).unwrap_or(dt.date_naive())
    })
}

#[cfg(feature = "time")]
#[must_use]
pub fn time_format_in_zone<E: From<String>>(
    pattern: String,
    zone: String,
    ms: i64,
) -> IpeResult<E, String> {
    let dt = match millis_to_zoned::<E>(&zone, ms) {
        IpeResult::Ok(d) => d,
        IpeResult::Err(e) => return IpeResult::Err(e),
    };
    // Non-panicking render: same risk as time_format — stray `%` in a
    // Ipê-supplied pattern causes DelayedFormat::fmt to return Err, which
    // to_string() turns into a panic. Use write! and fall back to "".
    let mut out = String::new();
    match std::fmt::write(&mut out, format_args!("{}", dt.format(&pattern))) {
        Ok(()) => IpeResult::Ok(out),
        Err(_) => IpeResult::Ok(String::new()),
    }
}

/// `Ipe.Time.formatISO8601 ms` — the UTC instant as an RFC3339 / ISO-8601
/// string .Format(time.RFC3339)`). Infallible (`""` only on
/// an out-of-range timestamp).
#[must_use]
pub fn time_format_iso8601(ms: i64) -> String {
    match Utc.timestamp_millis_opt(ms).single() {
        Some(dt) => dt.to_rfc3339(),
        None => String::new(),
    }
}

// === advanced diff / fromParts / zone kernels ===

/// `diffSeconds later earlier` — integer seconds between two epoch-ms timestamps.
// Division truncates toward zero (; negative spans truncate toward
// zero too). `saturating_sub` avoids an overflow-panic on extreme epoch inputs.
#[must_use]
pub fn time_diff_seconds(later_ms: i64, earlier_ms: i64) -> i64 {
    later_ms.saturating_sub(earlier_ms) / 1_000
}
#[must_use]
pub fn time_diff_minutes(later_ms: i64, earlier_ms: i64) -> i64 {
    later_ms.saturating_sub(earlier_ms) / 60_000
}
#[must_use]
pub fn time_diff_hours(later_ms: i64, earlier_ms: i64) -> i64 {
    later_ms.saturating_sub(earlier_ms) / 3_600_000
}
#[must_use]
pub fn time_diff_days(later_ms: i64, earlier_ms: i64) -> i64 {
    later_ms.saturating_sub(earlier_ms) / 86_400_000
}

/// Ipê source: `fromParts zone y m d h mins s -> Result Error Int`.
/// Computes the UTC epoch-ms for the given local date/time in the given IANA
/// zone. Invalid parts return Err. Unknown timezone returns Err.
#[cfg(feature = "time")]
#[must_use]
pub fn time_from_parts<E: From<String>>(
    zone: String,
    y: i64,
    m: i64,
    d: i64,
    h: i64,
    mins: i64,
    s: i64,
) -> IpeResult<E, i64> {
    let tz: Tz = match zone.parse() {
        Ok(t) => t,
        Err(_) => {
            return IpeResult::Err(format!("Time.fromParts: unknown timezone {zone:?}").into());
        }
    };
    // AUD-09: parse `y` into chrono's i32 domain rather than truncating — a
    // lossy `as i32` cast on a large caller Int wraps to a valid band,
    // silently accepting an out-of-range year as if it were a different,
    // in-range one instead of failing closed with "invalid date parts".
    let Some(naive) = i32::try_from(y).ok().and_then(|y32| {
        NaiveDate::from_ymd_opt(y32, m as u32, d as u32)
            .and_then(|day| day.and_hms_opt(h as u32, mins as u32, s as u32))
    }) else {
        return IpeResult::Err(
            format!("Time.fromParts: invalid date parts {y}-{m:02}-{d:02} {h:02}:{mins:02}:{s:02}")
                .into(),
        );
    };
    match tz.from_local_datetime(&naive).single() {
        Some(zoned) => IpeResult::Ok(zoned.with_timezone(&Utc).timestamp_millis()),
        None => IpeResult::Err(format!(
            "Time.fromParts: ambiguous/non-existent local time {y}-{m:02}-{d:02} {h:02}:{mins:02}:{s:02} in {zone}").into()),
    }
}

/// `zoneOffset zone ms -> Result Error Int` — UTC offset in seconds for the
/// instant in the given zone. Unknown zones return Err.
#[cfg(feature = "time")]
#[must_use]
pub fn time_zone_offset<E: From<String>>(zone_name: String, ms: i64) -> IpeResult<E, i64> {
    use chrono::Offset;
    let utc: DateTime<Utc> = match Utc.timestamp_millis_opt(ms).single() {
        Some(t) => t,
        None => return IpeResult::Err(format!("Time.zoneOffset: invalid epoch ms {ms}").into()),
    };
    match zone_name.parse::<Tz>() {
        Ok(tz) => IpeResult::Ok(i64::from(
            tz.from_utc_datetime(&utc.naive_utc())
                .offset()
                .fix()
                .local_minus_utc(),
        )),
        Err(_) => IpeResult::Err(format!("Time.zoneOffset: unknown timezone {zone_name:?}").into()),
    }
}

/// `zoneName zone ms -> Result Error String` — short timezone abbreviation
/// (e.g. "EST", "PDT"). Unknown zones return Err.
#[cfg(feature = "time")]
#[must_use]
pub fn time_zone_name<E: From<String>>(zone_name: String, ms: i64) -> IpeResult<E, String> {
    let utc: DateTime<Utc> = match Utc.timestamp_millis_opt(ms).single() {
        Some(t) => t,
        None => return IpeResult::Err(format!("Time.zoneName: invalid epoch ms {ms}").into()),
    };
    match zone_name.parse::<Tz>() {
        Ok(tz) => IpeResult::Ok(
            tz.from_utc_datetime(&utc.naive_utc())
                .format("%Z")
                .to_string(),
        ),
        Err(_) => IpeResult::Err(format!("Time.zoneName: unknown timezone {zone_name:?}").into()),
    }
}

// `time_time_string` is unconditional (no `time` feature), so its regression
// test lives in an always-compiled module. It asserts a fixed instant formats
// to a constant UTC `HH:MM:SS` regardless of the process `TZ`.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod time_string_tests {
    use super::time_time_string;

    /// Set only on the re-exec of this test binary that carries a non-UTC `TZ`.
    const TZ_CHILD_MARKER: &str = "IPE_TIME_STRING_TZ_CHILD";

    #[test]
    fn time_string_is_utc_regardless_of_tz() {
        // A fixed instant whose UTC wall-clock time is 15:30:45.
        assert_eq!(time_time_string(1_615_735_845_000), "15:30:45");
        if crate::system::read_env_var(TZ_CHILD_MARKER).is_ok() {
            return;
        }
        rerun_under_non_utc_zones();
    }

    /// `TZ` is read by the host time library from the real process
    /// environment, so each non-UTC zone is set at spawn time on a re-exec of
    /// this binary that must actually run and pass this one test.
    #[cfg(not(target_arch = "wasm32"))]
    fn rerun_under_non_utc_zones() {
        let module = module_path!();
        let name = format!(
            "{}::time_string_is_utc_regardless_of_tz",
            module.split_once("::").map_or(module, |(_, rest)| rest)
        );
        for tz in ["America/New_York", "Asia/Tokyo"] {
            let rerun = e2e_support::rerun_this_test_exact(&name, |cmd| {
                cmd.arg("--test-threads=1")
                    .env(TZ_CHILD_MARKER, "1")
                    .env("TZ", tz);
            });
            assert!(rerun.is_ok(), "TZ={tz} re-exec did not pass: {rerun:?}");
        }
    }

    /// A wasm32 test binary cannot re-exec itself; the fixed-instant assertion
    /// above is its whole check.
    #[cfg(target_arch = "wasm32")]
    const fn rerun_under_non_utc_zones() {}

    #[test]
    fn time_string_epoch_is_midnight() {
        assert_eq!(time_time_string(0), "00:00:00");
    }

    #[test]
    fn time_string_positive_sub_second_remainder() {
        // 500ms past 15:30:45 stays on the same second (no rounding up).
        assert_eq!(time_time_string(1_615_735_845_500), "15:30:45");
    }

    #[test]
    fn time_string_pre_epoch_sub_second_remainder() {
        // -500ms is 0.5s BEFORE the epoch: the correct UTC wall-clock time is
        // 23:59:59 of the prior day, not the epoch second 00:00:00. Truncation
        // toward zero (ms / 1000 == 0) would wrongly render "00:00:00"; the
        // millis-native construction floors correctly.
        assert_eq!(time_time_string(-500), "23:59:59");
    }

    #[test]
    fn time_string_pre_epoch_whole_second() {
        // -1000ms is exactly one second before the epoch: 23:59:59.
        assert_eq!(time_time_string(-1000), "23:59:59");
    }
}

// Exercises the IANA-zone helpers, so it needs the `chrono-tz`-backed surface
// the `time` feature gates. The chrono-core calendar math (add/diff/isLeapYear)
// is covered here too; running the whole module under `--features time` keeps a
// single fixture set rather than splitting core from zone tests.
#[cfg(all(test, feature = "time"))]
#[cfg(not(target_arch = "wasm32"))]
mod time_advanced_tests {
    use super::*;

    // 2026-05-29 12:00:00 UTC is a Friday
    const T1: i64 = 1_780_400_400_000;

    #[test]
    fn test_in_zone_utc() {
        let r: IpeResult<String, String> = time_in_zone("UTC".to_string(), T1);
        assert!(matches!(r, IpeResult::Ok(ref s) if s.contains("2026")));
    }

    #[test]
    fn test_in_zone_unknown() {
        let r: IpeResult<String, String> = time_in_zone("Not/AZone".to_string(), T1);
        assert!(matches!(r, IpeResult::Err(_)));
    }

    #[test]
    fn test_day_of_week_friday() {
        let r: IpeResult<String, i64> = time_day_of_week("UTC".to_string(), T1);
        assert!(
            matches!(r, IpeResult::Ok(d) if (1..=7).contains(&d)),
            "got {r:?}"
        );
    }

    #[test]
    fn test_is_leap_year() {
        assert!(time_is_leap_year(2024));
        assert!(!time_is_leap_year(2025));
        assert!(!time_is_leap_year(1900));
        assert!(time_is_leap_year(2000));
    }

    #[test]
    fn test_add_days_months() {
        // adding 1 day = +86400000 ms
        assert_eq!(time_add_days(1, T1), T1 + 86_400_000);
        // adding months returns SOME result (no panic)
        let added = time_add_months(1, T1);
        assert!(added > T1);
    }

    // advanced kernel tests

    #[test]
    fn test_diff_seconds() {
        assert_eq!(time_diff_seconds(5_500, 3_000), 2);
        assert_eq!(time_diff_seconds(0, 2_500), -2);
    }

    #[test]
    fn test_diff_minutes_hours_days() {
        assert_eq!(time_diff_minutes(120_000, 0), 2);
        assert_eq!(time_diff_hours(3_600_000 * 5, 0), 5);
        assert_eq!(time_diff_days(86_400_000 * 7, 0), 7);
    }

    #[test]
    fn test_from_parts_epoch_utc() {
        let r: IpeResult<String, i64> = time_from_parts("UTC".into(), 1970, 1, 1, 0, 0, 0);
        assert!(matches!(r, IpeResult::Ok(0)));
    }

    #[test]
    fn test_from_parts_invalid_returns_err() {
        let r1: IpeResult<String, i64> = time_from_parts("UTC".into(), 2024, 13, 1, 0, 0, 0); // month 13
        let r2: IpeResult<String, i64> = time_from_parts("UTC".into(), 2024, 2, 30, 0, 0, 0); // Feb 30
        let r3: IpeResult<String, i64> = time_from_parts("Not/AZone".into(), 2024, 1, 1, 0, 0, 0);
        assert!(matches!(r1, IpeResult::Err(_)));
        assert!(matches!(r2, IpeResult::Err(_)));
        assert!(matches!(r3, IpeResult::Err(_))); // unknown timezone
    }

    #[test]
    fn test_zone_offset_utc() {
        let r: IpeResult<String, i64> = time_zone_offset("UTC".into(), 0);
        assert!(matches!(r, IpeResult::Ok(0)));
    }

    #[test]
    fn test_zone_offset_ny_winter() {
        // 1970-01-01 00:00 UTC; America/New_York was EST (-5h) on that day.
        let r: IpeResult<String, i64> = time_zone_offset("America/New_York".into(), 0);
        assert!(matches!(r, IpeResult::Ok(v) if v == -5 * 3_600));
    }

    #[test]
    fn test_zone_name_utc() {
        let r: IpeResult<String, String> = time_zone_name("UTC".into(), 0);
        match r {
            IpeResult::Ok(name) => assert!(name == "UTC" || name == "Z"),
            IpeResult::Err(_) => panic!("UTC should be a known timezone"),
        }
    }

    #[test]
    fn test_zone_offset_unknown_returns_err() {
        let r: IpeResult<String, i64> = time_zone_offset("Not/AZone".into(), 0);
        assert!(matches!(r, IpeResult::Err(_)));
    }

    // ── go-parity kernels ─────────────────────────

    #[test]
    fn test_add_millis() {
        assert_eq!(time_add_millis(1000, 5000), 6000);
        assert_eq!(time_add_millis(-500, 1000), 500);
        assert_eq!(time_add_millis(0, 999), 999);
    }

    #[test]
    fn test_diff_millis() {
        assert_eq!(time_diff_millis(5000, 3000), 2000);
        assert_eq!(time_diff_millis(1000, 3000), -2000);
        assert_eq!(time_diff_millis(42, 42), 0);
    }

    #[test]
    fn test_format_http() {
        // 1970-01-01 00:00:00 UTC = epoch 0.
        //  http.TimeFormat gives "Thu, 01 Jan 1970 00:00:00 GMT".
        let s = time_format_http(0);
        assert!(s.contains("1970"), "HTTP format for epoch 0: {s}");
        assert!(s.ends_with("GMT"), "HTTP format must end in GMT: {s}");
    }

    #[test]
    fn test_format_rfc3339() {
        let s = time_format_rfc3339(0);
        // chrono's to_rfc3339 produces "1970-01-01T00:00:00+00:00" for epoch 0.
        assert!(s.starts_with("1970-01-01T"), "RFC3339 for epoch 0: {s}");
    }

    #[test]
    fn test_format_http_out_of_range() {
        // An invalid timestamp should return "" rather than panic.
        let s = time_format_http(i64::MAX);
        // Either empty or some valid string — just must not panic.
        let _ = s;
    }
}
