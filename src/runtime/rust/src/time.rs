// Time kernel — the clock and sleep (tokio-gated on native, wasm-client-gated
// in the browser) + the Ipe.Time calendar formatters and rules.
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
    Box::pin(async move { ok_res(super::narrow::unix_millis()) })
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
        // Clamp negative ms to 0: a negative reinterpreted as `u64` is a near-
        // infinite Duration (permanent deadlock from a well-typed Time.sleep).
        tokio::time::sleep(std::time::Duration::from_millis(ms.max(0).unsigned_abs())).await;
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
        std::thread::sleep(std::time::Duration::from_millis(ms.max(0).unsigned_abs()));
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
    Box::pin(async move { ok_res(super::narrow::unix_millis()) })
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
pub fn time_sleep<E: 'static>(ms: i64) -> IpeTask<E, ()> {
    Box::pin(async move {
        for chunk in sleep_chunks(ms) {
            gloo_timers::future::TimeoutFuture::new(chunk).await;
        }
        ok_res(())
    })
}

/// The longest single browser timer wait, in milliseconds.
#[cfg(any(
    all(test, not(target_arch = "wasm32")),
    all(target_arch = "wasm32", feature = "wasm-client")
))]
const SLEEP_CHUNK_MS: u32 = super::narrow::BROWSER_TIMER_MAX_MS;

/// Splits a `Time.sleep` of `ms` milliseconds into browser-timer-sized waits.
///
/// The waits sum to `ms.max(0)`, each is at most [`SLEEP_CHUNK_MS`], and there
/// is always at least one (a zero wait still yields to the event loop, as the
/// native arm's zero sleep does). A negative `ms` waits zero, matching the
/// native arm's deadlock guard.
#[cfg(any(
    all(test, not(target_arch = "wasm32")),
    all(target_arch = "wasm32", feature = "wasm-client")
))]
fn sleep_chunks(ms: i64) -> impl Iterator<Item = u32> {
    let mut rest = Some(ms.max(0).unsigned_abs());
    std::iter::from_fn(move || {
        let left = rest?;
        let chunk = u32::try_from(left.min(u64::from(SLEEP_CHUNK_MS))).unwrap_or(SLEEP_CHUNK_MS);
        let after = left.saturating_sub(u64::from(chunk));
        rest = (after > 0).then_some(after);
        Some(chunk)
    })
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
pub fn time_unix_millis<E: 'static>(_: ()) -> IpeTask<E, i64> {
    time_now(())
}

// === Ipe.Time calendar kernels — UTC, proleptic Gregorian ===
//
// Every kernel below returns the exact answer or trips a typed `TimeDomain`
// naming itself: no sentinel `0`, `false`, or `""` stands in for a refusal.
use crate::core::{RuntimeTrip, TimeDomainCause, TimeOp, trip};
use chrono::format::{Fixed, Item, Numeric, Pad};
use chrono::{DateTime, TimeZone, Utc};

/// The UTC calendar instant `ms` names, or a `TimeDomain` trip for `op`.
///
/// The formatters render years `-262143` to `262142` (chrono's calendar); an
/// instant outside them has no rendering.
fn calendar_instant(ms: i64, op: TimeOp) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(ms).single().unwrap_or_else(|| {
        trip(RuntimeTrip::TimeDomain {
            op,
            cause: TimeDomainCause::InstantOutsideCalendar,
        })
    })
}

/// `Time.timeString : Int -> String` — the UTC wall-clock time as `HH:MM:SS`.
///
/// Pinned to UTC, so a pure formatter is host-independent. The millis-native
/// construction floors a pre-epoch sub-second instant to the prior second.
#[must_use]
pub fn time_time_string(ms: i64) -> String {
    calendar_instant(ms, TimeOp::TimeString)
        .format("%H:%M:%S")
        .to_string()
}

/// `Time.addMillis : Int -> Int -> Int` — the exact `Int` sum.
/// Args order: delta first, ms second (matches the Ipê sig
/// `addMillis : Int -> Int -> Int`, called `Time.addMillis delta ms`). A sum
/// outside the 64-bit range trips `IntOverflow`, as `+` does.
#[must_use]
pub fn time_add_millis(delta: i64, ms: i64) -> i64 {
    crate::math::ipe_int_add(ms, delta)
}

/// `Time.diffMillis : Int -> Int -> Int` — the exact `later - earlier`.
/// Args: (later, earlier). A difference outside the 64-bit range trips
/// `IntOverflow`, as `-` does.
#[must_use]
pub fn time_diff_millis(later: i64, earlier: i64) -> i64 {
    crate::math::ipe_int_sub(later, earlier)
}

/// A field of the Go reference time `Mon Jan 2 15:04:05 MST 2006` in a
/// `Time.format` layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayoutToken {
    /// `2006`: the year.
    Year,
    /// `01`: the zero-padded month number.
    Month,
    /// `02`: the zero-padded day of the month.
    Day,
    /// `15`: the zero-padded 24-hour hour.
    Hour,
    /// `04`: the zero-padded minute.
    Minute,
    /// `05`: the zero-padded second.
    Second,
    /// `Jan`: the abbreviated month name.
    MonthName,
    /// `Mon`: the abbreviated weekday name.
    WeekdayName,
    /// `MST`: the zone name, always `UTC`.
    ZoneName,
    /// `.000`: a dot and the milliseconds.
    Millis,
    /// `.000000`: a dot and the microseconds.
    Micros,
    /// `PM`: `AM` or `PM`.
    UpperMeridiem,
    /// `pm`: `am` or `pm`.
    LowerMeridiem,
}

impl LayoutToken {
    /// Every token with its layout spelling.
    const ALL: [(&'static str, Self); 13] = [
        ("2006", Self::Year),
        ("01", Self::Month),
        ("02", Self::Day),
        ("15", Self::Hour),
        ("04", Self::Minute),
        ("05", Self::Second),
        ("Jan", Self::MonthName),
        ("Mon", Self::WeekdayName),
        ("MST", Self::ZoneName),
        (".000", Self::Millis),
        (".000000", Self::Micros),
        ("PM", Self::UpperMeridiem),
        ("pm", Self::LowerMeridiem),
    ];

    /// The longest token spelled at the start of `rest`, with the text after it.
    fn longest_prefix(rest: &str) -> Option<(Self, &str)> {
        Self::ALL
            .into_iter()
            .filter_map(|(spelling, token)| Some((token, rest.strip_prefix(spelling)?)))
            .min_by_key(|(_, after)| after.len())
    }

    /// The chrono item that renders this field.
    const fn item(self) -> Item<'static> {
        match self {
            Self::Year => Item::Numeric(Numeric::Year, Pad::Zero),
            Self::Month => Item::Numeric(Numeric::Month, Pad::Zero),
            Self::Day => Item::Numeric(Numeric::Day, Pad::Zero),
            Self::Hour => Item::Numeric(Numeric::Hour, Pad::Zero),
            Self::Minute => Item::Numeric(Numeric::Minute, Pad::Zero),
            Self::Second => Item::Numeric(Numeric::Second, Pad::Zero),
            Self::MonthName => Item::Fixed(Fixed::ShortMonthName),
            Self::WeekdayName => Item::Fixed(Fixed::ShortWeekdayName),
            Self::ZoneName => Item::Literal("UTC"),
            Self::Millis => Item::Fixed(Fixed::Nanosecond3),
            Self::Micros => Item::Fixed(Fixed::Nanosecond6),
            Self::UpperMeridiem => Item::Fixed(Fixed::UpperAmPm),
            Self::LowerMeridiem => Item::Fixed(Fixed::LowerAmPm),
        }
    }
}

/// One piece of a parsed `Time.format` layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayoutPiece<'a> {
    /// A reference-time field.
    Token(LayoutToken),
    /// Text rendered verbatim, `%` included.
    Literal(&'a str),
}

impl<'a> LayoutPiece<'a> {
    /// The chrono item that renders this piece.
    const fn item(self) -> Item<'a> {
        match self {
            Self::Token(token) => token.item(),
            Self::Literal(text) => Item::Literal(text),
        }
    }
}

/// Parses a `Time.format` layout once, left to right, taking the longest
/// token at each position; every other character is literal text.
fn parse_layout(layout: &str) -> Vec<LayoutPiece<'_>> {
    let mut pieces = Vec::new();
    let mut literal_from = layout;
    let mut rest = layout;
    loop {
        let token = LayoutToken::longest_prefix(rest);
        if (token.is_some() || rest.is_empty())
            && let Some(literal) = literal_from.strip_suffix(rest).filter(|l| !l.is_empty())
        {
            pieces.push(LayoutPiece::Literal(literal));
        }
        if let Some((token, after)) = token {
            pieces.push(LayoutPiece::Token(token));
            rest = after;
            literal_from = rest;
        } else {
            let mut chars = rest.chars();
            if chars.next().is_none() {
                return pieces;
            }
            rest = chars.as_str();
        }
    }
}

/// `Time.format : String -> Int -> String` — the UTC instant in a Go
/// reference-time layout.
///
/// The layout spells fields of `Mon Jan 2 15:04:05 MST 2006`: `2006 01 02 15
/// 04 05 Jan Mon MST .000 .000000 PM pm`. It is parsed into those tokens once,
/// longest match first; every other character, `%` included, is literal.
#[must_use]
pub fn time_format(layout: String, ms: i64) -> String {
    let instant = calendar_instant(ms, TimeOp::Format);
    let items: Vec<Item<'_>> = parse_layout(&layout)
        .into_iter()
        .map(LayoutPiece::item)
        .collect();
    // Every item names a field a UTC `DateTime` carries, so the render is total.
    instant.format_with_items(items.iter()).to_string()
}

/// `Time.formatHTTP : Int -> String` — the HTTP-date (RFC 7231) rendering,
/// `Mon, 02 Jan 2006 15:04:05 GMT`.
#[must_use]
pub fn time_format_http(ms: i64) -> String {
    calendar_instant(ms, TimeOp::FormatHttp)
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

/// `Time.formatRFC3339 : Int -> String` — the RFC 3339 rendering, with
/// sub-second precision when non-zero.
#[must_use]
pub fn time_format_rfc3339(ms: i64) -> String {
    calendar_instant(ms, TimeOp::FormatRfc3339).to_rfc3339()
}

/// `Time.formatISO8601 : Int -> String` — the ISO 8601 rendering of the UTC
/// instant (the RFC 3339 profile).
#[must_use]
pub fn time_format_iso8601(ms: i64) -> String {
    calendar_instant(ms, TimeOp::FormatIso8601).to_rfc3339()
}

/// `Time.isLeapYear : Int -> Bool` — the proleptic Gregorian leap rule, over
/// every `Int` year.
#[must_use]
pub const fn time_is_leap_year(year: i64) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

/// A month of the Gregorian year.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Month {
    /// Month 1.
    January,
    /// Month 2.
    February,
    /// Month 3.
    March,
    /// Month 4.
    April,
    /// Month 5.
    May,
    /// Month 6.
    June,
    /// Month 7.
    July,
    /// Month 8.
    August,
    /// Month 9.
    September,
    /// Month 10.
    October,
    /// Month 11.
    November,
    /// Month 12.
    December,
}

impl Month {
    /// The month numbered `number`, if it is in `1..=12`.
    const fn from_number(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::January),
            2 => Some(Self::February),
            3 => Some(Self::March),
            4 => Some(Self::April),
            5 => Some(Self::May),
            6 => Some(Self::June),
            7 => Some(Self::July),
            8 => Some(Self::August),
            9 => Some(Self::September),
            10 => Some(Self::October),
            11 => Some(Self::November),
            12 => Some(Self::December),
            _ => None,
        }
    }

    /// The month's length in a leap or common year.
    const fn days(self, leap: bool) -> u8 {
        match self {
            Self::February if leap => 29,
            Self::February => 28,
            Self::April | Self::June | Self::September | Self::November => 30,
            Self::January
            | Self::March
            | Self::May
            | Self::July
            | Self::August
            | Self::October
            | Self::December => 31,
        }
    }
}

/// `Time.daysInMonth : Int -> Int -> Int` — the days in `month` of `year`.
///
/// Every `Int` year is a proleptic Gregorian year; a month outside `1..=12`
/// trips `TimeDomain`.
#[must_use]
pub fn time_days_in_month(year: i64, month: i64) -> i64 {
    Month::from_number(month).map_or_else(
        || {
            trip(RuntimeTrip::TimeDomain {
                op: TimeOp::DaysInMonth,
                cause: TimeDomainCause::MonthOutsideYear,
            })
        },
        |month| i64::from(month.days(time_is_leap_year(year))),
    )
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod kernel_tests {
    use super::{
        time_diff_millis, time_format, time_format_http, time_format_iso8601, time_format_rfc3339,
        time_is_leap_year,
    };

    #[test]
    fn test_is_leap_year() {
        assert!(time_is_leap_year(2024));
        assert!(!time_is_leap_year(2025));
        assert!(!time_is_leap_year(1900));
        assert!(time_is_leap_year(2000));
    }

    #[test]
    fn test_add_millis() {
        assert_eq!(super::time_add_millis(1000, 5000), 6000);
        assert_eq!(super::time_add_millis(-500, 1000), 500);
        assert_eq!(super::time_add_millis(0, 999), 999);
    }

    #[test]
    fn test_diff_millis() {
        assert_eq!(time_diff_millis(5000, 3000), 2000);
        assert_eq!(time_diff_millis(1000, 3000), -2000);
        assert_eq!(time_diff_millis(42, 42), 0);
    }

    #[test]
    fn test_format_http() {
        assert_eq!(time_format_http(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn test_format_rfc3339() {
        assert_eq!(time_format_rfc3339(0), "1970-01-01T00:00:00+00:00");
        assert_eq!(time_format_iso8601(1_500), "1970-01-01T00:00:01.500+00:00");
    }

    /// Every reference-time token renders its field of one instant.
    #[test]
    fn every_layout_token_renders_its_field() {
        // 2021-03-14 15:30:45.123 UTC, a Sunday.
        let ms = 1_615_735_845_123;
        assert_eq!(time_format("2006-01-02".to_owned(), ms), "2021-03-14");
        assert_eq!(
            time_format("Mon Jan 02 15:04:05.000 MST 2006".to_owned(), ms),
            "Sun Mar 14 15:30:45.123 UTC 2021"
        );
        assert_eq!(time_format(".000000 PM pm".to_owned(), ms), ".123000 PM pm");
    }
}

// `Time.format` parses its layout once into closed tokens and literal text.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod layout_tests {
    use super::{LayoutPiece, LayoutToken, parse_layout, time_format};

    #[test]
    fn literal_text_is_never_a_token() {
        assert_eq!(
            parse_layout("Monday"),
            [
                LayoutPiece::Token(LayoutToken::WeekdayName),
                LayoutPiece::Literal("day")
            ]
        );
        assert_eq!(parse_layout("%Y"), [LayoutPiece::Literal("%Y")]);
        assert_eq!(parse_layout(""), []);
        // A `%` is literal text, never a strftime directive.
        assert_eq!(time_format("%Y %m".to_owned(), 0), "%Y %m");
        assert_eq!(time_format("at 2006!".to_owned(), 0), "at 1970!");
        // Text a replace chain would rewrite twice renders once.
        assert_eq!(time_format("2006".to_owned(), 0), "1970");
    }

    /// The longer fractional token wins over the shorter at the same position.
    #[test]
    fn the_longest_token_wins() {
        assert_eq!(
            parse_layout("05.000000"),
            [
                LayoutPiece::Token(LayoutToken::Second),
                LayoutPiece::Token(LayoutToken::Micros)
            ]
        );
        assert_eq!(
            parse_layout("é.0000"),
            [
                LayoutPiece::Literal("é"),
                LayoutPiece::Token(LayoutToken::Millis),
                LayoutPiece::Literal("0")
            ]
        );
    }
}

// Every calendar kernel answers exactly or trips a typed `TimeDomain`.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod calendar_tests {
    use super::{
        time_days_in_month, time_format, time_format_http, time_format_iso8601,
        time_format_rfc3339, time_is_leap_year, time_time_string,
    };
    use crate::core::{RuntimeTrip, TimeDomainCause, TimeOp, runtime_trip};
    use chrono::NaiveDate;

    /// The trip `f` raised, or `None` when it returned.
    fn tripped<T>(f: impl FnOnce() -> T + std::panic::UnwindSafe) -> Option<RuntimeTrip> {
        std::panic::catch_unwind(f)
            .err()
            .and_then(|payload| runtime_trip(payload.as_ref()))
    }

    /// Whether `trip` is kernel `op` refusing by `cause`.
    fn is_domain(trip: Option<RuntimeTrip>, op: TimeOp, cause: TimeDomainCause) -> bool {
        trip == Some(RuntimeTrip::TimeDomain { op, cause })
    }

    #[test]
    fn days_in_month_refuses_a_month_outside_the_year() {
        assert_eq!(time_days_in_month(2024, 12), 31);
        assert_eq!(time_days_in_month(2024, 2), 29);
        assert_eq!(time_days_in_month(2023, 2), 28);
        assert_eq!(time_days_in_month(i64::MAX, 4), 30);
        assert_eq!(time_days_in_month(i64::MIN, 2), 29);
        for month in [0, 13, -1, (1 << 32) + 1, i64::MAX, i64::MIN] {
            assert!(
                is_domain(
                    tripped(|| time_days_in_month(2024, month)),
                    TimeOp::DaysInMonth,
                    TimeDomainCause::MonthOutsideYear
                ),
                "month {month}"
            );
        }
    }

    #[test]
    fn leap_rule_holds_past_i32() {
        assert!(time_is_leap_year(4_000_000_000));
        assert!(!time_is_leap_year(4_000_000_100));
        assert!(time_is_leap_year(4_000_000_004));
        assert!(time_is_leap_year(-4));
        assert!(!time_is_leap_year(-100));
        assert!(time_is_leap_year(-400));
        assert!(!time_is_leap_year(i64::MAX));
        assert!(time_is_leap_year(i64::MIN));
    }

    /// A formatter of a Unix-millis instant.
    type Render = fn(i64) -> String;

    /// Each formatter, one per `TimeOp` it raises.
    fn formatters() -> [(TimeOp, Render); 5] {
        [
            (TimeOp::TimeString, time_time_string),
            (TimeOp::Format, |ms| {
                time_format("2006-01-02".to_owned(), ms)
            }),
            (TimeOp::FormatHttp, time_format_http),
            (TimeOp::FormatIso8601, time_format_iso8601),
            (TimeOp::FormatRfc3339, time_format_rfc3339),
        ]
    }

    #[test]
    fn formatters_refuse_an_instant_outside_the_calendar() {
        for (op, render) in formatters() {
            for ms in [i64::MAX, i64::MIN] {
                assert!(
                    is_domain(
                        tripped(|| render(ms)),
                        op,
                        TimeDomainCause::InstantOutsideCalendar
                    ),
                    "{op:?} at {ms}"
                );
            }
        }
    }

    /// The first and last calendar milliseconds render; one step past either
    /// trips.
    #[test]
    fn last_in_range_instant_formats() {
        let last = NaiveDate::MAX
            .and_hms_milli_opt(23, 59, 59, 999)
            .map(|dt| dt.and_utc().timestamp_millis());
        let first = NaiveDate::MIN
            .and_hms_milli_opt(0, 0, 0, 0)
            .map(|dt| dt.and_utc().timestamp_millis());
        let (Some(last), Some(first)) = (last, first) else {
            assert!(last.is_some() && first.is_some(), "chrono's range edges");
            return;
        };
        assert_eq!(time_format("2006".to_owned(), last), "+262142");
        assert_eq!(time_format("2006".to_owned(), first), "-262143");
        for (op, render) in formatters() {
            assert!(tripped(|| render(last)).is_none(), "{op:?} at {last}");
            assert!(tripped(|| render(first)).is_none(), "{op:?} at {first}");
            for past in [last + 1, first - 1] {
                assert!(
                    is_domain(
                        tripped(|| render(past)),
                        op,
                        TimeDomainCause::InstantOutsideCalendar
                    ),
                    "{op:?} at {past}"
                );
            }
        }
    }
}

// The sleep narrowing, outside any feature so the featureless runtime runs it.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod narrowing_tests {
    use super::{SLEEP_CHUNK_MS, sleep_chunks};

    /// `2^32`: the first value a `u32` narrowing wraps back to zero.
    const WRAP: i64 = 1 << 32;

    #[test]
    fn sleep_chunks_sum_to_the_request_and_fit_a_browser_timer() {
        let chunks = |ms: i64| sleep_chunks(ms).collect::<Vec<u32>>();
        assert_eq!(SLEEP_CHUNK_MS, i32::MAX.unsigned_abs());
        assert_eq!(chunks(0), [0]);
        assert_eq!(chunks(-5), [0]);
        assert_eq!(chunks(5), [5]);
        assert_eq!(chunks(i64::from(i32::MAX)), [SLEEP_CHUNK_MS]);
        assert_eq!(chunks(i64::from(i32::MAX) + 1), [SLEEP_CHUNK_MS, 1]);
        assert_eq!(chunks(WRAP + 5), [SLEEP_CHUNK_MS, SLEEP_CHUNK_MS, 7]);
    }
}

// The instant arithmetic is the exact `Int` arithmetic: past the 64-bit range
// it trips `IntOverflow`, never a saturated instant.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod int_arith_tests {
    use super::{time_add_millis, time_diff_millis};
    use crate::core::{IntOp, RuntimeTrip, runtime_trip};

    fn outcome(
        f: impl FnOnce() -> i64 + std::panic::UnwindSafe,
    ) -> Result<i64, Option<RuntimeTrip>> {
        std::panic::catch_unwind(f).map_err(|p| runtime_trip(p.as_ref()))
    }

    fn overflow(op: IntOp) -> Result<i64, Option<RuntimeTrip>> {
        Err(Some(RuntimeTrip::IntOverflow { op }))
    }

    #[test]
    fn instant_shifts_trip_past_the_int_range() {
        assert_eq!(
            outcome(|| time_add_millis(1, i64::MAX)),
            overflow(IntOp::Add)
        );
        assert_eq!(
            outcome(|| time_add_millis(-1, i64::MIN)),
            overflow(IntOp::Add)
        );
        assert_eq!(
            outcome(|| time_diff_millis(i64::MAX, -1)),
            overflow(IntOp::Sub)
        );
        assert_eq!(
            outcome(|| time_diff_millis(i64::MIN, 1)),
            overflow(IntOp::Sub)
        );
        assert_eq!(time_add_millis(-1, i64::MAX), i64::MAX - 1);
        assert_eq!(time_diff_millis(i64::MAX, 0), i64::MAX);
    }
}
