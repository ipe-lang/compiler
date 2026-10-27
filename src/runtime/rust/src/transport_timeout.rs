//! Transport deadlines parsed once into a bounded type.
//!
//! An Ipê program hands the runtime a deadline as the `Int` milliseconds of a
//! record field (`HttpRequest.timeout`, `WebSocketCfg.timeout`,
//! `WebSocketCfg.pingInterval`). The kernel boundary parses that number here,
//! exactly once: past it a deadline exists only as a [`TransportTimeout`],
//! which admits `1 ..= MAX_TRANSPORT_TIMEOUT_MS` milliseconds, and a keep-alive
//! cadence only as a [`PingCadence`], whose "no ping" is a named variant.
//! Anything else is a typed [`TimeoutRefusal`]: no sentinel value stands in
//! for a default, and no `as` cast narrows a value the type has not already
//! bounded.

use std::num::NonZeroU32;
use std::time::Duration;

/// The ceiling in the whole minutes its refusal text names.
const MAX_TRANSPORT_TIMEOUT_MINUTES: u32 = 10;

/// The longest transport deadline a program may ask for, in milliseconds.
pub const MAX_TRANSPORT_TIMEOUT_MS: u32 = MAX_TRANSPORT_TIMEOUT_MINUTES * 60_000;

/// A transport deadline between 1 ms and [`MAX_TRANSPORT_TIMEOUT_MS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportTimeout(NonZeroU32);

impl TransportTimeout {
    /// Parses the DTO's millisecond count into a deadline.
    ///
    /// # Errors
    ///
    /// Zero or a negative count is [`TimeoutRefusal::NotPositive`]; a count
    /// above [`MAX_TRANSPORT_TIMEOUT_MS`] is [`TimeoutRefusal::AboveCeiling`].
    pub fn parse(ms: i64) -> Result<Self, TimeoutRefusal> {
        let Ok(ms) = u32::try_from(ms) else {
            return Err(if ms < 0 {
                TimeoutRefusal::NotPositive
            } else {
                TimeoutRefusal::AboveCeiling
            });
        };
        let Some(ms) = NonZeroU32::new(ms) else {
            return Err(TimeoutRefusal::NotPositive);
        };
        if ms.get() > MAX_TRANSPORT_TIMEOUT_MS {
            return Err(TimeoutRefusal::AboveCeiling);
        }
        Ok(Self(ms))
    }

    /// The deadline in milliseconds, within the ceiling by construction.
    #[must_use]
    pub const fn millis(self) -> u32 {
        self.0.get()
    }

    /// The deadline as a duration.
    #[must_use]
    pub fn as_duration(self) -> Duration {
        Duration::from_millis(u64::from(self.0.get()))
    }
}

/// How often an open connection sends a keep-alive ping, if at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PingCadence {
    /// No keep-alive ping is sent.
    Off,
    /// A ping is sent each time this span passes.
    Every(TransportTimeout),
}

impl PingCadence {
    /// Parses the DTO's millisecond count into a cadence; `0` is [`Self::Off`].
    ///
    /// # Errors
    ///
    /// A negative count is [`TimeoutRefusal::NotPositive`]; a count above
    /// [`MAX_TRANSPORT_TIMEOUT_MS`] is [`TimeoutRefusal::AboveCeiling`].
    pub fn parse(ms: i64) -> Result<Self, TimeoutRefusal> {
        if ms == 0 {
            return Ok(Self::Off);
        }
        TransportTimeout::parse(ms).map(Self::Every)
    }
}

/// Why a millisecond count is no transport deadline.
///
/// The text names the admitted range and never the refused value, so it may
/// reach a view or a log as it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutRefusal {
    /// Zero or negative.
    NotPositive,
    /// Above [`MAX_TRANSPORT_TIMEOUT_MS`].
    AboveCeiling,
}

impl std::fmt::Display for TimeoutRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPositive => write!(
                f,
                "a span below 1 ms is refused (1 ms to {MAX_TRANSPORT_TIMEOUT_MINUTES} minutes)"
            ),
            Self::AboveCeiling => write!(
                f,
                "a span above {MAX_TRANSPORT_TIMEOUT_MINUTES} minutes is refused \
                 (1 ms to {MAX_TRANSPORT_TIMEOUT_MINUTES} minutes)"
            ),
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn zero_and_every_negative_count_are_not_positive() {
        for ms in [0, -1, i64::MIN] {
            assert_eq!(
                TransportTimeout::parse(ms),
                Err(TimeoutRefusal::NotPositive),
                "{ms}"
            );
        }
    }

    #[test]
    fn every_count_past_the_ceiling_is_above_it() {
        for ms in [
            i64::from(MAX_TRANSPORT_TIMEOUT_MS) + 1,
            (1_i64 << 32) | 1,
            i64::MAX,
        ] {
            assert_eq!(
                TransportTimeout::parse(ms),
                Err(TimeoutRefusal::AboveCeiling),
                "{ms}"
            );
        }
    }

    #[test]
    fn the_ceiling_is_ten_minutes() {
        assert_eq!(MAX_TRANSPORT_TIMEOUT_MS, 600_000);
    }

    #[test]
    fn the_range_ends_are_admitted_as_themselves() {
        for ms in [1_u32, MAX_TRANSPORT_TIMEOUT_MS] {
            let parsed = TransportTimeout::parse(i64::from(ms));
            assert_eq!(parsed.map(TransportTimeout::millis), Ok(ms));
            assert_eq!(
                parsed.map(TransportTimeout::as_duration),
                Ok(Duration::from_millis(u64::from(ms)))
            );
        }
    }

    #[test]
    fn a_ping_cadence_names_off_and_refuses_what_a_deadline_refuses() {
        assert_eq!(PingCadence::parse(0), Ok(PingCadence::Off));
        assert_eq!(
            PingCadence::parse(30_000).map(|c| match c {
                PingCadence::Off => 0,
                PingCadence::Every(span) => span.millis(),
            }),
            Ok(30_000)
        );
        assert_eq!(PingCadence::parse(-1), Err(TimeoutRefusal::NotPositive));
        assert_eq!(
            PingCadence::parse(i64::from(MAX_TRANSPORT_TIMEOUT_MS) + 1),
            Err(TimeoutRefusal::AboveCeiling)
        );
    }

    #[test]
    fn a_refusal_text_holds_no_digit_of_the_input() {
        for (ms, refusal) in [
            (-7_654_321, TimeoutRefusal::NotPositive),
            (9_876_543_210, TimeoutRefusal::AboveCeiling),
        ] {
            assert_eq!(TransportTimeout::parse(ms), Err(refusal));
            let shown = refusal.to_string();
            let digits = ms.abs().to_string();
            assert!(!shown.contains(&digits), "{ms} leaked into {shown}");
            assert!(shown.contains("1 ms to 10 minutes"), "{shown}");
        }
    }
}
