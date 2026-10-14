//! Cancellation probes a lint run polls between modules and between rules.
//!
//! A run that observes its probe firing returns the probe's typed `Cancelled`
//! value instead of a report, so a pass cut short is never mistaken for a
//! complete one. A caller that never cancels uses [`NeverCancel`], whose
//! `Cancelled` is [`Infallible`]: its run cannot yield the cancelled branch.

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};

/// A signal a lint run polls at each checkpoint to learn it has been superseded.
pub trait CancelProbe {
    /// The value a cancelled run returns in place of its report.
    type Cancelled;

    /// `Err` once the run must stop; `Ok(())` while it may continue.
    ///
    /// # Errors
    ///
    /// Returns the probe's `Cancelled` value once cancellation was requested.
    fn poll(&self) -> Result<(), Self::Cancelled>;
}

/// The probe of a run nothing can supersede, such as `ipe lint`.
#[derive(Clone, Copy, Debug, Default)]
pub struct NeverCancel;

impl CancelProbe for NeverCancel {
    type Cancelled = Infallible;

    fn poll(&self) -> Result<(), Infallible> {
        Ok(())
    }
}

/// The marker a run cut short by a [`CancelFlag`] returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LintCancelled;

/// A probe over a shared flag another thread sets to supersede the run.
#[derive(Clone, Copy, Debug)]
pub struct CancelFlag<'a> {
    flag: &'a AtomicBool,
}

impl<'a> CancelFlag<'a> {
    /// A probe that fires once `flag` holds `true`.
    #[must_use]
    pub const fn new(flag: &'a AtomicBool) -> Self {
        Self { flag }
    }
}

impl CancelProbe for CancelFlag<'_> {
    type Cancelled = LintCancelled;

    fn poll(&self) -> Result<(), LintCancelled> {
        if self.flag.load(Ordering::Relaxed) {
            Err(LintCancelled)
        } else {
            Ok(())
        }
    }
}
