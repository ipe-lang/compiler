//! The one home of every worker script body a web app serves.
//!
//! Every body is a compile-time constant listed in [`WORKER_CONSTANTS`], the
//! list the admitted-call scan (`tests/worker_scan.rs`) reads, so no body can
//! issue, cache or rewrite a request without failing that scan.

/// The worker script served at an app's worker route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkerBody {
    /// Unregister the installed worker and do nothing else.
    Retire,
}

impl WorkerBody {
    /// The script text of this body.
    pub(crate) const fn source(self) -> &'static str {
        match self {
            Self::Retire => RETIRE_BODY,
        }
    }
}

/// The retire body: take over at once, then unregister.
///
/// A browser keeps an installed worker while its update fetch fails, so the
/// worker route always answers, and this body actively retires a worker an
/// earlier build installed.
pub const RETIRE_BODY: &str = "self.addEventListener('install',function(event){event.waitUntil(self.skipWaiting());});\nself.addEventListener('activate',function(event){event.waitUntil(self.registration.unregister());});\n";

/// Every worker body constant, in [`WorkerBody`] order.
pub const WORKER_CONSTANTS: &[&str] = &[RETIRE_BODY];
