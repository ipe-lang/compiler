#![forbid(unsafe_code)]
//! `ipe_watch` — the confined filesystem watcher + process supervisor that
//! power `ipe dev watch`.
//!
//! This crate is deliberately salsa-agnostic: it knows nothing about
//! `ipe_db`, `IpeDatabase`, or the compile pipeline. It provides
//! independently-testable primitives that `crates/ipe/src/watch.rs` (the
//! salsa-aware orchestrator) wires together:
//!
//! - [`scope`] — the typed, project-root-confined watch allowlist
//!   (`WatchedPath`, `WatchScope`), foreclosing symlink escape (H18) and
//!   bounding watched-file count (`DoS` guard).
//! - [`coalesce`] — the debounce half: turns a storm of raw
//!   filesystem events into settled batches via a quiescence window bounded
//!   by a hard latency cap.
//! - [`process`] — the typed `SupervisorState` state machine
//!   (`NotRunning` / `Running`) plus readiness-gated restart, implementing
//!   INV-3 ("a failing rebuild never kills the running binary") and H15/H16
//!   (`RespawnLastGood` recovery from the on-disk artifact when a fresh
//!   binary fails its readiness probe).
//! - [`proxy`] — the DEV-ONLY blue-green front proxy: a persistent front that
//!   holds the user's port while the app binary runs behind it on an internal
//!   port, so a rebuild can cut traffic over to a freshly-ready binary without
//!   dropping the browser's connection. Never in a release build.
//!
//! Decision record: `docs/adr/0007-build-incrementality-and-release-infra.md`.

pub mod coalesce;
pub mod process;
pub mod proxy;
pub mod scope;

pub use coalesce::{Batch, DebounceConfig, coalesce_loop};
pub use process::{
    LastGoodBinary, ReadinessCheck, RestartOutcome, RestartTimeouts, SupervisorState,
};
pub use proxy::DevProxy;
pub use scope::{MAX_WATCHED_FILES, ScopeError, WatchScope, WatchedPath};
