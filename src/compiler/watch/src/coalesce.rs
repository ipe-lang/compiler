//! Coalesce a storm of raw filesystem events into a single settled batch per
//! "pause in activity".
//!
//! Editors save via tmp-write + rename (often 2-3 raw events per logical
//! save), format-on-save chains a second write shortly after the first, and
//! a multi-file operation (branch switch, `git stash pop`) can emit dozens
//! of events within milliseconds. Firing one rebuild per raw event would
//! defeat the whole point of building `ipe dev watch` on an incremental engine —
//! salsa's minimal recompute only pays off if the driver demands it once per
//! logical change, not once per raw inotify/FSEvents wakeup.
//!
//! The policy (design doc §"Debounce + coalescing"): a **quiescence window**
//! that resets on every new event, bounded by a **hard latency cap** so a
//! continuous trickle of saves still eventually fires — the classic
//! debounce-with-a-ceiling shape, not an unbounded reset loop.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

/// A settled batch of distinct changed paths — the coalescer's output. Empty
/// batches are never emitted (a batch always represents at least one
/// observed, in-scope, non-duplicate event).
#[derive(Debug, Clone, Default)]
pub struct Batch {
    pub changed_paths: BTreeSet<PathBuf>,
    /// The instant the FIRST raw event of this batch arrived — the true start
    /// of the debounce/settle window. `None` only on a manually-constructed
    /// batch (never on one the loop emits). The orchestrator subtracts this
    /// from the batch's arrival time to measure settle latency (edit → settled)
    /// under `IPE_WATCH_TIMING`; it is otherwise unused, so `PartialEq`/`Eq`
    /// deliberately exclude it (two batches with the same paths are equal).
    pub first_event_at: Option<Instant>,
}

// `first_event_at` is a wall-clock probe, not part of a batch's identity; two
// batches carrying the same changed paths are equal regardless of when their
// windows opened. Hand-implemented so tests can compare batches by paths alone.
impl PartialEq for Batch {
    fn eq(&self, other: &Self) -> bool {
        self.changed_paths == other.changed_paths
    }
}

impl Eq for Batch {}

/// Tunable coalescing windows.
///
/// Defaults match the design doc's recommended range (quiescence ~80-120 ms,
/// hard cap ~400-500 ms); both are exposed for tests (which want a tight
/// window so they don't wait real wall-clock seconds) and for a future
/// `--debounce-ms` CLI override.
#[derive(Debug, Clone, Copy)]
pub struct DebounceConfig {
    /// Reset on every new event; a batch fires once this much time has
    /// passed with NO further events.
    pub quiescence: Duration,
    /// Fires the batch unconditionally once this much time has passed since
    /// the FIRST event in the current batch, even under a continuous
    /// trickle that keeps resetting the quiescence timer.
    pub hard_cap: Duration,
}

impl Default for DebounceConfig {
    fn default() -> Self {
        Self {
            quiescence: Duration::from_millis(100),
            hard_cap: Duration::from_millis(450),
        }
    }
}

/// Drain `raw_rx` and emit coalesced [`Batch`]es to `out_tx`.
///
/// Runs until `raw_rx` disconnects (the watcher was dropped) — the caller
/// runs this on its own thread and treats the function returning as "the
/// watcher is gone."
///
/// Dedup is by canonical path within a batch (a `BTreeSet`, so ten writes to
/// the same file in one storm still yield one entry); the caller
/// (`ipe_watch`'s consumer) is expected to have already applied the
/// in-scope/excluded-dir filter ([`crate::scope::WatchScope::is_relevant`])
/// before pushing onto `raw_rx` — this function has no scope knowledge and
/// coalesces whatever it is handed, so it stays testable without a real
/// filesystem tree.
pub fn coalesce_loop(raw_rx: &Receiver<PathBuf>, out_tx: &Sender<Batch>, cfg: DebounceConfig) {
    loop {
        // Block for the FIRST event of a new batch — no busy-poll while idle.
        let first = match raw_rx.recv() {
            Ok(p) => p,
            Err(_disconnected) => return,
        };
        let mut pending: BTreeSet<PathBuf> = BTreeSet::new();
        pending.insert(first);
        let batch_started = Instant::now();
        let mut last_event = Instant::now();

        loop {
            let since_last = last_event.elapsed();
            let since_start = batch_started.elapsed();
            if since_start >= cfg.hard_cap {
                break; // hard cap reached — flush regardless of trickle.
            }
            let quiescence_remaining = cfg.quiescence.saturating_sub(since_last);
            let cap_remaining = cfg.hard_cap.saturating_sub(since_start);
            let wait = quiescence_remaining.min(cap_remaining);
            match raw_rx.recv_timeout(wait) {
                Ok(p) => {
                    pending.insert(p);
                    last_event = Instant::now();
                }
                Err(RecvTimeoutError::Timeout) => break, // quiescence settled.
                Err(RecvTimeoutError::Disconnected) => {
                    // Flush whatever we have, then let the outer loop's next
                    // `recv()` observe the disconnect and return.
                    break;
                }
            }
        }

        if !pending.is_empty() {
            // A closed receiver on the consumer side means the orchestrator
            // shut down; nothing left to do but stop coalescing too.
            if out_tx
                .send(Batch {
                    changed_paths: pending,
                    first_event_at: Some(batch_started),
                })
                .is_err()
            {
                return;
            }
        }

        // If the raw channel is now disconnected, exit after flushing the
        // in-flight batch above rather than looping back into a `recv()`
        // that would immediately error.
        if matches!(
            raw_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected)
        ) {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn a_burst_of_events_coalesces_into_one_batch() {
        let (raw_tx, raw_rx) = mpsc::channel();
        let (out_tx, out_rx) = mpsc::channel();
        let cfg = DebounceConfig {
            quiescence: Duration::from_millis(30),
            hard_cap: Duration::from_millis(500),
        };
        let handle = thread::Builder::new()
            .spawn(move || coalesce_loop(&raw_rx, &out_tx, cfg))
            .expect("spawn test thread");

        for i in 0..20 {
            raw_tx
                .send(PathBuf::from(format!("/proj/src/File{i}.ipe")))
                .expect("send must succeed");
        }
        // Let the burst land within the quiescence window, then stop sending.
        let batch = out_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("no batch received");
        assert_eq!(
            batch.changed_paths.len(),
            20,
            "burst must coalesce to ONE batch"
        );

        drop(raw_tx);
        let _ = handle.join();
    }

    #[test]
    fn a_byte_equal_resend_of_the_same_path_still_yields_one_entry() {
        let (raw_tx, raw_rx) = mpsc::channel();
        let (out_tx, out_rx) = mpsc::channel();
        let cfg = DebounceConfig {
            quiescence: Duration::from_millis(20),
            hard_cap: Duration::from_millis(300),
        };
        let handle = thread::Builder::new()
            .spawn(move || coalesce_loop(&raw_rx, &out_tx, cfg))
            .expect("spawn test thread");

        for _ in 0..5 {
            raw_tx
                .send(PathBuf::from("/proj/src/Main.ipe"))
                .expect("send must succeed");
        }
        let batch = out_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("no batch");
        assert_eq!(batch.changed_paths.len(), 1);

        drop(raw_tx);
        let _ = handle.join();
    }

    #[test]
    fn a_continuous_trickle_still_flushes_at_the_hard_cap() {
        let (raw_tx, raw_rx) = mpsc::channel();
        let (out_tx, out_rx) = mpsc::channel();
        let cfg = DebounceConfig {
            quiescence: Duration::from_millis(60),
            hard_cap: Duration::from_millis(150),
        };
        let handle = thread::Builder::new()
            .spawn(move || coalesce_loop(&raw_rx, &out_tx, cfg))
            .expect("spawn test thread");

        // A trickle every 40ms keeps resetting the 60ms quiescence window
        // forever — only the 150ms hard cap can ever flush this batch.
        let sender = thread::Builder::new()
            .spawn(move || {
                for i in 0..10 {
                    let _ = raw_tx.send(PathBuf::from(format!("/proj/src/T{i}.ipe")));
                    thread::sleep(Duration::from_millis(40));
                }
            })
            .expect("spawn test thread");

        let started = Instant::now();
        let batch = out_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("no batch");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(140) && elapsed < Duration::from_millis(400),
            "expected the hard cap (~150ms) to fire, took {elapsed:?}"
        );
        assert!(!batch.changed_paths.is_empty());

        let _ = sender.join();
        drop(out_rx);
        let _ = handle.join();
    }

    #[test]
    fn disconnect_of_the_raw_channel_stops_the_loop() {
        let (raw_tx, raw_rx) = mpsc::channel::<PathBuf>();
        let (out_tx, _out_rx) = mpsc::channel();
        let cfg = DebounceConfig::default();
        let handle = thread::Builder::new()
            .spawn(move || coalesce_loop(&raw_rx, &out_tx, cfg))
            .expect("spawn test thread");
        drop(raw_tx);
        // Must return promptly, not hang forever.
        handle.join().expect("coalesce_loop thread panicked");
    }
}
