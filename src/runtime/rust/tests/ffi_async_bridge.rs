//! Async-FFI bridge runtime contract:
//!
//! 1. `block_on` drives every entry on ONE process-global runtime, so a
//!    reactor-registered handle (FFI client, listener, timer) constructed in
//!    one `block_on` stays usable in a later one — a fresh runtime per entry
//!    would leave the handle on a dead reactor.
//! 2. `AbortOnDrop` — the guard the emitted async FFI wrapper arms around its
//!    spawned foreign task — aborts the inner task when the wrapper future is
//!    dropped before completion (`Task.parallel` early-cancel), so a
//!    cancelled foreign call cannot keep producing side effects.
//! 3. A poll-time panic inside the spawned foreign future surfaces as the
//!    wrapper's typed `Err` through the join-error arm and the redacting
//!    foreign-error funnel — never a process abort, never a silent hang.
// `tokio` is a native-only dependency: the feature names it, wasm32 has no crate.
#![cfg(all(feature = "tokio", not(target_arch = "wasm32")))]

use ipe_runtime_rust::{
    AbortOnDrop, IpeError, IpeResult, IpeTask, block_on, ffi_spawn_guarded, ipe_error_from_foreign,
    ok_res,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[test]
fn reactor_handle_survives_across_two_block_on_entries() -> Result<(), String> {
    let make: IpeTask<String, tokio::net::TcpListener> = Box::pin(async {
        match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => ok_res(l),
            Err(e) => IpeResult::Err(format!("bind failed: {e}")),
        }
    });
    let listener = match block_on(make) {
        IpeResult::Ok(l) => l,
        IpeResult::Err(e) => return Err(format!("first block_on failed: {e}")),
    };
    // The listener is registered with the reactor of the runtime that bound
    // it; accepting inside a LATER entry only works if both entries share one
    // runtime.
    let roundtrip: IpeTask<String, bool> = Box::pin(async move {
        let addr = match listener.local_addr() {
            Ok(a) => a,
            Err(e) => return IpeResult::Err(format!("local_addr failed: {e}")),
        };
        let (accepted, connected) =
            tokio::join!(listener.accept(), tokio::net::TcpStream::connect(addr));
        match (accepted, connected) {
            (Ok(_), Ok(_)) => ok_res(true),
            (a, c) => IpeResult::Err(format!("accept={a:?} connect={c:?}")),
        }
    });
    match block_on(roundtrip) {
        IpeResult::Ok(true) => Ok(()),
        other => Err(format!(
            "listener bound in entry 1 must accept in entry 2 (shared reactor): {other:?}"
        )),
    }
}

#[test]
fn abort_on_drop_cancels_the_spawned_foreign_task() {
    let side_effect = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&side_effect);
    // The emitted async wrapper shape: spawn, arm the guard, await, defuse.
    let wrapper: IpeTask<String, i64> = Box::pin(async move {
        let handle = tokio::task::spawn(async move {
            tokio::time::sleep(Duration::from_millis(60)).await;
            side_effect.store(true, Ordering::SeqCst);
            1_i64
        });
        let guard = AbortOnDrop::new(handle.abort_handle());
        let joined = handle.await;
        guard.defuse();
        match joined {
            Ok(v) => ok_res(v),
            Err(e) => IpeResult::Err(format!("{e:?}")),
        }
    });
    let outcome: IpeResult<String, bool> = block_on(Box::pin(async move {
        // Cancel the wrapper mid-flight: the timeout drops the wrapper future
        // before the inner sleep completes, so the guard must abort the spawn.
        let cancelled = tokio::time::timeout(Duration::from_millis(5), wrapper).await;
        if cancelled.is_ok() {
            return IpeResult::Err("wrapper completed before the cancel window".to_owned());
        }
        // Give a leaked (non-aborted) inner task time to run its side effect.
        tokio::time::sleep(Duration::from_millis(150)).await;
        ok_res(observed.load(Ordering::SeqCst))
    }));
    assert!(
        matches!(outcome, IpeResult::Ok(false)),
        "the aborted foreign task must not produce its side effect: {outcome:?}"
    );
}

#[test]
fn panicking_spawned_foreign_task_folds_to_a_typed_err() {
    // The emitted async wrapper's join-error arm: a panic at poll time inside
    // the spawned foreign future becomes a `JoinError`, folded to the redacted
    // funnel message (generic text + correlation id) — the raw panic payload
    // never rides the Ipê-visible error value.
    let wrapper: IpeTask<String, i64> = Box::pin(async move {
        let handle: tokio::task::JoinHandle<i64> =
            tokio::task::spawn(async move { panic!("foreign poll-time panic") });
        let guard = AbortOnDrop::new(handle.abort_handle());
        let joined = handle.await;
        guard.defuse();
        match joined {
            Ok(v) => ok_res(v),
            Err(join_err) => IpeResult::Err(ipe_error_from_foreign(join_err)),
        }
    });
    match block_on(wrapper) {
        IpeResult::Err(e) => assert!(
            e.starts_with("external operation failed (ref "),
            "join error must fold to the redacted funnel message: {e}"
        ),
        IpeResult::Ok(v) => panic!("expected a typed Err, got Ok({v})"),
    }
}

#[test]
fn entry_future_panic_folds_through_the_funnel() {
    // A panic in the entry future itself (outside any spawned foreign task —
    // e.g. a wrapper prelude) is join-mapped by `block_on` to a typed `Err`
    // carrying the funnel correlation id, never an unwind out of the entry.
    let entry: IpeTask<String, i64> = Box::pin(async { panic!("entry poll panic") });
    match block_on(entry) {
        IpeResult::Err(e) => assert!(
            e.starts_with("async task panicked (ref "),
            "entry panic must fold to the funnel message: {e}"
        ),
        IpeResult::Ok(v) => panic!("expected a typed Err, got Ok({v})"),
    }
}

// ── ffi_spawn_guarded: the structural single choke-point ─────────────────────
//
// Every emitted async FFI wrapper routes its spawn through `ffi_spawn_guarded`,
// so the guard-arming, the cancel-abort, and the join-error funnel are one
// indivisible operation the emitter cannot partially apply. These prove the
// three honesty properties directly on the helper, independent of any emitter.

#[test]
fn spawn_guarded_passes_the_success_value_through() {
    // The happy path returns the spawned future's output verbatim; the caller
    // applies its own shape-specific lift. Exercised for each output shape a
    // wrapper spawns: a bare value, a fallible `Result`, and an `Option`.
    let bare: IpeResult<IpeError, i64> = block_on(Box::pin(async {
        match ffi_spawn_guarded(async { 7_i64 }).await {
            Ok(v) => ok_res(v),
            Err(e) => IpeResult::Err(e),
        }
    }));
    assert!(matches!(bare, IpeResult::Ok(7)));

    let fallible: IpeResult<IpeError, i64> = block_on(Box::pin(async {
        match ffi_spawn_guarded(async { Ok::<i64, String>(9) }).await {
            Ok(Ok(v)) => ok_res(v),
            Ok(Err(e)) => IpeResult::Err(ipe_error_from_foreign(e)),
            Err(e) => IpeResult::Err(e),
        }
    }));
    assert!(matches!(fallible, IpeResult::Ok(9)));

    let optional: IpeResult<IpeError, i64> = block_on(Box::pin(async {
        match ffi_spawn_guarded(async { Some(11_i64) }).await {
            Ok(Some(v)) => ok_res(v),
            Ok(None) => IpeResult::Err("none".to_owned().into()),
            Err(e) => IpeResult::Err(e),
        }
    }));
    assert!(matches!(optional, IpeResult::Ok(11)));
}

#[test]
fn spawn_guarded_aborts_the_inner_task_on_cancel() {
    // Dropping the wrapper future before `ffi_spawn_guarded` returns must abort
    // the spawned foreign task, so a cancelled call fires no post-cancel side
    // effect. The guard-arm is structural — the caller writes no `AbortOnDrop`.
    let side_effect = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&side_effect);
    let wrapper: IpeTask<IpeError, i64> = Box::pin(async move {
        match ffi_spawn_guarded(async move {
            tokio::time::sleep(Duration::from_millis(60)).await;
            side_effect.store(true, Ordering::SeqCst);
            1_i64
        })
        .await
        {
            Ok(v) => ok_res(v),
            Err(e) => IpeResult::Err(e),
        }
    });
    let outcome: IpeResult<String, bool> = block_on(Box::pin(async move {
        let cancelled = tokio::time::timeout(Duration::from_millis(5), wrapper).await;
        if cancelled.is_ok() {
            return IpeResult::Err("wrapper completed before the cancel window".to_owned());
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        ok_res(observed.load(Ordering::SeqCst))
    }));
    assert!(
        matches!(outcome, IpeResult::Ok(false)),
        "the aborted foreign task must not produce its side effect: {outcome:?}"
    );
}

#[test]
fn spawn_guarded_folds_a_poll_panic_to_the_redacted_funnel() {
    // A poll-time panic inside the spawned foreign future becomes a `JoinError`
    // the helper routes through `ipe_error_from_panic`: the Ipê-visible value is
    // the generic message + correlation id, never the raw panic payload.
    let wrapper: IpeTask<IpeError, i64> = Box::pin(async move {
        match ffi_spawn_guarded(async move { panic!("foreign poll-time panic") }).await {
            Ok(v) => ok_res(v),
            Err(e) => IpeResult::Err(e),
        }
    });
    match block_on(wrapper) {
        IpeResult::Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("foreign async task panicked (ref "),
                "a poll panic must fold to the redacted funnel message: {msg}"
            );
            assert!(
                !msg.contains("foreign poll-time panic"),
                "the raw panic payload must never ride the Ipê-visible error: {msg}"
            );
        }
        IpeResult::Ok(v) => panic!("expected a typed Err, got Ok({v})"),
    }
}

#[test]
fn defused_guard_lets_the_join_outcome_through() {
    let wrapper: IpeTask<String, i64> = Box::pin(async move {
        let handle = tokio::task::spawn(async move { 7_i64 });
        let guard = AbortOnDrop::new(handle.abort_handle());
        let joined = handle.await;
        guard.defuse();
        match joined {
            Ok(v) => ok_res(v),
            Err(e) => IpeResult::Err(format!("{e:?}")),
        }
    });
    assert!(matches!(block_on(wrapper), IpeResult::Ok(7)));
}
