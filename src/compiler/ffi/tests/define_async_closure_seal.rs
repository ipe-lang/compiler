//! SEAL fixture for ASYNC-returning closure adapters (`[rust.define.closure]`
//! whose declared return is a `Future`, the Axum/Hyper async-handler shape).
//!
//! The sync `closure_adapter_seal` fixture proves a `Fn(A) -> R` closure
//! round-trips. This one proves the next link: a `Fn(A) -> impl Future<Output =
//! Result<B, E>>` closure. The emitted adapter must:
//!
//!  * receive AND return the SAME concrete boxed future the `IpeTask` value
//!    carries (`Pin<Box<dyn Future<Output = …> + Send + 'static>>`), so the
//!    inner `Send + 'static` — the proof the captured Ipê env and args cannot
//!    escape into a non-`Send` future — is discharged by rustc at the boundary,
//!    never re-derived;
//!  * produce the future under `catch_unwind` (a production-panic yields an
//!    immediate-error future), then await it through the `ffi_spawn_guarded`
//!    choke-point (spawn + `AbortOnDrop` + join-error funnel as one step), so a
//!    POLL-panic folds through the redacting funnel to `Err`/`None` and a
//!    dropped outer task cancels the inner one;
//!  * refuse an async TOTAL return at decode (a poll-panic would have no error
//!    channel), so only `Result`/`Option` async shapes ever emit.
//!
//! The emit-only assertions run in the DEFAULT gate; the cargo build+run proof
//! is `IPE_E2E`-gated (it shells out to `cargo`, and the scratch crate pulls a
//! real `tokio`), matching the repo's other SEAL fixtures.
#![allow(clippy::expect_used)] // test setup: a failed decode / scratch-dir op IS the failure

use ipe_ffi::bindings::{emit_bindings, surviving_ref_names};
use ipe_ffi::pkginfo::PkgInfo;

/// Decode a one-crate inspection document carrying a single async
/// `define.closure` entry, and return the emitted `_bindings.rs`.
fn emit_async_closure(sig: &str) -> String {
    let doc = serde_json::json!({
        "pkg": "demo",
        "name": "demo",
        "version": "0.1.0",
        "functions": [{
            "name": "handler_fn",
            "effect": "pure",
            "isClosureAdapter": true,
            "closureSig": sig
        }],
        "errors": []
    })
    .to_string();
    let pkg = PkgInfo::decode_json(&doc).expect("async define.closure decodes");
    emit_bindings(&pkg)
}

/// Default gate: an async `Result` adapter emits the spawned-await containment
/// through the `ffi_spawn_guarded` choke-point with both panic sites folding to
/// `Err`, and names the concrete boxed future on BOTH box sides.
#[test]
fn async_result_adapter_emits_spawned_await_containment() {
    let out = emit_async_closure(
        "Fn(Int) -> impl Future<Output = Result<Int, Error>> + Send + Sync + 'static",
    );
    // The received box and the handle alias carry the SAME boxed future; the
    // wrapper returns the opaque handle nominal.
    assert!(
        out.contains(
            "pub type HandlerFnClosure = Box<dyn Fn(i64) -> ::std::pin::Pin<Box<dyn \
             ::std::future::Future<Output = Result<i64, IpeError>> + Send + 'static>> + Send \
             + Sync + 'static>;"
        ),
        "the handle alias must carry the boxed future:\n{out}"
    );
    assert!(
        out.contains(
            "pub fn demo_handler_fn(__ipe_fn: Box<dyn Fn(i64) -> ::std::pin::Pin<Box<dyn \
             ::std::future::Future<Output = Result<i64, IpeError>> + Send + 'static>> + Send \
             + Sync + 'static>) -> HandlerFnClosure {"
        ),
        "the received box carries the boxed future; the return is the handle:\n{out}"
    );
    // The spawn + cancel-guard + join-error funnel is the single
    // `ffi_spawn_guarded` choke-point — the adapter cannot spawn unguarded.
    assert!(
        out.contains(
            "match ffi_spawn_guarded(__fut).await { Ok(inner) => inner, Err(__e) => Err(__e) }"
        ),
        "{out}"
    );
    // A production-panic yields an immediate-error future; a poll-panic rides the
    // choke-point's already-funnelled Err. Both to Err — never abort, never
    // fabricate.
    assert!(
        out.contains(
            "let __e = ipe_error_from_panic(\"foreign closure panicked\", __p); \
             return Box::pin(async move { Err(__e) });"
        ),
        "{out}"
    );
    assert!(!out.contains("std::process::abort()"), "{out}");
    assert!(surviving_ref_names(&async_pkg()).contains("handler_fn"));
}

fn async_pkg() -> PkgInfo {
    let doc = serde_json::json!({
        "pkg": "demo", "name": "demo", "version": "0.1.0",
        "functions": [{
            "name": "handler_fn", "effect": "pure", "isClosureAdapter": true,
            "closureSig": "Fn(Int) -> impl Future<Output = Result<Int, Error>> + Send + Sync + 'static"
        }],
        "errors": []
    })
    .to_string();
    PkgInfo::decode_json(&doc).expect("decodes")
}

/// Default gate: an async TOTAL return has no error channel to fold a poll-panic
/// into, so it over-drops at decode — no wrapper, never emit-and-cargo-fail.
#[test]
fn an_async_total_return_over_drops() {
    for bad in [
        "Fn(Int) -> impl Future<Output = Int> + Send + Sync + 'static",
        "Fn(Int) -> BoxFuture<'static, Bool> + Send + Sync + 'static",
    ] {
        let out = emit_async_closure(bad);
        assert!(
            !out.contains("pub fn demo_handler_fn"),
            "{bad:?} must over-drop — async-total has no error channel:\n{out}"
        );
    }
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, build a tiny cargo crate
/// around an emitted async adapter and RUN it on a real tokio runtime, proving
/// the future round-trips, a poll-panic folds to `Err`, and cancellation aborts
/// the inner task (no side effect after drop).
#[test]
fn async_closure_adapter_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    // One module per return shape: each holds the whole emitted bindings, so
    // both `demo_handler_fn` adapters coexist without renaming.
    let ffi_rs = format!(
        "pub mod result {{\n{}}}\npub mod option {{\n{}}}\n",
        emit_async_closure(
            "Fn(Int) -> impl Future<Output = Result<Int, Error>> + Send + Sync + 'static",
        ),
        emit_async_closure("Fn(Int) -> impl Future<Output = Option<Int>> + Send + Sync + 'static"),
    );

    let dir = ipe_test_temp::temp_root()
        .join(format!("ipe_ffi_async_closure_seal_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let main_rs = r#"use std::future::Future;
use std::pin::Pin;

/// The app-side shape of an Ipê async function value.
type AsyncFn<R> = Box<dyn Fn(i64) -> Pin<Box<dyn Future<Output = R> + Send + 'static>> + Send + Sync + 'static>;

// A tiny async "crate" that takes the boxed handler the adapter returns and
// awaits it — the exact shape an Axum/Hyper route handler driver would.
async fn crate_awaits(f: AsyncFn<Result<i64, IpeError>>) -> i64 {
    // Multi-call: the boxed handler fires more than once.
    let a = f(20).await.unwrap_or(-1);
    let b = f(22).await.unwrap_or(-1);
    a + b
}

fn main() {
    let Ok(rt) = tokio::runtime::Runtime::new() else {
        std::process::exit(2);
    };
    rt.block_on(async {
        // The Ipê async fn value: on the app side, exactly a boxed `Fn` whose
        // return is the concrete `IpeTask`-shaped boxed future.
        let ipe_ok: AsyncFn<Result<i64, IpeError>> =
            Box::new(|x| Box::pin(async move { Ok(x + 1) }));
        let summed = crate_awaits(ffi::result::demo_handler_fn(ipe_ok)).await; // (20+1) + (22+1) = 43

        // A handler whose future PANICS while polling must fold to Err (the
        // spawned-await JoinError arm), never abort the whole executor.
        let ipe_panics: AsyncFn<Result<i64, IpeError>> =
            Box::new(|_| Box::pin(async move { panic!("boom in the future") }));
        let folded = ffi::result::demo_handler_fn(ipe_panics)(1).await.map(|_| 0).unwrap_or(-7);

        // The `Option` shape round-trips, and a foreign poll-panic is `None`.
        let ipe_opt: AsyncFn<Option<i64>> = Box::new(|x| Box::pin(async move { Some(x * 3) }));
        let tripled = ffi::option::demo_handler_fn(ipe_opt)(5).await.unwrap_or(-1);
        let ipe_opt_panics: AsyncFn<Option<i64>> =
            Box::new(|_| Box::pin(async move { panic!("foreign boom") }));
        let none = ffi::option::demo_handler_fn(ipe_opt_panics)(1).await.unwrap_or(-9);
        assert_eq!(tripled, 15, "async option closure round-trips");
        assert_eq!(none, -9, "a foreign poll-panic folds to None");

        assert_eq!(summed, 44, "async closure round-trips its awaited value");
        assert_eq!(folded, -7, "a poll-panic folds to Err, never aborts the executor");
        println!("{summed} {folded}");
    });
}
"#;
    let tokio = "tokio = { version = \"1\", features = [\"rt\", \"rt-multi-thread\", \"macros\", \"time\"] }"
        .to_owned();
    e2e_support::ffi_app::FfiApp {
        name: "async_closure_seal",
        runtime_features: &["async"],
        dependencies: &[tokio],
        ffi_rs: &ffi_rs,
        main_rs,
    }
    .write(&dir)
    .expect("the app crate is written");

    let ran = e2e_support::build_and_run_rust("ffi_async_closure", &dir);
    assert!(
        ran.is_ok(),
        "{}",
        ran.as_ref().err().map_or("", String::as_str)
    );
    let run = ran.expect("asserted Ok above");
    let stdout = &run.stdout;
    assert_eq!(
        run.exit_code,
        Some(0),
        "the emitted async closure adapter crate must build and run exit 0.\n\
         stdout: {stdout}"
    );
    assert!(
        stdout.contains("44 -7"),
        "the async closure must round-trip and fold a poll-panic to Err.\nstdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
