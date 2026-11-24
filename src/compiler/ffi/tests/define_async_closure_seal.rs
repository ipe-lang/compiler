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
//! The emit-only assertions run in the DEFAULT gate; the cargo build+run proofs
//! are `IPE_E2E`-gated (they shell out to `cargo`), matching the repo's other
//! SEAL fixtures. Each app runs as the emitted `fn main` does: the runtime's
//! panic classifier first, then its own `block_on_entry`, never an executor the
//! fixture builds, so a trip ends exactly as it would in a shipped program.
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

/// The `src/ffi.rs` of an app that holds one async adapter per return shape.
///
/// Each module holds the whole emitted bindings, so both `demo_handler_fn`
/// adapters coexist without renaming.
fn async_ffi_rs() -> String {
    format!(
        "pub mod result {{\n{}}}\npub mod option {{\n{}}}\n",
        emit_async_closure(
            "Fn(Int) -> impl Future<Output = Result<Int, Error>> + Send + Sync + 'static",
        ),
        emit_async_closure("Fn(Int) -> impl Future<Output = Option<Int>> + Send + Sync + 'static"),
    )
}

/// The driver items every async seal app shares, ahead of its own `main`.
///
/// `Entry` is the task `block_on_entry` drives, spelled through the runtime's
/// own `IpeResult` so it names no crate-root task alias.
const DRIVER_ITEMS: &str = r"use std::future::Future;
use std::pin::Pin;

/// The app-side shape of an Ipê async function value.
type AsyncFn<R> = Box<dyn Fn(i64) -> Pin<Box<dyn Future<Output = R> + Send + 'static>> + Send + Sync + 'static>;

/// The entry task the runtime's own entry drives.
type Entry = Pin<Box<dyn Future<Output = IpeResult<IpeError, ()>> + Send + 'static>>;

/// The template's `fn main`: classifier first, then the runtime's own entry,
/// both outcomes through the runtime's one exit funnel.
fn run_entry(entry: impl FnOnce() -> Entry + Send + 'static) -> ! {
    ipe_runtime::core::install_panic_classifier();
    match block_on_entry(entry) {
        IpeResult::Ok(()) => {
            ipe_runtime::system::exit_process(ipe_runtime::system::ProcessStatus::SUCCESS)
        }
        IpeResult::Err(e) => {
            ipe_runtime::core::eprint_task_error(&e.to_string());
            ipe_runtime::system::exit_process(ipe_runtime::system::ProcessStatus::FAILURE)
        }
    }
}
";

/// Write the app crate for one async seal into a fresh `dir`.
///
/// The runtime is the real crate under its `async` feature; the app names no
/// executor of its own, so the adapters run on the runtime's.
fn write_async_app(dir: &std::path::Path, name: &str, ffi_rs: &str, main_rs: &str) {
    let _ = std::fs::remove_dir_all(dir);
    let main_rs = format!("{DRIVER_ITEMS}\n{main_rs}");
    e2e_support::ffi_app::FfiApp {
        name,
        runtime_features: &["async"],
        dependencies: &[],
        ffi_rs,
        main_rs: &main_rs,
    }
    .write(dir)
    .expect("the app crate is written");
}

/// The round-trip driver: a tiny async crate that awaits the adapters' futures.
const ROUND_TRIP_DRIVER: &str = r#"// A tiny async "crate" that takes the boxed handler the adapter returns and
// awaits it — the exact shape an Axum/Hyper route handler driver would.
async fn crate_awaits(f: AsyncFn<Result<i64, IpeError>>) -> i64 {
    // Multi-call: the boxed handler fires more than once.
    let a = f(20).await.unwrap_or(-1);
    let b = f(22).await.unwrap_or(-1);
    a + b
}

fn main() {
    run_entry(|| -> Entry {
        Box::pin(async {
            // The Ipê async fn value: on the app side, exactly a boxed `Fn`
            // whose return is the concrete `IpeTask`-shaped boxed future.
            let ipe_ok: AsyncFn<Result<i64, IpeError>> =
                Box::new(|x| Box::pin(async move { Ok(x + 1) }));
            let summed = crate_awaits(ffi::result::demo_handler_fn(ipe_ok)).await; // (20+1) + (22+1) = 44

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
            IpeResult::Ok(())
        })
    })
}
"#;

/// The trip driver: one mode per return shape and seam, plus the trip's text.
///
/// `deep` is the shape every emitted Ipê function body takes: a depth guard at
/// the top, then a recursive call no input in this fixture ever stops.
const TRIP_DRIVER: &str = r#"fn deep(n: i64) -> i64 {
    let _guard = recursion_guard();
    if n < 0 {
        return n;
    }
    deep(n.wrapping_add(1)).wrapping_add(1)
}

/// The typed error the runtime's own producer gives the trip `deep` raises.
fn trip_error() -> Option<IpeError> {
    std::panic::catch_unwind(|| deep(0))
        .err()
        .and_then(|payload| ipe_runtime::core::runtime_trip(payload.as_ref()))
        .map(ipe_runtime::core::RuntimeTrip::to_ipe_error)
}

fn report(got: Result<i64, IpeError>, trip: Option<IpeError>) {
    match (got, trip) {
        (Err(e), Some(t)) if e == t => println!("result returned the trip's typed error"),
        (got, trip) => println!("result returned {got:?}; the trip is {trip:?}"),
    }
}

async fn drive(mode: String) {
    match mode.as_str() {
        "trip-text" => println!("{}", trip_error().map_or_else(String::new, |e| e.to_string())),
        "option-poll" => {
            let ipe: AsyncFn<Option<i64>> = Box::new(|n| Box::pin(async move { Some(deep(n)) }));
            println!("option returned {:?}", ffi::option::demo_handler_fn(ipe)(0).await);
        }
        "option-build" => {
            let ipe: AsyncFn<Option<i64>> = Box::new(|n| {
                let v = deep(n);
                Box::pin(async move { Some(v) })
            });
            println!("option returned {:?}", ffi::option::demo_handler_fn(ipe)(0).await);
        }
        "result-poll" => {
            let trip = trip_error();
            let ipe: AsyncFn<Result<i64, IpeError>> = Box::new(|n| Box::pin(async move { Ok(deep(n)) }));
            report(ffi::result::demo_handler_fn(ipe)(0).await, trip);
        }
        "result-build" => {
            let trip = trip_error();
            let ipe: AsyncFn<Result<i64, IpeError>> = Box::new(|n| {
                let v = deep(n);
                Box::pin(async move { Ok(v) })
            });
            report(ffi::result::demo_handler_fn(ipe)(0).await, trip);
        }
        _ => println!("unknown mode"),
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    run_entry(move || -> Entry {
        Box::pin(async move {
            println!("start");
            drive(mode).await;
            IpeResult::Ok(())
        })
    })
}
"#;

/// The load-bearing SEAL proof: under `IPE_E2E=1`, build a tiny cargo crate
/// around an emitted async adapter and RUN it under the runtime's own entry.
///
/// It proves the future round-trips, a poll-panic folds to `Err`, and a foreign
/// poll-panic in the `Option` shape folds to `None`.
#[test]
fn async_closure_adapter_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = ipe_test_temp::temp_root()
        .join(format!("ipe_ffi_async_closure_seal_{}", std::process::id()));
    write_async_app(
        &dir,
        "async_closure_seal",
        &async_ffi_rs(),
        ROUND_TRIP_DRIVER,
    );

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

/// Under `IPE_E2E=1`, a runtime trip in an async adapter's Ipê future ends typed.
///
/// The app runs under the runtime's own entry. The trip is raised while the
/// adapter builds the future (`*-build`) and while the spawned task polls it
/// (`*-poll`). An `Option` return has no `None` that would be true, so the
/// process ends: status 1, the trip's typed error on stderr, nothing after the
/// call on stdout. A `Result` return hands the program an `Err` equal to the
/// typed error the runtime produces for the same trip, computed in the driver
/// through `RuntimeTrip::to_ipe_error`.
#[test]
fn async_closure_trip_ends_typed() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = ipe_test_temp::temp_root()
        .join(format!("ipe_ffi_async_closure_trip_{}", std::process::id()));

    write_async_app(&dir, "async_closure_trip", &async_ffi_rs(), TRIP_DRIVER);

    let outcome = e2e_support::build_rust_binary("ffi_async_closure_trip", &dir);
    assert!(
        outcome.is_ok(),
        "{}",
        outcome.as_ref().err().map_or("", String::as_str)
    );
    let build = outcome.expect("asserted Ok above");
    let run_mode = |mode: &str| {
        std::process::Command::new(build.path())
            .arg(mode)
            .output()
            .expect("the built binary runs")
    };

    // The trip's typed error, as the runtime itself renders it.
    let text = run_mode("trip-text");
    let trip_stdout = String::from_utf8_lossy(&text.stdout);
    let trip_line = trip_stdout
        .strip_prefix("start\n")
        .and_then(|rest| rest.strip_suffix('\n'))
        .unwrap_or_default();
    assert!(
        text.status.success() && !trip_line.is_empty(),
        "the driver must compute the trip's typed error from the runtime.\n\
         stdout: {trip_stdout}\nstderr: {}",
        String::from_utf8_lossy(&text.stderr)
    );

    for mode in ["option-poll", "option-build"] {
        let run = run_mode(mode);
        let stdout = String::from_utf8_lossy(&run.stdout);
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert_eq!(
            run.status.code(),
            Some(1),
            "{mode}: a trip in an async Option closure must end the process typed (status 1, \
             never `None`, never 134).\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_eq!(
            stdout, "start\n",
            "{mode}: nothing may run after the tripped call.\nstderr: {stderr}"
        );
        assert!(
            stderr.contains(trip_line),
            "{mode}: the trip's typed error `{trip_line}` must reach stderr.\nstderr: {stderr}"
        );
    }

    for mode in ["result-poll", "result-build"] {
        let run = run_mode(mode);
        let stdout = String::from_utf8_lossy(&run.stdout);
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert_eq!(
            run.status.code(),
            Some(0),
            "{mode}: a trip in an async Result closure is the program's `Err`, never a process \
             end.\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_eq!(
            stdout, "start\nresult returned the trip's typed error\n",
            "{mode}: the `Err` must be the trip's typed error.\nstderr: {stderr}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
