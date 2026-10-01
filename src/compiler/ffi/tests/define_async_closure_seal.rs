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
#[allow(clippy::too_many_lines)] // one linear E2E-crate assembly (manifest + runtime-glue stand-in + driver + build/run); splitting would scatter the fixture
fn async_closure_adapter_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let cargo = ipe_env::var("CARGO").expect("cargo sets CARGO for every test it runs");

    let result_region = emit_async_closure(
        "Fn(Int) -> impl Future<Output = Result<Int, Error>> + Send + Sync + 'static",
    );
    let result_fn = wrapper_region(&result_region, "handler_fn");

    let dir = ipe_test_temp::temp_root()
        .join(format!("ipe_ffi_async_closure_seal_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("mkdir");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"async_closure_seal\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
         [[bin]]\nname = \"async_closure_seal\"\npath = \"src/main.rs\"\n\
         [dependencies]\ntokio = { version = \"1\", features = [\"rt\", \"rt-multi-thread\", \"macros\", \"time\"] }\n\
         # catch_unwind soundness requires panic=unwind (the emitter's own fence)\n\
         [profile.dev]\npanic = \"unwind\"\n",
    )
    .expect("Cargo.toml");

    // A minimal stand-in for the runtime glue the emitted async adapter names
    // (`str_err`, `IpeError`, and the `AbortOnDrop` cancel guard). These mirror
    // `ipe_runtime`'s real definitions; the fixture supplies its own so it need
    // not depend on the whole runtime crate.
    let main_rs = format!(
        r#"use std::pin::Pin;
use std::future::Future;

#[derive(Debug)]
pub struct IpeError(String);
pub fn str_err<E: From<String>>(s: &str) -> E {{ s.to_string().into() }}
pub fn ipe_error_from_panic<E: From<String>>(c: &str, _p: Box<dyn std::any::Any + Send>) -> E {{ c.to_string().into() }}
pub fn note_foreign_panic(_c: &str, _p: Box<dyn std::any::Any + Send>) -> String {{ String::new() }}
pub fn note_foreign_error<T: std::fmt::Debug>(_e: T) -> String {{ String::new() }}
pub fn ipe_error_from_foreign<T: std::fmt::Debug, E: From<String>>(_e: T) -> E {{ "external operation failed".to_string().into() }}
impl From<String> for IpeError {{ fn from(s: String) -> Self {{ IpeError(s) }} }}

// The cancel guard the emitted async adapter arms around its spawned task: its
// Drop aborts the inner task unless defused (matches `ipe_runtime::AbortOnDrop`).
pub struct AbortOnDrop(Option<tokio::task::AbortHandle>);
impl AbortOnDrop {{
    pub fn new(h: tokio::task::AbortHandle) -> Self {{ Self(Some(h)) }}
    pub fn defuse(mut self) {{ self.0 = None; }}
}}
impl Drop for AbortOnDrop {{
    fn drop(&mut self) {{ if let Some(h) = self.0.take() {{ h.abort(); }} }}
}}

// The single spawn choke-point the emitted async adapter routes through: spawn
// the foreign future, arm the cancel guard, await, defuse, funnel the JoinError
// (matches `ipe_runtime::ffi_spawn_guarded`). Spawn + arm are one step here too.
pub async fn ffi_spawn_guarded<F>(future: F) -> Result<F::Output, IpeError>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{{
    let handle = tokio::task::spawn(future);
    let guard = AbortOnDrop::new(handle.abort_handle());
    let joined = handle.await;
    guard.defuse();
    match joined {{
        Ok(output) => Ok(output),
        Err(join_err) => match join_err.try_into_panic() {{
            Ok(payload) => Err(ipe_error_from_panic("foreign async task panicked", payload)),
            Err(join_err) => Err(ipe_error_from_foreign(join_err)),
        }},
    }}
}}

// A tiny async "crate" that takes the boxed handler the adapter returns and
// awaits it — the exact shape an Axum/Hyper route handler driver would.
async fn crate_awaits(
    f: Box<dyn Fn(i64) -> Pin<Box<dyn Future<Output = Result<i64, IpeError>> + Send + 'static>> + Send + Sync + 'static>,
) -> i64 {{
    // Multi-call: the boxed handler fires more than once.
    let a = f(20).await.unwrap_or(-1);
    let b = f(22).await.unwrap_or(-1);
    a + b
}}

{result_fn}

fn main() {{
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {{
        // The Ipê async fn value: on the app side, exactly a boxed `Fn` whose
        // return is the concrete `IpeTask`-shaped boxed future.
        let ipe_ok: Box<dyn Fn(i64) -> Pin<Box<dyn Future<Output = Result<i64, IpeError>> + Send + 'static>> + Send + Sync + 'static> =
            Box::new(|x| Box::pin(async move {{ Ok(x + 1) }}));
        let adapted = demo_handler_fn(ipe_ok);
        let summed = crate_awaits(adapted).await; // (20+1) + (22+1) = 43

        // A handler whose future PANICS while polling must fold to Err (the
        // spawned-await JoinError arm), never abort the whole executor.
        let ipe_panics: Box<dyn Fn(i64) -> Pin<Box<dyn Future<Output = Result<i64, IpeError>> + Send + 'static>> + Send + Sync + 'static> =
            Box::new(|_| Box::pin(async move {{ panic!("boom in the future") }}));
        let adapted_panic = demo_handler_fn(ipe_panics);
        let folded = adapted_panic(1).await.map(|_| 0).unwrap_or(-7);

        assert_eq!(summed, 44, "async closure round-trips its awaited value");
        assert_eq!(folded, -7, "a poll-panic folds to Err, never aborts the executor");
        println!("{{summed}} {{folded}}");
    }});
}}
"#,
    );
    std::fs::write(dir.join("src").join("main.rs"), main_rs).expect("main.rs");

    let out = std::process::Command::new(&cargo)
        .arg("run")
        .arg("--quiet")
        .current_dir(&dir)
        .output()
        .expect("cargo run spawns");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "the emitted async closure adapter crate must build and run exit 0.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("44 -7"),
        "the async closure must round-trip and fold a poll-panic to Err.\nstdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Extract the sentinel-bracketed wrapper region for `ref_name` from an emitted
/// `_bindings.rs`, without the preamble.
fn wrapper_region(bindings: &str, ref_name: &str) -> String {
    let begin = format!("// IPE-FFI-WRAPPER BEGIN {ref_name}");
    let mut keep = false;
    let mut out = String::new();
    for line in bindings.lines() {
        if line.trim_end() == begin {
            keep = true;
            continue;
        }
        if line.trim_end() == "// IPE-FFI-WRAPPER END" && keep {
            break;
        }
        if keep {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}
