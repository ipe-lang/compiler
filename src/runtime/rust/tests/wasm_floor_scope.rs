//! WASM pure-kernel **floor guard** — native-side invariants of the enforced
//! wasm floor.
//!
//! Spec: `docs/adr/0005-delivery-shapes-runtimes-hosts-targets.md`. The floor itself is a live CI
//! gate (`wasm-floor` job): `cargo build -p ipe-runtime-rust --target
//! wasm32-unknown-unknown` (default and `--features json`) must exit 0 — the
//! entire default kernel set, including the `Ipe.Ui` render surface
//! (`ui/*`, `html.rs`, `css*`), compiles to wasm.
//!
//! This file guards the floor's two native-side premises:
//!
//!   1. The floor kernels are synchronous, total, `std`-only — no Task /
//!      tokio / async path. Proven by *calling* a representative pure fn from
//!      each module (list / string / dict / json + Maybe / Result) with
//!      concrete values. If any grows a Task return, an `await`, or a tokio
//!      dependency, this file stops compiling / passing.
//!
//!   2. `IpeTask`'s `Send` bound (`core.rs`) stays intact on native. The wasm
//!      relaxation is the `#[cfg(target_arch = "wasm32")]`-split `EffectSend`
//!      bound (`Send + 'static` on native, `'static` on wasm32) — never a
//!      forked type — leaving the native assertion below untouched.
//!
//! Keep this small, deterministic, dependency-free, and panic-free on every
//! Ipê-reachable path.

use ipe_runtime_rust::*;

// ── (1) Pure-kernel floor candidates: no Task / tokio / async ──────────────
//
// Each of these is a synchronous `std`-only kernel. Calling them here is the
// proof that the floor's "pure subset" is real: if any kernel below acquired a
// Task return or an async backend, the call would no longer type-check as a
// plain value comparison and this test would fail to compile.

#[test]
fn list_kernel_is_pure_and_total() {
    // List.range / List.length — no Task, no allocation surprise, fully sync.
    let xs = ipe_runtime_rust::list::list_range(1, 5);
    assert_eq!(xs, vec![1, 2, 3, 4, 5]);
    assert_eq!(ipe_runtime_rust::list::list_length(xs), 5);

    // List.member over an empty list must NOT panic (total negative path).
    let empty: Vec<i64> = Vec::new();
    assert!(!ipe_runtime_rust::list::list_member(7, empty));
}

#[test]
fn string_kernel_is_pure_and_total() {
    // String.append / toUpper / reverse — pure transforms, no I/O.
    let s = ipe_runtime_rust::string::string_append("ipe".to_string(), "wasm".to_string());
    assert_eq!(
        ipe_runtime_rust::string::string_to_upper(s.clone()),
        "IPEWASM"
    );
    assert_eq!(ipe_runtime_rust::string::string_reverse(s), "msawepi");

    // String.toInt failure path is a Maybe, not a panic — floor-safe.
    match ipe_runtime_rust::string::string_to_int("not-a-number".to_string()) {
        IpeMaybe::Nothing => {}
        IpeMaybe::Just(_) => panic!("test bug: non-numeric string parsed as Int"),
    }
}

#[test]
fn dict_kernel_is_pure_and_total() {
    // Dict.fromList / get — pure HashMap ops, deterministic sorted iteration.
    let d = ipe_runtime_rust::dict::dict_from_list(vec![
        ("a".to_string(), 1i64),
        ("b".to_string(), 2i64),
    ]);
    match ipe_runtime_rust::dict::dict_get("a".to_string(), d.clone()) {
        IpeMaybe::Just(v) => assert_eq!(v, 1),
        IpeMaybe::Nothing => panic!("test bug: present key missed"),
    }
    // Absent key → Nothing (total), and keys come back sorted (pure contract).
    assert!(matches!(
        ipe_runtime_rust::dict::dict_get("zzz".to_string(), d.clone()),
        IpeMaybe::Nothing
    ));
    assert_eq!(
        ipe_runtime_rust::dict::dict_keys(d),
        vec!["a".to_string(), "b".to_string()]
    );
}

// `json` is feature-gated (the kernel uses serde_json), so this leg compiles only
// when the feature is on. Without the gate, `cargo test/clippy --all-targets` under
// a narrow non-json subset (e.g. `--features websocket_client`) fails to resolve
// `ipe_runtime_rust::json`. The list/string/dict legs below stay ungated (always-compiled).
#[cfg(feature = "json")]
#[test]
fn json_kernel_encode_is_pure_and_total() {
    // JSON encode is a pure `Int -> Value -> String` — the floor's JSON leg.
    let obj = ipe_runtime_rust::json::json_enc_object(vec![
        (
            "name".to_string(),
            ipe_runtime_rust::json::json_enc_string("ipe".to_string()),
        ),
        ("n".to_string(), ipe_runtime_rust::json::json_enc_int(42)),
        (
            "ok".to_string(),
            ipe_runtime_rust::json::json_enc_bool(true),
        ),
    ]);
    let compact = ipe_runtime_rust::json::json_enc_encode(0, obj);
    // Field order is preserved by the object encoder; assert on stable substrings
    // so the test does not depend on serde map iteration order beyond presence.
    assert!(compact.contains("\"name\":\"ipe\""), "encoded: {compact}");
    assert!(compact.contains("\"n\":42"), "encoded: {compact}");
    assert!(compact.contains("\"ok\":true"), "encoded: {compact}");
}

#[test]
fn maybe_result_combinators_are_pure_and_total() {
    // Maybe.withDefault on Nothing plugs the default — no panic on the empty case.
    let n: IpeMaybe<i64> = IpeMaybe::Nothing;
    assert_eq!(n.with_default(0), 0);
    assert_eq!(IpeMaybe::Just(9i64).with_default(0), 9);

    // Result happy + error paths are values, never aborts.
    let ok: IpeResult<String, i64> = ok_res(5);
    match ok {
        IpeResult::Ok(v) => assert_eq!(v, 5),
        IpeResult::Err(_) => panic!("test bug: ok_res produced Err"),
    }
    let err: IpeResult<String, i64> = IpeResult::Err(str_err::<String>("boom"));
    assert!(matches!(err, IpeResult::Err(_)));
}

// ── (2) The `IpeTask` `Send` gate (core.rs:17) ─────────────────────────────
//
// `IpeTask`'s `Send` bound is relaxed only under `#[cfg(target_arch = "wasm32")]`,
// through the cfg-split `EffectSend` bound, never a forked type. A native test
// cannot assert the wasm shape, but it nails down the native invariant the
// cfg-split preserves: on the native (non-wasm) target a `IpeTask` value is
// `Send`. A regression that drops `Send` on native (or a fork that diverges the
// type) breaks this assertion.

/// Compile-time witness: `T: Send`. Never called — its existence is the proof.
#[allow(dead_code)]
fn assert_send<T: Send>() {}

#[test]
fn ipe_task_is_send_on_native_target() {
    // Native host (`not(target_arch = "wasm32")`) MUST keep the `Send` bound —
    // tokio `block_on` on a spawned OS thread and `tokio::spawn` both require it.
    // The wasm cfg-split relaxes this ONLY under the wasm cfg.
    #[cfg(not(target_arch = "wasm32"))]
    {
        // `IpeTask<E, A>` is `Pin<Box<dyn Future<..> + Send + 'static>>` per
        // core.rs:17, so the boxed value itself is `Send`.
        assert_send::<IpeTask<String, i64>>();
    }

    // On a hypothetical wasm build this assertion is simply skipped — the floor
    // tracer makes no `Send` claim there, matching the spec's `!Send` wasm arm.
    #[cfg(target_arch = "wasm32")]
    {
        // Intentionally empty: see spec Q2 — wasm futures are `!Send`.
    }
}
