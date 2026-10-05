//! `HttpStream.open` must return `Task Error StreamId`,
//! not `Task Error Int`.
//!
//! Before this fix, `K::HttpStreamOpen`'s scheme was `fun(http_request(), task(int()))`.
//! User code that handled the result as `Result Error StreamId` triggered
//! `IPE-T0001: expected StreamId, found Int`.
//!
//! The fix changes the scheme to `fun(http_request(), task(stream_id()))` where
//! `stream_id()` resolves to the opaque `StreamId` builtin type, and introduces
//! the `IpeStreamId` Rust newtype in the runtime + routes it through `enum_name`
//! in the emitter.
//!
//! This test uses `ipe::emit_ir_text` (parse → canon → types → lower → IR text)
//! which stops before Rust emission — originally chosen to verify the type
//! scheme and lowering without hitting an UNRELATED Http-builder synthesizer
//! limitation (IPE-I0001 on `Http.defaultRequest`'s struct-literal emission,
//! since this fixture's `req` has no consumer that spells out the
//! `HttpRequest` fieldset in an annotation). That limitation is closed (see
//! `golden_m5b_http.rs`'s `http_default_request_emits_without_signature_consumer`
//! for the dedicated regression) — `http_stream_open_full_emit_succeeds` below
//! now exercises the full `ipe::build` path this fixture originally had to
//! route around.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Parse + type-check + lower `tests/golden/http_stream_id/Main.ipe`.
/// Asserts the pipeline succeeds (no IPE-T0001 from mismatched `Int` vs
/// `StreamId`, and no `callee_arity` panic from a missing lower arm).
#[test]
fn http_stream_open_returns_stream_id_not_int() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("http_stream_id")
        .join("Main.ipe");

    let result = ipe::emit_ir_text(&entry);
    assert!(
        result.is_ok(),
        "HttpStream.open typed as `Task Error StreamId` must pass type-check + lower \
         without IPE-T0001; got: {:?}",
        result.err()
    );
}

/// Companion to the IR-text check above: `req = Http.defaultRequest url`
/// here is passed straight to `HttpStream.open` and never read as a field
/// nor passed through any signature that spells out the `HttpRequest`
/// fieldset — a shape prone to IPE-I0001 during Rust
/// emission (see `golden_m5b_http.rs`'s
/// `http_default_request_emits_without_signature_consumer`). Default-gate,
/// emit-only (no `IPE_E2E`, no cargo build needed).
#[test]
fn http_stream_open_full_emit_succeeds() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("http_stream_id")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i148_http_stream_id_full_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for HttpStream.open's HttpRequest arg (no \
         field-read consumer, no signature spelling out the fieldset); \
         got: {:?}",
        built.err()
    );
}
