//! Four residual `CopyLeaf` / depth / T4-hoist / T7-close holes in the
//! clone-classification gate (see `ipe-121-postmerge-seal-round.md`).
//!
//! Fixes:
//!
//! * **Fix 1** — `clone_class_named_composite`: floors `CopyLeaf` → `CloneOk`
//!   for named composite types (`IrType::Record` / `IrType::Enum`).  Emitted
//!   Rust structs and enums derive `Clone` but NOT `Copy`, so `CopyLeaf` here
//!   is a wrong claim that produces E0525.
//! * **Fix 2** — `rewrite_captured_clones` depth guard: the `NonClone`
//!   callee-position exemption fires only at `depth == 0`.  At depth > 0 the
//!   symbol is consumed by an inner `move` closure → outer `FnOnce` → E0525.
//! * **Fix 3 T4** — `eta_expand_partial` complex-arg hoist: non-Var supplied
//!   args are lifted to `let __ipe_cap_i = <expr>` OUTSIDE the lambda so the
//!   lambda captures the named binding (Clone-wrapped) rather than inlining
//!   the expression with its free vars captured bare.
//! * **Fix 4 T7** — `eta_expand_partial` fail-close: `ir_type_from_ty` → None
//!   emits IPE-L0126 instead of silently passing a bare Var.
//!
//! Green fixtures (c01, c02, c13) require `IPE_E2E=1` for cargo build+run.
//! Gate fixture (c14) runs the diagnostic check always.
//!
//! ```text
//! # green suite:
//! IPE_E2E=1 cargo test -p ipe --test golden_i130_seal
//!
//! # gate check only (fast):
//! cargo test -p ipe --test golden_i130_seal
//! ```

use std::path::{Path, PathBuf};

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Assert that `ipe::build(fixture)` surfaces `expected` as a
/// `CliError::Pipeline` diagnostic.  Runs WITHOUT `IPE_E2E` so the gate
/// checks remain fast in the default CI pass.
#[allow(dead_code)] // retained gate helper for env-gated fixtures
fn assert_ipec_gate(fixture: &str, out_suffix: &str, expected: ipe_diagnostics::Code) {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(out_suffix);
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // runtime unavailable — skip silently rather than fail
    };
    let built = ipe::build(&entry, &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(expected),
        "fixture {fixture}: expected ipec-fail {expected:?}, got build result {built:?}"
    );
}

// ── c01 — enum capture (Fix 1: CopyLeaf misclass for named types) ────────────

/// `List.map (\_ -> colorName color) [1,2,3]` — `color : Color` is an enum
/// with no payload fields.  Without the fix, `clone_class(Enum{args:[]})` returned
/// `CopyLeaf` (composite over empty iterator); the bare capture made the
/// lambda `FnOnce` → E0525 on the second element.
/// Fix 1: `clone_class_named_composite` floors `CopyLeaf` → `CloneOk`;
/// the lambda emits `CloneVar(color)` → re-callable.
/// Expected output: "green,green,green".
#[test]
fn c01_enum_capture_fix1() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("enum_capture")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i130_enum_capture_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for enum_capture: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("enum_capture", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "must exit 0 (was E0525: enum CopyLeaf misclass)"
    );
    assert!(
        outcome.stdout.contains("green,green,green"),
        "List.map over enum capture must produce 'green,green,green'; got:\n{}",
        outcome.stdout
    );
}

// ── c02 — all-Int record capture (Fix 1: CopyLeaf misclass for named types) ──

/// `List.map (\dx -> translate origin dx) [1,2,3]` — `origin : Point` is an
/// all-Int record alias.  Without the fix, `clone_class(Record{fields:[Int,Int]})`
/// returned `CopyLeaf` (all fields `CopyLeaf`); emitted Rust struct derives
/// `Clone` but NOT `Copy` → bare capture → `FnOnce` → `E0525` on second element.
/// Fix 1: `clone_class_named_composite` floors to `CloneOk` for named types.
/// Expected output: "1,5 2,5 3,5".
#[test]
fn c02_record_capture_fix1() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("record_capture")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i130_record_capture_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for record_capture: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("record_capture", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "must exit 0 (was E0525: all-Int record CopyLeaf misclass)"
    );
    assert!(
        outcome.stdout.contains("1,5 2,5 3,5"),
        "List.map over all-Int record capture must produce '1,5 2,5 3,5'; got:\n{}",
        outcome.stdout
    );
}

// ── c13 — complex-expr partial hoist (Fix 3 T4) ──────────────────────────────

/// `let f = mk (String.append base suffix) in f "!" ; f "?"` — the supplied
/// arg `String.append base suffix` is a complex expression (not a bare Var).
/// Without the fix, the expr was inlined into the eta-lambda body; `base` and `suffix`
/// (both String, `CloneOk`) were captured bare → `FnOnce` → `E0525` on second call.
/// Fix 3 T4: hoist to `let __ipe_cap_0 = <expr>` outside the lambda; lambda
/// captures `CloneVar(__ipe_cap_0)` → re-callable.
/// Expected output: "hello! hello?".
#[test]
fn c13_complex_arg_hoist_t4() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("complex_arg_hoist")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i130_complex_arg_hoist_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for complex_arg_hoist: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("complex_arg_hoist", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "must exit 0 (was E0525: complex-expr arg inlined bare → FnOnce)"
    );
    assert!(
        outcome.stdout.contains("hello!"),
        "first call of partial must produce 'hello!'; got:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("hello?"),
        "second call of partial must produce 'hello?' (re-callable); got:\n{}",
        outcome.stdout
    );
}

// ── c14 — nested-lambda fn callee → Arc-promoted, ACCEPTED ───────────────────

/// `composed f = \p -> (\x -> f x) p` — `f : Int -> Int` called as the direct
/// callee INSIDE a nested lambda (depth ≥ 2 from the param's scope).
/// Under the fn-value `Arc`-carrier promotion, `f` is
/// shadow-rebound to the `Clone` `Arc<dyn Fn>` carrier and a clone relayed
/// across each closure boundary, so the shape compiles and runs
/// (`composed (*2) 3` = `6`). A IPE-L0126 gate is sound only under a
/// bare `Box<dyn Fn>` carrier (whose inner `move` closure consumes `f` per
/// call, E0525); the state it would reject is not invalid here.
#[test]
fn c14_nested_lambda_noncopy_promoted_accepts() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("nested_lambda_noncopy")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i130_nested_lambda_noncopy_accept");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "nested-lambda fn callee must Arc-promote and build: {:?}",
        built.err()
    );

    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let outcome = crate::support::build_and_run_emitted("nested_lambda_noncopy", &out);
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
    assert_eq!(outcome.stdout.trim(), "6", "composed (*2) 3 = 6");
}

// ── c05 — StreamWriter capture-forward (clone_class opaque audit) ────────────

/// `Stream.stream (\writer -> emitTick writer 1 |> Task.andThen (\_ ->
/// emitTick writer 2))` — the exact shape of examples/30-sse-server-demo.
///
/// Without the fix, `clone_class(IrType::StreamWriter)` said `NonClone`, so
/// forwarding the captured handle as an argument (not calling it) tripped
/// IPE-L0126.  The runtime type is `#[derive(Clone, Copy)]`
/// (`server_stream.rs:38`) — the classification was an active wrong claim.
/// Same audit flipped ServerRequest/ServerResponse/ServerRoute/ServerCookie/
/// `HttpRequest` to `CloneOk` (all derive `Clone`).
///
/// ipe must exit 0.  The cargo/runtime layer is covered by the
/// 30-sse-server-demo sweep entry (a server fixture can't run-to-exit here).
#[test]
fn c05_streamwriter_capture_forward() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("streamwriter_capture")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("streamwriter_capture");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // runtime unavailable — skip silently rather than fail
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "StreamWriter capture-forward must pass ipec (was IPE-L0126): {:?}",
        built.err()
    );
}

// ── c06 — Stream.stream handler capturing enclosing non-Copy Strings ──

/// `Stream.stream (\writer -> Stream.emit header writer |> ...)` where
/// `header`/`body` are `String`s bound in the handler-constructing function —
/// the exact shape of examples/36-composite-server's Csv-stream export.
///
/// The `StreamStream` emit arm's `move |_x| (handler)(_x)` re-wrap
/// (which rebuilds the box per call to recover the runtime's `+Sync` bound)
/// captures `header`/`body`; if the re-embedded box MOVED them out on the
/// first call the wrapper would degrade to `FnOnce` → `server_stream_stream`'s
/// `Fn` bound rejects it (2x `E0507: cannot move out of a captured variable
/// in an Fn closure`, AFTER `ipe` exit 0 — a SEAL break).
///
/// So the arm pre-clones every free local the handler captures INSIDE the
/// wrapper body, so the box moves fresh clones and the wrapper stays `Fn`.
///
/// Unlike `c05` (ipe exit-0 only), this asserts the EMITTED CRATE cargo-builds
/// — the layer where this surfaces. A listening-server fixture cannot
/// run-to-exit, so a successful `cargo build` IS the acceptance. E2E-gated
/// (`IPE_E2E=1`) so the default fast pass stays emit-only.
#[test]
fn c06_stream_string_capture_seal() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("stream_string_capture")
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("stream_string_capture");
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // runtime unavailable — skip silently rather than fail
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "Stream.stream String-capture must pass ipec: {:?}",
        built.err()
    );

    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    // Build-only: the fixture is a listening server, so it cannot run-to-exit.
    // A successful cargo build is the seal (ipe-0 ⇒ cargo builds).
    let built_bin = e2e_support::build_rust_binary("stream_string_capture", &out);
    assert!(
        built_bin.is_ok(),
        "emitted crate must cargo-build (was 2x E0507 on the stream handler): {}",
        built_bin.as_ref().err().map_or("", String::as_str)
    );
}
