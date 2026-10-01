//! Regression guard for the `wants_arc_ctor` structural-dispatch fix.
//!
//! ## The bug this pins
//!
//! Choosing the smart-pointer constructor by testing the RENDERED type string
//! with `typed.starts_with("Arc<")` is unsound: `render_type` emits a
//! `ServerHandler<E>` slot as the type-ALIAS name `"ServerHandler<IpeError>"`,
//! NOT the expanded `"Arc<dyn Fn…>"` — so the string test misclassifies every
//! inline `Server.post path (\req -> …)` handler lambda as `Box`, emitting
//! `Box::new(move |req: ServerRequest| …)` into an `Arc<dyn Fn>` field. `ipe`
//! still exits 0, but the emitted crate fails `cargo build` with E0308
//! (`expected Arc…, found Box…`) — a break of THE SEAL (ipe exit-0 must imply
//! the emitted Rust cargo-builds). So both `emit_lambda` and
//! `emit_func_value` route through the shared structural `wants_arc_ctor` helper
//! that matches on the `IrType` shape, never the rendered string.
//!
//! ## Why this test is NOT `IPE_E2E`-gated
//!
//! The full cargo-build proof lives in `server_e2e.rs` (`IPE_E2E`), but that
//! suite does not run in the default `cargo nextest` gate — which is exactly
//! how the regression reached `master` green. This test needs only the emitted
//! Rust text (no cargo build), so it runs in the DEFAULT gate and can never be
//! silently regressed again. It reuses the existing
//! `server_request_accessors` fixture, whose sole lambda is the inline
//! `Server.post "/introspect/:tag" (\req -> …)` handler.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn move_closure_lines(src: &str) -> String {
    src.lines()
        .filter(|l| l.contains("::new(move |") || l.contains("ServerHandler"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The inline `Server.post path (\req -> …)` handler lambda must be boxed with
/// `Arc::new` (the `ServerHandler` field is `Arc<dyn Fn + Send + Sync>`), never
/// `Box::new`. The fixture contains exactly one lambda — the handler — so the
/// emitted crate must contain an `Arc::new(move |` and no `Box::new(move |`.
#[test]
fn server_handler_lambda_boxes_with_arc_not_box() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("server_request_accessors")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_l0114_server_handler_arc");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for the server-handler fixture: {:?}",
        built.err()
    );

    let main_rs = crate::support::read_all_emitted_src(&out);

    assert!(
        main_rs.contains("Arc::new(move |"),
        "handler lambda must be boxed with `Arc::new` (ServerHandler is \
         Arc<dyn Fn>). wants_arc_ctor must dispatch on the IrType structure, \
         not the rendered `ServerHandler<E>` alias string.\n\
         --- move-closure / ServerHandler lines ---\n{}",
        move_closure_lines(&main_rs)
    );
    assert!(
        !main_rs.contains("Box::new(move |"),
        "the fixture's only lambda is the handler — any `Box::new(move |` means \
         it was misboxed into the Arc<dyn Fn> ServerHandler slot (E0308 SEAL \
         break).\n--- move-closure / ServerHandler lines ---\n{}",
        move_closure_lines(&main_rs)
    );
}

fn ws_onerror_lines(src: &str) -> String {
    src.lines()
        .filter(|l| l.contains("on_error") || l.contains("main_on_error"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The WS `onError` callback — `Fn(WsHandle, Error) -> IpeTask<()>` — fills an
/// `Arc<dyn Fn(WsHandle, E)>` setter slot, so it must box with `Arc::new`. Its
/// second param is the error type (NOT `String` like `onMessage`), the shape
/// that `wants_arc_ctor` / `render_type` originally omitted → generic
/// `Box<dyn Fn>` → ipe-0-then-cargo-fail E0308. Emit-only guard, default gate.
#[test]
fn ws_on_error_callback_boxes_with_arc_not_box() {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("ws_onerror")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_l0114_ws_onerror_arc");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for the WS onError fixture: {:?}",
        built.err()
    );

    let main_rs = crate::support::read_all_emitted_src(&out);

    // `callee_name` (`emit_expr.rs`) emits every top-level function reference
    // as an absolute `crate::`-qualified path (closes the E0618 local-shadow
    // class — a `let` binder can never shadow an absolute path), so the
    // reference reads `crate::main_on_error`, not the bare name.
    assert!(
        main_rs.contains("Arc::new(crate::main_on_error)"),
        "onError callback must box with `Arc::new` (setter takes Arc<dyn Fn>).\n\
         --- on_error lines ---\n{}",
        ws_onerror_lines(&main_rs)
    );
    assert!(
        !main_rs.contains("Box::new(crate::main_on_error)"),
        "onError boxed with `Box::new` into the Arc<dyn Fn> setter slot = E0308 \
         SEAL break.\n--- on_error lines ---\n{}",
        ws_onerror_lines(&main_rs)
    );
}
