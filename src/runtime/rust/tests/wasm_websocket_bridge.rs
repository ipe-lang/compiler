//! Browser-run proof of the M4 `Ipe.WebSocket` client substitute's Sub-tier
//! receive surface (`sub_subscribe_ws_open`/`_message`/`_close`): the
//! Layer-1 wasm gate used to deny `Sub_subscribeWebSocket` because it had
//! no wasm32 runtime symbol; this file is the headless-browser
//! (`wasm-bindgen-test`, real Chromium via `wasm-bindgen-test-runner` +
//! `chromedriver`) proof that the symbol it now has actually works, not
//! just compiles.
//!
//! Needs a live counterparty: a native echo server on `127.0.0.1:8033`
//! (path `/ws`) that echoes every text frame prefixed `"echo: "`. CI's
//! `browser-e2e` job starts `tools/scripts/wasm-test/ws_echo_server.py` and runs:
//!
//! ```sh
//! CHROMEDRIVER=chromedriver cargo test -p ipe-runtime-rust \
//!     --target wasm32-unknown-unknown --features wasm-client --test wasm_websocket_bridge
//! ```
//!
//! A real browser socket to a real server (not a mock) is the point: it
//! proves `web_sys::WebSocket`'s `onopen`/`onmessage`/`onclose` handler
//! wiring in `ws_client.rs`'s wasm32 arm actually round-trips a frame,
//! which no native-target test can exercise.

#![cfg(all(target_arch = "wasm32", feature = "wasm-client"))]

use std::cell::RefCell;
use std::rc::Rc;

use ipe_runtime_rust::core::IpeResult;
use ipe_runtime_rust::tea::IpeSub;
use ipe_runtime_rust::ws_client::{web_socket_close, web_socket_connect, web_socket_send};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

const ECHO_URL: &str = "ws://127.0.0.1:8033/ws";

/// Teardown thunk a started `IpeSub::Source` hands back.
type Teardown = Box<dyn FnOnce()>;

/// Start an `IpeSub::Source` by hand, returning its teardown.
///
/// `None` when `sub` is any other variant; callers assert on it. No TEA
/// scheduler runs here: driving the Source directly is the narrowest proof of
/// the exact runtime fn under test.
fn drive_source<M: 'static>(sub: IpeSub<M>, emit: Rc<dyn Fn(M)>) -> Option<Teardown> {
    if let IpeSub::Source(spawn) = sub {
        Some(spawn(emit))
    } else {
        None
    }
}

/// Busy-poll-with-yield until `pred` is true or `attempts` is exhausted.
///
/// `wasm_bindgen_test`'s async support has no timer primitive of its own, so
/// this drives the event loop forward by awaiting a short `setTimeout`
/// promise between polls.
async fn wait_until(mut attempts: u32, mut pred: impl FnMut() -> bool) -> bool {
    while attempts > 0 {
        if pred() {
            return true;
        }
        yield_to_browser().await;
        attempts = attempts.saturating_sub(1);
    }
    pred()
}

async fn yield_to_browser() {
    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        // Without a `Window` (or a timer) the promise rejects at once, so the
        // poll loop runs out of attempts and the caller's assertion fails
        // instead of hanging.
        let scheduled = web_sys::window().is_some_and(|window| {
            window
                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 20)
                .is_ok()
        });
        if !scheduled {
            let _ = reject.call0(&wasm_bindgen::JsValue::NULL);
        }
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

#[wasm_bindgen_test]
async fn onopen_onmessage_onclose_round_trip_against_a_live_server() {
    // Task-tier connect — the M4 substitute already tagged `WasmClient`
    // before this change; unaffected here except as the socket this test's
    // new Sub-tier coverage subscribes against.
    let connected = web_socket_connect::<String>(ECHO_URL.to_owned()).await;
    assert!(
        matches!(connected, IpeResult::Ok(_)),
        "WebSocket.connect against the live echo server must resolve: {connected:?}"
    );
    let IpeResult::Ok(socket_id) = connected else {
        return;
    };

    // ── onOpen: the one-shot Sub-tier receive kernel this commit adds ──────
    let opened = Rc::new(RefCell::new(false));
    let opened_w = Rc::clone(&opened);
    let open_emit: Rc<dyn Fn(())> = Rc::new(move |()| *opened_w.borrow_mut() = true);
    let open_teardown = drive_source(
        ipe_runtime_rust::ws_client::sub_subscribe_ws_open(socket_id, ()),
        open_emit,
    );
    assert!(open_teardown.is_some(), "onOpen must be an IpeSub::Source");
    let Some(open_teardown) = open_teardown else {
        return;
    };
    assert!(
        wait_until(100, || *opened.borrow()).await,
        "onOpen never fired against a live socket"
    );

    // ── onMessage: send a frame, expect the echo server's "echo: " prefix ──
    let received: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let received_w = Rc::clone(&received);
    let msg_emit: Rc<dyn Fn(String)> = Rc::new(move |s: String| received_w.borrow_mut().push(s));
    let message_teardown = drive_source(
        ipe_runtime_rust::ws_client::sub_subscribe_ws_message(socket_id, |m| match m {
            ipe_runtime_rust::ws_client::WsClientMessage::Text(t) => t,
            ipe_runtime_rust::ws_client::WsClientMessage::Binary(_) => {
                "<binary — unexpected in this test>".to_owned()
            }
        }),
        msg_emit,
    );
    assert!(
        message_teardown.is_some(),
        "onMessage must be an IpeSub::Source"
    );
    let Some(message_teardown) = message_teardown else {
        return;
    };

    let sent =
        web_socket_send::<String>(socket_id, "hello-from-wasm-bindgen-test".to_owned()).await;
    assert!(
        matches!(sent, IpeResult::Ok(_)),
        "WebSocket.send on an open socket must resolve: {sent:?}"
    );

    assert!(
        wait_until(100, || received
            .borrow()
            .iter()
            .any(|m| m == "echo: hello-from-wasm-bindgen-test"))
        .await,
        "onMessage never delivered the server's echo (got {:?})",
        received.borrow()
    );

    // ── onClose: closing from this side must still surface a close event ──
    let closed = Rc::new(RefCell::new(false));
    let closed_w = Rc::clone(&closed);
    let close_emit: Rc<dyn Fn(ipe_runtime_rust::ws_client::WsCloseCode)> =
        Rc::new(move |_code| *closed_w.borrow_mut() = true);
    let close_teardown = drive_source(
        ipe_runtime_rust::ws_client::sub_subscribe_ws_close(socket_id, |code| code),
        close_emit,
    );
    assert!(
        close_teardown.is_some(),
        "onClose must be an IpeSub::Source"
    );
    let Some(close_teardown) = close_teardown else {
        return;
    };

    let closed_result = web_socket_close::<String>(socket_id).await;
    assert!(
        matches!(closed_result, IpeResult::Ok(_)),
        "WebSocket.close must resolve: {closed_result:?}"
    );

    assert!(
        wait_until(100, || *closed.borrow()).await,
        "onClose never fired after WebSocket.close"
    );

    open_teardown();
    message_teardown();
    close_teardown();
}
