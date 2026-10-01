//! Browser-run proof of the `Ipe.Ffi.Js` typed-port client substitute
//! (`js_send` / `js_subscribe`): the Layer-1 wasm gate used to deny the port
//! because it had no wasm32 runtime symbol wired into the sink; this file is the
//! headless-browser (`wasm-bindgen-test`, real Chromium via
//! `wasm-bindgen-test-runner` + `chromedriver`) proof that the substitute
//! actually round-trips a frame in-tab, not just compiles.
//!
//! No external counterparty is needed — a port is in-process on wasm: the test
//! installs a `window.ipeOnReceive` capture for the OUTBOUND direction and calls
//! `js_port::push_inbound` (the seam `window.ipe.send` funnels into) for the
//! INBOUND direction, exercising the exact runtime fns the gate now allows.
//!
//! ```sh
//! CHROMEDRIVER=chromedriver cargo test -p ipe-runtime-rust \
//!     --target wasm32-unknown-unknown --features wasm-client --test wasm_js_port_bridge
//! ```

#![cfg(all(target_arch = "wasm32", feature = "wasm-client"))]

use std::cell::RefCell;
use std::rc::Rc;

use ipe_runtime_rust::error::IpeError;
use ipe_runtime_rust::js_port::{js_send, js_subscribe, push_inbound};
use ipe_runtime_rust::json::{Decoder, json_decode_int};
use ipe_runtime_rust::tea::{IpeCmd, IpeSub};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

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

fn int_decoder() -> Decoder<IpeError, i64> {
    json_decode_int()
}

/// INBOUND: a clean seal frame pushed through `push_inbound` decodes and emits;
/// a malformed / wrong-typed frame is dropped whole (no panic, no partial).
#[wasm_bindgen_test]
fn inbound_decodes_clean_and_drops_malformed() {
    let got: Rc<RefCell<Vec<i64>>> = Rc::new(RefCell::new(Vec::new()));
    let got_w = Rc::clone(&got);
    let emit: Rc<dyn Fn(i64)> = Rc::new(move |m| got_w.borrow_mut().push(m));
    let teardown = drive_source(js_subscribe::<i64, i64, _>(int_decoder(), |a| a), emit);
    assert!(teardown.is_some(), "js_subscribe must be an IpeSub::Source");
    let Some(teardown) = teardown else {
        return;
    };

    // Clean integer frame → decoded and emitted.
    push_inbound("7");
    // Wrong-typed and malformed frames → dropped whole.
    push_inbound("\"not an int\"");
    push_inbound("{not json");

    assert_eq!(
        *got.borrow(),
        vec![7],
        "only the clean frame must be emitted"
    );
    teardown();

    // After teardown the drain is removed: a further push emits nothing.
    push_inbound("9");
    assert_eq!(*got.borrow(), vec![7], "no frame after teardown");
}

/// OUTBOUND: `js_send` seal-encodes the payload and hands the wire string to the
/// page-registered `window.ipeOnReceive` handler. Canonical seal encoding of the
/// integer 42 is the string "42".
#[wasm_bindgen_test]
fn outbound_encodes_and_delivers_to_page_handler() {
    let seen: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let seen_w = Rc::clone(&seen);
    let handler = Closure::<dyn Fn(JsValue)>::new(move |raw: JsValue| {
        if let Some(s) = raw.as_string() {
            seen_w.borrow_mut().push(s);
        }
    });
    let window = web_sys::window();
    assert!(window.is_some(), "run_in_browser must provide a Window");
    let Some(window) = window else {
        return;
    };
    let installed = js_sys::Reflect::set(
        &window,
        &JsValue::from_str("ipeOnReceive"),
        handler.as_ref().unchecked_ref(),
    );
    assert!(installed.is_ok(), "could not install window.ipeOnReceive");
    handler.forget();

    let cmd = js_send::<i64, i64>(42);
    assert!(
        matches!(cmd, IpeCmd::Publish(_)),
        "js_send must build a Publish cmd"
    );
    let IpeCmd::Publish(thunk) = cmd else {
        return;
    };
    // In wasm the origin arg is unused (delivery is in-tab, not per-session).
    let _ = thunk("");

    assert_eq!(
        seen.borrow().last().map(String::as_str),
        Some("42"),
        "outbound frame must be the canonical seal encoding of 42"
    );
}
