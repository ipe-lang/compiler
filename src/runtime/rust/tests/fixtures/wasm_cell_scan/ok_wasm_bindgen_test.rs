#![cfg(all(target_arch = "wasm32", feature = "wasm-client"))]

use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen_test]
fn t() {}
