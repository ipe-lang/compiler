#![cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen_test]
fn runs() {}

#[cfg(feature = "unclaimed")]
#[wasm_bindgen_test]
fn never_runs() {}

mod claimed_mod {
    #[wasm_bindgen_test]
    fn t() {}
}

#[cfg(feature = "unclaimed")]
mod unclaimed_mod {
    #[wasm_bindgen_test]
    fn t() {}
}
