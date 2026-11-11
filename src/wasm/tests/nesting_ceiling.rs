//! The in-browser compiler holds every nesting shape the parser admits.
//!
//! Each shape of the shared `nesting_shapes` table is compiled through
//! [`ipe_wasm::compile`] at the deepest count the parser admits, and one level
//! deeper. At the ceiling the program compiles (or, for a shape whose types pass
//! the type ceiling first, is refused by the type checker); one level deeper it
//! is refused by the parser with its nesting code. Neither may trap.
//!
//! Built for wasm32 and run under node by `wasm-bindgen-test-runner`, the
//! file proves the linked shadow stack and the engine's own stack both hold the
//! front end at the ceiling, and that the module's stack is laid out from
//! `nesting.rs`. Natively the same shapes run through the compile thread.
//!
//! ```sh
//! CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
//!     cargo test -p ipe-wasm --target wasm32-unknown-unknown --release --test nesting_ceiling
//! ```

use ipe_diagnostics::IPE_P0003;
use nesting_shapes::{AtCeiling, shapes};

/// The shadow stack the test harness may already hold when a test body starts.
#[cfg(target_arch = "wasm32")]
const HARNESS_FRAMES: usize = 128 << 10;

/// The module's shadow stack sits first in linear memory, as large as
/// `nesting.rs` declares: a local of a test body lies just under its top.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test::wasm_bindgen_test]
fn layout_is_stack_first_and_linked_from_the_ssot() {
    use ipe_diagnostics::nesting::WASM_SHADOW_STACK_BYTES;
    let probe = core::hint::black_box(0_u8);
    let at = core::hint::black_box(&raw const probe).addr();
    assert!(
        at < WASM_SHADOW_STACK_BYTES && at > WASM_SHADOW_STACK_BYTES - HARNESS_FRAMES,
        "a local at {at} must lie just under the {WASM_SHADOW_STACK_BYTES}-byte shadow stack's top"
    );
}

/// Every shape at its ceiling compiles, or is refused by the type checker when
/// its types pass the type ceiling first, without trapping either stack.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn at_ceiling_shapes_compile_in_the_engine() {
    for (name, shape, deepest, expected) in shapes() {
        let outcome = ipe_wasm::compile(&shape(deepest).src);
        match expected {
            AtCeiling::Builds => assert!(
                outcome.ok,
                "{name}: depth {deepest} must compile in the browser:\n{}",
                outcome.diagnostics
            ),
            AtCeiling::TypeRefused => assert!(
                !outcome.ok
                    && outcome.diagnostics.contains("IPE-T")
                    && !outcome.diagnostics.contains(IPE_P0003.as_str()),
                "{name}: depth {deepest} must be refused by the type checker:\n{}",
                outcome.diagnostics
            ),
        }
    }
}

/// One level past every shape's ceiling is refused by the parser's nesting
/// code, never by a trap or a later stage.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn one_past_the_ceiling_is_refused_not_trapped() {
    for (name, shape, deepest, _) in shapes() {
        let outcome = ipe_wasm::compile(&shape(deepest + 1).src);
        assert!(
            !outcome.ok && outcome.diagnostics.contains(IPE_P0003.as_str()),
            "{name}: depth {} must be refused by the parser with {}:\n{}",
            deepest + 1,
            IPE_P0003.as_str(),
            outcome.diagnostics
        );
    }
}
