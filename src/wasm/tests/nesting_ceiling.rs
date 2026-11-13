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
//! front end at the ceiling, that the module's stack is laid out from
//! `nesting.rs`, and that the door's shadow-stack need is both enough and
//! enforced. Natively the same shapes run through the compile thread.
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
        (WASM_SHADOW_STACK_BYTES - HARNESS_FRAMES..WASM_SHADOW_STACK_BYTES).contains(&at),
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
        assert_at_ceiling(name, deepest, expected, &outcome);
    }
}

/// Assert `outcome`, the compile of shape `name` at its ceiling `deepest`, is
/// what `expected` pins.
fn assert_at_ceiling(
    name: &str,
    deepest: usize,
    expected: AtCeiling,
    outcome: &ipe_wasm::CompileOutcome,
) {
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

/// Compile `src` with `PAD` bytes of shadow stack held above the door.
///
/// `pad` stays live across the call, so its frame keeps the space: the door
/// is entered with the harness's top less `PAD` left.
#[cfg(target_arch = "wasm32")]
#[inline(never)]
#[allow(clippy::large_stack_arrays)] // the frame's size is the point: it spends shadow stack above the door
fn compile_under<const PAD: usize>(src: &str) -> ipe_wasm::CompileOutcome {
    let pad = [0_u8; PAD];
    core::hint::black_box(&pad);
    let outcome = ipe_wasm::compile(src);
    core::hint::black_box(&pad);
    outcome
}

/// Shadow stack spent above the door so it is entered with its need, plus at
/// most the harness's frames, left.
#[cfg(target_arch = "wasm32")]
const PAD_TO_NEED: usize = ipe_diagnostics::nesting::WASM_SHADOW_STACK_BYTES
    - ipe_diagnostics::nesting::WASM_FRONT_END_SHADOW_NEED
    - HARNESS_FRAMES;

/// Shadow stack spent above the door so a page less than its need is left.
#[cfg(target_arch = "wasm32")]
const PAD_PAST_NEED: usize = ipe_diagnostics::nesting::WASM_SHADOW_STACK_BYTES
    - ipe_diagnostics::nesting::WASM_FRONT_END_SHADOW_NEED
    + ipe_diagnostics::nesting::WASM_PAGE_BYTES;

/// The door's need is enough: entered with only its need left, every shape at
/// its ceiling still compiles without trapping the shadow stack, so whatever
/// the door admits fits.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test::wasm_bindgen_test]
fn at_ceiling_shapes_fit_the_doors_need() {
    for (name, shape, deepest, expected) in shapes() {
        let outcome = compile_under::<PAD_TO_NEED>(&shape(deepest).src);
        assert_at_ceiling(name, deepest, expected, &outcome);
    }
}

/// Entered with less shadow stack than its need, the door refuses before the
/// front end runs, with its typed refusal rather than a diagnostic or a trap.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test::wasm_bindgen_test]
fn door_short_of_its_need_is_refused() {
    use ipe_diagnostics::nesting::WASM_FRONT_END_SHADOW_NEED;
    let required = format!("the {WASM_FRONT_END_SHADOW_NEED} bytes");
    for (name, shape, _, _) in shapes() {
        let outcome = compile_under::<PAD_PAST_NEED>(&shape(1).src);
        assert!(
            !outcome.ok
                && !outcome.diagnostics.contains("IPE-")
                && outcome.diagnostics.contains(&required),
            "{name}: a door short of its need must refuse the stack:\n{}",
            outcome.diagnostics
        );
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
