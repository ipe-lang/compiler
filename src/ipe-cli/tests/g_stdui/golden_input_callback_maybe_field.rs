//! Regression lock — THE SEAL for `Ipe.Ui.Input.*` callback fields.
//!
//! Every `Ipe.Ui.Input.*` runtime function (`input_text_`, `input_slider_`,
//! `input_checkbox_`, `input_radio_row_`, …) takes its callback fields
//! (`onChange`, checkbox `icon`) as `Arc<dyn Fn(_) -> _ + Send + Sync + 'static>`.
//! When the `onChange` field is a BARE `Msg`-constructor it eta-expands to a
//! plain lambda that the emitter boxes with `Box::new` (the non-Server/WS `Fun`
//! default in `emit_lambda` / `wants_arc_ctor`) — a `Box<dyn Fn(_) -> _ + Send>`
//! that does NOT fill the `Arc<.. + Send + Sync>` parameter slot. ipe accepted
//! the program (exit 0) but the emitted Rust failed `cargo build` with E0308 —
//! a seal break (the `examples/37-composite-live-shop` blocker).
//!
//! The fix (mirroring the reference's uniform-Arc callback policy and this
//! crate's existing `ui_on_input_` / `ui_on_change_` arms) eta-wraps each Input
//! callback field in `::std::sync::Arc::new(move |_x| (f)(_x))` at the
//! call-argument boundary, so it fills the Arc slot regardless of how the field
//! expression lowered.
//!
//! The two non-E2E goldens for these kernels (`golden_i148_input_slider`,
//! `golden_i155_input_radio_row`) only check ipe lowering — they never run
//! `cargo build`, so they could not catch this cargo-time E0308. This one DOES
//! cargo-build and run the emitted binary, which is the only test shape that
//! can lock the seal for the Input-callback path.
//!
//! ## Oracle provenance
//!
//! The reference (`ipe dev`) does not expose `Html.htmlRender` and exits 1 on
//! this source, so there is no golden-verified assertion here. The test asserts the
//! emitted Rust compiles (`cargo build` exit 0 — enforced inside
//! `build_and_run_emitted`) and the binary runs (exit 0) and renders the four
//! Input controls.
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m7_input_callback_maybe_field
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Compile / build / run `tests/golden/input_callback_maybe_field/Main.ipe`.
/// Gated on `IPE_E2E=1`. The `cargo build` step is where the seal is enforced:
/// a `Box`-vs-`Arc` callback mismatch fails the build (E0308), failing this
/// test hard.
fn build_run_input_callback() -> crate::support::RunOutcome {
    let root = repo_root();
    let dir = root
        .join("tests")
        .join("golden")
        .join("input_callback_maybe_field");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m7_input_callback_maybe_field_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for input_callback_maybe_field: {:?}",
        built.err()
    );

    crate::support::build_and_run_emitted("input_callback_maybe_field", &out)
}

/// A bare-constructor `onChange` (and checkbox `icon`) on every
/// `Ipe.Ui.Input.*` cfg record must Arc-wrap so the emitted Rust `cargo build`s
/// (exit 0) and the binary runs (exit 0), rendering all four Input controls.
#[test]
fn input_callback_bare_ctor_arc_wraps_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let outcome = build_run_input_callback();
    let html = &outcome.stdout;

    // The text input, its placeholder, and the checkbox must render — proving
    // the Arc-wrapped callbacks type-checked and the controls were emitted.
    assert!(
        html.contains("Search…"),
        "input placeholder must render (Just Input.placeholder Maybe field)\n--- actual ---\n{html}"
    );
    assert!(
        html.contains("data-ipe-on=\"input\"") || html.contains("ipe-input"),
        "text/slider input event must be wired\n--- actual ---\n{html}"
    );
    assert!(
        html.contains("Notify"),
        "checkbox label must render (icon Arc-callback field)\n--- actual ---\n{html}"
    );

    assert_eq!(
        outcome.exit_code,
        Some(0),
        "input_callback_maybe_field: binary must exit 0"
    );
}
