//! Regression lock: `Arc<dyn Fn(String) -> M + Send + Sync>` bound.
//!
//! A CLOSURE (lambda, not a top-level fn item) passed to `Ui.onInput` must
//! compile, build, and run.  This locks the emitter's T6 Arc-wrap path for
//! String-carrying events: the emitted code is
//!
//! ```rust
//! ipe_runtime::ui::helpers::ui_on_input_(
//!     ::std::sync::Arc::new(move |_x| ({closure})(_x))
//! )
//! ```
//!
//! where `{closure}` is the emitted lambda.  Without `Arc::new(move …)` the
//! closure does not satisfy `Arc<dyn Fn(String) -> M + Send + Sync + 'static>`
//! and cargo rejects it with E0308.
//!
//! Without the fix, fn-item handlers worked (captured no state, auto-coerced to fn ptr);
//! closure handlers exposed the bare `Fn(String) -> M` → missing `Send + Sync`
//! bounds (or the Arc wrap was absent entirely).
//!
//! ## Oracle provenance
//!
//! `oracle_divergence = true`: there is no external oracle for this shape, so
//! the golden holds Ipê's own correct output — the Rust-backend HTML with the
//! input event wired.
//!
//! ## What is tested
//!
//! * `KernelFn::UiOnInput` emits `ui_on_input_(Arc::new(move |_x| f(_x)))`
//!   where `f` is a closure expression (not a top-level fn name).
//! * The emitted Rust project builds without `E0308` or missing-trait-bound errors.
//! * The rendered HTML contains `data-ipe-on="input"` (event wired) and the
//!   text node `input here`.
//! * The binary exits 0.
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m7_stdui_oninput_closure
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Compile / build / run `tests/golden/stdui_oninput_closure/Main.ipe` and
/// return the golden directory together with the run outcome.  Gated on `IPE_E2E=1`.
fn build_run_oninput_closure() -> (PathBuf, crate::support::RunOutcome) {
    let root = repo_root();
    let dir = root
        .join("tests")
        .join("golden")
        .join("stdui_oninput_closure");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m7_stdui_oninput_closure_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for stdui_oninput_closure: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("stdui_oninput_closure", &out);
    (dir, outcome)
}

/// Regression lock: `onInput` with a closure handler must
/// compile (cargo exit 0), emit HTML with the event attribute wired, and
/// the binary must exit 0.
#[test]
fn oninput_closure_arc_wrap_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let (dir, outcome) = build_run_oninput_closure();
    let html = &outcome.stdout;

    // The input event must be rendered — confirms Arc<dyn Fn(String)->M> was
    // correctly emitted and the type-checker accepted it.
    assert!(
        html.contains("data-ipe-on=\"input\"") || html.contains("ipe-input"),
        "stdui_oninput_closure: input event must be rendered in HTML output\n--- actual ---\n{html}"
    );
    // The text content must be present.
    assert!(
        html.contains("input here"),
        "stdui_oninput_closure: text 'input here' must be in HTML output\n--- actual ---\n{html}"
    );
    // The wrapping div from ui_layout must exist.
    assert!(
        html.contains("display:flex"),
        "stdui_oninput_closure: ui_layout must emit flex container\n--- actual ---\n{html}"
    );

    crate::support::assert_go_parity("stdui_oninput_closure", &dir, html);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "stdui_oninput_closure: must exit 0"
    );
}
