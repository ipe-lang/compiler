//! Ipe.Ui type-annotation smoke test —
//! `Ui.layout` inside a function annotated `Msg -> Html Msg` must produce
//! well-typed emitted Rust (no `E0308` from cargo).
//!
//! The golden compiles `tests/golden/stdui_msg/Main.ipe` through `ipe`,
//! builds the emitted Rust project with the shared cargo target, runs the
//! binary, and checks its stdout against the cached oracle
//! (`tests/golden/stdui_msg/oracle.meta` + `expected_go.txt`).
//! The test is gated on `IPE_E2E=1`; without it it returns early.
//!
//! ## Oracle provenance
//!
//! This is a DIVERGENCE golden (`oracle_divergence = true`).  The reference
//! compiler emits a different HTML skeleton.  `expected_go.txt` therefore holds
//! ipe's OWN output — the Rust-backend correct rendering — rather than the golden
//! oracle.  The divergence is documented in
//! `tests/golden/stdui_msg/sanctioned.divergence`.
//!
//! ## What is tested
//!
//! * `ir_type_from_canon` handles `Html Msg` in type annotations, producing
//!   `IrType::Ui { ctor: UiCtor::Html, msg: IrType::Enum { Msg, [] } }`.
//! * `KernelFn::UiLayout` emits `ipe_runtime::ui::render::ui_layout(attrs_s, elem_s)`
//!   with no turbofish — Rust infers `M = MainMsg` bottom-up from the concrete
//!   element tree.  (The old `with_ui_msg` / `enclosing_ui_msg()` mechanism
//!   was removed; M-propagation is now purely bottom-up from event payloads.)
//! * The rendered HTML is correct (the annotation ensures the no-event case
//!   still produces a valid monomorphisation).
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m7_stdui_msg
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Compile / build / run `tests/golden/stdui_msg/Main.ipe` and return the
/// golden directory together with the run outcome. Gated on `IPE_E2E=1`.
fn build_run_msg() -> (PathBuf, crate::support::RunOutcome) {
    let root = repo_root();
    let dir = root.join("tests").join("golden").join("stdui_msg");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m7_stdui_msg_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for stdui_msg: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("stdui_msg", &out);
    (dir, outcome)
}

/// Full E2E smoke test: `Ui.layout` inside a `Msg -> Html Msg` function must
/// compile, build, run, and produce the cached expected HTML.
/// Divergence golden — the expected value is ipe's own correct output.
#[test]
fn ui_layout_turbofish_uses_enclosing_msg_type() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let (dir, outcome) = build_run_msg();
    let html = &outcome.stdout;

    // The output must contain the typed text node.
    assert!(
        html.contains("typed"),
        "stdui_msg: text 'typed' must be present in output\n--- actual ---\n{html}"
    );
    // Font.bold must be applied.
    assert!(
        html.contains("font-weight:700"),
        "stdui_msg: Font.bold must render font-weight:700\n--- actual ---\n{html}"
    );

    crate::support::assert_go_parity("stdui_msg", &dir, html);
    assert_eq!(outcome.exit_code, Some(0), "stdui_msg: must exit 0");
}
