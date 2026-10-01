//! Sentinel: genuine bottom-up M-propagation for Ipe.Ui event subtrees.
//!
//! This golden covers: a non-view function (`staticHtml : String`)
//! that renders an event-bearing subtree (`el [onClick Bump] (text "x")`) must
//! compile, build, and run without a cargo E0308.
//!
//! A `UiLayout` arm emitting `ui_layout::<()>(…)` (an
//! `enclosing_ui_msg().unwrap_or("()")` fallback) while the event kernel emits
//! `Attribute<MainMsg>` produces a type mismatch. Instead, M is inferred
//! bottom-up from the event's concrete `Attribute<MainMsg>` with no turbofish.
//!
//! ## Oracle provenance
//!
//! `oracle_divergence = true`: there is no external oracle for this shape, so
//! the golden holds Ipê's own correct output — the Rust-backend HTML with the
//! click event wired.
//!
//! ## What is tested
//!
//! * `ir_type_from_ty` handles `Attribute Msg` in the region-type map
//!   (`SolvedTypes.regions`), producing `IrType::Ui { AttrEvent, msg: MainMsg }`.
//! * `KernelFn::UiOnClick` lowers and emits `ui_on_click_(MainMsg::Bump)` →
//!   `element::Attribute::AttrEvent(EventAttr(OnMsg("click", Bump)))`.
//! * `UiLayout` emits no turbofish; Rust infers `M = MainMsg`
//!   bottom-up from the concrete `Attribute<MainMsg>` element.
//! * The rendered HTML contains `data-ipe-on="click"` and the text node `x`.
//! * The binary exits 0.
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m7_stdui_onclick
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Compile / build / run `tests/golden/stdui_onclick/Main.ipe` and return
/// the golden directory together with the run outcome.  Gated on `IPE_E2E=1`.
fn build_run_onclick() -> (PathBuf, crate::support::RunOutcome) {
    let root = repo_root();
    let dir = root.join("tests").join("golden").join("stdui_onclick");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m7_stdui_onclick_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for stdui_onclick: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("stdui_onclick", &out);
    (dir, outcome)
}

/// Sentinel: `onClick` event in a non-view function must compile, build,
/// run, and produce HTML with the event attribute wired.  M is inferred
/// bottom-up from the event payload — no turbofish fallback to `()`.
#[test]
fn onclick_in_non_view_fn_propagates_m_bottom_up() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let (dir, outcome) = build_run_onclick();
    let html = &outcome.stdout;

    // The click event must be rendered — confirms M=MainMsg not M=().
    assert!(
        html.contains("data-ipe-on=\"click\"") || html.contains("ipe-click"),
        "stdui_onclick: click event must be rendered in HTML output\n--- actual ---\n{html}"
    );
    // The text content must be present.
    assert!(
        html.contains(">x<"),
        "stdui_onclick: text 'x' must be in HTML output\n--- actual ---\n{html}"
    );
    // The wrapping div structure from ui_layout must exist.
    assert!(
        html.contains("display:flex"),
        "stdui_onclick: ui_layout must emit flex container\n--- actual ---\n{html}"
    );

    crate::support::assert_go_parity("stdui_onclick", &dir, html);
    assert_eq!(outcome.exit_code, Some(0), "stdui_onclick: must exit 0");
}
