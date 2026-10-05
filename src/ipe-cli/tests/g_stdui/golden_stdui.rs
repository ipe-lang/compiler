//! `Ipe.Ui` / `Ipe.Html` gate —
//! `Ui.layout` / `Ui.column` / `Ui.el` / `Ui.text` / `Ui.spacing` /
//! `Background.color` / `Font.bold` / `Html.htmlRender` end-to-end smoke test.
//!
//! The golden compiles `tests/golden/stdui/Main.ipe` through `ipe`, builds
//! the emitted Rust project with the shared cargo target, runs the binary, and
//! checks its stdout against the cached oracle
//! (`tests/golden/stdui/oracle.meta` + `expected_go.txt`).
//! The test is gated on `IPE_E2E=1`; without it it returns early.
//!
//! ## Oracle provenance
//!
//! This is a DIVERGENCE golden (`oracle_divergence = true`).  The reference
//! compiler emits a different HTML skeleton (separate `<style>` reset block,
//! `min-height`, trailing spaces).  `expected_go.txt` therefore holds ipe's
//! OWN output — the Rust-backend correct rendering — rather than the golden oracle.
//! The divergence is documented in `tests/golden/stdui/sanctioned.divergence`.
//!
//! ## What is tested
//!
//! * `Ipe.Html` qualifier (`Ipe.Html.htmlRender`) resolves correctly via the
//!   qualifier-alias table (env.rs `QUALIFIER_ALIASES`).
//! * `Ipe.Ui` qualifier (`Ipe.Ui.layout`, `Ipe.Ui.column`, etc.) resolves
//!   correctly.
//! * `Ui.column [Ui.spacing N]` emits `display:flex;flex-direction:column;gap:N`.
//! * `Ui.el [Font.bold]` emits `font-weight:700`.
//! * `Ui.el [Background.color (Ui.rgb r g b)]` emits `background-color:rgba(r,g,b,1)`.
//! * Internal direction markers (`__col`, `__row`) do NOT leak into HTML output.
//! * The emitted Rust project builds and produces a correctly-shaped HTML string.
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m7_stdui
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Compile / build / run `tests/golden/stdui/Main.ipe` and return the golden
/// directory together with the run outcome. Gated on `IPE_E2E=1`.
fn build_run_m7() -> (PathBuf, crate::support::RunOutcome) {
    let root = repo_root();
    let dir = root.join("tests").join("golden").join("stdui");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m7_stdui_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for stdui: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("stdui", &out);
    (dir, outcome)
}

/// Full E2E smoke test: `Ipe.Ui` + `Ipe.Html.htmlRender` must compile, build,
/// run, and produce the cached expected HTML.  Divergence golden — the expected
/// value is ipec's own correct output, not the golden oracle.
#[test]
fn stdui_layout_column_el_text_renders_html() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let (dir, outcome) = build_run_m7();
    crate::support::assert_go_parity("stdui", &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "stdui: must exit 0");
}
