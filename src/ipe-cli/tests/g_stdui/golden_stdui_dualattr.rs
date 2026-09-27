//! Dual-attribute bridge gate —
//! mixing `Ipe.Ui` typed attributes (`Font.bold`, `Background.color`) with a
//! `Ipe.Html` node (`Html.div` / `Html.text`) embedded via `Ui.html`.
//!
//! The golden compiles `tests/golden/stdui_dualattr/Main.ipe` through
//! `ipe`, builds the emitted Rust project with the shared cargo target, runs
//! the binary, and checks its stdout against the cached oracle
//! (`tests/golden/stdui_dualattr/oracle.meta` + `expected_go.txt`).
//! The test is gated on `IPE_E2E=1`; without it it returns early.
//!
//! ## Oracle provenance
//!
//! This is a DIVERGENCE golden (`oracle_divergence = true`).  The reference
//! compiler emits a different HTML skeleton.  `expected_go.txt` therefore holds
//! ipe's OWN output — the Rust-backend correct rendering — rather than the golden
//! oracle.  The divergence is documented in
//! `tests/golden/stdui_dualattr/sanctioned.divergence`.
//!
//! ## What is tested
//!
//! * `Ui.el [ Font.bold, Background.color (Ui.rgb 0 128 0) ]` emits
//!   `font-weight:700;background-color:rgba(0,128,0,1)` on one element.
//! * `Ui.html (Html.div [] [ Html.text "html-node" ])` bridges a raw Html node
//!   into the Ipe.Ui element tree — the `UiCtor::Html` / `UiHtml` bridge path.
//! * `Ui.column [ Ui.spacing 8 ]` emits `gap:8px`.
//! * No internal direction markers (`__col`, `__row`) leak into the output.
//! * The full path `Ipe.Ui` + `Ipe.Html` kernel mix builds and runs.
//!
//! ## Scope note
//!
//! The full dual-Attribute+Event golden (mixing typed Ipe.Ui attributes and
//! Html.Events event handlers) is blocked by the `UiCtor::HtmlEvent`
//! emit-arm gap (IPE-I0###).  This reduced golden avoids event kernels and
//! exercises only the attribute + Html-node bridge.
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m7_stdui_dualattr
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Compile / build / run `tests/golden/stdui_dualattr/Main.ipe` and return
/// the golden directory together with the run outcome. Gated on `IPE_E2E=1`.
fn build_run_dualattr() -> (PathBuf, crate::support::RunOutcome) {
    let root = repo_root();
    let dir = root.join("tests").join("golden").join("stdui_dualattr");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m7_stdui_dualattr_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else {
        return (
            dir,
            crate::support::RunOutcome {
                stdout: String::new(),
                exit_code: None,
            },
        );
    };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for stdui_dualattr: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("stdui_dualattr", &out);
    (dir, outcome)
}

/// Full E2E smoke test: dual-attribute Ipe.Ui + Ipe.Html bridge must compile,
/// build, run, and produce the cached expected HTML.
/// Divergence golden — the expected value is ipe's own correct output.
#[test]
fn dualattr_stdui_attributes_and_html_node_bridge_render_correctly() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let (dir, outcome) = build_run_dualattr();
    let html = &outcome.stdout;

    // Font.bold + Background.color must both be applied to the same element.
    assert!(
        html.contains("font-weight:700"),
        "stdui_dualattr: Font.bold must render font-weight:700\n--- actual ---\n{html}"
    );
    assert!(
        html.contains("background-color:rgba(0,128,0,1)"),
        "stdui_dualattr: Background.color must render correctly\n--- actual ---\n{html}"
    );
    // The Html.div / Html.text bridge must be present.
    assert!(
        html.contains("html-node"),
        "stdui_dualattr: Ui.html bridge node must be present\n--- actual ---\n{html}"
    );
    // Spacing on the column must be present.
    assert!(
        html.contains("gap:8px"),
        "stdui_dualattr: Ui.column spacing must render gap:8px\n--- actual ---\n{html}"
    );
    // Internal direction markers must NOT leak into output.
    assert!(
        !html.contains("__col") && !html.contains("__row"),
        "stdui_dualattr: direction markers must not leak into HTML output\n--- actual ---\n{html}"
    );

    crate::support::assert_go_parity("stdui_dualattr", &dir, html);
    assert_eq!(outcome.exit_code, Some(0), "stdui_dualattr: must exit 0");
}
