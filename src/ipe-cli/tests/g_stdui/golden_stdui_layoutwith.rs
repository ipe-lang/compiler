//! `Ui.layoutWith` gate —
//! `Ui.layoutWith` with inline cfg literal must apply both `wrapperAttrs`
//! (padding) and `rootAttrs` (spacing), confirming the cfg is NOT silently
//! dropped (BLOCKER-2 fix).
//!
//! The golden compiles `tests/golden/stdui_layoutwith/Main.ipe` through
//! `ipe`, builds the emitted Rust project with the shared cargo target, runs
//! the binary, and checks its stdout against the cached oracle
//! (`tests/golden/stdui_layoutwith/oracle.meta` + `expected_go.txt`).
//! The test is gated on `IPE_E2E=1`; without it it returns early.
//!
//! ## Oracle provenance
//!
//! This is a DIVERGENCE golden (`oracle_divergence = true`).  The reference
//! compiler emits a different HTML skeleton.  `expected_go.txt` therefore holds
//! ipe's OWN output — the Rust-backend correct rendering — rather than the golden
//! oracle.  The divergence is documented in
//! `tests/golden/stdui_layoutwith/sanctioned.divergence`.
//!
//! ## What is tested
//!
//! * `Ui.layoutWith { wrapperAttrs, rootAttrs }` inline-cfg field extraction
//!   routes to `ui_layout_with_vecs` correctly (BLOCKER-2 fix).
//! * `wrapperAttrs = [ Ui.padding 12 ]` → `padding:12px 12px 12px 12px` on the
//!   outer wrapper `<div>`.
//! * `rootAttrs = [ Ui.spacing 6 ]` → `gap:6px` on the inner root `<div>`.
//! * `Ui.el [ Font.bold ]` → `font-weight:700`.
//! * The cfg is NOT silently dropped.
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m7_stdui_layoutwith
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Compile / build / run `tests/golden/stdui_layoutwith/Main.ipe` and
/// return the golden directory together with the run outcome.
/// Gated on `IPE_E2E=1`.
fn build_run_layoutwith() -> (PathBuf, crate::support::RunOutcome) {
    let root = repo_root();
    let dir = root.join("tests").join("golden").join("stdui_layoutwith");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m7_stdui_layoutwith_e2e");
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
        "ipe build must succeed for stdui_layoutwith: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("stdui_layoutwith", &out);
    (dir, outcome)
}

/// Full E2E smoke test: `Ui.layoutWith` with inline cfg literal must apply
/// both `wrapperAttrs` and `rootAttrs` in the rendered HTML.
/// Divergence golden — the expected value is ipe's own correct output.
#[test]
fn layoutwith_inline_cfg_applies_wrapper_and_root_attrs() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let (dir, outcome) = build_run_layoutwith();
    let html = &outcome.stdout;

    // wrapperAttrs = [ Ui.padding 12 ] must appear on the outermost div.
    assert!(
        html.contains("padding:12px 12px 12px 12px"),
        "stdui_layoutwith: wrapperAttrs padding must be present in output\n--- actual ---\n{html}"
    );
    // rootAttrs = [ Ui.spacing 6 ] must appear on the inner root div.
    assert!(
        html.contains("gap:6px"),
        "stdui_layoutwith: rootAttrs spacing must be present in output\n--- actual ---\n{html}"
    );
    // Font.bold on the el must be present.
    assert!(
        html.contains("font-weight:700"),
        "stdui_layoutwith: Font.bold must render font-weight:700\n--- actual ---\n{html}"
    );
    // The text node must be present.
    assert!(
        html.contains("lw"),
        "stdui_layoutwith: text content 'lw' must be present\n--- actual ---\n{html}"
    );

    crate::support::assert_go_parity("stdui_layoutwith", &dir, html);
    assert_eq!(outcome.exit_code, Some(0), "stdui_layoutwith: must exit 0");
}
