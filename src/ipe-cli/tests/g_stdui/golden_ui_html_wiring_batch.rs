//! E2E golden for the 20-kernel wiring batch — the exhaustiveness gate's list
//! of 20 reachable-but-unbacked `qual_vars`
//! members: `Ui.image/disabled/paddingEach/clipX/clipY/scrollbarX/
//! scrollbarY/onFile/onPseudo/hover/focus/focusVisible/active`,
//! `Html.toString/voidNode/doctype/titleNode/htmlNode/headNode`,
//! `Background.linearGradient`).
//!
//! `Ui.mediaQuery` is NOT exercised here — it has its own golden
//! (`golden_ui_mediaquery.rs`; see
//! `docs/adr/0003-security-render-and-data-access-invariants.md`).
//!
//! ## Oracle provenance
//!
//! `oracle_divergence = true` — this is a brand-new Rust-only kernel batch
//! with no reference behaviour to diff against structurally (the CSS/HTML
//! shape is verified by direct assertions below, matching the semantics
//! documented in `../ipe`'s `Ipe.Ui.ipe` / `Ipe.Html.ipe` source, not a cached
//! oracle file).
//!
//! ## What is tested
//!
//! * `ipe build` compiles `tests/golden/ui_html_wiring_batch/Main.ipe`
//!   (canon → types → lower → Rust backend) for all 19 exercised kernels.
//! * The emitted Rust project `cargo build`s and the binary runs and exits 0.
//! * `Html.doctype` + `Html.htmlNode` + `Html.headNode` + `Html.titleNode` +
//!   `Html.voidNode` + `Html.toString` produce a well-formed HTML5 document
//!   skeleton with a literal `<!DOCTYPE html>` prefix.
//! * `Ui.paddingEach` renders four DISTINCT side values (not swapped/aliased).
//! * `Ui.clipX` / `Ui.clipY` / `Ui.scrollbarX` / `Ui.scrollbarY` render the
//!   correct PER-AXIS `overflow-x`/`overflow-y` pair (not folded onto the
//!   both-axes `Ui.clip` / `Ui.scrollbars` semantics).
//! * `Background.linearGradient` renders a `linear-gradient(...)` CSS value.
//! * `Ui.onPseudo` + all 5 `PseudoClass` constants (`hover`/`focus`/
//!   `focusVisible`/`active`/`disabled`) attach a `data-ipe-pc-rules` marker
//!   with the correct wire tag per constant.
//! * `Ui.image` renders `<img src=… alt=…>`.
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_ui_html_wiring_batch
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Compile / build / run `tests/golden/ui_html_wiring_batch/Main.ipe` and
/// return the golden directory together with the run outcome. Gated on
/// `IPE_E2E=1`.
fn build_run_ui_html_wiring_batch() -> (PathBuf, crate::support::RunOutcome) {
    let root = repo_root();
    let dir = root
        .join("tests")
        .join("golden")
        .join("ui_html_wiring_batch");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_ui_html_wiring_batch_e2e");
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
        "ipe build must succeed for ui_html_wiring_batch: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("ui_html_wiring_batch", &out);
    (dir, outcome)
}

#[test]
fn ui_html_wiring_batch_compiles_builds_and_renders_correctly() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let (_dir, outcome) = build_run_ui_html_wiring_batch();
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "binary must exit 0\n--- stdout ---\n{}",
        outcome.stdout
    );

    let mut lines = outcome.stdout.lines();
    let doc = lines.next().unwrap_or_default();
    let ui = lines.next().unwrap_or_default();

    // ── Html.doctype / htmlNode / headNode / titleNode / voidNode / toString ──
    assert!(
        doc.starts_with("<!DOCTYPE html>"),
        "Html.doctype must emit a literal DOCTYPE prefix\n--- doc ---\n{doc}"
    );
    assert!(
        doc.contains("<html>") || doc.contains("<html "),
        "Html.htmlNode must render <html>\n--- doc ---\n{doc}"
    );
    assert!(
        doc.contains("<head>") || doc.contains("<head "),
        "Html.headNode must render <head>\n--- doc ---\n{doc}"
    );
    assert!(
        doc.contains("<title>My Page</title>"),
        "Html.titleNode must wrap the raw string in <title>\n--- doc ---\n{doc}"
    );
    assert!(
        doc.contains("<br"),
        "Html.voidNode \"br\" must render a <br> element\n--- doc ---\n{doc}"
    );

    // ── Ui.paddingEach — four distinct sides ──────────────────────────────────
    assert!(
        ui.contains("padding:1px 2px 3px 4px"),
        "Ui.paddingEach must render top/right/bottom/left distinctly\n--- ui ---\n{ui}"
    );

    // ── Ui.clipX / clipY / scrollbarX / scrollbarY — per-axis, not folded ────
    assert!(
        ui.contains("overflow-x:clip") && ui.contains("overflow-y:clip"),
        "Ui.clipX + Ui.clipY together must produce BOTH overflow-x:clip and \
         overflow-y:clip (each axis from its own dedicated kernel, not the \
         both-axes Ui.clip semantics)\n--- ui ---\n{ui}"
    );
    assert!(
        ui.contains("overflow-x:auto") && ui.contains("overflow-y:auto"),
        "Ui.scrollbarX + Ui.scrollbarY together must produce BOTH \
         overflow-x:auto and overflow-y:auto\n--- ui ---\n{ui}"
    );

    // ── Background.linearGradient ─────────────────────────────────────────────
    assert!(
        ui.contains("linear-gradient(90deg, rgba(255,0,0,1) 0%, rgba(0,0,255,1) 100%)"),
        "Background.linearGradient CSS malformed\n--- ui ---\n{ui}"
    );

    // ── Ui.onPseudo + hover/focus/focusVisible/active/disabled ───────────────
    // Encoded as `data-ipe-pc-rules="h|css||f|css||v|css||a|css||d|css"`
    // (`||`-joined `tag|css` segments) — one segment per onPseudo call above.
    for tag in ["h", "f", "v", "a", "d"] {
        assert!(
            ui.contains(&format!("{tag}|background-color:rgba(")),
            "Ui.onPseudo must attach a data-ipe-pc-rules segment for wire tag \
             {tag:?}\n--- ui ---\n{ui}"
        );
    }

    // ── Ui.image ───────────────────────────────────────────────────────────────
    assert!(
        ui.contains("<img"),
        "Ui.image must render <img>\n--- ui ---\n{ui}"
    );
    // `Ui.image`'s `src` is a typed `ImageValue`; a `Ui.imageData { mime,
    // base64 }` renders the `data:<mime>;base64,<payload>` URI.
    assert!(
        ui.contains("src=\"data:image/png;base64,AAAA\"") && ui.contains("alt=\"alt text\""),
        "Ui.image src/alt malformed\n--- ui ---\n{ui}"
    );

    // ── Ui.onFile — wire event name "ipe-file" ────────────────────────────────
    assert!(
        ui.contains("data-ipe-on=\"ipe-file\""),
        "Ui.onFile must register a data-ipe-on=\"ipe-file\" handler marker\n--- ui ---\n{ui}"
    );
}
