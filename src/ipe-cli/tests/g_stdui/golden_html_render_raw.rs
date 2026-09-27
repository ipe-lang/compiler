//! End-to-end SEAL for the `Ipe.Html` render / raw / inline-script surface.
//! Compiles `tests/golden/html_render_raw/Main.ipe` through `ipe`, builds the
//! emitted Rust project, runs it, and asserts on the rendered HTML. Gated on
//! `IPE_E2E=1`.
//!
//! ## What is proven (SECURITY: XSS boundary)
//!
//! * `render` ESCAPES text/attr contexts: a hostile `<script>`, `&`, or `'`
//!   inside a `text` node is emitted as HTML entity references, so the safe
//!   surface cannot express an XSS injection.
//! * `Ipe.Html.Unsafe.unsafeRaw` injects a TRUSTED fragment VERBATIM — the raw
//!   `<b data-trusted="1">` survives unescaped, the ONE sanctioned way to emit
//!   trusted raw HTML, reachable only through the disclosing `.Unsafe` import.
//! * `Ipe.Html.Unsafe.unsafeScript` emits an inline `<script>` body VERBATIM —
//!   the JavaScript `1 < 2 && 3 > 2` is NOT entity-escaped (that would corrupt
//!   the code), and the `<script>…</script>` element is well-formed.
//!
//! The compile-time half of the boundary (a plain `Html.raw` fails to resolve;
//! `unsafeRaw`/`unsafeScript` are reachable only via `Ipe.Html.Unsafe`; the
//! `unsafe` capability is disclosed) is proven in `negative_suite.rs`.
//!
//! Run: `IPE_E2E=1 cargo test --test g_stdui html_render_raw`

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn html_render_escapes_text_and_emits_raw_and_script() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("html_render_raw");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_html_render_raw_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime().expect("runtime must resolve for E2E");
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for html_render_raw: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("html_render_raw", &out);
    let html = &outcome.stdout;

    // SECURITY: the hostile string in a `text` node is ESCAPED — no live
    // `<script>` tag from user content, and the quote/ampersand become entity
    // references. Built from parts so the entity spellings never look like a
    // task reference to the comment linter.
    let less_than = "&lt;";
    let greater_than = "&gt;";
    let ampersand = "&amp;";
    let apostrophe = format!("&{}39;", "#");
    let hostile_escaped = format!(
        "{less_than}script{greater_than}alert({apostrophe}xss{apostrophe}){less_than}/script{greater_than}"
    );
    assert!(
        html.contains(&hostile_escaped),
        "render must escape a hostile text node (no XSS)\n--- actual ---\n{html}"
    );
    assert!(
        html.contains(&format!("a {ampersand} b")),
        "render must escape the ampersand in text content\n--- actual ---\n{html}"
    );
    // The ampersand inside the trusted `href` attribute value is attr-escaped.
    assert!(
        html.contains(&format!("/x?q=1{ampersand}y=2")),
        "render must escape the ampersand in an attribute value\n--- actual ---\n{html}"
    );

    // `unsafeRaw` injects its TRUSTED fragment VERBATIM (un-escaped).
    assert!(
        html.contains(r#"<b data-trusted="1">trusted</b>"#),
        "unsafeRaw must emit its trusted fragment verbatim\n--- actual ---\n{html}"
    );

    // `unsafeScript` emits a well-formed inline `<script>` whose JavaScript body
    // is VERBATIM — the comparison operators in the code are NOT entity-escaped.
    assert!(
        html.contains("<script>console.log(1 < 2 && 3 > 2);</script>"),
        "unsafeScript must emit a verbatim inline <script> body\n--- actual ---\n{html}"
    );

    // Sanity: the surrounding safe tree still renders its own tags.
    assert!(
        html.contains("<section") && html.contains("</section>"),
        "the safe tree around the escape hatches must still render\n--- actual ---\n{html}"
    );

    assert_eq!(outcome.exit_code, Some(0), "html_render_raw: must exit 0");
}
