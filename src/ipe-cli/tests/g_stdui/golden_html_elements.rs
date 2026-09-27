//! Batch 2 — Ipe.Html ELEMENT family end-to-end golden.
//!
//! Compiles `tests/golden/html_elements/Main.ipe` through `ipe`, builds the
//! emitted Rust project with the shared cargo target, runs the binary, and
//! asserts on the rendered HTML. Gated on `IPE_E2E=1`.
//!
//! ## What is proven (CORRECT-TAG, not the pre-batch wrong-render fold)
//!
//! * Container elements render their OWN tag: `nav`→`<nav>…</nav>`,
//!   `h1`→`<h1>…</h1>`, `table`/`thead`/`tbody`/`tr`/`th`/`td`, `ul`/`li`,
//!   `section`/`header`/`footer`, `a`→`<a>…</a>` — NONE collapse to `<p>`.
//! * Void elements self-close with NO children and NO close tag: `img`/`br`/
//!   `hr`/`link` → `<tag … />`. `link` renders `<link … />`, NOT `<a>` (the old
//!   `a | link` fold is gone); `br`/`hr` render as themselves, NOT `<img>`.
//! * SECURITY (P1): every element flows through the SAME battle-tested render
//!   sink (`html::render_into`) as `Html.node` — no new escaping boundary. The
//!   sink is tag-name-driven for void self-closing + drops children for void
//!   tags, so no injected-child surface.
//!
//! Run: `IPE_E2E=1 cargo test golden_m7_html_elements`

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn html_element_family_renders_correct_tags() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("html_elements");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m7_html_elements_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime().expect("runtime must resolve for E2E");
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for html_elements: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("html_elements", &out);
    let html = &outcome.stdout;

    // Container elements render their own open + close tag (NOT collapsed to <p>).
    for open in [
        "<section", "<nav", "<h1", "<table", "<thead", "<tbody", "<tr", "<th", "<td", "<ul", "<li",
        "<header", "<footer", "<a",
    ] {
        assert!(
            html.contains(open),
            "html_elements: expected container open `{open}`\n--- actual ---\n{html}"
        );
    }
    for close in [
        "</section>",
        "</nav>",
        "</h1>",
        "</table>",
        "</tr>",
        "</td>",
        "</ul>",
        "</li>",
        "</header>",
        "</footer>",
        "</a>",
    ] {
        assert!(
            html.contains(close),
            "html_elements: expected container close `{close}`\n--- actual ---\n{html}"
        );
    }

    // WRONG-RENDER GUARD: nothing collapses to <p>. The source uses no `p`
    // element, so no `<p>` / `<p ` may appear.
    assert!(
        !html.contains("<p>") && !html.contains("<p "),
        "html_elements: NO element may collapse to <p>\n--- actual ---\n{html}"
    );

    // Void elements self-close (` />`) with no close tag.
    for void_open in ["<img", "<br", "<hr", "<link"] {
        assert!(
            html.contains(void_open),
            "html_elements: expected void `{void_open}`\n--- actual ---\n{html}"
        );
    }
    for no_close in ["</img>", "</br>", "</hr>", "</link>"] {
        assert!(
            !html.contains(no_close),
            "html_elements: void element must NOT have a close tag `{no_close}`\n--- actual ---\n{html}"
        );
    }
    // `<br />` / `<hr />` self-close verbatim (not folded to <img>).
    assert!(
        html.contains("<br />") && html.contains("<hr />"),
        "html_elements: br/hr must self-close as themselves\n--- actual ---\n{html}"
    );
    // `link` is void `<link … />`, NOT an `<a>`.
    assert!(
        html.contains("<link"),
        "html_elements: link must render as <link>, not <a>\n--- actual ---\n{html}"
    );

    assert_eq!(outcome.exit_code, Some(0), "html_elements: must exit 0");
}
