//! Ipe.Html.Attributes family end-to-end golden.
//!
//! Compiles `tests/golden/html_attrs/Main.ipe` through `ipe`, builds the
//! emitted Rust project with the shared cargo target, runs the binary, and
//! asserts on the rendered HTML. Gated on `IPE_E2E=1`.
//!
//! ## What is proven
//!
//! * Fixed-key string attrs (`class` / `id` / `href` / `value` / `type_` /
//!   `placeholder`) render with the correct wire name — including the
//!   Ipê-keyword-avoidance fixup `type_` → `type`.
//! * Fixed-key bool attrs render bare-when-true (`checked`) and omitted-when-
//!   false (`disabled`).
//! * The generic `attribute k v` / `boolAttribute k b` builders round-trip.
//! * SECURITY (P1): the render sink escapes attribute VALUES (`<` → `&lt;`,
//!   `"` → `&#34;`, `'` → `&#39;`) and DROPS a hostile event attribute name
//!   (`attribute "onclick" "alert(1)"`) via `SafeAttrName` — no XSS reflection.
//!
//! Run: `IPE_E2E=1 cargo test golden_m7_html_attrs`

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn html_attributes_family_renders_and_escapes() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("html_attrs");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m7_html_attrs_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for html_attrs: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("html_attrs", &out);
    let html = &outcome.stdout;

    // Fixed-key string attrs, including the `type_` → `type` wire fixup.
    for needle in [
        "class=\"app\"",
        "id=\"main\"",
        "type=\"text\"",
        "placeholder=\"name\"",
        "data-ok=\"safe\"",
    ] {
        assert!(
            html.contains(needle),
            "html_attrs: expected `{needle}`\n--- actual ---\n{html}"
        );
    }

    // Bool attrs: checked (true) present, disabled (false) omitted.
    assert!(
        html.contains("checked=\"true\""),
        "html_attrs: checked True must render\n--- actual ---\n{html}"
    );
    assert!(
        !html.contains("disabled"),
        "html_attrs: disabled False must be omitted\n--- actual ---\n{html}"
    );
    // Generic boolAttribute.
    assert!(
        html.contains("hidden=\"true\""),
        "html_attrs: boolAttribute hidden True must render\n--- actual ---\n{html}"
    );

    // SECURITY: attribute value is escaped, never reflected verbatim.
    assert!(
        html.contains("value=\"a&lt;b&#34;c\""),
        "html_attrs: value must be HTML-escaped\n--- actual ---\n{html}"
    );
    assert!(
        !html.contains("a<b\"c"),
        "html_attrs: raw unescaped value must NOT appear\n--- actual ---\n{html}"
    );
    // SECURITY: a single-quote in the relative-ref query is percent-encoded at
    // the typed URL boundary (`Url.relative`), so it cannot break out of the
    // double-quoted `href` — neutralised at parse time, not only at the sink.
    assert!(
        html.contains("href=\"/x?q=%27z\""),
        "html_attrs: href single-quote must be percent-encoded\n--- actual ---\n{html}"
    );
    assert!(
        !html.contains("q='z"),
        "html_attrs: raw single-quote must NOT reach the href\n--- actual ---\n{html}"
    );

    // SECURITY: the hostile event-attribute name must be DROPPED at the sink.
    assert!(
        !html.contains("onclick") && !html.contains("alert(1)"),
        "html_attrs: hostile `attribute \"onclick\"` must be neutralised\n--- actual ---\n{html}"
    );

    // A11Y: the typed `role` / `aria-*` helpers render the exact canonical
    // wire strings. Enumerated aria values come from closed sums, so a
    // misspelling is a type error, not a silent bad string here.
    for needle in [
        "role=\"searchbox\"",
        "aria-label=\"search\"",
        "aria-live=\"polite\"",
        "aria-current=\"page\"",
        "aria-checked=\"mixed\"",
        "aria-hidden=\"true\"",
        "aria-valuenow=\"3\"",
    ] {
        assert!(
            html.contains(needle),
            "html_attrs: expected aria `{needle}`\n--- actual ---\n{html}"
        );
    }
    // A11Y: an aria STATE boolean writes `false` OUT explicitly — unlike the
    // omit-on-false `disabled`, `aria-expanded="false"` must be present, because
    // an absent state and an explicit `"false"` differ to assistive tech.
    assert!(
        html.contains("aria-expanded=\"false\""),
        "html_attrs: ariaExpanded False must render explicit false\n--- actual ---\n{html}"
    );

    assert_eq!(outcome.exit_code, Some(0), "html_attrs: must exit 0");
}
