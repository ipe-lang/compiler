//! Browser-run proof that the wasm client's markup paths never let a rendered
//! `autofocus` reach the live DOM, and parse markup in its container's own
//! context. The browser focuses an `autofocus` element on insertion while focus
//! is on the body, so a render the user did not cause would move focus; the
//! runtime strips the attribute from the detached parse and moves focus itself,
//! at first paint only while the load's own autofocus is due. Real Chromium
//! (`wasm-bindgen-test-runner` + `chromedriver`): no other runner has a DOM.
//!
//! Each test paints into its own element below the body, never the body
//! itself, which holds the runner's own report.
//!
//! ```sh
//! CHROMEDRIVER=chromedriver cargo test -p ipe-runtime-rust \
//!     --target wasm32-unknown-unknown --features wasm-client --test wasm_dom_paint
//! ```

#![cfg(all(target_arch = "wasm32", feature = "wasm-client"))]

use ipe_runtime_rust::wasm::{paint_first, replace_children_html};
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

/// The test page's document.
fn document() -> Option<web_sys::Document> {
    web_sys::window()?.document()
}

/// A fresh `tag` element appended to the body, with focus back on the body.
fn fresh(document: &web_sys::Document, tag: &str) -> Option<web_sys::HtmlElement> {
    if let Some(active) = document.active_element()
        && let Some(active) = active.dyn_ref::<web_sys::HtmlElement>()
    {
        let _ = active.blur();
    }
    let el = document.create_element(tag).ok()?;
    document.body()?.append_child(&el).ok()?;
    el.dyn_into::<web_sys::HtmlElement>().ok()
}

/// The id of the focused element, "" for the body or none.
fn focused_id(document: &web_sys::Document) -> String {
    document
        .active_element()
        .map(|el| el.id())
        .unwrap_or_default()
}

/// Whether any element below `el` carries `autofocus`.
fn holds_autofocus(el: &web_sys::Element) -> bool {
    !matches!(el.query_selector("[autofocus]"), Ok(None))
}

#[wasm_bindgen_test]
fn the_first_paint_connects_no_autofocus_and_focuses_the_first() {
    let doc = document();
    assert!(doc.is_some(), "run_in_browser must provide a document");
    let Some(doc) = doc else { return };
    let root = fresh(&doc, "div");
    assert!(root.is_some(), "the mount root must attach");
    let Some(root) = root else { return };
    let painted = paint_first(
        &doc,
        &root,
        r#"<input id="first-a" autofocus><input id="first-b" autofocus>"#,
    );
    assert!(painted.is_ok());
    assert!(!holds_autofocus(&root));
    assert_eq!(focused_id(&doc), "first-a");
    root.remove();
}

#[wasm_bindgen_test]
fn the_first_paint_never_takes_focus_the_user_moved() {
    let doc = document();
    assert!(doc.is_some(), "run_in_browser must provide a document");
    let Some(doc) = doc else { return };
    let root = fresh(&doc, "div");
    let held = fresh(&doc, "input");
    assert!(root.is_some() && held.is_some(), "the elements must attach");
    let (Some(root), Some(held)) = (root, held) else {
        return;
    };
    held.set_id("moved-here");
    assert!(held.focus().is_ok());
    assert_eq!(focused_id(&doc), "moved-here");
    let painted = paint_first(&doc, &root, r#"<input id="moved-a" autofocus>"#);
    assert!(painted.is_ok());
    assert!(!holds_autofocus(&root));
    assert_eq!(focused_id(&doc), "moved-here");
    root.remove();
    held.remove();
}

#[wasm_bindgen_test]
fn a_patch_connects_no_autofocus() {
    let doc = document();
    assert!(doc.is_some(), "run_in_browser must provide a document");
    let Some(doc) = doc else { return };
    let root = fresh(&doc, "div");
    assert!(root.is_some(), "the patch target must attach");
    let Some(root) = root else { return };
    replace_children_html(
        &doc,
        &root,
        r#"<p><input id="patch-a" autofocus></p><input id="patch-b" autofocus>"#,
    );
    assert!(root.query_selector("#patch-b").ok().flatten().is_some());
    assert!(!holds_autofocus(&root));
    root.remove();
}

#[wasm_bindgen_test]
fn a_table_body_keeps_its_rows_and_cells() {
    let doc = document();
    assert!(doc.is_some(), "run_in_browser must provide a document");
    let Some(doc) = doc else { return };
    let table = fresh(&doc, "table");
    let body = doc.create_element("tbody").ok();
    assert!(table.is_some() && body.is_some(), "the table must attach");
    let (Some(table), Some(body)) = (table, body) else {
        return;
    };
    assert!(table.append_child(&body).is_ok());
    replace_children_html(&doc, &body, r#"<tr><td id="cell">x</td></tr>"#);
    assert!(body.query_selector("tr > td#cell").ok().flatten().is_some());
    table.remove();
}

#[wasm_bindgen_test]
fn a_template_takes_its_markup_into_its_inert_content() {
    let doc = document();
    assert!(doc.is_some(), "run_in_browser must provide a document");
    let Some(doc) = doc else { return };
    let host = fresh(&doc, "template");
    assert!(host.is_some(), "the template must attach");
    let Some(host) = host else { return };
    replace_children_html(&doc, &host, r#"<tr><td id="inert" autofocus>x</td></tr>"#);
    assert_eq!(host.child_nodes().length(), 0);
    let template = host.dyn_ref::<web_sys::HtmlTemplateElement>();
    assert!(template.is_some());
    if let Some(template) = template {
        let cell = template
            .content()
            .query_selector("tr > td#inert")
            .ok()
            .flatten();
        assert!(cell.is_some());
        assert!(cell.is_some_and(|cell| !cell.has_attribute("autofocus")));
    }
    host.remove();
}
