//! Browser-run proof that the wasm client's markup paths never let a rendered
//! `autofocus` reach the live DOM, parse markup in its container's own
//! context, and keep focus after a frame by the view, never by the patch. The browser focuses an `autofocus` element on insertion while focus
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

use std::collections::HashMap;

use ipe_runtime_rust::dom::diff::{AUTOFOCUS_SPENT_GLOBAL, Patch};
use ipe_runtime_rust::wasm::{
    QueuedCause, apply_frame, paint_first, replace_children_html, write_patched_attr,
};
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

/// Sets the global the loader writes once the user pressed a key or the
/// pointer; `None` removes it.
fn set_spent(spent: Option<bool>) -> bool {
    let global = js_sys::global();
    let key = wasm_bindgen::JsValue::from_str(AUTOFOCUS_SPENT_GLOBAL);
    match spent {
        Some(on) => js_sys::Reflect::set(&global, &key, &on.into()).unwrap_or(false),
        None => js_sys::Reflect::delete_property(&global, &key).unwrap_or(false),
    }
}

#[wasm_bindgen_test]
fn the_first_paint_never_autofocuses_after_the_user_acted() {
    let doc = document();
    assert!(doc.is_some(), "run_in_browser must provide a document");
    let Some(doc) = doc else { return };
    let root = fresh(&doc, "div");
    assert!(root.is_some(), "the mount root must attach");
    let Some(root) = root else { return };
    // The loader heard a key or a pointer press; focus is back on the body.
    assert!(set_spent(Some(true)));
    let painted = paint_first(&doc, &root, r#"<input id="acted-a" autofocus>"#);
    assert!(set_spent(None));
    assert!(painted.is_ok());
    assert!(!holds_autofocus(&root));
    assert_eq!(focused_id(&doc), "");
    root.remove();
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

#[wasm_bindgen_test]
fn a_patched_iframe_connects_sandboxed() {
    let doc = document();
    assert!(doc.is_some(), "run_in_browser must provide a document");
    let Some(doc) = doc else { return };
    let root = fresh(&doc, "div");
    assert!(root.is_some(), "the patch target must attach");
    let Some(root) = root else { return };
    replace_children_html(
        &doc,
        &root,
        r#"<iframe id="bare" src="/"></iframe><iframe id="wide" sandbox="allow-scripts ALLOW-SAME-ORIGIN allow-popups-to-escape-sandbox"></iframe>"#,
    );
    let sandbox = |id: &str| {
        root.query_selector(id)
            .ok()
            .flatten()
            .and_then(|el| el.get_attribute("sandbox"))
    };
    assert_eq!(sandbox("#bare").as_deref(), Some(""));
    assert_eq!(sandbox("#wide").as_deref(), Some("allow-scripts"));
    root.remove();
}

#[wasm_bindgen_test]
fn a_patched_embed_with_a_url_never_connects() {
    let doc = document();
    assert!(doc.is_some(), "run_in_browser must provide a document");
    let Some(doc) = doc else { return };
    let root = fresh(&doc, "div");
    assert!(root.is_some(), "the patch target must attach");
    let Some(root) = root else { return };
    replace_children_html(
        &doc,
        &root,
        r#"<embed src="/"><object data="/"></object><p><embed SRC=" "></p><embed id="inert" type="x">"#,
    );
    assert!(root.query_selector("p").ok().flatten().is_some());
    assert!(root.query_selector("#inert").ok().flatten().is_some());
    assert!(matches!(root.query_selector("[src], object"), Ok(None)));
    root.remove();
}

#[wasm_bindgen_test]
fn a_patched_attribute_keeps_the_frame_rule_on_a_live_node() {
    let doc = document();
    assert!(doc.is_some(), "run_in_browser must provide a document");
    let Some(doc) = doc else { return };
    let root = fresh(&doc, "div");
    assert!(root.is_some(), "the patch target must attach");
    let Some(root) = root else { return };
    // Built node by node: no parse fence ever sees these elements.
    let frame = doc.create_element("iframe").ok();
    let embed = doc.create_element("embed").ok();
    assert!(
        frame.is_some() && embed.is_some(),
        "the elements must build"
    );
    let (Some(frame), Some(embed)) = (frame, embed) else {
        return;
    };
    assert!(root.append_child(&frame).is_ok() && root.append_child(&embed).is_ok());
    write_patched_attr(&frame, "SRC", Some("/"));
    assert_eq!(frame.get_attribute("sandbox").as_deref(), Some(""));
    assert_eq!(frame.get_attribute("src").as_deref(), Some("/"));
    write_patched_attr(&frame, "sandbox", None);
    assert_eq!(frame.get_attribute("sandbox").as_deref(), Some(""));
    write_patched_attr(&frame, "Sandbox", Some("ALLOW-SAME-ORIGIN allow-forms"));
    assert_eq!(
        frame.get_attribute("sandbox").as_deref(),
        Some("allow-forms")
    );
    write_patched_attr(&embed, "src", Some("/"));
    write_patched_attr(&embed, "title", Some("kept"));
    assert!(!embed.has_attribute("src"));
    assert_eq!(embed.get_attribute("title").as_deref(), Some("kept"));
    root.remove();
}

/// A fresh view root stamped `id` holding `markup`, below the body as the
/// wasm mount's own view root sits.
fn view(document: &web_sys::Document, id: &str, markup: &str) -> Option<web_sys::HtmlElement> {
    let root = fresh(document, "div")?;
    root.set_attribute("ipe-id", id).ok()?;
    root.set_inner_html(markup);
    Some(root)
}

/// Focuses the element `id` below `document`; whether it took focus.
fn focus_on(document: &web_sys::Document, id: &str) -> bool {
    document
        .get_element_by_id(id)
        .and_then(|el| el.dyn_into::<web_sys::HtmlElement>().ok())
        .is_some_and(|el| el.focus().is_ok())
        && focused_id(document) == id
}

/// A patch of the element stamped `id`.
fn patch(id: &str, html: Option<&str>, attrs: &[(&str, Option<&str>)]) -> Patch {
    Patch {
        id: id.into(),
        text: None,
        html: html.map(str::to_string),
        attrs: attrs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.map(str::to_string)))
            .collect::<HashMap<_, _>>(),
    }
}

/// Resolves after `n` animation frames; a stalled frame resolves on a timeout.
async fn frames(n: u32) {
    for _ in 0..n {
        let tick = js_sys::Promise::new(&mut |resolve: js_sys::Function, _reject| {
            if let Some(window) = web_sys::window() {
                let _ = window.request_animation_frame(&resolve);
                let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 500);
            } else {
                let _ = resolve.call0(&wasm_bindgen::JsValue::NULL);
            }
        });
        let _ = wasm_bindgen_futures::JsFuture::from(tick).await;
    }
}

#[wasm_bindgen_test]
async fn a_swap_that_drops_focus_lands_on_the_nearest_stamped_host() {
    let doc = document();
    assert!(doc.is_some(), "run_in_browser must provide a document");
    let Some(doc) = doc else { return };
    let root = view(
        &doc,
        "fks",
        r#"<div ipe-id="fks_0_div" id="fks-host" tabindex="-1"><button ipe-id="fks_0_div_0_button" id="fks-old">x</button></div>"#,
    );
    assert!(root.is_some(), "the view must attach");
    let Some(root) = root else { return };
    assert!(focus_on(&doc, "fks-old"));
    let swap = [patch(
        "fks_0_div",
        Some(r#"<p ipe-id="fks_0_div_0_p">y</p>"#),
        &[],
    )];
    apply_frame(&doc, &swap, None, &QueuedCause::default());
    assert_eq!(focused_id(&doc), "fks-host");
    frames(3).await;
    assert_eq!(focused_id(&doc), "fks-host");
    root.remove();
}

#[wasm_bindgen_test]
async fn an_in_place_untab_lands_on_the_ancestor_at_the_deferred_check() {
    let doc = document();
    assert!(doc.is_some(), "run_in_browser must provide a document");
    let Some(doc) = doc else { return };
    let root = view(
        &doc,
        "fku",
        r#"<div ipe-id="fku_0_div" id="fku-host" tabindex="-1"><div ipe-id="fku_0_div_0_div" id="fku-row" tabindex="0">row</div></div>"#,
    );
    assert!(root.is_some(), "the view must attach");
    let Some(root) = root else { return };
    assert!(focus_on(&doc, "fku-row"));
    let untab = [patch("fku_0_div_0_div", None, &[("tabindex", None)])];
    apply_frame(&doc, &untab, None, &QueuedCause::default());
    frames(3).await;
    assert_eq!(focused_id(&doc), "fku-host");
    root.remove();
}

#[wasm_bindgen_test]
async fn focus_the_user_placed_elsewhere_is_never_taken() {
    let doc = document();
    assert!(doc.is_some(), "run_in_browser must provide a document");
    let Some(doc) = doc else { return };
    let root = view(
        &doc,
        "fke",
        r#"<div ipe-id="fke_0_div" id="fke-host" tabindex="-1"><div ipe-id="fke_0_div_0_div" id="fke-row" tabindex="0">row</div></div>"#,
    );
    let held = fresh(&doc, "input");
    assert!(root.is_some() && held.is_some(), "the elements must attach");
    let (Some(root), Some(held)) = (root, held) else {
        return;
    };
    held.set_id("fke-held");
    assert!(focus_on(&doc, "fke-row"));
    let untab = [patch("fke_0_div_0_div", None, &[("tabindex", None)])];
    apply_frame(&doc, &untab, None, &QueuedCause::default());
    // The user moves focus out of the view before the deferred check.
    assert!(focus_on(&doc, "fke-held"));
    frames(3).await;
    assert_eq!(focused_id(&doc), "fke-held");
    root.remove();
    held.remove();
}

#[wasm_bindgen_test]
async fn focus_in_the_overlay_records_nothing() {
    let doc = document();
    assert!(doc.is_some(), "run_in_browser must provide a document");
    let Some(doc) = doc else { return };
    // An unstamped sibling of the view, as the debugger overlay is.
    let overlay = fresh(&doc, "div");
    assert!(overlay.is_some(), "the overlay must attach");
    let Some(overlay) = overlay else { return };
    overlay.set_inner_html(
        r#"<div ipe-id="fko_0_div" id="fko-host" tabindex="-1"><button ipe-id="fko_0_div_0_button" id="fko-btn">x</button></div>"#,
    );
    assert!(focus_on(&doc, "fko-btn"));
    let swap = [patch("fko_0_div", Some("<p>y</p>"), &[])];
    apply_frame(&doc, &swap, None, &QueuedCause::default());
    assert_eq!(focused_id(&doc), "");
    frames(3).await;
    assert_eq!(focused_id(&doc), "");
    overlay.remove();
}
