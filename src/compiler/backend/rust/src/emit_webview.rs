//! Emission of the webview-native executor for a `Web.tea` under a `web desktop`
//! delivery host.
//!
//! A `Web.tea` is a DOM `Web`-shape entry. When the resolved delivery host is
//! webview-native (`web desktop`), the same DOM app is driven by
//! `ipe_runtime::tea::WebViewApp` instead of the served `ipe_runtime::tea::WebApp`:
//!
//! ```text
//! ipe_runtime::tea::WebViewApp(
//!     ipe_runtime::webview::webview_app(init, update, view, subs, window))
//! ```
//!
//! The window (`{ title, size : (width, height) }`) is a delivery HOST decision,
//! sourced from the manifest `delivery.desktop` block and threaded into
//! [`crate::EmitCtx::webview_window`] — never a source `main` field. When the
//! delivery carries no explicit desktop block, a built-in fallback window is used.
//!
//! `run_blocking()` on the `WebViewApp` internally calls `block_on_current_thread`,
//! satisfying tao/Cocoa's requirement that the event loop runs on the process main
//! thread (hard `NSApplication` requirement on macOS). The `fn main` epilogue
//! switch to `run_blocking` is performed in `project.rs` (`emit_program` /
//! `emit_spine`) keyed on the emitted `ipe_main` return type.

/// The built-in desktop window used when a webview-native delivery carries no
/// explicit `delivery.desktop` block.
const FALLBACK_TITLE: &str = "Ipe App";
const FALLBACK_WIDTH: i64 = 1024;
const FALLBACK_HEIGHT: i64 = 768;

/// Wrap already-emitted `init` / `update` / `view` / `subs` callback strings into
/// the webview executor for a `Web.tea` under a webview-native delivery host.
///
/// The `view` string must already be wrapped by [`crate::emit_web::wrap_view`]
/// (the same `Ui.layout` framework wrap the served web path applies), so the raw
/// `Model -> Element Msg` view becomes the `Model -> Html` the runtime mounts.
///
/// The window title/size are read from [`crate::EmitCtx::webview_window`], emitted
/// as Rust string and integer literals. `None` uses the built-in fallback window.
pub fn emit_web_app_as_webview(
    ctx: &crate::EmitCtx,
    init_s: &str,
    update_s: &str,
    view_s: &str,
    subs_s: &str,
) -> String {
    let (title, width, height) = match &ctx.webview_window {
        // An empty manifest title (the `delivery.desktop` default when no block
        // is written) falls back to the built-in title so the window is never
        // nameless.
        Some(w) if !w.title.is_empty() => (w.title.as_str(), w.width, w.height),
        Some(w) => (FALLBACK_TITLE, w.width, w.height),
        None => (FALLBACK_TITLE, FALLBACK_WIDTH, FALLBACK_HEIGHT),
    };
    // `rust_str_lit` produces a valid Rust double-quoted literal with every escape
    // (quotes, backslashes, control characters) handled — the manifest title is
    // arbitrary text, so the Debug form is the fail-closed choice.
    let title_lit = ipe_intern::rust_str_lit(title);
    format!(
        "ipe_runtime::tea::WebViewApp(ipe_runtime::webview::webview_app(\
         {init_s}, {update_s}, {view_s}, {subs_s}, \
         ipe_runtime::webview::WebViewWindowCfg {{ title: {title_lit}.to_string(), size: ({width}, {height}) }}))"
    )
}
