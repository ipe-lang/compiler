//! Native desktop window backend — the webview host of a `web desktop` delivery.
//!
//! `webview_app(init, update, view, subscriptions, window)` opens a native
//! system webview (`wry` ≥0.55 + `tao` ≥0.35: WKWebView on macOS, WebView2 on
//! Windows, WebKitGTK on Linux — webkit2gtk-4.1 + libsoup-3.0) and runs the same
//! TEA loop as Ipe.Web, reusing Ipe.Web's `Html` renderer + event dispatch
//! (`HandlerIndex`) — the view paints identically across web / terminal /
//! desktop. The bridge is in-process: `with_html` for the initial paint, an IPC
//! handler for DOM events, `evaluate_script` for re-renders. No HTTP server, SSE,
//! or session store.
//!
//! Modern wry/tao use objc2 (macOS) + current windows-rs (Windows) and so build
//! on macOS-15/Xcode-16 + Windows-2025 toolchains — unlike the legacy wry 0.24 /
//! tao 0.16 stack this replaced. The event loop is created + run on the
//! process's TRUE main thread on every OS: the generated Ipe.WebView entry
//! drives this future via `block_on_current_thread` (a current-thread tokio
//! runtime, no `std::thread::spawn` — see task.rs), so `event_loop.run(...)`
//! never runs off the main thread. macOS REQUIRES this (tao/winit + Cocoa's
//! `NSApplication` assert the main thread — a hard requirement with no
//! any-thread escape); Windows expects it; GTK on Linux is happy on it. So the
//! loop is built uniformly (`EventLoopBuilder::build()`), with no per-OS
//! `with_any_thread(true)` branch. The webview itself is built per-OS:
//! `build(&window)` (raw-window-handle) off Linux, `build_gtk(...)` on Linux.
//!
//! Two builds: the real backend is behind the opt-in `webview` Cargo feature
//! (needs the system webview dev libraries); otherwise a stub returning a graceful
//! `Err` is compiled, so a `web desktop` build always links + never panics. No
//! panic vectors: the stub returns `Err`; the real path routes every fallible
//! call through `Err`.

use super::core::IpeTask;
use super::html::Html;
use super::tea::{IpeCmd, IpeSub};

/// Window configuration — mirrors Ipê's closed `WindowCfg { title, size }`.
///
/// `size` is the logical **content/inner** area in CSS pixels: the drawable
/// region the Ipê view occupies, not the outer OS frame (title bar + border).
/// Tao's `with_inner_size` honours this: on macOS it calls `initWithContentRect:`
/// with the content rect (the same Cocoa API that backs `NSWindow.contentView`),
/// so a `size = (800, 500)` config gives exactly 800×500 px of content regardless
/// of the native title-bar height.
#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct WebViewWindowCfg {
    pub title: String,
    pub size: (i64, i64),
}

/// Phantom marker for Ipê's `AppCfg model msg` record alias (destructured at the
/// call site, never built in Rust). See the codegen `markerCfgAliases`.
pub struct WebViewAppCfg;

// Bridge JS: delegated event listeners on the document forward DOM events on
// `[ipe-id]` elements to the IPC channel as `{ipeId, event, args}`. Re-bound
// implicitly via event delegation, so a full innerHTML swap needs no re-bind.
#[cfg(any(feature = "webview", test))]
const BRIDGE_JS: &str = r#"
(function(){
  // The document members the bridge reads, bound from the prototypes before any
  // page content is consulted: an `img`, `form`, `embed`, `object` or `iframe`
  // named after a document member shadows that member with the element.
  var doc=(function(d){
    var body=Object.getOwnPropertyDescriptor(Document.prototype,'body');
    return { body:function(){ return body.get.call(d); }, on:EventTarget.prototype.addEventListener.bind(d) };
  })(document);
  function send(ipeId, ev, args){ try{ window.ipc.postMessage(JSON.stringify({ipeId:ipeId, event:ev, args:args})); }catch(e){} }
  function idOf(el){ return el && el.getAttribute ? el.getAttribute('ipe-id') : null; }
  // Match the wire-event arg table the HandlerIndex consumes: a checkbox/radio
  // reports its toggle STATE (OnBool reads "true"/"false"), not its static
  // `value` attribute (default "on"); everything else reports `value`
  // (OnString) — number/range deliver the numeric value as its string form.
  function valOf(t){ return (t && (t.type==='checkbox'||t.type==='radio')) ? String(!!t.checked) : ((t && t.value)||''); }
  doc.on('click', function(e){ var id=idOf(e.target.closest('[ipe-id]')); if(id) send(id,'click',[]); });
  doc.on('input', function(e){ var id=idOf(e.target.closest('[ipe-id]')); if(id) send(id,'input',[valOf(e.target)]); }, true);
  doc.on('change', function(e){ var id=idOf(e.target.closest('[ipe-id]')); if(id) send(id,'change',[valOf(e.target)]); }, true);
  // INVARIANT: `html` is produced by `render_html` (the shared Ipe.Web renderer),
  // which HTML-escapes every text + attribute node — so this innerHTML assignment
  // is not an XSS sink for user data. Any future RAW-html node added to the
  // renderer becomes the XSS boundary and must be audited there.
  window.__ipeApply = function(html){ var b=doc.body(); if(b) b.innerHTML = html; };
})();
"#;

#[cfg(test)]
mod tests {
    /// The bridge reads no document member through the document's own lookup.
    #[test]
    fn bridge_reads_the_document_only_through_the_bound_table() {
        assert_eq!(
            crate::js_document_scan::unbound_document_reads(super::BRIDGE_JS),
            Vec::<String>::new(),
            "the webview bridge names `document` only in its bound table"
        );
    }
}

#[cfg(not(feature = "webview"))]
mod imp {
    use super::*;
    use crate::core::IpeResult;

    /// Stub `webview_app` — compiled when the `webview` feature is off (no system
    /// webview libraries). Returns a graceful `Err` with a remediation message.
    #[allow(clippy::type_complexity)]
    pub fn webview_app<Model, Msg, E, FInit, FUpdate, FView, FSubs>(
        _init: FInit,
        _update: FUpdate,
        _view: FView,
        _subscriptions: FSubs,
        _window: WebViewWindowCfg,
    ) -> IpeTask<E, ()>
    where
        E: Send + From<String> + 'static,
        Model: Clone + Send + 'static,
        Msg: Clone + Send + 'static,
        FInit: Fn(crate::dom::req::WebReq) -> (Model, IpeCmd<Msg>) + Send + 'static,
        FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + 'static,
        FView: Fn(Model) -> Html<Msg> + Send + 'static,
        FSubs: Fn(Model) -> IpeSub<Msg> + Send + 'static,
    {
        Box::pin(async move {
            IpeResult::Err(
                "Webview.app: this Ipe build has no native webview backend. Rebuild \
                 with `--features webview` on a machine with the webview dev \
                 libraries (Linux: webkit2gtk + libsoup; macOS: WKWebView; Windows: \
                 the Edge WebView2 runtime)."
                    .to_string()
                    .into(),
            )
        })
    }
}

#[cfg(feature = "webview")]
mod imp {
    use super::*;
    use crate::core::{IpeResult, ok_res};
    use crate::html::{assign_ipe_ids, render_html};
    use crate::web::dispatch::build_index;
    use crate::web::page_shell;

    /// Encode `s` as a JSON string literal for embedding in `evaluate_script`.
    /// Delegates to serde (already a dep here via `parse_ipc`) so there is one
    /// escaping implementation. serde never fails on a `&str`; the `Err` arm is
    /// unreachable but kept total (a minimal correct literal fallback).
    fn json_str(s: &str) -> String {
        serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
    }

    /// The synchronous webview event loop doesn't pump tokio, so a real (non-`None`)
    /// `Cmd` returned from `init`/`update` is dropped. Warn ONCE so this otherwise-
    /// silent dropped-effect behaviour is observable rather than a quiet surprise.
    fn warn_dropped_cmd_if_real<M>(cmd: &IpeCmd<M>) {
        use std::sync::Once;
        static WARNED: Once = Once::new();
        if !matches!(cmd, IpeCmd::None) {
            WARNED.call_once(|| {
                crate::system::emit_runtime_log(
                    "webview",
                    "warn: a non-`Cmd.none` command was returned but Ipe.WebView v0.1's \
                     synchronous event loop does not run Cmd.perform/Sub.every yet — the \
                     effect was dropped.",
                );
            });
        }
    }

    /// Parse `{ipeId, event, args}` (from the bridge) without serde.
    fn parse_ipc(body: &str) -> Option<(String, String, Vec<String>)> {
        let v: serde_json::Value = serde_json::from_str(body).ok()?;
        let ipe_id = v.get("ipeId")?.as_str()?.to_string();
        let event = v.get("event")?.as_str()?.to_string();
        let args = v
            .get("args")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Some((ipe_id, event, args))
    }

    /// Render the view to an `(html_body, HandlerIndex)` pair, stamping ipe-ids.
    fn render<Model, Msg, FView>(
        view: &FView,
        model: &Model,
    ) -> (String, crate::web::dispatch::HandlerIndex<Msg>)
    where
        Model: Clone,
        Msg: Clone,
        FView: Fn(Model) -> Html<Msg>,
    {
        let mut tree = view(model.clone());
        assign_ipe_ids(&mut tree, "r");
        crate::web::style_inject::apply_style_injections(&mut tree);
        let index = build_index(&tree);
        (render_html(&tree), index)
    }

    /// Real `Webview.app` — opens a native window and runs the TEA loop on the
    /// event-loop thread. DOM events arrive over IPC, resolve to Msgs via the
    /// reused `HandlerIndex`, drive `update`, and re-render via `evaluate_script`.
    ///
    /// The future has no `.await` after the (`!Send`) window/webview are created
    /// — `event_loop.run` is synchronous + diverging — so the future stays `Send`
    /// (`IpeTask`'s bound) while the webview itself never crosses an await.
    /// Async `Cmd.perform` / `Sub.every` are a follow-on (the synchronous event
    /// loop doesn't pump tokio); `Cmd.none` works.
    #[allow(clippy::type_complexity)]
    pub fn webview_app<Model, Msg, E, FInit, FUpdate, FView, FSubs>(
        init: FInit,
        update: FUpdate,
        view: FView,
        _subscriptions: FSubs,
        window: WebViewWindowCfg,
    ) -> IpeTask<E, ()>
    where
        E: Send + From<String> + 'static,
        Model: Clone + Send + 'static,
        Msg: Clone + Send + 'static,
        FInit: Fn(crate::dom::req::WebReq) -> (Model, IpeCmd<Msg>) + Send + 'static,
        FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + 'static,
        FView: Fn(Model) -> Html<Msg> + Send + 'static,
        FSubs: Fn(Model) -> IpeSub<Msg> + Send + 'static,
    {
        Box::pin(async move {
            use tao::dpi::LogicalSize;
            use tao::event::{Event, WindowEvent};
            use tao::event_loop::{ControlFlow, EventLoopBuilder};
            #[cfg(target_os = "linux")]
            use tao::platform::unix::WindowExtUnix;
            use tao::window::WindowBuilder;
            use wry::WebViewBuilder;
            #[cfg(target_os = "linux")]
            use wry::WebViewBuilderExtUnix;

            #[derive(Debug)]
            enum UserEvent {
                Ipc(String),
            }

            // The entry drives a Ipe.WebView app via `block_on_current_thread`
            // (see task.rs), so this future is polled on the process's TRUE main
            // thread on EVERY OS. tao/winit's `EventLoop` + Cocoa's
            // `NSApplication` require the main thread on macOS (hard Cocoa
            // requirement); Windows expects it too; GTK on Linux is happy on the
            // main thread. So the event loop is built uniformly on the main
            // thread — no per-OS `with_any_thread(true)` escape hatch is needed
            // (that was only required when the loop was constructed OFF the main
            // thread, which no longer happens).
            let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
            let (w, h) = window.size;
            // `with_inner_size` maps `size` to the content/inner area — the
            // drawable region — not the outer OS frame. On macOS this calls
            // `initWithContentRect:` so the content rect is exactly (w, h) in
            // CSS-logical pixels; the title bar is additive on top. This is
            // the correct semantic for an app-specified window size: the app
            // controls its content area, not the platform chrome.
            let win = match WindowBuilder::new()
                .with_title(&window.title)
                .with_inner_size(LogicalSize::new(w.max(1) as f64, h.max(1) as f64))
                .build(&event_loop)
            {
                Ok(win) => win,
                Err(e) => return IpeResult::Err(format!("Webview.app: window: {e}").into()),
            };

            // A native window has no incoming HTTP request; the app opens at its
            // root, so `init` receives the same initial-load `WebReq` a fresh
            // browser `GET /` reports. This is the ONE Web.tea init shape across
            // the served, WASM, and webview hosts — never a divergent `()`.
            let (mut model, _cmd0) = init(crate::dom::req::WebReq::local_root());
            warn_dropped_cmd_if_real(&_cmd0);
            let (body0, mut index) = render::<Model, Msg, _>(&view, &model);
            let tail = format!("<script>{BRIDGE_JS}</script>");
            let html = page_shell("", &body0, &tail);

            let proxy = event_loop.create_proxy();
            // Modern wry: `WebViewBuilder::new()` is no-arg; the window is supplied
            // at build time. The IPC handler closure receives the message as a
            // `wry::http::Request<String>`; we forward its body to the TEA loop.
            let builder = WebViewBuilder::new().with_html(html).with_ipc_handler(
                move |req: wry::http::Request<String>| {
                    let _ = proxy.send_event(UserEvent::Ipc(req.into_body()));
                },
            );
            // Build per-OS: raw-window-handle path off Linux, gtk widget on Linux
            // (so Wayland + X11 both work). Both return `wry::Result<WebView>`.
            #[cfg(not(target_os = "linux"))]
            let built: wry::Result<wry::WebView> = builder.build(&win);
            #[cfg(target_os = "linux")]
            // Pack into the window's default vertical `gtk::Box` when present —
            // a tao `gtk::ApplicationWindow` is a single-child `GtkBin` that
            // already holds that box, so adding the WebKitWebView to the window
            // directly is a GTK contract violation (the "can only contain one
            // widget" warning). The box is the correct container; fall back to
            // the window only if the default vbox was disabled.
            let built: wry::Result<wry::WebView> = match win.default_vbox() {
                Some(vbox) => builder.build_gtk(vbox),
                None => builder.build_gtk(win.gtk_window()),
            };
            let webview = match built {
                Ok(wv) => wv,
                Err(e) => return IpeResult::Err(format!("Webview.app: webview: {e}").into()),
            };

            event_loop.run(move |event, _target, control_flow| {
                *control_flow = ControlFlow::Wait;
                match event {
                    Event::WindowEvent {
                        event: WindowEvent::CloseRequested,
                        ..
                    } => {
                        *control_flow = ControlFlow::Exit;
                    }
                    Event::UserEvent(UserEvent::Ipc(body)) => {
                        if let Some((ipe_id, ev, args)) = parse_ipc(&body)
                            && let Some(msg) = index.resolve(&ipe_id, &ev, &args)
                        {
                            let (next, _cmd) = update(msg, model.clone());
                            warn_dropped_cmd_if_real(&_cmd);
                            model = next;
                            let (nbody, nindex) = render::<Model, Msg, _>(&view, &model);
                            index = nindex;
                            let js = format!("window.__ipeApply({})", json_str(&nbody));
                            let _ = webview.evaluate_script(&js);
                        }
                    }
                    _ => {}
                }
            });

            // event_loop.run diverges; this is unreachable but satisfies the type.
            #[allow(unreachable_code)]
            ok_res(())
        })
    }
}

pub use imp::webview_app;
