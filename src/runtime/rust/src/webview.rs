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
//! loop is built uniformly (`shell::WindowSystem::open`), with no per-OS
//! `with_any_thread(true)` branch. The webview itself is built per-OS:
//! `build(&window)` (raw-window-handle) off Linux, `build_gtk(...)` on Linux.
//!
//! Two builds: the real backend is behind the opt-in `webview` Cargo feature
//! (needs the system webview dev libraries); otherwise a stub returning a graceful
//! `Err` is compiled, so a `web desktop` build always links + never panics. No
//! panic vectors: the stub returns `Err`; the real path routes every fallible
//! call through `Err`.
//!
//! [`bundle_app`] is the `client desktop` shell: one window serving an
//! embedded bundle from memory under the shell's custom scheme, behind the
//! `webview-shell` feature, with no IPC channel and no injected script. Both
//! hosts install the one navigation policy of [`nav_policy::attach_policy`].

#[cfg(any(
    feature = "webview-shell",
    all(test, feature = "encoding", not(target_arch = "wasm32"))
))]
pub mod bundle_site;
#[cfg(any(
    feature = "webview-shell",
    all(test, feature = "browser-open", not(target_arch = "wasm32"))
))]
pub mod nav_policy;

#[cfg(feature = "tokio")]
use super::core::IpeTask;
#[cfg(feature = "tokio")]
use super::html::Html;
#[cfg(feature = "tokio")]
use super::tea::{IpeCmd, IpeSub};

/// Window configuration — mirrors Ipê's closed `WindowCfg { title, size }`.
///
/// `size` is the logical **content/inner** area in CSS pixels: the drawable
/// region the Ipê view occupies, not the outer OS frame (title bar + border).
/// Tao's `with_inner_size` honours this: on macOS it calls `initWithContentRect:`
/// with the content rect (the same Cocoa API that backs `NSWindow.contentView`),
/// so a `size = (800, 500)` config gives exactly 800×500 px of content regardless
/// of the native title-bar height.
#[cfg(feature = "tokio")]
#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct WebViewWindowCfg {
    pub title: String,
    pub size: (i64, i64),
}

/// Phantom marker for Ipê's `AppCfg model msg` record alias (destructured at the
/// call site, never built in Rust). See the codegen `markerCfgAliases`.
#[cfg(feature = "tokio")]
pub struct WebViewAppCfg;

// Bridge JS: delegated event listeners on the document forward DOM events on
// `[ipe-id]` elements to the IPC channel as `{ipeId, event, args}`. Re-bound
// implicitly via event delegation, so a full innerHTML swap needs no re-bind.
#[cfg(any(feature = "webview", all(test, not(target_arch = "wasm32"))))]
const BRIDGE_JS: &str = r#"
(function(){
  // The document members the bridge reads, bound from the prototypes before any
  // page content is consulted: an `img`, `form`, `embed`, `object` or `iframe`
  // named after a document member shadows that member with the element.
  var doc=(function(d){
    var body=Object.getOwnPropertyDescriptor(Document.prototype,'body');
    var active=Object.getOwnPropertyDescriptor(Document.prototype,'activeElement');
    return { body:function(){ return body.get.call(d); }, active:function(){ return active.get.call(d); }, on:EventTarget.prototype.addEventListener.bind(d) };
  })(document);
  // The element members the focus keep reads, bound from the prototypes: a
  // `form` names its controls as its own members.
  var node=(function(){
    function getter(p,n){ return Object.getOwnPropertyDescriptor(p,n).get; }
    var attr=Element.prototype.getAttribute, has=Node.prototype.contains;
    var parent=getter(Node.prototype,'parentElement'), first=getter(Element.prototype,'firstElementChild');
    var next=getter(Element.prototype,'nextElementSibling'), tag=getter(Element.prototype,'tagName');
    var focusers=[[HTMLElement,HTMLElement.prototype.focus],[SVGElement,SVGElement.prototype.focus]];
    return {
      attr:function(el,n){ return attr.call(el,n); }, contains:function(el,o){ return has.call(el,o); },
      parent:function(el){ return parent.call(el); }, first:function(el){ return first.call(el); },
      next:function(el){ return next.call(el); }, tag:function(el){ return tag.call(el); },
      focus:function(el){
        for(var i=0;i<focusers.length;i++){
          if(el instanceof focusers[i][0]){ try{ focusers[i][1].call(el,{preventScroll:true}); }catch(e){} break; }
        }
        return doc.active()===el;
      }
    };
  })();
  // The focus keep (`dom::focus`, the rule `client.js` and the wasm client run
  // too): each render replaces the body's markup, which drops focus to the
  // body. Before it, the view chain of the focused node is recorded: the
  // `ipe-id` and tag of each element from the body's child down to it, cut at
  // the first element with no `ipe-id`, and only when the first carries one.
  // After it, when nothing holds focus, focus goes to the deepest node of the
  // chain still in the view that takes focus: each depth takes the ONE child
  // whose `ipe-id` and tag equal the link (none or several end the descent),
  // so an equal `ipe-id` under another chain never matches.
  var FOCUS_CHAIN_MAX=1024;
  function focusChain(root){
    var now=doc.active();
    if(!now||now===root||!node.contains(root,now)) return null;
    var up=[];
    for(var at=now; at&&at!==root; at=node.parent(at)){
      if(up.length>=FOCUS_CHAIN_MAX) return null;
      up.push({id:node.attr(at,'ipe-id'), tag:node.tag(at)});
    }
    var chain=[];
    for(var i=up.length-1; i>=0&&up[i].id!==null; i--) chain.push(up[i]);
    return chain.length>0 ? chain : null;
  }
  function restoreFocus(root, chain){
    var found=[], at=root;
    for(var d=0; d<chain.length; d++){
      var only=null, count=0;
      for(var kid=node.first(at); kid; kid=node.next(kid)){
        if(node.attr(kid,'ipe-id')===chain[d].id && node.tag(kid)===chain[d].tag){ only=kid; count++; }
      }
      if(count!==1) break;
      found.push(only); at=only;
    }
    for(var m=found.length-1; m>=0; m--){ if(node.focus(found[m])) return; }
  }
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
  window.__ipeApply = function(html){
    var b=doc.body(); if(!b) return;
    var chain=focusChain(b);
    b.innerHTML = html;
    var now=doc.active();
    if(chain!==null && (!now||now===b)) restoreFocus(b, chain);
  };
})();
"#;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    /// The bridge reads no document member through the document's own lookup.
    #[test]
    fn bridge_reads_the_document_only_through_the_bound_table() {
        assert_eq!(
            crate::js_document_scan::unbound_document_reads(super::BRIDGE_JS),
            Vec::<String>::new(),
            "the webview bridge names `document` only in its bound table"
        );
        assert_eq!(super::BRIDGE_JS.matches("})(document);").count(), 1);
    }

    /// Each render, a whole-body swap, runs inside the focus keep: the chain is
    /// recorded before the swap and put back after it only while nothing holds
    /// focus, by the runtime's own chain bound.
    ///
    /// Without it every webview render dropped focus to the body, so a key
    /// handler on an ancestor of the focused control stopped hearing keys.
    #[test]
    fn bridge_renders_inside_the_focus_keep() {
        let js = super::BRIDGE_JS;
        let open = "var FOCUS_CHAIN_MAX=";
        let bound = js
            .find(open)
            .and_then(|at| js.get(at + open.len()..))
            .and_then(|rest| rest.get(..rest.find(';')?))
            .and_then(|n| n.parse::<usize>().ok());
        assert_eq!(bound, Some(crate::dom::focus::FOCUS_CHAIN_MAX));
        assert_eq!(js.matches("innerHTML =").count(), 1, "one swap site");
        assert!(
            js.contains(
                "var chain=focusChain(b);\n    b.innerHTML = html;\n    var now=doc.active();\n    if(chain!==null && (!now||now===b)) restoreFocus(b, chain);"
            ),
            "the swap is bracketed by the record and the guarded restore"
        );
        assert!(
            js.contains("if(up.length>=FOCUS_CHAIN_MAX) return null;")
                && js.contains("i>=0&&up[i].id!==null")
                && js.contains("if(count!==1) break;")
                && js.contains(
                    "node.attr(kid,'ipe-id')===chain[d].id && node.tag(kid)===chain[d].tag"
                ),
            "the chain is bounded, cut at raw markup, and matched by id and tag at one child per depth"
        );
    }

    /// The source text of `bundle_app`, up to the end of its body.
    fn bundle_app_body() -> Option<&'static str> {
        include_str!("webview.rs")
            .split_once(concat!("pub fn ", "bundle_app("))
            .and_then(|(_, rest)| rest.split_once("\n    }\n"))
            .map(|(body, _)| body)
    }

    /// The text of the item that starts at `head`, up to the first line closing it at `close`.
    fn item_body(source: &'static str, head: &str, close: &str) -> Option<&'static str> {
        source
            .split_once(head)
            .and_then(|(_, rest)| rest.split_once(close))
            .map(|(body, _)| body)
    }

    /// Every `with_*` builder call `source` names, in order of appearance.
    fn builder_calls(source: &str) -> Vec<&str> {
        let mut calls = Vec::new();
        let mut rest = source;
        while let Some(at) = rest.find("with_") {
            let (before, from) = rest.split_at(at);
            let end = from
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(from.len());
            let (name, after) = from.split_at(end);
            let preceded = before
                .chars()
                .next_back()
                .is_some_and(|c| c == '.' || c == ':');
            if preceded && after.starts_with('(') {
                calls.push(name);
            }
            rest = after;
        }
        calls
    }

    /// The bundle shell opens no channel from the page to the host and runs no script of its own.
    ///
    /// `bundle_app` and its callees (`attach_policy`, `attach_webview`) build
    /// the webview through exactly the admitted builder call list, from the one
    /// admitted constructor `new_with_web_context`; `bundle_site.rs`, the
    /// handler's whole surface, names no injected-content or file spelling.
    #[test]
    fn bundle_shell_registers_no_ipc_or_injected_script() {
        let body = bundle_app_body();
        let Some(body) = body else {
            assert!(body.is_some(), "bundle_app is defined in webview.rs");
            return;
        };
        let attach = item_body(
            include_str!("webview.rs"),
            concat!("pub fn ", "attach_webview("),
            "\n    }\n",
        );
        let Some(attach) = attach else {
            assert!(attach.is_some(), "attach_webview is defined in webview.rs");
            return;
        };
        let policy = item_body(
            include_str!("webview/nav_policy.rs"),
            concat!("pub fn ", "attach_policy("),
            "\n}\n",
        );
        let Some(policy) = policy else {
            assert!(
                policy.is_some(),
                "attach_policy is defined in nav_policy.rs"
            );
            return;
        };
        let site = include_str!("webview/bundle_site.rs")
            .split_once(concat!("#[cfg(all(test, ", "not(target_arch"))
            .map(|(production, _)| production);
        let Some(site) = site else {
            assert!(site.is_some(), "bundle_site.rs has a test module");
            return;
        };
        assert_eq!(
            body.matches(concat!("shell::", "attach_webview(")).count(),
            1
        );
        assert_eq!(
            body.matches(concat!("nav_policy::", "attach_policy("))
                .count(),
            1
        );
        let mut calls = builder_calls(body);
        calls.extend(builder_calls(attach));
        calls.extend(builder_calls(policy));
        calls.sort_unstable();
        assert_eq!(
            calls,
            [
                "with_custom_protocol",
                "with_devtools",
                "with_download_started_handler",
                "with_drag_drop_handler",
                "with_https_scheme",
                "with_navigation_handler",
                "with_new_window_req_handler",
                "with_title",
                "with_url",
            ],
            "the one admitted builder call list"
        );
        assert_eq!(body.matches("WebViewBuilder::").count(), 1);
        assert_eq!(
            body.matches("WebViewBuilder::new_with_web_context(")
                .count(),
            1
        );
        assert_eq!(body.matches("with_devtools(false)").count(), 1);
        for (part, text) in [
            ("bundle_app", body),
            ("attach_webview", attach),
            ("attach_policy", policy),
            ("bundle_site.rs", site),
        ] {
            for banned in [
                "with_ipc_handler",
                "with_initialization_script",
                "evaluate_script",
                "with_html",
                "file://",
                "with_incognito",
                "WebViewBuilder::new(",
            ] {
                assert!(!text.contains(banned), "{part} must not name {banned}");
            }
        }
    }

    /// The served host installs the same policy, on its inline document.
    #[test]
    fn served_webview_attaches_the_policy() {
        let source = include_str!("webview.rs");
        assert!(source.contains(concat!("LocalOrigin::", "InlineDocument,")));
        assert_eq!(
            source
                .matches(concat!("nav_policy::", "attach_policy("))
                .count(),
            2
        );
    }

    /// `source` without its test module: the code before the module's
    /// `#[cfg(all(test, …))]` line and after the module's closing brace.
    fn production(source: &'static str) -> Option<String> {
        let (head, rest) = source.split_once(concat!(
            "#[cfg(all(test, ",
            "not(target_arch = \"wasm32\")))]\nmod tests {"
        ))?;
        let (_, tail) = rest.split_once("\n}\n")?;
        Some(format!("{head}{tail}"))
    }

    /// The identifier tokens of `text`: maximal runs of `[A-Za-z0-9_]`.
    fn tokens(text: &str) -> Vec<&str> {
        text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|token| !token.is_empty())
            .collect()
    }

    /// The byte offset of the one occurrence of `needle` in `text`.
    fn sole_offset(text: &str, needle: &str) -> Option<usize> {
        (text.matches(needle).count() == 1)
            .then(|| text.find(needle))
            .flatten()
    }

    /// No GTK-backed object exists before the window system is up, and a
    /// missing display is a typed refusal on every webview entry point.
    ///
    /// On Linux GTK's constructors panic until GTK is initialized, and tao's
    /// event loop builder initializes it with a panic when no display
    /// answers. Only `shell::WindowSystem::open` builds an event loop, after
    /// the fallible `gtk::init()`; a web context is built only from an open
    /// `WindowSystem`; and both hosts open it before any window or web
    /// context, the bundle shell after its storage and site refusals (which
    /// therefore hold on a host with no display).
    #[test]
    fn no_native_object_precedes_the_window_system() {
        let mut outside = Vec::new();
        for (name, source) in [
            ("webview.rs", include_str!("webview.rs")),
            ("nav_policy.rs", include_str!("webview/nav_policy.rs")),
            ("bundle_site.rs", include_str!("webview/bundle_site.rs")),
        ] {
            let Some(code) = production(source) else {
                outside.push(format!("{name}: no test module found"));
                continue;
            };
            let code = match code.split_once(concat!("\nmod ", "shell {\n")) {
                Some((head, rest)) => match rest.split_once("\n}\n") {
                    Some((_, tail)) => format!("{head}{tail}"),
                    None => {
                        outside.push(format!("{name}: the shell module is unclosed"));
                        continue;
                    }
                },
                None => code,
            };
            for token in tokens(&code) {
                if ["EventLoopBuilder", "EventLoop", "WebContext", "gtk"].contains(&token) {
                    outside.push(format!("{name}: `{token}` outside the shell module"));
                }
            }
        }
        assert_eq!(
            outside,
            Vec::<String>::new(),
            "only the shell module names the native constructors"
        );

        let source = include_str!("webview.rs");
        let shell = item_body(source, concat!("\nmod ", "shell {\n"), "\n}\n");
        let Some(shell) = shell else {
            assert!(shell.is_some(), "the shell module is defined in webview.rs");
            return;
        };
        let open = item_body(
            shell,
            concat!("pub fn ", "open() -> Result<Self, WindowSystemRefused> {"),
            "\n        }\n",
        );
        let Some(open) = open else {
            assert!(open.is_some(), "WindowSystem::open is defined");
            return;
        };
        let init = sole_offset(
            open,
            concat!("gtk::", "init().map_err(WindowSystemRefused::Gtk)?;"),
        );
        let build = sole_offset(
            open,
            concat!("EventLoop", "Builder::<T>::with_user_event().build()"),
        );
        assert!(
            matches!((init, build), (Some(i), Some(b)) if i < b),
            "GTK starts fallibly before tao builds the event loop: {init:?} {build:?}"
        );
        let shell_tokens = tokens(shell);
        for (token, count) in [("EventLoopBuilder", 1), ("WebContext", 2)] {
            assert_eq!(
                shell_tokens.iter().filter(|t| **t == token).count(),
                count,
                "the shell module names `{token}` {count} times"
            );
        }
        assert_eq!(
            shell.matches(concat!("gtk::", "init(")).count(),
            1,
            "the shell module calls GTK init exactly once"
        );
        assert_eq!(shell.matches(concat!("Self { ", "event_loop }")).count(), 1);
        assert_eq!(
            shell
                .matches(concat!("pub fn ", "web_context(&self, "))
                .count(),
            1,
            "a web context is built only from an open window system"
        );

        let bundle = bundle_app_body();
        let Some(bundle) = bundle else {
            assert!(bundle.is_some(), "bundle_app is defined in webview.rs");
            return;
        };
        let order = [
            sole_offset(bundle, concat!("BundleSite::", "parse(")),
            sole_offset(bundle, concat!("AppDataRoot::", "from_env()")),
            sole_offset(bundle, concat!("StoragePlan::", "resolve(")),
            sole_offset(bundle, concat!("WindowSystem::<()>::", "open()")),
            sole_offset(bundle, concat!("system.", "web_context(")),
            sole_offset(bundle, concat!("WindowBuilder::", "new()")),
        ];
        assert!(
            order.iter().all(Option::is_some) && order.is_sorted(),
            "bundle_app refuses its site and storage, then opens the window system, \
             then builds the web context and the window: {order:?}"
        );
        let worker = item_body(
            source,
            concat!(
                "pub fn ",
                "webview_app<Model, Msg, E, FInit, FUpdate, FView, FSubs>(\n        init:"
            ),
            "\n    }\n",
        );
        let Some(worker) = worker else {
            assert!(worker.is_some(), "the native webview_app is defined");
            return;
        };
        let order = [
            sole_offset(worker, concat!("WindowSystem::<UserEvent>::", "open()")),
            sole_offset(worker, concat!("WindowBuilder::", "new()")),
        ];
        assert!(
            order.iter().all(Option::is_some) && order.is_sorted(),
            "webview_app opens the window system before its window: {order:?}"
        );
    }
}

/// The window and webview steps both hosts share.
#[cfg(feature = "webview-shell")]
mod shell {
    /// The native window system, up on this thread: the one value every
    /// event loop, window and web context is built from.
    ///
    /// On Linux GTK backs all three, and GTK's constructors panic until GTK is
    /// initialized; tao's event loop builder initializes it and panics when no
    /// display answers. [`WindowSystem::open`] runs GTK's fallible
    /// `gtk_init_check` first, which makes tao's own init a no-op, so a missing
    /// display is a [`WindowSystemRefused`] and no GTK object exists before
    /// the window system does.
    pub struct WindowSystem<T: 'static> {
        event_loop: tao::event_loop::EventLoop<T>,
    }

    /// Why the window system could not start.
    #[derive(Debug)]
    pub enum WindowSystemRefused {
        /// GTK could not initialize: no display answered.
        #[cfg(target_os = "linux")]
        Gtk(gtk::glib::BoolError),
    }

    impl std::fmt::Display for WindowSystemRefused {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match *self {
                #[cfg(target_os = "linux")]
                Self::Gtk(ref cause) => {
                    write!(f, "no graphical display is available ({cause})")
                }
            }
        }
    }

    impl<T: 'static> WindowSystem<T> {
        /// Start the window system on the calling (main) thread.
        ///
        /// # Errors
        /// [`WindowSystemRefused`] when no display answers.
        pub fn open() -> Result<Self, WindowSystemRefused> {
            #[cfg(target_os = "linux")]
            gtk::init().map_err(WindowSystemRefused::Gtk)?;
            let event_loop = tao::event_loop::EventLoopBuilder::<T>::with_user_event().build();
            Ok(Self { event_loop })
        }

        /// The event loop windows are built on.
        pub const fn event_loop(&self) -> &tao::event_loop::EventLoop<T> {
            &self.event_loop
        }

        /// A web context keeping its data in `dir`, or the engine's own store.
        pub fn web_context(&self, dir: Option<std::path::PathBuf>) -> wry::WebContext {
            wry::WebContext::new(dir)
        }

        /// The event loop, to run.
        pub fn into_event_loop(self) -> tao::event_loop::EventLoop<T> {
            self.event_loop
        }
    }

    /// Build `builder`'s webview into `window`.
    ///
    /// Off Linux through the raw window handle; on Linux packed into the
    /// window's default vertical `gtk::Box` when present (a tao window is a
    /// single-child `GtkBin` already holding that box), else the window.
    pub fn attach_webview(
        builder: wry::WebViewBuilder<'_>,
        window: &tao::window::Window,
    ) -> wry::Result<wry::WebView> {
        #[cfg(not(target_os = "linux"))]
        {
            builder.build(window)
        }
        #[cfg(target_os = "linux")]
        {
            use tao::platform::unix::WindowExtUnix;
            use wry::WebViewBuilderExtUnix;
            match window.default_vbox() {
                Some(vbox) => builder.build_gtk(vbox),
                None => builder.build_gtk(window.gtk_window()),
            }
        }
    }
}

/// Why the bundle shell did not open.
#[cfg(feature = "webview-shell")]
#[derive(Debug)]
pub enum BundleShellError {
    /// No display answered.
    NoDisplay(shell::WindowSystemRefused),
    /// The window could not be created.
    Window(tao::error::OsError),
    /// The webview could not be created.
    Webview(wry::Error),
    /// The embedded table is malformed.
    BadSite(bundle_site::SiteRefusal),
    /// The webview's storage could not be set up.
    Storage(crate::app_data::StorageRefusal),
    /// The link opener thread could not start.
    ThreadRefused(std::io::ErrorKind),
}

#[cfg(feature = "webview-shell")]
impl std::fmt::Display for BundleShellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDisplay(refusal) => write!(f, "{refusal}"),
            Self::Window(e) => write!(f, "the window could not open: {e}"),
            Self::Webview(e) => write!(f, "the webview could not start: {e}"),
            Self::BadSite(refusal) => write!(f, "the embedded app is malformed: {refusal}"),
            Self::Storage(refusal) => write!(f, "{refusal}"),
            Self::ThreadRefused(kind) => write!(f, "the link opener could not start ({kind})"),
        }
    }
}

#[cfg(feature = "webview-shell")]
mod bundle_imp {
    use super::BundleShellError;
    use super::bundle_site::{BundleSite, SiteConfig};
    use super::nav_policy::{ExternalOpener, LocalOrigin};
    use super::shell::WindowSystem;
    use crate::app_data::{AppDataRoot, StoragePlan, StorageRefusal};
    use crate::csp::{APP_SCHEME, SchemeSpelling};
    use std::borrow::Cow;

    /// Convert a site answer into the webview's response.
    fn to_response(
        answer: super::bundle_site::SiteResponse,
    ) -> wry::http::Response<Cow<'static, [u8]>> {
        let mut builder = wry::http::Response::builder().status(answer.status.code());
        for (name, value) in answer.headers {
            builder = builder.header(name, value);
        }
        builder
            .body(Cow::Borrowed(answer.body))
            .unwrap_or_else(|_| {
                let mut fallback = wry::http::Response::new(Cow::Borrowed(&[][..]));
                *fallback.status_mut() = wry::http::StatusCode::INTERNAL_SERVER_ERROR;
                fallback
            })
    }

    /// Open the `client desktop` window over the embedded bundle `config`.
    ///
    /// The bundle is served from memory under the shell's scheme; navigation
    /// stays on that exact origin, public `https` links open in the system
    /// browser, and the webview keeps its data in the bundle id's private
    /// directory. Runs the event loop on the calling (main) thread and returns
    /// only on a startup failure.
    ///
    /// # Errors
    /// The [`BundleShellError`] of the first step that failed.
    pub fn bundle_app(config: &SiteConfig) -> Result<(), BundleShellError> {
        use tao::event::{Event, WindowEvent};
        use tao::event_loop::ControlFlow;
        use tao::window::WindowBuilder;
        use wry::WebViewBuilder;

        let native = SchemeSpelling::native();
        let site =
            BundleSite::parse(config, SchemeSpelling::Scheme).map_err(BundleShellError::BadSite)?;
        let root = AppDataRoot::from_env()
            .map_err(|refusal| BundleShellError::Storage(StorageRefusal::Root(refusal)))?;
        let plan =
            StoragePlan::resolve(&root, site.storage_key()).map_err(BundleShellError::Storage)?;
        let system = WindowSystem::<()>::open().map_err(BundleShellError::NoDisplay)?;
        let mut context = system.web_context(match plan {
            StoragePlan::Private(dir) => Some(dir.as_path().to_path_buf()),
            StoragePlan::BundleStore => None,
        });
        let opener =
            ExternalOpener::start().map_err(|e| BundleShellError::ThreadRefused(e.kind()))?;
        let start = site.start_url(native);

        let window = WindowBuilder::new()
            .with_title(site.title())
            .build(system.event_loop())
            .map_err(BundleShellError::Window)?;
        let builder = WebViewBuilder::new_with_web_context(&mut context)
            .with_custom_protocol(APP_SCHEME.to_owned(), move |_id, request| {
                to_response(site.respond(request.method().as_str(), &request.uri().to_string()))
            })
            .with_devtools(false)
            .with_url(start);
        #[cfg(windows)]
        let builder = wry::WebViewBuilderExtWindows::with_https_scheme(builder, true);
        let builder =
            super::nav_policy::attach_policy(builder, LocalOrigin::BundleScheme(native), opener);
        let webview =
            super::shell::attach_webview(builder, &window).map_err(BundleShellError::Webview)?;

        system
            .into_event_loop()
            .run(move |event, _target, control_flow| {
                let _keep = (&webview, &context);
                *control_flow = ControlFlow::Wait;
                if let Event::WindowEvent {
                    event: WindowEvent::CloseRequested,
                    ..
                } = event
                {
                    *control_flow = ControlFlow::Exit;
                }
            })
    }
}

#[cfg(feature = "webview-shell")]
pub use bundle_imp::bundle_app;

#[cfg(all(feature = "tokio", not(feature = "webview")))]
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
            use tao::event_loop::ControlFlow;
            use tao::window::WindowBuilder;
            use wry::WebViewBuilder;

            #[derive(Debug)]
            enum UserEvent {
                Ipc(String),
            }

            // The entry drives a Ipe.WebView app via `block_on_current_thread`
            // (see task.rs), so this future is polled on the process's TRUE main
            // thread on EVERY OS. tao/winit's event loop + Cocoa's
            // `NSApplication` require the main thread on macOS (hard Cocoa
            // requirement); Windows expects it too; GTK on Linux is happy on the
            // main thread. So the event loop is built uniformly on the main
            // thread — no per-OS `with_any_thread(true)` escape hatch is needed
            // (that was only required when the loop was constructed OFF the main
            // thread, which no longer happens).
            let system = match super::shell::WindowSystem::<UserEvent>::open() {
                Ok(system) => system,
                Err(e) => return IpeResult::Err(format!("Webview.app: {e}").into()),
            };
            let event_loop = system.into_event_loop();
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
            let opener = match super::nav_policy::ExternalOpener::start() {
                Ok(opener) => opener,
                Err(e) => {
                    return IpeResult::Err(format!("Webview.app: link opener: {e}").into());
                }
            };
            let builder = super::nav_policy::attach_policy(
                builder,
                super::nav_policy::LocalOrigin::InlineDocument,
                opener,
            );
            let built = super::shell::attach_webview(builder, &win);
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

#[cfg(feature = "tokio")]
pub use imp::webview_app;
