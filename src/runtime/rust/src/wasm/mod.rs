//! Browser-WASM TEA sink — mount, patch-apply, delegated events, scheduler.
//!
//! The same data path as the Ipe.Web SSE wire, with the transport swapped
//! for in-process calls: `view` → `Html<M>` (`ui/render.rs`) →
//! `dom::diff` → `Vec<Patch>` → typed `web-sys` DOM mutation. One diff
//! algorithm, two consumers (the SSE client and this sink), so behaviour
//! stays byte-parity with the server-driven path.
//!
//! Mount applies the sanitiser-gated `render_html` output through ONE
//! renderer (the same string the SSE first paint serves), so the DOM the
//! diff subsequently patches is byte-identical to what `render_html`
//! produces — a hand-rolled node builder would be a second render
//! implementation that could drift from the first. `Patch.html` subtree
//! replaces flow through the same gate.
//!
//! Casting discipline: every JS→web-sys crossing uses the CHECKED
//! `dyn_into`/`dyn_ref` (the DOM is mutable by extensions and devtools; an
//! unchecked cast on a foreign node is UB in the glue). A failed cast routes
//! to the classified console-error path, never a trap.
//!
//! `Sub.every`/`Time.every` (via `subs::SubManager`, `gloo-timers`) and
//! `Cmd.publish`/`PubSub.publish`/`Sub.subscribeTopic` (via `pubsub`, an
//! in-tab broker) are the M4 Cmd/Sub browser bridge — see each submodule's
//! doc comment. Client-side routing (`wasm_app_routed`) uses the browser
//! History API: mount, `popstate`, and in-app navigation enter the URL
//! through the same `route::enter` the server uses — one algorithm, every
//! entry point — and each entry runs the page's entry Cmd.

#![allow(clippy::type_complexity)] // TEA fn-quadruples are inherent here

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

use crate::core::{IpeResult, IpeTask};
use crate::dom::{HandlerIndex, WebReq, build_index, diff::Patch, diff::diff};
use crate::html::{FormData, Html, assign_ipe_ids, render_html};
use crate::tea::{IpeCmd, IpeSub};

#[cfg(feature = "debugger")]
mod debugger_overlay;
pub mod pubsub;
mod subs;
pub mod widget;

/// Root ipe-id path — matches the Web/WebView renderers so a future
/// SSR-adopt path sees identical ids.
const ROOT_IPE_ID: &str = "r";

/// Classified fatal-diagnostic prefix (mirrors the native panic classifier's
/// taxonomy labels; the instance may be unusable after one of these).
fn console_fatal(class: &str, detail: &str) {
    web_sys::console::error_1(&JsValue::from_str(&format!("[ipe-wasm:{class}] {detail}")));
}

/// Shared non-fatal diagnostic sink — reused by `ws_client.rs`'s
/// `web_socket_connect_with` (browser platform limitations that degrade
/// rather than fail, e.g. unsettable custom headers), and by the emitted
/// `hydrate` wasm export for fault-tolerant SSR takeover.
pub fn console_warn(detail: &str) {
    web_sys::console::warn_1(&JsValue::from_str(&format!("[ipe-wasm] {detail}")));
}

/// Install `console_error_panic_hook` so a residual trap (e.g. stack
/// exhaustion from a non-TCO fold — the documented reachable residual)
/// dies with a classified `console.error`, never a silent white screen.
pub fn install_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Drive the program's entry task on the browser microtask queue.
/// The `Err` arm logs a classified diagnostic (there is no process to exit).
pub fn run_start<E: std::fmt::Debug + 'static>(task: IpeTask<E, ()>) {
    wasm_bindgen_futures::spawn_local(async move {
        if let IpeResult::Err(e) = task.await {
            console_fatal("EntryFailed", &format!("{e:?}"));
        }
    });
}

/// `Web.tea` compiled for the browser: mount into `document.body`, then run
/// the update→diff→patch loop locally. Session stores do not exist client-side;
/// `init` receives a `WebReq` synthesised from `location` + `document.cookie`.
///
/// For routed apps (`Web.tea { …, routes, notFound }` with a `page` field in
/// the Model) see [`wasm_app_routed`].
pub fn wasm_app<E, Model, Msg, FInit, FUpdate, FView, FSubs>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
) -> IpeTask<E, ()>
where
    E: From<String> + 'static,
    Model: Clone + 'static,
    Msg: Clone + crate::stringify::IpeStringify + 'static,
    FInit: Fn(WebReq) -> (Model, IpeCmd<Msg>) + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + 'static,
    FView: Fn(Model) -> Html<Msg> + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + 'static,
{
    Box::pin(async move {
        match mount_app(init, update, view, subscriptions) {
            Ok(()) => IpeResult::Ok(()),
            Err(e) => {
                console_fatal("MountFailed", &e);
                IpeResult::Err(E::from(e))
            }
        }
    })
}

/// Hydration entry for isomorphic SSR + WASM (M7 mode 2).
///
/// The emitted `hydrate(model_json)` wasm-bindgen export calls this function
/// with the already-parsed `HydrationState` value (converted to the `Model`
/// type via the app-supplied `from_hydration` projection). On a parse error in
/// the caller, it falls back to calling `init` instead — this function is
/// therefore always called with a valid, fully-typed model.
///
/// The **adopt path** — unlike `mount_app`, does NOT call `set_inner_html`.
/// The server-rendered DOM is already correct; we compute the virtual tree
/// from `view(model)`, build the handler index, and wire delegated event
/// listeners. The first user interaction triggers the normal diff→patch cycle.
///
/// Dev-mode empty-first-diff assertion: after adoption, `diff` of the new
/// virtual tree against itself must be empty (ipe-ids match ↔ SSR and client
/// view are deterministic). A non-empty diff is a determinism violation — logged
/// as a classified warning and the DOM is patched to the client's view
/// (production fallback, never a white-screen).
pub fn wasm_adopt_app<E, Model, Msg, FUpdate, FView, FSubs>(
    model: Model,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
) -> IpeTask<E, ()>
where
    E: From<String> + 'static,
    Model: Clone + 'static,
    Msg: Clone + crate::stringify::IpeStringify + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + 'static,
    FView: Fn(Model) -> Html<Msg> + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + 'static,
{
    Box::pin(async move {
        match adopt_app(model, update, view, subscriptions) {
            Ok(()) => IpeResult::Ok(()),
            Err(e) => {
                console_fatal("AdoptFailed", &e);
                IpeResult::Err(E::from(e))
            }
        }
    })
}

/// `Web.tea { …, routes, notFound }` with a `page` field compiled for the
/// browser. Mirrors `web_app_routed` on the server, but session-free: the
/// model lives in the tab, URLs are matched client-side, and navigation uses
/// the History API.
///
/// URL → page entry uses the same `route::enter` the server uses (one
/// algorithm, every entry point). On mount, on every `popstate` event, and on
/// in-app navigation the router applies `set_page(matched_page, current_model)`
/// → (new model, entry Cmd), runs the view→diff→patch cycle, then runs the
/// entry Cmd — matching the server's `init`/`set_page` flow.
///
/// `init` receives a `WebReq` synthesised from `location` + cookies, the same
/// shape `wasm_app` uses.
pub fn wasm_app_routed<E, Model, Msg, Page, FInit, FUpdate, FView, FSubs, FSetPage, FRender>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
    routes: Vec<crate::web::route::Route<Page>>,
    not_found: Page,
    set_page: FSetPage,
    render: FRender,
) -> IpeTask<E, ()>
where
    E: From<String> + 'static,
    Model: Clone + 'static,
    Msg: Clone + crate::stringify::IpeStringify + 'static,
    Page: Clone + 'static,
    FInit: Fn(WebReq) -> (Model, IpeCmd<Msg>) + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + 'static,
    FView: Fn(Model) -> Html<Msg> + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + 'static,
    FSetPage: Fn(Page, Model) -> (Model, IpeCmd<Msg>) + 'static,
    FRender: Fn(&Page) -> Result<crate::web::route::RoutePath, crate::web::route::RenderRefusal>
        + 'static,
{
    Box::pin(async move {
        match mount_app_routed(
            init,
            update,
            view,
            subscriptions,
            routes,
            not_found,
            set_page,
            render,
        ) {
            Ok(()) => IpeResult::Ok(()),
            Err(e) => {
                console_fatal("MountFailed", &e);
                IpeResult::Err(E::from(e))
            }
        }
    })
}

thread_local! {
    /// Distinct origin token per mounted app instance — the wasm analogue of
    /// a Web session's sid, used ONLY to scope `Cmd.publish`/`PubSub.publish`
    /// echo-suppression (`wasm::pubsub`) to the mount instance that owns a
    /// given `Sub.subscribeTopic`. Monotonic within one wasm module instance
    /// (a fresh page load always resets it), so two `wasm_app`/`wasm::mount`
    /// calls on the same page (e.g. multiple embeds) never collide.
    static NEXT_INSTANCE_ID: Cell<u64> = const { Cell::new(1) };

    /// One-time guard for the `Ipe.Ffi.Js` port inbound seam. The seam is a single
    /// process-global `window.__ipePortSend` slot every mount instance shares
    /// (like the outbound `window.ipeOnReceive` handler); installing it once per
    /// tab avoids leaking a fresh closure on every embed.
    static PORT_SEAM_INSTALLED: Cell<bool> = const { Cell::new(false) };
}
fn next_instance_origin() -> String {
    NEXT_INSTANCE_ID.with(|c| {
        let id = c.get();
        c.set(id + 1);
        format!("wasm-instance-{id}")
    })
}

/// Install the `Ipe.Ffi.Js` port inbound seam once per tab.
///
/// The page glue's `window.ipe.send(value)` funnels an inbound JSON string to
/// `window.__ipePortSend`; this installs that slot as a closure that hands the
/// string to `js_port::push_inbound`, which fans it out to every active
/// `Js.subscribe` drain. Each drain decodes the string fail-closed through the
/// bounded seal decoder — a malformed or oversized frame is dropped whole, never
/// a trap. Idempotent: the closure is installed at most once and lives for the
/// tab's lifetime.
fn install_port_inbound_seam() {
    if PORT_SEAM_INSTALLED.with(Cell::get) {
        return;
    }
    let Some(window) = web_sys::window() else {
        return;
    };
    let seam = Closure::<dyn Fn(JsValue)>::new(move |raw: JsValue| {
        // The page glue always stringifies before calling this slot; a non-string
        // value is a misuse of the seam and is dropped rather than trapping.
        if let Some(s) = raw.as_string() {
            crate::js_port::push_inbound(&s);
        }
    });
    if js_sys::Reflect::set(
        &window,
        &JsValue::from_str("__ipePortSend"),
        seam.as_ref().unchecked_ref(),
    )
    .is_err()
    {
        // A frozen `window` (rare, e.g. a hardened embed) leaves the seam
        // uninstalled; inbound port frames are then dropped rather than trapping.
        console_warn(
            "Ipe.Ffi.Js port inbound seam could not be installed (window.__ipePortSend unset)",
        );
        return;
    }
    // The seam lives for the whole tab lifetime.
    seam.forget();
    PORT_SEAM_INSTALLED.with(|c| c.set(true));
}

/// The retained application state driving one mounted TEA app.
/// A routed app's URL entry: path + current model → the entered model and entry Cmd, or `None` when unrouted.
type WasmRouter<Model, Msg> =
    dyn Fn(&str, Model) -> Option<crate::web::route::Entered<Model, IpeCmd<Msg>>>;

struct App<Model, Msg> {
    model: RefCell<Model>,
    tree: RefCell<Html<Msg>>,
    index: RefCell<HandlerIndex<Msg>>,
    queue: RefCell<VecDeque<Msg>>,
    frame_scheduled: Cell<bool>,
    update: Box<dyn Fn(Msg, Model) -> (Model, IpeCmd<Msg>)>,
    view: Box<dyn Fn(Model) -> Html<Msg>>,
    subscriptions: Box<dyn Fn(Model) -> IpeSub<Msg>>,
    submgr: RefCell<subs::SubManager<Msg>>,
    /// This mount instance's `Cmd.publish`/`Sub.subscribeTopic` origin token.
    origin: String,
    /// Client-side router: enters a URL path, yielding the new model and the
    /// page's entry Cmd (present only for routed apps). Called on `popstate`
    /// and in-app navigation. Returns `None` when no route builds a page that
    /// renders back (`web::route::resolve` misses) — the current model and DOM
    /// are left unchanged and no Cmd runs, matching the server's unrouted-GET
    /// guard (prevents handler-index orphaning on noise paths like
    /// `/favicon.ico`).
    router: Option<Box<WasmRouter<Model, Msg>>>,
    /// Development-only time-travelling debugger recorder. Passive: records
    /// each live-pass `update` step without re-firing any `Cmd`. Present only
    /// when the `debugger` feature is active (`ipe dev build/run --debugger`).
    #[cfg(feature = "debugger")]
    recorder: RefCell<crate::debugger::RecordBuffer<Msg, Model>>,
    /// Pre-rendered string labels for each recorded step, newest at the back.
    /// Populated in `flush` via `label_fn`; kept in sync with `recorder`.
    /// Stored as strings so `flush` and all generic callers need no
    /// `IpeStringify` bound — the bound is satisfied once at construction.
    #[cfg(feature = "debugger")]
    label_log: RefCell<std::collections::VecDeque<String>>,
    /// Renders a `Msg` to its display label. Stored as a boxed closure so no
    /// `IpeStringify` bound is needed anywhere `App` is referenced generically.
    #[cfg(feature = "debugger")]
    label_fn: Box<dyn Fn(&Msg) -> String>,
    /// The debugger overlay panel (message list + scrubber). Mounted once into
    /// `<body>` at startup; never part of the app view tree or ipe-id space.
    /// `None` when mounting the overlay DOM failed (warning logged; app continues).
    #[cfg(feature = "debugger")]
    overlay: Option<std::rc::Rc<debugger_overlay::OverlayState>>,
}

/// Recompute `subscriptions(model)` and hand it to the `SubManager`, wrapped
/// in [`pubsub::with_origin`] so a `Sub.subscribeTopic` materialised during
/// this call registers against the owning mount instance (mirrors native's
/// `with_session_sid` around `SubManager::update`).
fn resync_subscriptions<Model, Msg>(app: &Rc<App<Model, Msg>>)
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    let model = app.model.borrow().clone();
    let sub = pubsub::with_origin(&app.origin, || (app.subscriptions)(model));
    let app2 = Rc::clone(app);
    let emit: Rc<dyn Fn(Msg)> = Rc::new(move |msg| enqueue(&app2, msg));
    app.submgr.borrow_mut().update(sub, &emit);
}

fn mount_app<Model, Msg, FInit, FUpdate, FView, FSubs>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
) -> Result<(), String>
where
    Model: Clone + 'static,
    Msg: Clone + crate::stringify::IpeStringify + 'static,
    FInit: Fn(WebReq) -> (Model, IpeCmd<Msg>) + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + 'static,
    FView: Fn(Model) -> Html<Msg> + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + 'static,
{
    let document = document()?;
    let body: web_sys::HtmlElement = document.body().ok_or("document has no <body>")?;

    let (model, cmd0) = init(synthesize_req(&document)?);

    let mut tree = view(model.clone());
    assign_ipe_ids(&mut tree, ROOT_IPE_ID);
    // One renderer: the DOM starts as exactly the bytes `render_html`
    // produces, so every later `diff` runs against known ground truth.
    body.set_inner_html(&render_html(&tree));

    let index = build_index(&tree);
    // Under the `debugger` feature the recorder seeds from the initial model, so
    // we keep `model` alive until after the `App` is built.
    #[cfg(feature = "debugger")]
    let recorder_base = model.clone();
    #[cfg(feature = "debugger")]
    let overlay = debugger_overlay::mount_overlay();
    let app = Rc::new(App {
        model: RefCell::new(model),
        tree: RefCell::new(tree),
        index: RefCell::new(index),
        queue: RefCell::new(VecDeque::new()),
        frame_scheduled: Cell::new(false),
        update: Box::new(update),
        view: Box::new(view),
        subscriptions: Box::new(subscriptions),
        submgr: RefCell::new(subs::SubManager::new()),
        origin: next_instance_origin(),
        router: None,
        #[cfg(feature = "debugger")]
        recorder: RefCell::new(crate::debugger::RecordBuffer::new(
            recorder_base,
            crate::debugger::DEFAULT_HISTORY_CAP,
        )),
        #[cfg(feature = "debugger")]
        label_log: RefCell::new(std::collections::VecDeque::new()),
        #[cfg(feature = "debugger")]
        label_fn: Box::new(|m: &Msg| crate::stringify::IpeStringify::ipe_show(m)),
        #[cfg(feature = "debugger")]
        overlay,
    });

    #[cfg(feature = "debugger")]
    attach_overlay_listeners(&app);
    attach_delegated_listeners(&body, &app)?;
    attach_widget_up_listener(&body, &app)?;
    // The first paint went through `set_inner_html`, not the attribute-patch
    // path, so deliver each `CustomElement.node`'s decoded down-state PROPERTY once here.
    widget::sync_widget_properties(&document, &app.tree.borrow());
    // Wire the `Ipe.Ffi.Js` port inbound seam before the first `resync` spawns any
    // `Js.subscribe` drain, so no early page-JS frame is lost.
    install_port_inbound_seam();
    run_cmd(&app, cmd0);
    resync_subscriptions(&app);
    Ok(())
}

/// Adopt the existing server-rendered DOM for an isomorphic SSR + WASM page
/// (the `hydrate` path, M7 mode 2).
///
/// Unlike `mount_app`, this function does NOT overwrite `body.innerHTML`.
/// The server-rendered DOM is trusted to be byte-identical to what `view(model)`
/// produces (the hydration-determinism invariant). We:
/// 1. Compute the virtual tree from `view(model)` and assign ipe-ids.
/// 2. Build the handler index from the virtual tree.
/// 3. Attach delegated event listeners to `<body>`.
///
/// A dev-mode empty-first-diff assertion follows: diffing `tree` against
/// itself must yield zero patches (the virtual tree IS ground truth for the
/// diff engine). A non-empty diff signals a ipe-id numbering inconsistency —
/// logged as a classified warning. Production always falls back to a full
/// diff-and-replace via the normal update loop, never white-screens.
fn adopt_app<Model, Msg, FUpdate, FView, FSubs>(
    model: Model,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
) -> Result<(), String>
where
    Model: Clone + 'static,
    Msg: Clone + crate::stringify::IpeStringify + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + 'static,
    FView: Fn(Model) -> Html<Msg> + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + 'static,
{
    let document = document()?;
    let body: web_sys::HtmlElement = document.body().ok_or("document has no <body>")?;

    let mut tree = view(model.clone());
    assign_ipe_ids(&mut tree, ROOT_IPE_ID);

    // Dev-mode empty-first-diff assertion: `diff(&tree, &tree)` must be empty
    // (the virtual tree IS the diff engine's ground truth; any non-empty result
    // means the ipe-id assignment is non-deterministic — a determinism
    // violation). Log a warning and continue: production falls back to a full
    // diff-and-replace on the first real update, never white-screens.
    {
        use crate::dom::diff::diff;
        let self_patches = diff(&tree, &tree);
        if !self_patches.is_empty() {
            console_warn(&format!(
                "hydration-mismatch: self-diff produced {} patch(es) — \
                 ipe-id assignment is non-deterministic; \
                 client will patch DOM on first update",
                self_patches.len()
            ));
        }
    }

    let index = build_index(&tree);
    #[cfg(feature = "debugger")]
    let recorder_base = model.clone();
    #[cfg(feature = "debugger")]
    let overlay = debugger_overlay::mount_overlay();
    let app = Rc::new(App {
        model: RefCell::new(model),
        tree: RefCell::new(tree),
        index: RefCell::new(index),
        queue: RefCell::new(VecDeque::new()),
        frame_scheduled: Cell::new(false),
        update: Box::new(update),
        view: Box::new(view),
        subscriptions: Box::new(subscriptions),
        submgr: RefCell::new(subs::SubManager::new()),
        origin: next_instance_origin(),
        router: None,
        #[cfg(feature = "debugger")]
        recorder: RefCell::new(crate::debugger::RecordBuffer::new(
            recorder_base,
            crate::debugger::DEFAULT_HISTORY_CAP,
        )),
        #[cfg(feature = "debugger")]
        label_log: RefCell::new(std::collections::VecDeque::new()),
        #[cfg(feature = "debugger")]
        label_fn: Box::new(|m: &Msg| crate::stringify::IpeStringify::ipe_show(m)),
        #[cfg(feature = "debugger")]
        overlay,
    });

    #[cfg(feature = "debugger")]
    attach_overlay_listeners(&app);
    attach_delegated_listeners(&body, &app)?;
    attach_widget_up_listener(&body, &app)?;
    // Adopt does NOT repaint (the server DOM is trusted), so the widget's `state`
    // property has not been set. Deliver it from the client view tree once here,
    // so the author hook receives the decoded down-state on takeover.
    widget::sync_widget_properties(&document, &app.tree.borrow());
    // No cmd0: in hydrate mode there is no `init`-produced command to run.
    // The first user interaction triggers the normal update→diff→patch cycle.
    install_port_inbound_seam();
    resync_subscriptions(&app);
    Ok(())
}

/// Mount a routed `Web.tea` in the browser. Identical to `mount_app` except:
/// 1. The initial model is entered at the current URL, and the entry Cmd runs
///    after `init`'s.
/// 2. A `popstate` listener is installed so back/forward navigation enters the
///    URL (running its entry Cmd).
fn mount_app_routed<Model, Msg, Page, FInit, FUpdate, FView, FSubs, FSetPage, FRender>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
    routes: Vec<crate::web::route::Route<Page>>,
    not_found: Page,
    set_page: FSetPage,
    render: FRender,
) -> Result<(), String>
where
    Model: Clone + 'static,
    Msg: Clone + crate::stringify::IpeStringify + 'static,
    Page: Clone + 'static,
    FInit: Fn(WebReq) -> (Model, IpeCmd<Msg>) + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + 'static,
    FView: Fn(Model) -> Html<Msg> + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + 'static,
    FSetPage: Fn(Page, Model) -> (Model, IpeCmd<Msg>) + 'static,
    FRender: Fn(&Page) -> Result<crate::web::route::RoutePath, crate::web::route::RenderRefusal>
        + 'static,
{
    use crate::web::route::{DecodedPath, Matched, enter, refuse_route_table, resolve};

    // A malformed literal in the route table fails the mount loudly, with the
    // same refusal the server's `web_app_routed` starts with.
    refuse_route_table(&routes)?;

    let document = document()?;
    let body: web_sys::HtmlElement = document.body().ok_or("document has no <body>")?;

    let req = synthesize_req(&document)?;
    let initial_path = req.path.clone();

    // Seed the model from `init`, then enter the current URL so the `page`
    // field reflects the browser's address bar before the first render. This
    // mirrors the server's miss: `init`'s Cmd, then the entry Cmd. A malformed
    // address-bar path names no route: it enters `not_found`.
    let (init_model, init_cmd) = init(req);
    let (model, entry_cmd) = match DecodedPath::parse(&initial_path) {
        Ok(path) => {
            let entered = enter(
                resolve(&routes, &path, &render),
                &not_found,
                init_model,
                &set_page,
            );
            (entered.model, entered.cmd)
        }
        Err(_) => set_page(not_found.clone(), init_model),
    };
    let cmd0 = IpeCmd::Batch(vec![init_cmd, entry_cmd]);

    let mut tree = view(model.clone());
    assign_ipe_ids(&mut tree, ROOT_IPE_ID);
    body.set_inner_html(&render_html(&tree));

    let index = build_index(&tree);

    // Shared router closure: enters a URL path → new model + entry Cmd, or
    // `None` when the path does not match any declared route.
    //
    // The resolved-hit guard before `enter` is the browser-client
    // analogue of the server's routed-app noise-path guard: a popstate to an
    // unrouted path (e.g.
    // `/favicon.ico`) must not re-route the model to `not_found` and rebuild
    // the handler index — that would orphan every handler on the page the
    // browser is actually showing, silently breaking all subsequent events.
    let routes_rc = Rc::new(routes);
    let not_found_rc = Rc::new(not_found);
    let set_page_rc = Rc::new(set_page);
    let render_rc = Rc::new(render);
    let router: Box<WasmRouter<Model, Msg>> = {
        let routes = Rc::clone(&routes_rc);
        let not_found = Rc::clone(&not_found_rc);
        let set_page = Rc::clone(&set_page_rc);
        let render = Rc::clone(&render_rc);
        Box::new(move |raw: &str, m: Model| {
            // Parsed once; a malformed path is refused like an unrouted one.
            let path = DecodedPath::parse(raw).ok()?;
            let matched = resolve(&routes, &path, &*render);
            // An empty table serves only `/`, as on the server.
            let routed =
                matches!(matched, Matched::Hit { .. }) || (routes.is_empty() && path.is_root());
            routed.then(|| enter(matched, &not_found, m, &*set_page))
        })
    };

    #[cfg(feature = "debugger")]
    let recorder_base = model.clone();
    #[cfg(feature = "debugger")]
    let overlay = debugger_overlay::mount_overlay();
    let app = Rc::new(App {
        model: RefCell::new(model),
        tree: RefCell::new(tree),
        index: RefCell::new(index),
        queue: RefCell::new(VecDeque::new()),
        frame_scheduled: Cell::new(false),
        update: Box::new(update),
        view: Box::new(view),
        subscriptions: Box::new(subscriptions),
        submgr: RefCell::new(subs::SubManager::new()),
        origin: next_instance_origin(),
        router: Some(router),
        #[cfg(feature = "debugger")]
        recorder: RefCell::new(crate::debugger::RecordBuffer::new(
            recorder_base,
            crate::debugger::DEFAULT_HISTORY_CAP,
        )),
        #[cfg(feature = "debugger")]
        label_log: RefCell::new(std::collections::VecDeque::new()),
        #[cfg(feature = "debugger")]
        label_fn: Box::new(|m: &Msg| crate::stringify::IpeStringify::ipe_show(m)),
        #[cfg(feature = "debugger")]
        overlay,
    });

    #[cfg(feature = "debugger")]
    attach_overlay_listeners(&app);
    attach_delegated_listeners(&body, &app)?;
    attach_widget_up_listener(&body, &app)?;
    attach_popstate_listener(&app)?;
    // First paint went through `set_inner_html`; deliver each widget's decoded
    // down-state PROPERTY once here (later changes ride the diff/patch route).
    widget::sync_widget_properties(&document, &app.tree.borrow());
    install_port_inbound_seam();
    run_cmd(&app, cmd0);
    resync_subscriptions(&app);
    Ok(())
}

/// Install a `popstate` listener on `window` so back/forward navigation
/// enters the new URL (running its entry Cmd).
fn attach_popstate_listener<Model, Msg>(app: &Rc<App<Model, Msg>>) -> Result<(), String>
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    let window = web_sys::window().ok_or("no window")?;
    let app = Rc::clone(app);
    let closure =
        Closure::<dyn Fn(web_sys::PopStateEvent)>::new(move |_ev: web_sys::PopStateEvent| {
            let path = web_sys::window()
                .and_then(|w| w.location().pathname().ok())
                .unwrap_or_else(|| "/".to_owned());
            navigate_to(&app, &path);
        });
    window
        .add_event_listener_with_callback("popstate", closure.as_ref().unchecked_ref())
        .map_err(|e| format!("addEventListener(popstate) failed: {e:?}"))?;
    // The listener lives for the whole app lifetime.
    closure.forget();
    Ok(())
}

/// Apply a client-side navigation: enter `path` via the app's router closure,
/// commit the model, run a view→diff→patch cycle, then run the entry Cmd —
/// matching the server's entry.
///
/// Returns early (no DOM mutation, no Cmd) when the router returns `None`, which means
/// the path does not match any declared route — unrouted popstate events (e.g.
/// a browser extension pushing `/favicon.ico`) must not rebuild the handler
/// index from the `notFound` view and orphan the live page's handlers.
fn navigate_to<Model, Msg>(app: &Rc<App<Model, Msg>>, path: &str)
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    let Some(router) = app.router.as_ref() else {
        return;
    };
    let current = app.model.borrow().clone();
    let Some(crate::web::route::Entered {
        model: new_model,
        cmd,
    }) = (router)(path, current)
    else {
        return;
    };
    *app.model.borrow_mut() = new_model.clone();

    let mut new_tree = (app.view)(new_model);
    assign_ipe_ids(&mut new_tree, ROOT_IPE_ID);
    let patches = diff(&app.tree.borrow(), &new_tree);
    apply_patches(&patches);
    *app.index.borrow_mut() = build_index(&new_tree);
    *app.tree.borrow_mut() = new_tree;
    // A widget that first appears via an `html`-subtree replace bypasses the
    // attribute-patch property route; re-deliver each widget's decoded down-state
    // PROPERTY (idempotent, bounded by the widget count).
    if let Ok(document) = document() {
        widget::sync_widget_properties(&document, &app.tree.borrow());
    }

    run_cmd(app, cmd);
    resync_subscriptions(app);
}

fn document() -> Result<web_sys::Document, String> {
    web_sys::window()
        .and_then(|w| w.document())
        .ok_or_else(|| "no window/document (not a browser context?)".to_owned())
}

/// Rebuild the row-poly `req` record from the browser environment.
fn synthesize_req(document: &web_sys::Document) -> Result<WebReq, String> {
    let window = web_sys::window().ok_or("no window")?;
    let loc = window.location();
    let path = loc.pathname().unwrap_or_default();
    let query = loc.search().unwrap_or_default();
    let raw_query = query.strip_prefix('?').unwrap_or(&query).to_owned();

    let mut cookies: crate::dict::IpeDict<String> = crate::dict::IpeDict::new();
    // `cookie()` lives on `HtmlDocument`; checked cast (an XML document has none).
    if let Some(html_doc) = document.dyn_ref::<web_sys::HtmlDocument>()
        && let Ok(cookie_str) = html_doc.cookie()
    {
        // The server's `Cookie` grammar: decoded, canonical names only, first value wins.
        for (k, v) in crate::http_header::cookie::request_cookies(&cookie_str) {
            cookies.entry(k).or_insert(v);
        }
    }

    Ok(WebReq {
        path,
        query: raw_query,
        method: "GET".to_owned(),
        params: crate::dict::IpeDict::new(),
        headers: crate::dict::IpeDict::new(),
        cookies,
    })
}

/// The delegated event names — one listener per name on `<body>`, so nodes
/// inserted by later patches need no re-wiring and no per-node `Closure`
/// lifecycle exists to leak.
const DELEGATED_EVENTS: &[&str] = &[
    "click",
    "input",
    "change",
    "submit",
    "keydown",
    "keyup",
    "mouseover",
    "mouseout",
];

fn attach_delegated_listeners<Model, Msg>(
    body: &web_sys::HtmlElement,
    app: &Rc<App<Model, Msg>>,
) -> Result<(), String>
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    for name in DELEGATED_EVENTS {
        let app = Rc::clone(app);
        let event_name: &'static str = name;
        let closure = Closure::<dyn Fn(web_sys::Event)>::new(move |ev: web_sys::Event| {
            on_dom_event(&app, event_name, &ev);
        });
        body.add_event_listener_with_callback(name, closure.as_ref().unchecked_ref())
            .map_err(|e| format!("addEventListener({name}) failed: {e:?}"))?;
        // Delegated root listeners live for the whole app lifetime.
        closure.forget();
    }
    Ok(())
}

/// Attach the single delegated `CustomElement.node` up-event listener on `<body>`.
///
/// The wasm-client widget glue dispatches a bubbling `CustomEvent` named
/// [`widget::up_event_name`] carrying the encoded `up` value in `detail`. This
/// one body-level listener receives it, climbs to the nearest `ipe-id`-bearing
/// ancestor, and runs that node's generated `OnWidget` handler — the SAME total,
/// fail-closed seal up-decoder the server path invokes — folding the decoded msg
/// into the in-process TEA loop. A malformed/oversized `detail`, or one that does
/// not decode to the declared `up` type, is dropped whole (`None`): no partial
/// value, no panic, no network hop.
fn attach_widget_up_listener<Model, Msg>(
    body: &web_sys::HtmlElement,
    app: &Rc<App<Model, Msg>>,
) -> Result<(), String>
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    let app = Rc::clone(app);
    let closure = Closure::<dyn Fn(web_sys::Event)>::new(move |ev: web_sys::Event| {
        on_widget_up_event(&app, &ev);
    });
    let name = widget::up_event_name();
    body.add_event_listener_with_callback(name, closure.as_ref().unchecked_ref())
        .map_err(|e| format!("addEventListener({name}) failed: {e:?}"))?;
    // The delegated widget-up listener lives for the whole app lifetime.
    closure.forget();
    Ok(())
}

/// Decode + dispatch one widget up-`CustomEvent`. The encoded `up` rides the
/// event `detail` (a string); a non-string / absent detail drops before any
/// decoder runs. Climb from the target to the nearest `ipe-id` ancestor whose
/// `OnWidget` handler resolves the payload — the fail-closed seal decode returns
/// `None` on any mismatch, so nothing partial is ever enqueued.
fn on_widget_up_event<Model, Msg>(app: &Rc<App<Model, Msg>>, ev: &web_sys::Event)
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    let Some(detail) = widget::up_event_detail(ev) else {
        // A forged/malformed CustomEvent (non-string detail, or not a
        // CustomEvent) — dropped fail-closed before the seal decoder runs.
        return;
    };
    let args = [detail];
    let mut cur: Option<web_sys::Element> = ev
        .target()
        .and_then(|t| t.dyn_into::<web_sys::Element>().ok());
    while let Some(el) = cur {
        if let Some(ipe_id) = el.get_attribute("ipe-id") {
            // The generated `OnWidget` closure runs the total, fail-closed seal
            // up-decoder over `detail`; a mismatch yields `None` (clean drop).
            if let Some(msg) = app
                .index
                .borrow()
                .resolve(&ipe_id, widget::UP_WIRE_NAME, &args)
            {
                enqueue(app, msg);
                return;
            }
        }
        cur = el.parent_element();
    }
}

/// Decode + dispatch one delegated DOM event: climb from the target to the
/// nearest ancestor whose ipe-id has a handler for this event name.
fn on_dom_event<Model, Msg>(app: &Rc<App<Model, Msg>>, name: &'static str, ev: &web_sys::Event)
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    let target: Option<web_sys::Element> = ev
        .target()
        .and_then(|t| t.dyn_into::<web_sys::Element>().ok());
    let args = decode_event_args(name, ev, target.as_ref());

    let mut cur = target;
    while let Some(el) = cur {
        if let Some(ipe_id) = el.get_attribute("ipe-id") {
            let resolved = if name == "submit" {
                ev.prevent_default();
                let fd = collect_form_data(&el);
                app.index.borrow().resolve_form(&ipe_id, name, fd)
            } else {
                app.index.borrow().resolve(&ipe_id, name, &args)
            };
            if let Some(msg) = resolved {
                enqueue(app, msg);
                return;
            }
        }
        cur = el.parent_element();
    }
}

/// Wire-event args per shape (mirrors the SSE wire): checkbox/radio →
/// checked Bool, other input-likes → value String, key events → key.
fn decode_event_args(
    name: &str,
    ev: &web_sys::Event,
    target: Option<&web_sys::Element>,
) -> Vec<String> {
    match name {
        "input" | "change" => target.map_or_else(Vec::new, |el| {
            if let Some(input) = el.dyn_ref::<web_sys::HtmlInputElement>() {
                let ty = input.type_();
                if ty == "checkbox" || ty == "radio" {
                    vec![input.checked().to_string()]
                } else {
                    vec![input.value()]
                }
            } else if let Some(ta) = el.dyn_ref::<web_sys::HtmlTextAreaElement>() {
                vec![ta.value()]
            } else if let Some(sel) = el.dyn_ref::<web_sys::HtmlSelectElement>() {
                vec![sel.value()]
            } else {
                Vec::new()
            }
        }),
        "keydown" | "keyup" => ev
            .dyn_ref::<web_sys::KeyboardEvent>()
            .map_or_else(Vec::new, |k| vec![k.key()]),
        _ => Vec::new(),
    }
}

/// Collect `{name: value}` form data from a `<form>` element (the shape
/// `dom::form::decode_form` narrows into the typed record).
fn collect_form_data(el: &web_sys::Element) -> FormData {
    let mut out = FormData::new();
    let Some(form) = el.dyn_ref::<web_sys::HtmlFormElement>() else {
        return out;
    };
    let Ok(fd) = web_sys::FormData::new_with_form(form) else {
        return out;
    };
    let entries = fd.entries();
    loop {
        let Ok(next) = entries.next() else { break };
        if next.done() {
            break;
        }
        let Ok(pair) = next.value().dyn_into::<js_sys::Array>() else {
            continue;
        };
        let key = pair.get(0).as_string().unwrap_or_default();
        let val = pair.get(1).as_string().unwrap_or_default();
        // First-value-wins on duplicate names (matches the server decode).
        out.entry(key).or_insert(val);
    }
    out
}

/// Queue a message and coalesce processing into one rAF tick — one
/// update+view+diff+patch per animation frame (the browser analogue of the
/// SSE wire's seq-ordered batching).
fn enqueue<Model, Msg>(app: &Rc<App<Model, Msg>>, msg: Msg)
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    app.queue.borrow_mut().push_back(msg);
    if app.frame_scheduled.get() {
        return;
    }
    app.frame_scheduled.set(true);
    let app2 = Rc::clone(app);
    let cb = Closure::once_into_js(move || {
        app2.frame_scheduled.set(false);
        flush(&app2);
    });
    let scheduled = web_sys::window()
        .map(|w| w.request_animation_frame(cb.unchecked_ref()).is_ok())
        .unwrap_or(false);
    if !scheduled {
        // No rAF (e.g. hidden document edge) — run on the microtask queue.
        let app3 = Rc::clone(app);
        wasm_bindgen_futures::spawn_local(async move {
            app3.frame_scheduled.set(false);
            flush(&app3);
        });
    }
}

/// Drain the queue: fold every pending Msg through `update`, then run ONE
/// view+diff+patch cycle and rebuild the handler index.
fn flush<Model, Msg>(app: &Rc<App<Model, Msg>>)
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    let msgs: Vec<Msg> = app.queue.borrow_mut().drain(..).collect();
    if msgs.is_empty() {
        return;
    }
    let mut model = app.model.borrow().clone();
    let mut cmds: Vec<IpeCmd<Msg>> = Vec::new();
    for msg in msgs {
        // Clone the msg before calling update so the recorder can store it;
        // the clone is compiled out entirely when `debugger` is not active.
        #[cfg(feature = "debugger")]
        let msg_for_recorder = msg.clone();
        let (next, cmd) = (app.update)(msg, model);
        // Passive recording: store the message and the resulting model after the
        // live pass. Effects fire normally above; recording does not re-fire them.
        // The pre-rendered label is pushed alongside to avoid requiring
        // `IpeStringify` on every generic caller — the bound is satisfied once
        // at construction via `label_fn`.
        #[cfg(feature = "debugger")]
        {
            let label = (app.label_fn)(&msg_for_recorder);
            app.recorder
                .borrow_mut()
                .record(msg_for_recorder, next.clone(), &|m, mdl| {
                    (app.update)(m, mdl)
                });
            // Keep `label_log` in sync with the recorder ring buffer.
            // On overflow the recorder drops its oldest step; mirror that here.
            let cap = app.recorder.borrow().cap();
            let mut log = app.label_log.borrow_mut();
            if log.len() >= cap {
                log.pop_front();
            }
            log.push_back(label);
        }
        model = next;
        cmds.push(cmd);
    }
    *app.model.borrow_mut() = model.clone();

    // When the user has scrubbed to a past step, the app view is frozen at that
    // reconstructed model. Live messages keep recording above (history is never
    // corrupted), but the DOM is NOT updated to the new live model — the user's
    // chosen past step stays visible until they return the scrubber to the end.
    // Effects still fire (they were produced by the live update pass above).
    #[cfg(feature = "debugger")]
    let scrub_active = app
        .overlay
        .as_ref()
        .and_then(|ov| ov.scrub_step())
        .is_some();
    #[cfg(not(feature = "debugger"))]
    let scrub_active = false;

    if !scrub_active {
        let mut new_tree = (app.view)(model);
        assign_ipe_ids(&mut new_tree, ROOT_IPE_ID);
        let patches = diff(&app.tree.borrow(), &new_tree);
        apply_patches(&patches);
        *app.index.borrow_mut() = build_index(&new_tree);
        *app.tree.borrow_mut() = new_tree;
        // A widget that first appears via an `html`-subtree replace bypasses the
        // attribute-patch property route; re-deliver each widget's decoded down-state
        // PROPERTY (idempotent, bounded by the widget count).
        if let Ok(document) = document() {
            widget::sync_widget_properties(&document, &app.tree.borrow());
        }
    }

    for cmd in cmds {
        run_cmd(app, cmd);
    }
    // Re-evaluate subscriptions against the new model, exactly like native's
    // `SubRuntime::reconcile` after every `update` — keeps each still-requested
    // `Sub.every` timer, stops dropped ones, and tears down and respawns the
    // `Sub.subscribeTopic` registrations from the fresh `Sub` tree.
    resync_subscriptions(app);

    // Refresh the overlay panel with the newly recorded step.
    #[cfg(feature = "debugger")]
    refresh_overlay(app);
}

/// Fire a Cmd: None/Batch recurse; Perform runs on the microtask queue and
/// feeds its Msg back through the scheduler; Publish broadcasts through the
/// in-tab `wasm::pubsub` broker, scoped to this mount instance's origin.
fn run_cmd<Model, Msg>(app: &Rc<App<Model, Msg>>, cmd: IpeCmd<Msg>)
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    match cmd {
        IpeCmd::None => {}
        IpeCmd::Batch(items) => {
            for c in items {
                run_cmd(app, c);
            }
        }
        IpeCmd::Perform(thunk) => {
            let app = Rc::clone(app);
            wasm_bindgen_futures::spawn_local(async move {
                let msg = thunk().await;
                enqueue(&app, msg);
            });
        }
        IpeCmd::Publish(thunk) => {
            // The thunk closes over the payload + topic (`wasm::pubsub::cmd_publish`/
            // `cmd_publish_no_echo`); this mount instance's origin scopes
            // echo-suppression to ITS OWN `Sub.subscribeTopic` listeners.
            thunk(&app.origin);
        }
    }
}

/// Wire the debugger overlay scrubber and message-list click listeners.
///
/// When the scrubber moves to a past step, `flush_overlay_scrub` re-renders the
/// app at the reconstructed model WITHOUT running any `Cmd`. When it moves back
/// to the end, live mode resumes and the current live model is re-rendered.
#[cfg(feature = "debugger")]
fn attach_overlay_listeners<Model, Msg>(app: &Rc<App<Model, Msg>>)
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    let Some(ref overlay) = app.overlay else {
        return;
    };
    let overlay_rc = std::rc::Rc::clone(overlay);
    let app2 = Rc::clone(app);
    debugger_overlay::attach_overlay_listeners(&overlay_rc, move |step| {
        flush_overlay_scrub(&app2, step);
    });
}

/// Re-render the app at step `n` (scrubbed) or at the live model (`None`).
///
/// Reconstruction is a pure re-fold — no `Cmd` is run. The diff→patch cycle
/// updates only the app's own DOM nodes (the overlay panel is not part of the
/// app view tree). This function does NOT enqueue any message.
#[cfg(feature = "debugger")]
fn flush_overlay_scrub<Model, Msg>(app: &Rc<App<Model, Msg>>, step: Option<usize>)
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    use crate::dom::{build_index, diff::diff};
    use crate::html::assign_ipe_ids;

    let render_model = match step {
        None => {
            // Resuming live: re-render the current live model.
            app.model.borrow().clone()
        }
        Some(n) => {
            // Reconstruct without re-firing effects.
            let reconstructed = app
                .recorder
                .borrow()
                .reconstruct(n, &|m, mdl| (app.update)(m, mdl));
            match reconstructed {
                Some(m) => m,
                None => {
                    // Step out of range (ring buffer may have advanced); resume live.
                    if let Some(ref ov) = app.overlay {
                        ov.scrub_step.set(None);
                    }
                    app.model.borrow().clone()
                }
            }
        }
    };

    let mut new_tree = (app.view)(render_model);
    assign_ipe_ids(&mut new_tree, ROOT_IPE_ID);
    let patches = diff(&app.tree.borrow(), &new_tree);
    apply_patches(&patches);
    *app.index.borrow_mut() = build_index(&new_tree);
    *app.tree.borrow_mut() = new_tree;
    if let Ok(document) = document() {
        widget::sync_widget_properties(&document, &app.tree.borrow());
    }

    // Refresh the overlay panel to highlight the newly selected step.
    refresh_overlay(app);
}

/// Refresh the overlay panel (message list + scrubber) from the current
/// recorder snapshot. Uses pre-rendered `label_log` strings, so no
/// `IpeStringify` bound is needed here.
#[cfg(feature = "debugger")]
fn refresh_overlay<Model, Msg>(app: &Rc<App<Model, Msg>>)
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    let Some(ref overlay) = app.overlay else {
        return;
    };
    let len = app.recorder.borrow().len();
    let selected = overlay.scrub_step();
    let labels: Vec<String> = app.label_log.borrow().iter().cloned().collect();
    debugger_overlay::render_overlay(overlay, labels.into_iter(), len, selected);
}

/// Apply the same `Vec<Patch>` the SSE wire serialises, via typed web-sys
/// calls. Target lookup is by the `ipe-id` attribute, exactly as `client.js`.
fn apply_patches(patches: &[Patch]) {
    let Ok(document) = document() else {
        console_fatal("PatchTargetLost", "document vanished during patch apply");
        return;
    };
    for p in patches {
        let selector = format!("[ipe-id=\"{}\"]", p.id.replace('"', "\\\""));
        let Ok(Some(el)) = document.query_selector(&selector) else {
            // A stale id can appear when a parent html-replace in this same
            // batch already rewrote the subtree — benign, matching client.js.
            continue;
        };
        if p.remove {
            el.remove();
            continue;
        }
        if let Some(text) = &p.text {
            el.set_text_content(Some(text));
        }
        if let Some(html) = &p.html {
            // Sanitiser-gated: `Patch.html` is produced exclusively by
            // `render_html` over the new subtree.
            el.set_inner_html(html);
        }
        for (k, v) in &p.attrs {
            // `CustomElement.node` down-state: on a compiler-generated `ipe-ce-*` node the
            // `state` value crosses as a DECODED PROPERTY (the wasm-client
            // adapter), never the escaped attribute the server path writes. The
            // glue's `set state(v)` setter forwards the decoded object to the
            // author hook — data handed to a setter, never spliced into markup.
            if k == "state" && widget::is_widget_tag(&el.tag_name().to_lowercase()) {
                widget::set_widget_down_property(&el, v);
                continue;
            }
            if v.is_empty() {
                let _ = el.remove_attribute(k);
            } else {
                let _ = el.set_attribute(k, v);
                sync_dom_property(&el, k, v);
            }
        }
    }
}

/// Attributes whose DOM *property* does not reflect from the attribute —
/// mirror `client.js`'s value/checked/selected/disabled sync.
fn sync_dom_property(el: &web_sys::Element, key: &str, val: &str) {
    let truthy = !val.is_empty() && val != "false";
    match key {
        "value" => {
            if let Some(input) = el.dyn_ref::<web_sys::HtmlInputElement>() {
                input.set_value(val);
            } else if let Some(ta) = el.dyn_ref::<web_sys::HtmlTextAreaElement>() {
                ta.set_value(val);
            } else if let Some(sel) = el.dyn_ref::<web_sys::HtmlSelectElement>() {
                sel.set_value(val);
            }
        }
        "checked" => {
            if let Some(input) = el.dyn_ref::<web_sys::HtmlInputElement>() {
                input.set_checked(truthy);
            }
        }
        "disabled" => {
            if let Some(input) = el.dyn_ref::<web_sys::HtmlInputElement>() {
                input.set_disabled(truthy);
            }
        }
        _ => {}
    }
}
