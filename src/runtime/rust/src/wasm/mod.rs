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

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

use crate::core::{IpeResult, IpeTask};
use crate::dom::{
    HandlerIndex, WebReq, build_index,
    diff::{AUTOFOCUS_SPENT_GLOBAL, Patch, StampedId, diff, focus_target},
    focus::{
        FocusLink, Now, Recorded, WINDOW_FOCUS_MOVES, chain_from_ancestry, landing, settle_due,
    },
};
use crate::html::{
    FormData, Html, IFRAME_TAG, RenderCtx, SANDBOX_ATTR, STAMPED_ID_ATTR, SandboxTokens,
    assign_ipe_ids, frame_loader_key, render_html,
};
use crate::tea::{IpeCmd, IpeSub};
use crate::web::route::MountRefusal;

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
///
/// The line is built by [`crate::web::route::console_line`], which scrubs it.
fn console_fatal(class: &str, detail: &str) {
    let line = crate::web::route::console_line(Some(class), detail);
    web_sys::console::error_1(&JsValue::from_str(&line));
}

/// [`console_fatal`] for a mount refusal, whose `Display` is already scrubbed:
/// the line is built by [`crate::web::route::console_refusal_line`], which
/// scrubs only the class.
fn console_fatal_refusal(class: &str, refusal: &MountRefusal) {
    let line = crate::web::route::console_refusal_line(class, refusal);
    web_sys::console::error_1(&JsValue::from_str(&line));
}

/// The warning-level sibling of [`console_fatal_refusal`], for a refusal the
/// app survives.
#[cfg(feature = "debugger")]
fn console_warn_refusal(class: &str, refusal: &MountRefusal) {
    let line = crate::web::route::console_refusal_line(class, refusal);
    web_sys::console::warn_1(&JsValue::from_str(&line));
}

/// Shared non-fatal diagnostic sink — reused by `ws_client.rs`'s
/// `web_socket_connect_with` (browser platform limitations that degrade
/// rather than fail, e.g. unsettable custom headers), and by the emitted
/// `hydrate` wasm export for fault-tolerant SSR takeover.
///
/// The line is built by [`crate::web::route::console_line`], which scrubs it.
pub fn console_warn(detail: &str) {
    let line = crate::web::route::console_line(None, detail);
    web_sys::console::warn_1(&JsValue::from_str(&line));
}

/// Install `console_error_panic_hook` so a residual trap (e.g. stack
/// exhaustion from a non-TCO fold — the documented reachable residual)
/// dies with a classified `console.error`, never a silent white screen.
pub fn install_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Drive the program's entry task on the browser microtask queue.
/// The `Err` arm logs a classified diagnostic (there is no process to exit).
pub fn run_start<E: std::fmt::Display + 'static>(task: IpeTask<E, ()>) {
    wasm_bindgen_futures::spawn_local(async move {
        if let IpeResult::Err(e) = task.await {
            console_fatal("EntryFailed", &e.to_string());
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
    E: crate::FromIpeError + 'static,
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
                console_fatal_refusal("MountFailed", &e);
                IpeResult::Err(E::from_ipe_error(e.into()))
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
/// The **adopt path** — unlike `mount_app`, does NOT repaint the body.
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
    E: crate::FromIpeError + 'static,
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
                console_fatal_refusal("AdoptFailed", &e);
                IpeResult::Err(E::from_ipe_error(e.into()))
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
///
/// Divergence: a routed wasm app is served at the root only. Until the base
/// path reaches the wasm client, a path below a base is matched with the base
/// still on it: it enters `notFound`, or the page a pattern with a leading
/// `:param` segment builds from the base segment (`/:slug` at `/app` enters
/// `slug = "app"`).
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
    E: crate::FromIpeError + 'static,
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
                console_fatal_refusal("MountFailed", &e);
                IpeResult::Err(E::from_ipe_error(e.into()))
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
/// A routed app's URL entry: located path + current model → the entered model and entry Cmd, or `None` when unrouted.
type WasmRouter<Model, Msg> = dyn Fn(
    &crate::web::route::LocatedPath,
    Model,
) -> Option<crate::web::route::Entered<Model, IpeCmd<Msg>>>;

/// Where a queued Msg came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    /// A trusted DOM event of a deliberate input kind (see
    /// [`DELEGATED_EVENTS`]) raised while the runtime was not moving focus.
    User,
    /// An event that proves no act of the user's: a widget's up event (its
    /// script raises it), an untrusted event, an incidental kind a render can
    /// raise (a pointer crossing), one raised while the runtime moves focus,
    /// an edit or key an input method is still composing, or any wire outside
    /// [`DELEGATED_EVENTS`].
    Unproven,
    /// A Cmd result or a Sub delivery.
    Effect,
}

/// Where focus stood at one moment: the count of the user's focus moves so far
/// and the element holding focus.
#[derive(Debug, PartialEq, Eq)]
struct FocusMark<F> {
    epoch: u64,
    at: Option<F>,
}

/// What caused the Msgs queued since the last render.
enum Cause<F = web_sys::Element> {
    /// No Msg is queued.
    Idle,
    /// Only the user's own events, with focus as it stood when the first was
    /// queued.
    User(FocusMark<F>),
    /// At least one Cmd result or Sub delivery.
    Effect,
}

impl<F: PartialEq> Cause<F> {
    /// The cause once a Msg from `source` joins the queue; `mark` reads focus
    /// only when this Msg is the first of the user's.
    fn with(self, source: Source, mark: impl FnOnce() -> FocusMark<F>) -> Self {
        match (self, source) {
            (Self::Idle, Source::User) => Self::User(mark()),
            (Self::User(at), Source::User) => Self::User(at),
            (Self::Idle | Self::User(_) | Self::Effect, Source::Unproven | Source::Effect)
            | (Self::Effect, Source::User) => Self::Effect,
        }
    }

    /// Whether the render of these Msgs may move focus: they are all the
    /// user's own, and focus stands at `now` where it stood when the first
    /// was queued.
    fn addressed(&self, now: &FocusMark<F>) -> bool {
        match self {
            Self::User(then) => then == now,
            Self::Idle | Self::Effect => false,
        }
    }

    /// Moves a pending user mark onto `at`, where the focus keep put focus.
    ///
    /// A restore is the runtime's own move: it never changes whether the
    /// user's queued Msgs may move focus.
    fn restamp(&mut self, at: F) {
        if let Self::User(mark) = self {
            mark.at = Some(at);
        }
    }
}

/// The cause of the Msgs queued since the last render, shared with each
/// frame's deferred focus check.
#[derive(Clone)]
pub struct QueuedCause(Rc<RefCell<Cause>>);

impl Default for QueuedCause {
    fn default() -> Self {
        Self(Rc::new(RefCell::new(Cause::Idle)))
    }
}

impl QueuedCause {
    /// Puts `cause` in place and returns the one it replaced.
    fn replace(&self, cause: Cause) -> Cause {
        self.0.replace(cause)
    }

    /// Moves a pending user mark onto `at`.
    fn restamp(&self, at: &web_sys::Element) {
        self.0.borrow_mut().restamp(at.clone());
    }
}

thread_local! {
    /// The user's focus moves in this tab: each focus change or pointer press
    /// the runtime did not cause itself, as `client.js` counts them.
    static FOCUS_EPOCH: Cell<u64> = const { Cell::new(0) };
    /// Set while the runtime itself moves focus.
    static RUNTIME_FOCUSING: Cell<bool> = const { Cell::new(false) };
    /// One-time guard for the focus-move listeners every mount shares.
    static FOCUS_EPOCH_INSTALLED: Cell<bool> = const { Cell::new(false) };
    /// The token of the newest frame committed, compared for equality only.
    static FRAME_TOKEN: Cell<u64> = const { Cell::new(0) };
}

/// The events that count a focus move. A key press is not one: it is what
/// raises the user's event.
const FOCUS_MOVE_EVENTS: &[&str] = &["focusin", "pointerdown", "mousedown", "touchstart"];

/// Counts one focus move unless the runtime is moving focus itself.
fn note_focus_move() {
    if !RUNTIME_FOCUSING.with(Cell::get) {
        FOCUS_EPOCH.with(|c| c.set(c.get().wrapping_add(1)));
    }
}

/// Counts one focus move for a window event whose target is the window itself
/// (`on_window`): focus leaving the document. An element's own event crossing
/// the window's capture phase is not one.
fn note_window_focus_move(on_window: bool) {
    if on_window {
        note_focus_move();
    }
}

/// Runs `move_focus` as the runtime's own focus move, which the epoch skips.
fn runtime_focus(move_focus: impl FnOnce()) {
    let was = RUNTIME_FOCUSING.with(|c| c.replace(true));
    move_focus();
    RUNTIME_FOCUSING.with(|c| c.set(was));
}

/// Install the capture listeners that count focus moves, once per tab.
fn install_focus_epoch(document: &web_sys::Document) -> Result<(), MountRefusal> {
    if FOCUS_EPOCH_INSTALLED.with(Cell::get) {
        return Ok(());
    }
    for name in FOCUS_MOVE_EVENTS {
        let event_name: &'static str = name;
        let closure = Closure::<dyn Fn(web_sys::Event)>::new(move |_: web_sys::Event| {
            note_focus_move();
        });
        document
            .add_event_listener_with_callback_and_bool(
                event_name,
                closure.as_ref().unchecked_ref(),
                true,
            )
            .map_err(|e| listener_refusal(event_name, &e))?;
        // The counting listeners live for the whole tab lifetime.
        closure.forget();
    }
    let window = web_sys::window().ok_or(MountRefusal::NoWindow)?;
    for event_name in WINDOW_FOCUS_MOVES {
        let closure = Closure::<dyn Fn(web_sys::Event)>::new(move |ev: web_sys::Event| {
            note_window_focus_move(
                ev.target()
                    .is_some_and(|target| target.dyn_ref::<web_sys::Window>().is_some()),
            );
        });
        window
            .add_event_listener_with_callback_and_bool(
                event_name,
                closure.as_ref().unchecked_ref(),
                true,
            )
            .map_err(|e| listener_refusal(event_name, &e))?;
        // The counting listeners live for the whole tab lifetime.
        closure.forget();
    }
    FOCUS_EPOCH_INSTALLED.with(|c| c.set(true));
    Ok(())
}

/// Where focus stands in this document now.
fn focus_mark() -> FocusMark<web_sys::Element> {
    FocusMark {
        epoch: FOCUS_EPOCH.with(Cell::get),
        at: document().ok().and_then(|d| d.active_element()),
    }
}

struct App<Model, Msg> {
    model: RefCell<Model>,
    tree: RefCell<Html<Msg>>,
    index: RefCell<HandlerIndex<Msg>>,
    queue: RefCell<VecDeque<Msg>>,
    /// What caused the Msgs in `queue`.
    cause: QueuedCause,
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
/// `with_session` around `SubManager::update`).
fn resync_subscriptions<Model, Msg>(app: &Rc<App<Model, Msg>>)
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    let model = app.model.borrow().clone();
    let sub = pubsub::with_origin(&app.origin, || (app.subscriptions)(model));
    let app2 = Rc::clone(app);
    let emit: Rc<dyn Fn(Msg)> = Rc::new(move |msg| enqueue(&app2, msg, Source::Effect));
    app.submgr.borrow_mut().update(sub, &emit);
}

fn mount_app<Model, Msg, FInit, FUpdate, FView, FSubs>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
) -> Result<(), MountRefusal>
where
    Model: Clone + 'static,
    Msg: Clone + crate::stringify::IpeStringify + 'static,
    FInit: Fn(WebReq) -> (Model, IpeCmd<Msg>) + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + 'static,
    FView: Fn(Model) -> Html<Msg> + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + 'static,
{
    let document = document()?;
    let body: web_sys::HtmlElement = document.body().ok_or(MountRefusal::NoBody)?;

    let (req, _pathname) = synthesize_req(&document)?;
    let (model, cmd0) = init(req);

    let mut tree = view(model.clone());
    assign_ipe_ids(&mut tree, ROOT_IPE_ID);
    // One renderer: the DOM starts as exactly the bytes `render_html`
    // produces, so every later `diff` runs against known ground truth.
    paint_first(&document, &body, &render_html(&tree))?;

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
        cause: QueuedCause::default(),
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
    install_focus_epoch(&document)?;
    attach_delegated_listeners(&body, &app)?;
    attach_widget_up_listener(&body, &app)?;
    // The first paint parsed markup, not the attribute-patch path, so deliver each `CustomElement.node`'s decoded down-state PROPERTY once here.
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
) -> Result<(), MountRefusal>
where
    Model: Clone + 'static,
    Msg: Clone + crate::stringify::IpeStringify + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + 'static,
    FView: Fn(Model) -> Html<Msg> + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + 'static,
{
    let document = document()?;
    let body: web_sys::HtmlElement = document.body().ok_or(MountRefusal::NoBody)?;

    let mut tree = view(model.clone());
    assign_ipe_ids(&mut tree, ROOT_IPE_ID);

    // Dev-mode empty-first-diff assertion: `diff(&tree, &tree)` must be empty
    // (the virtual tree IS the diff engine's ground truth; any non-empty result
    // means the ipe-id assignment is non-deterministic — a determinism
    // violation). Log a warning and continue: production falls back to a full
    // diff-and-replace on the first real update, never white-screens.
    {
        use crate::dom::diff::diff;
        let self_patches = diff(&tree, &tree, &RenderCtx::Unstamped);
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
        cause: QueuedCause::default(),
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
    install_focus_epoch(&document)?;
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
) -> Result<(), MountRefusal>
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
    use crate::web::route::{DecodedPath, check_route_table, enter_located, navigate};

    // A malformed literal in the route table fails the mount loudly, with the
    // same refusal the server's `web_app_routed` starts with.
    check_route_table(&routes).map_err(MountRefusal::RouteTable)?;
    // The client is served at the root: the empty base strips nothing.
    let base = DecodedPath::parse("").map_err(MountRefusal::BasePath)?;

    let document = document()?;
    let body: web_sys::HtmlElement = document.body().ok_or(MountRefusal::NoBody)?;

    let (req, pathname) = synthesize_req(&document)?;
    let initial = crate::web::route::located(pathname.as_deref(), &base);

    // Seed the model from `init`, then enter the current URL so the `page`
    // field reflects the browser's address bar before the first render. This
    // mirrors the server's miss: `init`'s Cmd, then the entry Cmd. An
    // address-bar path that does not locate below the base names no route: it
    // enters `not_found`.
    let (init_model, init_cmd) = init(req);
    let entered = enter_located(
        &routes, &initial, &not_found, init_model, &set_page, &render,
    );
    let (model, entry_cmd) = (entered.model, entered.cmd);
    let cmd0 = IpeCmd::Batch(vec![init_cmd, entry_cmd]);

    let mut tree = view(model.clone());
    assign_ipe_ids(&mut tree, ROOT_IPE_ID);
    paint_first(&document, &body, &render_html(&tree))?;

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
        Box::new(move |located: &crate::web::route::LocatedPath, m: Model| {
            navigate(&routes, located, &not_found, m, &*set_page, &*render)
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
        cause: QueuedCause::default(),
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
    install_focus_epoch(&document)?;
    attach_delegated_listeners(&body, &app)?;
    attach_widget_up_listener(&body, &app)?;
    attach_popstate_listener(&app, base)?;
    // The first paint parsed markup; deliver each widget's decoded
    // down-state PROPERTY once here (later changes ride the diff/patch route).
    widget::sync_widget_properties(&document, &app.tree.borrow());
    install_port_inbound_seam();
    run_cmd(&app, cmd0);
    resync_subscriptions(&app);
    Ok(())
}

/// Install a `popstate` listener on `window` so back/forward navigation
/// enters the new URL (running its entry Cmd).
///
/// A pathname the platform cannot report is [`PathMiss::Unreadable`]: an
/// unrouted no-op, never an entry at the root page.
///
/// [`PathMiss::Unreadable`]: crate::web::route::PathMiss::Unreadable
fn attach_popstate_listener<Model, Msg>(
    app: &Rc<App<Model, Msg>>,
    base: crate::web::route::DecodedPath,
) -> Result<(), MountRefusal>
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    let window = web_sys::window().ok_or(MountRefusal::NoWindow)?;
    let app = Rc::clone(app);
    let closure =
        Closure::<dyn Fn(web_sys::PopStateEvent)>::new(move |_ev: web_sys::PopStateEvent| {
            let raw = web_sys::window().and_then(|w| w.location().pathname().ok());
            navigate_to(&app, &crate::web::route::located(raw.as_deref(), &base));
        });
    window
        .add_event_listener_with_callback("popstate", closure.as_ref().unchecked_ref())
        .map_err(|e| listener_refusal("popstate", &e))?;
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
fn navigate_to<Model, Msg>(app: &Rc<App<Model, Msg>>, path: &crate::web::route::LocatedPath)
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
    commit_view(app, new_tree, None);

    run_cmd(app, cmd);
    resync_subscriptions(app);
}

fn document() -> Result<web_sys::Document, MountRefusal> {
    web_sys::window()
        .ok_or(MountRefusal::NoWindow)?
        .document()
        .ok_or(MountRefusal::NoDocument)
}

/// The refusal for a listener the platform would not register.
fn listener_refusal(event: &'static str, error: &JsValue) -> MountRefusal {
    MountRefusal::Listener {
        event,
        detail: crate::system::RefusedText::new(&format!("{error:?}")),
    }
}

/// Rebuild the row-poly `req` record from the browser environment, beside the
/// address bar's pathname, `None` when the platform cannot report it.
///
/// A router locates that report through [`crate::web::route::located`], so an
/// unreported pathname is `Unreadable` and never enters the root page; the
/// `req` then carries the empty path.
fn synthesize_req(document: &web_sys::Document) -> Result<(WebReq, Option<String>), MountRefusal> {
    let window = web_sys::window().ok_or(MountRefusal::NoWindow)?;
    let loc = window.location();
    let pathname = loc.pathname().ok();
    let path = pathname.clone().unwrap_or_default();
    let query = loc.search().unwrap_or_default();
    let raw_query = query.strip_prefix('?').unwrap_or(&query).to_owned();

    let mut cookies: crate::dict::IpeDict<String> = crate::dict::IpeDict::new();
    // `cookie()` lives on `HtmlDocument`; checked cast (an XML document has none).
    if let Some(html_doc) = document.dyn_ref::<web_sys::HtmlDocument>()
        && let Ok(cookie_str) = html_doc.cookie()
    {
        // The server's `Cookie` grammar: decoded, canonical names only, first value wins.
        for (k, v) in crate::http_header::cookie::request_cookies([cookie_str.as_bytes()]) {
            cookies.entry(k).or_insert(v);
        }
    }

    let req = WebReq {
        path,
        query: raw_query,
        method: "GET".to_owned(),
        params: crate::dict::IpeDict::new(),
        headers: crate::dict::IpeDict::new(),
        cookies,
    };
    Ok((req, pathname))
}

/// What a trusted delegated event says of the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Input {
    /// A deliberate act: a key, a click, an edit, a submit. Only the user
    /// raises a trusted one, outside the runtime's own focus moves.
    Deliberate,
    /// A pointer crossing: a render that shifts layout under a pointer at rest
    /// raises a trusted one with no act of the user's.
    Incidental,
}

/// The delegated event names — one listener per name on `<body>`, so nodes
/// inserted by later patches need no re-wiring and no per-node `Closure`
/// lifecycle exists to leak — each with what a trusted one says of the user.
/// The deliberate kinds are the only ones whose render may move focus.
const DELEGATED_EVENTS: &[(&str, Input)] = &[
    ("click", Input::Deliberate),
    ("input", Input::Deliberate),
    ("change", Input::Deliberate),
    ("submit", Input::Deliberate),
    ("keydown", Input::Deliberate),
    ("keyup", Input::Deliberate),
    ("mouseover", Input::Incidental),
    ("mouseout", Input::Incidental),
];

fn attach_delegated_listeners<Model, Msg>(
    body: &web_sys::HtmlElement,
    app: &Rc<App<Model, Msg>>,
) -> Result<(), MountRefusal>
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    for &(name, _) in DELEGATED_EVENTS {
        let app = Rc::clone(app);
        let event_name: &'static str = name;
        let closure = Closure::<dyn Fn(web_sys::Event)>::new(move |ev: web_sys::Event| {
            on_dom_event(&app, event_name, &ev);
        });
        body.add_event_listener_with_callback(name, closure.as_ref().unchecked_ref())
            .map_err(|e| listener_refusal(event_name, &e))?;
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
) -> Result<(), MountRefusal>
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
        .map_err(|e| listener_refusal(name, &e))?;
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
    let target = ev
        .target()
        .and_then(|t| t.dyn_into::<web_sys::Element>().ok());
    // The generated `OnWidget` closure runs the total, fail-closed seal
    // up-decoder over `detail`; a mismatch yields `None` (clean drop).
    let source = listener_source(widget::UP_WIRE_NAME, Arrival::of(ev));
    dispatch(app, target, source, |_, ipe_id| {
        app.index
            .borrow()
            .resolve(ipe_id, widget::UP_WIRE_NAME, &args)
    });
}

/// What a delegated event says of itself as it arrives, read once.
#[derive(Clone, Copy, Debug)]
struct Arrival {
    /// The browser raised it, not a page script.
    trusted: bool,
    /// An input method is still composing the edit or key it carries.
    composing: bool,
}

impl Arrival {
    fn of(ev: &web_sys::Event) -> Self {
        Self {
            trusted: ev.is_trusted(),
            composing: composing(ev),
        }
    }
}

/// Whether `ev` is an edit or a key an input method is still composing.
fn composing(ev: &web_sys::Event) -> bool {
    ev.dyn_ref::<web_sys::InputEvent>().map_or_else(
        || {
            ev.dyn_ref::<web_sys::KeyboardEvent>().is_some_and(|key| {
                key.is_composing() || key.key_code() == crate::dom::diff::COMPOSING_KEY_CODE
            })
        },
        web_sys::InputEvent::is_composing,
    )
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
    let source = listener_source(name, Arrival::of(ev));
    dispatch(app, target, source, |el, ipe_id| {
        if name == "submit" {
            ev.prevent_default();
            let fd = collect_form_data(el);
            app.index.borrow().resolve_form(ipe_id, name, fd)
        } else {
            app.index.borrow().resolve(ipe_id, name, &args)
        }
    });
}

/// The source of a Msg a listener resolved under `wire`, read as the event
/// arrives: the user's only for a trusted, uncomposed event of a deliberate
/// kind in [`DELEGATED_EVENTS`] raised while the runtime is not moving focus.
/// An event the runtime or a render can raise proves no act of the user's, so
/// its render never moves focus: a widget's up event, an untrusted event, a
/// pointer crossing, the `change` a runtime focus move commits, or any name
/// outside the table. Nor does an edit or key an input method is composing:
/// moving focus would cut the composition off.
fn listener_source(wire: &str, arrival: Arrival) -> Source {
    let deliberate = DELEGATED_EVENTS
        .iter()
        .any(|&(name, input)| name == wire && input == Input::Deliberate);
    if deliberate && arrival.trusted && !arrival.composing && !RUNTIME_FOCUSING.with(Cell::get) {
        Source::User
    } else {
        Source::Unproven
    }
}

/// Climb from `target` to the nearest `ipe-id` ancestor whose handler
/// `resolve` turns into a Msg, and queue that Msg with `source`.
fn dispatch<Model, Msg>(
    app: &Rc<App<Model, Msg>>,
    target: Option<web_sys::Element>,
    source: Source,
    resolve: impl Fn(&web_sys::Element, &str) -> Option<Msg>,
) where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    let mut cur = target;
    while let Some(el) = cur {
        if let Some(ipe_id) = el.get_attribute("ipe-id")
            && let Some(msg) = resolve(&el, &ipe_id)
        {
            enqueue(app, msg, source);
            return;
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
fn enqueue<Model, Msg>(app: &Rc<App<Model, Msg>>, msg: Msg, source: Source)
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    app.queue.borrow_mut().push_back(msg);
    let cause = app.cause.replace(Cause::Idle);
    app.cause.replace(cause.with(source, focus_mark));
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
    let cause = app.cause.replace(Cause::Idle);
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
        let target = if cause.addressed(&focus_mark()) {
            focus_target(&app.tree.borrow(), &new_tree)
        } else {
            None
        };
        commit_view(app, new_tree, target.as_ref());
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
        IpeCmd::Perform(body) => {
            let app = Rc::clone(app);
            wasm_bindgen_futures::spawn_local(async move {
                let msg = body.run().await;
                enqueue(&app, msg, Source::Effect);
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
    use crate::html::{RenderCtx, assign_ipe_ids};

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
    commit_view(app, new_tree, None);

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

/// Focus the element stamped `id`; an absent or unfocusable one is left alone.
/// The move is the runtime's own: it does not count as the user's.
fn focus_stamped(document: &web_sys::Document, id: &str) {
    if let Ok(Some(el)) = document.query_selector(&ipe_id_selector(id))
        && let Some(html) = el.dyn_ref::<web_sys::HtmlElement>()
    {
        runtime_focus(|| {
            let _ = html.focus();
        });
    }
}

/// The selector matching the element whose `ipe-id` is exactly `id`: the id is
/// a CSS string, `"` and `\` escaped, NUL replaced as CSS parses it, and every
/// other control character written as its code point.
fn ipe_id_selector(id: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(id.len().saturating_add(12));
    out.push_str("[ipe-id=\"");
    for c in id.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\0' => out.push('\u{FFFD}'),
            c if c.is_control() => {
                let _ = write!(out, "\\{:x} ", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push_str("\"]");
    out
}

/// How a patch writes one attribute.
#[derive(Debug, PartialEq, Eq)]
enum AttrWrite<'v> {
    /// Set the attribute to this value.
    Set(Cow<'v, str>),
    /// Remove the attribute.
    Remove,
    /// Write nothing.
    Keep,
    /// Set the empty `sandbox` first, then the attribute to this value: the
    /// sandbox binds when the frame navigates.
    SandboxThenSet(&'v str),
}

/// The write for attribute `key` of an element `tag` patched to `value`, where
/// `sandboxed` says whether the element holds a `sandbox` now.
///
/// `None` removes and a value sets, the empty one included. `autofocus` never
/// reaches a live node, where a later move would focus it. The frame rule of
/// `html.rs` holds on the live node: an `iframe`'s `sandbox` is never removed
/// and is set canonical, a `src` or `srcdoc` on an unsandboxed `iframe` is
/// preceded by the empty sandbox, and a frame loader never gains the
/// attribute it loads from.
fn attr_write<'v>(tag: &str, key: &str, value: Option<&'v str>, sandboxed: bool) -> AttrWrite<'v> {
    if key.eq_ignore_ascii_case("autofocus") {
        return AttrWrite::Remove;
    }
    if tag.eq_ignore_ascii_case(IFRAME_TAG) {
        if key.eq_ignore_ascii_case(SANDBOX_ATTR) {
            return value.map_or(AttrWrite::Keep, |v| {
                AttrWrite::Set(Cow::Owned(SandboxTokens::parse(v).canonical()))
            });
        }
        if let Some(v) = value
            && !sandboxed
            && (key.eq_ignore_ascii_case("src") || key.eq_ignore_ascii_case("srcdoc"))
        {
            return AttrWrite::SandboxThenSet(v);
        }
    } else if value.is_some()
        && frame_loader_key(tag).is_some_and(|loads| key.eq_ignore_ascii_case(loads))
    {
        return AttrWrite::Keep;
    }
    value.map_or(AttrWrite::Remove, |v| AttrWrite::Set(Cow::Borrowed(v)))
}

/// The frame-loading elements a detached holder is fenced on.
const FRAME_SELECTOR: &str = "iframe, embed, object, frame";

/// Fence every frame `frames` of a detached holder before its nodes connect:
/// an `iframe` gets the canonical sandbox, and an `embed`, `object` or `frame`
/// holding the attribute it loads from is removed.
fn fence_frames(frames: &web_sys::NodeList) -> Result<(), &'static str> {
    for i in 0..frames.length() {
        let Some(element) = frames
            .item(i)
            .and_then(|node| node.dyn_into::<web_sys::Element>().ok())
        else {
            continue;
        };
        let tag = element.local_name();
        if tag.eq_ignore_ascii_case(IFRAME_TAG) {
            let held = element.get_attribute(SANDBOX_ATTR).unwrap_or_default();
            element
                .set_attribute(SANDBOX_ATTR, &SandboxTokens::parse(&held).canonical())
                .map_err(|_| "frame sandbox could not be set")?;
        } else if frame_loader_key(&tag).is_some_and(|loads| element.has_attribute(loads)) {
            element.remove();
        }
    }
    Ok(())
}

/// The HTML namespace.
const HTML_NS: &str = "http://www.w3.org/1999/xhtml";

/// Markup parsed detached, every `autofocus` already removed and every frame
/// fenced.
struct Detached {
    /// The holder whose children are the parsed nodes.
    nodes: web_sys::Node,
    /// The first element that carried `autofocus`, in document order.
    autofocus: Option<web_sys::Element>,
}

/// `html` parsed detached in `el`'s own namespace and context, with every
/// `autofocus` removed before the nodes connect: the browser focuses an
/// autofocus element on insertion while focus is on the body. Every frame is
/// fenced there too (`fence_frames`), as a detached holder loads no document,
/// so no document a patch frames shares the app's origin. The holder is an
/// element of `el`'s own tag, so the parser reads the markup in the insertion
/// mode `el` sets (a `<tr>` below a `<tbody>`); a custom element's name would
/// run its constructor on the holder, so it gets a `div`, and a template's
/// markup is parsed into a template's inert content.
fn parse_detached(
    document: &web_sys::Document,
    el: &web_sys::Element,
    html: &str,
) -> Result<Detached, &'static str> {
    let local = el.local_name();
    let ns = el.namespace_uri();
    let html_ns = ns.as_deref() == Some(HTML_NS);
    let tag = if html_ns && local.contains('-') {
        "div"
    } else {
        local.as_str()
    };
    let holder = document
        .create_element_ns(ns.as_deref(), tag)
        .map_err(|_| "detached patch holder refused")?;
    holder.set_inner_html(html);
    let template = if html_ns {
        holder.dyn_ref::<web_sys::HtmlTemplateElement>()
    } else {
        None
    };
    let (nodes, found, frames): (web_sys::Node, _, _) = if let Some(template) = template {
        let content = template.content();
        let found = content.query_selector_all("[autofocus]");
        let frames = content.query_selector_all(FRAME_SELECTOR);
        (content.into(), found, frames)
    } else {
        let found = holder.query_selector_all("[autofocus]");
        let frames = holder.query_selector_all(FRAME_SELECTOR);
        (holder.into(), found, frames)
    };
    fence_frames(&frames.map_err(|_| "frame query refused")?)?;
    let found = found.map_err(|_| "autofocus query refused")?;
    let mut autofocus = None;
    for i in 0..found.length() {
        let Some(element) = found
            .item(i)
            .and_then(|node| node.dyn_into::<web_sys::Element>().ok())
        else {
            continue;
        };
        element
            .remove_attribute("autofocus")
            .map_err(|_| "autofocus could not be removed")?;
        if autofocus.is_none() {
            autofocus = Some(element);
        }
    }
    Ok(Detached { nodes, autofocus })
}

/// Move every child of `from` to the end of `to`, in order.
fn move_children(from: &web_sys::Node, to: &web_sys::Node) -> Result<(), &'static str> {
    while let Some(child) = from.first_child() {
        to.append_child(&child)
            .map_err(|_| "patched node could not be attached")?;
    }
    Ok(())
}

/// The node whose children are `el`'s markup: a template's inert content, or
/// `el` itself.
fn markup_parent(el: &web_sys::Element) -> web_sys::Node {
    match el.dyn_ref::<web_sys::HtmlTemplateElement>() {
        Some(template) if el.namespace_uri().as_deref() == Some(HTML_NS) => {
            template.content().into()
        }
        _ => el.clone().into(),
    }
}

/// Replace `el`'s children with `html`, parsed by [`parse_detached`].
pub fn replace_children_html(document: &web_sys::Document, el: &web_sys::Element, html: &str) {
    let replaced = parse_detached(document, el, html).and_then(|parsed| {
        let live = markup_parent(el);
        live.set_text_content(None);
        move_children(&parsed.nodes, &live)
    });
    if let Err(why) = replaced {
        console_fatal("PatchTargetLost", why);
    }
}

/// Paint `html` as the mount root's first content, parsed by
/// [`parse_detached`], and focus its first `autofocus` element only while the
/// load's own autofocus is still due: focus is on the body, the user has not
/// pressed a key or the pointer or moved focus since the loader ran
/// ([`load_autofocus_spent`]), and the URL fragment names no element. The
/// runtime makes the move, as `client.js` does at mount, so no render-inserted
/// `autofocus` reaches the browser's own focus-on-insertion.
///
/// # Errors
///
/// [`MountRefusal::Dom`] when the browser refuses a step of the detached parse
/// or the move into `root`.
pub fn paint_first(
    document: &web_sys::Document,
    root: &web_sys::HtmlElement,
    html: &str,
) -> Result<(), MountRefusal> {
    let refusal = |step: &'static str| MountRefusal::Dom { step, detail: None };
    let due =
        focus_on_body(document) && !load_autofocus_spent() && fragment_target(document).is_none();
    let parsed = parse_detached(document, root, html).map_err(refusal)?;
    root.set_text_content(None);
    move_children(&parsed.nodes, root).map_err(refusal)?;
    if due
        && fragment_target(document).is_none()
        && let Some(target) = parsed.autofocus
        && let Some(target) = target.dyn_ref::<web_sys::HtmlElement>()
    {
        runtime_focus(|| {
            let _ = target.focus();
        });
    }
    Ok(())
}

/// Whether the loader heard one of
/// [`AUTOFOCUS_SPENDING_EVENTS`](crate::dom::diff::AUTOFOCUS_SPENDING_EVENTS): it sets
/// [`AUTOFOCUS_SPENT_GLOBAL`]. A global that cannot be read counts as spent.
fn load_autofocus_spent() -> bool {
    match js_sys::Reflect::get(
        &js_sys::global(),
        &JsValue::from_str(AUTOFOCUS_SPENT_GLOBAL),
    ) {
        Ok(value) => value.is_truthy(),
        Err(_) => true,
    }
}

/// Whether focus is on the body, or on nothing.
fn focus_on_body(document: &web_sys::Document) -> bool {
    match (document.active_element(), document.body()) {
        (None, _) => true,
        (Some(active), Some(body)) => {
            let body: &web_sys::Element = body.as_ref();
            active == *body
        }
        (Some(_), None) => false,
    }
}

/// The element the URL fragment names, raw or percent-decoded, read from the
/// URL itself: `:target` matches only once the browser has applied it.
fn fragment_target(document: &web_sys::Document) -> Option<web_sys::Element> {
    let hash = document.location()?.hash().ok()?;
    let raw = hash.strip_prefix('#').unwrap_or(&hash);
    if raw.is_empty() {
        return None;
    }
    document.get_element_by_id(raw).or_else(|| {
        let decoded: String = js_sys::decode_uri_component(raw).ok()?.into();
        document.get_element_by_id(&decoded)
    })
}

/// Commits `new_tree` as the app's next frame, focusing `target` when the
/// frame addresses one.
///
/// The view the handlers resolve against becomes `new_tree` BEFORE the frame
/// applies: the frame's own focus moves (the focus keep, `target`) raise
/// `focus`/`focusin` synchronously, and the Msg such an event resolves to must
/// come from the view on screen, never from the one the frame replaced.
fn commit_view<Model, Msg: Clone>(
    app: &App<Model, Msg>,
    new_tree: Html<Msg>,
    target: Option<&StampedId>,
) {
    let patches = diff(&app.tree.borrow(), &new_tree, &RenderCtx::Unstamped);
    *app.index.borrow_mut() = build_index(&new_tree);
    *app.tree.borrow_mut() = new_tree;
    commit_frame(&patches, target, &app.cause);
    // A widget that first appears via an `html`-subtree replace bypasses the
    // attribute-patch property route; re-deliver each widget's decoded down-state
    // PROPERTY (idempotent, bounded by the widget count).
    if let Ok(document) = document() {
        widget::sync_widget_properties(&document, &app.tree.borrow());
    }
}

/// [`apply_frame`] on this tab's document; a vanished document applies nothing.
fn commit_frame(patches: &[Patch], target: Option<&StampedId>, queued: &QueuedCause) {
    let Ok(document) = document() else {
        console_fatal("PatchTargetLost", "document vanished during patch apply");
        return;
    };
    apply_frame(&document, patches, target, queued);
}

/// Commits one frame inside the focus keep: the one site that applies patches.
///
/// Applies `patches` (the `Vec<Patch>` the SSE wire serialises, through typed
/// web-sys calls, each target found by its `ipe-id` as in `client.js`), then
/// focuses `target`. Focus the frame left on the body is put back by the rule
/// of [`crate::dom::focus`] at once and again two animation frames later,
/// after the browser's own fixup for a node a patch made unfocusable; a
/// restore moves a pending user mark in `queued` onto the landing node.
pub fn apply_frame(
    document: &web_sys::Document,
    patches: &[Patch],
    target: Option<&StampedId>,
    queued: &QueuedCause,
) {
    fn apply(document: &web_sys::Document, patches: &[Patch]) {
        for p in patches {
            let Ok(Some(el)) = document.query_selector(&ipe_id_selector(&p.id)) else {
                // A stale id can appear when a parent html-replace in this same
                // batch already rewrote the subtree — benign, matching client.js.
                continue;
            };
            if let Some(text) = &p.text {
                el.set_text_content(Some(text));
            }
            if let Some(html) = &p.html {
                // Sanitiser-gated: `Patch.html` is produced exclusively by
                // `render_html` over the new subtree.
                replace_children_html(document, &el, html);
            }
            for (k, v) in &p.attrs {
                // `CustomElement.node` down-state: on a compiler-generated `ipe-ce-*` node the
                // `state` value crosses as a DECODED PROPERTY (the wasm-client
                // adapter), never the escaped attribute the server path writes. The
                // glue's `set state(v)` setter forwards the decoded object to the
                // author hook — data handed to a setter, never spliced into markup.
                if k == "state" && widget::is_widget_tag(&el.tag_name().to_lowercase()) {
                    widget::set_widget_down_property(&el, v.as_deref().unwrap_or_default());
                    continue;
                }
                write_patched_attr(&el, k, v.as_deref());
            }
        }
    }

    let chain = document
        .active_element()
        .and_then(|focused| view_chain(document, focused));
    let focus_epoch = FOCUS_EPOCH.with(Cell::get);
    apply(document, patches);
    if let Some(target) = target {
        focus_stamped(document, target.as_str());
    }
    let frame = FRAME_TOKEN.with(|c| {
        let next = c.get().wrapping_add(1);
        c.set(next);
        next
    });
    let Some(chain) = chain else {
        return;
    };
    let rec = Recorded { focus_epoch, frame };
    keep_focus(document, &chain, rec, queued);
    settle_later(chain, rec, queued.clone());
}

/// The view chain of `focused` below the body, the wasm mount container.
fn view_chain(document: &web_sys::Document, focused: web_sys::Element) -> Option<Vec<FocusLink>> {
    let body = document.body()?;
    let root: &web_sys::Element = body.as_ref();
    if focused == *root || !root.contains(Some(&focused)) {
        return None;
    }
    let upward = std::iter::successors(Some(focused), web_sys::Element::parent_element)
        .take_while(|el| el != root)
        .map(|el| (el.get_attribute(STAMPED_ID_ATTR), el.tag_name()));
    chain_from_ancestry(upward)
}

/// Puts focus on the landing of `chain` when [`settle_due`] holds for `rec`.
fn keep_focus(
    document: &web_sys::Document,
    chain: &[FocusLink],
    rec: Recorded,
    queued: &QueuedCause,
) {
    let now = Now {
        focus_held: !focus_on_body(document),
        focus_epoch: FOCUS_EPOCH.with(Cell::get),
        newest_frame: FRAME_TOKEN.with(Cell::get),
        runtime_focusing: RUNTIME_FOCUSING.with(Cell::get),
    };
    if !settle_due(&rec, &now) {
        return;
    }
    let Some(body) = document.body() else {
        return;
    };
    let root: &web_sys::Element = body.as_ref();
    for node in landing(root, chain) {
        let Some(html) = node.dyn_ref::<web_sys::HtmlElement>() else {
            continue;
        };
        runtime_focus(|| {
            let _ = html.focus();
        });
        if document.active_element().as_ref() == Some(&node) {
            queued.restamp(&node);
            return;
        }
    }
}

/// Runs [`keep_focus`] for `rec` two animation frames on; with no animation
/// frame the deferred check is skipped.
fn settle_later(chain: Vec<FocusLink>, rec: Recorded, queued: QueuedCause) {
    let Some(window) = web_sys::window() else {
        return;
    };
    let again = window.clone();
    let second = Closure::once_into_js(move || {
        if let Ok(document) = document() {
            keep_focus(&document, &chain, rec, &queued);
        }
    });
    let first = Closure::once_into_js(move || {
        let _ = again.request_animation_frame(second.unchecked_ref());
    });
    let _ = window.request_animation_frame(first.unchecked_ref());
}

/// Write one patched attribute onto the live `el`: `Some` sets, `None`
/// removes, both through the frame rule of `attr_write` — an iframe holds a
/// sandbox before it holds a URL, and a frame loader never gains its URL.
pub fn write_patched_attr(el: &web_sys::Element, key: &str, value: Option<&str>) {
    let sandboxed = el.has_attribute(SANDBOX_ATTR);
    match attr_write(&el.local_name(), key, value, sandboxed) {
        AttrWrite::Set(v) => {
            let _ = el.set_attribute(key, &v);
            sync_dom_property(el, key, &v);
        }
        AttrWrite::SandboxThenSet(v) => {
            if el.set_attribute(SANDBOX_ATTR, "").is_ok() {
                let _ = el.set_attribute(key, v);
            }
        }
        AttrWrite::Remove => {
            let _ = el.remove_attribute(key);
            clear_dom_property(el, key);
        }
        AttrWrite::Keep => {}
    }
}

/// Attributes whose DOM *property* does not reflect from the attribute —
/// mirror `client.js`'s value/checked/selected/disabled sync: a set property
/// follows its value unless the value spells `false`, the empty value
/// included, as the attribute `checked=""` checks.
fn sync_dom_property(el: &web_sys::Element, key: &str, val: &str) {
    let truthy = val != "false";
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

/// A removed attribute clears the property it mirrors, as `client.js`.
fn clear_dom_property(el: &web_sys::Element, key: &str) {
    if key == "checked" || key == "disabled" {
        sync_dom_property(el, key, "false");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    const TRUSTED: Arrival = Arrival {
        trusted: true,
        composing: false,
    };
    const UNTRUSTED: Arrival = Arrival {
        trusted: false,
        composing: false,
    };
    const COMPOSING: Arrival = Arrival {
        trusted: true,
        composing: true,
    };

    fn mark(epoch: u64, at: u8) -> FocusMark<u8> {
        FocusMark {
            epoch,
            at: Some(at),
        }
    }

    #[wasm_bindgen_test]
    fn a_batch_of_the_users_own_events_with_focus_unmoved_is_addressed() {
        let cause = Cause::Idle
            .with(Source::User, || mark(3, 1))
            .with(Source::User, || mark(4, 2));
        assert!(cause.addressed(&mark(3, 1)));
        assert!(!cause.addressed(&mark(4, 2)));
    }

    #[wasm_bindgen_test]
    fn a_batch_an_effect_joined_never_moves_focus() {
        let before = Cause::Idle
            .with(Source::Effect, || mark(0, 1))
            .with(Source::User, || mark(0, 1));
        assert!(!before.addressed(&mark(0, 1)));
        let after = Cause::Idle
            .with(Source::User, || mark(0, 1))
            .with(Source::Effect, || mark(0, 1))
            .with(Source::User, || mark(0, 1));
        assert!(!after.addressed(&mark(0, 1)));
        assert!(!Cause::<u8>::Idle.addressed(&mark(0, 1)));
    }

    #[wasm_bindgen_test]
    fn only_a_trusted_deliberate_input_counts_as_the_users() {
        let alone = Cause::Idle.with(Source::Unproven, || mark(0, 1));
        assert!(!alone.addressed(&mark(0, 1)));
        let joined = Cause::Idle
            .with(Source::User, || mark(0, 1))
            .with(Source::Unproven, || mark(0, 1));
        assert!(!joined.addressed(&mark(0, 1)));
        let raised = [
            widget::UP_WIRE_NAME,
            widget::up_event_name(),
            "mouseover",
            "mouseout",
            "focus",
            "blur",
            "focusin",
            "focusout",
            "dblclick",
            "",
            "CLICK",
        ];
        for name in raised {
            assert_eq!(listener_source(name, TRUSTED), Source::Unproven, "{name}");
        }
        let acts = ["click", "input", "change", "submit", "keydown", "keyup"];
        for name in acts {
            assert_eq!(listener_source(name, TRUSTED), Source::User, "{name}");
            assert_eq!(listener_source(name, UNTRUSTED), Source::Unproven, "{name}");
            assert_eq!(listener_source(name, COMPOSING), Source::Unproven, "{name}");
            runtime_focus(|| {
                assert_eq!(listener_source(name, TRUSTED), Source::Unproven, "{name}");
            });
        }
        for &(name, input) in DELEGATED_EVENTS {
            let user = input == Input::Deliberate;
            assert_eq!(
                listener_source(name, TRUSTED) == Source::User,
                user,
                "{name}"
            );
            assert_eq!(acts.contains(&name), user, "{name}");
        }
    }

    #[wasm_bindgen_test]
    fn focus_moved_between_queue_and_frame_is_not_addressed() {
        let cause = Cause::Idle.with(Source::User, || mark(5, 1));
        assert!(!cause.addressed(&mark(6, 1)));
        assert!(!cause.addressed(&mark(5, 2)));
        assert!(!cause.addressed(&FocusMark { epoch: 5, at: None }));
    }

    #[wasm_bindgen_test]
    fn the_runtimes_own_focus_move_is_not_the_users() {
        let start = FOCUS_EPOCH.with(Cell::get);
        runtime_focus(note_focus_move);
        assert_eq!(FOCUS_EPOCH.with(Cell::get), start);
        assert!(!RUNTIME_FOCUSING.with(Cell::get));
        note_focus_move();
        assert_eq!(FOCUS_EPOCH.with(Cell::get), start.wrapping_add(1));
    }

    #[wasm_bindgen_test]
    fn a_restore_restamps_the_pending_user_mark() {
        let mut cause = Cause::Idle.with(Source::User, || mark(5, 1));
        cause.restamp(2);
        assert!(cause.addressed(&mark(5, 2)));
        assert!(!cause.addressed(&mark(5, 1)));
        assert!(!cause.addressed(&mark(6, 2)));
        let mut effect: Cause<u8> = Cause::Effect;
        effect.restamp(2);
        assert!(!effect.addressed(&mark(5, 2)));
        let mut idle: Cause<u8> = Cause::Idle;
        idle.restamp(2);
        assert!(matches!(idle, Cause::Idle));
    }

    #[wasm_bindgen_test]
    fn window_blur_is_a_focus_move() {
        assert!(WINDOW_FOCUS_MOVES.contains(&"blur"));
        assert!(!FOCUS_MOVE_EVENTS.contains(&"blur"));
        let start = FOCUS_EPOCH.with(Cell::get);
        note_window_focus_move(false);
        assert_eq!(FOCUS_EPOCH.with(Cell::get), start);
        runtime_focus(|| note_window_focus_move(true));
        assert_eq!(FOCUS_EPOCH.with(Cell::get), start);
        note_window_focus_move(true);
        assert_eq!(FOCUS_EPOCH.with(Cell::get), start.wrapping_add(1));
    }

    #[wasm_bindgen_test]
    fn an_ipe_id_selector_cannot_leave_its_string() {
        assert_eq!(ipe_id_selector("r_0_1"), r#"[ipe-id="r_0_1"]"#);
        assert_eq!(
            ipe_id_selector(r#"a"],[autofocus"#),
            r#"[ipe-id="a\"],[autofocus"]"#
        );
        assert_eq!(ipe_id_selector(r#"a\"b"#), r#"[ipe-id="a\\\"b"]"#);
        assert_eq!(ipe_id_selector("a\nb\0"), "[ipe-id=\"a\\a b\u{FFFD}\"]");
    }

    /// The write of a set to `v`, borrowed.
    const fn set(v: &str) -> AttrWrite<'_> {
        AttrWrite::Set(Cow::Borrowed(v))
    }

    #[wasm_bindgen_test]
    fn a_patch_never_writes_autofocus() {
        let write = |key, value| attr_write("div", key, value, false);
        assert_eq!(write("autofocus", Some("")), AttrWrite::Remove);
        assert_eq!(write("autofocus", Some("autofocus")), AttrWrite::Remove);
        assert_eq!(write("AutoFocus", Some("true")), AttrWrite::Remove);
        assert_eq!(write("class", Some("a")), set("a"));
        assert_eq!(write("class", Some("")), set(""));
        assert_eq!(write("class", None), AttrWrite::Remove);
    }

    /// An `iframe`'s `sandbox` is never removed, and a set is canonical.
    #[wasm_bindgen_test]
    fn a_patch_never_removes_an_iframe_sandbox() {
        for (tag, key) in [("iframe", "sandbox"), ("IFRAME", "SandBox")] {
            assert_eq!(attr_write(tag, key, None, true), AttrWrite::Keep);
            assert_eq!(
                attr_write(
                    tag,
                    key,
                    Some("ALLOW-SCRIPTS allow-same-origin allow-forms"),
                    true
                ),
                set("allow-forms allow-scripts")
            );
            assert_eq!(
                attr_write(tag, key, Some("allow-popups-to-escape-sandbox"), true),
                set("")
            );
        }
        assert_eq!(attr_write("div", "sandbox", None, false), AttrWrite::Remove);
    }

    /// A frame loader never gains the attribute it loads from, in any case.
    #[wasm_bindgen_test]
    fn a_patch_never_gives_a_frame_loader_its_url() {
        for (tag, key) in [
            ("embed", "src"),
            ("EMBED", "SRC"),
            ("object", "data"),
            ("frame", "Src"),
        ] {
            for value in ["", " ", "/"] {
                assert_eq!(
                    attr_write(tag, key, Some(value), false),
                    AttrWrite::Keep,
                    "{tag} {key}"
                );
            }
            assert_eq!(attr_write(tag, key, None, false), AttrWrite::Remove);
        }
        assert_eq!(attr_write("embed", "type", Some("x"), false), set("x"));
        assert_eq!(attr_write("object", "src", Some("/"), false), set("/"));
    }

    /// A `src` patched onto an `iframe` with no sandbox writes the empty
    /// sandbox first; one already sandboxed only sets the `src`.
    #[wasm_bindgen_test]
    fn an_iframe_src_patch_sandboxes_first() {
        assert_eq!(
            attr_write("iframe", "src", Some("/"), false),
            AttrWrite::SandboxThenSet("/")
        );
        assert_eq!(
            attr_write("iframe", "SRC", Some(""), false),
            AttrWrite::SandboxThenSet("")
        );
        assert_eq!(attr_write("iframe", "src", Some("/"), true), set("/"));
        assert_eq!(attr_write("iframe", "src", None, false), AttrWrite::Remove);
        assert_eq!(attr_write("div", "src", Some("/"), false), set("/"));
    }
}
