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
use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;

use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

use crate::core::{IpeResult, IpeTask};
use crate::dom::{
    HandlerIndex, WebReq, build_index,
    diff::{AUTOFOCUS_SPENT_GLOBAL, Patch, StampedId, diff, focus_target},
    focus::{
        FOCUS_DROP_EVENT, FocusLink, Now, Recorded, WINDOW_FOCUS_MOVES, arms, carries,
        chain_from_ancestry, drop_answers, landing, settle_due,
    },
    keep::{
        AUTHORITY_ATTRS, CONTROLLED_ATTR, Control, Field, Keep, Marker, is_authority_attr, keep,
    },
};
use crate::frames::{EscapedPopups, PageAuthority};
use crate::html::frame_patch::{
    FrameFence, FrameWrite, fence_frame, frame_patch_key, plan_frame_patch,
};
use crate::html::{
    ClientMarks, FormData, Html, RenderCtx, STAMPED_ID_ATTR, assign_ipe_ids, render_html_in,
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

/// The startup judgement: `Some(true)` once every registered variable was
/// accepted and the values read once per process were fixed. Unset means the
/// entry never judged the environment, and the program does not start.
static STARTUP_ACCEPTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// What the entry's frame-origin registration came to.
///
/// `Registered` and `Refused` are reachable only through
/// [`install_panic_hook_trusting_frames`]; an entry with no list judges `NoList`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameAdmission {
    /// The program declares no frame origins.
    NoList,
    /// The declared origins re-parsed and are the program's frame policy.
    Registered,
    /// The declared origins did not re-parse; the program must not start.
    Refused,
}

/// Whether the program may start, from the environment verdict and the frame admission.
const fn startup_accepted(env_clean: bool, frames: FrameAdmission) -> bool {
    match frames {
        FrameAdmission::NoList | FrameAdmission::Registered => env_clean,
        FrameAdmission::Refused => false,
    }
}

/// The one startup judge every entry form calls, setting [`STARTUP_ACCEPTED`] once.
///
/// It judges the environment and fixes the values read once per process,
/// before the program's first line, as a native `main` does, then folds in
/// `frames`.
fn judge_startup(frames: FrameAdmission) {
    let env_clean = match crate::env_registry::startup_check() {
        Ok(()) => true,
        Err(refusals) => {
            for refusal in &refusals {
                console_fatal("StartupRefused", &refusal.to_string());
            }
            false
        }
    };
    let accepted = startup_accepted(env_clean, frames);
    let _ = STARTUP_ACCEPTED.set(accepted);
}

/// Install the panic hook, then judge startup for a program with no frame origins.
///
/// `console_error_panic_hook` makes a residual trap (e.g. stack exhaustion
/// from a non-TCO fold — the documented reachable residual) die with a
/// classified `console.error`, never a silent white screen.
pub fn install_panic_hook() {
    console_error_panic_hook::set_once();
    judge_startup(FrameAdmission::NoList);
}

/// [`install_panic_hook`] for a program that declares trusted frame origins.
///
/// `origins` are re-parsed and registered with the granted web-capability
/// suffixes `granted` as the program's frame policy. A list that does not
/// re-parse is a classified `console.error`, and the program never starts.
#[cfg(feature = "encoding")]
pub fn install_panic_hook_trusting_frames(origins: &[&str], granted: &[&str]) {
    console_error_panic_hook::set_once();
    let frames = match crate::frames::try_register(origins, granted) {
        Ok(()) => FrameAdmission::Registered,
        Err(refusal) => {
            console_fatal("StartupRefused", &refusal.to_string());
            FrameAdmission::Refused
        }
    };
    judge_startup(frames);
}

/// Drive the program's entry task on the browser microtask queue.
/// The `Err` arm logs a classified diagnostic (there is no process to exit).
/// A program whose environment was refused, or never judged, does not start.
pub fn run_start<E: std::fmt::Display + 'static>(task: IpeTask<E, ()>) {
    if STARTUP_ACCEPTED.get() != Some(&true) {
        console_fatal("StartupRefused", "the program did not start");
        return;
    }
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

/// The route-table half of a routed `Web.tea` that [`wasm_app_routed`] mounts.
///
/// `routes` match a path to a `Page`, `not_found` is entered when none does,
/// `set_page` applies an entered page to the model (yielding its entry Cmd),
/// `page_of` reads the model's page, and `render` turns a page back into its
/// canonical path, for navigation and for the URL every commit records.
pub struct RoutedPages<Page, FSetPage, FPageOf, FRender> {
    /// The declared route table, checked once at mount.
    pub routes: Vec<crate::web::route::Route<Page>>,
    /// The page a path matching no route enters.
    pub not_found: Page,
    /// Applies an entered page to the model.
    pub set_page: FSetPage,
    /// Reads the page a model shows.
    pub page_of: FPageOf,
    /// Renders a page to its canonical path.
    pub render: FRender,
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
pub fn wasm_app_routed<
    E,
    Model,
    Msg,
    Page,
    FInit,
    FUpdate,
    FView,
    FSubs,
    FSetPage,
    FPageOf,
    FRender,
>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
    pages: RoutedPages<Page, FSetPage, FPageOf, FRender>,
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
    FPageOf: for<'a> Fn(&'a Model) -> &'a Page + 'static,
    FRender: Fn(&Page) -> Result<crate::web::route::RoutePath, crate::web::route::RenderRefusal>
        + 'static,
{
    Box::pin(async move {
        match mount_app_routed(init, update, view, subscriptions, pages) {
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

/// A routed app's two halves: entering a URL, and the URL a model's page has.
///
/// Only a routed app has one, so an unrouted app never writes its URL.
struct WasmRouting<Model, Msg> {
    /// Enters a located path into the model.
    enter: Box<WasmRouter<Model, Msg>>,
    /// The browser path of the page a model shows.
    url_of: Box<dyn Fn(&Model) -> crate::dom::PageUrl>,
}

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

    /// Whether these Msgs are all the user's own events.
    const fn is_user(&self) -> bool {
        matches!(self, Self::User(_))
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
    /// The drop check the newest frame armed, if any; taken by its one drop.
    static FOCUS_PENDING: Cell<Option<Pending>> = const { Cell::new(None) };
}

/// A drop check a frame armed after its synchronous check.
///
/// The next drop of `held` to nothing posts one settle of `rec` over `chain`.
struct Pending {
    chain: Vec<FocusLink>,
    rec: Recorded,
    /// The node focused before the frame and still focused after it.
    held: web_sys::Element,
    queued: QueuedCause,
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
    let dropped = Closure::<dyn Fn(web_sys::Event)>::new(|ev: web_sys::Event| on_focus_drop(&ev));
    document
        .add_event_listener_with_callback_and_bool(
            FOCUS_DROP_EVENT,
            dropped.as_ref().unchecked_ref(),
            true,
        )
        .map_err(|e| listener_refusal(FOCUS_DROP_EVENT, &e))?;
    // The drop listener lives for the whole tab lifetime.
    dropped.forget();
    FOCUS_EPOCH_INSTALLED.with(|c| c.set(true));
    Ok(())
}

/// Answers the armed drop check when `ev` drops its held node to nothing.
///
/// The check is taken (one-shot) and runs in a posted task, after the whole
/// focus change: a `focusin` the same change raises has bumped the epoch by
/// then, so a move to another node is never taken back. A microtask would run
/// between `focusout` and `focusin` and read a Tab as a drop.
fn on_focus_drop(ev: &web_sys::Event) {
    let Some(pending) = FOCUS_PENDING.take() else {
        return;
    };
    let target_is_held = ev
        .target()
        .and_then(|target| target.dyn_into::<web_sys::Element>().ok())
        .is_some_and(|target| target == pending.held);
    // `relatedTarget` read by name: a `FocusEvent` web-sys feature would widen
    // the list the emitted manifest mirrors. An unreadable one is not null.
    let related_is_null = js_sys::Reflect::get(ev, &JsValue::from_str("relatedTarget"))
        .is_ok_and(|related| related.is_null() || related.is_undefined());
    if !drop_answers(target_is_held, related_is_null) {
        FOCUS_PENDING.set(Some(pending));
        return;
    }
    let Some(window) = web_sys::window() else {
        return;
    };
    let Pending {
        chain, rec, queued, ..
    } = pending;
    let task = Closure::once_into_js(move || {
        if let Ok(document) = document() {
            keep_focus(&document, &chain, rec, &queued);
        }
    });
    let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(task.unchecked_ref(), 0);
}

/// Where focus stands in this document now.
fn focus_mark() -> FocusMark<web_sys::Element> {
    FocusMark {
        epoch: FOCUS_EPOCH.with(Cell::get),
        at: document().ok().and_then(|d| d.active_element()),
    }
}

struct App<Model, Msg> {
    /// The page this client shows, as every paint and diff reads it.
    marks: ClientMarks,
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
    router: Option<WasmRouting<Model, Msg>>,
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
    // One renderer: the DOM starts as exactly the bytes the render sink
    // produces, so every later `diff` runs against known ground truth.
    let marks = client_marks();
    paint_first(
        &document,
        &body,
        &render_html_in(&tree, &RenderCtx::Client(&marks)),
    )?;

    let index = build_index(&tree);
    // Under the `debugger` feature the recorder seeds from the initial model, so
    // we keep `model` alive until after the `App` is built.
    #[cfg(feature = "debugger")]
    let recorder_base = model.clone();
    #[cfg(feature = "debugger")]
    let overlay = debugger_overlay::mount_overlay();
    let app = Rc::new(App {
        marks,
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

    // Dev-mode empty-first-diff assertion: the self-diff of `tree` must be empty
    // (the virtual tree IS the diff engine's ground truth; any non-empty result
    // means the ipe-id assignment is non-deterministic — a determinism
    // violation). Log a warning and continue: production falls back to a full
    // diff-and-replace on the first real update, never white-screens.
    let marks = client_marks();
    {
        use crate::dom::diff::diff;
        let self_patches = diff(&tree, &tree, &RenderCtx::Client(&marks));
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
        marks,
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
fn mount_app_routed<Model, Msg, Page, FInit, FUpdate, FView, FSubs, FSetPage, FPageOf, FRender>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
    pages: RoutedPages<Page, FSetPage, FPageOf, FRender>,
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
    FPageOf: for<'a> Fn(&'a Model) -> &'a Page + 'static,
    FRender: Fn(&Page) -> Result<crate::web::route::RoutePath, crate::web::route::RenderRefusal>
        + 'static,
{
    use crate::web::route::{DecodedPath, check_route_table, enter_located, navigate, page_url};

    let RoutedPages {
        routes,
        not_found,
        set_page,
        page_of,
        render,
    } = pages;

    // A malformed literal in the route table fails the mount loudly, with the
    // same refusal the server's `web_app_routed` starts with.
    check_route_table(&routes).map_err(MountRefusal::RouteTable)?;
    // The client is served at the root: the empty base strips nothing, and
    // adds nothing to a page's browser path.
    let base = DecodedPath::parse("").map_err(MountRefusal::BasePath)?;
    let url_base = crate::encoding::MountBase::root().encoded();

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
    let marks = client_marks();
    paint_first(
        &document,
        &body,
        &render_html_in(&tree, &RenderCtx::Client(&marks)),
    )?;

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
    let enter: Box<WasmRouter<Model, Msg>> = {
        let routes = Rc::clone(&routes_rc);
        let not_found = Rc::clone(&not_found_rc);
        let set_page = Rc::clone(&set_page_rc);
        let render = Rc::clone(&render_rc);
        Box::new(move |located: &crate::web::route::LocatedPath, m: Model| {
            navigate(&routes, located, &not_found, m, &*set_page, &*render)
        })
    };
    let url_of: Box<dyn Fn(&Model) -> crate::dom::PageUrl> = {
        let render = Rc::clone(&render_rc);
        Box::new(move |m: &Model| page_url(&url_base, (*render)(page_of(m))))
    };
    let router = WasmRouting { enter, url_of };

    #[cfg(feature = "debugger")]
    let recorder_base = model.clone();
    #[cfg(feature = "debugger")]
    let overlay = debugger_overlay::mount_overlay();
    let app = Rc::new(App {
        marks,
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
    attach_page_link_listener(&body, &app, base.clone())?;
    attach_popstate_listener(&app, base)?;
    // The entered page's route rewrites the entry the app was loaded at.
    sync_mounted_url(&app);
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
            navigate_to(
                &app,
                &crate::web::route::located(raw.as_deref(), &base),
                false,
            );
        });
    window
        .add_event_listener_with_callback("popstate", closure.as_ref().unchecked_ref())
        .map_err(|e| listener_refusal("popstate", &e))?;
    // The listener lives for the whole app lifetime.
    closure.forget();
    Ok(())
}

/// Install the delegated `click` listener that follows a page link in place.
///
/// It acts on the nearest `a[ipe-nav]` around the click target, the marker
/// only `Web.pageLink` writes, under the served client's predicate: a left
/// click with no modifier, on a link with no foreign `target` and no
/// `download`, whose `href` is a same-origin path. It enters that path
/// through [`navigate_to`], whose committed frame pushes its own page URL
/// through [`write_url`], the location's one writer. A path no route enters
/// leaves the click to the browser. The listener sits on `<body>`, so a link a
/// patch inserts is followed too.
fn attach_page_link_listener<Model, Msg>(
    body: &web_sys::HtmlElement,
    app: &Rc<App<Model, Msg>>,
    base: crate::web::route::DecodedPath,
) -> Result<(), MountRefusal>
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    let app = Rc::clone(app);
    let closure = Closure::<dyn Fn(web_sys::Event)>::new(move |ev: web_sys::Event| {
        let Some(href) = page_link_href(&ev) else {
            return;
        };
        if navigate_to(&app, &crate::web::route::located(Some(&href), &base), true) {
            ev.prevent_default();
        }
    });
    body.add_event_listener_with_callback("click", closure.as_ref().unchecked_ref())
        .map_err(|e| listener_refusal("click", &e))?;
    // The delegated page-link listener lives for the whole app lifetime.
    closure.forget();
    Ok(())
}

/// The `href` of the page link a click follows in place, `None` when the
/// browser keeps the click: one already handled, any button but the main one,
/// a modifier key, no `a[ipe-nav]` around the target, a `target` other than
/// `_self`, a `download` link, or an `href` that is not a same-origin path.
fn page_link_href(ev: &web_sys::Event) -> Option<String> {
    if ev.default_prevented() {
        return None;
    }
    let read = |name: &str| js_sys::Reflect::get(ev, &JsValue::from_str(name)).ok();
    if read("button")?.as_f64() != Some(0.0) {
        return None;
    }
    if ["metaKey", "ctrlKey", "shiftKey", "altKey"]
        .iter()
        .any(|key| read(key).is_none_or(|held| held.is_truthy()))
    {
        return None;
    }
    let link = ev
        .target()?
        .dyn_into::<web_sys::Element>()
        .ok()?
        .closest("a[ipe-nav]")
        .ok()??;
    if link
        .get_attribute("target")
        .is_some_and(|target| !target.eq_ignore_ascii_case("_self"))
        || link.has_attribute("download")
    {
        return None;
    }
    let href = link.get_attribute("href")?;
    // A same-origin path: one leading `/`, never `//` or `/\`, which a
    // browser reads as another host.
    let rest = href.strip_prefix('/')?;
    if rest.starts_with('/') || rest.starts_with('\\') {
        return None;
    }
    Some(href)
}

/// Apply a client-side navigation: enter `path` via the app's router closure,
/// commit the model, run a view→diff→patch cycle, then run the entry Cmd —
/// matching the server's entry. The committed frame's page URL is a new
/// history entry when `push` (a page-link click), else it rewrites the entry
/// the browser moved to (`popstate`). Returns whether a route entered `path`.
///
/// Returns early (no DOM mutation, no Cmd) when the router returns `None`, which means
/// the path does not match any declared route — unrouted popstate events (e.g.
/// a browser extension pushing `/favicon.ico`) must not rebuild the handler
/// index from the `notFound` view and orphan the live page's handlers.
fn navigate_to<Model, Msg>(
    app: &Rc<App<Model, Msg>>,
    path: &crate::web::route::LocatedPath,
    push: bool,
) -> bool
where
    Model: Clone + 'static,
    Msg: Clone + 'static,
{
    let Some(router) = app.router.as_ref() else {
        return false;
    };
    let current = app.model.borrow().clone();
    let Some(crate::web::route::Entered {
        model: new_model,
        cmd,
    }) = (router.enter)(path, current)
    else {
        return false;
    };
    *app.model.borrow_mut() = new_model.clone();

    // A scrubbed past step stays shown, as in `dispatch`; re-committing it
    // writes its URL back over the one the browser moved to.
    match frozen_step(app) {
        None => commit_view(app, render_frame(app, new_model), None, push),
        #[cfg(feature = "debugger")]
        Some(step) => flush_overlay_scrub(app, Some(step)),
        #[cfg(not(feature = "debugger"))]
        Some(_) => {}
    }

    run_cmd(app, cmd);
    resync_subscriptions(app);
    true
}

/// The past step the debugger scrubber holds the view at, `None` when the
/// view follows the live model.
fn frozen_step<Model, Msg>(app: &App<Model, Msg>) -> Option<usize> {
    #[cfg(feature = "debugger")]
    {
        app.overlay.as_ref().and_then(|ov| ov.scrub_step())
    }
    #[cfg(not(feature = "debugger"))]
    {
        let _: &App<Model, Msg> = app;
        None
    }
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
    if frozen_step(app).is_none() {
        let frame = render_frame(app, model);
        let target = if cause.addressed(&focus_mark()) {
            focus_target(&app.tree.borrow(), &frame.tree)
        } else {
            None
        };
        commit_view(app, frame, target.as_ref(), cause.is_user());
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

    // The shown step's page is the location, rewriting the current entry.
    commit_view(app, render_frame(app, render_model), None, false);

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

/// How a patch writes one attribute that is not a frame key.
#[derive(Debug, PartialEq, Eq)]
enum AttrWrite<'v> {
    /// Set the attribute to this value.
    Set(&'v str),
    /// Remove the attribute.
    Remove,
}

/// The write for attribute `key`, not a frame key, patched to `value`.
///
/// `None` removes and a value sets, the empty one included. `autofocus` never
/// reaches a live node, where a later move would focus it.
fn attr_write<'v>(key: &str, value: Option<&'v str>) -> AttrWrite<'v> {
    if key.eq_ignore_ascii_case("autofocus") {
        return AttrWrite::Remove;
    }
    value.map_or(AttrWrite::Remove, AttrWrite::Set)
}

/// The marks of the page this client shows: the authority its location
/// names, `Unknown` when there is no window or the host does not parse.
/// Popups never leave a trusted frame's sandbox here: a browser-built page
/// has no served `Cross-Origin-Opener-Policy` to bind them.
fn client_marks() -> ClientMarks {
    client_marks_of(web_sys::window().and_then(|window| window.location().host().ok()))
}

/// The client marks of a page whose location host is `host`.
fn client_marks_of(host: Option<String>) -> ClientMarks {
    ClientMarks {
        page: host.map_or(PageAuthority::Unknown, |host| {
            PageAuthority::of_location_host(&host)
        }),
        popups: EscapedPopups::Dropped,
    }
}

/// The ordered frame writes that patch the live frame `el` by `delta`, under
/// the program's frame policy and this client's marks.
fn frame_plan(el: &web_sys::Element, delta: &[(&str, Option<&str>)]) -> Vec<FrameWrite> {
    let marks = client_marks();
    plan_frame_patch(
        &el.local_name(),
        delta,
        |key| el.get_attribute(key),
        crate::frames::policy(),
        &marks.page,
        marks.popups,
    )
}

/// Apply `writes` to `el` in order, stopping at the first write the browser
/// refuses: a grant write that fails leaves every later navigation unwritten.
fn write_frame_plan(el: &web_sys::Element, writes: &[FrameWrite]) {
    for (key, value) in writes {
        let written = match value {
            Some(value) => el.set_attribute(key, value),
            None => el.remove_attribute(key),
        };
        if written.is_err() {
            return;
        }
    }
}

/// The frame-loading elements a detached holder is fenced on.
const FRAME_SELECTOR: &str = "iframe, embed, object, frame";

/// Fence every frame `frames` of a detached holder before its nodes connect:
/// each gets the grant its target earns ([`fence_frame`]), and an `embed`,
/// `object` or `frame` loading anything but a trusted origin is removed.
fn fence_frames(frames: &web_sys::NodeList) -> Result<(), &'static str> {
    let marks = client_marks();
    for i in 0..frames.length() {
        let Some(element) = frames
            .item(i)
            .and_then(|node| node.dyn_into::<web_sys::Element>().ok())
        else {
            continue;
        };
        match fence_frame(
            &element.local_name(),
            |key| element.get_attribute(key),
            crate::frames::policy(),
            &marks.page,
            marks.popups,
        ) {
            FrameFence::Remove => element.remove(),
            FrameFence::Write(writes) => {
                for (key, value) in writes {
                    let written = match value {
                        Some(value) => element.set_attribute(key, &value),
                        None => element.remove_attribute(key),
                    };
                    if written.is_err() {
                        element.remove();
                        break;
                    }
                }
            }
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

/// Replace `el`'s children with `html`, parsed by [`parse_detached`], keeping
/// each live node the new markup repeats by the rule of [`crate::dom::keep`].
pub fn replace_children_html(document: &web_sys::Document, el: &web_sys::Element, html: &str) {
    let replaced = parse_detached(document, el, html).and_then(|parsed| {
        let focused = document.active_element();
        swap_keeping(&markup_parent(el), &parsed.nodes, focused.as_ref())
    });
    if let Err(why) = replaced {
        console_fatal("PatchTargetLost", why);
    }
}

/// A live parent whose children a swap writes, and the parsed node holding
/// its new children.
struct SwapPair {
    live: web_sys::Node,
    parsed: web_sys::Node,
    /// Whether the pair lies inside a kept field, whose authority attributes
    /// the user owns.
    in_field: bool,
}

/// Swap `live`'s children for `parsed`'s, keeping every live node the new
/// markup repeats below a kept parent.
///
/// Each pair is walked once and a kept node is taken from its parent's
/// children at most once, so the walk is bounded by the live tree's size.
fn swap_keeping(
    live: &web_sys::Node,
    parsed: &web_sys::Node,
    focused: Option<&web_sys::Element>,
) -> Result<(), &'static str> {
    let mut pending = vec![SwapPair {
        live: live.clone(),
        parsed: parsed.clone(),
        in_field: false,
    }];
    while let Some(pair) = pending.pop() {
        swap_children(&pair, focused, &mut pending)?;
    }
    Ok(())
}

/// The children of `node`, in order.
fn children_of(node: &web_sys::Node) -> Vec<web_sys::Node> {
    let list = node.child_nodes();
    (0..list.length()).filter_map(|i| list.item(i)).collect()
}

/// The identity a swap keeps a node by: its non-empty `ipe-id` and its tag,
/// for an HTML element only. A foreign element is always rebuilt.
fn keep_key(node: &web_sys::Node) -> Option<(String, String)> {
    let el = node.dyn_ref::<web_sys::Element>()?;
    if el.namespace_uri().as_deref() != Some(HTML_NS) {
        return None;
    }
    let id = el
        .get_attribute(STAMPED_ID_ATTR)
        .filter(|id| !id.is_empty())?;
    Some((id, el.local_name()))
}

/// What the new markup `el` of `field` says about its value. A selected-option
/// query the browser refuses reads as controlled, so the program's value wins.
fn control_of(field: Field, el: &web_sys::Element) -> Control {
    let authority = AUTHORITY_ATTRS.iter().any(|name| el.has_attribute(name));
    let text = el.text_content().is_some_and(|t| !t.is_empty());
    let selected = !matches!(el.query_selector("option[selected]"), Ok(None));
    let marker = if el.has_attribute(CONTROLLED_ATTR) {
        Marker::Present
    } else {
        Marker::Absent
    };
    Control::of(field, marker, authority, text, selected)
}

/// Write `pair.live`'s children to `pair.parsed`'s, keeping each live child
/// [`keep`] admits and queueing it to have its own children written.
///
/// A kept node already in place is never moved: the children the new markup
/// drops leave first, and each child is then inserted only where it does not
/// already stand.
fn swap_children(
    pair: &SwapPair,
    focused: Option<&web_sys::Element>,
    pending: &mut Vec<SwapPair>,
) -> Result<(), &'static str> {
    let old = children_of(&pair.live);
    let mut by_key: HashMap<(String, String), VecDeque<usize>> = HashMap::new();
    for (index, node) in old.iter().enumerate() {
        if let Some(key) = keep_key(node) {
            by_key.entry(key).or_default().push_back(index);
        }
    }
    let mut taken = vec![false; old.len()];
    let mut placed = Vec::new();
    for new in children_of(&pair.parsed) {
        let matched = keep_key(&new)
            .and_then(|key| by_key.get_mut(&key)?.pop_front())
            .and_then(|index| Some((index, old.get(index)?.dyn_ref::<web_sys::Element>()?)));
        let (Some((index, live)), Some(markup)) = (matched, new.dyn_ref::<web_sys::Element>())
        else {
            placed.push(new);
            continue;
        };
        let kept = keep(&live.local_name(), focused == Some(live), |field| {
            control_of(field, markup)
        });
        let in_field = match kept {
            Keep::Rebuild => {
                placed.push(new);
                continue;
            }
            Keep::Node => pair.in_field,
            Keep::Field(_) => true,
        };
        write_kept_attrs(live, markup, in_field)?;
        if let Some(slot) = taken.get_mut(index) {
            *slot = true;
        }
        let live: web_sys::Node = live.clone().into();
        // A kept `textarea`'s text is its value, which the user owns.
        if kept != Keep::Field(Field::Textarea) {
            pending.push(SwapPair {
                live: live.clone(),
                parsed: new,
                in_field,
            });
        }
        placed.push(live);
    }
    for (node, kept) in old.iter().zip(&taken) {
        if !kept {
            pair.live
                .remove_child(node)
                .map_err(|_| "patched node could not be detached")?;
        }
    }
    let mut cursor = pair.live.first_child();
    for node in &placed {
        if cursor.as_ref() == Some(node) {
            cursor = node.next_sibling();
        } else {
            pair.live
                .insert_before(node, cursor.as_ref())
                .map_err(|_| "patched node could not be attached")?;
        }
    }
    Ok(())
}

/// The attribute names `el` carries.
fn attribute_names(el: &web_sys::Element) -> Vec<String> {
    el.get_attribute_names()
        .iter()
        .filter_map(|name| name.as_string())
        .collect()
}

/// Write `live`'s attributes to `markup`'s: a missing one is removed, a
/// different one set, an equal one left alone. Inside a kept field
/// (`in_field`) the authority attributes stay as the user left them.
fn write_kept_attrs(
    live: &web_sys::Element,
    markup: &web_sys::Element,
    in_field: bool,
) -> Result<(), &'static str> {
    let owned = |name: &str| in_field && is_authority_attr(name);
    let names = attribute_names(markup);
    let wanted: HashSet<&str> = names.iter().map(String::as_str).collect();
    for name in attribute_names(live) {
        if !owned(&name) && !wanted.contains(name.as_str()) {
            live.remove_attribute(&name)
                .map_err(|_| "kept node attribute could not be removed")?;
        }
    }
    for name in &names {
        if owned(name) {
            continue;
        }
        let Some(value) = markup.get_attribute(name) else {
            continue;
        };
        if live.get_attribute(name).as_deref() != Some(value.as_str()) {
            live.set_attribute(name, &value)
                .map_err(|_| "kept node attribute could not be set")?;
        }
    }
    Ok(())
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

/// The view of one model with the page URL that model's page has.
///
/// Both halves come from the same model in [`render_frame`], so a committed
/// frame never carries the URL of another model than the one it shows.
struct Frame<Msg> {
    tree: Html<Msg>,
    url: crate::dom::PageUrl,
}

/// Renders `model` into the frame [`commit_view`] commits: its page URL is
/// taken before the view consumes it. An unrouted app's frame has no URL.
fn render_frame<Model, Msg>(app: &App<Model, Msg>, model: Model) -> Frame<Msg> {
    let url = app
        .router
        .as_ref()
        .map_or(crate::dom::PageUrl::Unrouted, |router| {
            (router.url_of)(&model)
        });
    let mut tree = (app.view)(model);
    assign_ipe_ids(&mut tree, ROOT_IPE_ID);
    Frame { tree, url }
}

/// Commits `frame` as the app's next frame, focusing `target` when the frame
/// addresses one, then records the frame's page URL as the location: a new
/// history entry when `push`, else the current entry rewritten.
///
/// The view the handlers resolve against becomes the frame's tree BEFORE the
/// frame applies: the frame's own focus moves (the focus keep, `target`) raise
/// `focus`/`focusin` synchronously, and the Msg such an event resolves to must
/// come from the view on screen, never from the one the frame replaced.
fn commit_view<Model, Msg: Clone>(
    app: &App<Model, Msg>,
    frame: Frame<Msg>,
    target: Option<&StampedId>,
    push: bool,
) {
    let Frame {
        tree: new_tree,
        url,
    } = frame;
    let patches = diff(
        &app.tree.borrow(),
        &new_tree,
        &RenderCtx::Client(&app.marks),
    );
    *app.index.borrow_mut() = build_index(&new_tree);
    *app.tree.borrow_mut() = new_tree;
    commit_frame(&patches, target, &app.cause);
    // A widget that first appears via an `html`-subtree replace bypasses the
    // attribute-patch property route; re-deliver each widget's decoded down-state
    // PROPERTY (idempotent, bounded by the widget count).
    if let Ok(document) = document() {
        widget::sync_widget_properties(&document, &app.tree.borrow());
    }
    write_url(&url, push);
}

/// Records the route of the page the mounted model shows as the location,
/// rewriting the entry the app was loaded at.
fn sync_mounted_url<Model, Msg>(app: &App<Model, Msg>) {
    let Some(router) = app.router.as_ref() else {
        return;
    };
    write_url(&(router.url_of)(&app.model.borrow()), false);
}

/// The one writer of the location: records `url` as a new history entry when
/// `push` (a render of the user's own events, a page-link click), otherwise
/// rewriting the current entry (mount, `popstate`, a debugger scrub, and every
/// Cmd or Sub result). A route that is already the location writes nothing, an
/// unrouted app has no route, and a page whose route does not render leaves
/// the URL as it is and is reported once per commit.
fn write_url(url: &crate::dom::PageUrl, push: bool) {
    let path = match url {
        crate::dom::PageUrl::Routed(path) => path.as_str(),
        crate::dom::PageUrl::Unrouted => return,
        crate::dom::PageUrl::Unrenderable(refusal) => {
            console_warn(&format!(
                "route.unrenderable: the page's URL is left unchanged: {refusal}"
            ));
            return;
        }
    };
    let Some(window) = web_sys::window() else {
        return;
    };
    if window.location().pathname().ok().as_deref() == Some(path) {
        return;
    }
    let Ok(history) = window.history() else {
        return;
    };
    let written = if push {
        history.push_state_with_url(&JsValue::NULL, "", Some(path))
    } else {
        history.replace_state_with_url(&JsValue::NULL, "", Some(path))
    };
    if written.is_err() {
        console_warn("route.history: the browser refused the page's URL");
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
/// of [`crate::dom::focus`] at once; when the frame (or an earlier one whose
/// check it carries) patched the focused node's chain and focus held, the
/// browser's own later drop of that node to nothing is answered once, by the
/// drop event it raises. A restore moves a pending user mark in `queued` onto
/// the landing node.
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
            let tag = el.local_name();
            let delta: Vec<(&str, Option<&str>)> = p
                .attrs
                .iter()
                .filter(|(k, _)| frame_patch_key(&tag, k).is_some())
                .map(|(k, v)| (k.as_str(), v.as_deref()))
                .collect();
            if !delta.is_empty() {
                write_frame_plan(&el, &frame_plan(&el, &delta));
            }
            for (k, v) in &p.attrs {
                if frame_patch_key(&tag, k).is_some() {
                    continue;
                }
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

    let before = document.active_element();
    let chain = before
        .clone()
        .and_then(|focused| view_chain(document, focused));
    let focus_epoch = FOCUS_EPOCH.with(Cell::get);
    // Taken before the commit: a drop the commit raises answers no record. An
    // armed check on the node still held is handed on to this frame below.
    let earlier = FOCUS_PENDING.take();
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
    let held = document.active_element();
    let carried = earlier.is_some_and(|armed| {
        carries(
            before.as_ref() == Some(&armed.held),
            armed.rec.focus_epoch == focus_epoch,
        )
    });
    let armed = arms(
        &chain,
        |id| patches.iter().any(|p| p.id == id),
        held.is_some() && held == before,
        !focus_on_body(document),
        carried,
    );
    // The drop listener is installed here too: a frame can commit before a
    // mount installed the focus-move listeners.
    if armed
        && let Some(held) = held
        && install_focus_epoch(document).is_ok()
    {
        FOCUS_PENDING.set(Some(Pending {
            chain,
            rec,
            held,
            queued: queued.clone(),
        }));
    }
}

/// The view chain of `focused` below the body, the wasm mount container.
fn view_chain(document: &web_sys::Document, focused: web_sys::Element) -> Option<Vec<FocusLink>> {
    let body = document.body()?;
    let root: &web_sys::Element = body.as_ref();
    if focused == *root || !root.contains(Some(&focused)) {
        return None;
    }
    let upward = std::iter::successors(Some(focused), |el: &web_sys::Element| el.parent_element())
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

/// Write one patched attribute onto the live `el`: `Some` sets, `None`
/// removes. A frame key goes through the element's frame plan, so an iframe
/// holds its grant before it holds a URL and a frame loader gains its URL only
/// toward a trusted origin; any other key through `attr_write`.
pub fn write_patched_attr(el: &web_sys::Element, key: &str, value: Option<&str>) {
    if frame_patch_key(&el.local_name(), key).is_some() {
        write_frame_plan(el, &frame_plan(el, &[(key, value)]));
        return;
    }
    match attr_write(key, value) {
        AttrWrite::Set(v) => {
            let _ = el.set_attribute(key, v);
            sync_dom_property(el, key, v);
        }
        AttrWrite::Remove => {
            let _ = el.remove_attribute(key);
            clear_dom_property(el, key);
        }
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

    #[wasm_bindgen_test]
    fn startup_accepted_folds_the_frame_admission() {
        let table = [
            (true, FrameAdmission::NoList, true),
            (true, FrameAdmission::Registered, true),
            (true, FrameAdmission::Refused, false),
            (false, FrameAdmission::NoList, false),
            (false, FrameAdmission::Registered, false),
            (false, FrameAdmission::Refused, false),
        ];
        for (env_clean, frames, accepted) in table {
            assert_eq!(
                startup_accepted(env_clean, frames),
                accepted,
                "({env_clean}, {frames:?})"
            );
        }
    }

    #[wasm_bindgen_test]
    fn wasm_runtime_refuses_a_loopback_frame_origin() {
        let loopback = crate::frames::policy_of(&["http://localhost:3000"], &[]);
        assert!(
            matches!(
                loopback,
                Err(crate::frames::FrameRegisterRefusal::Origin { index: 0, .. })
            ),
            "{loopback:?}"
        );
        let listed = crate::frames::policy_of(&["https://player.example"], &["camera"]);
        assert!(listed.is_ok(), "{listed:?}");
    }

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

    #[wasm_bindgen_test]
    fn a_patch_never_writes_autofocus() {
        assert_eq!(attr_write("autofocus", Some("")), AttrWrite::Remove);
        assert_eq!(
            attr_write("autofocus", Some("autofocus")),
            AttrWrite::Remove
        );
        assert_eq!(attr_write("AutoFocus", Some("true")), AttrWrite::Remove);
        assert_eq!(attr_write("class", Some("a")), AttrWrite::Set("a"));
        assert_eq!(attr_write("class", Some("")), AttrWrite::Set(""));
        assert_eq!(attr_write("class", None), AttrWrite::Remove);
    }

    /// The frame writes that patch a `tag` whose live attributes are `live` by
    /// `delta`, under `policy` on a page with no known authority.
    fn plan(
        tag: &str,
        live: &[(&str, &str)],
        delta: &[(&str, Option<&str>)],
        policy: &crate::frames::FramePolicy,
    ) -> Vec<FrameWrite> {
        let marks = client_marks_of(Some("other.example".to_owned()));
        plan_frame_patch(
            tag,
            delta,
            |key| {
                live.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(key))
                    .map(|(_, v)| (*v).to_owned())
            },
            policy,
            &marks.page,
            marks.popups,
        )
    }

    /// The value `writes` leaves on `key`, when it writes `key`.
    fn written<'w>(writes: &'w [FrameWrite], key: &str) -> Option<Option<&'w str>> {
        writes
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_deref())
    }

    /// An `iframe`'s `sandbox` is never removed, a set is canonical, and an
    /// unlisted frame never keeps a widening token.
    #[wasm_bindgen_test]
    fn a_patch_never_removes_an_iframe_sandbox() {
        let none = crate::frames::FramePolicy::none();
        for (tag, key) in [("iframe", "sandbox"), ("IFRAME", "SandBox")] {
            let removed = plan(tag, &[("sandbox", "allow-forms")], &[(key, None)], &none);
            assert_eq!(written(&removed, "sandbox"), Some(Some("")));
            let wide = Some("ALLOW-SCRIPTS allow-same-origin allow-forms");
            let set = plan(tag, &[], &[(key, wide)], &none);
            assert_eq!(
                written(&set, "sandbox"),
                Some(Some("allow-forms allow-scripts"))
            );
            let escape = Some("allow-popups-to-escape-sandbox");
            let set = plan(tag, &[], &[(key, escape)], &none);
            assert_eq!(written(&set, "sandbox"), Some(Some("")));
        }
        assert_eq!(frame_patch_key("div", "sandbox"), None);
    }

    /// A frame loader never gains the attribute it loads from toward an
    /// unlisted URL, in any case.
    #[wasm_bindgen_test]
    fn a_patch_never_gives_a_frame_loader_its_url() {
        let none = crate::frames::FramePolicy::none();
        for (tag, key, stored) in [
            ("embed", "src", "src"),
            ("EMBED", "SRC", "src"),
            ("object", "data", "data"),
            ("frame", "Src", "src"),
        ] {
            for value in ["", " ", "/"] {
                let writes = plan(tag, &[], &[(key, Some(value))], &none);
                assert_eq!(written(&writes, stored), Some(None), "{tag} {key}");
            }
            let writes = plan(tag, &[], &[(key, None)], &none);
            assert_eq!(written(&writes, stored), Some(None));
        }
        assert_eq!(frame_patch_key("embed", "type"), None);
        assert_eq!(frame_patch_key("object", "src"), None);
    }

    /// A `src` patched onto an `iframe` writes the sandbox first, whether or
    /// not one was held.
    #[wasm_bindgen_test]
    fn an_iframe_src_patch_sandboxes_first() {
        let none = crate::frames::FramePolicy::none();
        for live in [&[][..], &[("sandbox", "allow-forms")][..]] {
            for (key, value) in [("src", Some("/")), ("SRC", Some("")), ("src", None)] {
                let writes = plan("iframe", live, &[(key, value)], &none);
                assert_eq!(writes.first().map(|(k, _)| *k), Some("sandbox"));
                assert_eq!(writes.last(), Some(&("src", value.map(str::to_owned))));
            }
        }
        assert_eq!(frame_patch_key("div", "src"), None);
    }

    /// R10g: the client's marks read its location's host, and a page with no
    /// window or an unparsable host trusts no frame.
    #[wasm_bindgen_test]
    #[allow(clippy::expect_used)] // every vector is well-formed
    fn wasm_client_marks_read_the_location() {
        let page = crate::inbound_authority::Authority::parse("app.example:8443")
            .expect("a well-formed vector");
        assert_eq!(
            client_marks_of(Some("app.example:8443".to_owned())).page,
            PageAuthority::Known(page)
        );
        for host in [None, Some(String::new()), Some("app.example.".to_owned())] {
            assert_eq!(client_marks_of(host).page, PageAuthority::Unknown);
        }
        if web_sys::window().is_none() {
            assert_eq!(client_marks().page, PageAuthority::Unknown);
        }
    }

    /// R13, client half: under a listed policy every grant write precedes the
    /// navigation, and leaving the listed origin withdraws the grant first.
    #[wasm_bindgen_test]
    #[allow(clippy::expect_used)] // every vector is well-formed
    fn a_wasm_patch_writes_grants_before_navigation() {
        let policy = crate::frames::policy_of(&["https://frames.example"], &[])
            .expect("a well-formed vector");
        let live = [
            ("src", "https://frames.example/a"),
            ("sandbox", "allow-same-origin allow-scripts"),
        ];
        let away = plan("iframe", &live, &[("src", Some("/b"))], &policy);
        assert_eq!(written(&away, "sandbox"), Some(Some("allow-scripts")));
        assert_eq!(away.last(), Some(&("src", Some("/b".to_owned()))));
        let stay = plan(
            "iframe",
            &live,
            &[("src", Some("https://frames.example/b"))],
            &policy,
        );
        assert_eq!(
            written(&stay, "sandbox"),
            Some(Some("allow-same-origin allow-scripts"))
        );
        let embed = plan(
            "embed",
            &[],
            &[("src", Some("https://frames.example"))],
            &policy,
        );
        assert_eq!(
            embed.last(),
            Some(&("src", Some("https://frames.example".to_owned())))
        );
    }

    /// R27, client half: a browser-built page never holds escaped popups, so
    /// a trusted frame's escape token is dropped.
    #[wasm_bindgen_test]
    #[allow(clippy::expect_used)] // every vector is well-formed
    fn wasm_popups_are_always_dropped() {
        for host in [None, Some("other.example".to_owned())] {
            assert_eq!(client_marks_of(host).popups, EscapedPopups::Dropped);
        }
        assert_eq!(client_marks().popups, EscapedPopups::Dropped);
        let policy = crate::frames::policy_of(&["https://frames.example"], &[])
            .expect("a well-formed vector");
        let escape = Some("allow-popups allow-popups-to-escape-sandbox");
        let writes = plan(
            "iframe",
            &[("src", "https://frames.example")],
            &[("sandbox", escape)],
            &policy,
        );
        assert_eq!(written(&writes, "sandbox"), Some(Some("allow-popups")));
    }

    /// The browser client's script, whose frame rules R14 runs here.
    const CLIENT_JS: &str = include_str!("../web/client.js");

    /// The one top-level item of `client.js` that starts with `head` and ends
    /// at the first `tail` after it, `tail` included.
    #[allow(clippy::expect_used)] // the script holds each named item once
    fn client_js_item(head: &str, tail: &str) -> &'static str {
        assert_eq!(CLIENT_JS.matches(head).count(), 1, "one {head}");
        let start = CLIENT_JS.find(head).expect("the item");
        let rest = CLIENT_JS.get(start..).expect("the item");
        let len = rest.find(tail).expect("the item's end") + tail.len();
        rest.get(..len).expect("the item")
    }

    /// The `client.js` frame rules as one function of the boot block, the
    /// page's host and a frame's live and patched attributes, returning the
    /// JSON of `__ipeFramePlan`'s writes. The DOM reads it makes go through a
    /// stand-in node.
    fn client_js_frame_plan() -> js_sys::Function {
        let mut body = String::from(
            "var __ipeBoot = JSON.parse(boot);\n\
             var window = { top: 1, self: 1 };\n\
             var location = { host: host };\n\
             var __ipeNode = {\n\
               local: function(el) { return el.tag; },\n\
               attr: function(el, k) {\n\
                 return Object.prototype.hasOwnProperty.call(el.attrs, k) ? el.attrs[k] : null;\n\
               }\n\
             };\n",
        );
        for table in [
            "__IPE_SANDBOX_TOKENS",
            "__IPE_FRAME_LOADERS",
            "__IPE_TRUSTED_SANDBOX_TOKENS",
            "__IPE_FRAME_PERMISSIONS",
            "__IPE_DELEGATION_FEATURES",
        ] {
            body.push_str(client_js_item(&format!("var {table} = "), ";\n"));
        }
        for function in [
            "__ipeAsciiLower",
            "__ipeSandbox",
            "__ipeFrameLoaderKey",
            "__ipeFrameList",
            "__ipeEscapePopups",
            "__ipeListedOrigin",
            "__ipeServedOn",
            "__ipeFrameTarget",
            "__ipeTrustedSandbox",
            "__ipeAllow",
            "__ipeFrameGrant",
            "__ipeFramePatchKeys",
            "__ipeFramePlan",
        ] {
            body.push_str(client_js_item(&format!("\nfunction {function}("), "\n}\n"));
        }
        body.push_str("return JSON.stringify(__ipeFramePlan(JSON.parse(el), JSON.parse(attrs)));");
        js_sys::Function::new_with_args("boot, host, el, attrs", &body)
    }

    /// `pairs` as a JSON object, in order; `None` is `null`.
    #[allow(clippy::expect_used)] // a string always serializes
    fn json_object(pairs: &[(&str, Option<&str>)]) -> String {
        let fields: Vec<String> = pairs
            .iter()
            .map(|(key, value)| {
                format!(
                    "{}:{}",
                    serde_json::to_string(key).expect("a key"),
                    serde_json::to_string(value).expect("a value")
                )
            })
            .collect();
        format!("{{{}}}", fields.join(","))
    }

    /// The frame origins R14 lists, two loopback names among them.
    const R14_ORIGINS: [&str; 4] = [
        "https://app.example",
        "https://frames.example:8443",
        "https://localhost:8443",
        "https://a.localhost",
    ];

    /// Every sandbox token a trusted frame may keep.
    const R14_WIDE: &str =
        "allow-same-origin allow-scripts allow-popups allow-popups-to-escape-sandbox";

    /// An `allow` naming a gated, a granted, a never, a cross-origin and an
    /// undisclosed feature.
    const R14_ALLOW: &str =
        "camera; geolocation 'src'; payment; fullscreen https://frames.example:8443; usb";

    /// One R14 vector: a frame's tag, its live attributes and a patch.
    type R14Vector = (
        &'static str,
        &'static [(&'static str, &'static str)],
        &'static [(&'static str, Option<&'static str>)],
    );

    /// The frames and patches R14 runs on every page.
    const R14_VECTORS: &[R14Vector] = &[
        (
            "iframe",
            &[],
            &[
                ("src", Some("https://frames.example:8443/x")),
                ("sandbox", Some(R14_WIDE)),
                ("allow", Some(R14_ALLOW)),
            ],
        ),
        (
            "iframe",
            &[
                ("src", "https://frames.example:8443/a"),
                ("sandbox", "allow-same-origin allow-scripts"),
                ("allow", "camera"),
            ],
            &[("src", Some("/b"))],
        ),
        (
            "iframe",
            &[
                ("src", "https://frames.example:8443"),
                ("sandbox", R14_WIDE),
            ],
            &[("srcdoc", Some("<p>"))],
        ),
        (
            "iframe",
            &[("srcdoc", "<p>"), ("sandbox", R14_WIDE)],
            &[("srcdoc", None), ("src", Some("https://app.example/"))],
        ),
        (
            "IFRAME",
            &[],
            &[
                ("SRC", Some("https://localhost:8443")),
                ("Sandbox", Some("ALLOW-SAME-ORIGIN allow-scripts")),
                ("AllowFullScreen", Some("")),
            ],
        ),
        (
            "iframe",
            &[("sandbox", R14_WIDE)],
            &[
                ("src", Some("https://evil.example")),
                ("SRC", Some("https://a.localhost/p?q#f")),
            ],
        ),
        (
            "iframe",
            &[
                ("src", "https://frames.example:8443"),
                ("sandbox", R14_WIDE),
            ],
            &[("sandbox", None), ("allowpaymentrequest", Some(""))],
        ),
        (
            "iframe",
            &[],
            &[("src", Some("https://frames.example:8443.evil/"))],
        ),
        (
            "iframe",
            &[],
            &[("src", Some("https://frames.example:84430"))],
        ),
        (
            "iframe",
            &[],
            &[("src", Some("https://frames.example:8443\\@evil"))],
        ),
        (
            "iframe",
            &[],
            &[("src", Some(" https://frames.example:8443"))],
        ),
        (
            "iframe",
            &[],
            &[("src", Some("HTTPS://frames.example:8443"))],
        ),
        (
            "embed",
            &[],
            &[
                ("src", Some("https://a.localhost/x")),
                ("allowfullscreen", Some("")),
            ],
        ),
        (
            "embed",
            &[("src", "https://frames.example:8443")],
            &[("src", Some("/"))],
        ),
        (
            "object",
            &[],
            &[("data", Some("https://frames.example:8443?q"))],
        ),
        ("OBJECT", &[], &[("DATA", Some("https://evil.example"))]),
        (
            "frame",
            &[],
            &[("src", Some("https://frames.example:8443"))],
        ),
        ("div", &[], &[("src", Some("https://frames.example:8443"))]),
    ];

    /// The page hosts R14 runs every vector on: the listed hosts at and off
    /// their ports and in another case, a subdomain, loopback names, IP
    /// literals and a numeric last label, and hosts `Authority::parse`
    /// refuses (a trailing dot, an edge hyphen, a 64-byte label, a 254-byte
    /// name, a non-canonical or out-of-range port, an empty host).
    const R14_HOSTS: [&str; 25] = [
        "app.example",
        "app.example:8443",
        "APP.Example:8443",
        "sub.app.example",
        "frames.example",
        "frames.example:8443",
        "localhost:8443",
        "localhost",
        "a.localhost:3000",
        "b.localhost",
        "B.LocalHost",
        "other.example",
        "127.0.0.1:3000",
        "203.0.113.7",
        "a.123",
        "[::1]:3000",
        "app.example.",
        "localhost.",
        "-a.example",
        "a-.localhost",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "app.example:0443",
        "app.example:65536",
        "",
    ];

    /// The JSON of `client.js`'s frame plan for `vector` on a page at `host`
    /// under the boot block `boot`.
    #[allow(clippy::expect_used)] // the client plan returns its JSON string
    fn client_js_plan(
        client: &js_sys::Function,
        boot: &str,
        host: &str,
        (tag, live, delta): &R14Vector,
    ) -> String {
        let live: Vec<(&str, Option<&str>)> = live.iter().map(|(k, v)| (*k, Some(*v))).collect();
        let el = format!(
            "{{\"tag\":{},\"attrs\":{}}}",
            serde_json::to_string(tag).expect("a tag"),
            json_object(&live)
        );
        let args = js_sys::Array::of4(
            &boot.into(),
            &host.into(),
            &el.as_str().into(),
            &json_object(delta).as_str().into(),
        );
        client
            .apply(&wasm_bindgen::JsValue::NULL, &args)
            .expect("the client plan runs")
            .as_string()
            .expect("the client plan's JSON")
    }

    /// R14, executed: on every page host, popup mark, frame and patch of the
    /// vector table, `client.js`'s `__ipeFramePlan` writes exactly what the
    /// runtime's `plan_frame_patch` writes, in the same order.
    #[wasm_bindgen_test]
    #[allow(clippy::expect_used)] // the vector table is well-formed
    fn client_js_frame_plan_matches_the_runtime() {
        let policy = crate::frames::policy_of(&R14_ORIGINS, &["camera"]).expect("the policy");
        let grants: Vec<&str> = policy
            .grants()
            .suffixes()
            .map(crate::frames::GrantSuffix::as_str)
            .collect();
        let client = client_js_frame_plan();
        for popups in [EscapedPopups::Held, EscapedPopups::Dropped] {
            let boot = serde_json::json!({
                "frameOrigins": R14_ORIGINS,
                "frameGrants": grants,
                "escapePopups": popups.is_held(),
            })
            .to_string();
            for host in R14_HOSTS {
                let page = PageAuthority::of_location_host(host);
                for vector in R14_VECTORS {
                    let (tag, live, delta) = vector;
                    let runtime = plan_frame_patch(
                        tag,
                        delta,
                        |key| {
                            live.iter()
                                .find(|(k, _)| *k == key)
                                .map(|(_, v)| (*v).to_owned())
                        },
                        &policy,
                        &page,
                        popups,
                    );
                    assert_eq!(
                        client_js_plan(&client, &boot, host, vector),
                        serde_json::to_string(&runtime).expect("the runtime plan's JSON"),
                        "{popups:?} on {host:?}: {tag} {live:?} {delta:?}"
                    );
                }
            }
        }
    }

    /// A `Decode.index` past the 32-bit `usize` is out of range here, never
    /// wrapped to element `0`; this is the target where a cast would wrap.
    #[wasm_bindgen_test]
    fn a_decode_index_past_the_usize_width_is_out_of_range() {
        use crate::json::{decode_index, index_of, json_decode_int};
        use crate::json_val::JsonVal;
        assert_eq!(index_of(1 << 32, 1), None);
        assert_eq!(index_of(-(1 << 32), 1), None);
        assert_eq!(index_of(-1, 1), None);
        assert_eq!(index_of(0, 1), Some(0));
        // The decoder itself, so a cast reintroduced at the call site is red.
        let arr = JsonVal::from_serde(serde_json::json!([10, 20]));
        for n in [1_i64 << 32, -(1_i64 << 32), (1_i64 << 32) + 1, -1, 2] {
            let got = (decode_index(n, json_decode_int::<String>()).run)(&arr);
            assert!(
                matches!(&got, IpeResult::Err(e) if e.contains("index out of range")),
                "index {n}: {got:?}"
            );
        }
        let got = (decode_index(1, json_decode_int::<String>()).run)(&arr);
        assert!(matches!(got, IpeResult::Ok(20)), "{got:?}");
    }
}
