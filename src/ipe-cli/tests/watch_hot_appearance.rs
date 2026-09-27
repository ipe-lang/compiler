//! End-to-end proof for `ipe watch`'s appearance hot-swap classifier.
//!
//! Under `IPE_WATCH_HOT_APPEARANCE`, an edit to a hoisted style-value literal in
//! a web `view` is classified `AppearanceOnly` and pushed to the running app as a
//! `LiteralTable` patch — no `cargo build`, no process restart. A structural edit
//! (add an element) is classified `Logic` and recompiles. This test asserts both
//! outcomes at the watch-loop + process level:
//!
//! - a style-value edit fires [`WatchEvent::AppearanceHotSwapped`], produces NO
//!   new `RebuildStarted`, and leaves the SAME server PID serving (no restart);
//! - a structural edit fires `RebuildStarted` and swaps the server PID.
//!
//! The browser-visible half — the endpoint applying the patch and pushing the
//! resulting VDOM diff over SSE — is proven by the Step-2 runtime/client test
//! (`ipe_runtime::web`'s `apply_literal_patch_to_web_sessions`); here we prove the
//! watch loop reaches that endpoint for a style edit and recompiles for a logic
//! edit, which is the classifier's contract.
//!
//! Gated on `IPE_E2E=1` like the sibling `watch_integration.rs`: it drives a real
//! `cargo build` and spawns the emitted binary. Linux-only for the PID-liveness
//! check via `/proc`, exactly as `watch_integration.rs`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ipe::watch::{WatchEvent, WatchHandle, WatchOptions};

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A minimal `Web.tea` whose view carries a hoistable `Ui.padding` style value
/// and a marker text so an HTTP read can confirm the app is up. `padding` is the
/// dominant appearance edit and hoists to a `LiteralTable` default under the flag.
fn web_fixture(padding: u32, extra_text: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Tea.Web.Cmd\n\
         import Ipe.Tea.Web.Sub\n\
         import Ipe.String\n\n\
         type alias Model = {{ count : Int }}\n\n\
         type Msg = Noop\n\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req =\n    \
             ( {{ count = 0 }}, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model =\n    \
             ( model, Cmd.none )\n\n\
         view : Model -> Element Msg\n\
         view _model =\n    \
             Ui.column [ Ui.padding {padding} ]\n        \
                 [ Ui.text \"marker\"{extra_text} ]\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n    \
             Sub.none\n\n\
         main =\n    \
             Web.tea\n        \
                 {{ init = init, update = update, view = view, subscriptions = subscriptions\n        \
                 , routes = [], notFound = Noop\n        \
                 }}\n",
    )
}

/// A `Web.tea` whose view carries a hoistable **numeric appearance scalar**
/// (`Font.weight : Int`) — a direct `Int` style value read back through the
/// `parse::<i64>().unwrap_or(<literal>)` path. A marker text confirms the app is
/// up. The weight hoists into the per-view `LiteralTable` default under the flag.
fn web_fixture_weight(weight: u32, extra_text: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Ui.Font as Font\n\
         import Ipe.Tea.Web.Cmd\n\
         import Ipe.Tea.Web.Sub\n\
         import Ipe.String\n\n\
         type alias Model = {{ count : Int }}\n\n\
         type Msg = Noop\n\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req =\n    \
             ( {{ count = 0 }}, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model =\n    \
             ( model, Cmd.none )\n\n\
         view : Model -> Element Msg\n\
         view _model =\n    \
             Ui.column [ Font.weight {weight} ]\n        \
                 [ Ui.text \"marker\"{extra_text} ]\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n    \
             Sub.none\n\n\
         main =\n    \
             Web.tea\n        \
                 {{ init = init, update = update, view = view, subscriptions = subscriptions\n        \
                 , routes = [], notFound = Noop\n        \
                 }}\n",
    )
}

/// A `Web.tea` whose view attaches an animation built from a fully literal
/// `Ipe.Ui.Animation` pipeline — every knob a compile-time constant. The
/// Phase-2 const-fold reduces `Animation.attribute { …, duration, … }` to a
/// direct `Ui.animate <name> "<shorthand tail>" …` whose shorthand-tail string
/// literal carries `<duration>ms …`; that literal hoists into the per-view
/// `LiteralTable`, so a `duration` edit changes only a `LiteralTable` slot and
/// hot-swaps without a rebuild. A marker text confirms the app is up.
fn web_fixture_animation(duration: u32, extra_text: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Ui.Animation as Animation\n\
         import Ipe.Tea.Web.Cmd\n\
         import Ipe.Tea.Web.Sub\n\
         import Ipe.String\n\n\
         type alias Model = {{ count : Int }}\n\n\
         type Msg = Noop\n\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req =\n    \
             ( {{ count = 0 }}, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model =\n    \
             ( model, Cmd.none )\n\n\
         view : Model -> Element Msg\n\
         view _model =\n    \
             Ui.column\n        \
                 [ Animation.attribute\n            \
                     {{ name = \"spin\"\n            \
                     , duration = {duration}\n            \
                     , easing = Animation.easeInOut\n            \
                     , delay = 0\n            \
                     , iterations = Animation.once\n            \
                     , fillMode = Animation.forwards\n            \
                     , respectReducedMotion = True\n            \
                     , keyframes = []\n            \
                     }}\n        \
                 ]\n        \
                 [ Ui.text \"marker\"{extra_text} ]\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n    \
             Sub.none\n\n\
         main =\n    \
             Web.tea\n        \
                 {{ init = init, update = update, view = view, subscriptions = subscriptions\n        \
                 , routes = [], notFound = Noop\n        \
                 }}\n",
    )
}

/// A `Web.tea` whose view carries a hoistable **attribute value** (`Ui.name`)
/// and a **static text** node whose content is `text` — both widened
/// appearance-literal kinds (Step 5). A marker text confirms the app is up.
fn web_fixture_attr_text(name: &str, text: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Tea.Web.Cmd\n\
         import Ipe.Tea.Web.Sub\n\
         import Ipe.String\n\n\
         type alias Model = {{ count : Int }}\n\n\
         type Msg = Noop\n\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req =\n    \
             ( {{ count = 0 }}, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model =\n    \
             ( model, Cmd.none )\n\n\
         view : Model -> Element Msg\n\
         view _model =\n    \
             Ui.column [ Ui.name \"{name}\" ]\n        \
                 [ Ui.text \"marker\", Ui.text \"{text}\" ]\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n    \
             Sub.none\n\n\
         main =\n    \
             Web.tea\n        \
                 {{ init = init, update = update, view = view, subscriptions = subscriptions\n        \
                 , routes = [], notFound = Noop\n        \
                 }}\n",
    )
}

/// A `Web.tea` whose view carries a `Ui.image { src, description }` whose
/// `description` (alt text) is a hoistable record-native appearance field. A
/// marker text confirms the app is up. `description` is a direct string
/// literal, so it hoists into the per-view `LiteralTable`; `src` is a typed
/// `ImageValue` (a data URI via `Ui.imageData`) since `Ui.image` no longer
/// accepts a raw string.
fn web_fixture_image(description: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Tea.Web.Cmd\n\
         import Ipe.Tea.Web.Sub\n\
         import Ipe.String\n\n\
         type alias Model = {{ count : Int }}\n\n\
         type Msg = Noop\n\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req =\n    \
             ( {{ count = 0 }}, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model =\n    \
             ( model, Cmd.none )\n\n\
         view : Model -> Element Msg\n\
         view _model =\n    \
             Ui.column []\n        \
                 [ Ui.text \"marker\"\n        \
                 , Ui.image [] {{ src = Ui.imageData {{ mime = \"image/png\", base64 = \"AAAA\" }}, description = \"{description}\" }}\n        \
                 ]\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n    \
             Sub.none\n\n\
         main =\n    \
             Web.tea\n        \
                 {{ init = init, update = update, view = view, subscriptions = subscriptions\n        \
                 , routes = [], notFound = Noop\n        \
                 }}\n",
    )
}

/// A `Web.tea` whose view carries a direct `Ipe.Css` value literal reaching the
/// `CssSafety.safeValue` sanitizer — the one `Ipe.Css` value sink that lowers to
/// Rust. `safeValue "<value>"` is a direct literal, so under the flag it hoists
/// into the view's `LiteralTable` while the runtime `safe_value` wrapper is kept
/// (re-sanitize-on-read). Its sanitized result is rendered into a `data-css`
/// attribute so an HTTP read confirms the served CSS value. A marker text
/// confirms the app is up.
fn web_fixture_css(value: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Tea.Web.Cmd\n\
         import Ipe.Tea.Web.Sub\n\
         import Ipe.CssSafety exposing (safeValue)\n\
         import Ipe.Maybe as Maybe\n\n\
         type alias Model = {{ count : Int }}\n\n\
         type Msg = Noop\n\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req =\n    \
             ( {{ count = 0 }}, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model =\n    \
             ( model, Cmd.none )\n\n\
         view : Model -> Element Msg\n\
         view _model =\n    \
             Ui.column [ Ui.htmlAttribute \"data-css\" (Maybe.withDefault \"none\" (safeValue \"{value}\")) ]\n        \
                 [ Ui.text \"marker\" ]\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n    \
             Sub.none\n\n\
         main =\n    \
             Web.tea\n        \
                 {{ init = init, update = update, view = view, subscriptions = subscriptions\n        \
                 , routes = [], notFound = Noop\n        \
                 }}\n",
    )
}

/// A `Web.tea` whose `view` returns a fully-static `Ipe.Html` subtree (built
/// from the raw `Html.node` / `Html.text` / `Attributes.attribute` kernels, no
/// `Model` read / control flow / handler), wrapped by `Ui.html`. Under the flag
/// the WHOLE subtree hoists as ONE serialized template into the per-view
/// `LiteralTable`, so a STRUCTURAL edit inside it — adding / editing a static
/// element or text — changes only that one slot's value and hot-swaps with no
/// recompile. `text` is the first paragraph's text; `extra_child` is spliced
/// after it (empty, or a full `<p>` element) so a test can add a static child.
fn web_fixture_static_html(text: &str, extra_child: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Html as H\n\
         import Ipe.Html.Attributes as A\n\
         import Ipe.Tea.Web.Cmd\n\
         import Ipe.Tea.Web.Sub\n\n\
         type alias Model = {{ count : Int }}\n\n\
         type Msg = Noop\n\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req =\n    \
             ( {{ count = 0 }}, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model =\n    \
             ( model, Cmd.none )\n\n\
         view : Model -> Element Msg\n\
         view _model =\n    \
             Ui.html\n        \
                 (H.node \"div\" [ A.attribute \"class\" \"marker\" ]\n            \
                     [ H.node \"p\" [] [ H.text \"{text}\" ]{extra_child} ])\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n    \
             Sub.none\n\n\
         main =\n    \
             Web.tea\n        \
                 {{ init = init, update = update, view = view, subscriptions = subscriptions\n        \
                 , routes = [], notFound = Noop\n        \
                 }}\n",
    )
}

/// A `Web.tea` whose view is a fully-static `Ipe.Ui` subtree built from the
/// `Ui.node` element kernel over inert `Ui.padding` / `Ui.spacing` attributes and
/// static `Ui.text` children — no `Model` read, no handler. Under the flag the
/// WHOLE subtree hoists as ONE serialized `UiTemplate` into the per-view
/// `LiteralTable`, so a STRUCTURAL edit (static text, an added static child) is a
/// single-slot change the classifier routes to `AppearanceOnly` — a zero-compile
/// hot-swap. This is the `Ipe.Ui` analogue of `web_fixture_static_html`; the
/// `Ui.node` element kernel is what the `Ui.el` / `Ui.column` wrappers lower to.
fn web_fixture_static_ui(text: &str, extra_child: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Tea.Web.Cmd\n\
         import Ipe.Tea.Web.Sub\n\n\
         type alias Model = {{ count : Int }}\n\n\
         type Msg = Noop\n\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req =\n    \
             ( {{ count = 0 }}, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model =\n    \
             ( model, Cmd.none )\n\n\
         view : Model -> Element Msg\n\
         view _model =\n    \
             Ui.node Ui.descMain [ Ui.padding 8, Ui.spacing 4 ]\n        \
                 [ Ui.node Ui.descContentInfo [ Ui.htmlAttribute \"class\" \"marker\" ] [ Ui.text \"{text}\" ]{extra_child} ]\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n    \
             Sub.none\n\n\
         main =\n    \
             Web.tea\n        \
                 {{ init = init, update = update, view = view, subscriptions = subscriptions\n        \
                 , routes = [], notFound = Noop\n        \
                 }}\n",
    )
}

/// A `Web.tea` whose view carries a `Ui.gridTracks cols rows` — two direct raw
/// CSS String literals (`grid-template-columns` / `-rows` values) that each hoist
/// into the per-view `LiteralTable` under the flag. The raw-CSS value sink
/// (`SafeCssValue` on each axis) is a pure function of the String, so a hoisted
/// slot read neutralises identically to the baked literal. A marker text confirms
/// the app is up.
fn web_fixture_grid(cols: &str, rows: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Tea.Web.Cmd\n\
         import Ipe.Tea.Web.Sub\n\
         import Ipe.String\n\n\
         type alias Model = {{ count : Int }}\n\n\
         type Msg = Noop\n\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req =\n    \
             ( {{ count = 0 }}, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model =\n    \
             ( model, Cmd.none )\n\n\
         view : Model -> Element Msg\n\
         view _model =\n    \
             Ui.column [ Ui.gridTracks \"{cols}\" \"{rows}\" ]\n        \
                 [ Ui.text \"marker\" ]\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n    \
             Sub.none\n\n\
         main =\n    \
             Web.tea\n        \
                 {{ init = init, update = update, view = view, subscriptions = subscriptions\n        \
                 , routes = [], notFound = Noop\n        \
                 }}\n",
    )
}

/// E2E budget for an appearance hot-swap (no `cargo` build, no process restart).
///
/// Under normal conditions the pipeline completes in under a second: FS debounce
/// quiesces (≤120 ms + 600 ms hard cap), the classifier runs in-process, the
/// `/_ipe/hot-appearance` POST reaches the child, and the `AppearanceHotSwapped`
/// event fires. Under CI CPU starvation (sccache down, many shards competing for
/// the runner) every step can slow substantially. 90 s is the ceiling: generous
/// enough to survive heavy contention (matched to the warm-rebuild budget used in
/// `watch_integration.rs`) while proving no cargo build ran — any rebuild would
/// fire `Restarted` and the test catches that separately.
const E2E_HOT_SWAP_BUDGET: Duration = Duration::from_secs(90);

fn fresh_dirs(tag: &str) -> Result<(PathBuf, PathBuf), BoxError> {
    let base = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "watch_hot_{tag}_{}_{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    let ipe_dir = base.join("ipe");
    let out_dir = base.join("out");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&ipe_dir)
        .map_err(|e| -> BoxError { format!("mkdir {}: {e}", ipe_dir.display()).into() })?;
    Ok((ipe_dir, out_dir))
}

fn write_main(ipe_dir: &Path, source: &str) -> Result<(), BoxError> {
    std::fs::write(ipe_dir.join("Main.ipe"), source)
        .map_err(|e| -> BoxError { format!("write Main.ipe: {e}").into() })
}

fn http_get_body(port: u16) -> Option<String> {
    // Retry a few times with a short pause: a freshly hot-swapped server may
    // accept the connection but return a partial body before the SSR finishes.
    // We only give up on a genuine read failure (not a slow/partial read).
    for attempt in 0..4u8 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(150));
        }
        let Ok(mut stream) = TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().ok()?,
            Duration::from_millis(300),
        ) else {
            continue;
        };
        if stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .is_err()
        {
            continue;
        }
        if stream
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .is_err()
        {
            continue;
        }
        let mut buf = Vec::new();
        // Return only a complete body; an empty body or a read error means the
        // server is not ready yet — fall through and retry on the next attempt.
        if stream.read_to_end(&mut buf).is_ok() && !buf.is_empty() {
            return Some(String::from_utf8_lossy(&buf).into_owned());
        }
    }
    None
}

fn wait_for_serving(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if http_get_body(port).is_some_and(|b| b.contains("marker")) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Poll `cond` until it holds or `timeout` elapses; `true` if it held.
fn wait_for(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[derive(Clone, Default)]
struct EventSink(Arc<Mutex<Vec<WatchEvent>>>);

impl EventSink {
    fn push(&self, event: WatchEvent) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event);
    }

    fn count_hot_swapped(&self) -> usize {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|e| matches!(e, WatchEvent::AppearanceHotSwapped { .. }))
            .count()
    }

    fn count_restarted(&self) -> usize {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|e| matches!(e, WatchEvent::Restarted { .. }))
            .count()
    }

    fn as_callback(&self) -> Arc<dyn Fn(WatchEvent) + Send + Sync> {
        let this = self.clone();
        Arc::new(move |e| this.push(e))
    }
}

fn start_watch(
    entry: &Path,
    out_dir: &Path,
    port: u16,
    sink: &EventSink,
) -> Result<
    (
        std::thread::JoinHandle<Result<(), ipe::CliError>>,
        WatchHandle,
    ),
    BoxError,
> {
    let runtime_dir = ipe::resolve_runtime()
        .map_err(|e| -> BoxError { format!("runtime dir must resolve: {e}").into() })?;
    let mut opts = WatchOptions::new(entry.to_path_buf(), out_dir.to_path_buf(), runtime_dir);
    opts.port = port;
    opts.debounce = ipe_watch::DebounceConfig {
        quiescence: Duration::from_millis(120),
        hard_cap: Duration::from_millis(600),
    };
    opts.on_event = Some(sink.as_callback());
    // Forward CI's warm shared target (exported ONLY as IPE_ORACLE_SHARED_TARGET)
    // into the watch rebuild so it links against a pre-compiled dep tree; absent,
    // the watch stays isolated exactly as before.
    opts.target_dir = e2e_support::child_shared_target_from_env().map(PathBuf::from);
    Ok(ipe::watch::spawn(opts))
}

fn stop_and_join(
    handle: &WatchHandle,
    join: std::thread::JoinHandle<Result<(), ipe::CliError>>,
) -> Result<(), BoxError> {
    handle.stop();
    join.join().map_or_else(
        |_| Err("watch thread panicked".into()),
        |result| result.map_err(|e| -> BoxError { e.to_string().into() }),
    )
}

/// The live server PID, matched by the exact `IPE_WEB_PORT=<port>` env pair the
/// supervised child carries. Same `/proc`-environ technique as
/// `watch_integration.rs`, so it does not depend on the emitted binary's path.
#[cfg(target_os = "linux")]
fn server_pid(port: u16) -> Option<u32> {
    let needle = format!("IPE_WEB_PORT={port}\0");
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(environ) = std::fs::read(entry.path().join("environ")) else {
            continue;
        };
        if String::from_utf8_lossy(&environ).contains(&needle) {
            return Some(pid);
        }
    }
    None
}

#[test]
#[cfg(target_os = "linux")]
fn style_edit_hot_swaps_without_rebuild_and_structural_edit_recompiles() -> Result<(), BoxError> {
    if std::env::var("IPE_E2E").is_err() {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    // Enable the flag for THIS watch process (and, by inheritance, the spawned
    // child, whose `/_ipe/hot-appearance` route needs it too). nextest isolates
    // each test in its own process, so this does not leak to other tests. The set
    // happens before any watch thread is spawned, so no other thread races this
    // var — the only precondition `set_var` needs.
    // SAFETY: single-threaded at this point (no watch thread spawned yet), and no
    // other code in this isolated test process reads or writes this var.
    unsafe {
        std::env::set_var("IPE_WATCH_HOT_APPEARANCE", "1");
    }

    let (ipe_dir, out_dir) = fresh_dirs("swap")?;
    write_main(&ipe_dir, &web_fixture(12, ""))?;

    let sink = EventSink::default();
    let port = 19171;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink)?;

    assert!(
        wait_for_serving(port, Duration::from_mins(4)),
        "initial cold build must serve the web app"
    );
    // The app answers HTTP the instant its readiness probe passes, which is
    // slightly BEFORE the loop emits the cold build's `Restarted` event. Wait for
    // that event to settle so the restart count is stable before the edit — else
    // the baseline races the generation-1 restart and looks like a spurious +1.
    assert!(
        wait_for(Duration::from_secs(10), || sink.count_restarted() >= 1),
        "the cold build must record its initial Restarted event"
    );
    let pid_before = server_pid(port).ok_or("server PID must be discoverable after cold build")?;
    // A hot-swap must add NO further restart. (`RebuildStarted` fires at the START
    // of every edit cycle, hot-swap included, so it is NOT the no-cargo signal —
    // `Restarted` is.)
    let restarts_before = sink.count_restarted();

    // ── Style-value edit: padding 12 -> 16. Appearance-only ⇒ hot-swap. ──
    write_main(&ipe_dir, &web_fixture(16, ""))?;
    let swap_start = Instant::now();
    let hot_swapped = wait_for(E2E_HOT_SWAP_BUDGET, || sink.count_hot_swapped() > 0);
    let swap_elapsed = swap_start.elapsed();
    assert!(
        hot_swapped,
        "a padding-value edit must be hot-swapped (AppearanceHotSwapped), not recompiled"
    );
    // Give any (erroneous) rebuild a generous window to have started a cargo
    // build + restart, so "no restart" is a real observation, not a race win.
    std::thread::sleep(Duration::from_secs(2));
    // No restart happened — the running binary was never swapped (⇒ no cargo).
    assert_eq!(
        sink.count_restarted(),
        restarts_before,
        "a hot-swapped style edit must NOT restart the app (no cargo rebuild)"
    );
    // The server process is unchanged — the app was never restarted.
    let pid_after_style = server_pid(port).ok_or("server PID must still be discoverable")?;
    assert_eq!(
        pid_before, pid_after_style,
        "a hot-swapped style edit must leave the SAME server process running"
    );
    // The app still answers (proving the swap did not crash the running server).
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("marker")),
        "the app must keep serving after a hot-swap"
    );
    eprintln!(
        "[measure] style padding 12->16 hot-swap round-trip (edit -> AppearanceHotSwapped): {} ms \
         (no cargo, no restart)",
        swap_elapsed.as_millis()
    );

    // ── Structural edit: add an element. The view uses the `Ui.column` wrapper
    // (a compiled stdlib function, not the `Ui.node` element kernel), so it is NOT
    // whole-subtree templated; an added element is a `Logic` change ⇒ recompile +
    // restart. (Whole-subtree Ui templating fires on the raw `Ui.node` kernel —
    // see `static_ui_subtree_structural_edit_hot_swaps_without_rebuild`.) ──
    let restarts_before_struct = sink.count_restarted();
    write_main(&ipe_dir, &web_fixture(16, "\n        , Ui.text \"added\""))?;
    // A recompile swaps the running binary — wait for a NEW PID serving the added
    // element, proving both the recompile AND the restart onto a new process.
    let restarted = wait_for(Duration::from_mins(2), || {
        server_pid(port).is_some_and(|pid| pid != pid_before)
            && http_get_body(port).is_some_and(|b| b.contains("added"))
    });
    assert!(
        restarted,
        "a structural edit (added element) must recompile and restart onto a new binary"
    );
    // The `Restarted` event lands just after the new binary answers HTTP; wait for
    // it to settle before asserting the count grew (same readiness-vs-event race).
    assert!(
        wait_for(Duration::from_secs(10), || {
            sink.count_restarted() > restarts_before_struct
        }),
        "a structural edit must recompile and restart (a new Restarted event)"
    );

    stop_and_join(&handle, join)
}

/// The widened surface (Step 5): an **attribute-value** edit and a **text-value**
/// edit each hot-swap without a rebuild, exactly like the style-value path, while
/// a structural add still recompiles. Records both round-trips (Step 6 preview).
#[test]
#[cfg(target_os = "linux")]
// E2E harness: three sequential edit round-trips (attribute, text, structural) in
// one live watch session — the length is the scenario, not incidental complexity.
#[allow(clippy::too_many_lines)]
fn attribute_and_text_edits_hot_swap_without_rebuild() -> Result<(), BoxError> {
    if std::env::var("IPE_E2E").is_err() {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    // SAFETY: single-threaded here (no watch thread spawned yet); nextest isolates
    // this process, so the var neither races nor leaks.
    unsafe {
        std::env::set_var("IPE_WATCH_HOT_APPEARANCE", "1");
    }

    let (ipe_dir, out_dir) = fresh_dirs("attrtext")?;
    write_main(&ipe_dir, &web_fixture_attr_text("card", "Hello"))?;

    let sink = EventSink::default();
    let port = 19172;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink)?;

    assert!(
        wait_for_serving(port, Duration::from_mins(4)),
        "initial cold build must serve the web app"
    );
    assert!(
        wait_for(Duration::from_secs(10), || sink.count_restarted() >= 1),
        "the cold build must record its initial Restarted event"
    );
    let pid_before = server_pid(port).ok_or("server PID must be discoverable after cold build")?;

    // ── Attribute-value edit: name "card" -> "panel". Appearance-only. ──
    let restarts_before_attr = sink.count_restarted();
    let hot_before_attr = sink.count_hot_swapped();
    write_main(&ipe_dir, &web_fixture_attr_text("panel", "Hello"))?;
    let attr_start = Instant::now();
    let attr_swapped = wait_for(E2E_HOT_SWAP_BUDGET, || {
        sink.count_hot_swapped() > hot_before_attr
    });
    let attr_elapsed = attr_start.elapsed();
    assert!(
        attr_swapped,
        "an attribute-value edit must be hot-swapped, not recompiled"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        sink.count_restarted(),
        restarts_before_attr,
        "a hot-swapped attribute edit must NOT restart the app"
    );
    assert_eq!(
        server_pid(port),
        Some(pid_before),
        "a hot-swapped attribute edit must leave the SAME server process running"
    );
    eprintln!(
        "[measure] attribute name card->panel hot-swap round-trip: {} ms (no cargo, no restart)",
        attr_elapsed.as_millis()
    );

    // ── Text-value edit: text "Hello" -> "Goodbye". Appearance-only. ──
    let restarts_before_text = sink.count_restarted();
    let hot_before_text = sink.count_hot_swapped();
    write_main(&ipe_dir, &web_fixture_attr_text("panel", "Goodbye"))?;
    let text_start = Instant::now();
    let text_swapped = wait_for(E2E_HOT_SWAP_BUDGET, || {
        sink.count_hot_swapped() > hot_before_text
    });
    let text_elapsed = text_start.elapsed();
    assert!(
        text_swapped,
        "a text-value edit must be hot-swapped, not recompiled"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        sink.count_restarted(),
        restarts_before_text,
        "a hot-swapped text edit must NOT restart the app"
    );
    assert_eq!(
        server_pid(port),
        Some(pid_before),
        "a hot-swapped text edit must leave the SAME server process running"
    );
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("marker")),
        "the app must keep serving after the text hot-swap"
    );
    eprintln!(
        "[measure] text Hello->Goodbye hot-swap round-trip: {} ms (no cargo, no restart)",
        text_elapsed.as_millis()
    );

    // ── Structural edit: add a third text node. The view uses the `Ui.column`
    // wrapper (a compiled stdlib function, not the `Ui.node` element kernel), so it
    // is NOT whole-subtree templated; an added text node is a `Logic` change ⇒
    // recompile + restart. ──
    let restarts_before_struct = sink.count_restarted();
    write_main(
        &ipe_dir,
        &web_fixture_attr_text("panel", "Goodbye").replace(
            "Ui.text \"Goodbye\" ]",
            "Ui.text \"Goodbye\", Ui.text \"added\" ]",
        ),
    )?;
    let restarted = wait_for(Duration::from_mins(2), || {
        server_pid(port).is_some_and(|pid| pid != pid_before)
            && http_get_body(port).is_some_and(|b| b.contains("added"))
    });
    assert!(
        restarted,
        "a structural edit (added text node) must recompile and restart onto a new binary"
    );
    assert!(
        wait_for(Duration::from_secs(10), || {
            sink.count_restarted() > restarts_before_struct
        }),
        "a structural edit must recompile and restart (a new Restarted event)"
    );

    stop_and_join(&handle, join)
}

/// SEAL for the direct numeric appearance surface: a `Font.weight : Int` value
/// edit hot-swaps without a rebuild — the same no-cargo, no-restart outcome the
/// other appearance surfaces produce — while a structural add still recompiles.
/// Proves a typed `Int` scalar read back through `parse::<i64>().unwrap_or(...)`
/// reaches the running app through the identical hot-swap channel.
#[test]
#[cfg(target_os = "linux")]
fn numeric_weight_edit_hot_swaps_without_rebuild() -> Result<(), BoxError> {
    if std::env::var("IPE_E2E").is_err() {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    // SAFETY: single-threaded here (no watch thread spawned yet); nextest isolates
    // this process, so the var neither races nor leaks.
    unsafe {
        std::env::set_var("IPE_WATCH_HOT_APPEARANCE", "1");
    }

    let (ipe_dir, out_dir) = fresh_dirs("weight")?;
    write_main(&ipe_dir, &web_fixture_weight(400, ""))?;

    let sink = EventSink::default();
    let port = 19175;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink)?;

    assert!(
        wait_for_serving(port, Duration::from_mins(4)),
        "the flag-on cold build of a Font.weight view must serve (hoisted i64 read compiles)"
    );
    assert!(
        wait_for(Duration::from_secs(10), || sink.count_restarted() >= 1),
        "the cold build must record its initial Restarted event"
    );
    let pid_before = server_pid(port).ok_or("server PID must be discoverable after cold build")?;
    let restarts_before = sink.count_restarted();

    // ── Numeric edit: weight 400 -> 700. Appearance-only ⇒ hot-swap, no rebuild. ──
    write_main(&ipe_dir, &web_fixture_weight(700, ""))?;
    let swap_start = Instant::now();
    let hot_swapped = wait_for(E2E_HOT_SWAP_BUDGET, || sink.count_hot_swapped() > 0);
    assert!(
        hot_swapped,
        "a Font.weight value edit must be hot-swapped (AppearanceHotSwapped), not recompiled"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        sink.count_restarted(),
        restarts_before,
        "a hot-swapped numeric edit must NOT restart the app (no cargo rebuild)"
    );
    assert_eq!(
        server_pid(port),
        Some(pid_before),
        "a hot-swapped numeric edit must leave the SAME server process running"
    );
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("marker")),
        "the app must keep serving after the numeric hot-swap"
    );
    eprintln!(
        "[measure] Font.weight 400->700 hot-swap round-trip: {} ms (no cargo, no restart)",
        swap_start.elapsed().as_millis()
    );

    // ── Structural edit: add an element. The view uses the `Ui.column` wrapper
    // (a compiled stdlib function, not the `Ui.node` element kernel), so it is NOT
    // whole-subtree templated; an added element is a `Logic` change ⇒ recompile +
    // restart. ──
    let restarts_before_struct = sink.count_restarted();
    write_main(
        &ipe_dir,
        &web_fixture_weight(700, "\n        , Ui.text \"added\""),
    )?;
    let restarted = wait_for(Duration::from_mins(2), || {
        server_pid(port).is_some_and(|pid| pid != pid_before)
            && http_get_body(port).is_some_and(|b| b.contains("added"))
    });
    assert!(
        restarted,
        "a structural edit (added element) must recompile and restart onto a new binary"
    );
    assert!(
        wait_for(Duration::from_secs(10), || {
            sink.count_restarted() > restarts_before_struct
        }),
        "a structural edit must recompile and restart (a new Restarted event)"
    );

    stop_and_join(&handle, join)
}

/// SEAL for the Phase-2 const-fold appearance slice: a web view carrying an
/// animation built from a fully literal `Ipe.Ui.Animation` pipeline cold-builds
/// and serves under the flag (proving the folded `ui_animate_raw_(__ipe_lit
/// .get(N).to_string(), …)` emit cargo-compiles), an animation `duration` edit
/// hot-swaps without a rebuild — the const-fold reduces the whole pipeline to a
/// direct shorthand-tail string literal that hoists into the per-view
/// `LiteralTable`, so a `duration` edit changes only a slot — while a structural
/// edit recompiles. The folded literal flows through the SAME `build_anim` sink
/// (`sink_safe_keyframes_body` / `SafeCssValue` / `sanitise_animation_name`) as
/// an unfolded one, so the hoisted read is neutralised identically to the baked
/// value (dev == prod, no sink bypass).
#[test]
#[cfg(target_os = "linux")]
fn animation_duration_edit_hot_swaps_without_rebuild() -> Result<(), BoxError> {
    if std::env::var("IPE_E2E").is_err() {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    // SAFETY: single-threaded here (no watch thread spawned yet); nextest isolates
    // this process, so the var neither races nor leaks.
    unsafe {
        std::env::set_var("IPE_WATCH_HOT_APPEARANCE", "1");
    }

    let (ipe_dir, out_dir) = fresh_dirs("animation")?;
    write_main(&ipe_dir, &web_fixture_animation(300, ""))?;

    let sink = EventSink::default();
    let port = 19180;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink)?;

    assert!(
        wait_for_serving(port, Duration::from_mins(4)),
        "the flag-on cold build of a folded Animation view must serve (hoisted \
         ui_animate_raw_ literal args compile)"
    );
    assert!(
        wait_for(Duration::from_secs(10), || sink.count_restarted() >= 1),
        "the cold build must record its initial Restarted event"
    );
    let pid_before = server_pid(port).ok_or("server PID must be discoverable after cold build")?;
    let restarts_before = sink.count_restarted();

    // ── Animation edit: duration 300 -> 600. The const-fold re-reduces the
    //    pipeline to a NEW shorthand-tail literal (`600ms …`); the difference is
    //    confined to a hoisted LiteralTable slot ⇒ appearance-only hot-swap. ──
    write_main(&ipe_dir, &web_fixture_animation(600, ""))?;
    let swap_start = Instant::now();
    let hot_swapped = wait_for(E2E_HOT_SWAP_BUDGET, || sink.count_hot_swapped() > 0);
    assert!(
        hot_swapped,
        "a folded animation `duration` edit must be hot-swapped (AppearanceHotSwapped), \
         not recompiled"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        sink.count_restarted(),
        restarts_before,
        "a hot-swapped animation edit must NOT restart the app (no cargo rebuild)"
    );
    assert_eq!(
        server_pid(port),
        Some(pid_before),
        "a hot-swapped animation edit must leave the SAME server process running"
    );
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("marker")),
        "the app must keep serving after the animation hot-swap"
    );
    eprintln!(
        "[measure] Animation duration 300->600 hot-swap round-trip: {} ms (no cargo, no restart)",
        swap_start.elapsed().as_millis()
    );

    // ── Structural edit: add an element. Logic ⇒ recompile + restart. ──
    let restarts_before_struct = sink.count_restarted();
    write_main(
        &ipe_dir,
        &web_fixture_animation(600, "\n        , Ui.text \"added\""),
    )?;
    let restarted = wait_for(Duration::from_mins(2), || {
        server_pid(port).is_some_and(|pid| pid != pid_before)
            && http_get_body(port).is_some_and(|b| b.contains("added"))
    });
    assert!(
        restarted,
        "a structural edit (added element) must recompile and restart onto a new binary"
    );
    assert!(
        wait_for(Duration::from_secs(10), || {
            sink.count_restarted() > restarts_before_struct
        }),
        "a structural edit must recompile and restart (a new Restarted event)"
    );

    stop_and_join(&handle, join)
}

/// SEAL for the raw-CSS appearance slice: a web view carrying a direct
/// `Ui.gridTracks cols rows` cold-builds and serves under the flag (proving the
/// hoisted `ui_grid_tracks_raw_(__ipe_lit.get(N).to_string(), …)` emit
/// cargo-compiles), a raw-CSS value edit hot-swaps without a rebuild — the same
/// no-cargo, no-restart outcome the other appearance surfaces produce — while a
/// structural edit recompiles. The raw-CSS value sink (`SafeCssValue`) is a pure
/// function of the String, so the hoisted read is neutralised identically to the
/// baked literal (dev == prod).
#[test]
#[cfg(target_os = "linux")]
fn grid_tracks_edit_hot_swaps_without_rebuild() -> Result<(), BoxError> {
    if std::env::var("IPE_E2E").is_err() {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    // SAFETY: single-threaded here (no watch thread spawned yet); nextest isolates
    // this process, so the var neither races nor leaks.
    unsafe {
        std::env::set_var("IPE_WATCH_HOT_APPEARANCE", "1");
    }

    let (ipe_dir, out_dir) = fresh_dirs("grid")?;
    write_main(&ipe_dir, &web_fixture_grid("1fr 1fr", "auto"))?;

    let sink = EventSink::default();
    let port = 19176;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink)?;

    assert!(
        wait_for_serving(port, Duration::from_mins(4)),
        "the flag-on cold build of a raw-CSS gridTracks view must serve (hoisted \
         ui_grid_tracks_raw_ compiles)"
    );
    assert!(
        wait_for(Duration::from_secs(10), || sink.count_restarted() >= 1),
        "the cold build must record its initial Restarted event"
    );
    let pid_before = server_pid(port).ok_or("server PID must be discoverable after cold build")?;
    let restarts_before = sink.count_restarted();

    // ── Raw-CSS value edit: cols "1fr 1fr" -> "2fr 1fr". Appearance-only. ──
    write_main(&ipe_dir, &web_fixture_grid("2fr 1fr", "auto"))?;
    let swap_start = Instant::now();
    let hot_swapped = wait_for(E2E_HOT_SWAP_BUDGET, || sink.count_hot_swapped() > 0);
    assert!(
        hot_swapped,
        "a raw-CSS gridTracks value edit must be hot-swapped (AppearanceHotSwapped), \
         not recompiled"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        sink.count_restarted(),
        restarts_before,
        "a hot-swapped raw-CSS value edit must NOT restart the app (no cargo rebuild)"
    );
    assert_eq!(
        server_pid(port),
        Some(pid_before),
        "a hot-swapped raw-CSS value edit must leave the SAME server process running"
    );
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("marker")),
        "the app must keep serving after the raw-CSS hot-swap"
    );
    eprintln!(
        "[measure] gridTracks cols 1fr 1fr->2fr 1fr hot-swap round-trip: {} ms \
         (no cargo, no restart)",
        swap_start.elapsed().as_millis()
    );

    // ── Structural edit: add an element. Logic ⇒ recompile + restart. ──
    let restarts_before_struct = sink.count_restarted();
    write_main(
        &ipe_dir,
        &web_fixture_grid("2fr 1fr", "auto").replace(
            "Ui.text \"marker\" ]",
            "Ui.text \"marker\", Ui.text \"added\" ]",
        ),
    )?;
    let restarted = wait_for(Duration::from_mins(2), || {
        server_pid(port).is_some_and(|pid| pid != pid_before)
            && http_get_body(port).is_some_and(|b| b.contains("added"))
    });
    assert!(
        restarted,
        "a structural edit (added element) must recompile and restart onto a new binary"
    );
    assert!(
        wait_for(Duration::from_secs(10), || {
            sink.count_restarted() > restarts_before_struct
        }),
        "a structural edit must recompile and restart (a new Restarted event)"
    );

    stop_and_join(&handle, join)
}

/// SEAL for the record-native `Ui.image` appearance surface: an alt-text
/// (`description`) edit on a `Ui.image { src, description }` hot-swaps without a
/// rebuild — the same no-cargo, no-restart outcome the positional appearance
/// surfaces produce — while a structural add still recompiles. Proves the
/// record-path hoist reaches the running app through the identical channel.
#[test]
#[cfg(target_os = "linux")]
fn image_alt_edit_hot_swaps_without_rebuild() -> Result<(), BoxError> {
    if std::env::var("IPE_E2E").is_err() {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    // SAFETY: single-threaded here (no watch thread spawned yet); nextest isolates
    // this process, so the var neither races nor leaks.
    unsafe {
        std::env::set_var("IPE_WATCH_HOT_APPEARANCE", "1");
    }

    let (ipe_dir, out_dir) = fresh_dirs("image")?;
    write_main(&ipe_dir, &web_fixture_image("a cat"))?;

    let sink = EventSink::default();
    let port = 19173;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink)?;

    assert!(
        wait_for_serving(port, Duration::from_mins(4)),
        "initial cold build must serve the web app with a Ui.image"
    );
    assert!(
        wait_for(Duration::from_secs(10), || sink.count_restarted() >= 1),
        "the cold build must record its initial Restarted event"
    );
    let pid_before = server_pid(port).ok_or("server PID must be discoverable after cold build")?;

    // ── Alt-text edit: description "a cat" -> "a dog". Appearance-only. ──
    let restarts_before_alt = sink.count_restarted();
    let hot_before_alt = sink.count_hot_swapped();
    write_main(&ipe_dir, &web_fixture_image("a dog"))?;
    let alt_start = Instant::now();
    let alt_swapped = wait_for(E2E_HOT_SWAP_BUDGET, || {
        sink.count_hot_swapped() > hot_before_alt
    });
    let alt_elapsed = alt_start.elapsed();
    assert!(
        alt_swapped,
        "an image alt-text edit must be hot-swapped, not recompiled"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        sink.count_restarted(),
        restarts_before_alt,
        "a hot-swapped image alt edit must NOT restart the app"
    );
    assert_eq!(
        server_pid(port),
        Some(pid_before),
        "a hot-swapped image alt edit must leave the SAME server process running"
    );
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("marker")),
        "the app must keep serving after the image hot-swap"
    );
    eprintln!(
        "[measure] image alt a cat->a dog hot-swap round-trip: {} ms (no cargo, no restart)",
        alt_elapsed.as_millis()
    );

    // ── Structural edit: add a text node. Logic ⇒ recompile + restart. ──
    let restarts_before_struct = sink.count_restarted();
    write_main(
        &ipe_dir,
        &web_fixture_image("a dog").replace(
            "Ui.text \"marker\"\n        ,",
            "Ui.text \"marker\", Ui.text \"added\"\n        ,",
        ),
    )?;
    let restarted = wait_for(Duration::from_mins(2), || {
        server_pid(port).is_some_and(|pid| pid != pid_before)
            && http_get_body(port).is_some_and(|b| b.contains("added"))
    });
    assert!(
        restarted,
        "a structural edit (added text node) must recompile and restart onto a new binary"
    );
    assert!(
        wait_for(Duration::from_secs(10), || {
            sink.count_restarted() > restarts_before_struct
        }),
        "a structural edit must recompile and restart (a new Restarted event)"
    );

    stop_and_join(&handle, join)
}

/// SEAL for the `Ipe.Css` value slice: a web view carrying a direct
/// `CssSafety.safeValue` literal cold-builds and serves under the flag (proving
/// the hoisted `safe_value(__ipe_lit.get(N))` emit cargo-compiles), the served
/// sanitized value is byte-identical to the flag-off form (dev == prod), and a
/// css-value edit hot-swaps without a rebuild while a structural edit recompiles.
#[test]
#[cfg(target_os = "linux")]
fn css_value_edit_hot_swaps_and_is_byte_identical() -> Result<(), BoxError> {
    if std::env::var("IPE_E2E").is_err() {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    // SAFETY: single-threaded at this point (no watch thread spawned yet), and no
    // other code in this isolated test process reads or writes this var.
    unsafe {
        std::env::set_var("IPE_WATCH_HOT_APPEARANCE", "1");
    }

    let (ipe_dir, out_dir) = fresh_dirs("css")?;
    write_main(&ipe_dir, &web_fixture_css("16px"))?;

    let sink = EventSink::default();
    let port = 19174;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink)?;

    assert!(
        wait_for_serving(port, Duration::from_mins(4)),
        "the flag-on cold build of a Css-value view must serve (hoisted safe_value compiles)"
    );
    assert!(
        wait_for(Duration::from_secs(10), || sink.count_restarted() >= 1),
        "the cold build must record its initial Restarted event"
    );
    // dev == prod: the served sanitized value is exactly the source literal (the
    // sanitizer keeps benign bytes), identical to what a flag-off build renders.
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("data-css=\"16px\"")),
        "the served CSS value must be the sanitized source literal (byte-identical)"
    );
    let pid_before = server_pid(port).ok_or("server PID must be discoverable after cold build")?;
    let restarts_before = sink.count_restarted();

    // ── Css-value edit: 16px -> 24px. Appearance-only ⇒ hot-swap, no rebuild. ──
    write_main(&ipe_dir, &web_fixture_css("24px"))?;
    let swap_start = Instant::now();
    let hot_swapped = wait_for(E2E_HOT_SWAP_BUDGET, || sink.count_hot_swapped() > 0);
    assert!(
        hot_swapped,
        "a Css-value edit must be hot-swapped (AppearanceHotSwapped), not recompiled"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        sink.count_restarted(),
        restarts_before,
        "a hot-swapped Css-value edit must NOT restart the app (no cargo rebuild)"
    );
    assert_eq!(
        server_pid(port),
        Some(pid_before),
        "a hot-swapped Css-value edit must leave the SAME server process running"
    );
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("marker")),
        "the app must keep serving after the Css-value hot-swap"
    );
    eprintln!(
        "[measure] Css value 16px->24px hot-swap round-trip: {} ms (no cargo, no restart)",
        swap_start.elapsed().as_millis()
    );

    // ── Structural edit: add an element. Logic ⇒ recompile + restart. ──
    let restarts_before_struct = sink.count_restarted();
    write_main(
        &ipe_dir,
        &web_fixture_css("24px").replace(
            "Ui.text \"marker\" ]",
            "Ui.text \"marker\", Ui.text \"added\" ]",
        ),
    )?;
    let restarted = wait_for(Duration::from_mins(2), || {
        server_pid(port).is_some_and(|pid| pid != pid_before)
            && http_get_body(port).is_some_and(|b| b.contains("added"))
    });
    assert!(
        restarted,
        "a structural edit (added element) must recompile and restart onto a new binary"
    );
    assert!(
        wait_for(Duration::from_secs(10), || {
            sink.count_restarted() > restarts_before_struct
        }),
        "a structural edit must recompile and restart (a new Restarted event)"
    );

    stop_and_join(&handle, join)
}

/// The headline structural-hot-swap proof: a fully-static `Ipe.Html` subtree is
/// hoisted whole as a serialized template, so editing the tree's STRUCTURE —
/// static text, and adding a fully-static child element — hot-swaps with no
/// recompile and no restart. This is the class that recompiled before this
/// feature (an added element is `Logic` for a non-templated view — see
/// `css_value_edit_…`'s structural arm); inside a templated subtree it is a
/// single-slot template-value edit the classifier routes to `AppearanceOnly`.
#[test]
#[cfg(target_os = "linux")]
// E2E harness: two sequential structural edits (static text, added static child)
// in one live watch session — the length is the scenario, not incidental.
#[allow(clippy::too_many_lines)]
fn static_html_subtree_structural_edit_hot_swaps_without_rebuild() -> Result<(), BoxError> {
    if std::env::var("IPE_E2E").is_err() {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    // SAFETY: single-threaded here (no watch thread spawned yet); nextest isolates
    // this process, so the var neither races nor leaks.
    unsafe {
        std::env::set_var("IPE_WATCH_HOT_APPEARANCE", "1");
    }

    let (ipe_dir, out_dir) = fresh_dirs("statichtml")?;
    write_main(&ipe_dir, &web_fixture_static_html("one", ""))?;

    let sink = EventSink::default();
    let port = 19178;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink)?;

    assert!(
        wait_for_serving(port, Duration::from_mins(4)),
        "the flag-on cold build of a static-Html-subtree view must serve"
    );
    assert!(
        wait_for(Duration::from_secs(10), || sink.count_restarted() >= 1),
        "the cold build must record its initial Restarted event"
    );
    // dev == prod: the served HTML is exactly what the direct (flag-off) inline
    // emit would render — the baked-default template materializes byte-identically.
    // (The live path injects an `ipe-id` on each element's OPEN tag, so match the
    // text + close tag, which survive that injection.)
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("one</p>")),
        "the templated static subtree must render its baked default (dev == prod)"
    );
    let pid_before = server_pid(port).ok_or("server PID must be discoverable after cold build")?;
    let restarts_before = sink.count_restarted();

    // Static-text edit inside the template: "one" -> "uno". Hot-swap.
    write_main(&ipe_dir, &web_fixture_static_html("uno", ""))?;
    let swap_start = Instant::now();
    assert!(
        wait_for(E2E_HOT_SWAP_BUDGET, || sink.count_hot_swapped() > 0),
        "a static-text edit inside a templated subtree must hot-swap, not recompile"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        sink.count_restarted(),
        restarts_before,
        "a hot-swapped static-text edit must NOT restart the app (no cargo rebuild)"
    );
    assert_eq!(
        server_pid(port),
        Some(pid_before),
        "a hot-swapped static-text edit must leave the SAME server process running"
    );
    eprintln!(
        "[measure] static-Html text one->uno hot-swap: {} ms (no cargo, no restart)",
        swap_start.elapsed().as_millis()
    );

    // STRUCTURAL edit: ADD a fully-static child <p>two</p>. Hot-swap.
    // Before this feature an added element recompiled; inside a templated subtree
    // it is one changed template slot => AppearanceOnly => zero-compile swap.
    let hot_before_add = sink.count_hot_swapped();
    write_main(
        &ipe_dir,
        &web_fixture_static_html("uno", ", H.node \"p\" [] [ H.text \"two\" ]"),
    )?;
    let add_start = Instant::now();
    assert!(
        wait_for(E2E_HOT_SWAP_BUDGET, || {
            sink.count_hot_swapped() > hot_before_add
        }),
        "adding a fully-static child element must hot-swap (structural template edit), not recompile"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        sink.count_restarted(),
        restarts_before,
        "adding a static child must NOT restart the app (no cargo rebuild)"
    );
    assert_eq!(
        server_pid(port),
        Some(pid_before),
        "adding a static child must leave the SAME server process running"
    );
    // The running server keeps serving after the structural hot-swap.
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("marker")),
        "the app must keep serving after the structural hot-swap"
    );
    eprintln!(
        "[measure] static-Html ADD child <p>two</p> hot-swap: {} ms (no cargo, no restart)",
        add_start.elapsed().as_millis()
    );

    stop_and_join(&handle, join)
}

/// The `Ipe.Ui` structural-hot-swap proof: a fully-static `Ipe.Ui` subtree is
/// hoisted whole as a serialized `UiTemplate`, so editing the tree's STRUCTURE —
/// static text, and adding a fully-static child — hot-swaps with no recompile
/// and no restart. Real apps write `Ipe.Ui`, not raw `Ipe.Html`, so this is the
/// biggest single coverage gain over the shipped `Ipe.Html` template. Off, the
/// same subtree emits inline byte-for-byte (dev == prod), asserted by the served
/// baked default matching the direct render.
#[test]
#[cfg(target_os = "linux")]
// E2E harness: two sequential structural edits (static text, added static child)
// in one live watch session — the length is the scenario, not incidental.
#[allow(clippy::too_many_lines)]
fn static_ui_subtree_structural_edit_hot_swaps_without_rebuild() -> Result<(), BoxError> {
    if std::env::var("IPE_E2E").is_err() {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    // SAFETY: single-threaded here (no watch thread spawned yet); nextest isolates
    // this process, so the var neither races nor leaks.
    unsafe {
        std::env::set_var("IPE_WATCH_HOT_APPEARANCE", "1");
    }

    let (ipe_dir, out_dir) = fresh_dirs("staticui")?;
    write_main(&ipe_dir, &web_fixture_static_ui("one", ""))?;

    let sink = EventSink::default();
    let port = 19179;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink)?;

    assert!(
        wait_for_serving(port, Duration::from_mins(4)),
        "the flag-on cold build of a static-Ui-subtree view must serve"
    );
    assert!(
        wait_for(Duration::from_secs(10), || sink.count_restarted() >= 1),
        "the cold build must record its initial Restarted event"
    );
    // dev == prod: the served HTML is exactly what the direct (flag-off) inline
    // emit renders — the baked-default `UiTemplate` materializes byte-identically
    // through the same `render_element` chain. The static text survives the live
    // `ipe-id` open-tag injection, so match on it.
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("one")),
        "the templated static Ui subtree must render its baked default (dev == prod)"
    );
    let pid_before = server_pid(port).ok_or("server PID must be discoverable after cold build")?;
    let restarts_before = sink.count_restarted();

    // Static-text edit inside the template: "one" -> "uno". Hot-swap.
    write_main(&ipe_dir, &web_fixture_static_ui("uno", ""))?;
    let swap_start = Instant::now();
    assert!(
        wait_for(E2E_HOT_SWAP_BUDGET, || sink.count_hot_swapped() > 0),
        "a static-text edit inside a templated Ui subtree must hot-swap, not recompile"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        sink.count_restarted(),
        restarts_before,
        "a hot-swapped static-text edit must NOT restart the app (no cargo rebuild)"
    );
    assert_eq!(
        server_pid(port),
        Some(pid_before),
        "a hot-swapped static-text edit must leave the SAME server process running"
    );
    eprintln!(
        "[measure] static-Ui text one->uno hot-swap: {} ms (no cargo, no restart)",
        swap_start.elapsed().as_millis()
    );

    // STRUCTURAL edit: ADD a fully-static child `Ui.text "two"`. Hot-swap.
    let hot_before_add = sink.count_hot_swapped();
    write_main(&ipe_dir, &web_fixture_static_ui("uno", ", Ui.text \"two\""))?;
    let add_start = Instant::now();
    assert!(
        wait_for(E2E_HOT_SWAP_BUDGET, || {
            sink.count_hot_swapped() > hot_before_add
        }),
        "adding a fully-static Ui child must hot-swap (structural template edit), not recompile"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        sink.count_restarted(),
        restarts_before,
        "adding a static Ui child must NOT restart the app (no cargo rebuild)"
    );
    assert_eq!(
        server_pid(port),
        Some(pid_before),
        "adding a static Ui child must leave the SAME server process running"
    );
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("two")),
        "the app must serve the added static child after the structural hot-swap"
    );
    eprintln!(
        "[measure] static-Ui ADD child Ui.text \"two\" hot-swap: {} ms (no cargo, no restart)",
        add_start.elapsed().as_millis()
    );

    stop_and_join(&handle, join)
}

/// A `Web.tea` whose view is built entirely with `Ipe.Ui` structural wrappers
/// (`Ui.column`, `Ui.row`) over literal attrs and static text, with no raw
/// `Ui.node` / `Ui.taggedNode` call at the call site. Under the
/// `IPE_WATCH_HOT_APPEARANCE` flag the compiler inlines each wrapper body and
/// hoists the whole tree as a `UiTemplate`, proving wrapper calls are transparent
/// to the template partition pass.
fn web_fixture_static_ui_wrappers(text: &str, extra_child: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Tea.Web.Cmd\n\
         import Ipe.Tea.Web.Sub\n\n\
         type alias Model = {{ count : Int }}\n\n\
         type Msg = Noop\n\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req =\n    \
             ( {{ count = 0 }}, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model =\n    \
             ( model, Cmd.none )\n\n\
         view : Model -> Element Msg\n\
         view _model =\n    \
             Ui.column [ Ui.padding 8, Ui.spacing 4 ]\n        \
                 [ Ui.row [ Ui.htmlAttribute \"class\" \"marker\" ] [ Ui.text \"{text}\"{extra_child} ] ]\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n    \
             Sub.none\n\n\
         main =\n    \
             Web.tea\n        \
                 {{ init = init, update = update, view = view, subscriptions = subscriptions\n        \
                 , routes = [], notFound = Noop\n        \
                 }}\n",
    )
}

/// Wrapper-transparent hot-swap SEAL: a fully-static `Ipe.Ui` subtree built
/// with `Ui.column`/`Ui.row` wrapper calls (not raw `Ui.node`) must templatize
/// identically to a raw-kernel subtree. Two structural edits — a static-text
/// change and adding a fully-static child — must each hot-swap without any
/// cargo rebuild or server restart.
#[test]
#[cfg(target_os = "linux")]
// E2E harness: two sequential structural edits in one live watch session —
// the length is the scenario, not incidental.
#[allow(clippy::too_many_lines)]
fn static_ui_subtree_wrapper_hot_swaps_without_rebuild() -> Result<(), BoxError> {
    if std::env::var("IPE_E2E").is_err() {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    // SAFETY: single-threaded here (no watch thread spawned yet); nextest isolates
    // this process, so the var neither races nor leaks.
    unsafe {
        std::env::set_var("IPE_WATCH_HOT_APPEARANCE", "1");
    }

    let (ipe_dir, out_dir) = fresh_dirs("staticuiwrap")?;
    write_main(&ipe_dir, &web_fixture_static_ui_wrappers("one", ""))?;

    let sink = EventSink::default();
    let port = 19181;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink)?;

    assert!(
        wait_for_serving(port, Duration::from_mins(4)),
        "the flag-on cold build of a wrapper-based static-Ui subtree must serve"
    );
    assert!(
        wait_for(Duration::from_secs(10), || sink.count_restarted() >= 1),
        "the cold build must record its initial Restarted event"
    );
    // dev == prod: wrapper call templatizes identically to a raw kernel call,
    // so the baked-default template materializes the static text byte-identically.
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("one")),
        "the wrapper-based templated subtree must render its baked default (dev == prod)"
    );
    let pid_before = server_pid(port).ok_or("server PID must be discoverable after cold build")?;
    let restarts_before = sink.count_restarted();

    // Static-text edit inside the template: "one" -> "uno". Hot-swap.
    write_main(&ipe_dir, &web_fixture_static_ui_wrappers("uno", ""))?;
    let swap_start = Instant::now();
    assert!(
        wait_for(E2E_HOT_SWAP_BUDGET, || sink.count_hot_swapped() > 0),
        "a static-text edit inside a wrapper-based templated subtree must hot-swap, not recompile"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        sink.count_restarted(),
        restarts_before,
        "a hot-swapped static-text edit must NOT restart the app (no cargo rebuild)"
    );
    assert_eq!(
        server_pid(port),
        Some(pid_before),
        "a hot-swapped static-text edit must leave the SAME server process running"
    );
    eprintln!(
        "[measure] wrapper-Ui text one->uno hot-swap: {} ms (no cargo, no restart)",
        swap_start.elapsed().as_millis()
    );

    // STRUCTURAL edit: ADD a fully-static child `Ui.text "two"`. Hot-swap.
    let hot_before_add = sink.count_hot_swapped();
    write_main(
        &ipe_dir,
        &web_fixture_static_ui_wrappers("uno", ", Ui.text \"two\""),
    )?;
    let add_start = Instant::now();
    assert!(
        wait_for(E2E_HOT_SWAP_BUDGET, || {
            sink.count_hot_swapped() > hot_before_add
        }),
        "adding a fully-static child to a wrapper subtree must hot-swap (structural template edit), not recompile"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        sink.count_restarted(),
        restarts_before,
        "adding a static child must NOT restart the app (no cargo rebuild)"
    );
    assert_eq!(
        server_pid(port),
        Some(pid_before),
        "adding a static child must leave the SAME server process running"
    );
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("two")),
        "the app must serve the added static child after the structural hot-swap"
    );
    eprintln!(
        "[measure] wrapper-Ui ADD child Ui.text \"two\" hot-swap: {} ms (no cargo, no restart)",
        add_start.elapsed().as_millis()
    );

    stop_and_join(&handle, join)
}

/// A `Web.tea` whose `view` is a MOSTLY-static `Ipe.Ui` subtree carrying a
/// `Model`-derived **value hole** (`Ui.text (String.fromInt model.count)`)
/// and a static sibling text. Under the flag the subtree partitions into a
/// hoisted template (the static skeleton + a `Hole` marker) plus the compiled
/// hole fill, so editing the static sibling's text changes ONLY the baked template
/// string — a structural hot-swap with no recompile, while the `{count}` hole
/// stays compiled.
fn web_fixture_value_hole(label: &str, extra_child: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Tea.Web.Cmd\n\
         import Ipe.Tea.Web.Sub\n\
         import Ipe.String as String\n\n\
         type alias Model = {{ count : Int }}\n\n\
         type Msg = Noop\n\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req =\n    \
             ( {{ count = 7 }}, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model =\n    \
             ( model, Cmd.none )\n\n\
         view : Model -> Element Msg\n\
         view model =\n    \
             Ui.column [ Ui.padding 8, Ui.spacing 4 ]\n        \
                 [ Ui.text \"marker\"\n        \
                 , Ui.text \"{label}\"\n        \
                 , Ui.text (String.fromInt model.count){extra_child}\n        \
                 ]\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n    \
             Sub.none\n\n\
         main =\n    \
             Web.tea\n        \
                 {{ init = init, update = update, view = view, subscriptions = subscriptions\n        \
                 , routes = [], notFound = Noop\n        \
                 }}\n",
    )
}

/// The value-hole hot-swap SEAL: a mostly-static view with a `{count}` value hole
/// hot-swaps a static-sibling edit with NO cargo build and NO restart, while the
/// model-derived hole still renders its compiled value. This proves increment 1
/// (value holes): the surrounding structure is a template, the leaf a hole.
#[test]
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_lines)]
fn value_hole_static_sibling_hot_swaps_without_rebuild() -> Result<(), BoxError> {
    if std::env::var("IPE_E2E").is_err() {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    // SAFETY: single-threaded here (no watch thread spawned yet); nextest isolates
    // this process, so the var neither races nor leaks.
    unsafe {
        std::env::set_var("IPE_WATCH_HOT_APPEARANCE", "1");
    }

    let (ipe_dir, out_dir) = fresh_dirs("valuehole")?;
    write_main(&ipe_dir, &web_fixture_value_hole("alpha", ""))?;

    let sink = EventSink::default();
    let port = 19187;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink)?;

    assert!(
        wait_for_serving(port, Duration::from_mins(4)),
        "the flag-on cold build of a value-hole view must serve"
    );
    assert!(
        wait_for(Duration::from_secs(10), || sink.count_restarted() >= 1),
        "the cold build must record its initial Restarted event"
    );
    // dev == prod: the static skeleton renders its baked default AND the compiled
    // hole renders the model value (`count = 7`).
    let body0 = http_get_body(port).ok_or("server must serve a body after cold build")?;
    assert!(
        body0.contains("alpha"),
        "the static skeleton must render its baked default sibling"
    );
    assert!(
        body0.contains('7'),
        "the model-derived value hole must render the compiled count (7)"
    );
    let pid_before = server_pid(port).ok_or("server PID must be discoverable after cold build")?;
    let restarts_before = sink.count_restarted();

    // Static-sibling edit: "alpha" -> "omega" — a template-only structural edit.
    // The `{count}` hole is untouched, so the hole count is unchanged and the edit
    // is a pure skeleton (baked-string) change → hot-swap.
    write_main(&ipe_dir, &web_fixture_value_hole("omega", ""))?;
    let swap_start = Instant::now();
    assert!(
        wait_for(E2E_HOT_SWAP_BUDGET, || sink.count_hot_swapped() > 0),
        "editing the static sibling of a value-hole view must hot-swap, not recompile"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        sink.count_restarted(),
        restarts_before,
        "a hot-swapped static-sibling edit must NOT restart the app (no cargo rebuild)"
    );
    assert_eq!(
        server_pid(port),
        Some(pid_before),
        "a hot-swapped static-sibling edit must leave the SAME server process running"
    );
    let body1 = http_get_body(port).ok_or("server must serve a body after hot-swap")?;
    assert!(
        body1.contains("omega") && body1.contains('7'),
        "after the hot-swap the edited skeleton AND the compiled hole must both render"
    );
    eprintln!(
        "[measure] value-hole static sibling alpha->omega hot-swap: {} ms (no cargo, no restart)",
        swap_start.elapsed().as_millis()
    );

    stop_and_join(&handle, join)
}

/// A `Web.tea` counter whose `update` is a data-describable transition arm
/// (`Increment -> ( { m | count = m.count + step }, Cmd.none )`). Under the flag
/// the arm compiles to `apply_transition_hot("<baked datum>", model)`, so editing
/// the `step` literal changes ONLY the baked datum json — a transition hot-swap
/// with no recompile. A marker text confirms the app is up.
fn web_fixture_counter(step: u32, extra_text: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Tea.Web.Cmd\n\
         import Ipe.Tea.Web.Sub\n\
         import Ipe.String\n\n\
         type alias Model = {{ count : Int }}\n\n\
         type Msg = Increment\n\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req =\n    \
             ( {{ count = 0 }}, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update msg model =\n    \
             case msg of\n        \
                 Increment ->\n            \
                     ( {{ model | count = model.count + {step} }}, Cmd.none )\n\n\
         view : Model -> Element Msg\n\
         view model =\n    \
             Ui.column []\n        \
                 [ Ui.text \"marker\"{extra_text} ]\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n    \
             Sub.none\n\n\
         main =\n    \
             Web.tea\n        \
                 {{ init = init, update = update, view = view, subscriptions = subscriptions\n        \
                 , routes = [], notFound = Increment\n        \
                 }}\n",
    )
}

/// The transition-hot-swap SEAL: a counter's `update` arm edited from `+ 1` to
/// `+ 2` hot-swaps with no `cargo build` and no restart — the arm compiled to
/// `apply_transition_hot(<baked datum>, model)`, so only the baked datum json
/// changed and the classifier routes it to a transition patch. A structural
/// `update` edit (a real `Cmd`) still recompiles.
#[test]
#[cfg(target_os = "linux")]
fn update_arm_step_edit_hot_swaps_without_rebuild() -> Result<(), BoxError> {
    if std::env::var("IPE_E2E").is_err() {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    // SAFETY: single-threaded here (no watch thread spawned yet); nextest isolates
    // this process, so the var neither races nor leaks.
    unsafe {
        std::env::set_var("IPE_WATCH_HOT_APPEARANCE", "1");
    }

    let (ipe_dir, out_dir) = fresh_dirs("counter")?;
    write_main(&ipe_dir, &web_fixture_counter(1, ""))?;

    let sink = EventSink::default();
    let port = 19181;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink)?;

    assert!(
        wait_for_serving(port, Duration::from_mins(4)),
        "the flag-on cold build of a transition-arm counter must serve \
         (the emitted apply_transition_hot arm compiles)"
    );
    assert!(
        wait_for(Duration::from_secs(10), || sink.count_restarted() >= 1),
        "the cold build must record its initial Restarted event"
    );
    let pid_before = server_pid(port).ok_or("server PID must be discoverable after cold build")?;
    let restarts_before = sink.count_restarted();

    // update-arm edit: count + 1 -> count + 2. Transition-only => hot-swap.
    write_main(&ipe_dir, &web_fixture_counter(2, ""))?;
    let swap_start = Instant::now();
    let hot_swapped = wait_for(E2E_HOT_SWAP_BUDGET, || sink.count_hot_swapped() > 0);
    assert!(
        hot_swapped,
        "a +1 -> +2 update-arm edit must be hot-swapped (transition patch), not recompiled"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        sink.count_restarted(),
        restarts_before,
        "a hot-swapped update-arm edit must NOT restart the app (no cargo rebuild)"
    );
    assert_eq!(
        server_pid(port),
        Some(pid_before),
        "a hot-swapped update-arm edit must leave the SAME server process running"
    );
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("marker")),
        "the app must keep serving after the transition hot-swap"
    );
    eprintln!(
        "[measure] update-arm count +1->+2 hot-swap round-trip: {} ms (no cargo, no restart)",
        swap_start.elapsed().as_millis()
    );

    // Structural update edit: add a real Cmd (Cmd.batch []). Logic => recompile.
    // The arm gains a non-none Cmd, so it is no longer data-describable; the emit
    // no longer routes through apply_transition_hot and the classifier sees a
    // skeleton change => recompile + restart.
    let restarts_before_struct = sink.count_restarted();
    write_main(
        &ipe_dir,
        &web_fixture_counter(2, "").replace(
            "( { model | count = model.count + 2 }, Cmd.none )",
            "( { model | count = model.count + 2 }, Cmd.batch [] )",
        ),
    )?;
    let restarted = wait_for(Duration::from_mins(2), || {
        server_pid(port).is_some_and(|pid| pid != pid_before)
    });
    assert!(
        restarted,
        "a structural update edit (a real Cmd) must recompile and restart onto a new binary"
    );
    assert!(
        wait_for(Duration::from_secs(10), || {
            sink.count_restarted() > restarts_before_struct
        }),
        "a structural update edit must recompile and restart (a new Restarted event)"
    );

    stop_and_join(&handle, join)
}

/// A `Web.tea` counter with a two-variant `Msg` (`Increment | Decrement`), each a
/// data-describable arm. Under the hot flag the emitter bakes a
/// `const IPE_WEB_MSG_SET` descriptor of the variant surface, which the watch
/// classifier diffs across emits. `keep_decrement` drops `Decrement` (a
/// NON-additive removal) when false.
fn web_fixture_msg_variants(keep_decrement: bool) -> String {
    let decrement_variant = if keep_decrement { " | Decrement" } else { "" };
    let decrement_arm = if keep_decrement {
        "        Decrement ->\n            \
             ( { model | count = model.count - 1 }, Cmd.none )\n"
    } else {
        ""
    };
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Tea.Web.Cmd\n\
         import Ipe.Tea.Web.Sub\n\
         import Ipe.String\n\n\
         type alias Model = {{ count : Int }}\n\n\
         type Msg = Increment{decrement_variant}\n\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req =\n    \
             ( {{ count = 0 }}, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update msg model =\n    \
             case msg of\n        \
                 Increment ->\n            \
                     ( {{ model | count = model.count + 1 }}, Cmd.none )\n\
         {decrement_arm}\n\
         view : Model -> Element Msg\n\
         view model =\n    \
             Ui.column []\n        \
                 [ Ui.text \"marker\" ]\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n    \
             Sub.none\n\n\
         main =\n    \
             Web.tea\n        \
                 {{ init = init, update = update, view = view, subscriptions = subscriptions\n        \
                 , routes = [], notFound = Increment\n        \
                 }}\n",
    )
}

/// A minimal Web TEA program whose `subscriptions` is a single data-describable
/// tick source `Sub.every <interval> Tick`, plus a `Tick` `Msg` its `update`
/// consumes. `extra_text` perturbs the view to force a structural edit when
/// needed. The `subscriptions` entry compiles to `sub_every_hot(<baked datum>)`
/// under the hot flag; editing only the interval literal changes only the baked
/// datum json, so the classifier routes it to a sub patch (no recompile).
fn web_fixture_ticker(interval: u32, extra_text: &str) -> String {
    format!(
        "module Main exposing (main)\n\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Tea.Web.Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\n\
         type alias Model = {{ count : Int }}\n\n\
         type Msg = Tick\n\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req =\n    \
             ( {{ count = 0 }}, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update msg model =\n    \
             case msg of\n        \
                 Tick ->\n            \
                     ( {{ model | count = model.count + 1 }}, Cmd.none )\n\n\
         view : Model -> Element Msg\n\
         view model =\n    \
             Ui.column []\n        \
                 [ Ui.text \"marker\"{extra_text} ]\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n    \
             Sub.every {interval} Tick\n\n\
         main =\n    \
             Web.tea\n        \
                 {{ init = init, update = update, view = view, subscriptions = subscriptions\n        \
                 , routes = [], notFound = Tick\n        \
                 }}\n",
    )
}

/// The `Msg`-set fail-closed SEAL: a NON-additive `Msg` change (dropping a live
/// variant) must RECOMPILE (restart onto a new binary), never a hot-swap — the
/// baked `IPE_WEB_MSG_SET` descriptor is no longer an additive superset, so the
/// classifier withholds the `Msg`-set patch and falls through to a full rebuild,
/// re-initialising to a clean session. (The additive direction — adding a variant
/// plus its arm and button — hot-swaps only once the sibling view-subtree and
/// transition-arm masking lands; this SEAL locks the conservative fail-closed leg
/// this slice owns end-to-end.)
#[test]
#[cfg(target_os = "linux")]
fn non_additive_msg_change_recompiles() -> Result<(), BoxError> {
    if std::env::var("IPE_E2E").is_err() {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    // SAFETY: single-threaded here (no watch thread spawned yet); nextest isolates
    // this process, so the var neither races nor leaks.
    unsafe {
        std::env::set_var("IPE_WATCH_HOT_APPEARANCE", "1");
    }

    let (ipe_dir, out_dir) = fresh_dirs("msgset")?;
    write_main(&ipe_dir, &web_fixture_msg_variants(true))?;

    let sink = EventSink::default();
    let port = 19182;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink)?;

    assert!(
        wait_for_serving(port, Duration::from_mins(4)),
        "the flag-on cold build of a two-variant counter must serve"
    );
    assert!(
        wait_for(Duration::from_secs(10), || sink.count_restarted() >= 1),
        "the cold build must record its initial Restarted event"
    );
    let pid_before = server_pid(port).ok_or("server PID must be discoverable after cold build")?;
    let restarts_before = sink.count_restarted();

    // NON-additive edit: drop the `Decrement` variant (and its arm). The baked
    // Msg-set descriptor loses a live variant, so it is NOT an additive superset;
    // the classifier withholds a Msg-set patch and the whole edit recompiles.
    write_main(&ipe_dir, &web_fixture_msg_variants(false))?;
    let restarted = wait_for(Duration::from_mins(2), || {
        server_pid(port).is_some_and(|pid| pid != pid_before)
    });
    assert!(
        restarted,
        "a non-additive Msg change (a removed variant) must recompile and restart \
         onto a new binary (fail-closed to a clean session), never hot-swap"
    );
    assert!(
        wait_for(Duration::from_secs(10), || {
            sink.count_restarted() > restarts_before
        }),
        "a non-additive Msg change must record a fresh Restarted event"
    );
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("marker")),
        "the app must keep serving on the recompiled binary"
    );

    stop_and_join(&handle, join)
}

/// The sub-description-hot-swap SEAL: a ticker's `subscriptions` interval edited
/// from `1000` to `500` hot-swaps with no `cargo build` and no restart — the entry
/// compiled to `sub_every_hot(<baked datum>)`, so only the baked datum json
/// changed and the classifier routes it to a sub patch. A structural
/// `subscriptions` edit (a real `Sub.batch`) still recompiles.
#[test]
#[cfg(target_os = "linux")]
fn subscriptions_interval_edit_hot_swaps_without_rebuild() -> Result<(), BoxError> {
    if std::env::var("IPE_E2E").is_err() {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    // SAFETY: single-threaded here (no watch thread spawned yet); nextest isolates
    // this process, so the var neither races nor leaks.
    unsafe {
        std::env::set_var("IPE_WATCH_HOT_APPEARANCE", "1");
    }

    let (ipe_dir, out_dir) = fresh_dirs("ticker")?;
    write_main(&ipe_dir, &web_fixture_ticker(1000, ""))?;

    let sink = EventSink::default();
    let port = 19183;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink)?;

    assert!(
        wait_for_serving(port, Duration::from_mins(4)),
        "the flag-on cold build of a ticker subscriptions must serve \
         (the emitted sub_every_hot entry compiles)"
    );
    assert!(
        wait_for(Duration::from_secs(10), || sink.count_restarted() >= 1),
        "the cold build must record its initial Restarted event"
    );
    let pid_before = server_pid(port).ok_or("server PID must be discoverable after cold build")?;
    let restarts_before = sink.count_restarted();

    // subscriptions edit: Time.every 1000 -> 500. Sub-description-only => hot-swap.
    write_main(&ipe_dir, &web_fixture_ticker(500, ""))?;
    let swap_start = Instant::now();
    let hot_swapped = wait_for(E2E_HOT_SWAP_BUDGET, || sink.count_hot_swapped() > 0);
    assert!(
        hot_swapped,
        "a 1000 -> 500 interval edit must be hot-swapped (sub patch), not recompiled"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        sink.count_restarted(),
        restarts_before,
        "a hot-swapped subscriptions edit must NOT restart the app (no cargo rebuild)"
    );
    assert_eq!(
        server_pid(port),
        Some(pid_before),
        "a hot-swapped subscriptions edit must leave the SAME server process running"
    );
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("marker")),
        "the app must keep serving after the sub-description hot-swap"
    );
    eprintln!(
        "[measure] subscriptions 1000->500 hot-swap round-trip: {} ms (no cargo, no restart)",
        swap_start.elapsed().as_millis()
    );

    // Structural subscriptions edit: wrap in a real Sub.batch. Logic => recompile.
    // The entry is no longer a bare data-describable tick, so the emit no longer
    // routes through sub_every_hot and the classifier sees a skeleton change =>
    // recompile + restart.
    let restarts_before_struct = sink.count_restarted();
    write_main(
        &ipe_dir,
        &web_fixture_ticker(500, "")
            .replace("Sub.every 500 Tick", "Sub.batch [ Sub.every 500 Tick ]"),
    )?;
    let restarted = wait_for(Duration::from_mins(2), || {
        server_pid(port).is_some_and(|pid| pid != pid_before)
    });
    assert!(
        restarted,
        "a structural subscriptions edit (a real Sub.batch) must recompile and restart"
    );
    assert!(
        wait_for(Duration::from_secs(10), || {
            sink.count_restarted() > restarts_before_struct
        }),
        "a structural subscriptions edit must recompile and restart (a new Restarted event)"
    );

    stop_and_join(&handle, join)
}

/// A `Web.tea` whose `update` arm fires a single literal `Cmd.perform`
/// (`Fetch -> ( model, Cmd.perform (Time.now ()) GotTime )`). Under the hot flag
/// that arm's Cmd position composes to `fire_cmd_wiring("<baked wiring>", vec![…])`
/// over the arm's OWN compiled effect table (the `Cmd.perform` stays compiled,
/// wrapped in a lazy `move` thunk; only the wiring id is data). A marker text
/// confirms the app is up.
fn web_fixture_cmd_perform() -> String {
    "module Main exposing (main)\n\n\
     import Ipe.Tea.Web as Web\n\
     import Ipe.Ui as Ui\n\
     import Ipe.Tea.Web.Cmd\n\
     import Ipe.Tea.Web.Sub\n\
     import Ipe.Time as Time\n\
     import Ipe.Time.Timestamp exposing (Timestamp)\n\
     import Ipe.Error exposing (Error)\n\n\
     type alias Model = { count : Int }\n\n\
     type Msg = Fetch | GotTime (Result Error Timestamp)\n\n\
     init : WebReq -> ( Model, Cmd Msg )\n\
     init _req =\n    \
         ( { count = 0 }, Cmd.none )\n\n\
     update : Msg -> Model -> ( Model, Cmd Msg )\n\
     update msg model =\n    \
         case msg of\n        \
             Fetch ->\n            \
                 ( model, Cmd.perform (Time.now ()) GotTime )\n\n        \
             GotTime _result ->\n            \
                 ( { model | count = model.count + 1 }, Cmd.none )\n\n\
     view : Model -> Element Msg\n\
     view model =\n    \
         Ui.column []\n        \
             [ Ui.text \"marker\" ]\n\n\
     subscriptions : Model -> Sub Msg\n\
     subscriptions _model =\n    \
         Sub.none\n\n\
     main =\n    \
         Web.tea\n        \
             { init = init, update = update, view = view, subscriptions = subscriptions\n        \
             , routes = [], notFound = Fetch\n        \
             }\n"
    .to_owned()
}

/// The Cmd-wiring composition SEAL: a web app whose `update` has a single literal
/// `Cmd.perform` arm cold-builds and SERVES under the hot flag — which is the
/// compiler↔runtime SEAL for this slice (`ipe`-accepts ⇒ `cargo`-builds ⇒ the app
/// runs). The composed arm emits `fire_cmd_wiring("<baked wiring>", vec![Box::new(
/// move || <compiled Cmd.perform>)])` at the Cmd position; a build failure here
/// would mean the emitted dispatch does not type-check. The effect-firing and
/// fail-closed selection are proven in the runtime `cmd_wiring::fire_tests`; this
/// locks that the composed emit itself compiles and boots.
#[test]
#[cfg(target_os = "linux")]
fn cmd_perform_arm_composes_and_serves() -> Result<(), BoxError> {
    if std::env::var("IPE_E2E").is_err() {
        eprintln!("skipping (set IPE_E2E=1 to run)");
        return Ok(());
    }
    // SAFETY: single-threaded here (no watch thread spawned yet); nextest isolates
    // this process, so the var neither races nor leaks.
    unsafe {
        std::env::set_var("IPE_WATCH_HOT_APPEARANCE", "1");
    }

    let (ipe_dir, out_dir) = fresh_dirs("cmdperform")?;
    write_main(&ipe_dir, &web_fixture_cmd_perform())?;

    let sink = EventSink::default();
    let port = 19184;
    let (join, handle) = start_watch(&ipe_dir.join("Main.ipe"), &out_dir, port, &sink)?;

    assert!(
        wait_for_serving(port, Duration::from_mins(4)),
        "the flag-on cold build of a Cmd.perform update arm must serve \
         (the composed fire_cmd_wiring dispatch compiles and boots)"
    );
    assert!(
        wait_for(Duration::from_secs(10), || sink.count_restarted() >= 1),
        "the cold build must record its initial Restarted event"
    );
    assert!(
        http_get_body(port).is_some_and(|b| b.contains("marker")),
        "the composed-wiring app must serve its view"
    );

    stop_and_join(&handle, join)
}
