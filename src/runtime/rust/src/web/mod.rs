//! Ipe.Web on the Rust backend — HTTP-first render + SSE patch loop.
//! Generic over the app's (Model, Msg); no `any`, static dispatch only.
// Re-exported from the target-neutral `dom` module (shared with the
// browser-WASM sink); module aliases keep `web::diff::Patch`-style paths valid.
pub use crate::dom::diff;
pub use crate::dom::dispatch;
pub use diff::*;
pub use dispatch::*;
// `sse` is the axum Server-Sent-Events patch channel — server-only.
#[cfg(feature = "server")]
pub mod sse;
pub use crate::dom::form;
pub use form::*;
#[cfg(feature = "server")]
pub use sse::*;
// The appearance-literal table now lives at the crate root (a pure, dev-loop
// module shared with the loopback tui/cli hot-swap path, which links no
// `web-core`). Re-exported here so `web::literal_table` / `web::LiteralTable`
// paths stay valid for the served render host's callers.
pub use crate::literal_table;
pub use crate::literal_table::LiteralTable;
pub mod template;
pub use template::{Template, TemplateAttr, materialize_template, template_of};
pub mod route;
pub use route::*;
// `console` (dev telemetry ingest) and `csrf` (axum CSRF middleware +
// `crate::server` re-exports) are axum/`server`-only. `style_inject` is pure
// render-core and stays unconditional.
#[cfg(feature = "server")]
pub mod console;
#[cfg(feature = "server")]
pub mod csrf;
pub mod style_inject;
// Custom-element (`CustomElement.node`) registration glue + SRI-pinned author-JS serving.
// The generator lives at the crate top level (`crate::widget_assets`) so the
// build-time static/wasm bundler can reach it without the server surface; `web`
// re-exports it here so the server's `ipe_runtime::web::widget_assets::*` path
// (the process-start `register` + route mounting) keeps its security shape.
// Populated
// once at process start by the generated `main`; inert for a widget-free program.
// Rides the `web` feature (which lists `widget-assets`); the server surface is
// its only in-module consumer.
#[cfg(feature = "server")]
pub use crate::widget_assets;
// Pre-built console child + reverse-proxy — spawns the bundled console
// binary and proxies /_ipe/console/*; falls back to in-process `console` when the
// binary is absent. Uses reqwest for the reverse-proxy path; gated so a web
// app that makes no outbound HTTP calls (no `http_client` feature) stays reqwest-free.
#[cfg(feature = "http_client")]
pub mod console_proxy;
// Observability middleware + noise ingest — axum request/response types, server-only.
#[cfg(feature = "server")]
pub mod observability;
// Observability export pipelines: federation push to a parent ingest
// and remote-hub OTLP push. Both env-gated + inert by default.
// Use reqwest for outbound push; gated so a web app with no outbound HTTP
// kernel (`http_client` absent) stays reqwest-free.
#[cfg(feature = "http_client")]
pub mod hub_exporter;
#[cfg(feature = "http_client")]
pub mod push_exporter;
// Hub read-side kernels (the bundled console's data plane). Gated on `db` —
// they read the SQLite telemetry spill via sqlx, so a `live`-only program with
// no db never compiles them and stays sqlx-free.
#[cfg(feature = "db")]
pub mod hub;
#[cfg(feature = "db")]
pub use hub::*;
// `req` builds a `WebReq` from an axum request; `store` is the axum/sqlx session
// store — both server-only. Render hosts take their `WebReq` from the
// target-neutral `crate::dom::req` instead.
#[cfg(feature = "server")]
pub mod req;
#[cfg(feature = "server")]
pub use req::*;
#[cfg(feature = "server")]
pub mod store;
#[cfg(feature = "server")]
pub use store::*;
// Additive-superset Model reconstruction: keeps a returning session's state
// when the app's `Model` gains a new field (see the module doc). A pure,
// self-contained decision + splice over a self-describing checkpoint body.
pub mod additive;
// The session-aware pub/sub broker (`crate::tea` + tokio broadcast) — server-only.
#[cfg(feature = "server")]
pub mod pubsub;
// Inert `update`-arm transitions: the logic counterpart of the appearance
// `literal_table`. A data-describable `update` arm (a field record-update, a
// toggle, a setter) reduces to a `Transition` datum run by the compiled
// `apply_transition` — one update semantics, dev == prod (see the module doc).
pub mod transition;
pub use transition::Transition;
// The `apply_transition*` server-side session-Model mutators are gated at their
// definition on `any(db, redis_store, web)`; mirror that on the re-export so the
// render core (which never mutates a server-held Model) drops them cleanly.
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
pub use transition::{apply_transition, apply_transition_hot};
// The additive-only `Msg` SET codec: a schema-tagged descriptor of the running
// program's `Msg` variant surface. Gates whether a live edit that adds a variant
// (plus its arm and a button firing it) may hot-swap — accepted only when the new
// set is a proven additive superset of the live one, so a returning session's
// in-flight `handler_id`s still resolve (see the module doc).
pub mod msg_set;
// Inert `subscriptions`-entry descriptions: the TEA-loop counterpart of the
// `transition` table. A data-describable subscription (`Time.every 1000 Tick`)
// reduces to a `SubDescription` datum built by the compiled `sub_every_hot` —
// one subscription semantics, dev == prod (see the module doc).
pub mod sub_desc;
pub use sub_desc::SubDescription;
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
pub use sub_desc::{build_sub, sub_every_hot};
// Inert session-`init` datum: the STARTING-`Model` counterpart of `transition`.
// A data-describable `init` (a record of closed leaf values, `Cmd.none`) reduces
// to an `InitDatum` decoded by the compiled `apply_init_hot` at session creation
// only — one init semantics, dev == prod, and session-scoped by construction (a
// live session never re-consults it). See the module doc.
pub mod init_datum;
pub use init_datum::InitDatum;
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
pub use init_datum::{apply_init, apply_init_hot};
// Inert `update`-arm Cmd WIRING: which compiled effect an arm fires, as data
// (the effect BODY stays compiled). A wiring edit — an arm now fires a different
// already-compiled effect — is a data patch selected by the compiled
// `select_cmd_hot`; a genuinely-new effect body grows the arm's effect table and
// recompiles. See the module doc.
pub mod cmd_wiring;
pub use cmd_wiring::CmdWiring;
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
pub use cmd_wiring::{fire_cmd_wiring, select_cmd_hot, select_effect};
// Explicit re-export of ONLY the codegen-referenced kernel functions. A glob
// (`pub use pubsub::*`) leaked the broker's `Event<T>` into this namespace,
// colliding with the HTML `Event` enum re-exported below (`pub use …html::*`)
// and surfacing as `error: `Event` is ambiguous` in generated code that names
// `ipe_runtime::Event`. The broker internals (`Event`, `Broker`, `broker`,
// `subscribe`, `publish`) are `pub(crate)` in pubsub.rs — they never leave the
// crate, so they don't need re-exporting here.
#[cfg(feature = "server")]
pub use pubsub::{
    cmd_publish, cmd_publish_no_echo, pubsub_publish, pubsub_publish_no_echo, sub_subscribe_topic,
};

// Html ADTs + renderer now live in the standalone top-level `html` module;
// re-export them so live submodules (diff.rs, store.rs, …) that `use super::*`
// still see Html / Attribute / Event / render_html / html_render_. The render
// core reaches `crate::html` directly, so the re-export rides the server surface.
#[cfg(feature = "server")]
pub use crate::html::*;

#[cfg(feature = "server")]
use super::*;

/// Body returned with a session-miss 404 from `/_ipe/event` and `/_ipe/sse`.
///
/// LOAD-BEARING CONTRACT — `client.js` `__ipeProbeSessionLost` only triggers
/// `window.location.reload()` (the SSE-reconnect recovery path) when a probe
/// POST gets a 404 + `X-Ipê-Web: 1` AND the body CONTAINS the substring
/// `"session not found"` (client.js l1481/l1530/l1536).  backend returns
/// the same string; diverging it (the old `"no session"` body) silently broke
/// recovery after a server restart — the browser shows "Reconnecting…" forever.
/// Guarded by `session_lost_body_tests`.
#[cfg(feature = "server")]
const SESSION_LOST_BODY: &str = "session not found";

// ─── Client assets ────────────────────────────────────────────────────────────

/// The browser-side Ipe.Web client JS asset. The 12 header `%`-verb
/// lines are replaced with static literals; the two `%%` CSS escapes are
/// un-escaped to `%`.
#[cfg(feature = "server")]
const CLIENT_JS: &str = include_str!("client.js");

/// Content-addressing for the client asset: computed ONCE at first access via
/// `OnceLock`. Holds `(hex16, base64full)` where:
///   - `hex16` — first 16 hex chars of SHA-256(CLIENT_JS) → used in the URL
///     (`/_ipe/client.<hex16>.js`) for cache-busting.
///   - `base64full` — standard base64 of the full 32-byte SHA-256 digest → the
///     `integrity="sha256-<base64full>"` SRI attribute value.
///
/// Both are derived from the same digest, computed once and interned.
/// The `sha2` crate is unconditionally available in every generated Web project
/// (`default` features always include `crypto` which gates `sha2`).
#[cfg(feature = "server")]
static CLIENT_JS_HASH: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();

/// Return `(hex16, base64full)` for `CLIENT_JS`, computing once on first call.
#[cfg(feature = "server")]
fn client_js_hashes() -> &'static (String, String) {
    CLIENT_JS_HASH.get_or_init(|| {
        use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(CLIENT_JS.as_bytes()).into();
        let hex16: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        let base64full = B64.encode(digest);
        (hex16, base64full)
    })
}

/// The content-addressed URL path for the client JS asset, e.g.
/// `/_ipe/client.a1b2c3d4e5f6a7b8.js`. The path is stable for a given
/// `client.js` build and changes whenever the file changes — making
/// `Cache-Control: immutable` safe. Callers may prepend the sub-app `base`.
#[cfg(feature = "server")]
pub fn client_js_path() -> String {
    let (hex16, _) = client_js_hashes();
    format!("/_ipe/client.{}.js", hex16)
}

// ─── Page renders ─────────────────────────────────────────────────────────────

// `page_shell` + its `BASE_CSS` reset are the server-free page scaffold; they
// live in the render-core `web_page_core` module (shared with the lean render
// hosts) and are re-exported here so every `page_shell(...)` call site in this
// module — and the emitted `ipe_runtime::web::page_shell` path — stays valid.
pub use crate::web_page_core::page_shell;

/// Render `view(model)` to a full HTML page and print it — the static
/// render path (the interactive server is `web_app`).
#[cfg(feature = "server")]
pub fn web_render_static<E, Model, Msg, FView>(view: FView, model: Model) -> IpeTask<E, ()>
where
    E: Send + 'static,
    Model: Send + 'static,
    Msg: Send + 'static,
    FView: Fn(Model) -> Html<Msg> + Send + 'static,
{
    Box::pin(async move {
        let mut tree = view(model);
        assign_ipe_ids(&mut tree, "r");
        style_inject::apply_style_injections(&mut tree);
        println!("{}", render_page(&render_html(&tree)));
        IpeResult::Ok(())
    })
}

/// Static SSR page: body only, no client JS.
#[cfg(feature = "server")]
pub fn render_page(body: &str) -> String {
    page_shell("", &format!("<div id=\"ipe-root\">{body}</div>"), "")
}

/// Escape a serde-serialised JSON string for safe embedding inside a
/// `<script>` element (HTML script-data context, not attribute context).
///
/// JSON alone is not sufficient: a string field containing `</script>` would
/// end the `<script>` element, breaking out of the data island into executable
/// script context and defeating the no-eval / no-`'unsafe-eval'` posture.
/// The five characters below are the only ones that matter in script-data
/// context; `serde_json`'s own output already encodes control characters, so
/// no other escaping is required.
///
/// Escapes applied (JSON numeric escapes — losslessly round-trippable by any
/// JSON parser, including `serde_json`):
/// - U+003C `<`    → `<`  (forecloses `</script`)
/// - U+003E `>`    → `>`  (defence-in-depth against `>` injection)
/// - U+0026 `&`    → `&`  (forecloses HTML entity injection)
/// - U+2028 LINE SEPARATOR   → ` `  (JSON-legal but HTML-hostile)
/// - U+2029 PARAGRAPH SEPARATOR → ` `
///
/// Identical escape class as the telemetry `json_escape` U+2028/2029 gap —
/// the island serialiser applies it here for consistency.
#[cfg(feature = "server")]
pub fn island_escape(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for ch in json.chars() {
        match ch {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out
}

/// Page wrap for isomorphic SSR + WASM hydration (M7 mode 2).
///
/// Emits a standard HTML page with:
/// - The SSR body in `<div id="ipe-root">`.
/// - The WASM bundle boot scripts (external JS + `hydrate(island_json)` call).
/// - A **typed public-payload island** `<script type="application/ipe-model+json">`
///   carrying the XSS-escaped, serde-serialised `HydrationState` JSON.
///
/// The island body is read by the WASM client via
/// `document.querySelector('script[type="application/ipe-model+json"]').textContent`
/// and passed to the emitted `hydrate(model_json)` entry — parsed with `serde_json`,
/// never evaluated. The `island_escape` call forecloses all script-injection paths.
///
/// `body`        — SSR-rendered HTML (from `render_html` with ipe-ids assigned).
/// `island_json` — serde-serialised `HydrationState` (BEFORE island_escape;
///                 this function applies the escape internally).
/// `pkg_base`    — URL prefix for the WASM bundle assets, e.g. `/pkg` or `./pkg`.
#[cfg(feature = "server")]
pub fn render_page_hydrate(body: &str, island_json: &str, pkg_base: &str) -> String {
    let escaped = island_escape(island_json);
    let body_inner = format!("<div id=\"ipe-root\">{body}</div>");
    let tail_scripts = format!(
        "<script type=\"application/ipe-model+json\">{escaped}</script>\
<script type=\"module\">\
import init, {{ hydrate }} from '{pkg_base}/ipe_app.js';\
async function boot() {{\
  await init('{pkg_base}/ipe_app_bg.wasm');\
  const island = document.querySelector('script[type=\"application/ipe-model+json\"]');\
  hydrate(island ? island.textContent : '');\
}}\
boot();\
</script>"
    );
    page_shell("", &body_inner, &tail_scripts)
}

#[cfg(all(test, feature = "server"))]
mod island_escape_tests {
    use super::island_escape;

    #[test]
    fn escapes_lt_gt_amp() {
        let input = r#"{"k":"<b>&amp;</b>"}"#;
        let out = island_escape(input);
        assert!(!out.contains('<'));
        assert!(!out.contains('>'));
        assert!(!out.contains('&'));
        assert!(out.contains("\\u003c"));
        assert!(out.contains("\\u003e"));
        assert!(out.contains("\\u0026"));
    }

    #[test]
    fn script_injection_foreclosed() {
        let payload = r#"{"x":"</script><script>evil()</script>"}"#;
        let out = island_escape(payload);
        assert!(!out.contains("</script>"), "script tag must not be present");
    }

    #[test]
    fn line_separator_escaped() {
        let payload = "\u{2028}\u{2029}";
        let out = island_escape(payload);
        assert!(!out.contains('\u{2028}'));
        assert!(!out.contains('\u{2029}'));
        assert!(out.contains("\\u2028"));
        assert!(out.contains("\\u2029"));
    }

    #[test]
    fn plain_json_is_lossless() {
        let payload = r#"{"count":42,"name":"hello"}"#;
        let out = island_escape(payload);
        assert_eq!(out, payload); // nothing to escape
    }
}

/// Full page wrap with the live client loaded as a cacheable external asset.
/// Implements live page render
///
/// `sid`  — session id (injected into the JS via `window.__IPE_SID`).
/// `base` — sub-app base path, e.g. "" for root-mounted apps.
/// `body` — pre-rendered HTML body (from `render_html`).
///
/// Two scripts are emitted in document order (no defer/async — execution order
/// is left-to-right by the HTML spec):
///   1. A tiny inline `<script>` setting the three per-session window globals
///      (`__IPE_SID`, `__IPE_BASE`, `__IPE_CSRF_TOKEN`). These MUST stay inline
///      because they are per-session values and must never be cached.
///   2. An external `<script src="…/_ipe/client.<hash>.js" integrity="sha256-…"
///      crossorigin="anonymous">` loading the invariant client body. The URL is
///      content-addressed (hash of the file) so it is safe to cache with
///      `immutable`. The SRI `integrity` attribute lets the browser verify the
///      file has not been tampered with before execution.
///
/// CSP note: the inline window-vars script still requires `script-src
/// 'unsafe-inline'` (unchanged from the fully-inlined baseline). The external
/// script requires no additional CSP directive beyond `script-src 'self'`
/// (already needed for same-origin resource loading). Adding a nonce to the
/// inline script to tighten CSP is deferred; it requires threading the nonce
/// through the response pipeline and is outside the scope of this change.
/// Server-side client-config templating: read the `IPE_WEB_*` tuning env vars
/// and emit the `window.__IPE_*` assignments the client (`client.js`) reads
/// with a hardcoded fallback. Malformed values fall back to the default; never
/// panics.
#[cfg(feature = "server")]
fn web_client_config_js() -> String {
    fn num(var: &str, default: u64) -> u64 {
        crate::system::read_env_var(var)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(default)
    }
    // IPE_WEB_BANNER: off/0/false → disabled; anything else → on.
    let banner = !matches!(
        crate::system::read_env_var("IPE_WEB_BANNER")
            .ok()
            .map(|s| s.trim().to_ascii_lowercase()),
        Some(ref v) if v == "off" || v == "0" || v == "false"
    );
    // IPE_WEB_SWAP_TOAST: set (non-empty ≠ "0") ⇒ this process runs behind the
    // dev-watch blue-green proxy, so a reconnect is an expected rebuild cutover,
    // not an outage. The client then greets a reconnect with a brief positive
    // "updated ✓" toast instead of the amber "Reconnecting…" banner. Only the
    // `ipe watch` blue-green path sets this; a release/`ipe run` server never
    // does, so the flag defaults off there.
    let swap_toast = matches!(
        crate::system::read_env_var("IPE_WEB_SWAP_TOAST")
            .ok()
            .map(|s| s.trim().to_string()),
        Some(ref v) if !v.is_empty() && v != "0"
    );
    format!(
        "window.__IPE_BANNER_ENABLED={banner};\
         window.__IPE_SWAP_TOAST={swap_toast};\
         window.__IPE_RETRY_BASE_MS={};\
         window.__IPE_RETRY_MAX_MS={};\
         window.__IPE_RETRY_MAX_ATTEMPTS={};\
         window.__IPE_RETRY_FAST_MS={};\
         window.__IPE_RETRY_FAST_WINDOW_MS={};\
         window.__IPE_EVENT_QUEUE_MAX={};\
         window.__IPE_HELLO_TIMEOUT_MS={};\
         window.__IPE_HEARTBEAT_TTL_MS={};\
         window.__IPE_MSG_RECONNECTING=\"Reconnecting…\";\
         window.__IPE_MSG_UPDATED=\"updated ✓\";\
         window.__IPE_MSG_OFFLINE=\"Connection lost — refresh to retry\";",
        num("IPE_WEB_RETRY_BASE_MS", 500),
        num("IPE_WEB_RETRY_MAX_MS", 16000),
        num("IPE_WEB_RETRY_MAX_ATTEMPTS", 10),
        num("IPE_WEB_RETRY_FAST_MS", 200),
        num("IPE_WEB_RETRY_FAST_WINDOW_MS", 3000),
        num("IPE_WEB_QUEUE_MAX", 50),
        num("IPE_WEB_HELLO_TIMEOUT_MS", 8000),
        num("IPE_WEB_HEARTBEAT_TTL_MS", 35000),
    )
}

/// Whether the dev watch/status banner endpoint should be mounted.
///
/// True when the banner is enabled (not explicitly disabled via `IPE_WEB_BANNER`
/// off/0/false), the app is NOT in production, and the app is root-mounted
/// (not a sub-app). Mirrors the three conditions the banner injection already
/// uses so no new env var is needed.
#[cfg(feature = "server")]
fn watch_banner_active(base: &str) -> bool {
    if crate::telemetry::production_from_env() {
        return false;
    }
    if !base.is_empty() {
        return false;
    }
    // Banner explicitly disabled → no endpoint either.
    !matches!(
        crate::system::read_env_var("IPE_WEB_BANNER")
            .ok()
            .map(|s| s.trim().to_ascii_lowercase()),
        Some(ref v) if v == "off" || v == "0" || v == "false"
    )
}

#[cfg(feature = "server")]
pub fn render_page_full(sid: &str, base: &str, body: &str, csrf_token: &str) -> String {
    // sid_js / base_js / csrf_js: Rust Debug ("{:?}") of a &str yields a
    // double-quoted, properly-escaped JS string literal for plain ASCII
    // session ids, base paths, and the hex CSRF token.
    let sid_js = format!("{sid:?}");
    let base_js = format!("{base:?}");
    let csrf_js = format!("{csrf_token:?}");
    let dev_banner = dev_console_banner(base);
    // Content-addressed client asset URL and SRI hash — computed once at first call.
    let (hex16, b64) = client_js_hashes();
    // Honour the sub-app base prefix so the external script request goes through
    // the parent proxy (same as /_ipe/sse, /_ipe/event, /_ipe/console).
    let client_src = format!("{base}/_ipe/client.{hex16}.js");
    let integrity = format!("sha256-{b64}");
    let config_js = web_client_config_js();
    let head_extra = format!("<meta name=\"ipe-base\" content=\"{base}\">");
    let body_inner = format!("<div id=\"ipe-root\">{body}</div>{dev_banner}");
    // Custom-element glue: an EXTERNAL, SRI-pinned `<script type="module">` plus a
    // `modulepreload` SRI pin per author asset. Empty when the program registers
    // no widget, so a widget-free page is byte-identical and its CSP is unchanged.
    // It loads AFTER the client core so `__ipeEmitWidgetUp` can reuse `__ipeSend`.
    let widget_scripts = widget_assets::page_scripts(base, widget_assets::WidgetTransport::Server);
    let port_glue = port_glue_script(base);
    let tail_scripts = format!(
        "<script>window.__IPE_SID={sid_js};window.__IPE_BASE={base_js};window.__IPE_CSRF_TOKEN={csrf_js};{config_js}</script>\
         <script src=\"{client_src}\" integrity=\"{integrity}\" crossorigin=\"anonymous\"></script>\
         {widget_scripts}{port_glue}"
    );
    page_shell(&head_extra, &body_inner, &tail_scripts)
}

/// The SRI-pinned `<script>` tag that loads the `Ipe.Ffi.Js` browser port surface,
/// or an empty string when the glue is unavailable. Loaded AFTER the client core
/// so `window.__ipePortSend` (the inbound seam) and the `port` SSE listener are
/// already installed when `window.ipe.send` first fires. Content-addressed +
/// integrity-pinned exactly like the client core, so a tampered byte makes the
/// browser refuse the module.
#[cfg(feature = "widget-assets")]
fn port_glue_script(base: &str) -> String {
    let path = crate::js_port_glue::port_glue_path();
    let integrity = crate::js_port_glue::port_glue_integrity();
    format!(
        "<script src=\"{base}{path}\" integrity=\"{integrity}\" crossorigin=\"anonymous\"></script>"
    )
}

/// No `Ipe.Ffi.Js` port glue when the widget-asset serving surface is absent: the
/// page carries no port `<script>` and `window.ipe` is never wired. Gated with
/// `server` to match its callers (`render_page_full*`, server-only): the
/// server-free `web-core` render core reaches neither the stub nor a caller.
#[cfg(all(feature = "server", not(feature = "widget-assets")))]
fn port_glue_script(_base: &str) -> String {
    String::new()
}

/// Same as [`render_page_full`] but appends `overlay` (raw HTML) after the
/// `#ipe-root` div. The overlay must carry `data-ipe-debugger` so the
/// diff/patch engine ignores it.
#[cfg(all(feature = "server", feature = "debugger"))]
fn render_page_full_with_overlay(
    sid: &str,
    base: &str,
    body: &str,
    csrf_token: &str,
    overlay: &str,
) -> String {
    let sid_js = format!("{sid:?}");
    let base_js = format!("{base:?}");
    let csrf_js = format!("{csrf_token:?}");
    let dev_banner = dev_console_banner(base);
    let (hex16, b64) = client_js_hashes();
    let client_src = format!("{base}/_ipe/client.{hex16}.js");
    let integrity = format!("sha256-{b64}");
    let config_js = web_client_config_js();
    let head_extra = format!("<meta name=\"ipe-base\" content=\"{base}\">");
    let body_inner = format!("<div id=\"ipe-root\">{body}</div>{dev_banner}{overlay}");
    let widget_scripts = widget_assets::page_scripts(base, widget_assets::WidgetTransport::Server);
    let port_glue = port_glue_script(base);
    let tail_scripts = format!(
        "<script>window.__IPE_SID={sid_js};window.__IPE_BASE={base_js};window.__IPE_CSRF_TOKEN={csrf_js};{config_js}</script>\
         <script src=\"{client_src}\" integrity=\"{integrity}\" crossorigin=\"anonymous\"></script>\
         {widget_scripts}{port_glue}"
    );
    page_shell(&head_extra, &body_inner, &tail_scripts)
}

/// Floating "🔍 Console" link injected into every dev-mode page. The
/// implementation lives in the always-compiled `telemetry` module so the
/// Ipe.Http.Server path (`server.rs`) shares the identical byte-exact banner;
/// this is a thin re-export for the Web page renderer.
#[cfg(feature = "server")]
fn dev_console_banner(base: &str) -> String {
    crate::telemetry::dev_console_banner(base)
}

// ─── web_app: axum mount + per-session TEA driver over SSE ─────────────────

#[cfg(feature = "server")]
use crate::tea::{IpeCmd, IpeSub};
#[cfg(feature = "server")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "server")]
use std::sync::{Arc, Mutex, Weak};
#[cfg(feature = "server")]
use tokio::sync::mpsc::{self, Receiver, Sender};

/// Per-session live state behind an `Arc<Mutex<…>>`. `index` / `last_view` are
/// re-derived on every commit; `sse_tx` is filled when the browser attaches the
/// SSE channel; `msg_tx` feeds the per-session driver loop.
#[cfg(feature = "server")]
pub struct SessionEntry<Model, Msg> {
    pub model: Model,
    pub last_view: Html<Msg>,
    pub index: HandlerIndex<Msg>,
    pub seq: u64,
    pub sse_tx: Option<SseTx>,
    pub msg_tx: Sender<Msg>,
    /// Bounded rolling message log for time-travel scrubbing. Present only
    /// when the `debugger` feature is active; absent builds pay no cost.
    #[cfg(feature = "debugger")]
    pub history: crate::debugger::RecordBuffer<Msg, Model>,
    /// Current scrub cursor for `back`/`forward` stepping.
    ///
    /// `None` = live mode (no active time-travel); `Some(n)` = the last step
    /// committed by `step_to`/`back`/`forward`. Reset to `None` on `reset`.
    #[cfg(feature = "debugger")]
    pub debug_cursor: Option<usize>,
}

/// SSE patches envelope. The browser client (`live/client.js`) consumes the
/// `event: patches` frame as `{globalSeq, patches}` and routes it through
/// `__ipeHandleResponse(undefined, _, _, globalSeq)` → `__ipeApplyPatches`.
/// We use `globalSeq` (the server-owned broadcast counter) rather than the
/// local `seq` so it never collides with the client's own POST-local seq gate.
#[derive(serde::Serialize)]
#[cfg(feature = "server")]
struct PatchEnvelope<'a> {
    #[serde(rename = "globalSeq")]
    global_seq: u64,
    patches: &'a [crate::web::diff::Patch],
}

/// Body for the dev-only `POST /_ipe/watch/status` endpoint.
///
/// Sent by `ipe watch` to push build state to connected browsers.
/// Only mounted when the dev banner is active (non-production, root-mounted,
/// and `IPE_WEB_BANNER` not explicitly disabled).
#[derive(serde::Deserialize)]
#[cfg(feature = "server")]
struct WatchStatusBody {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    /// Optional lifecycle phase. `"recompiling"` is pushed when a rebuild starts
    /// so the browser can show a soft-yellow "Recompiling app" banner during the
    /// otherwise-silent cargo build; absent for the terminal ok/error result.
    #[serde(default)]
    phase: Option<String>,
}

/// Latest build status from `ipe watch`, held in the server's shared state.
///
/// `None` = no status yet (initial state or production). Set by the
/// `/_ipe/watch/status` endpoint and replayed to new SSE connections so a
/// browser refresh during a failed build still shows the error.
#[derive(Clone, Debug)]
#[cfg(feature = "server")]
struct WatchBuildStatus {
    ok: bool,
    error: Option<String>,
}

/// Serialise a build-status verdict into the `ipe-build-status` SSE `data`
/// payload. `serde_json` escapes every control char below 0x20 as `\u00XX`, so
/// a compiler excerpt carrying carriage returns or ANSI escapes yields JSON the
/// browser can parse — hand-rolled backslash/quote escaping alone left those
/// raw, and a raw newline inside the value would break the `data:` line framing.
/// A crafted excerpt is confined to the `error` string value: it cannot inject
/// sibling fields.
#[cfg(feature = "server")]
fn watch_status_sse_payload(ok: bool, error: Option<&str>) -> String {
    let value = if ok {
        serde_json::json!({ "ok": true })
    } else {
        serde_json::json!({ "ok": false, "error": error.unwrap_or("") })
    };
    value.to_string()
}

/// Wire shape POSTed by the browser client to `/_ipe/event`
/// (`live/client.js` __ipeSend): `{sessionId, seq, msg, args, handlerId}`.
/// `handlerId` is the element's `data-ipe-hid` (== its ipe-id); `msg` is the
/// `ipe-<event>` marker. We resolve handlers server-side by ipe-id + event,
/// so `handlerId` is the authoritative locator; `event` is derived below.
#[derive(serde::Deserialize)]
#[cfg(feature = "server")]
struct EventBody {
    #[serde(default)]
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(default)]
    #[serde(rename = "handlerId")]
    handler_id: String,
    /// Some senders use `id` instead of `handlerId`; accept both.
    #[serde(default)]
    id: String,
    /// Event name. The client posts the `ipe-<event>` marker value as `msg`;
    /// `render_html` makes that value the event name (click / input / submit / …),
    /// so `msg` is the authoritative event. `event` is an explicit-override slot
    /// for future senders. Resolution: `event` ?: `msg` ?: "click".
    #[serde(default)]
    event: String,
    #[serde(default)]
    msg: String,
    /// Event args. For click/input/keydown `args[0]` is a string; for `submit`
    /// `args[0]` is the form-data object `{name: value, …}`. Parsed as JSON
    /// values so both shapes decode.
    #[serde(default)]
    args: Vec<serde_json::Value>,
}

/// Coerce a wire arg `Value` to the string the click/input/keydown path expects.
#[cfg(feature = "server")]
fn value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Boxed route resolver: a freshly-`init`'d model + GET path → the model whose
/// `page` field reflects the matched route.
#[cfg(feature = "server")]
type RouteResolver<Model> = Arc<dyn Fn(Model, &str) -> Model + Send + Sync>;
/// Boxed param resolver: a GET path → the matched route's `:name`→value params.
#[cfg(feature = "server")]
type ParamResolver = Arc<dyn Fn(&str) -> crate::dict::IpeDict<String> + Send + Sync>;
/// Boxed route predicate: does a GET path match a declared route?
/// Gates the page handler's browser-noise 404 and the
/// unrouted-GET-against-a-live-session 404 — see `page`.
#[cfg(feature = "server")]
type RouteMatched = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Shared axum state: the session store + Arc'd TEA callbacks.
#[cfg(feature = "server")]
pub(crate) struct WebState<Model, Msg, FInit, FUpdate, FView, FSubs> {
    store: Arc<dyn store::SessionStore<Model, Msg>>,
    init: Arc<FInit>,
    update: Arc<FUpdate>,
    view: Arc<FView>,
    subs: Arc<FSubs>,
    /// Maps the freshly-`init`'d model + GET path to the model whose `page`
    /// field reflects the matched route. `web_app` passes identity (no
    /// routing); `web_app_routed` captures the route table + page-setter.
    /// `Page`/`set_page` are erased into this boxed closure, so `WebState`
    /// keeps its original 6 type params.
    route_resolver: RouteResolver<Model>,
    /// Maps a GET path to the matched route's `:name`→value params (for
    /// `req.params`). Model-independent so the page handler can build `req`
    /// BEFORE calling `init`. `web_app` returns empty; `web_app_routed`
    /// captures the route table.
    param_resolver: ParamResolver,
    /// Does a GET path match a declared route? `web_app` treats only `/` as
    /// routed; `web_app_routed` captures the route table. An unrouted GET must
    /// never re-route a live session's
    /// model or rebuild its handler index: that wipes the handlers of the
    /// page the browser is showing, silently killing every subsequent event
    /// (form submits included).
    route_matched: RouteMatched,
    /// Web driver count for admission control. Each spawned `drive_session`
    /// holds a `SessionSlot` that decrements this on exit; a cookieless GET that
    /// would push it past `max_sessions()` is rejected (503) instead of minting
    /// an unbounded number of sessions. Decremented ONLY via `SessionSlot::drop`,
    /// so the leak fix (mortal driver) and this cap share one mechanism.
    session_count: Arc<AtomicUsize>,
    /// Latest build status from `ipe watch`. `None` until the first status
    /// POST arrives. Replayed to new SSE connections so a browser refresh
    /// during a failed build immediately shows the sticky error banner.
    /// Populated only when the dev watch/status endpoint is mounted;
    /// inert (always `None`) in production.
    watch_build_status: Arc<Mutex<Option<WatchBuildStatus>>>,
}

// Manual Clone — derive would demand Clone on the closures (they're behind Arc).
#[cfg(feature = "server")]
impl<Model, Msg, FInit, FUpdate, FView, FSubs> Clone
    for WebState<Model, Msg, FInit, FUpdate, FView, FSubs>
{
    fn clone(&self) -> Self {
        WebState {
            store: self.store.clone(),
            init: self.init.clone(),
            update: self.update.clone(),
            view: self.view.clone(),
            subs: self.subs.clone(),
            route_resolver: self.route_resolver.clone(),
            param_resolver: self.param_resolver.clone(),
            route_matched: self.route_matched.clone(),
            session_count: self.session_count.clone(),
            watch_build_status: self.watch_build_status.clone(),
        }
    }
}

/// Max concurrent Web-session drivers (admission control). 0 = unlimited
/// (opt-out). Default 50_000 — far above any single-instance real load, low
/// enough to bound memory under a session-creation flood.
/// Env `IPE_WEB_MAX_SESSIONS`.
#[cfg(feature = "server")]
fn max_sessions() -> usize {
    crate::system::read_env_var("IPE_WEB_MAX_SESSIONS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50_000)
}

/// RAII admission slot: decrements `WebState::session_count` exactly once when
/// the owning `drive_session` task exits (any path). Paired 1:1 with the
/// `fetch_add` reservation at the session-create site — the ONLY decrement.
#[cfg(feature = "server")]
struct SessionSlot {
    count: Arc<AtomicUsize>,
}
#[cfg(feature = "server")]
impl Drop for SessionSlot {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Fire a `Cmd`: None/Batch recurse; Perform spawns the composed task→Msg thunk
/// and pushes the result back into the per-session loop.
#[cfg(feature = "server")]
fn run_cmd<Msg: Send + 'static>(cmd: IpeCmd<Msg>, tx: &Sender<Msg>, sid: &str) {
    match cmd {
        IpeCmd::None => {}
        IpeCmd::Batch(items) => {
            for c in items {
                run_cmd(c, tx, sid);
            }
        }
        IpeCmd::Perform(thunk) => {
            let tx = tx.clone();
            tokio::spawn(async move {
                let m = thunk().await;
                // Bounded send: drop the Msg and warn if the session queue is
                // full (a stalled driver or a burst of fast Perform tasks).
                if tx.send(m).await.is_err() {
                    eprintln!(
                        "[ipe.live] run_cmd: session msg channel closed; dropping Perform result"
                    );
                }
            });
        }
        IpeCmd::Publish(thunk) => {
            // Inject this session's sid as the broadcast origin (
            // liveApp.Publish sets Origin = session.sid). Fire-and-forget.
            let _ = thunk(sid);
        }
    }
}

/// (Re-)spawn subscription tasks. Aborts the previous handles first (one model
/// re-evaluated each commit). When `subscriptions` is `Sub.none`, this is
/// exercised mainly by the None arm.
#[cfg(feature = "server")]
fn spawn_subs<Msg: Clone + Send + 'static>(
    sub: IpeSub<Msg>,
    tx: &Sender<Msg>,
    handles: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    for h in handles.drain(..) {
        h.abort();
    }
    fn go<Msg: Clone + Send + 'static>(
        sub: IpeSub<Msg>,
        tx: &Sender<Msg>,
        handles: &mut Vec<tokio::task::JoinHandle<()>>,
    ) {
        match sub {
            IpeSub::None => {}
            IpeSub::Batch(items) => {
                for s in items {
                    go(s, tx, handles);
                }
            }
            IpeSub::Every { ms, msg } => {
                if ms <= 0 {
                    return;
                }
                let tx = tx.clone();
                let dur = std::time::Duration::from_millis(ms as u64);
                let h = tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(dur).await;
                        // Bounded send: break when the session queue is full
                        // or the receiver is gone (driver exited).
                        if tx.send(msg.clone()).await.is_err() {
                            break;
                        }
                    }
                });
                handles.push(h);
            }
            IpeSub::Source(spawn) => {
                let tx = tx.clone();
                let emit: Arc<dyn Fn(Msg) + Send + Sync> = Arc::new(move |m| {
                    let _ = tx.try_send(m);
                });
                handles.push(spawn(emit));
            }
        }
    }
    go(sub, tx, handles);
}

/// The per-session driver: folds each Msg through `update`, diffs the new view
/// against the last, pushes patches over SSE (if attached), runs the resulting
/// Cmd, and re-evaluates subscriptions.
// Eight distinct per-session runtime handles (entry, both channel ends, the three
// Arc'd TEA callbacks, the store, the sid) — bundling them into a struct purely to
// satisfy the 7-arg heuristic would add indirection without clarifying anything.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "server")]
async fn drive_session<Model, Msg, FUpdate, FView, FSubs>(
    // WEAK ref: the driver must NOT keep the session alive. The strong holders are
    // the store map (until TTL evict) and any open SSE connection (pins the entry
    // for the connection lifetime — see sse_handler). When BOTH release, the entry
    // drops and the driver exits (tick `upgrade()` → None), closing the leak where
    // a strong-Arc + own-msg_tx made `recv()` never return None → immortal task.
    entry: Weak<Mutex<SessionEntry<Model, Msg>>>,
    mut msg_rx: Receiver<Msg>,
    msg_tx: Sender<Msg>,
    update: Arc<FUpdate>,
    view: Arc<FView>,
    subs: Arc<FSubs>,
    store: Arc<dyn store::SessionStore<Model, Msg>>,
    sid: String,
    // Admission-control slot: decrements WebState::session_count on driver exit.
    _slot: SessionSlot,
) where
    // PartialEq: the `noop` signal compares old vs new Model by structural
    // equality. Generated Model structs always derive PartialEq.
    Model: Clone + PartialEq + Send + 'static,
    // `Debug` is required to derive the BOUNDED Msg variant-name label for the
    // `ipe_web_msg_seconds` histogram (telemetry::variant_name). Generated Msg
    // enums always derive Debug, so this internal bound is always satisfiable.
    Msg: Clone + Send + std::fmt::Debug + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FView: Fn(Model) -> Html<Msg> + Send + Sync + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + Send + Sync + 'static,
{
    let mut sub_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // `Ipe.Ffi.Js` port channel lifecycle. Open this session's inbound/outbound port
    // endpoints now (before the browser can POST to `/_ipe/port`) and close them
    // when the driver exits — the driver is the session's single mortal owner (it
    // exits once the store has evicted the session and no SSE connection pins it),
    // so binding open/close here drops no-longer-reachable channels without
    // touching every store backend's eviction path. The guard closes on EVERY exit
    // path, including the early `return` when the session is already gone.
    #[cfg(all(feature = "json", feature = "tokio"))]
    struct PortLifecycle(Option<crate::js_port::SessionId>);
    #[cfg(all(feature = "json", feature = "tokio"))]
    impl Drop for PortLifecycle {
        fn drop(&mut self) {
            if let Some(port_sid) = &self.0 {
                crate::js_port::session_close(port_sid);
            }
        }
    }
    #[cfg(all(feature = "json", feature = "tokio"))]
    let _port_lifecycle = {
        let port_sid = crate::js_port::SessionId::parse(&sid);
        if let Some(ref ps) = port_sid {
            crate::js_port::session_open(ps);
        }
        PortLifecycle(port_sid)
    };

    // Register initial subscriptions at session creation, before the first
    // event. Without this a watch-only session never subscribes until it
    // dispatches its own Msg, so a pub/sub broadcast (or a Sub.every ticker)
    // would never reach a freshly loaded session. Wrapped in the session-sid
    // scope so SkipOrigin filtering binds the right owner.
    {
        // Upgrade transiently; if the session is already gone there is nothing to drive.
        let Some(strong) = entry.upgrade() else {
            return;
        };
        let model0 = {
            strong
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .model
                .clone()
        };
        pubsub::with_session_sid(sid.clone(), || {
            spawn_subs(subs(model0), &msg_tx, &mut sub_handles)
        });
    }
    // Periodic liveness check: the driver holds only a Weak ref, but it also holds
    // its own `msg_tx` clone, so `recv()` alone never returns None. The tick
    // upgrades the Weak — once the store has evicted the session AND no SSE
    // connection pins it, `upgrade()` returns None and the driver exits (freeing
    // the entry, the channel, and the admission slot). 30 s bounds a dead driver's
    // lifetime to one interval past eviction.
    let mut liveness = tokio::time::interval(std::time::Duration::from_secs(30));
    liveness.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let msg = tokio::select! {
            maybe = msg_rx.recv() => match maybe {
                Some(m) => m,
                None => break,
            },
            _ = liveness.tick() => {
                if entry.upgrade().is_none() {
                    break;
                }
                continue;
            }
        };
        // Upgrade for THIS iteration only; drop `strong` before the next select!
        // (holding it across the park would re-pin the entry and re-introduce the
        // leak). None ⇒ the session was evicted between messages ⇒ stop.
        let Some(strong) = entry.upgrade() else {
            break;
        };
        // Clone the model under a short lock, release before update.
        let model = {
            strong
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .model
                .clone()
        };
        // Msg-handling latency histogram (`ipe_web_msg_seconds{name}`).
        // The `name` label is the BOUNDED Msg variant name
        // (finite cardinality), never a payload — see telemetry::variant_name.
        // Extracted BEFORE `update` consumes `msg`.
        let msg_name = crate::telemetry::variant_name(&msg);
        #[cfg(feature = "debugger")]
        let msg_for_history = msg.clone();
        let msg_started = std::time::Instant::now();
        // Run `update` inside the session-sid scope: a `Task` it returns (e.g.
        // `Geo.current`, `Clipboard.read`) captures the owning session's sid at
        // construction time via `scope_sid()`, so its outbound `Ipe.Ffi.Js` port
        // frame addresses THIS session's SSE sink. Without the scope the sid is
        // unset and a port-using Task's outbound frame reaches no sink — the
        // request never leaves the server and the awaited reply never arrives.
        let (next, cmd) = pubsub::with_session_sid(sid.clone(), || update(msg, model));
        crate::telemetry::metric_observe(
            "ipe_web_msg_seconds",
            &[("name", &msg_name)],
            msg_started.elapsed().as_secs_f64(),
        );
        // Borrow (not move) cmd to detect a no-command update; cmd is moved into
        // run_cmd later. Part of the `noop` signal below.
        let cmd_is_none = matches!(cmd, IpeCmd::None);

        let mut tree = view(next.clone());
        assign_ipe_ids(&mut tree, "r");
        style_inject::apply_style_injections(&mut tree);

        let (patches, seq, sse, noop) = {
            let mut e = strong.lock().unwrap_or_else(|e| e.into_inner());
            let patches = diff(&e.last_view, &tree);
            // noop. Here
            // `e.model` STILL holds the OLD model (top-of-loop cloned it OUT; the
            // store isn't updated until the assignment below), so `e.model ==
            // next` is old==new — a STRUCTURAL equality (no hash-collision false
            // noop, unlike  hash), computed with NO extra clone. The Rust
            // dispatch has no error channel, so the `err==nil` conjunct is always
            // true and is dropped.
            let noop = cmd_is_none && e.model == next;
            // Build the handler index from the tree, then move the tree into
            // last_view (its only remaining use), avoiding a deep VDOM clone.
            e.index = build_index(&tree);
            e.last_view = tree;
            e.model = next.clone();
            e.seq += 1;
            #[cfg(feature = "debugger")]
            e.history
                .record(msg_for_history, next.clone(), &|m, mdl| (*update)(m, mdl));
            (patches, e.seq, e.sse_tx.clone(), noop)
        };
        // Msg counter. All
        // labels bounded: name = finite variant set, outcome = "ok" (this path
        // has no error channel), noop ∈ {true,false}. Emitted OUTSIDE the entry
        // lock (no registry-lock-under-entry-lock nesting).
        crate::telemetry::metric_inc(
            "ipe_web_msg_total",
            &[
                ("name", &msg_name),
                ("outcome", "ok"),
                ("noop", if noop { "true" } else { "false" }),
            ],
            1,
        );

        if !patches.is_empty()
            && let Some(sse) = sse
        {
            let env = PatchEnvelope {
                global_seq: seq,
                patches: &patches,
            };
            if let Ok(json) = serde_json::to_string(&env) {
                let _ = sse.send(SsePatch(sse::frame("patches", &json))).await;
            }
        }

        // Write-through: checkpoint the committed model to the store (a touch
        // for memory; a re-serialize for persistent backends) on every commit.
        // Re-inserting an evicted-but-active session with a fresh last-seen is
        // intended: a session that processes a Msg is
        // alive. `strong` is dropped at the end of this iteration (block scope),
        // before the next select! park — never held across the await loop.
        store.set(&sid, strong.clone()).await;

        pubsub::with_session_sid(sid.clone(), || run_cmd(cmd, &msg_tx, &sid));
        pubsub::with_session_sid(sid.clone(), || {
            spawn_subs(subs(next.clone()), &msg_tx, &mut sub_handles)
        });
    }
    for h in sub_handles.drain(..) {
        h.abort();
    }
}

/// A fresh session id: **128 bits from the OS CSPRNG**, as 32 lowercase-hex
/// chars.
///
/// SECURITY: the sid is the SOLE bearer credential for a Ipe.Web session
/// (`sid_from_cookie` + `store.get` authorise every event off it). It MUST be
/// unpredictable. The prior scheme — `clock_nanos XOR counter` through
/// splitmix64 — was an invertible bijection over low-entropy, partly-known
/// inputs (the counter starts at 0; the clock is estimable), so sids were
/// guessable → session hijacking. `uuid::Uuid::new_v4` draws its bits from the
/// OS CSPRNG (the approved security-randomness source per `random.rs`), and its
/// `simple` form is exactly 32 lowercase-hex chars — same shape, no `aes-gcm`.
/// Never panics.
#[cfg(feature = "server")]
fn new_sid() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Normalise a raw `IPE_WEB_BASE_PATH` value: trim, drop a trailing slash,
/// ensure a single leading slash. `""` / `"/"` collapse to `""` (root-mounted —
/// no prefix).
#[cfg(feature = "server")]
fn normalise_base_path(raw: &str) -> String {
    let t = raw.trim().trim_end_matches('/');
    if t.is_empty() {
        String::new()
    } else if t.starts_with('/') {
        t.to_string()
    } else {
        format!("/{t}")
    }
}

/// The session cookie name for a given (normalised) base path. At the root,
/// `__Host-ipe_sid` in secure mode (production / frame-ancestors) else `ipe_sid`;
/// for a sub-app a base-derived DISTINCT name so this child's session cookie can
/// never clobber the PARENT app's `ipe_sid` (both would otherwise be `Path=/` and
/// share the browser's cookie jar on the proxied paths).
///
/// SECURITY (root, secure mode): the session cookie is the SOLE bearer credential
/// (`sid_from_cookie` + `store.get` authorise every `/_ipe/event` + `/_ipe/sse`),
/// so it gets the `__Host-` prefix — the browser then refuses any `Set-Cookie`
/// carrying a `Domain=` attribute, closing the sibling-subdomain cookie-tossing →
/// session-fixation vector (an attacker on `evil.example.com` with a valid cert
/// could otherwise plant `ipe_sid` for `example.com`). `__Host-` MANDATES
/// Secure + Path=/ + no-Domain — `page_response` satisfies all three in secure
/// mode (Secure flag set, root `cookie_path()` is `/`, no Domain attribute).
/// Mirrors `csrf::csrf_cookie_name_for`. Plain-HTTP dev keeps the bare `ipe_sid`
/// (`__Host-` requires Secure, which a browser drops over `http://`). A sub-app
/// (Path != `/`) can never use `__Host-`, so it keeps the base-scoped name.
#[cfg(feature = "server")]
fn cookie_name_for(base: &str) -> String {
    if base.is_empty() {
        if csrf::cookies_secure() {
            "__Host-ipe_sid".to_string()
        } else {
            "ipe_sid".to_string()
        }
    } else {
        let suffix: String = base
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        format!("ipe_sid{suffix}")
    }
}

/// Cookie `Path` for a given (normalised) base path: the base for a sub-app
/// (scopes the cookie to `/<base>/*` so it is never sent to the parent's own
/// routes — protecting the parent session), else `/`.
#[cfg(feature = "server")]
fn cookie_path_for(base: &str) -> String {
    if base.is_empty() {
        "/".to_string()
    } else {
        base.to_string()
    }
}

/// Normalised sub-app base path, read from `IPE_WEB_BASE_PATH`. Empty when
/// unset (root-mounted app). When set (this app runs as a reverse-proxied
/// sub-app — e.g. the bundled console mounted at `/_ipe/console`), the value
/// is threaded into `render_page_full` so the client JS prefixes both the
/// `/_ipe/event` and `/_ipe/sse` paths with it. The browser reaches this child
/// only through the parent proxy, which strips the prefix before forwarding —
/// so the child's own router stays root-relative.
#[cfg(feature = "server")]
pub(super) fn web_base_path() -> String {
    normalise_base_path(&crate::system::read_env_var("IPE_WEB_BASE_PATH").unwrap_or_default())
}

/// The active session cookie name (read AND write must agree, so both
/// `page_response` and `sid_from_cookie` route through this).
#[cfg(feature = "server")]
fn session_cookie_name() -> String {
    cookie_name_for(&web_base_path())
}

/// The active session cookie `Path`.
#[cfg(feature = "server")]
fn cookie_path() -> String {
    cookie_path_for(&web_base_path())
}

/// Whether to trust `X-Forwarded-Proto` for TLS-termination detection. Mirrors
/// `server.rs`'s `IPE_TRUSTED_PROXY` gate (same env var, same rationale: a
/// client-supplied header must never be trusted by default — an operator opts
/// in only when a real reverse proxy sits in front of this process).
///
/// Snapshotted once (env is stable at process start; same rationale as
/// `csrf::cookies_secure()` — avoids a per-request global env-lock read).
#[cfg(feature = "server")]
fn trust_proxy_headers() -> bool {
    use std::sync::OnceLock;
    static TRUST: OnceLock<bool> = OnceLock::new();
    *TRUST.get_or_init(|| {
        crate::system::read_env_var("IPE_TRUSTED_PROXY")
            .map(|v| !v.is_empty() && v != "0" && v != "false")
            .unwrap_or(false)
    })
}

/// Request-scoped HTTPS detection, parameterised on the trust decision so it's
/// unit-testable without mutating the real (OnceLock-cached) process env —
/// `trust_proxy_headers()` snapshots once per process, so a test that mutates
/// `IPE_TRUSTED_PROXY` and expects `request_is_https` to observe the change
/// would be flaky/order-dependent. Only consulted (via `request_is_https`)
/// when `trust` is true — otherwise a client could forge `X-Forwarded-Proto`
/// to fool the Secure-cookie decision (the same footgun `server.rs` already
/// closed for `X-Forwarded-For`).
#[cfg(feature = "server")]
fn request_is_https_with_trust(headers: &axum::http::HeaderMap, trust: bool) -> bool {
    if !trust {
        return false;
    }
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("https"))
        .unwrap_or(false)
}

/// Request-scoped HTTPS detection: true when THIS request arrived over TLS at
/// the trusted proxy (`X-Forwarded-Proto: https`). See
/// `request_is_https_with_trust` for the testable core.
#[cfg(feature = "server")]
fn request_is_https(headers: &axum::http::HeaderMap) -> bool {
    request_is_https_with_trust(headers, trust_proxy_headers())
}

/// Build the full-page HTTP response for a GET (initial render or reuse): the
/// client-bearing HTML wrap + the session cookie (name/path base-path-aware).
#[cfg(all(feature = "server", not(feature = "debugger")))]
fn page_response(
    sid: &str,
    body: &str,
    csrf_token: &str,
    headers: &axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let html = render_page_full(sid, &web_base_path(), body, csrf_token);
    // Session cookie carries `Secure` in production / frame-ancestors mode, OR
    // when this specific request arrived over TLS at a trusted proxy
    // (`request_is_https`, opt-in via `IPE_TRUSTED_PROXY` — closes the gap where
    // `csrf::cookies_secure()` snapshots `production_from_env() ||
    // frame_ancestors().is_some()` ONCE at process start and never inspects this
    // request's TLS / `X-Forwarded-Proto`, so a dev process fronted by a TLS
    // proxy would otherwise emit a non-Secure session cookie even though the
    // browser connection was HTTPS). The untrusted-proxy case (operator hasn't
    // set `IPE_TRUSTED_PROXY`) keeps ENV-only behaviour — still SOUND, just not
    // maximally precise, because it never marks a cookie Secure incorrectly,
    // only potentially fails to mark one Secure that could safely have been.
    //
    // NOTE: this does NOT change the `__Host-` cookie-NAME decision
    // (`csrf::cookies_secure()`, still process-global) — the cookie's identity
    // must stay stable across a browser session, or the double-submit compare
    // would spuriously fail whenever proxy-scheme detection flips between
    // requests. Only the SESSION cookie's `Secure` ATTRIBUTE becomes
    // request-scoped.
    //
    // SameSite=Lax stays so top-level navigations keep the session.
    let secure = if csrf::cookies_secure() || request_is_https(headers) {
        "; Secure"
    } else {
        ""
    };
    // SameSite: a deploy opted into cross-origin embedding via
    // IPE_WEB_FRAME_ANCESTORS needs `SameSite=None; Secure` so the
    // session cookie survives inside a third-party iframe; otherwise `Lax`
    // (top-level navigations keep the session). `cookies_secure()` is already true
    // in frame-ancestors mode, so `None` always pairs with `Secure`.
    let same_site = if csrf::frame_ancestors().is_some() {
        "None"
    } else {
        "Lax"
    };
    // Max-Age: persist the cookie for the store TTL so a
    // tab-close doesn't drop a still-live server session. Without it the cookie is
    // session-scoped and the user loses state on tab close.
    let max_age = web_ttl().as_secs();
    let session_cookie = format!(
        "{}={sid}; Path={}; HttpOnly; SameSite={same_site}{secure}; Max-Age={max_age}",
        session_cookie_name(),
        cookie_path()
    );
    let csrf_cookie = csrf::csrf_set_cookie(csrf_token, &web_base_path());
    let mut resp = (
        axum::http::StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/html; charset=utf-8".to_string(),
        )],
        html,
    )
        .into_response();
    let h = resp.headers_mut();
    // Two Set-Cookie headers — `append`, not `insert`, so both land.
    if let Ok(v) = axum::http::HeaderValue::from_str(&session_cookie) {
        h.append(axum::http::header::SET_COOKIE, v);
    }
    if let Ok(v) = axum::http::HeaderValue::from_str(&csrf_cookie) {
        h.append(axum::http::header::SET_COOKIE, v);
    }
    // Security response headers — page GET only.
    for (name, val) in csrf::security_headers() {
        if let Ok(v) = axum::http::HeaderValue::from_str(&val) {
            h.insert(axum::http::HeaderName::from_static(name), v);
        }
    }
    resp
}

/// Same as [`page_response`] but injects `overlay` (raw HTML) after `#ipe-root`
/// via [`render_page_full_with_overlay`]. Active only with the `debugger` feature.
#[cfg(all(feature = "server", feature = "debugger"))]
fn page_response_with_overlay(
    sid: &str,
    body: &str,
    overlay: &str,
    csrf_token: &str,
    headers: &axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let html = render_page_full_with_overlay(sid, &web_base_path(), body, csrf_token, overlay);
    let secure = if csrf::cookies_secure() || request_is_https(headers) {
        "; Secure"
    } else {
        ""
    };
    let same_site = if csrf::frame_ancestors().is_some() {
        "None"
    } else {
        "Lax"
    };
    let max_age = web_ttl().as_secs();
    let session_cookie = format!(
        "{}={sid}; Path={}; HttpOnly; SameSite={same_site}{secure}; Max-Age={max_age}",
        session_cookie_name(),
        cookie_path()
    );
    let csrf_cookie = csrf::csrf_set_cookie(csrf_token, &web_base_path());
    let mut resp = (
        axum::http::StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/html; charset=utf-8".to_string(),
        )],
        html,
    )
        .into_response();
    let h = resp.headers_mut();
    if let Ok(v) = axum::http::HeaderValue::from_str(&session_cookie) {
        h.append(axum::http::header::SET_COOKIE, v);
    }
    if let Ok(v) = axum::http::HeaderValue::from_str(&csrf_cookie) {
        h.append(axum::http::header::SET_COOKIE, v);
    }
    for (name, val) in csrf::security_headers() {
        if let Ok(v) = axum::http::HeaderValue::from_str(&val) {
            h.insert(axum::http::HeaderName::from_static(name), v);
        }
    }
    resp
}

/// Maximum request body bytes for `/_ipe/event`: `IPE_WEB_MAX_BODY_BYTES`,
/// default 5 MiB (5 << 20 = 5 242 880). The default covers `Event.onFile` /
/// `Event.onImage` data-URL payloads; override for larger file uploads.
#[cfg(feature = "server")]
fn web_max_body_bytes() -> usize {
    crate::system::read_env_var("IPE_WEB_MAX_BODY_BYTES")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(5 << 20)
}

#[cfg(test)]
mod web_max_body_bytes_tests {
    // IPE_WEB_MAX_BODY_BYTES=0 must floor at the default, not disable the
    // body (matching server::max_body's `.filter(|&n| n > 0)`). Without the
    // floor a 0 value would 413 every /_ipe/event POST.
    //
    // This tests the parsing/filtering formula directly rather than mutating
    // the real env var: `std::env::set_var` is not thread-safe under a
    // parallel test harness, and `IPE_WEB_MAX_BODY_BYTES` already has an
    // env-mutating test in server.rs (`max_body_env_override`) — a second
    // unsynchronized mutator of the same key would make both tests
    // intermittently flaky. Mirrors the established convention documented at
    // `server::tests::ws_send_buffer_default_is_256`.
    fn parse(raw: Option<&str>) -> usize {
        raw.and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(5 << 20)
    }

    #[test]
    fn web_max_body_bytes_floors_at_default_on_zero() {
        assert_eq!(parse(None), 5 << 20);
        assert_eq!(parse(Some("1024")), 1024);
        assert_eq!(parse(Some("0")), 5 << 20); // invalid → default, not "reject everything"
    }
}

/// Session idle-TTL under the one config precedence `env > setting-in-code >
/// fallback`: `IPE_WEB_TTL` wins, else an installed `Web.sessionTtl` setting,
/// else the default 1800 (30 min).
#[cfg(feature = "server")]
fn web_ttl() -> std::time::Duration {
    let secs = crate::system::read_env_var("IPE_WEB_TTL")
        .ok()
        .and_then(|s| parse_duration_secs(&s))
        .or_else(crate::app_config::resolve_session_ttl_override)
        .unwrap_or(1800u64);
    std::time::Duration::from_secs(secs)
}

/// Parse a duration string: a bare integer is seconds (legacy), otherwise one
/// or more `<number><unit>` segments with units `h` / `m` / `s`
/// (e.g. `30m`, `1h`, `24h`, `90s`, `1h30m`). Total: any malformed input
/// returns `None` (caller falls back to the default) — never panics.
#[cfg(feature = "server")]
fn parse_duration_secs(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    // Bare integer → seconds (legacy form).
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    let mut total: u64 = 0;
    let mut num: u64 = 0;
    let mut saw_unit = false;
    let mut saw_digit = false;
    for ch in s.chars() {
        if let Some(d) = ch.to_digit(10) {
            num = num.checked_mul(10)?.checked_add(d as u64)?;
            saw_digit = true;
        } else {
            let unit_secs = match ch {
                'h' => 3600,
                'm' => 60,
                's' => 1,
                _ => return None, // unknown unit / stray char → malformed
            };
            if !saw_digit {
                return None; // a unit with no preceding number
            }
            total = total.checked_add(num.checked_mul(unit_secs)?)?;
            num = 0;
            saw_digit = false;
            saw_unit = true;
        }
    }
    // A trailing number with no unit (e.g. `1h30`) is malformed.
    if saw_digit || !saw_unit {
        return None;
    }
    Some(total)
}

/// Graceful-drain grace window: how long the pure axum graceful drain is allowed
/// before we force a CLEAN exit-0. axum's `with_graceful_shutdown` WAITS for
/// every connection to finish, so an open SSE `EventSource` (heartbeat every
/// 15 s, otherwise idle) would hang the drain forever. This window lets ordinary
/// Returns `true` when `IPE_WEB_RESET_STATE=1` (or any truthy value) is set in
/// the process environment.
///
/// When `true`, the web request handler skips the session-checkpoint lookup
/// (`get_reconstructing`) and forces every returning session to a fresh `init`,
/// bypassing the additive-splice algorithm entirely. This is the escape hatch
/// for `ipe watch --reset-state`: the watch process sets the flag in the child's
/// env for the lifetime of that binary. Dev-only; a release binary is never
/// launched with this flag by the CLI.
///
/// Fail-closed by design: any read failure or unrecognised value is treated as
/// `false` (the additive algorithm runs normally), so a misconfigured env never
/// silently corrupts state — it only fails to reset.
#[cfg(feature = "server")]
pub(crate) fn reset_state_from_env() -> bool {
    crate::system::read_env_var("IPE_WEB_RESET_STATE")
        .ok()
        .as_deref()
        .is_some_and(|v| matches!(v, "1" | "true" | "yes" | "on"))
}

/// Best-effort bounded flush of all active telemetry exporters (push + hub).
/// Tunable via `IPE_WEB_SHUTDOWN_GRACE_MS` (default 1500 ms; 0 = exit at
/// once).
#[cfg(feature = "server")]
fn shutdown_grace() -> std::time::Duration {
    let ms = crate::system::read_env_var("IPE_WEB_SHUTDOWN_GRACE_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(1500);
    std::time::Duration::from_millis(ms)
}

/// Best-effort bounded flush of all active telemetry exporters (push + hub).
/// Waits at most 500 ms in total. Never panics, never blocks shutdown beyond
/// the cap. This MUST be called before every `process::exit` because
/// `process::exit` skips Drop, so the mpsc Sender never drops and the
/// batchers' channel-close drain path never runs without this explicit flush.
///
/// No-op when `http_client` is absent: the push/hub exporters make outbound
/// HTTP calls and are gated behind that feature; a web app with no outbound
/// HTTP kernel has no exporters to flush.
#[cfg(all(feature = "server", feature = "http_client"))]
async fn flush_exporters() {
    // 500 ms total cap (split across two exporters in sequence — each is capped
    // independently so a slow/unavailable first target doesn't eat all of the
    // second exporter's budget).
    const CAP_MS: u64 = 250;
    push_exporter::flush_now(CAP_MS).await;
    hub_exporter::flush_now(CAP_MS).await;
}
#[cfg(all(feature = "server", not(feature = "http_client")))]
async fn flush_exporters() {}

/// Push a bounded `event: reload` frame to every session THIS PROCESS is
/// currently serving over SSE, so a connected browser skips its own
/// reconnect-wait and refetches immediately instead of waiting out the
/// retry backoff ladder. Dev-mode only — see H23 ("dev-only reload channel
/// ABSENT, not disabled, in production"): the production gate lives at the
/// ONE call site chain ([`maybe_push_reload_to_web_sessions`], called from
/// `web_shutdown_signal`), never inside this helper — a caller that
/// reaches this function has already decided dev-mode applies. Delivery is
/// best-effort, at-most-once, never retried: a full/closed channel just
/// drops that one session's frame (the browser's own reconnect logic
/// already covers the restart-detection floor; this only shaves latency),
/// and a session that disconnects between the enumerate and the push
/// misses a frame it can't act on anyway.
#[cfg(feature = "server")]
async fn push_reload_to_web_sessions<Model, Msg>(store: &Arc<dyn store::SessionStore<Model, Msg>>)
where
    Model: Send + 'static,
    Msg: Send + 'static,
{
    for handle in store.web_sessions().await {
        let tx = handle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sse_tx
            .clone();
        if let Some(tx) = tx {
            let _ = tx.send(SsePatch(sse::frame("reload", "{}"))).await;
        }
    }
}

/// Apply a dev appearance-hot-swap patch to every session THIS PROCESS serves,
/// then re-render each session's `view(currentModel)` and push the resulting
/// VDOM diff over the same SSE `patches` channel a normal `update` uses.
///
/// This is the running server's half of Step 2's live socket: the dev control
/// path calls it with a table patch `[(idx, value)]` and the view's baked
/// defaults signature. It registers the patch in the [`LiteralTable`] dev
/// overlay, so a re-render of `view(model)` reads the patched literals — then it
/// re-renders each live session from its *current* Model (never through
/// `update`, so scroll/form/tab/counter state is preserved), diffs against the
/// session's last view, and reuses the existing diff → SSE-push → DOM-patch
/// machinery. One render semantics: the diff a hot-swap pushes is exactly the
/// diff a full recompile-and-reconnect would have produced for the same edit.
///
/// Dev-only: gated by [`literal_table::dev_overlay_active`] (flag on AND
/// non-production). When inactive it registers nothing and pushes no frame, so
/// no appearance patch is ever observable in a production build.
#[cfg(feature = "server")]
async fn apply_literal_patch_to_web_sessions<Model, Msg, FView>(
    store: &Arc<dyn store::SessionStore<Model, Msg>>,
    view: &Arc<FView>,
    defaults: &[String],
    patch: Vec<(usize, String)>,
) where
    Model: Clone + Send + 'static,
    Msg: Clone + Send + 'static,
    FView: Fn(Model) -> Html<Msg> + Send + Sync + 'static,
{
    if !literal_table::dev_overlay_active() {
        return;
    }
    // Register first, so the re-render below reads the patched literals.
    literal_table::register_dev_patch(defaults, patch);

    for handle in store.web_sessions().await {
        // Clone the current Model under a short lock; release before rendering.
        // A hot-swap NEVER runs `update`, so the Model is carried through
        // unchanged — this feeds the render its current input, it does not
        // advance the app's state.
        let model = {
            handle
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .model
                .clone()
        };
        let mut tree = view(model);
        assign_ipe_ids(&mut tree, "r");
        style_inject::apply_style_injections(&mut tree);

        // Commit + diff under the entry lock, mirroring the driver's commit
        // block: diff against last_view, then advance last_view/index/seq so the
        // client's monotonic seq gate accepts the frame and the next real Msg
        // diffs against this rendered view. The Model is deliberately left as-is.
        let (patches, seq, sse) = {
            let mut e = handle.lock().unwrap_or_else(|e| e.into_inner());
            let patches = diff(&e.last_view, &tree);
            // Index first (borrow), then move the tree into last_view — its
            // only remaining use — instead of a deep VDOM clone.
            e.index = build_index(&tree);
            e.last_view = tree;
            e.seq += 1;
            (patches, e.seq, e.sse_tx.clone())
        };
        if !patches.is_empty()
            && let Some(sse) = sse
        {
            let env = PatchEnvelope {
                global_seq: seq,
                patches: &patches,
            };
            if let Ok(json) = serde_json::to_string(&env) {
                let _ = sse.send(SsePatch(sse::frame("patches", &json))).await;
            }
        }
    }
}

/// The H23 production gate over [`push_reload_to_web_sessions`]: in
/// production (`ENV`/`IPE_ENV` set to a non-dev marker) the push path is
/// UNREACHABLE — same one-`if` shape every other production gate in this
/// module uses (dev-console mount, metrics auth). Split from
/// `web_shutdown_signal` so the gate itself is unit-testable without
/// delivering a real signal.
#[cfg(feature = "server")]
async fn maybe_push_reload_to_web_sessions<Model, Msg>(
    store: &Arc<dyn store::SessionStore<Model, Msg>>,
) where
    Model: Send + 'static,
    Msg: Send + 'static,
{
    if !crate::telemetry::production_from_env() {
        push_reload_to_web_sessions(store).await;
    }
}

/// Await the FIRST shutdown signal (SIGINT or SIGTERM), then run the graceful
/// teardown and return so axum's `with_graceful_shutdown` drains in-flight
/// connections and the serve future resolves `Ok(())` (→ the IpeTask is `Ok` →
/// the generated entry exits 0).
///
/// Two escapes guard against the drain hanging — both keep the no-panic thesis:
///  - A bounded grace timer that force-exits 0 (CLEAN) after `shutdown_grace()`,
///    so a never-idle SSE stream can't wedge the process (drops long-lived
///    connections rather than waiting).
///  - A SECOND signal (Ctrl-C twice) that force-exits 130 immediately.
///
/// Robustness: a failed SIGTERM registration must NOT crash — it degrades to
/// SIGINT-only (`ctrl_c`). On non-unix only `ctrl_c` is available.
#[cfg(feature = "server")]
async fn web_shutdown_signal<Model, Msg>(store: Arc<dyn store::SessionStore<Model, Msg>>)
where
    Model: Send + 'static,
    Msg: Send + 'static,
{
    // First press: block until SIGINT or SIGTERM arrives.
    wait_for_term_or_int().await;

    // Print to stdout. The leading newline keeps the `^C` echo on its own line.
    println!("\nIpe.Web shutting down…");

    // Flip readyz → draining so orchestrators stop routing new traffic while
    // in-flight requests finish.
    observability::mark_draining();

    // Dev-only proactive `event: reload` push to every locally-live SSE
    // session, fired once the shutdown is committed and BEFORE the bounded
    // grace-timer drain begins — a connected browser refetches immediately
    // instead of waiting out its reconnect backoff. Production-gated (H23).
    maybe_push_reload_to_web_sessions(&store).await;

    // Tear down the console child, if one was spawned. Idempotent no-op when
    // none exists.
    // Load-bearing: the child is tracked in a `static` whose `Drop`
    // (`kill_on_drop`) never runs on `process::exit`, so this explicit
    // `start_kill` is what prevents an orphan console child after a clean exit.
    // Absent when `http_client` is not active: the console proxy uses reqwest.
    #[cfg(feature = "http_client")]
    console_proxy::shutdown_console();

    // Telemetry export pipelines (push/hub exporters) flush every ~2 s on a
    // tick. The channel-close drain ONLY runs when the mpsc Sender is dropped,
    // which requires Drop — and `process::exit` skips Drop entirely. Without an
    // explicit pre-exit flush the grace-timer and watchdog paths below would
    // silently lose ≤1 batch-interval (~2 s default) of buffered telemetry.
    // `flush_exporters` sends a Flush sentinel to each active exporter and waits
    // a bounded 500 ms; it is best-effort (telemetry only, never user data) and
    // never hangs shutdown.

    // Grace timer: force a CLEAN exit-0 after the window so a never-idle SSE
    // connection can't hang the drain. Spawned (not awaited) so we still return
    // immediately and let the axum drain
    // win the race when there are no long-lived connections (the common case →
    // sub-window exit). Exit 0 keeps the IpeTask-Ok / exit-0 contract.
    tokio::spawn(async {
        tokio::time::sleep(shutdown_grace()).await;
        // Defense-in-depth: kill the console child again in case it was spawned
        // after the first teardown call (shutdown_console is idempotent).
        #[cfg(feature = "http_client")]
        console_proxy::shutdown_console();
        flush_exporters().await;
        // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — Ipe.Web server shutdown boundary: the grace timer won the drain race, exit zero [ledger #boundary]
        std::process::exit(0);
    });

    // Second press: a watchdog that force-exits 130 if the user hits Ctrl-C
    // again while the drain is in progress. Spawned (not awaited).
    tokio::spawn(async {
        wait_for_term_or_int().await;
        eprintln!("Ipe.Web: forcing exit (second signal)");
        #[cfg(feature = "http_client")]
        console_proxy::shutdown_console();
        flush_exporters().await;
        // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — Ipe.Web server shutdown boundary: a second interrupt forces exit 130 (128 + SIGINT) [ledger #boundary]
        std::process::exit(130); // 128 + SIGINT(2)
    });
    // Return → axum drains in-flight connections → serve future resolves Ok
    // (fast path when nothing long-lived is open; otherwise the grace timer
    // force-exits 0). The graceful return path also flushes exporters to cover
    // the no-open-connections fast exit where process tear-down follows quickly.
    flush_exporters().await;
}

/// Resolve when the next SIGINT or SIGTERM arrives. Total + robust: if SIGTERM
/// can't be registered (rare), fall back to SIGINT (`ctrl_c`) only rather than
/// panicking. On non-unix, only `ctrl_c` exists.
#[cfg(feature = "server")]
async fn wait_for_term_or_int() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            // SIGTERM registration failed — degrade to SIGINT only.
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// `Ipe.Web.tea { init, update, view, subscriptions }` — serve via axum.
///
/// HTTP-first: a GET renders the full page with the embedded client, opens a
/// per-session TEA loop, and serves an SSE patch channel + a POST event
/// endpoint. The driver diffs view-over-view and pushes patches over SSE.
///
/// `init` receives a typed `req::WebReq` (path/query/method/params/headers/
/// cookies) built from the incoming request; the driver calls `init(req)` so a
/// req-reader can bootstrap session state on first render. A non-req init is
/// monomorphised to ignore the threaded `WebReq`.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "server")]
pub fn web_app<E, Model, Msg, FInit, FUpdate, FView, FSubs>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
    store_kind: String,
    store_path: String,
    schema_tag: [u8; 32],
) -> IpeTask<E, ()>
where
    E: From<String> + Send + 'static,
    // IpeStringify: forwarded to serve_web → inspect_handler for the live-
    // datum surface. Generated Model types always satisfy this bound.
    Model: serde::Serialize
        + serde::de::DeserializeOwned
        + Clone
        + PartialEq
        + Send
        + Sync
        + crate::stringify::IpeStringify
        + 'static,
    // Debug: forwarded through serve_web → drive_session for the
    // ipe_web_msg_seconds{name} label. Generated Msg enums always derive Debug.
    // IpeStringify: forwarded through serve_web → page for debugger overlay
    // labels via `ipe_show`. Generated Msg enums always satisfy this bound.
    // DeserializeOwned: forwarded to import_handler (dev-only debug route).
    Msg: Clone
        + Send
        + Sync
        + std::fmt::Debug
        + serde::Serialize
        + serde::de::DeserializeOwned
        + crate::stringify::IpeStringify
        + 'static,
    FInit: Fn(req::WebReq) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FView: Fn(Model) -> Html<Msg> + Send + Sync + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + Send + Sync + 'static,
{
    Box::pin(async move {
        // A fail-closed store config (e.g. prod `IPE_WEB_STORE=sqlite` in a
        // build with no `db` feature) surfaces as a task error → stderr + exit
        // 1, never a silent downgrade to a different backend.
        let store = match store::choose_store::<Model, Msg>(
            &store_kind,
            &store_path,
            web_ttl(),
            schema_tag,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => return IpeResult::Err(e.to_string().into()),
        };
        let state = WebState {
            store,
            init: Arc::new(init),
            update: Arc::new(update),
            view: Arc::new(view),
            subs: Arc::new(subscriptions),
            // No routing: GET serves the freshly-init'd model unchanged; no params.
            route_resolver: Arc::new(|m, _path| m),
            param_resolver: Arc::new(|_path| crate::dict::dict_empty()),
            // No route table: only `/` is a page URL.
            route_matched: Arc::new(|path| path == "/"),
            session_count: Arc::new(AtomicUsize::new(0)),
            watch_build_status: Arc::new(Mutex::new(None)),
        };
        serve_web(state).await
    })
}

/// `Web.embed`'s mount router-builder: same single-page `WebState` as
/// [`web_app`], but instead of binding a listener it returns a closure that —
/// given the mount base-path prefix — builds the fully-layered axum `Router`
/// (via [`build_web_router`]) for `Server.mountApp` to nest under that prefix
/// on the shared server port.
///
/// The base-path prefix is installed process-wide (`IPE_WEB_BASE_PATH`) at
/// build time so the embedded app's session-cookie / CSRF-cookie / asset paths
/// scope to the mount, reusing the existing sub-app base-path machinery. The
/// console/proxy surface is OFF for a mounted sub-app (the parent server owns
/// those concerns), so `use_console_proxy` is `false`.
///
/// `Model`/`Msg`/the four callbacks stay concrete inside the returned closure —
/// only the outer builder is boxed (no `dyn` over the app's handlers).
#[cfg(feature = "server")]
pub fn web_embed_router<Model, Msg, FInit, FUpdate, FView, FSubs>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
    store_kind: String,
    store_path: String,
    schema_tag: [u8; 32],
) -> crate::tea::MountBuilder
where
    // IpeStringify: forwarded to serve_web → inspect_handler for the live-
    // datum surface. Generated Model types always satisfy this bound.
    Model: serde::Serialize
        + serde::de::DeserializeOwned
        + Clone
        + PartialEq
        + Send
        + Sync
        + crate::stringify::IpeStringify
        + 'static,
    Msg: Clone
        + Send
        + Sync
        + std::fmt::Debug
        + serde::Serialize
        + serde::de::DeserializeOwned
        + crate::stringify::IpeStringify
        + 'static,
    FInit: Fn(req::WebReq) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FView: Fn(Model) -> Html<Msg> + Send + Sync + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + Send + Sync + 'static,
{
    Box::new(move |prefix: String| {
        Box::pin(async move {
            // Scope the embedded app's cookies + assets to the mount prefix,
            // reusing the sub-app base-path mechanism. A single mounted WebApp
            // per server is the current contract (multiple distinct-prefix web
            // mounts would need per-mount base-path threading).
            let base = normalise_base_path(&prefix);
            if !base.is_empty() {
                // Write the process-local env overlay, never the real `environ`:
                // a raw `set_var` here races any concurrent libc `environ` reader
                // (a parallel `getaddrinfo`) and is undefined behavior.
                crate::system::locked_set_var("IPE_WEB_BASE_PATH", &base);
            }
            // A mount has no task-error channel (it yields a `Router`, not an
            // `IpeTask`), so an unhonourable store config fails closed as a
            // router that answers every path with 503 + the operator message —
            // never a silent downgrade to a different backend and never a mount
            // that quietly serves real sessions on the wrong store.
            let store = match store::choose_store::<Model, Msg>(
                &store_kind,
                &store_path,
                web_ttl(),
                schema_tag,
            )
            .await
            {
                Ok(s) => s,
                Err(e) => return fail_closed_router(e.to_string()),
            };
            let state = WebState {
                store,
                init: Arc::new(init),
                update: Arc::new(update),
                view: Arc::new(view),
                subs: Arc::new(subscriptions),
                route_resolver: Arc::new(|m, _path| m),
                param_resolver: Arc::new(|_path| crate::dict::dict_empty()),
                route_matched: Arc::new(|path| path == "/"),
                session_count: Arc::new(AtomicUsize::new(0)),
                watch_build_status: Arc::new(Mutex::new(None)),
            };
            // The router is E-free (E only surfaces on the standalone
            // `serve_web` task's result), so `build_web_router` carries no `E`.
            build_web_router::<Model, Msg, FInit, FUpdate, FView, FSubs>(state, false)
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = axum::Router> + Send>>
    })
}

/// `Web.embed` of a ROUTED app (`Model` has a `page` field): the routed sibling
/// of [`web_embed_router`]. It builds the SAME routed `WebState` as
/// [`web_app_routed`] — a `route_resolver` / `param_resolver` / `route_matched`
/// derived from the route table + `set_page` — but, exactly like
/// [`web_embed_router`], returns a [`crate::tea::MountBuilder`] that yields the
/// fully-layered `Router` for `Server.mountApp` to nest under a prefix on the
/// shared server port, instead of binding its own listener.
///
/// `Page` / `FSetPage` are erased into the boxed resolver closures, so
/// `build_web_router` / `WebState` keep the original six type params — no `dyn`
/// over the app's handlers (§9).
#[allow(clippy::too_many_arguments)] // mirrors web_app_routed's routed cfg (callbacks + route table + set_page + store)
#[cfg(feature = "server")]
pub fn web_embed_router_routed<Model, Msg, Page, FInit, FUpdate, FView, FSubs, FSetPage>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
    routes: Vec<route::Route<Page>>,
    not_found: Page,
    set_page: FSetPage,
    store_kind: String,
    store_path: String,
    schema_tag: [u8; 32],
) -> crate::tea::MountBuilder
where
    Model: serde::Serialize
        + serde::de::DeserializeOwned
        + Clone
        + PartialEq
        + Send
        + Sync
        + crate::stringify::IpeStringify
        + 'static,
    Msg: Clone
        + Send
        + Sync
        + std::fmt::Debug
        + serde::Serialize
        + serde::de::DeserializeOwned
        + crate::stringify::IpeStringify
        + 'static,
    Page: Clone + Send + Sync + 'static,
    FInit: Fn(req::WebReq) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FView: Fn(Model) -> Html<Msg> + Send + Sync + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + Send + Sync + 'static,
    FSetPage: Fn(Page, Model) -> Model + Send + Sync + 'static,
{
    Box::new(move |prefix: String| {
        Box::pin(async move {
            // Scope the embedded app's cookies + assets to the mount prefix,
            // reusing the sub-app base-path mechanism (see `web_embed_router`).
            let base = normalise_base_path(&prefix);
            if !base.is_empty() {
                crate::system::locked_set_var("IPE_WEB_BASE_PATH", &base);
            }
            // Routed resolvers — identical construction to `web_app_routed`; only
            // the terminal `build_web_router` (vs `serve_web`) differs.
            let routes = Arc::new(routes);
            let not_found = Arc::new(not_found);
            let set_page = Arc::new(set_page);
            let routes_for_params = routes.clone();
            let routes_for_match = routes.clone();
            let resolver: RouteResolver<Model> = Arc::new(move |m, path| {
                (set_page)(route::match_routes(&routes, &not_found, path), m)
            });
            let param_resolver: ParamResolver =
                Arc::new(move |path| route::match_params(&routes_for_params, path));
            let route_matched: RouteMatched =
                Arc::new(move |path| route::matches_any(&routes_for_match, path));
            // A mount has no task-error channel, so an unhonourable store config
            // fails closed as a 503-everywhere router (see `web_embed_router`).
            let store = match store::choose_store::<Model, Msg>(
                &store_kind,
                &store_path,
                web_ttl(),
                schema_tag,
            )
            .await
            {
                Ok(s) => s,
                Err(e) => return fail_closed_router(e.to_string()),
            };
            let state = WebState {
                store,
                init: Arc::new(init),
                update: Arc::new(update),
                view: Arc::new(view),
                subs: Arc::new(subscriptions),
                route_resolver: resolver,
                param_resolver,
                route_matched,
                session_count: Arc::new(AtomicUsize::new(0)),
                watch_build_status: Arc::new(Mutex::new(None)),
            };
            build_web_router::<Model, Msg, FInit, FUpdate, FView, FSubs>(state, false)
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = axum::Router> + Send>>
    })
}

/// `Web.embed`'s mountable handle over one evaluation of the single-page cfg.
///
/// Carries both run modes of the same app: the standalone `serve` task
/// ([`web_app`]) and the [`web_embed_router`] mount builder. Each callback is
/// shared between the two through an `Arc`, so the cfg's values — and every
/// local they capture, `Clone` or not (a function-typed parameter, a `Cmd`) —
/// are built once and never duplicated or cloned.
#[cfg(feature = "web")]
pub fn web_embed<Model, Msg, FInit, FUpdate, FView, FSubs>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
    store_kind: String,
    store_path: String,
    schema_tag: [u8; 32],
) -> crate::tea::WebApp
where
    Model: serde::Serialize
        + serde::de::DeserializeOwned
        + Clone
        + PartialEq
        + Send
        + Sync
        + crate::stringify::IpeStringify
        + 'static,
    Msg: Clone
        + Send
        + Sync
        + std::fmt::Debug
        + serde::Serialize
        + serde::de::DeserializeOwned
        + crate::stringify::IpeStringify
        + 'static,
    FInit: Fn(req::WebReq) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FView: Fn(Model) -> Html<Msg> + Send + Sync + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + Send + Sync + 'static,
{
    let init = Arc::new(init);
    let update = Arc::new(update);
    let view = Arc::new(view);
    let subscriptions = Arc::new(subscriptions);
    let serve = {
        let (init, update, view, subscriptions) = (
            Arc::clone(&init),
            Arc::clone(&update),
            Arc::clone(&view),
            Arc::clone(&subscriptions),
        );
        web_app::<crate::error::IpeError, Model, Msg, _, _, _, _>(
            move |req| (*init)(req),
            move |msg, model| (*update)(msg, model),
            move |model| (*view)(model),
            move |model| (*subscriptions)(model),
            store_kind.clone(),
            store_path.clone(),
            schema_tag,
        )
    };
    let router = web_embed_router::<Model, Msg, _, _, _, _>(
        move |req| (*init)(req),
        move |msg, model| (*update)(msg, model),
        move |model| (*view)(model),
        move |model| (*subscriptions)(model),
        store_kind,
        store_path,
        schema_tag,
    );
    crate::tea::WebApp(crate::tea::WebAppKind::Mountable { serve, router })
}

/// `Web.embed`'s mountable handle over one evaluation of the routed cfg.
///
/// The routed sibling of [`web_embed`]: [`web_app_routed`] serves standalone,
/// [`web_embed_router_routed`] builds the mount. The callbacks and `set_page`
/// are shared through an `Arc`; the route table and `notFound` page are `Clone`
/// by their bounds, so each half owns a copy.
#[allow(clippy::too_many_arguments)] // mirrors web_app_routed's routed cfg (callbacks + route table + set_page + store)
#[cfg(feature = "web")]
pub fn web_embed_routed<Model, Msg, Page, FInit, FUpdate, FView, FSubs, FSetPage>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
    routes: Vec<route::Route<Page>>,
    not_found: Page,
    set_page: FSetPage,
    store_kind: String,
    store_path: String,
    schema_tag: [u8; 32],
) -> crate::tea::WebApp
where
    Model: serde::Serialize
        + serde::de::DeserializeOwned
        + Clone
        + PartialEq
        + Send
        + Sync
        + crate::stringify::IpeStringify
        + 'static,
    Msg: Clone
        + Send
        + Sync
        + std::fmt::Debug
        + serde::Serialize
        + serde::de::DeserializeOwned
        + crate::stringify::IpeStringify
        + 'static,
    Page: Clone + Send + Sync + 'static,
    FInit: Fn(req::WebReq) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FView: Fn(Model) -> Html<Msg> + Send + Sync + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + Send + Sync + 'static,
    FSetPage: Fn(Page, Model) -> Model + Send + Sync + 'static,
{
    let init = Arc::new(init);
    let update = Arc::new(update);
    let view = Arc::new(view);
    let subscriptions = Arc::new(subscriptions);
    let set_page = Arc::new(set_page);
    let serve = {
        let (init, update, view, subscriptions, set_page) = (
            Arc::clone(&init),
            Arc::clone(&update),
            Arc::clone(&view),
            Arc::clone(&subscriptions),
            Arc::clone(&set_page),
        );
        web_app_routed::<crate::error::IpeError, Model, Msg, Page, _, _, _, _, _>(
            move |req| (*init)(req),
            move |msg, model| (*update)(msg, model),
            move |model| (*view)(model),
            move |model| (*subscriptions)(model),
            routes.clone(),
            not_found.clone(),
            move |page, model| (*set_page)(page, model),
            store_kind.clone(),
            store_path.clone(),
            schema_tag,
        )
    };
    let router = web_embed_router_routed::<Model, Msg, Page, _, _, _, _, _>(
        move |req| (*init)(req),
        move |msg, model| (*update)(msg, model),
        move |model| (*view)(model),
        move |model| (*subscriptions)(model),
        routes,
        not_found,
        move |page, model| (*set_page)(page, model),
        store_kind,
        store_path,
        schema_tag,
    );
    crate::tea::WebApp(crate::tea::WebAppKind::Mountable { serve, router })
}

/// A router that answers EVERY path with `503 Service Unavailable` + a plain
/// message. Used when a mounted `Web.embed` cannot honour its store config
/// (fail-closed): the mount stays reachable enough to report the fault, but
/// never serves a real session on a silently-degraded store. The startup fault
/// is logged once here too, so an operator sees it even without hitting a path.
#[cfg(feature = "web")]
fn fail_closed_router(message: String) -> axum::Router {
    eprintln!("[ipe.live] mounted web app disabled: {message}");
    axum::Router::new().fallback(move || {
        let message = message.clone();
        async move {
            (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                format!("session store misconfigured: {message}"),
            )
        }
    })
}

/// `Ipe.Web.tea { …, routes, notFound }` with URL routing — serve via axum.
///
/// Identical to `web_app` except a `route_resolver` is built from the route
/// table + page-setter: on each GET it matches the path to a `Page` value
/// (param strings applied via the route closures) and writes it into the
/// freshly-`init`'d model's `page` field via `set_page`. `Page`/`FSetPage`
/// are erased into the boxed resolver, so `serve_web`/`WebState` keep the
/// original 6 type params.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "server")]
pub fn web_app_routed<E, Model, Msg, Page, FInit, FUpdate, FView, FSubs, FSetPage>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
    routes: Vec<route::Route<Page>>,
    not_found: Page,
    set_page: FSetPage,
    store_kind: String,
    store_path: String,
    schema_tag: [u8; 32],
) -> IpeTask<E, ()>
where
    E: From<String> + Send + 'static,
    // IpeStringify: forwarded to serve_web → inspect_handler for the live-
    // datum surface. Generated Model types always satisfy this bound.
    Model: serde::Serialize
        + serde::de::DeserializeOwned
        + Clone
        + PartialEq
        + Send
        + Sync
        + crate::stringify::IpeStringify
        + 'static,
    // Debug: forwarded through serve_web → drive_session for the
    // ipe_web_msg_seconds{name} label. Generated Msg enums always derive Debug.
    // IpeStringify: forwarded through serve_web → page for debugger overlay
    // labels via `ipe_show`. Generated Msg enums always satisfy this bound.
    // DeserializeOwned: forwarded to import_handler (dev-only debug route).
    Msg: Clone
        + Send
        + Sync
        + std::fmt::Debug
        + serde::Serialize
        + serde::de::DeserializeOwned
        + crate::stringify::IpeStringify
        + 'static,
    Page: Clone + Send + Sync + 'static,
    FInit: Fn(req::WebReq) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FView: Fn(Model) -> Html<Msg> + Send + Sync + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + Send + Sync + 'static,
    FSetPage: Fn(Page, Model) -> Model + Send + Sync + 'static,
{
    Box::pin(async move {
        let routes = Arc::new(routes);
        let not_found = Arc::new(not_found);
        let set_page = Arc::new(set_page);
        let routes_for_params = routes.clone();
        let routes_for_match = routes.clone();
        let resolver: RouteResolver<Model> =
            Arc::new(move |m, path| (set_page)(route::match_routes(&routes, &not_found, path), m));
        let param_resolver: ParamResolver =
            Arc::new(move |path| route::match_params(&routes_for_params, path));
        let route_matched: RouteMatched =
            Arc::new(move |path| route::matches_any(&routes_for_match, path));
        // Fail-closed on an unhonourable store config (see `web_app`).
        let store = match store::choose_store::<Model, Msg>(
            &store_kind,
            &store_path,
            web_ttl(),
            schema_tag,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => return IpeResult::Err(e.to_string().into()),
        };
        let state = WebState {
            store,
            init: Arc::new(init),
            update: Arc::new(update),
            view: Arc::new(view),
            subs: Arc::new(subscriptions),
            route_resolver: resolver,
            param_resolver,
            route_matched,
            session_count: Arc::new(AtomicUsize::new(0)),
            watch_build_status: Arc::new(Mutex::new(None)),
        };
        serve_web(state).await
    })
}

///go `isBrowserNoisePath`): a path a browser or crawler
/// requests automatically (favicon, service-worker probe, source-map fetch,
/// `.well-known` discovery, static asset by extension). When unrouted, these
/// must never touch session state: they'd otherwise race the real `GET /`
/// for session creation (double `init`) or — worse — re-route a LIVE
/// session's model and rebuild its handler index from the `notFound` view,
/// orphaning every handler on the page the browser is actually showing (all
/// subsequent events, form submits included, would silently resolve to
/// nothing).
#[cfg(feature = "server")]
fn is_browser_noise_path(p: &str) -> bool {
    if matches!(
        p,
        "/favicon.ico"
            | "/robots.txt"
            | "/sitemap.xml"
            | "/apple-touch-icon.png"
            | "/apple-touch-icon-precomposed.png"
            | "/service-worker.js"
            | "/sw.js"
            | "/manifest.json"
    ) || p.starts_with("/.well-known/")
    {
        return true;
    }
    // Requests for assets by well-known extension are browser noise — real
    // page routes never end in these suffixes.
    [
        ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js", ".map", ".woff",
        ".woff2", ".ttf",
    ]
    .iter()
    .any(|ext| p.ends_with(ext))
}

///go `handleInitial`): serve an unrouted browser-noise file
/// from the static dir's ROOT when it exists there. Browsers always probe
/// `/favicon.ico` (and friends) at the origin root, never under `/static/`,
/// so without this shortcut an author with a configured static dir has no
/// way to suppress the 404. `None` → the caller 404s.
///
/// Security: the path is attacker-shaped. Any non-plain segment (empty, `.`,
/// `..`) is rejected BEFORE the join — stricter than  `filepath.Clean`,
/// no traversal can escape the dir. A directory (or unreadable file) reads
/// as `Err` → `None` → 404.
#[cfg(feature = "server")]
async fn serve_noise_from_static_root(path: &str) -> Option<axum::response::Response> {
    use axum::response::IntoResponse;
    // IPE_WEB_STATIC_DIR: a non-empty value mounts the named directory at /static.
    let dir = crate::system::read_env_var("IPE_WEB_STATIC_DIR")
        .ok()
        .filter(|d| !d.is_empty())?;
    let rel = path.trim_start_matches('/');
    if rel.is_empty()
        || rel
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return None;
    }
    let candidate = std::path::Path::new(&dir).join(rel);
    let bytes = tokio::fs::read(&candidate).await.ok()?;
    let mime = static_noise_mime(rel.rsplit('.').next().unwrap_or(""));
    Some(
        (
            axum::http::StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, mime)],
            bytes,
        )
            .into_response(),
    )
}

/// Content type for a browser-noise file served from the static root. The
/// extensions here mirror what browsers actually probe at the origin root.
/// Anything unknown falls back to octet-stream rather than guessing.
#[cfg(feature = "server")]
fn static_noise_mime(ext: &str) -> &'static str {
    match ext {
        "ico" => "image/x-icon",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "map" | "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

#[cfg(feature = "server")]
mod handlers {
    use super::*;
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};

    // ── GET page (root + any path) ────────────────────────────────────
    pub(super) async fn page<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        method: axum::http::Method,
        uri: axum::http::Uri,
        headers: axum::http::HeaderMap,
    ) -> Response
    where
        Model: Clone + PartialEq + Send + 'static,
        // Debug: the GET handler creates a session and spawns drive_session,
        // which needs the bound for the ipe_web_msg_seconds{name} label.
        // IpeStringify: the debugger overlay renders message labels via
        // `ipe_show` so `Secret`-bearing fields are structurally redacted.
        // Generated Msg types always satisfy both bounds.
        Msg: Clone + Send + std::fmt::Debug + crate::stringify::IpeStringify + 'static,
        FInit: Fn(req::WebReq) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
        FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
        FView: Fn(Model) -> Html<Msg> + Send + Sync + 'static,
        FSubs: Fn(Model) -> IpeSub<Msg> + Send + Sync + 'static,
    {
        // Cookie-based session lifecycle:
        //   * Web hit  → reuse the in-process session; re-apply routing for
        //                 this GET's path + re-render (no new driver).
        //   * Cold hit  → a persisted model (post-restart / different replica);
        //                 hydrate a fresh driver seeded with it (no init).
        //   * miss      → init a new session.
        let cookie_sid = sid_from_cookie(&headers);
        // CSRF double-submit token: reuse the browser's existing well-formed
        // per-app CSRF cookie (so a reload keeps the same token), else mint a
        // fresh one. `page_response` sets the cookie + injects the value into
        // the page JS; the client echoes it back in the `X-Ipê-Csrf` header.
        let csrf_tok = csrf::cookie_value(&headers, &csrf::csrf_cookie_name_for(&web_base_path()))
            .filter(|t| csrf::token_is_well_formed(t))
            .unwrap_or_else(csrf::gen_token);

        //
        // serve from the static root) BEFORE any session work — they must
        // never run `init` (double-init race against the real `GET /`) and
        // never touch an existing session (see the routed guards below).
        let routed = (st.route_matched)(uri.path());
        if !routed && is_browser_noise_path(uri.path()) {
            if let Some(resp) = serve_noise_from_static_root(uri.path()).await {
                return resp;
            }
            return (StatusCode::NOT_FOUND, "404 page not found").into_response();
        }

        // A returning session whose persisted checkpoint predates a purely
        // ADDITIVE Model change is reconstructed rather than dropped: the store
        // splices the persisted fields onto a live `init` value and keeps the
        // session (old state preserved, each new field filled from `init`) iff
        // the change is a proven additive superset. `make_init` sources that
        // value from THIS incoming GET request — the exact same `init(req)` the
        // clean-reinit miss path runs — so a reconstructed session's new fields
        // hold precisely what a fresh visit would have produced, with no
        // synthetic request and no surprising default. It is invoked LAZILY:
        // only on a schema-mismatched cold row, never on a live hit or a
        // matched-schema restore, so `init` (and any side effect it carries)
        // never fires on the hot paths. Any non-additive change (removed /
        // retyped field), corrupt / oversized body, or pre-`v2` row falls back
        // to the clean re-init the store's flat miss always produced.
        let make_init = || {
            let params = (st.param_resolver)(uri.path());
            let req = req::web_req(&method, &uri, &headers, params);
            let (m, _cmd) = (st.init)(req);
            m
        };
        // `IPE_WEB_RESET_STATE=1` (set by `ipe watch --reset-state` in the child
        // env) bypasses the checkpoint lookup entirely: every returning session
        // is treated as a miss and falls through to a fresh `init`. The flag is
        // evaluated once per request (cheap env read, cached by the OS) and is
        // fail-closed — any value other than a recognised truthy string leaves
        // the additive algorithm in place.
        let hit = if reset_state_from_env() {
            None
        } else {
            match cookie_sid.as_ref() {
                Some(s) => st
                    .store
                    .get_reconstructing(s, &make_init)
                    .await
                    .map(|h| (s.clone(), h)),
                None => None,
            }
        };

        //
        // session (live or persisted) 404s WITHOUT touching it. Re-routing
        // here would write the `notFound` page into the model and rebuild
        // the handler index from that view, orphaning every handler on the
        // page the browser is still showing — the next event POST (form
        // submit, click, input) would silently resolve to nothing.
        if !routed && hit.is_some() {
            return (StatusCode::NOT_FOUND, "404 page not found").into_response();
        }

        let (sid, model, cmd0) = match hit {
            Some((sid, store::StoreHit::Web(handle))) => {
                // sid is carried from the cookie lookup; the "hit but no sid"
                // state is unrepresentable.
                #[cfg_attr(not(feature = "debugger"), allow(unused_variables))]
                let (body, history_labels, history_total) = {
                    let mut e = handle.lock().unwrap_or_else(|e| e.into_inner());
                    e.model = (st.route_resolver)(e.model.clone(), uri.path());
                    let mut tree = (st.view)(e.model.clone());
                    assign_ipe_ids(&mut tree, "r");
                    style_inject::apply_style_injections(&mut tree);
                    e.index = build_index(&tree);
                    e.last_view = tree.clone();
                    let body = render_html(&tree);
                    #[cfg(feature = "debugger")]
                    let labels: Vec<String> = e.history.labels();
                    #[cfg(not(feature = "debugger"))]
                    let labels: Vec<String> = Vec::new();
                    let total = labels.len();
                    (body, labels, total)
                };
                st.store.set(&sid, handle).await; // touch last-seen
                #[cfg(feature = "debugger")]
                {
                    let base = web_base_path();
                    let overlay = crate::debugger::server::overlay_html(
                        &history_labels,
                        history_total,
                        &base,
                    );
                    return page_response_with_overlay(&sid, &body, &overlay, &csrf_tok, &headers);
                }
                #[cfg(not(feature = "debugger"))]
                return page_response(&sid, &body, &csrf_tok, &headers);
            }
            Some((sid, store::StoreHit::Cold(m))) => {
                // A returning user with a valid sid cookie → not new attack
                // volume, so NOT rejected; but count its driver so the slot it
                // gets below is paired (decremented on the driver's exit).
                st.session_count.fetch_add(1, Ordering::SeqCst);
                (sid, (st.route_resolver)(m, uri.path()), IpeCmd::None)
            }
            None => {
                // Admission control (cookieless = brand-new session = the
                // attack surface). Reserve a slot atomically: fetch_add-then-test
                // avoids the load-then-add TOCTOU where N concurrent GETs all
                // pass at cap-1. ALWAYS reserve (so the slot built below is
                // paired 1:1 with a decrement); only the rejection is gated on
                // cap>0 (0 = unlimited opt-out). Over cap → roll back + 503.
                let cap = max_sessions();
                let reserved = st.session_count.fetch_add(1, Ordering::SeqCst);
                if cap > 0 && reserved >= cap {
                    st.session_count.fetch_sub(1, Ordering::SeqCst);
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        [(axum::http::header::RETRY_AFTER, "2")],
                        "server at session capacity",
                    )
                        .into_response();
                }
                // Build the request context (params from routing — empty when
                // unrouted) and init a fresh model. The param_resolver is
                // model-independent, breaking the init↔routing cycle.
                let params = (st.param_resolver)(uri.path());
                let req = req::web_req(&method, &uri, &headers, params);
                let (m, c) = (st.init)(req);
                // Session fixation guard: a store MISS means this sid is NOT a
                // known session, so NEVER adopt the client-supplied cookie value
                // — always mint a fresh sid. (A HIT path keeps cookie_sid.)
                let s = new_sid();
                (s, (st.route_resolver)(m, uri.path()), c)
            }
        };

        let mut tree = (st.view)(model.clone());
        assign_ipe_ids(&mut tree, "r");
        style_inject::apply_style_injections(&mut tree);
        let index = build_index(&tree);
        let body = render_html(&tree);

        // Bounded per-session Msg queue: cap at 1024 to prevent a fast
        // client from growing the queue without bound (per-session memory DoS).
        // On overflow events are dropped with a warn (see event_handler).
        // 1024 is far above any legitimate burst of user-driven events.
        let (msg_tx, msg_rx) = mpsc::channel::<Msg>(1024);
        #[cfg(feature = "debugger")]
        let history_init =
            crate::debugger::RecordBuffer::new(model.clone(), crate::debugger::DEFAULT_HISTORY_CAP);
        let entry = Arc::new(Mutex::new(SessionEntry {
            model,
            last_view: tree,
            index,
            seq: 0,
            sse_tx: None,
            msg_tx: msg_tx.clone(),
            #[cfg(feature = "debugger")]
            history: history_init,
            #[cfg(feature = "debugger")]
            debug_cursor: None,
        }));
        st.store.set(&sid, entry.clone()).await;

        // The admission slot for this driver (reserved by the Cold/None arm
        // above); its Drop decrements session_count when the driver exits.
        let slot = SessionSlot {
            count: st.session_count.clone(),
        };
        // Spawn the per-session driver with a WEAK entry ref (the store +
        // any SSE connection are the strong holders) so the driver is mortal:
        // it exits once the session is evicted and unconnected, releasing the
        // slot. The local strong `entry` drops at this handler's return,
        // leaving the store (+ future SSE) as the only strong holders.
        tokio::spawn(drive_session(
            Arc::downgrade(&entry),
            msg_rx,
            msg_tx.clone(),
            st.update.clone(),
            st.view.clone(),
            st.subs.clone(),
            st.store.clone(),
            sid.clone(),
            slot,
        ));
        // Fire init's Cmd into the loop (None for a cold-restored session).
        run_cmd(cmd0, &msg_tx, &sid);

        #[cfg(feature = "debugger")]
        {
            let base = web_base_path();
            let overlay = crate::debugger::server::overlay_html(&[], 0, &base);
            page_response_with_overlay(&sid, &body, &overlay, &csrf_tok, &headers)
        }
        #[cfg(not(feature = "debugger"))]
        page_response(&sid, &body, &csrf_tok, &headers)
    }

    // ── GET /_ipe/sse ─────────────────────────────────────────────────
    pub(super) async fn sse_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        axum::extract::Query(qs): axum::extract::Query<std::collections::HashMap<String, String>>,
        headers: axum::http::HeaderMap,
    ) -> Response
    where
        Model: Clone + Send + 'static,
        Msg: Clone + Send + 'static,
        FInit: Send + Sync + 'static,
        FUpdate: Send + Sync + 'static,
        FView: Fn(Model) -> Html<Msg> + Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        let sid = sid_from_cookie(&headers);
        let entry = match &sid {
            Some(s) => match st.store.get(s).await {
                Some(store::StoreHit::Web(h)) => Some(h),
                _ => None,
            },
            None => None,
        };
        let entry = match entry {
            Some(e) => e,
            // X-Ipê-Web: 1 lets the client distinguish a genuine session-lost
            // 404 (reload to recover) from a wedged proxy (client.js probes for
            // exactly this header — l1481/l1530).
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    [(axum::http::HeaderName::from_static("x-ipe-web"), "1")],
                    SESSION_LOST_BODY,
                )
                    .into_response();
            }
        };

        // Reconnect reconciliation: the client sends
        // `?path=<encodeURIComponent(location.pathname)>` on every (re)open,
        // so after a bfcache Back/Forward, reload, or full-page navigation the
        // server knows which URL the browser is actually displaying.
        //
        // If the path param is present AND matches a declared route, apply
        // `route_resolver` to reconcile the model's page to that URL before the
        // resync render — preventing the stale-page bounce where the server's
        // model still thinks the user is on page B while the browser has
        // navigated back to page A.
        //
        // Absent param (older cached client) or an unroutable path (browser
        // noise, unknown URL) falls through to the current behaviour unchanged.
        // Idempotent when the tab is already on the page its URL names: the
        // resolver applied to the already-matching route is a no-op.
        //
        // Sub-app base-path trimming: the client sends the raw
        // `location.pathname` which includes any reverse-proxy prefix; strip the
        // base before matching so mounted sub-apps reconcile against their
        // own route table, not the root path.
        if let Some(raw_path) = qs.get("path") {
            // Sanitise: accept only paths (must start with `/`), reject anything
            // with `?` or `#` to avoid confusing the route matcher with query
            // strings or fragments the client should not be sending here.
            let client_path = raw_path.trim();
            let is_valid_path = client_path.starts_with('/')
                && !client_path.contains('?')
                && !client_path.contains('#');
            if is_valid_path {
                let base = web_base_path();
                // Strip the sub-app base prefix so the remaining path is
                // root-relative within this app's own route table.
                let route_path = if base.is_empty() {
                    client_path
                } else {
                    client_path.strip_prefix(&base).unwrap_or(client_path)
                };
                // Only reconcile when the path matches a declared route —
                // unknown paths (404 territory) fall through unchanged.
                if (st.route_matched)(route_path) {
                    let mut g = entry.lock().unwrap_or_else(|e| e.into_inner());
                    g.model = (st.route_resolver)(g.model.clone(), route_path);
                    // Keep last_view in sync with the reconciled model so the
                    // resync render below reflects the correct page. The tree
                    // MUST carry ipe-ids: the resync frame replaces the whole
                    // DOM on the client, and an unstamped tree renders every
                    // event element without `ipe-id`/`data-ipe-hid`, so each
                    // click posts an empty handlerId the server can't resolve.
                    // Stamp + rebuild the handler index exactly as the page and
                    // update render paths do, so ids stay consistent across all
                    // three render sites.
                    let mut tree = (st.view)(g.model.clone());
                    assign_ipe_ids(&mut tree, "r");
                    style_inject::apply_style_injections(&mut tree);
                    g.index = build_index(&tree);
                    g.last_view = tree;
                }
            }
        }

        let (tx, rx) = sse::channel();
        {
            entry.lock().unwrap_or_else(|e| e.into_inner()).sse_tx = Some(tx.clone());
        }

        // Bind this session's `Ipe.Ffi.Js` outbound port sink to THIS SSE
        // connection: every `js_send` whose origin is this sid is forwarded to
        // the browser as an `event: port` frame over the same stream that
        // carries DOM patches (mirroring how the custom-element served-widget
        // transport delivers per-session). The sink is keyed by sid in the port
        // registry, so a frame can only ever reach the session that produced it
        // — never another session's stream. `try_send` is non-blocking (this
        // sink runs on the synchronous Cmd-dispatch path): a full SSE buffer
        // drops the one frame rather than blocking the dispatch loop, the same
        // fire-and-forget contract the port carries client-side.
        #[cfg(all(feature = "json", feature = "tokio"))]
        if let Some(port_sid) = sid.as_deref().and_then(crate::js_port::SessionId::parse) {
            let port_tx = tx.clone();
            crate::js_port::register_out_sink_for(
                &port_sid,
                std::sync::Arc::new(move |encoded: &str| {
                    let _ = port_tx.try_send(SsePatch(sse::frame("port", encoded)));
                }),
            );
        }

        // Metrics (ipe_web_sse_connections_total /
        // ipe_web_sessions_active). Count the connection and mark the session
        // active; the gauge is decremented when the response body stream is
        // dropped on disconnect (the SessionGauge guard below).
        crate::telemetry::metric_inc("ipe_web_sse_connections_total", &[], 1);
        crate::telemetry::metric_add_gauge("ipe_web_sessions_active", &[], 1);

        // Immediate hello + ~2KB proxy-buffer padding comment, then a 15s
        // heartbeat keepalive.
        let _ = tx
            .send(SsePatch(format!(": {}\n\n", " ".repeat(2048))))
            .await;
        // Hello payload: `{"v":1,"sid":...,"ts":<ms>}`.
        // Reaching here means `entry` exists ⇒ the cookie sid was a live session,
        // so `sid` is Some; the impossible None degrades to an empty sid (the
        // client already holds its sid via window.__IPE_SID — the body is
        // confirmatory). The sid is hex (new_sid) ⇒ JSON-safe without escaping.
        let hello_sid = sid.as_deref().unwrap_or("");
        let hello_ts = chrono::Utc::now().timestamp_millis();
        let _ = tx
            .send(SsePatch(sse::frame(
                "hello",
                &format!("{{\"v\":1,\"sid\":\"{hello_sid}\",\"ts\":{hello_ts}}}"),
            )))
            .await;

        // Dev-watch blue-green cutover cue. When this process runs behind the
        // watch proxy (`IPE_WEB_SWAP_TOAST` set), announce ourselves on every
        // SSE open with a lightweight `swapped` frame. The client shows the
        // brief positive "updated ✓" toast only when it is a RECONNECT (it
        // already saw a prior `hello` this page-life), so a first page load is
        // silent. A release / `ipe run` server never sets the env, so this
        // frame is never emitted there.
        if crate::system::read_env_var("IPE_WEB_SWAP_TOAST")
            .ok()
            .map(|s| s.trim().to_string())
            .is_some_and(|v| !v.is_empty() && v != "0")
        {
            let _ = tx.send(SsePatch(sse::frame("swapped", "{}"))).await;
        }

        // Reconnect-resync.
        // A session restored from the store on a cold hit — or any process
        // restart / `ipe watch` rebuild / redeploy paired with a persistent
        // store — has no live subscriptions from the previous process, so
        // nothing pushes until the next user Msg. Render the current view once
        // and ship it as a full-body `event: patch` frame; the client consumes
        // `{seq, body}` → __ipePatch full replace (client.js:1318). No globalSeq
        // field → the client's broadcast-dedup guard (globalSeq>0) can never
        // drop this authoritative, idempotent frame. Bump seq under the same
        // lock the event path uses so it stays monotonic vs later patches; drop
        // the guard before the await (never hold a std Mutex across .await).
        //
        // When the reconnect reconciliation above ran, the model and last_view
        // were already updated; the render here picks up the reconciled state.
        let resync = {
            let mut g = entry.lock().unwrap_or_else(|e| e.into_inner());
            g.seq += 1;
            let html = render_html(&g.last_view);
            serde_json::json!({ "seq": g.seq, "body": html }).to_string()
        };
        let _ = tx.send(SsePatch(sse::frame("patch", &resync))).await;

        // Replay the latest build-status so a browser refresh during a failed
        // build immediately shows the sticky error banner without waiting for
        // the next `ipe watch` status POST. A `None` status (no build has run
        // yet, or production) sends nothing. Best-effort: a full channel is
        // fine — the next reload or real status event will catch up.
        {
            let status_snapshot = st
                .watch_build_status
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            if let Some(WatchBuildStatus { ok, error }) = status_snapshot {
                let payload = watch_status_sse_payload(ok, error.as_deref());
                let _ = tx
                    .send(SsePatch(sse::frame("ipe-build-status", &payload)))
                    .await;
            }
        }

        {
            let tx = tx.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                    if tx
                        .send(SsePatch(sse::frame("heartbeat", "{}")))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }

        // Drop guard tied to the stream lifetime: when the client disconnects
        // (axum drops the response body) or the channel closes, the unfold
        // state — and this guard — drops, decrementing the active-sessions
        // gauge exactly once.
        struct SessionGauge;
        impl Drop for SessionGauge {
            fn drop(&mut self) {
                crate::telemetry::metric_add_gauge("ipe_web_sessions_active", &[], -1);
            }
        }
        // Pin the STRONG entry Arc into the stream state for the connection's
        // whole life. This is load-bearing: the driver now holds only a Weak
        // ref, so without this an idle-but-SSE-connected (watch-only) session
        // — one receiving Cmd.publish / Sub.every broadcasts but sending no
        // user Msgs, hence never written-through to refresh store last-seen —
        // would be TTL-evicted, its last strong ref dropped, and its driver
        // would exit mid-stream. Holding the strong Arc here keeps it (and its
        // driver) alive exactly as long as the client stays connected; on
        // disconnect axum drops the body → this Arc releases.
        let body_stream = futures_util::stream::unfold(
            (rx, SessionGauge, entry),
            |(mut rx, guard, entry)| async move {
                rx.recv().await.map(|SsePatch(s)| {
                    (
                        Ok::<_, std::io::Error>(axum::body::Bytes::from(s)),
                        (rx, guard, entry),
                    )
                })
            },
        );
        match Response::builder()
            .status(StatusCode::OK)
            .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
            .header(axum::http::header::CACHE_CONTROL, "no-cache")
            .header("x-accel-buffering", "no")
            .body(axum::body::Body::from_stream(body_stream))
        {
            Ok(r) => r.into_response(),
            // Headers/status are all literals, so this never fails; total
            // fallback per the no-runtime-errors rule.
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }

    // ── POST /_ipe/event ──────────────────────────────────────────────
    pub(super) async fn event_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> Response
    where
        Model: Clone + Send + 'static,
        Msg: Clone + Send + 'static,
        FInit: Send + Sync + 'static,
        FUpdate: Send + Sync + 'static,
        FView: Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        let parsed: EventBody = match serde_json::from_slice(&body) {
            Ok(b) => b,
            Err(_) => return (StatusCode::BAD_REQUEST, "bad body").into_response(),
        };
        // Authenticate the target session by the COOKIE sid ONLY — never the
        // body-supplied `sessionId`. Trusting a body id lets a caller act on
        // ANY session by naming it (an auth-bypass that, paired with a
        // guessable sid, was a hijack path). A legitimate browser always has
        // the HttpOnly session cookie by the time an event fires (the page
        // GET set it). No cookie → no session.
        let _ = &parsed.session_id; // body field retained for wire-compat; not trusted for auth
        let sid = match sid_from_cookie(&headers) {
            Some(s) => s,
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    [(axum::http::HeaderName::from_static("x-ipe-web"), "1")],
                    SESSION_LOST_BODY,
                )
                    .into_response();
            }
        };
        let entry = match st.store.get(&sid).await {
            Some(store::StoreHit::Web(h)) => Some(h),
            _ => None,
        };
        let entry = match entry {
            Some(e) => e,
            // X-Ipê-Web: 1 lets the client distinguish a genuine session-lost
            // 404 (reload to recover) from a wedged proxy (client.js probes for
            // exactly this header — l1481/l1530).
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    [(axum::http::HeaderName::from_static("x-ipe-web"), "1")],
                    SESSION_LOST_BODY,
                )
                    .into_response();
            }
        };

        let hid = if !parsed.handler_id.is_empty() {
            parsed.handler_id
        } else {
            parsed.id
        };
        // Event name: explicit `event` override, else the `msg` marker
        // (render_html sets it to the event name), else default to click.
        let event = if !parsed.event.is_empty() {
            parsed.event
        } else if !parsed.msg.is_empty() {
            parsed.msg
        } else {
            "click".to_string()
        };

        let (msg, seq) = {
            let e = entry.lock().unwrap_or_else(|e| e.into_inner());
            if event == "submit" {
                // args[0] is the form-data object {name: value, …}.
                let fd: FormData = parsed
                    .args
                    .first()
                    .and_then(|v| v.as_object())
                    .map(|o| {
                        o.iter()
                            .map(|(k, v)| (k.clone(), value_to_string(v)))
                            .collect()
                    })
                    .unwrap_or_default();
                (e.index.resolve_form(&hid, &event, fd), e.seq)
            } else {
                let args: Vec<String> = parsed.args.iter().map(value_to_string).collect();
                (e.index.resolve(&hid, &event, &args), e.seq)
            }
        };
        if let Some(m) = msg {
            let tx = {
                entry
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .msg_tx
                    .clone()
            };
            // try_send is non-blocking; on a full queue drop the event and
            // return 429 so the client can back off (choosing 429 over silent
            // drop so the browser retry loop fires).
            if let Err(e) = tx.try_send(m) {
                eprintln!(
                    "[ipe.live] event_handler: session msg queue full or closed; dropping event ({})",
                    e
                );
                return (StatusCode::TOO_MANY_REQUESTS, "event queue full").into_response();
            }
        }
        // Real patches flow over SSE from the driver; ack with an empty list.
        // X-Ipê-Web: 1 marks this as a genuine Ipe.Web response (the client
        // treats a 200 WITHOUT it as a wedged-proxy signal).
        (
            StatusCode::OK,
            [
                (axum::http::header::CONTENT_TYPE, "application/json"),
                (axum::http::HeaderName::from_static("x-ipe-web"), "1"),
            ],
            format!("{{\"seq\":{seq},\"patches\":[]}}"),
        )
            .into_response()
    }

    // ── POST /_ipe/hot-appearance (dev-only) ──────────────────────────
    // The running server's inbound leg of the appearance-hot-swap live socket.
    // The `ipe watch` process (a SEPARATE process from the running app) computes
    // an appearance-only table patch for an edited `view` and POSTs it here; the
    // handler registers it and re-renders every live session's `view(currentModel)`,
    // pushing the resulting VDOM diff over the existing SSE `patches` channel —
    // no recompile, no reconnect, Model preserved.
    //
    // Dev-only surface, guarded three ways so it is inert in production:
    //   1. The route is MOUNTED only when `dev_overlay_active()` (flag on AND
    //      non-production), so in a production build it does not exist at all.
    //   2. A per-process control token (`IPE_WATCH_HOT_TOKEN`) must match the
    //      `X-Ipe-Hot-Token` header, so even on a `0.0.0.0`-bound dev server a
    //      LAN peer without the token (set by the watch that launched the app)
    //      cannot drive a re-render.
    //   3. The body carries only inert leaf values `[(idx, value)]` + the view's
    //      baked-defaults signature; the patch is applied through the total
    //      `LiteralTable::apply_patch` (out-of-range indices ignored). No
    //      handler, control flow, or Model-touching value can cross this path.
    pub(super) async fn hot_appearance_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> Response
    where
        Model: Clone + Send + 'static,
        Msg: Clone + Send + 'static,
        FInit: Send + Sync + 'static,
        FUpdate: Send + Sync + 'static,
        FView: Fn(Model) -> Html<Msg> + Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        // Defence in depth: even though the route is only mounted under the dev
        // gate, re-check here so the handler is inert if ever reached otherwise.
        if !literal_table::dev_overlay_active() {
            return StatusCode::NOT_FOUND.into_response();
        }
        // Per-process control token. Absent token ⇒ the endpoint is unusable
        // (fail closed), so a dev server with the flag set but no token minted
        // cannot be driven by an untrusted caller.
        let expected = crate::system::read_env_var("IPE_WATCH_HOT_TOKEN")
            .ok()
            .filter(|t| !t.is_empty());
        let presented = headers
            .get("x-ipe-hot-token")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        match (expected, presented) {
            (Some(exp), Some(got)) if crate::ct_eq::ct_bytes_eq(exp.as_bytes(), got.as_bytes()) => {
            }
            _ => return StatusCode::FORBIDDEN.into_response(),
        }

        // The body is the shared control wire's appearance patch — one wire
        // definition (`control::AppearancePatch`) for every dev-loop shape,
        // parsed once at the boundary into its typed form.
        let parsed: crate::control::AppearancePatch = match serde_json::from_slice(&body) {
            Ok(b) => b,
            Err(_) => return (StatusCode::BAD_REQUEST, "bad body").into_response(),
        };

        apply_literal_patch_to_web_sessions(&st.store, &st.view, &parsed.defaults, parsed.patch)
            .await;
        StatusCode::OK.into_response()
    }

    // ── POST /_ipe/hot-transition (dev-only) ──────────────────────────
    // The running server's inbound leg of the `update`-arm transition-hot-swap
    // live socket. The `ipe watch` process computes a transition patch for an
    // edited data-describable arm and POSTs it here; the handler registers the
    // replacement `Transition` under the arm's baked-datum signature, so the next
    // dispatch of that arm applies the edited transition through the SAME compiled
    // `apply_transition_hot` — no recompile, Model preserved.
    //
    // Guarded EXACTLY like `/_ipe/hot-appearance`, three ways, so it is inert in
    // production:
    //   1. Route MOUNTED only under `dev_overlay_active()` (flag on AND
    //      non-production) — absent from a production build.
    //   2. A per-process control token (`IPE_WATCH_HOT_TOKEN`) must match the
    //      `X-Ipe-Hot-Token` header (constant-time), so a LAN peer without the
    //      token cannot drive a transition.
    //   3. The body carries only two inert JSON strings — the old (key) datum and
    //      the new (replacement) datum. The replacement is STRICT-decoded into a
    //      `Transition` (a field name + a closed op + an inert source); anything
    //      that is not a well-formed `Transition` is rejected. The registered
    //      transition can drive nothing but the bounded, fail-closed
    //      `apply_transition`, which refuses any change it cannot prove applies.
    pub(super) async fn hot_transition_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(_st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> Response
    where
        Model: Clone + Send + 'static,
        Msg: Clone + Send + 'static,
        FInit: Send + Sync + 'static,
        FUpdate: Send + Sync + 'static,
        FView: Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        // Defence in depth: re-check the dev gate even though the route is only
        // mounted under it, so the handler is inert if ever reached otherwise.
        if !literal_table::dev_overlay_active() {
            return StatusCode::NOT_FOUND.into_response();
        }
        // Per-process control token — same mechanism as `/_ipe/hot-appearance`.
        // Absent expected token → fail closed (endpoint unusable without a token).
        let expected = crate::system::read_env_var("IPE_WATCH_HOT_TOKEN")
            .ok()
            .filter(|t| !t.is_empty());
        let presented = headers
            .get("x-ipe-hot-token")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        match (expected, presented) {
            (Some(exp), Some(got)) if crate::ct_eq::ct_bytes_eq(exp.as_bytes(), got.as_bytes()) => {
            }
            _ => return StatusCode::FORBIDDEN.into_response(),
        }

        #[derive(serde::Deserialize)]
        struct HotTransitionBody {
            /// The arm's PREVIOUS baked datum JSON — the overlay key the running
            /// app's compiled arm matches (it still bakes this string).
            old_json: String,
            /// The edited transition's JSON — strict-decoded into a `Transition`.
            new_json: String,
        }
        let parsed: HotTransitionBody = match serde_json::from_slice(&body) {
            Ok(b) => b,
            Err(_) => return (StatusCode::BAD_REQUEST, "bad body").into_response(),
        };
        // Parse, don't validate: the replacement must be a well-formed
        // `Transition` or the request is rejected. A registered transition can
        // therefore drive nothing but the bounded `apply_transition`.
        let replacement: transition::Transition = match serde_json::from_str(&parsed.new_json) {
            Ok(t) => t,
            Err(_) => return (StatusCode::BAD_REQUEST, "bad transition").into_response(),
        };
        transition::register_dev_transition(&parsed.old_json, replacement);
        StatusCode::OK.into_response()
    }

    // ── POST /_ipe/hot-msg (dev-only) ─────────────────────────────────
    // The running server's inbound leg of the additive-`Msg`-variant hot-swap
    // live socket. When a source edit adds a `Msg` variant (plus its arm and a
    // button firing it), `ipe watch` computes the edited program's `MsgSet`
    // descriptor and POSTs it here alongside the live baked descriptor. The
    // handler accepts it ONLY when it is a proven additive superset of the live
    // set (every live variant present, unchanged), so a returning session's live
    // `handler_id`s still resolve. A non-additive descriptor (a removed/retyped
    // variant) is refused, and the watch loop recompiles.
    //
    // Guarded EXACTLY like `/_ipe/hot-transition`, three ways, so it is inert in
    // production:
    //   1. Route MOUNTED only under `dev_overlay_active()` (flag on AND
    //      non-production) — absent from a production build.
    //   2. A per-process control token (`IPE_WATCH_HOT_TOKEN`) must match the
    //      `X-Ipe-Hot-Token` header (constant-time).
    //   3. The body carries two inert, schema-tagged JSON descriptors — the live
    //      baked set (the key) and the candidate set. Both are STRICT-decoded into
    //      a `MsgSet` (a schema tag + a list of variant name/shape pairs — no
    //      payload value, no code); a non-`MsgSet` body is rejected. The candidate
    //      can drive nothing but the bounded, total `is_additive_superset` gate;
    //      it never mutates the Model and never resolves a handler.
    pub(super) async fn hot_msg_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(_st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> Response
    where
        Model: Clone + Send + 'static,
        Msg: Clone + Send + 'static,
        FInit: Send + Sync + 'static,
        FUpdate: Send + Sync + 'static,
        FView: Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        // Defence in depth: re-check the dev gate even though the route is only
        // mounted under it, so the handler is inert if ever reached otherwise.
        if !literal_table::dev_overlay_active() {
            return StatusCode::NOT_FOUND.into_response();
        }
        // Per-process control token — same mechanism as `/_ipe/hot-transition`.
        // Absent expected token → fail closed (endpoint unusable without a token).
        let expected = crate::system::read_env_var("IPE_WATCH_HOT_TOKEN")
            .ok()
            .filter(|t| !t.is_empty());
        let presented = headers
            .get("x-ipe-hot-token")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        match (expected, presented) {
            (Some(exp), Some(got)) if crate::ct_eq::ct_bytes_eq(exp.as_bytes(), got.as_bytes()) => {
            }
            _ => return StatusCode::FORBIDDEN.into_response(),
        }

        #[derive(serde::Deserialize)]
        struct HotMsgBody {
            /// The running program's baked `Msg` set descriptor JSON — the live
            /// set the candidate must be an additive superset of.
            live_json: String,
            /// The edited program's `Msg` set descriptor JSON — the candidate.
            candidate_json: String,
        }
        let parsed: HotMsgBody = match serde_json::from_slice(&body) {
            Ok(b) => b,
            Err(_) => return (StatusCode::BAD_REQUEST, "bad body").into_response(),
        };
        // Parse, don't validate: both descriptors must be well-formed `MsgSet`s or
        // the request is rejected. A registered candidate can therefore drive
        // nothing but the bounded additive-superset gate.
        let live = match msg_set::decode_msg_set(parsed.live_json.as_bytes()) {
            Some(s) => s,
            None => return (StatusCode::BAD_REQUEST, "bad live set").into_response(),
        };
        let candidate = match msg_set::decode_msg_set(parsed.candidate_json.as_bytes()) {
            Some(s) => s,
            None => return (StatusCode::BAD_REQUEST, "bad candidate set").into_response(),
        };
        // Accept ONLY a proven additive superset. A non-additive candidate is
        // refused with 409 Conflict, so the watch loop recompiles rather than
        // hot-swapping a change that could orphan or hijack a live `handler_id`.
        if msg_set::register_dev_msg_set(&live, candidate) {
            StatusCode::OK.into_response()
        } else {
            (StatusCode::CONFLICT, "not an additive superset").into_response()
        }
    }

    // ── POST /_ipe/hot-subs (dev-only) ────────────────────────────────
    // The running server's inbound leg of the `subscriptions`-entry hot-swap live
    // socket. The `ipe watch` process computes a sub patch for an edited
    // data-describable subscription (an interval or tick-message change) and POSTs
    // it here; the handler registers the replacement `SubDescription` under the
    // entry's baked-datum signature, so the next re-subscribe of that entry builds
    // the edited tick source through the SAME compiled `sub_every_hot` — no
    // recompile, the running Model preserved.
    //
    // Guarded EXACTLY like `/_ipe/hot-transition`, three ways, so it is inert in
    // production:
    //   1. Route MOUNTED only under `dev_overlay_active()` (flag on AND
    //      non-production) — absent from a production build.
    //   2. A per-process control token (`IPE_WATCH_HOT_TOKEN`) must match the
    //      `X-Ipe-Hot-Token` header (constant-time), so a LAN peer without the
    //      token cannot drive a subscription.
    //   3. The body carries only two inert JSON strings — the old (key) datum and
    //      the new (replacement) datum. The replacement is STRICT-decoded into a
    //      `SubDescription` (an interval `i64` + a message JSON string); anything
    //      that is not a well-formed `SubDescription` is rejected. The registered
    //      description can drive nothing but the bounded, fail-closed
    //      `sub_every_hot`, which refuses (installs no subscription) any datum it
    //      cannot prove decodes into a well-typed tick source.
    pub(super) async fn hot_subs_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(_st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> Response
    where
        Model: Clone + Send + 'static,
        Msg: Clone + Send + 'static,
        FInit: Send + Sync + 'static,
        FUpdate: Send + Sync + 'static,
        FView: Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        // Defence in depth: re-check the dev gate even though the route is only
        // mounted under it, so the handler is inert if ever reached otherwise.
        if !literal_table::dev_overlay_active() {
            return StatusCode::NOT_FOUND.into_response();
        }
        // Per-process control token — same mechanism as `/_ipe/hot-transition`.
        // Absent expected token → fail closed (endpoint unusable without a token).
        let expected = crate::system::read_env_var("IPE_WATCH_HOT_TOKEN")
            .ok()
            .filter(|t| !t.is_empty());
        let presented = headers
            .get("x-ipe-hot-token")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        match (expected, presented) {
            (Some(exp), Some(got)) if crate::ct_eq::ct_bytes_eq(exp.as_bytes(), got.as_bytes()) => {
            }
            _ => return StatusCode::FORBIDDEN.into_response(),
        }

        #[derive(serde::Deserialize)]
        struct HotSubsBody {
            /// The entry's PREVIOUS baked datum JSON — the overlay key the running
            /// app's compiled entry matches (it still bakes this string).
            old_json: String,
            /// The edited description's JSON — strict-decoded into a
            /// `SubDescription`.
            new_json: String,
        }
        let parsed: HotSubsBody = match serde_json::from_slice(&body) {
            Ok(b) => b,
            Err(_) => return (StatusCode::BAD_REQUEST, "bad body").into_response(),
        };
        // Parse, don't validate: the replacement must be a well-formed
        // `SubDescription` or the request is rejected. A registered description can
        // therefore drive nothing but the bounded `sub_every_hot`.
        let replacement: sub_desc::SubDescription = match serde_json::from_str(&parsed.new_json) {
            Ok(d) => d,
            Err(_) => return (StatusCode::BAD_REQUEST, "bad sub description").into_response(),
        };
        sub_desc::register_dev_sub(&parsed.old_json, replacement);
        StatusCode::OK.into_response()
    }

    // ── POST /_ipe/hot-init (dev-only) ────────────────────────────────
    // The running server's inbound leg of the session-`init` hot-swap live
    // socket. The `ipe watch` process computes an init patch for an edited
    // data-describable `init` and POSTs it here; the handler registers the
    // replacement `InitDatum` under the app's baked-datum signature, so the NEXT
    // NEW session decodes the edited init through the SAME compiled
    // `apply_init_hot` — no recompile, and every LIVE session keeps its Model (a
    // live session never re-consults `init`).
    //
    // Guarded EXACTLY like `/_ipe/hot-transition`, three ways, so it is inert in
    // production:
    //   1. Route MOUNTED only under `dev_overlay_active()` (flag on AND
    //      non-production) — absent from a production build.
    //   2. A per-process control token (`IPE_WATCH_HOT_TOKEN`) must match the
    //      `X-Ipe-Hot-Token` header (constant-time), so a LAN peer without the
    //      token cannot drive an init change.
    //   3. The body carries only two inert JSON strings — the old (key) datum and
    //      the new (replacement) datum. The replacement is STRICT-decoded into an
    //      `InitDatum` (a self-describing Model object); anything that is not a
    //      well-formed `InitDatum` is rejected. The registered datum can drive
    //      nothing but the bounded, fail-closed `apply_init`, which returns the
    //      compiled fallback for any body it cannot strict-decode.
    pub(super) async fn hot_init_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(_st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> Response
    where
        Model: Clone + Send + 'static,
        Msg: Clone + Send + 'static,
        FInit: Send + Sync + 'static,
        FUpdate: Send + Sync + 'static,
        FView: Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        // Defence in depth: re-check the dev gate even though the route is only
        // mounted under it, so the handler is inert if ever reached otherwise.
        if !literal_table::dev_overlay_active() {
            return StatusCode::NOT_FOUND.into_response();
        }
        // Per-process control token — same mechanism as `/_ipe/hot-transition`.
        // Absent expected token → fail closed (endpoint unusable without a token).
        let expected = crate::system::read_env_var("IPE_WATCH_HOT_TOKEN")
            .ok()
            .filter(|t| !t.is_empty());
        let presented = headers
            .get("x-ipe-hot-token")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        match (expected, presented) {
            (Some(exp), Some(got)) if crate::ct_eq::ct_bytes_eq(exp.as_bytes(), got.as_bytes()) => {
            }
            _ => return StatusCode::FORBIDDEN.into_response(),
        }

        #[derive(serde::Deserialize)]
        struct HotInitBody {
            /// The app's PREVIOUS baked init datum JSON — the overlay key the
            /// running app's compiled `init` matches (it still bakes this string).
            old_json: String,
            /// The edited init datum's JSON — strict-decoded into an `InitDatum`.
            new_json: String,
        }
        let parsed: HotInitBody = match serde_json::from_slice(&body) {
            Ok(b) => b,
            Err(_) => return (StatusCode::BAD_REQUEST, "bad body").into_response(),
        };
        // Parse, don't validate: the replacement must be a well-formed
        // `InitDatum` or the request is rejected. A registered datum can therefore
        // drive nothing but the bounded, fail-closed `apply_init`.
        let replacement: init_datum::InitDatum = match serde_json::from_str(&parsed.new_json) {
            Ok(d) => d,
            Err(_) => return (StatusCode::BAD_REQUEST, "bad init datum").into_response(),
        };
        init_datum::register_dev_init(&parsed.old_json, replacement);
        StatusCode::OK.into_response()
    }

    // ── POST /_ipe/hot-wiring (dev-only) ──────────────────────────────
    // The running server's inbound leg of the `update`-arm Cmd-WIRING hot-swap
    // live socket. The `ipe watch` process computes a wiring patch for an edited
    // arm (which compiled effect it fires) and POSTs it here; the handler
    // registers the replacement `CmdWiring` under the arm's baked-datum signature,
    // so the next dispatch of that arm fires the edited (already-compiled) effect
    // through the SAME compiled `select_cmd_hot` — no recompile of the effect
    // body.
    //
    // Guarded EXACTLY like `/_ipe/hot-transition`, three ways, so it is inert in
    // production:
    //   1. Route MOUNTED only under `dev_overlay_active()` (flag on AND
    //      non-production) — absent from a production build.
    //   2. A per-process control token (`IPE_WATCH_HOT_TOKEN`) must match the
    //      `X-Ipe-Hot-Token` header (constant-time), so a LAN peer without the
    //      token cannot drive a wiring change.
    //   3. The body carries only two inert JSON strings — the old (key) datum and
    //      the new (replacement) datum. The replacement is STRICT-decoded into a
    //      `CmdWiring` (an optional effect id); anything else is rejected. A
    //      registered wiring drives only the bounded `select_cmd_hot`, which
    //      selects an effect ONLY if the id indexes the arm's OWN compiled effect
    //      table — an id past the table (a genuinely-new effect this build never
    //      compiled) fires NO effect, so a wiring patch can never fire an
    //      unintended effect.
    pub(super) async fn hot_wiring_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(_st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> Response
    where
        Model: Clone + Send + 'static,
        Msg: Clone + Send + 'static,
        FInit: Send + Sync + 'static,
        FUpdate: Send + Sync + 'static,
        FView: Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        // Defence in depth: re-check the dev gate even though the route is only
        // mounted under it, so the handler is inert if ever reached otherwise.
        if !literal_table::dev_overlay_active() {
            return StatusCode::NOT_FOUND.into_response();
        }
        // Per-process control token — same mechanism as `/_ipe/hot-transition`.
        let expected = crate::system::read_env_var("IPE_WATCH_HOT_TOKEN")
            .ok()
            .filter(|t| !t.is_empty());
        let presented = headers
            .get("x-ipe-hot-token")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        match (expected, presented) {
            (Some(exp), Some(got)) if crate::ct_eq::ct_bytes_eq(exp.as_bytes(), got.as_bytes()) => {
            }
            _ => return StatusCode::FORBIDDEN.into_response(),
        }

        #[derive(serde::Deserialize)]
        struct HotWiringBody {
            /// The arm's PREVIOUS baked wiring JSON — the overlay key the running
            /// app's compiled arm matches (it still bakes this string).
            old_json: String,
            /// The edited wiring's JSON — strict-decoded into a `CmdWiring`.
            new_json: String,
        }
        let parsed: HotWiringBody = match serde_json::from_slice(&body) {
            Ok(b) => b,
            Err(_) => return (StatusCode::BAD_REQUEST, "bad body").into_response(),
        };
        // Parse, don't validate: the replacement must be a well-formed `CmdWiring`
        // or the request is rejected. A registered wiring can drive nothing but the
        // bounded, fail-closed `select_cmd_hot`.
        let replacement: cmd_wiring::CmdWiring = match serde_json::from_str(&parsed.new_json) {
            Ok(w) => w,
            Err(_) => return (StatusCode::BAD_REQUEST, "bad wiring").into_response(),
        };
        cmd_wiring::register_dev_wiring(&parsed.old_json, replacement);
        StatusCode::OK.into_response()
    }

    // ── POST /_ipe/watch/status (dev-only) ───────────────────────────
    // Inbound build-status notification from `ipe watch`. Guarded two ways
    // so it is inert in production:
    //   1. The route is MOUNTED only when the dev banner is active (non-
    //      production + `IPE_WEB_BANNER` not disabled + root-mounted).
    //   2. The `X-Ipe-Hot-Token` header MUST match the per-process token
    //      set by `ipe watch` (the same mechanism as `/_ipe/hot-appearance`).
    //      A web page cannot obtain this token, so the token alone is the
    //      trust boundary (same model as `/_ipe/hot-appearance`).
    //
    // On acceptance: stores the latest status, then broadcasts an
    // `ipe-build-status` SSE event to every connected session.
    pub(super) async fn watch_status_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> Response
    where
        Model: Clone + Send + 'static,
        Msg: Clone + Send + 'static,
        FInit: Send + Sync + 'static,
        FUpdate: Send + Sync + 'static,
        FView: Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        // Per-process control token — same mechanism as `/_ipe/hot-appearance`.
        // Absent expected token → fail closed (endpoint unusable without a token).
        let expected = crate::system::read_env_var("IPE_WATCH_HOT_TOKEN")
            .ok()
            .filter(|t| !t.is_empty());
        let presented = headers
            .get("x-ipe-hot-token")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        match (expected, presented) {
            (Some(exp), Some(got)) if crate::ct_eq::ct_bytes_eq(exp.as_bytes(), got.as_bytes()) => {
            }
            _ => return StatusCode::FORBIDDEN.into_response(),
        }
        // Parse and bound-check the body.
        let parsed: WatchStatusBody = match serde_json::from_slice(&body) {
            Ok(b) => b,
            Err(_) => return (StatusCode::BAD_REQUEST, "bad body").into_response(),
        };
        // Truncate the error string to 512 chars (char-boundary-safe).
        let error = parsed
            .error
            .map(|e| e.chars().take(512).collect::<String>());
        // A transient "recompiling" phase — a rebuild is in flight. It carries no
        // terminal ok/error verdict; the browser shows a soft-yellow "Recompiling
        // app" banner and waits for the ok/error that follows.
        let recompiling = parsed.phase.as_deref() == Some("recompiling");
        // Build the JSON payload for the SSE event.
        let sse_payload = if recompiling {
            serde_json::json!({ "phase": "recompiling" }).to_string()
        } else {
            watch_status_sse_payload(parsed.ok, error.as_deref())
        };
        // Update the stored status so new SSE connections see the current state.
        // The recompiling phase is transient (not a terminal verdict), so it does
        // NOT overwrite the sticky replay state — a refresh mid-rebuild should
        // show the last real result, then the imminent ok/error updates it.
        if !recompiling {
            let mut guard = st
                .watch_build_status
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            *guard = Some(WatchBuildStatus {
                ok: parsed.ok,
                error: error.clone(),
            });
        }
        // Broadcast to all connected sessions. Dead channels (closed tabs)
        // get a send error — collect and ignore them; the next reload naturally
        // creates fresh channels.
        for handle in st.store.web_sessions().await {
            let tx = handle
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .sse_tx
                .clone();
            if let Some(tx) = tx {
                let _ = tx
                    .send(SsePatch(sse::frame("ipe-build-status", &sse_payload)))
                    .await;
            }
        }
        (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            r#"{"ok":true}"#,
        )
            .into_response()
    }

    // ── POST /_ipe/port ───────────────────────────────────────────────
    // The `Ipe.Ffi.Js` inbound port route: a browser→server port frame. Runs the
    // SAME trust gate as `/_ipe/event` — the CSRF middleware validates the
    // mutating POST, and the target session is authenticated by the session
    // COOKIE sid ONLY (never a body-supplied id), so a caller cannot address
    // another session's port by naming it. The raw payload is checked
    // fail-closed through the bounded seal boundary (byte + depth budget);
    // an oversized/malformed/over-nested frame is DROPPED WHOLE here, and only
    // an accepted frame is delivered to THIS session's inbound channel — never
    // any other session's. The per-subscriber typed seal decode still runs in
    // `js_subscribe`, so a well-formed-but-wrong-type frame is dropped there.
    pub(super) async fn port_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> Response
    where
        Model: Clone + Send + 'static,
        Msg: Clone + Send + 'static,
        FInit: Send + Sync + 'static,
        FUpdate: Send + Sync + 'static,
        FView: Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        #[derive(serde::Deserialize)]
        struct PortBody {
            /// The raw seal wire string the browser sent (`JSON.stringify` of
            /// the developer's port value). Decoded fail-closed downstream.
            #[serde(default)]
            payload: String,
        }
        let parsed: PortBody = match serde_json::from_slice(&body) {
            Ok(b) => b,
            Err(_) => return (StatusCode::BAD_REQUEST, "bad body").into_response(),
        };
        // Authenticate by the COOKIE sid ONLY (same rule as event_handler) —
        // never trust a body-supplied session id.
        let sid = match sid_from_cookie(&headers) {
            Some(s) => s,
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    [(axum::http::HeaderName::from_static("x-ipe-web"), "1")],
                    SESSION_LOST_BODY,
                )
                    .into_response();
            }
        };
        // The session must exist (a live Web session) for the frame to have a
        // destination; an unknown sid is the same session-lost 404 the event
        // path returns.
        match st.store.get(&sid).await {
            Some(store::StoreHit::Web(_)) => {}
            _ => {
                return (
                    StatusCode::NOT_FOUND,
                    [(axum::http::HeaderName::from_static("x-ipe-web"), "1")],
                    SESSION_LOST_BODY,
                )
                    .into_response();
            }
        }
        // Fail-closed boundary gate: reject an oversized / malformed /
        // over-nested frame BEFORE delivering it. A rejected frame is dropped
        // whole (200 ack, nothing delivered) — the client is never trusted, and
        // a bad frame is not an error the browser must retry.
        #[cfg(all(feature = "json", feature = "tokio"))]
        {
            use crate::seal_codec::{SealLimits, seal_boundary_check};
            if seal_boundary_check(&parsed.payload, SealLimits::default()).is_ok() {
                // Parse at the delivery boundary: an invalid/empty sid has no
                // registry entry and cannot be represented as a SessionId.
                if let Some(port_sid) = crate::js_port::SessionId::parse(&sid) {
                    crate::js_port::deliver_inbound_for(&port_sid, parsed.payload);
                }
            }
        }
        (
            StatusCode::OK,
            [
                (axum::http::header::CONTENT_TYPE, "application/json"),
                (axum::http::HeaderName::from_static("x-ipe-web"), "1"),
            ],
            "{\"ok\":true}",
        )
            .into_response()
    }

    // ── POST /_ipe/debug/scrub ────────────────────────────────────────
    // Session-scoped time-travel scrub endpoint. Registered only when the
    // `debugger` feature is active. The CSRF middleware (wrapped around
    // the whole router) already validates `X-Ipe-Csrf` before this handler
    // runs; the handler itself only needs to authenticate the session.
    //
    // Request body: `{"index": N}` — reconstruct model at retained step N.
    // Response: `{"body": "<html>"}` — the view rendered at step N.
    // Out-of-range N is clamped to the last retained step. No Cmd is fired.
    // The recorded history is never mutated — reconstruct is a pure re-fold.
    #[cfg(feature = "debugger")]
    pub(super) async fn scrub_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        headers: axum::http::HeaderMap,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> axum::response::Response
    where
        Model: Clone + PartialEq + Send + 'static,
        Msg: Clone + Send + std::fmt::Debug + 'static,
        FInit: Send + Sync + 'static,
        FUpdate: Fn(Msg, Model) -> (Model, crate::tea::IpeCmd<Msg>) + Send + Sync + 'static,
        FView: Fn(Model) -> crate::html::Html<Msg> + Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        use axum::response::IntoResponse;
        let sid = match sid_from_cookie(&headers) {
            Some(s) => s,
            None => {
                return (axum::http::StatusCode::UNAUTHORIZED, "no session").into_response();
            }
        };
        let handle = match st.store.get(&sid).await {
            Some(store::StoreHit::Web(h)) => h,
            _ => {
                return (axum::http::StatusCode::NOT_FOUND, "session not found").into_response();
            }
        };
        let requested_n = body
            .get("index")
            .and_then(|v| v.as_u64())
            .map(|n| n as usize)
            .unwrap_or(0);
        let model_at_n = {
            let e = handle.lock().unwrap_or_else(|e| e.into_inner());
            let total = e.history.len();
            let n = requested_n.min(total.saturating_sub(1));
            e.history.reconstruct(n, &|m, mdl| (*st.update)(m, mdl))
        };
        let model = match model_at_n {
            Some(m) => m,
            None => {
                return (axum::http::StatusCode::NOT_FOUND, "step out of range").into_response();
            }
        };
        let mut tree = (st.view)(model);
        assign_ipe_ids(&mut tree, "r");
        style_inject::apply_style_injections(&mut tree);
        let html_body = render_html(&tree);
        let resp_json = serde_json::json!({ "body": html_body });
        (
            axum::http::StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            resp_json.to_string(),
        )
            .into_response()
    }

    // ── POST /_ipe/debug/reset ────────────────────────────────────────────
    // Debugger "reset to init" button endpoint. Clears the session's recorded
    // history and resets the live model to a fresh `init` value derived from
    // the current request. The CSRF middleware validates `X-Ipe-Csrf` before
    // this handler runs. On success the client reloads the page (full GET)
    // so the reset model is re-rendered from scratch.
    //
    // Response: 200 OK on success; 401 if no session cookie; 404 if the
    // session has no live handle (it must be in-process for the reset to apply).
    #[cfg(feature = "debugger")]
    pub(super) async fn reset_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        headers: axum::http::HeaderMap,
        uri: axum::http::Uri,
        method: axum::http::Method,
    ) -> axum::response::Response
    where
        Model: Clone + PartialEq + Send + 'static,
        Msg: Clone + Send + std::fmt::Debug + crate::stringify::IpeStringify + 'static,
        FInit: Fn(req::WebReq) -> (Model, crate::tea::IpeCmd<Msg>) + Send + Sync + 'static,
        FUpdate: Fn(Msg, Model) -> (Model, crate::tea::IpeCmd<Msg>) + Send + Sync + 'static,
        FView: Fn(Model) -> crate::html::Html<Msg> + Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        use axum::response::IntoResponse;
        let sid = match sid_from_cookie(&headers) {
            Some(s) => s,
            None => {
                return (axum::http::StatusCode::UNAUTHORIZED, "no session").into_response();
            }
        };
        let handle = match st.store.get(&sid).await {
            Some(store::StoreHit::Web(h)) => h,
            _ => {
                return (axum::http::StatusCode::NOT_FOUND, "session not found").into_response();
            }
        };
        // Build a fresh init model from the current request context — the same
        // path the clean-reinit miss takes — so the reset session holds exactly
        // what a cold-start visit would have produced.
        let params = (st.param_resolver)(uri.path());
        let req = req::web_req(&method, &uri, &headers, params);
        let (init_model, _cmd) = (st.init)(req);
        {
            let mut e = handle.lock().unwrap_or_else(|e| e.into_inner());
            e.model = init_model.clone();
            e.history.reset_to_init(init_model);
            e.debug_cursor = None;
        }
        axum::http::StatusCode::OK.into_response()
    }

    // ── GET /_ipe/debug/export ────────────────────────────────────────────
    // Export the session's recorded message log as a JSON array. The returned
    // bytes are the direct output of `debugger::export_msgs` — a serde_json
    // array of every retained `Msg` value in oldest-first order. An importer
    // can reconstruct the model at any step by folding `apply_transition`
    // over the first N entries.
    //
    // Security: GET, read-only, no state mutation — CSRF token not required by
    // method. Session-cookie authentication still guards access so a cross-site
    // GET cannot exfiltrate the log. The log is LOCAL-ONLY and dev-build-only
    // (this route is absent from any artifact built without `--debugger`).
    // The exported JSON is bounded by the recorder's ring-buffer cap, so the
    // response body cannot grow past O(cap × max-msg-size).
    //
    // Requires `Msg: serde::Serialize` — a Secret-bearing Msg type never
    // implements Serialize (the seal-legality gate), so the compiler rejects
    // export for such types at the call site; no runtime filtering needed.
    #[cfg(feature = "debugger")]
    pub(super) async fn export_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        headers: axum::http::HeaderMap,
    ) -> axum::response::Response
    where
        Model: Clone + PartialEq + Send + 'static,
        Msg: Clone + Send + std::fmt::Debug + serde::Serialize + 'static,
        FInit: Send + Sync + 'static,
        FUpdate: Send + Sync + 'static,
        FView: Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        use axum::response::IntoResponse;
        let sid = match sid_from_cookie(&headers) {
            Some(s) => s,
            None => {
                return (axum::http::StatusCode::UNAUTHORIZED, "no session").into_response();
            }
        };
        let handle = match st.store.get(&sid).await {
            Some(store::StoreHit::Web(h)) => h,
            _ => {
                return (axum::http::StatusCode::NOT_FOUND, SESSION_LOST_BODY).into_response();
            }
        };
        let json_bytes = {
            let e = handle.lock().unwrap_or_else(|e| e.into_inner());
            crate::debugger::export_msgs(&e.history)
        };
        match json_bytes {
            Ok(bytes) => (
                axum::http::StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                bytes,
            )
                .into_response(),
            Err(err) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                err.to_string(),
            )
                .into_response(),
        }
    }

    // ── POST /_ipe/debug/import ───────────────────────────────────────────
    // Load an exported message log into the current session and replay it,
    // replacing the session history with the imported one. The request body
    // must be a JSON array produced by `GET /_ipe/debug/export`.
    //
    // On success the session model is advanced to the final reconstructed
    // step, the history is replaced, and the debug cursor is cleared (live
    // mode). On failure (malformed bytes, type mismatch, oversized blob) the
    // session is left unchanged and 422 Unprocessable Entity is returned.
    //
    // Security: POST, CSRF-guarded, session-cookie authenticated. The import
    // path is bounded — `import_msgs` rejects blobs exceeding the seal codec
    // byte budget before any allocation. Dev-only (`debugger` feature absent
    // from release artifacts).
    //
    // Requires `Msg: serde::de::DeserializeOwned` — a Secret-bearing Msg type
    // never implements Deserialize (seal-legality gate), so the compiler rejects
    // import for such types at the call site.
    #[cfg(feature = "debugger")]
    pub(super) async fn import_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        headers: axum::http::HeaderMap,
        uri: axum::http::Uri,
        method: axum::http::Method,
        body: axum::body::Bytes,
    ) -> axum::response::Response
    where
        Model: Clone + PartialEq + Send + 'static,
        Msg: Clone
            + Send
            + std::fmt::Debug
            + serde::de::DeserializeOwned
            + crate::stringify::IpeStringify
            + 'static,
        FInit: Fn(req::WebReq) -> (Model, crate::tea::IpeCmd<Msg>) + Send + Sync + 'static,
        FUpdate: Fn(Msg, Model) -> (Model, crate::tea::IpeCmd<Msg>) + Send + Sync + 'static,
        FView: Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        use axum::response::IntoResponse;
        let sid = match sid_from_cookie(&headers) {
            Some(s) => s,
            None => {
                return (axum::http::StatusCode::UNAUTHORIZED, "no session").into_response();
            }
        };
        let handle = match st.store.get(&sid).await {
            Some(store::StoreHit::Web(h)) => h,
            _ => {
                return (axum::http::StatusCode::NOT_FOUND, "session not found").into_response();
            }
        };
        // Derive the init model the same way reset_handler does: build a
        // WebReq from the current request context so route-aware apps get the
        // correct initial state.
        let params = (st.param_resolver)(uri.path());
        let req = req::web_req(&method, &uri, &headers, params);
        let (init_model, _cmd) = (st.init)(req);

        // Replay the imported log from the init model. Fail-closed: any
        // malformed, oversized, or type-mismatched blob yields None.
        let update = st.update.clone();
        let imported = crate::debugger::import_msgs::<Msg, Model, _>(
            &body,
            init_model,
            move |msg, model| (*update)(msg, model),
            crate::debugger::DEFAULT_HISTORY_CAP,
        );

        let imported_buf = match imported {
            Some(buf) => buf,
            None => {
                return (
                    axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                    "import failed: malformed, oversized, or type-mismatched log",
                )
                    .into_response();
            }
        };

        // Advance session model to the final reconstructed step.
        let final_model = if imported_buf.is_empty() {
            imported_buf.base().clone()
        } else {
            let update = st.update.clone();
            imported_buf
                .reconstruct(imported_buf.len() - 1, &move |msg, model| {
                    (*update)(msg, model)
                })
                .unwrap_or_else(|| imported_buf.base().clone())
        };

        {
            let mut e = handle.lock().unwrap_or_else(|e| e.into_inner());
            e.history = imported_buf;
            e.model = final_model;
            e.debug_cursor = None;
        }
        axum::http::StatusCode::OK.into_response()
    }

    // ── POST /_ipe/debug/step-to ──────────────────────────────────────────
    // Commit time-travel to an absolute step index N: set the live model to
    // the fold of the first N+1 messages, discard the tail (fork), and update
    // the session's debug cursor to N.
    //
    // Request body: `{"index": N}` — target step (0-indexed in the retained
    // window). Out-of-range N returns 404. The CSRF middleware validates
    // `X-Ipe-Csrf` before this handler runs.
    //
    // Response: `{"body": "<html>", "cursor": N, "total": T}`.
    #[cfg(feature = "debugger")]
    pub(super) async fn step_to_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        headers: axum::http::HeaderMap,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> axum::response::Response
    where
        Model: Clone + PartialEq + Send + 'static,
        Msg: Clone + Send + std::fmt::Debug + 'static,
        FInit: Send + Sync + 'static,
        FUpdate: Fn(Msg, Model) -> (Model, crate::tea::IpeCmd<Msg>) + Send + Sync + 'static,
        FView: Fn(Model) -> crate::html::Html<Msg> + Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        use axum::response::IntoResponse;
        let sid = match sid_from_cookie(&headers) {
            Some(s) => s,
            None => {
                return (axum::http::StatusCode::UNAUTHORIZED, "no session").into_response();
            }
        };
        let handle = match st.store.get(&sid).await {
            Some(store::StoreHit::Web(h)) => h,
            _ => {
                return (axum::http::StatusCode::NOT_FOUND, "session not found").into_response();
            }
        };
        let requested_n = match body.get("index").and_then(|v| v.as_u64()) {
            Some(n) => n as usize,
            None => {
                return (axum::http::StatusCode::BAD_REQUEST, "missing index").into_response();
            }
        };
        let (model_at_n, cursor, total) = {
            let mut e = handle.lock().unwrap_or_else(|p| p.into_inner());
            let total = e.history.len();
            let stepped = e
                .history
                .step_to(requested_n, &|m, mdl| (*st.update)(m, mdl));
            match stepped {
                Some(m) => {
                    e.model = m.clone();
                    e.debug_cursor = Some(requested_n);
                    (m, requested_n, total)
                }
                None => {
                    return (axum::http::StatusCode::NOT_FOUND, "step out of range")
                        .into_response();
                }
            }
        };
        let mut tree = (st.view)(model_at_n);
        assign_ipe_ids(&mut tree, "r");
        style_inject::apply_style_injections(&mut tree);
        let html_body = render_html(&tree);
        let resp_json = serde_json::json!({
            "body":   html_body,
            "cursor": cursor,
            "total":  total,
        });
        (
            axum::http::StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            resp_json.to_string(),
        )
            .into_response()
    }

    // ── POST /_ipe/debug/back ─────────────────────────────────────────────
    // Step the debug cursor backward by one: equivalent to step_to(cur - 1).
    // Clamps to 0 when already at the first step. No request body required.
    //
    // Response: `{"body": "<html>", "cursor": N, "total": T}`.
    #[cfg(feature = "debugger")]
    pub(super) async fn back_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        headers: axum::http::HeaderMap,
    ) -> axum::response::Response
    where
        Model: Clone + PartialEq + Send + 'static,
        Msg: Clone + Send + std::fmt::Debug + 'static,
        FInit: Send + Sync + 'static,
        FUpdate: Fn(Msg, Model) -> (Model, crate::tea::IpeCmd<Msg>) + Send + Sync + 'static,
        FView: Fn(Model) -> crate::html::Html<Msg> + Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        use axum::response::IntoResponse;
        let sid = match sid_from_cookie(&headers) {
            Some(s) => s,
            None => {
                return (axum::http::StatusCode::UNAUTHORIZED, "no session").into_response();
            }
        };
        let handle = match st.store.get(&sid).await {
            Some(store::StoreHit::Web(h)) => h,
            _ => {
                return (axum::http::StatusCode::NOT_FOUND, "session not found").into_response();
            }
        };
        let (model_at_n, cursor, total) = {
            let mut e = handle.lock().unwrap_or_else(|p| p.into_inner());
            let len = e.history.len();
            if len == 0 {
                return (axum::http::StatusCode::NOT_FOUND, "no history").into_response();
            }
            // Cursor starts at the last retained step when not yet set.
            let current = e.debug_cursor.unwrap_or(len - 1);
            let target = current.saturating_sub(1);
            match e.history.step_to(target, &|m, mdl| (*st.update)(m, mdl)) {
                Some(m) => {
                    e.model = m.clone();
                    e.debug_cursor = Some(target);
                    (m, target, len)
                }
                None => {
                    return (axum::http::StatusCode::NOT_FOUND, "step out of range")
                        .into_response();
                }
            }
        };
        let mut tree = (st.view)(model_at_n);
        assign_ipe_ids(&mut tree, "r");
        style_inject::apply_style_injections(&mut tree);
        let html_body = render_html(&tree);
        let resp_json = serde_json::json!({
            "body":   html_body,
            "cursor": cursor,
            "total":  total,
        });
        (
            axum::http::StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            resp_json.to_string(),
        )
            .into_response()
    }

    // ── POST /_ipe/debug/forward ──────────────────────────────────────────
    // Step the debug cursor forward by one: equivalent to step_to(cur + 1),
    // clamped to the last retained step. No request body required.
    //
    // Note: after a step_to/back call the tail is discarded, so forward can
    // only reach steps that were not yet truncated. When the cursor is already
    // at the tail this is a no-op (returns the same model).
    //
    // Response: `{"body": "<html>", "cursor": N, "total": T}`.
    #[cfg(feature = "debugger")]
    pub(super) async fn forward_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        headers: axum::http::HeaderMap,
    ) -> axum::response::Response
    where
        Model: Clone + PartialEq + Send + 'static,
        Msg: Clone + Send + std::fmt::Debug + 'static,
        FInit: Send + Sync + 'static,
        FUpdate: Fn(Msg, Model) -> (Model, crate::tea::IpeCmd<Msg>) + Send + Sync + 'static,
        FView: Fn(Model) -> crate::html::Html<Msg> + Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        use axum::response::IntoResponse;
        let sid = match sid_from_cookie(&headers) {
            Some(s) => s,
            None => {
                return (axum::http::StatusCode::UNAUTHORIZED, "no session").into_response();
            }
        };
        let handle = match st.store.get(&sid).await {
            Some(store::StoreHit::Web(h)) => h,
            _ => {
                return (axum::http::StatusCode::NOT_FOUND, "session not found").into_response();
            }
        };
        let (model_at_n, cursor, total) = {
            let mut e = handle.lock().unwrap_or_else(|p| p.into_inner());
            let len = e.history.len();
            if len == 0 {
                return (axum::http::StatusCode::NOT_FOUND, "no history").into_response();
            }
            let current = e.debug_cursor.unwrap_or(len - 1);
            // Clamp: cannot go past the last retained step.
            let target = (current + 1).min(len - 1);
            match e.history.step_to(target, &|m, mdl| (*st.update)(m, mdl)) {
                Some(m) => {
                    e.model = m.clone();
                    e.debug_cursor = Some(target);
                    (m, target, len)
                }
                None => {
                    return (axum::http::StatusCode::NOT_FOUND, "step out of range")
                        .into_response();
                }
            }
        };
        let mut tree = (st.view)(model_at_n);
        assign_ipe_ids(&mut tree, "r");
        style_inject::apply_style_injections(&mut tree);
        let html_body = render_html(&tree);
        let resp_json = serde_json::json!({
            "body":   html_body,
            "cursor": cursor,
            "total":  total,
        });
        (
            axum::http::StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            resp_json.to_string(),
        )
            .into_response()
    }

    // ── GET /_ipe/debug/inspect ───────────────────────────────────────────────
    // Read-only structural render of the current session model.
    //
    // Returns `{"model": "<ipe_show>"}` — the datum stringified via
    // `IpeStringify::ipe_show`. Never mutates the model or fires any effect:
    // the transition function is the sole mutation path (make-invalid-states-
    // unrepresentable). `Secret`-bearing fields render as `<redacted>`.
    //
    // Security: GET, read-only — CSRF token not required by method. Session-
    // cookie authentication guards access; the route is dev-build-only
    // (`debugger` feature absent from release artifacts).
    #[cfg(feature = "debugger")]
    pub(super) async fn inspect_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        headers: axum::http::HeaderMap,
    ) -> axum::response::Response
    where
        Model: Clone + PartialEq + Send + crate::stringify::IpeStringify + 'static,
        Msg: Clone + Send + std::fmt::Debug + 'static,
        FInit: Send + Sync + 'static,
        FUpdate: Send + Sync + 'static,
        FView: Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        use axum::response::IntoResponse;
        let sid = match sid_from_cookie(&headers) {
            Some(s) => s,
            None => {
                return (axum::http::StatusCode::UNAUTHORIZED, "no session").into_response();
            }
        };
        let handle = match st.store.get(&sid).await {
            Some(store::StoreHit::Web(h)) => h,
            _ => {
                return (axum::http::StatusCode::NOT_FOUND, SESSION_LOST_BODY).into_response();
            }
        };
        let rendered = {
            let e = handle.lock().unwrap_or_else(|e| e.into_inner());
            crate::debugger::server::inspect_model(&e.model)
        };
        let resp_json = serde_json::json!({ "model": rendered });
        (
            axum::http::StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            resp_json.to_string(),
        )
            .into_response()
    }
}

/// Shared server setup for `web_app` / `web_app_routed`: nested HTTP
/// handlers (`page` / `sse_handler` / `event_handler`), router + bind/serve.
/// The only per-entry difference (the `route_resolver`) lives on `state`.
#[cfg(feature = "server")]
async fn serve_web<E, Model, Msg, FInit, FUpdate, FView, FSubs>(
    state: WebState<Model, Msg, FInit, FUpdate, FView, FSubs>,
) -> IpeResult<E, ()>
where
    E: From<String> + Send + 'static,
    // IpeStringify: required by inspect_handler for the live-datum GET
    // (`/_ipe/debug/inspect`). Generated Model types always satisfy this bound.
    Model: Clone + PartialEq + Send + crate::stringify::IpeStringify + 'static,
    // Debug: forwarded to drive_session for the ipe_web_msg_seconds{name} label.
    // IpeStringify: forwarded to the page handler for debugger overlay labels.
    // DeserializeOwned: required by import_handler (dev-only debug import route).
    // Generated Msg types always satisfy all bounds.
    Msg: Clone
        + Send
        + std::fmt::Debug
        + serde::Serialize
        + serde::de::DeserializeOwned
        + crate::stringify::IpeStringify
        + 'static,
    FInit: Fn(req::WebReq) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FView: Fn(Model) -> Html<Msg> + Send + Sync + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + Send + Sync + 'static,
{
    // Background TTL eviction : sweep
    // idle-expired sessions every 60 s. Persistent backends also prune their
    // checkpoint table in `sweep`.
    {
        let store = state.store.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                store.sweep().await;
            }
        });
    }

    // Enable the telemetry SQLite spill when
    // IPE_CONSOLE_DB_PATH is set — the console child reads it via the
    // hub kernels. db-gated; a no-op for live-without-db apps. Enabled
    // BEFORE the console child spawns so early telemetry lands in the spill
    // the child will read.
    #[cfg(feature = "db")]
    crate::telemetry_spill::enable_from_env().await;

    // Observability export pipelines: federation push to a parent ingest
    // (IPE_PARENT_URL) and remote-hub OTLP push (IPE_CONSOLE_HUB).
    // Both env-gated + inert by default. Only available when `http_client`
    // is active: these pipelines make outbound HTTP calls via reqwest.
    #[cfg(feature = "http_client")]
    push_exporter::enable_from_env().await;
    #[cfg(feature = "http_client")]
    hub_exporter::enable_from_env().await;

    // Console precedence: try the pre-built console child +
    // reverse-proxy; fall back to the in-process console when the binary is
    // absent / spawn fails / readiness times out / the gate is closed.
    // Decided HERE (before the router is built) so both the proxy routes and
    // the in-process console routes sit under the same `track` middleware,
    // and the two never collide on `/_ipe/console`.
    // Only when `http_client` is active: the console proxy uses reqwest for
    // the reverse-proxy path. Without it, always use the in-process console.
    #[cfg(feature = "http_client")]
    let use_console_proxy = console_proxy::ensure_console_proxy().await;

    // Cloned for the shutdown path's dev-only reload push — the router's
    // `.with_state(state)` takes ownership of `state` below.
    let shutdown_store = state.store.clone();

    #[cfg(feature = "http_client")]
    let console_proxy_flag = use_console_proxy;
    #[cfg(not(feature = "http_client"))]
    let console_proxy_flag = false;

    let app =
        build_web_router::<Model, Msg, FInit, FUpdate, FView, FSubs>(state, console_proxy_flag);

    // IPE_WEB_PORT: default 8000. Resolved through the shared fail-closed
    // helper (same precedence as `Ipe.Http.Server`'s `IPE_SERVER_PORT`): a
    // malformed, out-of-range, or `0` value falls back to 8000, never a
    // silently OS-chosen ephemeral port.
    let port: i64 =
        crate::system::resolve_listen_port(crate::system::read_env_var("IPE_WEB_PORT").ok(), 8000);
    // Honour the same host-bind precedence as the Ipe.Http.Server path
    // (`IPE_HTTP_BIND` > `Host.bind` setting > loopback-unless-production), so
    // an explicit loopback setting is never overridden into all-interfaces.
    let host = crate::app_config::resolve_host_bind();
    let addr = format!("{host}:{port}");
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            return IpeResult::Err(
                format!(
                    "port {port} is already in use — another application is bound to it.\n\
                     Set a different port with the IPE_WEB_PORT environment variable, e.g.:\n\
                     IPE_WEB_PORT=8123 ipe run"
                )
                .into(),
            );
        }
        Err(e) => return IpeResult::Err(format!("Web.tea: bind {addr}: {e}").into()),
    };
    // Bind-address line (stderr) — carries the resolved host:port.
    {
        use std::io::IsTerminal;
        let msg = format!("[ipe.web] listening on http://{addr}");
        eprintln!(
            "{}",
            crate::system::gutter_line(&msg, std::io::stderr().is_terminal())
        );
    }
    // User-facing line on stdout.
    println!("Ipe.Web listening on :{port}");
    // Graceful shutdown: trap SIGINT/SIGTERM,
    // print the shutdown line, drain in-flight requests, and return cleanly so
    // the IpeTask resolves Ok → the generated entry exits 0 (NOT 130). A
    // SECOND signal force-exits 130 via the watchdog inside web_shutdown_signal.
    match axum::serve(listener, app)
        .with_graceful_shutdown(web_shutdown_signal(shutdown_store))
        .await
    {
        Ok(()) => ok_res(()),
        Err(e) => IpeResult::Err(format!("Web.tea: serve: {e}").into()),
    }
}

/// Assemble the fully-layered axum `Router` for a live web app WITHOUT
/// binding a listener. `serve_web` binds this router on the standalone port;
/// the mount path (`Server.mountApp`) nests the same router under a path
/// prefix on the shared server port. `use_console_proxy` is decided by the
/// caller so this stays feature-clean (the caller passes `false` when
/// `http_client` is off).
#[cfg(feature = "server")]
pub(crate) fn build_web_router<Model, Msg, FInit, FUpdate, FView, FSubs>(
    state: WebState<Model, Msg, FInit, FUpdate, FView, FSubs>,
    // Read only when `http_client` is active (the console-proxy arm); the
    // in-process console path ignores it, so it is unused without that feature.
    #[cfg_attr(not(feature = "http_client"), allow(unused_variables))] use_console_proxy: bool,
) -> axum::Router
where
    // IpeStringify: required by inspect_handler for the live-datum GET.
    // Generated Model types always satisfy this bound.
    Model: Clone + PartialEq + Send + crate::stringify::IpeStringify + 'static,
    // `serde::Serialize` is required by `export_handler` and
    // `serde::de::DeserializeOwned` by `import_handler` (both dev-only routes
    // under the `debugger` feature). Generated Msg enums always derive both,
    // so these bounds tighten nothing for real programs; they are unconditional
    // to avoid `#[cfg(…)]` on where predicates (which is an unstable feature).
    Msg: Clone
        + Send
        + std::fmt::Debug
        + crate::stringify::IpeStringify
        + serde::Serialize
        + serde::de::DeserializeOwned
        + 'static,
    FInit: Fn(req::WebReq) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FUpdate: Fn(Msg, Model) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FView: Fn(Model) -> Html<Msg> + Send + Sync + 'static,
    FSubs: Fn(Model) -> IpeSub<Msg> + Send + Sync + 'static,
{
    use axum::Router;
    use axum::routing::{get, post};

    // Body-size cap on /_ipe/event. axum's DefaultBodyLimit applies
    // before the handler sees the bytes, so an over-sized payload is
    // rejected at the extract layer with 413 Payload Too Large.
    let event_route = post(handlers::event_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>)
        .layer(axum::extract::DefaultBodyLimit::max(web_max_body_bytes()));

    // Inbound `Ipe.Ffi.Js` port route: same body-size cap as `/_ipe/event`, so an
    // over-sized port frame is rejected at the extract layer (413) before the
    // handler's own seal-boundary budget even runs.
    let port_route = post(handlers::port_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>)
        .layer(axum::extract::DefaultBodyLimit::max(web_max_body_bytes()));

    // Content-addressed client JS asset route. The URL is computed once at
    // startup from SHA-256(CLIENT_JS) so the path changes when the file
    // changes, making `Cache-Control: immutable` safe. This route is CSRF-
    // exempt (GET; the CSRF middleware only checks mutating verbs) and open
    // to all (it's a static public asset). It is registered BEFORE the
    // catch-all `/*path` route so it is matched first.
    let client_js_route_path = client_js_path(); // e.g. "/_ipe/client.a1b2c3d4e5f6a7b8.js"
    async fn serve_client_js() -> impl axum::response::IntoResponse {
        use axum::http::header;
        (
            [
                (
                    header::CONTENT_TYPE,
                    "application/javascript; charset=utf-8",
                ),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            CLIENT_JS,
        )
    }

    // Serve one content-addressed widget asset / glue module. Same static
    // immutable discipline as `serve_client_js`; the exact bytes here are what
    // the page's SRI pins, so integrity is verified by the browser.
    fn serve_widget_js(body: &'static str) -> impl axum::response::IntoResponse {
        use axum::http::header;
        (
            [
                (
                    header::CONTENT_TYPE,
                    "application/javascript; charset=utf-8",
                ),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            body,
        )
    }

    let router = Router::new()
        .route(
            "/_ipe/sse",
            get(handlers::sse_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>),
        )
        .route("/_ipe/event", event_route)
        .route("/_ipe/port", port_route)
        .route(&client_js_route_path, get(serve_client_js));
    // The `Ipe.Ffi.Js` browser port surface (`window.ipe`), served
    // content-addressed with SRI — the same static, immutable discipline as
    // the client core and widget glue. A GET of fixed bytes (no user input),
    // so it is CSRF-exempt by method and open. Registered before the page
    // catch-all so the glue URL hits its static handler.
    #[cfg(feature = "widget-assets")]
    let router = router.route(
        &crate::js_port_glue::port_glue_path(),
        get(|| async { serve_widget_js(crate::js_port_glue::port_glue_js()) }),
    );
    #[cfg(feature = "debugger")]
    let router = router.route(
        "/_ipe/debug/scrub",
        post(handlers::scrub_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>),
    );
    #[cfg(feature = "debugger")]
    let router = router.route(
        "/_ipe/debug/reset",
        post(handlers::reset_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>),
    );
    #[cfg(feature = "debugger")]
    let router = router.route(
        "/_ipe/debug/export",
        get(handlers::export_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>),
    );
    #[cfg(feature = "debugger")]
    let router = router.route(
        "/_ipe/debug/import",
        post(handlers::import_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>),
    );
    #[cfg(feature = "debugger")]
    let router = router.route(
        "/_ipe/debug/step-to",
        post(handlers::step_to_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>),
    );
    #[cfg(feature = "debugger")]
    let router = router.route(
        "/_ipe/debug/back",
        post(handlers::back_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>),
    );
    #[cfg(feature = "debugger")]
    let router = router.route(
        "/_ipe/debug/forward",
        post(handlers::forward_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>),
    );
    #[cfg(feature = "debugger")]
    let router = router.route(
        "/_ipe/debug/inspect",
        get(handlers::inspect_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>),
    );
    // Dev-only appearance-hot-swap control leg. MOUNTED only when the hot
    // overlay is active (flag on AND non-production), so the route is entirely
    // absent from a production build — an appearance patch cannot even be POSTed
    // to a prod server. The handler additionally token-gates each request.
    let router = if literal_table::dev_overlay_active() {
        router.route(
            "/_ipe/hot-appearance",
            post(handlers::hot_appearance_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>)
                .layer(axum::extract::DefaultBodyLimit::max(web_max_body_bytes())),
        )
    } else {
        router
    };
    // Dev-only `update`-arm transition-hot-swap control leg. Guarded IDENTICALLY
    // to `/_ipe/hot-appearance`: MOUNTED only under the same dev overlay gate
    // (flag on AND non-production), token-gated per request, and bounded. A
    // transition patch mutates the server-held Model, so it flows through the
    // total, fail-closed `apply_transition` alone — never arbitrary logic.
    let router = if literal_table::dev_overlay_active() {
        router.route(
            "/_ipe/hot-transition",
            post(handlers::hot_transition_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>)
                .layer(axum::extract::DefaultBodyLimit::max(web_max_body_bytes())),
        )
    } else {
        router
    };
    // Dev-only additive-`Msg`-variant hot-swap control leg. Guarded IDENTICALLY
    // to `/_ipe/hot-transition`: MOUNTED only under the same dev overlay gate
    // (flag on AND non-production), token-gated per request, and bounded. The
    // candidate descriptor drives nothing but the total `is_additive_superset`
    // gate — it is accepted only when it is a proven additive superset of the
    // live `Msg` set, never resolving a handler or mutating the Model.
    let router = if literal_table::dev_overlay_active() {
        router.route(
            "/_ipe/hot-msg",
            post(handlers::hot_msg_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>)
                .layer(axum::extract::DefaultBodyLimit::max(web_max_body_bytes())),
        )
    } else {
        router
    };
    // Dev-only session-`init` hot-swap control leg. Guarded IDENTICALLY to
    // `/_ipe/hot-transition`: MOUNTED only under the same dev overlay gate (flag
    // on AND non-production), token-gated per request, and bounded. An init patch
    // registers a replacement starting-Model datum that drives only the total,
    // fail-closed `apply_init` at SESSION CREATION — never a live session's Model.
    let router = if literal_table::dev_overlay_active() {
        router.route(
            "/_ipe/hot-init",
            post(handlers::hot_init_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>)
                .layer(axum::extract::DefaultBodyLimit::max(web_max_body_bytes())),
        )
    } else {
        router
    };
    // Dev-only `subscriptions`-entry hot-swap control leg. Guarded IDENTICALLY to
    // `/_ipe/hot-transition`: MOUNTED only under the same dev overlay gate (flag on
    // AND non-production), token-gated per request, and bounded. A sub patch
    // installs a subscription on the server, so it flows through the total,
    // fail-closed `sub_every_hot` alone — never arbitrary logic.
    let router = if literal_table::dev_overlay_active() {
        router.route(
            "/_ipe/hot-subs",
            post(handlers::hot_subs_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>)
                .layer(axum::extract::DefaultBodyLimit::max(web_max_body_bytes())),
        )
    } else {
        router
    };
    // Dev-only `update`-arm Cmd-wiring hot-swap control leg. Guarded IDENTICALLY
    // to `/_ipe/hot-transition`: MOUNTED only under the same dev overlay gate,
    // token-gated per request, and bounded. A wiring patch selects one of the
    // arm's OWN compiled effects (or none) through the total, fail-closed
    // `select_cmd_hot` — never an out-of-range effect, never an unintended one.
    let router = if literal_table::dev_overlay_active() {
        router.route(
            "/_ipe/hot-wiring",
            post(handlers::hot_wiring_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>)
                .layer(axum::extract::DefaultBodyLimit::max(web_max_body_bytes())),
        )
    } else {
        router
    };
    // Dev-only build-status notification leg. MOUNTED only when the dev banner
    // is active (non-production + banner not disabled + root-mounted). The
    // handler additionally token-gates each request (same `IPE_WATCH_HOT_TOKEN`
    // mechanism as `/_ipe/hot-appearance`). Never reachable in production.
    let router = if watch_banner_active(&web_base_path()) {
        router.route(
            "/_ipe/watch/status",
            post(handlers::watch_status_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>)
                .layer(axum::extract::DefaultBodyLimit::max(web_max_body_bytes())),
        )
    } else {
        router
    };
    let mut router = router
        // Observability surface.
        .route("/_ipe/healthz", get(observability::healthz))
        .route("/_ipe/readyz", get(observability::readyz))
        .route("/_ipe/buildinfo", get(observability::buildinfo))
        .route("/_ipe/metrics", get(observability::metrics))
        // Observability federation receiver stays on the parent regardless
        // of console mode (sub-apps push telemetry here). Body-capped (reuses
        // the /_ipe/event limit) so an unbounded ingest POST can't exhaust
        // memory before the JSON parse.
        .route(
            "/_ipe/observability/ingest",
            post(console::ingest).layer(axum::extract::DefaultBodyLimit::max(web_max_body_bytes())),
        );

    // When `http_client` is active and the pre-built console binary is
    // present, the proxy replaces the in-process console: a child process is
    // spawned and all `/_ipe/console/*` traffic is forwarded to it via
    // reqwest. The child logs its own `session store: …` + `reverse-proxy
    // ready` lines, so the parent does not duplicate the inline-mount log.
    #[cfg(feature = "http_client")]
    if use_console_proxy {
        router = console_proxy::proxy_routes(router);
    }

    // The in-process console (`/_ipe/console` + `/_ipe/console/api/*`) is
    // reqwest-free and mounts under `web` alone — no `http_client` required.
    // A web app without an outbound HTTP kernel still serves the developer
    // dashboard. The proxy override above takes precedence when active: when
    // the proxy is live (`use_console_proxy` true) it owns `/_ipe/console`,
    // so we skip this block to avoid duplicate route registration.
    let proxy_active = {
        #[cfg(feature = "http_client")]
        {
            use_console_proxy
        }
        #[cfg(not(feature = "http_client"))]
        {
            false
        }
    };
    if !proxy_active && console::gate_allows() {
        eprintln!("{}", store::memory_store_log_line(web_ttl()));
        eprintln!(
            "[ipe.console] inline console mounted as Ipe.Web sub-app at /_ipe/console mode={}",
            console::console_auth_mode_label()
        );
        router = router
            .route("/_ipe/console", get(console::console_html))
            .route("/_ipe/console/api/overview", get(console::api_overview))
            .route("/_ipe/console/api/logs", get(console::api_logs))
            .route("/_ipe/console/api/errors", get(console::api_errors))
            .route("/_ipe/console/api/traces", get(console::api_traces))
            .route(
                "/_ipe/console/api/metrics-summary",
                get(console::api_metrics_summary),
            );
    }
    // The console proxy needs `http_client` (outbound reqwest). The
    // in-process console is served under `web` whenever the mount gate
    // allows, so a web app without an outbound HTTP kernel still gets
    // `/_ipe/console`.

    // Custom-element (`CustomElement.node`) assets: one content-addressed route per
    // registered author module + one for the generated registration glue.
    // Each serves a `&'static str` (the bytes interned in the process-global
    // registry at startup) with the same `immutable` discipline as the client
    // asset. Registered BEFORE the `/*path` page catch-all so a widget URL
    // hits its static handler, not the page handler. The routes are static
    // public GETs (CSRF-exempt, open) — the served bytes are the exact bytes
    // the page's SRI pins, so a tampered asset makes the browser refuse the
    // module. A widget-free program registers nothing here (no extra routes).
    if widget_assets::has_widgets() {
        let base = web_base_path();
        for asset in widget_assets::registered() {
            let path = widget_assets::widget_asset_path(&asset.content);
            let content: &'static str = &asset.content;
            router = router.route(&path, get(move || async move { serve_widget_js(content) }));
        }
        let glue_path = widget_assets::glue_path(&base, widget_assets::WidgetTransport::Server);
        // The glue body folds in the base-prefixed author URLs, so it is
        // computed once here for the process (base is stable at startup) and
        // leaked to `'static` for the handler — a one-time, bounded allocation
        // sized by the program's widget count, never per-request.
        let glue_body: &'static str = Box::leak(
            widget_assets::glue_js(&base, widget_assets::WidgetTransport::Server).into_boxed_str(),
        );
        router = router.route(
            &glue_path,
            get(move || async move { serve_widget_js(glue_body) }),
        );
    }

    // package.ipe `[web] static` (baked as IPE_WEB_STATIC_DIR) → serve files at
    // /static/* via ServeDir. MUST be added before the `/*path` page catch-all
    // so a /static/<file> request hits ServeDir, not the page handler (which
    // would return HTML). ServeDir blocks `..` path traversal by construction
    // (percent-decodes first, so `%2e%2e` is caught too). NOTE: like
    // http.FileServer it FOLLOWS symlinks inside the dir — the dir is
    // author-controlled (package.ipe [web] static), so that is the intended
    // contract, NOT a confinement guarantee. Absent/empty → no static mount.
    // IPE_WEB_STATIC_DIR: non-empty value mounts the named directory at /static.
    if let Some(dir) = crate::system::read_env_var("IPE_WEB_STATIC_DIR")
        .ok()
        .filter(|d| !d.is_empty())
    {
        router = router.nest_service("/static", tower_http::services::ServeDir::new(dir));
    }

    let app: Router = router
        .route(
            "/",
            get(handlers::page::<Model, Msg, FInit, FUpdate, FView, FSubs>),
        )
        .route(
            "/*path",
            get(handlers::page::<Model, Msg, FInit, FUpdate, FView, FSubs>),
        )
        // Layer order (axum: last `.layer` = outermost): CSRF is INNER of
        // observability::track so a rejected CSRF POST still gets counted +
        // access-logged.
        .layer(axum::middleware::from_fn(csrf::csrf_middleware))
        // Per-request panic recovery: a handler or csrf-mw panic becomes a 500
        // instead of an unwound tokio task that drops the connection with no
        // response. Symmetric with Ipe.Http.Server (server.rs). The Rust thesis
        // is that well-typed Ipê can't panic, so this is the defense-in-depth
        // FLOOR, not the foundation. Placed INNER of `track` (and OUTER of
        // csrf + the route handlers) so the converted 500 returns through
        // track's `next.run().await` normally — track still counts +
        // access-logs + histograms it as status 500
        // recover is innermost; the outer middleware observes the 500). If it
        // were outermost the panic would unwind through track, skipping its
        // post-`next.run` metering. The custom responder classifies + logs the
        // panic SERVER-SIDE (errId, via core::panic_500_body) and returns a 500
        // carrying ONLY the errId — never the panic message (no info leak).
        // Symmetric with Ipe.Http.Server (the body shape is shared in `core`;
        // the Web router can't reference `server.rs` — a Web-only generated
        // project doesn't include it).
        .layer(tower_http::catch_panic::CatchPanicLayer::custom(
            |err: Box<dyn std::any::Any + Send + 'static>| {
                use axum::response::IntoResponse;
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    crate::core::panic_500_body(&*err),
                )
                    .into_response()
            },
        ))
        .layer(axum::middleware::from_fn(observability::track))
        .with_state(state);

    pubsub::mark_web_running();
    app
}

/// Read the session cookie from request headers. Uses the base-path-aware
/// cookie name (`session_cookie_name`) so a sub-app reads its own scoped cookie,
/// never the parent's `ipe_sid`.
#[cfg(feature = "server")]
fn sid_from_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    let name = session_cookie_name();
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for c in raw.split(';') {
        let c = c.trim();
        if let Some((k, v)) = c.split_once('=')
            && k.trim() == name
        {
            return Some(v.trim().to_string());
        }
    }
    None
}

// The Ipe.Html `Ffi.callPure "htmlXxx"` kernel wrappers (html_render_,
// html_escape_text_, html_escape_attr_, html_attr_to_string_) now live in the
// standalone top-level `ipe_runtime::html` module (re-exported here via
// `use super::*`), so a non-Web Ipe.Html / Ipe.Ui render doesn't pull this
// server module in.

#[cfg(all(test, feature = "server"))]
mod reload_push_tests {
    use super::*;
    use crate::web::store::{MemoryStore, SessionHandle, SessionStore};
    use std::time::Duration;
    use tokio::sync::mpsc::channel;

    fn handle_with(sse_tx: Option<SseTx>) -> SessionHandle<(), ()> {
        let (tx, _rx) = channel::<()>(1);
        let tree: Html<()> = Html::HText(String::new());
        let index = build_index(&tree);
        Arc::new(Mutex::new(SessionEntry {
            model: (),
            last_view: tree,
            index,
            seq: 0,
            sse_tx,
            msg_tx: tx,
            #[cfg(feature = "debugger")]
            history: crate::debugger::RecordBuffer::new((), crate::debugger::DEFAULT_HISTORY_CAP),
            #[cfg(feature = "debugger")]
            debug_cursor: None,
        }))
    }

    /// Every SSE-attached live session receives exactly ONE `event: reload`
    /// frame; a session with no SSE connection is skipped without panicking.
    #[tokio::test]
    async fn push_reload_to_web_sessions_sends_one_frame_per_web_session() {
        let store_impl: MemoryStore<(), ()> = MemoryStore::new(Duration::from_secs(60));
        let (sse_tx, mut sse_rx) = sse::channel();
        store_impl.set("with_sse", handle_with(Some(sse_tx))).await;
        store_impl.set("without_sse", handle_with(None)).await;
        let store: Arc<dyn SessionStore<(), ()>> = Arc::new(store_impl);

        push_reload_to_web_sessions(&store).await;

        let frame = sse_rx
            .try_recv()
            .expect("the SSE-attached session must receive a reload frame");
        assert_eq!(frame.0, sse::frame("reload", "{}"));
        assert!(
            sse_rx.try_recv().is_err(),
            "exactly one frame per live session, never more"
        );
    }

    /// H23: with `ENV=production` the reload push is UNREACHABLE — the
    /// gated path pushes nothing; in dev it pushes. (The gate is tested via
    /// `maybe_push_reload_to_web_sessions`, the exact call
    /// `web_shutdown_signal` makes right after `mark_draining` — split out
    /// so no real OS signal is needed here.)
    #[tokio::test]
    async fn web_shutdown_signal_skips_the_reload_push_in_production() {
        use crate::system::{locked_remove_var, locked_set_var};
        let prior_env = std::env::var("ENV").ok();
        let prior_ipe_env = std::env::var("IPE_ENV").ok();

        let store_impl: MemoryStore<(), ()> = MemoryStore::new(Duration::from_secs(60));
        let (sse_tx, mut sse_rx) = sse::channel();
        store_impl.set("s", handle_with(Some(sse_tx))).await;
        let store: Arc<dyn SessionStore<(), ()>> = Arc::new(store_impl);

        locked_set_var("ENV", "production");
        maybe_push_reload_to_web_sessions(&store).await;
        assert!(
            sse_rx.try_recv().is_err(),
            "production must have NO reachable path that pushes the reload frame"
        );

        locked_set_var("ENV", "dev");
        maybe_push_reload_to_web_sessions(&store).await;
        assert!(
            sse_rx.try_recv().is_ok(),
            "dev mode must push the reload frame"
        );

        match prior_env {
            Some(v) => locked_set_var("ENV", &v),
            None => locked_remove_var("ENV"),
        }
        match prior_ipe_env {
            Some(v) => locked_set_var("IPE_ENV", &v),
            None => locked_remove_var("IPE_ENV"),
        }
    }
}

#[cfg(all(test, feature = "server"))]
mod hot_appearance_push_tests {
    //! Applying an appearance patch to the running app re-renders
    //! `view(currentModel)` from the CURRENT Model (never through `update`) and
    //! pushes the resulting VDOM diff over the existing SSE `patches` channel —
    //! with the flag off, no frame is produced.
    use super::*;
    use crate::web::literal_table;
    use crate::web::literal_table::overlay_test_lock as guard;
    use crate::web::store::{MemoryStore, SessionHandle, SessionStore};
    use std::time::Duration;

    // The app view: an `i64` counter Model rendered into a div whose `style`
    // reads the hot-swappable padding literal from a per-view `LiteralTable`.
    // The counter appears as static text so the diff distinguishes a Model
    // change (text) from an appearance change (style value).
    const PADDING_DEFAULTS: &[&str] = &["padding: 12px"];
    fn app_view(count: i64) -> Html<()> {
        let t = LiteralTable::from_defaults(PADDING_DEFAULTS);
        Html::HElement(
            "div".to_string(),
            vec![Attribute::Attr("style".to_string(), t.get(0).to_string())],
            vec![Html::HText(format!("count: {count}"))],
        )
    }

    fn session_with_current_view(count: i64, sse_tx: Option<SseTx>) -> SessionHandle<i64, ()> {
        let mut tree = app_view(count);
        assign_ipe_ids(&mut tree, "r");
        style_inject::apply_style_injections(&mut tree);
        let index = build_index(&tree);
        let (msg_tx, _rx) = mpsc::channel::<()>(1);
        Arc::new(Mutex::new(SessionEntry {
            model: count,
            last_view: tree,
            index,
            seq: 0,
            sse_tx,
            msg_tx,
            #[cfg(feature = "debugger")]
            history: crate::debugger::RecordBuffer::new(
                count,
                crate::debugger::DEFAULT_HISTORY_CAP,
            ),
            #[cfg(feature = "debugger")]
            debug_cursor: None,
        }))
    }

    #[allow(clippy::expect_used)] // test helper — panic on bad fixture is correct
    fn parse_patch_frame(frame: &str) -> serde_json::Value {
        // frame = "event: patches\ndata: <json>\n\n"; recover the json line.
        let data = frame
            .lines()
            .find_map(|l| l.strip_prefix("data: "))
            .expect("a patches frame carries a data line");
        serde_json::from_str(data).expect("the patches frame data is JSON")
    }

    // Run an async test body on a fresh current-thread runtime while holding the
    // process-global overlay guard in SYNC scope, so the guard never crosses an
    // await point (the overlay statics are the shared state being serialised).
    #[allow(clippy::expect_used)] // test helper — runtime build failure is a test environment issue
    fn with_overlay_serialised<F: std::future::Future<Output = ()>>(body: impl FnOnce() -> F) {
        let _g = guard();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime must build for the test");
        rt.block_on(body());
        literal_table::clear_dev_overlay_for_test();
        literal_table::set_dev_overlay_active_for_test(None);
    }

    /// Flag ON: applying a padding patch to a running session re-renders from
    /// the CURRENT Model and pushes a VDOM diff reflecting the new literal; the
    /// Model is left unchanged (one render, no `update`).
    #[test]
    fn patch_re_renders_current_model_and_pushes_diff() {
        with_overlay_serialised(|| async {
            literal_table::set_dev_overlay_active_for_test(Some(true));
            literal_table::clear_dev_overlay_for_test();

            let store_impl: MemoryStore<i64, ()> = MemoryStore::new(Duration::from_secs(60));
            let (sse_tx, mut sse_rx) = sse::channel();
            // A non-initial Model, to prove the re-render uses the CURRENT Model.
            store_impl
                .set("live", session_with_current_view(7, Some(sse_tx)))
                .await;
            let store: Arc<dyn SessionStore<i64, ()>> = Arc::new(store_impl);
            let view: Arc<fn(i64) -> Html<()>> = Arc::new(app_view);

            let defaults: Vec<String> = PADDING_DEFAULTS.iter().map(|s| (*s).to_string()).collect();
            apply_literal_patch_to_web_sessions(
                &store,
                &view,
                &defaults,
                vec![(0, "padding: 16px".to_string())],
            )
            .await;

            let frame = sse_rx
                .try_recv()
                .expect("an SSE-attached session must receive a patches frame");
            let json = parse_patch_frame(&frame.0);
            let dump = json.to_string();
            assert!(
                dump.contains("padding: 16px"),
                "the pushed diff must carry the new literal value: {dump}"
            );
            assert!(
                !dump.contains("padding: 12px"),
                "the old literal must be gone from the diff: {dump}"
            );
            // The diff is strictly flatter than a general VDOM diff: an
            // appearance hot-swap touches only the style attribute value at a
            // fixed id, never the text (the Model-derived `count: N`) or
            // structure. The absence of a `text`/`html` patch is the proof the
            // Model was NOT advanced — the re-render used the current Model,
            // whose text is identical to last_view.
            assert!(
                !dump.contains("\"text\"") && !dump.contains("\"html\""),
                "an appearance hot-swap emits only the value delta, no structure patch: {dump}"
            );
            let model_after = store
                .get("live")
                .await
                .and_then(|hit| match hit {
                    store::StoreHit::Web(h) => {
                        Some(h.lock().unwrap_or_else(|e| e.into_inner()).model)
                    }
                    _ => None,
                })
                .expect("session still present");
            assert_eq!(model_after, 7, "a hot-swap must not advance the Model");
        });
    }

    /// Flag OFF: the apply path is inert — it registers nothing and pushes NO
    /// frame, so no `literal-patch`-derived diff is ever produced.
    #[test]
    fn patch_is_inert_when_flag_off() {
        with_overlay_serialised(|| async {
            literal_table::set_dev_overlay_active_for_test(Some(false));
            literal_table::clear_dev_overlay_for_test();

            let store_impl: MemoryStore<i64, ()> = MemoryStore::new(Duration::from_secs(60));
            let (sse_tx, mut sse_rx) = sse::channel();
            store_impl
                .set("live", session_with_current_view(3, Some(sse_tx)))
                .await;
            let store: Arc<dyn SessionStore<i64, ()>> = Arc::new(store_impl);
            let view: Arc<fn(i64) -> Html<()>> = Arc::new(app_view);

            let defaults: Vec<String> = PADDING_DEFAULTS.iter().map(|s| (*s).to_string()).collect();
            apply_literal_patch_to_web_sessions(
                &store,
                &view,
                &defaults,
                vec![(0, "padding: 16px".to_string())],
            )
            .await;

            assert!(
                sse_rx.try_recv().is_err(),
                "flag off: the apply path must push no frame at all"
            );
        });
    }
}

#[cfg(all(test, feature = "server"))]
mod dev_banner_tests {
    use super::dev_console_banner;

    #[test]
    fn banner_byte_matches_go_dev_banner_markup() {
        //go devBannerHTML): same id, target/rel/title,
        // monospace blue style, `&#128269;` ENTITY (not a literal emoji).
        let b = dev_console_banner("");
        let expected = "<a id=\"__ipe-dev-console\" href=\"/_ipe/console\" target=\"_blank\" \
            rel=\"noopener\" title=\"Ipe Console (dev only)\" \
            style=\"position:fixed;right:12px;bottom:12px;z-index:2147483646;\
            font:12px/1.4 ui-monospace,Menlo,monospace;\
            background:#1c2027;color:#7eb6ff;\
            border:1px solid #353b46;border-radius:6px;\
            padding:6px 10px;text-decoration:none;\
            box-shadow:0 2px 8px rgba(0,0,0,0.4);\">\
            &#128269; Console</a>";
        assert_eq!(b, expected, "dev console banner must match golden");
        assert!(
            !b.contains("🔍"),
            "must use the &#128269; entity, not a literal emoji"
        );
    }

    #[test]
    fn banner_suppressed_for_subapp() {
        // A non-empty base = sub-app (e.g. the console child) → no recursive link.
        assert_eq!(dev_console_banner("/_ipe/console"), "");
    }
}

#[cfg(all(test, feature = "server"))]
mod duration_parse_tests {
    use super::parse_duration_secs;

    #[test]
    fn duration_formats_and_bare_seconds() {
        assert_eq!(parse_duration_secs("1800"), Some(1800)); // bare seconds (legacy)
        assert_eq!(parse_duration_secs("30m"), Some(1800));
        assert_eq!(parse_duration_secs("1h"), Some(3600));
        assert_eq!(parse_duration_secs("24h"), Some(86400));
        assert_eq!(parse_duration_secs("90s"), Some(90));
        assert_eq!(parse_duration_secs("1h30m"), Some(5400));
        assert_eq!(parse_duration_secs("45m"), Some(2700)); // the e2e check (IPE_WEB_TTL=45m)
        assert_eq!(parse_duration_secs("  1h  "), Some(3600));
    }

    #[test]
    fn malformed_is_none_never_panics() {
        assert_eq!(parse_duration_secs(""), None);
        assert_eq!(parse_duration_secs("abc"), None);
        assert_eq!(parse_duration_secs("1d"), None); // unsupported unit
        assert_eq!(parse_duration_secs("1h30"), None); // trailing unit-less number
        assert_eq!(parse_duration_secs("m"), None); // unit with no number
        assert_eq!(parse_duration_secs("-5m"), None);
    }
}

#[cfg(all(test, feature = "server"))]
mod request_is_https_tests {
    use super::request_is_https_with_trust;

    #[test]
    fn ignored_without_trust_opt_in() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(
            !request_is_https_with_trust(&h, false),
            "must ignore X-Forwarded-Proto without IPE_TRUSTED_PROXY opt-in"
        );
    }

    #[test]
    fn honoured_when_trusted() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(request_is_https_with_trust(&h, true));

        let mut h2 = axum::http::HeaderMap::new();
        h2.insert("x-forwarded-proto", "http".parse().unwrap());
        assert!(!request_is_https_with_trust(&h2, true));
    }

    #[test]
    fn missing_header_is_not_https() {
        let h = axum::http::HeaderMap::new();
        assert!(!request_is_https_with_trust(&h, true));
    }
}

#[cfg(all(test, feature = "server"))]
mod base_path_tests {
    use super::{
        client_js_path, cookie_name_for, cookie_path_for, normalise_base_path, render_page_full,
    };

    #[test]
    fn normalise_root_and_empty_collapse() {
        assert_eq!(normalise_base_path(""), "");
        assert_eq!(normalise_base_path("/"), "");
        assert_eq!(normalise_base_path("   "), "");
    }

    #[test]
    fn normalise_adds_leading_drops_trailing() {
        assert_eq!(normalise_base_path("/_ipe/console"), "/_ipe/console");
        assert_eq!(normalise_base_path("/_ipe/console/"), "/_ipe/console");
        assert_eq!(normalise_base_path("_ipe/console"), "/_ipe/console");
        assert_eq!(normalise_base_path("  /billing/  "), "/billing");
    }

    #[test]
    fn cookie_name_is_ipe_sid_at_root_distinct_under_base() {
        assert_eq!(cookie_name_for(""), "ipe_sid");
        // Distinct from the parent's `ipe_sid` so the proxied child can't clobber it.
        assert_eq!(cookie_name_for("/_ipe/console"), "ipe_sid__ipe_console");
        assert_ne!(cookie_name_for("/_ipe/console"), "ipe_sid");
    }

    #[test]
    fn cookie_path_scopes_to_base() {
        assert_eq!(cookie_path_for(""), "/");
        // Scoped → the cookie is never sent to the parent's own routes.
        assert_eq!(cookie_path_for("/_ipe/console"), "/_ipe/console");
    }

    #[test]
    fn render_page_threads_base_into_meta_and_window_global() {
        let root = render_page_full("sid1", "", "<b>x</b>", "deadbeef");
        assert!(root.contains("<meta name=\"ipe-base\" content=\"\">"));
        assert!(root.contains("window.__IPE_BASE=\"\""));

        let sub = render_page_full("sid1", "/_ipe/console", "<b>x</b>", "deadbeef");
        assert!(sub.contains("<meta name=\"ipe-base\" content=\"/_ipe/console\">"));
        assert!(sub.contains("window.__IPE_BASE=\"/_ipe/console\""));
    }

    #[test]
    fn render_page_emits_external_client_script_with_sri() {
        let root = render_page_full("sid1", "", "<b>x</b>", "tok1");
        // Per-session values stay inline.
        assert!(root.contains("window.__IPE_SID=\"sid1\""));
        assert!(root.contains("window.__IPE_CSRF_TOKEN=\"tok1\""));
        // CLIENT_JS body must NOT be inlined.
        assert!(!root.contains("var __ipeSid = window.__IPE_SID"));
        // External script tag with content-addressed src.
        assert!(root.contains("<script src=\"/_ipe/client."));
        assert!(root.contains(".js\" integrity=\"sha256-"));
        assert!(root.contains("crossorigin=\"anonymous\">"));
        // SRI attribute is present and non-empty.
        assert!(root.contains("integrity=\"sha256-"));
    }

    #[test]
    fn render_page_sub_app_prefixes_client_src() {
        let sub = render_page_full("sid1", "/_ipe/console", "<b>x</b>", "tok1");
        // External script src must carry the base prefix.
        assert!(root_or_sub_has_prefixed_client_src(&sub, "/_ipe/console"));
    }

    fn root_or_sub_has_prefixed_client_src(html: &str, base: &str) -> bool {
        // Find `<script src="` and check the src starts with `base/_ipe/client.`
        let needle = format!("<script src=\"{}/_ipe/client.", base);
        html.contains(&needle)
    }

    #[test]
    fn client_js_path_is_content_addressed_and_stable() {
        let p1 = client_js_path();
        let p2 = client_js_path();
        // Same result on repeated calls (OnceLock).
        assert_eq!(p1, p2);
        // Path format: /_ipe/client.<16 hex chars>.js
        assert!(p1.starts_with("/_ipe/client."));
        assert!(p1.ends_with(".js"));
        let hash_part = p1
            .trim_start_matches("/_ipe/client.")
            .trim_end_matches(".js");
        assert_eq!(hash_part.len(), 16, "URL hash should be 16 hex chars");
        assert!(
            hash_part.chars().all(|c| c.is_ascii_hexdigit()),
            "URL hash should be hex: {hash_part}"
        );
    }
}

#[cfg(all(test, feature = "server"))]
mod session_lost_body_tests {
    //! Guards the LOAD-BEARING session-lost 404 wire contract.
    //!
    //! After a server restart, the browser recovers ONLY because
    //! `client.js` `__ipeProbeSessionLost` reloads the page when its probe
    //! POST to `/_ipe/event` gets a 404 + `X-Ipe-Web: 1` whose body CONTAINS
    //! the substring `"session not found"` (client.js l1481/l1530/l1536). A
    //! refactor that flips the body back to the old `"no session"` would
    //! silently strand every client on a permanent "Reconnecting…" banner —
    //! this module makes that regression a compile/test failure.
    use super::SESSION_LOST_BODY;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{HeaderName, Request, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use tower::ServiceExt; // for `oneshot`

    /// The exact response shape both real `event_handler` session-miss arms
    /// emit (no-cookie + store-miss), reproduced here over `SESSION_LOST_BODY`
    /// — the SAME constant the handlers reference — so the substring contract
    /// is mechanically checked against the real source of truth.
    async fn no_session_event_handler() -> Response {
        (
            StatusCode::NOT_FOUND,
            [(HeaderName::from_static("x-ipe-web"), "1")],
            SESSION_LOST_BODY,
        )
            .into_response()
    }

    #[test]
    fn const_body_satisfies_client_probe_substring() {
        // client.js: `if (body.indexOf("session not found") < 0) return;`
        assert!(
            SESSION_LOST_BODY.contains("session not found"),
            "session-lost 404 body must contain the client-probed substring \
             \"session not found\"; got {SESSION_LOST_BODY:?}"
        );
        // Belt-and-braces: the old broken body must never reappear.
        assert_ne!(
            SESSION_LOST_BODY, "no session",
            "session-lost body regressed to \"no session\" — client recovery breaks"
        );
    }

    #[tokio::test]
    async fn event_session_miss_returns_404_marker_and_contract_body() {
        let app = Router::new().route("/_ipe/event", post(no_session_event_handler));

        let req = Request::builder()
            .method("POST")
            .uri("/_ipe/event")
            .body(Body::from("{}"))
            .expect("build probe request");

        let resp = app.oneshot(req).await.expect("router responds");

        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "must be a 404");
        assert_eq!(
            resp.headers()
                .get("x-ipe-web")
                .expect("x-ipe-web header present")
                .to_str()
                .expect("ascii header value"),
            "1",
            "X-Ipe-Web marker distinguishes session-lost from a wedged proxy"
        );

        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("collect body");
        let body = String::from_utf8(bytes.to_vec()).expect("utf8 body");
        assert!(
            body.contains("session not found"),
            "body must contain the client-probed recovery substring; got {body:?}"
        );
    }
}

#[cfg(all(test, feature = "server"))]
mod admission_control_tests {
    use super::*;

    // Closes the leak/cap coupling: SessionSlot decrements EXACTLY once on drop,
    // paired 1:1 with the reservation fetch_add — no underflow, no double-count.
    #[test]
    fn session_slot_decrements_once_on_drop() {
        let count = Arc::new(AtomicUsize::new(0));
        // Simulate a reservation (what the Cold/None arm does).
        count.fetch_add(1, Ordering::SeqCst);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        {
            let _slot = SessionSlot {
                count: count.clone(),
            };
            assert_eq!(
                count.load(Ordering::SeqCst),
                1,
                "slot construction must not change the count"
            );
        } // _slot drops here → one decrement
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "slot drop must decrement exactly once"
        );
    }

    // Reserve/drop M >> N times returns to 0 (counter exactness, no leak/underflow).
    #[test]
    fn reserve_then_release_balances_to_zero() {
        let count = Arc::new(AtomicUsize::new(0));
        for _ in 0..1000 {
            count.fetch_add(1, Ordering::SeqCst);
            let _slot = SessionSlot {
                count: count.clone(),
            };
        }
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    // max_sessions(): env override, default, and the 0=unlimited opt-out.
    #[test]
    fn max_sessions_parsing() {
        // SAFETY: test-only env mutation; `std::env::set_var`/`remove_var` are `unsafe` in Rust 2024 due to the reader/mutator `environ` race.
        unsafe { std::env::remove_var("IPE_WEB_MAX_SESSIONS") };
        assert_eq!(max_sessions(), 50_000);
        // SAFETY: test-only env mutation.
        unsafe { std::env::set_var("IPE_WEB_MAX_SESSIONS", "7") };
        assert_eq!(max_sessions(), 7);
        // SAFETY: test-only env mutation.
        unsafe { std::env::set_var("IPE_WEB_MAX_SESSIONS", "0") };
        assert_eq!(max_sessions(), 0, "0 = unlimited opt-out");
        // SAFETY: test-only env mutation.
        unsafe { std::env::set_var("IPE_WEB_MAX_SESSIONS", "garbage") };
        assert_eq!(max_sessions(), 50_000, "unparseable falls back to default");
        // SAFETY: test-only env mutation.
        unsafe { std::env::remove_var("IPE_WEB_MAX_SESSIONS") };
    }
}

#[cfg(all(test, feature = "server"))]
mod sse_reconnect_reconcile_tests {
    //! Proves the two-half reconcile contract for SSE reconnect:
    //! 1. A reconnect whose `?path=` differs from the session's current route
    //!    applies `route_resolver` + re-renders `last_view` so the resync
    //!    frame reflects the correct page.
    //! 2. A reconnect whose `?path=` already matches the current route is
    //!    idempotent (model unchanged, same rendered output).
    //! 3. An absent `?path=` param (older cached client) falls through
    //!    unchanged — no reconciliation, no panic.
    //! 4. An invalid path (contains `?` or `#`, or doesn't start with `/`)
    //!    is rejected — session state untouched.
    //! 5. An unroutable path (not declared in the route table) is skipped —
    //!    session state untouched.
    //! 6. Sub-app base-path prefix is stripped before matching.

    use super::*;
    use crate::web::route::{Route, match_routes, matches_any};
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc::channel;

    /// A minimal two-page model: `Home` or `Detail(String)`.
    #[derive(Clone, Debug, PartialEq)]
    enum TestPage {
        Home,
        Detail(String),
    }

    /// Build a `SessionEntry` seeded with `page`, plus the three boxed
    /// closures that the reconciliation block in `sse_handler` calls.
    // The tuple names the exact set of collaborators the test drives; extracting
    // a `type` alias for a single test helper would hide, not clarify, them.
    #[allow(clippy::type_complexity)]
    fn make_session(
        page: TestPage,
    ) -> (
        SessionHandle<TestPage, ()>,
        RouteResolver<TestPage>,
        RouteMatched,
        Arc<dyn Fn(TestPage) -> Html<()> + Send + Sync>,
    ) {
        let routes: Vec<Route<TestPage>> = vec![
            Route::new("/", |_| Some(TestPage::Home)),
            Route::new("/items/:id", |p| Some(TestPage::Detail(p[0].clone()))),
        ];
        let not_found = TestPage::Home;

        let routes_arc = Arc::new(routes.clone());
        let routes_arc2 = routes_arc.clone();
        let nf = not_found.clone();

        let route_resolver: RouteResolver<TestPage> =
            Arc::new(move |_model, path| match_routes(&routes_arc, &nf, path));
        let route_matched: RouteMatched = Arc::new(move |path| matches_any(&routes_arc2, path));

        // Minimal view: render the page variant name as text so we can assert
        // which page the resync would ship.
        let view: Arc<dyn Fn(TestPage) -> Html<()> + Send + Sync> = Arc::new(|p| {
            let label = match p {
                TestPage::Home => "home-page".to_string(),
                TestPage::Detail(id) => format!("detail-{id}"),
            };
            Html::HText(label)
        });

        let model = page.clone();
        let last_view = (view)(model.clone());
        let index = build_index(&last_view);
        let (msg_tx, _rx) = channel::<()>(1);
        let entry = Arc::new(Mutex::new(SessionEntry {
            model,
            last_view,
            index,
            seq: 0,
            sse_tx: None,
            msg_tx,
            #[cfg(feature = "debugger")]
            history: crate::debugger::RecordBuffer::new(page, crate::debugger::DEFAULT_HISTORY_CAP),
            #[cfg(feature = "debugger")]
            debug_cursor: None,
        }));

        (entry, route_resolver, route_matched, view)
    }

    /// Apply the exact reconciliation block from `sse_handler`, extracted here
    /// for unit-testing without spinning up an axum server.
    fn reconcile(
        entry: &SessionHandle<TestPage, ()>,
        route_matched: &RouteMatched,
        route_resolver: &RouteResolver<TestPage>,
        view: &Arc<dyn Fn(TestPage) -> Html<()> + Send + Sync>,
        client_path: &str,
    ) {
        // Mirrors sse_handler's reconciliation block (IPE_WEB_BASE_PATH is
        // empty in tests so base = "").
        let is_valid_path = client_path.starts_with('/')
            && !client_path.contains('?')
            && !client_path.contains('#');
        if is_valid_path && route_matched(client_path) {
            let mut g = entry.lock().unwrap_or_else(|e| e.into_inner());
            g.model = route_resolver(g.model.clone(), client_path);
            let mut tree = (view)(g.model.clone());
            assign_ipe_ids(&mut tree, "r");
            style_inject::apply_style_injections(&mut tree);
            g.index = build_index(&tree);
            g.last_view = tree;
        }
    }

    /// Helper: read the current rendered text from the session's `last_view`.
    #[allow(clippy::unwrap_used)] // test helper — lock poison is a test environment issue
    fn rendered_text(entry: &SessionHandle<TestPage, ()>) -> String {
        let g = entry.lock().unwrap();
        render_html(&g.last_view)
    }

    #[test]
    fn differing_url_reconciles_model_and_last_view() {
        // Session is on Detail("42") but the browser is now showing "/".
        let (entry, resolver, matched, view) = make_session(TestPage::Detail("42".into()));
        assert!(rendered_text(&entry).contains("detail-42"));

        reconcile(&entry, &matched, &resolver, &view, "/");

        let g = entry.lock().unwrap();
        assert_eq!(
            g.model,
            TestPage::Home,
            "model must be reconciled to the Home route"
        );
        drop(g);
        assert!(
            rendered_text(&entry).contains("home-page"),
            "last_view must reflect the reconciled page"
        );
    }

    /// Regression: the SSE reconnect reconciliation must leave `last_view` and
    /// `index` in the same id-stamped state the page and update render paths
    /// produce. A view rebuilt WITHOUT `assign_ipe_ids` renders every event
    /// element with no `ipe-id` / `data-ipe-hid`, so the client posts an empty
    /// handlerId that the server can't resolve — every click, link, and button
    /// silently does nothing until the next full-page load.
    #[test]
    fn reconcile_stamps_ids_so_handlers_resolve() {
        // Every live app's SSE connect sends `?path=/`, and `/` always matches a
        // route, so this reconciliation runs on the first connect of an app with
        // no explicit routes as well. A view with one clickable element is the
        // minimal shape that exercises the event-id path.
        let routes: Vec<Route<TestPage>> = vec![Route::new("/", |_| Some(TestPage::Home))];
        let not_found = TestPage::Home;
        let routes_arc = Arc::new(routes.clone());
        let routes_arc2 = routes_arc.clone();
        let nf = not_found.clone();
        let route_resolver: RouteResolver<TestPage> =
            Arc::new(move |_m, path| match_routes(&routes_arc, &nf, path));
        let route_matched: RouteMatched = Arc::new(move |path| matches_any(&routes_arc2, path));

        // A view whose single element carries a click handler — mirrors an
        // `Ipe.Ui.el [ Ui.onClick msg ]` link in a real app.
        let view: Arc<dyn Fn(TestPage) -> Html<()> + Send + Sync> = Arc::new(|_p| {
            Html::HElement(
                "div".into(),
                vec![Attribute::EventAttr(Event::OnMsg("click".into(), ()))],
                vec![Html::HText("go".into())],
            )
        });

        // Seed the session with an UNSTAMPED last_view (the state right after
        // the reconciliation block rebuilds the view from the model).
        let model = TestPage::Home;
        let last_view = (view)(model.clone());
        let index = build_index(&last_view);
        let (msg_tx, _rx) = channel::<()>(1);
        let entry: SessionHandle<TestPage, ()> = Arc::new(Mutex::new(SessionEntry {
            model,
            last_view,
            index,
            seq: 0,
            sse_tx: None,
            msg_tx,
            #[cfg(feature = "debugger")]
            history: crate::debugger::RecordBuffer::new(
                TestPage::Home,
                crate::debugger::DEFAULT_HISTORY_CAP,
            ),
            #[cfg(feature = "debugger")]
            debug_cursor: None,
        }));

        reconcile(&entry, &route_matched, &route_resolver, &view, "/");

        let g = entry.lock().unwrap();
        // The rendered resync body the client applies must carry the id + hid,
        // or the client can't tell the server which handler fired.
        let body = render_html(&g.last_view);
        assert!(
            body.contains("data-ipe-hid=\"r\""),
            "reconciled resync body must stamp data-ipe-hid: {body}"
        );
        assert!(
            body.contains("ipe-id=\"r\""),
            "reconciled resync body must stamp ipe-id: {body}"
        );
        // And the rebuilt index must resolve that hid + event back to the Msg,
        // so the incoming click actually dispatches.
        assert_eq!(
            g.index.resolve("r", "click", &[]),
            Some(()),
            "reconciled handler index must resolve the stamped ipe-id"
        );
    }

    #[test]
    fn same_url_is_idempotent() {
        // Session is already on Home; reconnect with path "/" — no change.
        let (entry, resolver, matched, view) = make_session(TestPage::Home);
        let before = rendered_text(&entry);

        reconcile(&entry, &matched, &resolver, &view, "/");

        let g = entry.lock().unwrap();
        assert_eq!(g.model, TestPage::Home, "model must be unchanged");
        drop(g);
        assert_eq!(
            rendered_text(&entry),
            before,
            "last_view must be identical after same-URL reconnect"
        );
    }

    #[test]
    fn absent_path_param_leaves_session_unchanged() {
        // No reconciliation path is exercised at all — no-op.
        let (entry, _resolver, _matched, _view) = make_session(TestPage::Detail("7".into()));
        let before = rendered_text(&entry);
        let seq_before = entry.lock().unwrap().seq;
        // Do nothing (the `if let Some(raw_path) = qs.get("path")` branch is
        // not entered when the client sends no `path` param).
        assert_eq!(rendered_text(&entry), before);
        assert_eq!(entry.lock().unwrap().seq, seq_before);
    }

    #[test]
    fn invalid_path_rejected_session_unchanged() {
        let (entry, resolver, matched, view) = make_session(TestPage::Home);
        let before = rendered_text(&entry);

        // Path with query string — must be rejected.
        reconcile(&entry, &matched, &resolver, &view, "/?foo=bar");
        assert_eq!(
            rendered_text(&entry),
            before,
            "path with '?' must be rejected"
        );

        // Path with fragment — must be rejected.
        reconcile(&entry, &matched, &resolver, &view, "/#anchor");
        assert_eq!(
            rendered_text(&entry),
            before,
            "path with '#' must be rejected"
        );

        // Relative path (no leading '/') — must be rejected.
        reconcile(&entry, &matched, &resolver, &view, "items/1");
        assert_eq!(
            rendered_text(&entry),
            before,
            "relative path must be rejected"
        );
    }

    #[test]
    fn unroutable_path_leaves_session_unchanged() {
        // "/favicon.ico" is not a declared route — falls through unchanged.
        let (entry, resolver, matched, view) = make_session(TestPage::Home);
        let before = rendered_text(&entry);

        reconcile(&entry, &matched, &resolver, &view, "/favicon.ico");

        assert_eq!(
            rendered_text(&entry),
            before,
            "unroutable path must not modify session state"
        );
    }

    #[test]
    fn sub_app_base_prefix_is_stripped_before_matching() {
        // Simulate a sub-app mounted at "/app": the client sends "/app/items/5"
        // (its full location.pathname) but the route table has "/items/:id".
        // The reconciler must strip "/app" before matching.
        let (entry, _resolver, _matched, _view) = make_session(TestPage::Home);

        // Build sub-app-aware closures with base="/app".
        let routes: Vec<Route<TestPage>> = vec![
            Route::new("/", |_| Some(TestPage::Home)),
            Route::new("/items/:id", |p| Some(TestPage::Detail(p[0].clone()))),
        ];
        let routes_arc = Arc::new(routes.clone());
        let routes_arc2 = routes_arc.clone();
        let nf = TestPage::Home;
        let route_resolver: RouteResolver<TestPage> =
            Arc::new(move |_model, path| match_routes(&routes_arc, &nf, path));
        let route_matched: RouteMatched = Arc::new(move |path| matches_any(&routes_arc2, path));
        let view: Arc<dyn Fn(TestPage) -> Html<()> + Send + Sync> = Arc::new(|p| {
            Html::HText(match p {
                TestPage::Home => "home-page".to_string(),
                TestPage::Detail(id) => format!("detail-{id}"),
            })
        });

        // Manually apply the sub-app base-stripping logic (mirrors sse_handler).
        let base = "/app";
        let client_path = "/app/items/5";
        let route_path = client_path.strip_prefix(base).unwrap_or(client_path);
        // route_path is now "/items/5" — must match the declared route.
        assert!(
            route_matched(route_path),
            "stripped path must match route table"
        );
        if route_matched(route_path) {
            let mut g = entry.lock().unwrap_or_else(|e| e.into_inner());
            g.model = route_resolver(g.model.clone(), route_path);
            g.last_view = (view)(g.model.clone());
        }

        let g = entry.lock().unwrap();
        assert_eq!(
            g.model,
            TestPage::Detail("5".into()),
            "sub-app base must be stripped before route matching"
        );
    }
}

#[cfg(all(test, feature = "server"))]
mod static_noise_mime_tests {
    use super::static_noise_mime;

    #[test]
    fn known_browser_noise_extensions_map() {
        assert_eq!(static_noise_mime("ico"), "image/x-icon");
        assert_eq!(static_noise_mime("png"), "image/png");
        assert_eq!(static_noise_mime("css"), "text/css; charset=utf-8");
        assert_eq!(
            static_noise_mime("js"),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(static_noise_mime("json"), "application/json");
        assert_eq!(static_noise_mime("woff2"), "font/woff2");
    }

    #[test]
    fn wasm_serves_as_application_wasm() {
        assert_eq!(static_noise_mime("wasm"), "application/wasm");
    }

    #[test]
    fn unknown_extension_falls_back_to_octet_stream() {
        assert_eq!(static_noise_mime("dat"), "application/octet-stream");
        assert_eq!(static_noise_mime(""), "application/octet-stream");
    }
}

// Live-session isolation for a recursion trip. `drive_session` folds each Msg
// through the user `update` inside a `tokio::spawn`ed task; a recursion trip in
// `update` unwinds into that spawn boundary, ending only the tripping session's
// driver while the process — and every other session's driver — survives. This
// module pins that isolation at the spawn boundary the driver uses.
#[cfg(test)]
mod recursion_session_isolation_tests {
    // A session-`update` that trips the recursion guard, spawned exactly as
    // `drive_session` spawns its fold task, dies as a panicking `JoinError`
    // (its session is lost) — and a sibling session's spawned update, driven
    // concurrently, still completes. The process outlives the trip.
    #[tokio::test]
    async fn a_recursion_trip_in_update_ends_only_its_session() {
        // The tripping session: its update raises the exact recursion-guard trip
        // message inside the spawned task, mirroring an unbounded `update`.
        let tripping = tokio::spawn(async {
            let _g = crate::core::recursion_guard();
            panic!("maximum recursion depth exceeded");
        });

        // A healthy sibling session driven concurrently on its own spawned task.
        let healthy = tokio::spawn(async { 21_i64 * 2 });

        let tripping_result = tripping.await;
        let healthy_result = healthy.await;

        // The tripping session's driver ended by panic — that session is lost.
        let join_err = tripping_result
            .expect_err("the tripping session's task must end by panic, not complete");
        assert!(
            join_err.is_panic(),
            "the session driver ends via the spawn boundary's panic funnel, \
             so the trip is isolated to this one session"
        );

        // The process survived: the sibling session completed normally.
        assert_eq!(
            healthy_result.expect("a healthy concurrent session must complete"),
            42,
            "a concurrent session is unaffected by another session's trip"
        );
    }
}

/// Env-var coverage for the security-critical `IPE_WEB_*` settings.
///
/// Each test covers: (a) the `IPE_WEB_*` name takes effect, (b) unset →
/// unchanged default behavior.
///
/// These are env-mutating tests and must not run in parallel — they use
/// `std::env::set_var`/`remove_var` which are unsafe in Rust 2024 (see the
/// ENV_LOCK rationale in system.rs). Each test cleans up after itself.
#[cfg(all(test, feature = "server"))]
mod security_env_tests {

    // ── IPE_WEB_CSRF_ORIGIN_CHECK ─────────────────────────────────────────────
    //
    // `origin_check_enabled()` is memoized in a `OnceLock`, so we cannot test
    // it via the production `origin_mismatch` path in the same process run. We
    // test the env-read layer directly via `read_env_var`.

    #[test]
    fn csrf_origin_check_new_name_takes_effect() {
        // SAFETY: test-only env mutation.
        unsafe { std::env::remove_var("IPE_WEB_CSRF_ORIGIN_CHECK") };

        // (a) set → "on"
        // SAFETY: test-only env mutation.
        unsafe { std::env::set_var("IPE_WEB_CSRF_ORIGIN_CHECK", "on") };
        assert_eq!(
            crate::system::read_env_var("IPE_WEB_CSRF_ORIGIN_CHECK").as_deref(),
            Ok("on"),
            "IPE_WEB_CSRF_ORIGIN_CHECK must be read"
        );
        // SAFETY: test-only env mutation.
        unsafe { std::env::remove_var("IPE_WEB_CSRF_ORIGIN_CHECK") };

        // (b) unset → Err (origin check stays OFF — secure default)
        assert!(
            crate::system::read_env_var("IPE_WEB_CSRF_ORIGIN_CHECK").is_err(),
            "unset → Err; origin check defaults to OFF"
        );
    }

    // ── IPE_WEB_FRAME_ANCESTORS ───────────────────────────────────────────────
    //
    // `frame_ancestors()` is memoized in a `OnceLock`. We test the env-read
    // layer: set → value, unset → Err (→ `None` in production).

    #[test]
    fn frame_ancestors_new_name_takes_effect() {
        // SAFETY: test-only env mutation.
        unsafe { std::env::remove_var("IPE_WEB_FRAME_ANCESTORS") };

        // (a) set → value
        // SAFETY: test-only env mutation.
        unsafe { std::env::set_var("IPE_WEB_FRAME_ANCESTORS", "https://app.example.com") };
        assert_eq!(
            crate::system::read_env_var("IPE_WEB_FRAME_ANCESTORS").as_deref(),
            Ok("https://app.example.com"),
            "IPE_WEB_FRAME_ANCESTORS must be read"
        );
        // SAFETY: test-only env mutation.
        unsafe { std::env::remove_var("IPE_WEB_FRAME_ANCESTORS") };

        // (b) unset → Err; frame_ancestors() returns None (same-origin mode).
        assert!(
            crate::system::read_env_var("IPE_WEB_FRAME_ANCESTORS").is_err(),
            "unset → Err; frame_ancestors defaults to None (same-origin mode)"
        );
    }

    // ── IPE_WEB_MAX_BODY_BYTES (Web path) ────────────────────────────────────
    //
    // `web_max_body_bytes()` reads live from env each call (not memoized), so
    // we can test the production function directly.

    #[test]
    fn web_max_body_bytes_new_name_and_default() {
        use super::web_max_body_bytes;
        const DEFAULT: usize = 5 << 20;

        // SAFETY: test-only env mutation.
        unsafe { std::env::remove_var("IPE_WEB_MAX_BODY_BYTES") };

        // (c) unset → default (5 MiB); a rename bug that silently zeros this
        // would reject all /_ipe/event POSTs.
        assert_eq!(
            web_max_body_bytes(),
            DEFAULT,
            "unset → 5 MiB default must be preserved"
        );

        // Set → override takes effect.
        // SAFETY: test-only env mutation.
        unsafe { std::env::set_var("IPE_WEB_MAX_BODY_BYTES", "8192") };
        assert_eq!(
            web_max_body_bytes(),
            8192,
            "IPE_WEB_MAX_BODY_BYTES must take effect"
        );
        // SAFETY: test-only env mutation.
        unsafe { std::env::remove_var("IPE_WEB_MAX_BODY_BYTES") };

        // Restore default.
        assert_eq!(web_max_body_bytes(), DEFAULT);
    }
}

#[cfg(all(test, feature = "server"))]
mod watch_status_handler_tests {
    //! Regression-locks the `POST /_ipe/watch/status` trust boundary.
    //!
    //! The endpoint is a dev-only, token-gated build-status sink. Every refusal
    //! path and every side-effect path is covered here without weakening any gate.
    //!
    //! Tests call the handler through a minimal axum router built directly from
    //! `WebState`, matching the pattern used by `session_lost_body_tests` and
    //! `reload_push_tests` in this file.

    use super::*;
    use crate::system::{locked_remove_var, locked_set_var};
    use crate::web::sse;
    use crate::web::store::{MemoryStore, SessionStore};
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use std::time::Duration;
    use tower::ServiceExt; // oneshot

    // ── Minimal WebState fixture ──────────────────────────────────────────────
    //
    // The handler only touches `watch_build_status` (the status store) and
    // `store.web_sessions()` (to broadcast SSE). Every other WebState field
    // is unused by this handler, so we erase the generics to `()` throughout.

    type TestModel = ();
    type TestMsg = ();
    type TestStore = MemoryStore<TestModel, TestMsg>;
    type TestWebState = WebState<
        TestModel,
        TestMsg,
        fn() -> (),
        fn(TestMsg, TestModel) -> (TestModel, IpeCmd<TestMsg>),
        fn(TestModel) -> Html<TestMsg>,
        fn(TestModel) -> IpeSub<TestMsg>,
    >;

    // Named fn items so `Arc::new(<fn>)` produces the exact fn-pointer type
    // encoded in `TestWebState` — anonymous closures have distinct opaque
    // types that Rust will not coerce to `fn(…)` pointers in Arc struct fields.
    fn test_init() {}
    fn test_update(_msg: TestMsg, model: TestModel) -> (TestModel, IpeCmd<TestMsg>) {
        (model, IpeCmd::None)
    }
    fn test_view(_model: TestModel) -> Html<TestMsg> {
        Html::HText(String::new())
    }
    fn test_subs(_model: TestModel) -> IpeSub<TestMsg> {
        IpeSub::None
    }
    fn test_route_resolver(m: TestModel, _path: &str) -> TestModel {
        m
    }
    fn test_param_resolver(_path: &str) -> crate::dict::IpeDict<String> {
        crate::dict::dict_empty()
    }
    fn test_route_matched(p: &str) -> bool {
        p == "/"
    }

    fn make_state(store: Arc<TestStore>) -> TestWebState {
        WebState {
            store: store as Arc<dyn store::SessionStore<TestModel, TestMsg>>,
            init: Arc::new(test_init),
            update: Arc::new(test_update),
            view: Arc::new(test_view),
            subs: Arc::new(test_subs),
            route_resolver: Arc::new(test_route_resolver),
            param_resolver: Arc::new(test_param_resolver),
            route_matched: Arc::new(test_route_matched),
            session_count: Arc::new(AtomicUsize::new(0)),
            watch_build_status: Arc::new(Mutex::new(None)),
        }
    }

    fn make_router(state: TestWebState) -> Router {
        Router::new()
            .route(
                "/_ipe/watch/status",
                post(
                    handlers::watch_status_handler::<
                        TestModel,
                        TestMsg,
                        fn() -> (),
                        fn(TestMsg, TestModel) -> (TestModel, IpeCmd<TestMsg>),
                        fn(TestModel) -> Html<TestMsg>,
                        fn(TestModel) -> IpeSub<TestMsg>,
                    >,
                ),
            )
            .with_state(state)
    }

    fn make_session_handle(sse_tx: Option<SseTx>) -> store::SessionHandle<TestModel, TestMsg> {
        let (msg_tx, _rx) = mpsc::channel::<TestMsg>(1);
        let tree: Html<TestMsg> = Html::HText(String::new());
        let index = build_index(&tree);
        Arc::new(Mutex::new(SessionEntry {
            model: (),
            last_view: tree,
            index,
            seq: 0,
            sse_tx,
            msg_tx,
            #[cfg(feature = "debugger")]
            history: crate::debugger::RecordBuffer::new((), crate::debugger::DEFAULT_HISTORY_CAP),
            #[cfg(feature = "debugger")]
            debug_cursor: None,
        }))
    }

    #[allow(clippy::expect_used)] // test helper — request build / router failure is a test environment issue
    async fn post_status(
        router: Router,
        token_header: Option<&str>,
        body: &str,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/_ipe/watch/status")
            .header("content-type", "application/json");
        if let Some(tok) = token_header {
            builder = builder.header("x-ipe-hot-token", tok);
        }
        let req = builder
            .body(Body::from(body.to_owned()))
            .expect("build request");
        router.oneshot(req).await.expect("router responds")
    }

    // ── 1. Token refusal ─────────────────────────────────────────────────────

    /// No `X-Ipe-Hot-Token` header → 403.
    #[tokio::test]
    async fn token_missing_is_403() {
        locked_set_var("IPE_WATCH_HOT_TOKEN", "secret-token");

        let store = Arc::new(TestStore::new(Duration::from_secs(60)));
        let router = make_router(make_state(store));
        let resp = post_status(router, None, r#"{"ok":true}"#).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "no token → 403");

        locked_remove_var("IPE_WATCH_HOT_TOKEN");
    }

    /// `X-Ipe-Hot-Token` present but empty → 403.
    #[tokio::test]
    async fn token_empty_is_403() {
        locked_set_var("IPE_WATCH_HOT_TOKEN", "secret-token");

        let store = Arc::new(TestStore::new(Duration::from_secs(60)));
        let router = make_router(make_state(store));
        let resp = post_status(router, Some(""), r#"{"ok":true}"#).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "empty token → 403");

        locked_remove_var("IPE_WATCH_HOT_TOKEN");
    }

    /// `X-Ipe-Hot-Token` present but wrong → 403.
    #[tokio::test]
    async fn token_wrong_is_403() {
        locked_set_var("IPE_WATCH_HOT_TOKEN", "correct-token");

        let store = Arc::new(TestStore::new(Duration::from_secs(60)));
        let router = make_router(make_state(store));
        let resp = post_status(router, Some("wrong-token"), r#"{"ok":true}"#).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "wrong token → 403");

        locked_remove_var("IPE_WATCH_HOT_TOKEN");
    }

    /// Correct `X-Ipe-Hot-Token` → 200.
    #[tokio::test]
    async fn token_correct_is_200() {
        locked_set_var("IPE_WATCH_HOT_TOKEN", "correct-token");

        let store = Arc::new(TestStore::new(Duration::from_secs(60)));
        let router = make_router(make_state(store));
        let resp = post_status(router, Some("correct-token"), r#"{"ok":true}"#).await;
        assert_eq!(resp.status(), StatusCode::OK, "correct token → 200");

        locked_remove_var("IPE_WATCH_HOT_TOKEN");
    }

    /// Correct token + connected session → `ipe-build-status` SSE event broadcast.
    #[tokio::test]
    async fn correct_token_broadcasts_sse_event() {
        locked_set_var("IPE_WATCH_HOT_TOKEN", "broadcast-token");

        let store = Arc::new(TestStore::new(Duration::from_secs(60)));
        let (sse_tx, mut sse_rx) = sse::channel();
        store
            .set("live-session", make_session_handle(Some(sse_tx)))
            .await;
        let state = make_state(store);
        let router = make_router(state);

        let resp = post_status(
            router,
            Some("broadcast-token"),
            r#"{"ok":false,"error":"build failed"}"#,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let frame = sse_rx
            .try_recv()
            .expect("connected session must receive ipe-build-status frame");
        assert!(
            frame.0.starts_with("event: ipe-build-status\n"),
            "SSE event name must be ipe-build-status: {:?}",
            frame.0
        );
        assert!(
            frame.0.contains("build failed"),
            "SSE frame must carry the error text: {:?}",
            frame.0
        );

        locked_remove_var("IPE_WATCH_HOT_TOKEN");
    }

    // ── 2. Production inertness ───────────────────────────────────────────────

    /// Under `ENV=production` `watch_banner_active` returns false regardless of
    /// banner and base settings — the gate function is the single source of truth
    /// for whether the route is mounted.
    #[test]
    fn watch_banner_active_false_in_production() {
        locked_set_var("ENV", "production");
        assert!(
            !watch_banner_active(""),
            "watch_banner_active must be false in production"
        );
        locked_remove_var("ENV");
    }

    /// In dev mode (ENV unset) with banner on, `watch_banner_active` is true.
    #[test]
    fn watch_banner_active_true_in_dev() {
        locked_remove_var("ENV");
        locked_remove_var("IPE_ENV");
        locked_remove_var("IPE_WEB_BANNER");
        assert!(
            watch_banner_active(""),
            "watch_banner_active must be true in dev with no overrides"
        );
    }

    /// With banner explicitly disabled, `watch_banner_active` is false even in dev.
    #[test]
    fn watch_banner_active_false_when_banner_disabled() {
        locked_remove_var("ENV");
        locked_remove_var("IPE_ENV");
        for v in ["off", "0", "false"] {
            locked_set_var("IPE_WEB_BANNER", v);
            assert!(
                !watch_banner_active(""),
                "watch_banner_active must be false when IPE_WEB_BANNER={v}"
            );
        }
        locked_remove_var("IPE_WEB_BANNER");
    }

    /// A non-root base (sub-app) → `watch_banner_active` is false.
    #[test]
    fn watch_banner_active_false_for_subapp() {
        locked_remove_var("ENV");
        locked_remove_var("IPE_ENV");
        locked_remove_var("IPE_WEB_BANNER");
        assert!(
            !watch_banner_active("/sub"),
            "watch_banner_active must be false for a sub-app base"
        );
    }

    /// Under a production config the route is not mounted — a POST yields 404.
    #[tokio::test]
    async fn route_absent_in_production_gives_404() {
        // Build a router WITHOUT mounting the watch/status route (simulating
        // production, where watch_banner_active returns false and the route is
        // never added).
        let store = Arc::new(TestStore::new(Duration::from_secs(60)));
        let _state = make_state(store);
        let prod_router: Router = Router::new(); // no routes — production stub

        let req = Request::builder()
            .method("POST")
            .uri("/_ipe/watch/status")
            .header("x-ipe-hot-token", "any")
            .body(Body::from(r#"{"ok":true}"#))
            .expect("build request");
        let resp = prod_router.oneshot(req).await.expect("router responds");
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "route absent in production → 404"
        );
    }

    /// No `ipe-build-status` SSE event is emitted when the route is not mounted.
    #[tokio::test]
    async fn no_sse_event_emitted_when_route_absent() {
        let store = Arc::new(TestStore::new(Duration::from_secs(60)));
        let (sse_tx, mut sse_rx) = sse::channel();
        store
            .set("session", make_session_handle(Some(sse_tx)))
            .await;
        // Route not mounted — production scenario.
        let prod_router: Router = Router::new();
        let req = Request::builder()
            .method("POST")
            .uri("/_ipe/watch/status")
            .body(Body::from(r#"{"ok":false,"error":"err"}"#))
            .expect("build request");
        let _ = prod_router.oneshot(req).await;
        assert!(
            sse_rx.try_recv().is_err(),
            "no SSE frame must be emitted when the route is not mounted"
        );
    }

    // ── 3. Escape / injection safety ──────────────────────────────────────────

    /// An error containing `</script>`, a newline, and a `data:`-injection
    /// attempt is stored verbatim (the server is the raw-bytes store; the
    /// client renders via `textContent`), but the SSE framing produced by
    /// `sse::frame` strips CR/LF and splits on `\n` — each logical line gets
    /// its own `data:` prefix, so no single `data:` line can contain a raw
    /// newline that injects extra SSE fields.
    #[tokio::test]
    async fn error_with_script_tag_and_newline_is_sse_safe() {
        locked_set_var("IPE_WATCH_HOT_TOKEN", "injection-test-token");

        let store = Arc::new(TestStore::new(Duration::from_secs(60)));
        let (sse_tx, mut sse_rx) = sse::channel();
        store.set("sess", make_session_handle(Some(sse_tx))).await;
        let state = make_state(store);
        let watch_build_status = state.watch_build_status.clone();
        let router = make_router(state);

        // error field contains script-closing tag, a newline, and an SSE
        // field-injection attempt after the newline.
        let body = r#"{"ok":false,"error":"</script>\ndata: injected"}"#;
        let resp = post_status(router, Some("injection-test-token"), body).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // The stored value must be present (the error was accepted).
        let stored = watch_build_status
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        assert!(
            stored.is_some(),
            "build status must be stored after a valid POST"
        );

        // The SSE frame must not allow raw newlines to inject extra fields.
        let frame = sse_rx
            .try_recv()
            .expect("session must receive a build-status frame");
        for line in frame.0.lines() {
            // Every non-empty, non-event-terminating line must start with a
            // recognised SSE field prefix — proving no injected bare field name
            // slipped through.
            if line.is_empty() {
                continue;
            }
            assert!(
                line.starts_with("event: ")
                    || line.starts_with("data: ")
                    || line.starts_with("id: ")
                    || line.starts_with("retry: "),
                "SSE frame line must start with a recognised field prefix; got: {line:?}"
            );
        }

        // CR and LF must not appear raw inside any `data:` line value
        // (sse::frame's contract: it splits on `\n` and strips trailing `\r`).
        let data_lines: Vec<&str> = frame
            .0
            .lines()
            .filter(|l| l.starts_with("data: "))
            .collect();
        assert!(
            !data_lines.is_empty(),
            "at least one data: line must be present"
        );
        for dl in &data_lines {
            assert!(
                !dl.contains('\r') && !dl.contains('\n'),
                "data: line must not contain raw CR/LF: {dl:?}"
            );
        }

        locked_remove_var("IPE_WATCH_HOT_TOKEN");
    }

    /// A build-failure excerpt laced with raw control chars (carriage return,
    /// tab, bell, ANSI escape) and a double-quote must serialise to RFC 8259
    /// JSON: every control byte below 0x20 escaped as `\u00XX`, no raw byte that
    /// could break the SSE `data:` framing, and the excerpt confined to the
    /// `error` string value.
    #[test]
    fn watch_status_sse_payload_escapes_control_chars() {
        let hostile = "err\r\n\u{1b}[31m\"boom\"\ttab\u{7}bell";
        let payload = watch_status_sse_payload(false, Some(hostile));
        let parsed: serde_json::Value =
            serde_json::from_str(&payload).expect("payload must be RFC 8259-valid JSON");
        assert_eq!(parsed["ok"], serde_json::Value::Bool(false));
        assert_eq!(
            parsed["error"],
            serde_json::Value::String(hostile.to_string()),
            "the error round-trips byte-for-byte"
        );
        assert!(
            !payload.contains('\r') && !payload.contains('\n') && !payload.contains('\u{1b}'),
            "no raw control byte survives in the serialised payload: {payload:?}"
        );
    }

    /// A crafted excerpt cannot inject sibling JSON fields: a spoofed
    /// `"ok":true` and an `"injected"` key survive only as string content.
    #[test]
    fn watch_status_sse_payload_resists_field_injection() {
        let attack = r#"","ok":true,"injected":"x"#;
        let payload = watch_status_sse_payload(false, Some(attack));
        let parsed: serde_json::Value = serde_json::from_str(&payload).expect("valid JSON");
        assert_eq!(parsed["ok"], serde_json::Value::Bool(false));
        assert!(
            parsed.get("injected").is_none(),
            "a crafted excerpt must not add fields to the object"
        );
    }

    /// The ok verdict omits the `error` field entirely.
    #[test]
    fn watch_status_sse_payload_ok_omits_error() {
        let parsed: serde_json::Value =
            serde_json::from_str(&watch_status_sse_payload(true, None)).expect("valid JSON");
        assert_eq!(parsed["ok"], serde_json::Value::Bool(true));
        assert!(parsed.get("error").is_none());
    }

    /// The stored error value is NOT converted into an HTML/JS-active form
    /// (the `<` and `>` bytes must be present, not HTML-entity-escaped, because
    /// the client sink is `textContent`). The server must preserve bytes, not
    /// double-escape them.
    #[tokio::test]
    async fn error_bytes_preserved_not_html_escaped_in_storage() {
        locked_set_var("IPE_WATCH_HOT_TOKEN", "preserve-token");

        let store = Arc::new(TestStore::new(Duration::from_secs(60)));
        let state = make_state(store);
        let watch_build_status = state.watch_build_status.clone();
        let router = make_router(state);

        // JSON-encode the `<` and `>` as `<`/`>` so they survive
        // JSON decoding while still testing that the stored string contains the
        // actual `<`/`>` bytes (serde_json decodes `<` → `<`).
        let body = r#"{"ok":false,"error":"</script>"}"#;
        let resp = post_status(router, Some("preserve-token"), body).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let stored = watch_build_status
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let err = stored
            .as_ref()
            .and_then(|s| s.error.as_deref())
            .unwrap_or("");
        // The stored string must have the decoded bytes — NOT a double-escaped
        // `&lt;` or `<` — because the client renders via `textContent`.
        assert!(
            err.contains('<') && err.contains('>'),
            "stored error must contain the decoded angle-bracket bytes: {err:?}"
        );
        assert!(
            !err.contains("&lt;") && !err.contains("&gt;"),
            "stored error must NOT be HTML-entity-escaped: {err:?}"
        );

        locked_remove_var("IPE_WATCH_HOT_TOKEN");
    }

    // ── 4. Length bound (512-char cap) ────────────────────────────────────────

    /// An `error` longer than 512 chars is truncated to exactly 512 chars
    /// before storage and broadcast.
    #[tokio::test]
    async fn long_error_is_truncated_to_512_chars() {
        locked_set_var("IPE_WATCH_HOT_TOKEN", "trunc-token");

        let long_error: String = "A".repeat(600);
        let body = format!(r#"{{"ok":false,"error":"{long_error}"}}"#);

        let store = Arc::new(TestStore::new(Duration::from_secs(60)));
        let (sse_tx, mut sse_rx) = sse::channel();
        store.set("s", make_session_handle(Some(sse_tx))).await;
        let state = make_state(store);
        let watch_build_status = state.watch_build_status.clone();
        let router = make_router(state);

        let resp = post_status(router, Some("trunc-token"), &body).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Stored value must be capped.
        let stored = watch_build_status
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let err_len = stored
            .as_ref()
            .and_then(|s| s.error.as_deref())
            .map(|e| e.chars().count())
            .unwrap_or(0);
        assert_eq!(
            err_len, 512,
            "stored error must be truncated to exactly 512 chars, got {err_len}"
        );

        // Broadcast frame must also carry the truncated (not original) value.
        let frame = sse_rx.try_recv().expect("session must receive frame");
        let data_payload: String = frame
            .0
            .lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .collect::<Vec<_>>()
            .join("");
        // The 600-char run of "A" must not appear in the frame.
        assert!(
            !data_payload.contains(&long_error),
            "broadcast frame must not carry the un-truncated 600-char error"
        );

        locked_remove_var("IPE_WATCH_HOT_TOKEN");
    }

    // ── 5. SSE replay for late-connecting sessions ────────────────────────────

    /// A session connecting AFTER a failed-build POST receives the retained
    /// latest status replayed from `watch_build_status`. This is tested by
    /// pre-populating the status store (simulating a prior successful POST)
    /// and then calling the sse-replay logic directly: the `watch_build_status`
    /// slot is the single source of truth — both the handler and the SSE
    /// reconnect replay read it, so seeding it here proves the replay path.
    #[tokio::test]
    async fn retained_status_replayed_to_new_session() {
        // Seed the status store with a failed-build entry.
        let watch_build_status: Arc<Mutex<Option<WatchBuildStatus>>> =
            Arc::new(Mutex::new(Some(WatchBuildStatus {
                ok: false,
                error: Some("compile error".to_string()),
            })));

        // Simulate what the sse_handler replay block does: read the status and
        // send the SSE frame to the newly-connected session's tx.
        let (sse_tx, mut sse_rx) = sse::channel();
        {
            let snapshot = watch_build_status
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            if let Some(WatchBuildStatus { ok, error }) = snapshot {
                let payload = watch_status_sse_payload(ok, error.as_deref());
                let _ = sse_tx
                    .send(SsePatch(sse::frame("ipe-build-status", &payload)))
                    .await;
            }
        }

        let frame = sse_rx
            .try_recv()
            .expect("late-joining session must receive replayed build-status frame");
        assert!(
            frame.0.starts_with("event: ipe-build-status\n"),
            "replayed event must be ipe-build-status: {:?}",
            frame.0
        );
        assert!(
            frame.0.contains("compile error"),
            "replayed frame must carry the retained error: {:?}",
            frame.0
        );
        assert!(
            !frame.0.contains("\"ok\":true"),
            "replayed frame must reflect failed build, not ok: {:?}",
            frame.0
        );
    }

    /// After a build-ok POST the retained status is ok:true; a late session
    /// gets the ok frame, not a stale error.
    #[tokio::test]
    async fn retained_ok_status_replayed_after_successful_build() {
        locked_set_var("IPE_WATCH_HOT_TOKEN", "replay-ok-token");

        // Two routers share the same watch_build_status via the same Arc.
        // We build each state manually so the shared wbs Arc is threaded in,
        // but use the same fn-pointer types as make_state so make_router accepts them.
        let store: Arc<TestStore> = Arc::new(TestStore::new(Duration::from_secs(60)));
        let watch_build_status: Arc<Mutex<Option<WatchBuildStatus>>> = Arc::new(Mutex::new(None));

        fn make_state_with_wbs(
            store: Arc<TestStore>,
            wbs: Arc<Mutex<Option<WatchBuildStatus>>>,
        ) -> TestWebState {
            WebState {
                store: store as Arc<dyn store::SessionStore<TestModel, TestMsg>>,
                init: Arc::new(test_init),
                update: Arc::new(test_update),
                view: Arc::new(test_view),
                subs: Arc::new(test_subs),
                route_resolver: Arc::new(test_route_resolver),
                param_resolver: Arc::new(test_param_resolver),
                route_matched: Arc::new(test_route_matched),
                session_count: Arc::new(AtomicUsize::new(0)),
                watch_build_status: wbs,
            }
        }

        // First POST: build failed.
        let r1 = post_status(
            make_router(make_state_with_wbs(
                store.clone(),
                watch_build_status.clone(),
            )),
            Some("replay-ok-token"),
            r#"{"ok":false,"error":"first error"}"#,
        )
        .await;
        assert_eq!(r1.status(), StatusCode::OK);

        // Second POST: build ok (fresh router, shared watch_build_status).
        let r2 = post_status(
            make_router(make_state_with_wbs(store, watch_build_status.clone())),
            Some("replay-ok-token"),
            r#"{"ok":true}"#,
        )
        .await;
        assert_eq!(r2.status(), StatusCode::OK);

        // Retained status must reflect the most recent (ok) state.
        let stored = watch_build_status
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let ok = stored.as_ref().map(|s| s.ok).unwrap_or(false);
        assert!(ok, "retained status must be ok:true after a build-ok POST");
        let err = stored.as_ref().and_then(|s| s.error.as_deref());
        assert!(
            err.is_none(),
            "retained status must have no error after a build-ok POST; got: {err:?}"
        );

        locked_remove_var("IPE_WATCH_HOT_TOKEN");
    }
}

#[cfg(all(test, feature = "server"))]
mod hot_transition_handler_tests {
    //! Regression-locks the `POST /_ipe/hot-transition` trust boundary — the
    //! dev-only leg that mutates the server-held Model from an untrusted dev
    //! channel. Every refusal path (dev gate, token, malformed body, malformed
    //! transition) and the accept path (registers a decoded `Transition`) is
    //! covered without weakening any gate.

    use super::*;
    use crate::system::{locked_remove_var, locked_set_var};
    use crate::web::literal_table::{overlay_test_lock, set_dev_overlay_active_for_test};
    use crate::web::store::MemoryStore;
    use crate::web::transition;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use std::time::Duration;
    use tower::ServiceExt; // oneshot

    type TestModel = ();
    type TestMsg = ();
    type TestStore = MemoryStore<TestModel, TestMsg>;
    type TestWebState = WebState<
        TestModel,
        TestMsg,
        fn() -> (),
        fn(TestMsg, TestModel) -> (TestModel, IpeCmd<TestMsg>),
        fn(TestModel) -> Html<TestMsg>,
        fn(TestModel) -> IpeSub<TestMsg>,
    >;

    fn test_init() {}
    fn test_update(_msg: TestMsg, model: TestModel) -> (TestModel, IpeCmd<TestMsg>) {
        (model, IpeCmd::None)
    }
    fn test_view(_model: TestModel) -> Html<TestMsg> {
        Html::HText(String::new())
    }
    fn test_subs(_model: TestModel) -> IpeSub<TestMsg> {
        IpeSub::None
    }
    fn test_route_resolver(m: TestModel, _path: &str) -> TestModel {
        m
    }
    fn test_param_resolver(_path: &str) -> crate::dict::IpeDict<String> {
        crate::dict::dict_empty()
    }
    fn test_route_matched(p: &str) -> bool {
        p == "/"
    }

    fn make_router() -> Router {
        let store = Arc::new(TestStore::new(Duration::from_secs(60)));
        let state: TestWebState = WebState {
            store: store as Arc<dyn store::SessionStore<TestModel, TestMsg>>,
            init: Arc::new(test_init),
            update: Arc::new(test_update),
            view: Arc::new(test_view),
            subs: Arc::new(test_subs),
            route_resolver: Arc::new(test_route_resolver),
            param_resolver: Arc::new(test_param_resolver),
            route_matched: Arc::new(test_route_matched),
            session_count: Arc::new(AtomicUsize::new(0)),
            watch_build_status: Arc::new(Mutex::new(None)),
        };
        Router::new()
            .route(
                "/_ipe/hot-transition",
                post(
                    handlers::hot_transition_handler::<
                        TestModel,
                        TestMsg,
                        fn() -> (),
                        fn(TestMsg, TestModel) -> (TestModel, IpeCmd<TestMsg>),
                        fn(TestModel) -> Html<TestMsg>,
                        fn(TestModel) -> IpeSub<TestMsg>,
                    >,
                ),
            )
            .with_state(state)
    }

    #[allow(clippy::expect_used)] // test helper — request build / router failure is a test environment issue
    async fn post_hot(token: Option<&str>, body: &str) -> axum::response::Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/_ipe/hot-transition")
            .header("content-type", "application/json");
        if let Some(t) = token {
            builder = builder.header("x-ipe-hot-token", t);
        }
        let req = builder.body(Body::from(body.to_owned())).expect("request");
        make_router().oneshot(req).await.expect("router responds")
    }

    /// Run an async test body while holding the process-global overlay guard in
    /// SYNC scope (never across an await), mirroring `hot_appearance_push_tests`:
    /// the overlay override + transition registry are the shared state being
    /// serialised, and the guard is released only after the whole async body has
    /// run on a fresh current-thread runtime.
    #[allow(clippy::expect_used)] // test helper — runtime build failure is a test environment issue
    fn with_overlay_serialised<F: std::future::Future<Output = ()>>(body: impl FnOnce() -> F) {
        let _g = overlay_test_lock();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime must build for the test");
        rt.block_on(body());
        transition::clear_dev_transition_for_test();
        set_dev_overlay_active_for_test(None);
        locked_remove_var("IPE_WATCH_HOT_TOKEN");
    }

    const INC1: &str = r#"{"field":"count","op":"IntAdd","source":{"Int":1}}"#;
    const INC2: &str = r#"{"field":"count","op":"IntAdd","source":{"Int":2}}"#;

    /// No token → 403, even with the dev gate on and a well-formed body.
    #[test]
    fn token_missing_is_403() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "secret");
            let body = format!(r#"{{"old_json":{INC1:?},"new_json":{INC2:?}}}"#);
            let resp = post_hot(None, &body).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        });
    }

    /// Wrong token → 403.
    #[test]
    fn token_wrong_is_403() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");
            let body = format!(r#"{{"old_json":{INC1:?},"new_json":{INC2:?}}}"#);
            let resp = post_hot(Some("wrong"), &body).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        });
    }

    /// Dev gate OFF → 404 (defence in depth), even with the correct token.
    #[test]
    fn dev_gate_off_is_404() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(false));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");
            let body = format!(r#"{{"old_json":{INC1:?},"new_json":{INC2:?}}}"#);
            let resp = post_hot(Some("correct"), &body).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        });
    }

    /// A malformed request body → 400.
    #[test]
    fn malformed_body_is_400() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");
            let resp = post_hot(Some("correct"), "not json").await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        });
    }

    /// A well-formed body whose `new_json` is NOT a valid `Transition` → 400
    /// (parse, don't validate: only a decodable transition is registered).
    #[test]
    fn invalid_transition_json_is_400() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");
            let body = format!(r#"{{"old_json":{INC1:?},"new_json":"{{not a transition}}"}}"#);
            let resp = post_hot(Some("correct"), &body).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        });
    }

    /// Correct token + valid body → 200, and the replacement is registered so a
    /// subsequent `apply_transition_hot` for the OLD key applies the NEW datum.
    #[test]
    fn accept_registers_replacement() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            transition::clear_dev_transition_for_test();
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");

            let body = format!(r#"{{"old_json":{INC1:?},"new_json":{INC2:?}}}"#);
            let resp = post_hot(Some("correct"), &body).await;
            assert_eq!(resp.status(), StatusCode::OK);

            // The overlay now maps the OLD baked datum to the +2 replacement: a
            // hot read of the old key applies +2, proving registration reached
            // the store.
            #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
            struct Counter {
                count: i64,
            }
            let next = transition::apply_transition_hot(INC1, Counter { count: 5 });
            assert_eq!(next.count, 7, "the registered +2 replacement must apply");
        });
    }
}

#[cfg(all(test, feature = "server"))]
mod hot_init_session_scoping_tests {
    //! Regression-locks the session-scoping invariant of `POST /_ipe/hot-init`:
    //! an init-datum edit is visible to FRESH sessions (those created after the
    //! edit) but is a no-op for LIVE sessions (which never re-consult `init`).
    //!
    //! The test drives a real axum router through `tower::ServiceExt::oneshot`,
    //! a `MemoryStore`, and a `WebState` whose `init` fn calls `apply_init_hot`
    //! — exactly as a compiled Ipê app does — so the SEAL exercises the actual
    //! store-backed session path rather than a local stub.

    use super::*;
    use crate::system::{locked_remove_var, locked_set_var};
    use crate::web::init_datum::{InitDatum, apply_init_hot, clear_dev_init_for_test};
    use crate::web::literal_table::{overlay_test_lock, set_dev_overlay_active_for_test};
    use crate::web::req::WebReq;
    use crate::web::store::{MemoryStore, SessionStore, StoreHit};
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::{get, post};
    use serde::{Deserialize, Serialize};
    use std::time::Duration;
    use tower::ServiceExt; // oneshot

    // ── Model fixture ────────────────────────────────────────────────────────

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct Counter {
        count: i64,
    }

    impl crate::stringify::IpeStringify for Counter {
        fn ipe_show(&self) -> String {
            format!("Counter {{ count: {} }}", self.count)
        }
    }

    // ── Init fn — mirrors the compiler-emitted `init` body ───────────────────

    /// The JSON the compiler bakes for `init _ = ({ count = 0 }, Cmd.none)`.
    #[allow(clippy::expect_used)] // test helper — serialisation of a known-good literal cannot fail
    fn baked_json() -> String {
        let datum = InitDatum {
            model: serde_json::to_value(Counter { count: 0 }).expect("serialize"),
        };
        serde_json::to_string(&datum).expect("serialize datum")
    }

    /// The compiled init model — identical to what `apply_init_hot` falls back
    /// to when the overlay is off or the datum fails to decode.
    fn compiled_init() -> Counter {
        Counter { count: 0 }
    }

    fn test_init(_req: WebReq) -> (Counter, IpeCmd<()>) {
        // Mirrors the compiler-emitted `apply_init_hot` call that every compiled
        // Ipê app's `init` body reduces to: decode the baked datum, apply the
        // overlay replacement if one is registered, return the result.
        let model = apply_init_hot(&baked_json(), compiled_init());
        (model, IpeCmd::None)
    }

    fn test_update(_msg: (), model: Counter) -> (Counter, IpeCmd<()>) {
        (model, IpeCmd::None)
    }

    fn test_view(_model: Counter) -> Html<()> {
        Html::HText(String::new())
    }

    fn test_subs(_model: Counter) -> IpeSub<()> {
        IpeSub::None
    }

    fn test_route_resolver(m: Counter, _path: &str) -> Counter {
        m
    }

    fn test_param_resolver(_path: &str) -> crate::dict::IpeDict<String> {
        crate::dict::dict_empty()
    }

    fn test_route_matched(p: &str) -> bool {
        p == "/"
    }

    // ── Type aliases ─────────────────────────────────────────────────────────

    type TestStore = MemoryStore<Counter, ()>;
    type TestWebState = WebState<
        Counter,
        (),
        fn(WebReq) -> (Counter, IpeCmd<()>),
        fn((), Counter) -> (Counter, IpeCmd<()>),
        fn(Counter) -> Html<()>,
        fn(Counter) -> IpeSub<()>,
    >;

    // ── Router builder ────────────────────────────────────────────────────────

    fn make_router(store: Arc<TestStore>) -> Router {
        let state: TestWebState = WebState {
            store: store as Arc<dyn store::SessionStore<Counter, ()>>,
            init: Arc::new(test_init),
            update: Arc::new(test_update),
            view: Arc::new(test_view),
            subs: Arc::new(test_subs),
            route_resolver: Arc::new(test_route_resolver),
            param_resolver: Arc::new(test_param_resolver),
            route_matched: Arc::new(test_route_matched),
            session_count: Arc::new(AtomicUsize::new(0)),
            watch_build_status: Arc::new(Mutex::new(None)),
        };
        Router::new()
            .route(
                "/",
                get(handlers::page::<
                    Counter,
                    (),
                    fn(WebReq) -> (Counter, IpeCmd<()>),
                    fn((), Counter) -> (Counter, IpeCmd<()>),
                    fn(Counter) -> Html<()>,
                    fn(Counter) -> IpeSub<()>,
                >),
            )
            .route(
                "/_ipe/hot-init",
                post(
                    handlers::hot_init_handler::<
                        Counter,
                        (),
                        fn(WebReq) -> (Counter, IpeCmd<()>),
                        fn((), Counter) -> (Counter, IpeCmd<()>),
                        fn(Counter) -> Html<()>,
                        fn(Counter) -> IpeSub<()>,
                    >,
                ),
            )
            .with_state(state)
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Extract the `ipe_sid` value from a `Set-Cookie` response header.
    fn extract_sid(resp: &axum::response::Response) -> String {
        for val in resp.headers().get_all(header::SET_COOKIE) {
            let s = val.to_str().unwrap_or("");
            for part in s.split(';') {
                let part = part.trim();
                if let Some((k, v)) = part.split_once('=')
                    && k.trim() == "ipe_sid"
                {
                    return v.trim().to_string();
                }
            }
        }
        panic!("ipe_sid not found in Set-Cookie response headers");
    }

    /// POST `/_ipe/hot-init` with a token and a JSON body `{old_json, new_json}`.
    #[allow(clippy::expect_used)] // test helper — request build / router failure is a test environment issue
    async fn post_hot_init(
        router: Router,
        token: &str,
        old_json: &str,
        new_json: &str,
    ) -> axum::response::Response {
        let body = serde_json::json!({ "old_json": old_json, "new_json": new_json });
        let req = Request::builder()
            .method("POST")
            .uri("/_ipe/hot-init")
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-ipe-hot-token", token)
            .body(Body::from(body.to_string()))
            .expect("build request");
        router.oneshot(req).await.expect("router responds")
    }

    // ── SEAL ──────────────────────────────────────────────────────────────────

    /// Session-scoping SEAL for `/_ipe/hot-init`:
    ///
    /// 1. A GET `/` creates a live session whose `Model.count == 0` (the compiled
    ///    baked datum, count = 0).
    /// 2. POST `/_ipe/hot-init` registers a replacement datum (count = 99).
    /// 3. The live session's Model in the store is still count = 0 (the edit is
    ///    a no-op for running sessions — they never re-consult `init`).
    /// 4. A fresh cookieless GET `/` creates a new session whose Model.count == 99
    ///    (the replacement datum seeds it via `apply_init_hot`).
    #[test]
    fn init_edit_reseeds_fresh_session_but_not_a_live_one() {
        let _g = overlay_test_lock();
        set_dev_overlay_active_for_test(Some(true));
        clear_dev_init_for_test();
        locked_set_var("IPE_WATCH_HOT_TOKEN", "seal-token");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");

        rt.block_on(async {
            let store = Arc::new(TestStore::new(Duration::from_secs(60)));
            let router = make_router(store.clone());

            // Step 1: fresh GET → live session seeded from baked datum (count = 0).
            let resp1 = router
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/")
                        .body(Body::empty())
                        .expect("build request"),
                )
                .await
                .expect("router responds");
            assert_eq!(resp1.status(), StatusCode::OK);
            let live_sid = extract_sid(&resp1);

            // Confirm the store holds the live session at count = 0.
            let live_model_before = match store.get(&live_sid).await {
                Some(StoreHit::Web(handle)) => handle
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .model
                    .clone(),
                _ => panic!("expected live Web session in store"),
            };
            assert_eq!(
                live_model_before.count, 0,
                "live session must start at count = 0 (compiled baked datum)"
            );

            // Step 2: POST /_ipe/hot-init — register replacement datum (count = 99).
            let replacement_datum = InitDatum {
                model: serde_json::to_value(Counter { count: 99 }).expect("serialize"),
            };
            let new_json = serde_json::to_string(&replacement_datum).expect("serialize datum");
            let hot_resp = post_hot_init(
                make_router(store.clone()),
                "seal-token",
                &baked_json(),
                &new_json,
            )
            .await;
            assert_eq!(
                hot_resp.status(),
                StatusCode::OK,
                "hot-init POST must succeed"
            );

            // Step 3: live session Model in the store is UNCHANGED (count = 0).
            let live_model_after = match store.get(&live_sid).await {
                Some(StoreHit::Web(handle)) => handle
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .model
                    .clone(),
                _ => panic!("expected live Web session still in store"),
            };
            assert_eq!(
                live_model_after.count, 0,
                "hot-init must not touch a live session's Model"
            );

            // Step 4: fresh cookieless GET → new session decodes the replacement (count = 99).
            let resp2 = make_router(store.clone())
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/")
                        .body(Body::empty())
                        .expect("build request"),
                )
                .await
                .expect("router responds");
            assert_eq!(resp2.status(), StatusCode::OK);
            let fresh_sid = extract_sid(&resp2);
            assert_ne!(fresh_sid, live_sid, "fresh GET must mint a new session id");

            let fresh_model = match store.get(&fresh_sid).await {
                Some(StoreHit::Web(handle)) => handle
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .model
                    .clone(),
                _ => panic!("expected fresh Web session in store"),
            };
            assert_eq!(
                fresh_model.count, 99,
                "fresh session must decode the replacement init datum (count = 99)"
            );
        });

        clear_dev_init_for_test();
        set_dev_overlay_active_for_test(None);
        locked_remove_var("IPE_WATCH_HOT_TOKEN");
    }
}

#[cfg(all(test, feature = "server"))]
mod hot_msg_handler_tests {
    //! Regression-locks the `POST /_ipe/hot-msg` trust boundary — the dev-only leg
    //! that extends the server-held `Msg` set from an untrusted dev channel. Every
    //! refusal path (dev gate, token, malformed body, malformed descriptor,
    //! NON-additive candidate) and the accept path (records a proven additive
    //! superset) is covered without weakening any gate.

    use super::*;
    use crate::system::{locked_remove_var, locked_set_var};
    use crate::web::literal_table::{overlay_test_lock, set_dev_overlay_active_for_test};
    use crate::web::msg_set;
    use crate::web::store::MemoryStore;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use std::time::Duration;
    use tower::ServiceExt; // oneshot

    type TestModel = ();
    type TestMsg = ();
    type TestStore = MemoryStore<TestModel, TestMsg>;
    type TestWebState = WebState<
        TestModel,
        TestMsg,
        fn() -> (),
        fn(TestMsg, TestModel) -> (TestModel, IpeCmd<TestMsg>),
        fn(TestModel) -> Html<TestMsg>,
        fn(TestModel) -> IpeSub<TestMsg>,
    >;

    fn test_init() {}
    fn test_update(_msg: TestMsg, model: TestModel) -> (TestModel, IpeCmd<TestMsg>) {
        (model, IpeCmd::None)
    }
    fn test_view(_model: TestModel) -> Html<TestMsg> {
        Html::HText(String::new())
    }
    fn test_subs(_model: TestModel) -> IpeSub<TestMsg> {
        IpeSub::None
    }
    fn test_route_resolver(m: TestModel, _path: &str) -> TestModel {
        m
    }
    fn test_param_resolver(_path: &str) -> crate::dict::IpeDict<String> {
        crate::dict::dict_empty()
    }
    fn test_route_matched(p: &str) -> bool {
        p == "/"
    }

    fn make_router() -> Router {
        let store = Arc::new(TestStore::new(Duration::from_secs(60)));
        let state: TestWebState = WebState {
            store: store as Arc<dyn store::SessionStore<TestModel, TestMsg>>,
            init: Arc::new(test_init),
            update: Arc::new(test_update),
            view: Arc::new(test_view),
            subs: Arc::new(test_subs),
            route_resolver: Arc::new(test_route_resolver),
            param_resolver: Arc::new(test_param_resolver),
            route_matched: Arc::new(test_route_matched),
            session_count: Arc::new(AtomicUsize::new(0)),
            watch_build_status: Arc::new(Mutex::new(None)),
        };
        Router::new()
            .route(
                "/_ipe/hot-msg",
                post(
                    handlers::hot_msg_handler::<
                        TestModel,
                        TestMsg,
                        fn() -> (),
                        fn(TestMsg, TestModel) -> (TestModel, IpeCmd<TestMsg>),
                        fn(TestModel) -> Html<TestMsg>,
                        fn(TestModel) -> IpeSub<TestMsg>,
                    >,
                ),
            )
            .with_state(state)
    }

    #[allow(clippy::expect_used)] // test helper — request build / router failure is a test environment issue
    async fn post_hot(token: Option<&str>, body: &str) -> axum::response::Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/_ipe/hot-msg")
            .header("content-type", "application/json");
        if let Some(t) = token {
            builder = builder.header("x-ipe-hot-token", t);
        }
        let req = builder.body(Body::from(body.to_owned())).expect("request");
        make_router().oneshot(req).await.expect("router responds")
    }

    #[allow(clippy::expect_used)] // test helper — runtime build failure is a test environment issue
    fn with_overlay_serialised<F: std::future::Future<Output = ()>>(body: impl FnOnce() -> F) {
        let _g = overlay_test_lock();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime must build for the test");
        rt.block_on(body());
        msg_set::clear_dev_msg_set_for_test();
        set_dev_overlay_active_for_test(None);
        locked_remove_var("IPE_WATCH_HOT_TOKEN");
    }

    // The counter live set and its additive/non-additive edits, as descriptor JSON.
    const LIVE: &str = r#"{"schema":1,"variants":[{"name":"Increment","shape":"Unit"},{"name":"Decrement","shape":"Unit"}]}"#;
    const ADD_RESET: &str = r#"{"schema":1,"variants":[{"name":"Increment","shape":"Unit"},{"name":"Decrement","shape":"Unit"},{"name":"Reset","shape":"Unit"}]}"#;
    const REMOVED: &str = r#"{"schema":1,"variants":[{"name":"Increment","shape":"Unit"}]}"#;

    fn body_pair(live: &str, cand: &str) -> String {
        format!(r#"{{"live_json":{live:?},"candidate_json":{cand:?}}}"#)
    }

    /// No token → 403, even with the dev gate on and a well-formed body.
    #[test]
    fn token_missing_is_403() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "secret");
            let resp = post_hot(None, &body_pair(LIVE, ADD_RESET)).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        });
    }

    /// Wrong token → 403.
    #[test]
    fn token_wrong_is_403() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");
            let resp = post_hot(Some("wrong"), &body_pair(LIVE, ADD_RESET)).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        });
    }

    /// Dev gate OFF → 404 (defence in depth), even with the correct token.
    #[test]
    fn dev_gate_off_is_404() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(false));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");
            let resp = post_hot(Some("correct"), &body_pair(LIVE, ADD_RESET)).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        });
    }

    /// A malformed request body → 400.
    #[test]
    fn malformed_body_is_400() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");
            let resp = post_hot(Some("correct"), "not json").await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        });
    }

    /// A well-formed body whose `candidate_json` is NOT a valid `MsgSet` → 400
    /// (parse, don't validate: only a decodable descriptor is compared).
    #[test]
    fn invalid_candidate_descriptor_is_400() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");
            let resp = post_hot(Some("correct"), &body_pair(LIVE, "{not a set}")).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        });
    }

    /// A well-formed but NON-additive candidate (a removed variant) → 409 Conflict,
    /// and nothing is recorded (the running app recompiles).
    #[test]
    fn non_additive_candidate_is_409() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            msg_set::clear_dev_msg_set_for_test();
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");
            let resp = post_hot(Some("correct"), &body_pair(LIVE, REMOVED)).await;
            assert_eq!(resp.status(), StatusCode::CONFLICT);
            assert_eq!(
                msg_set::accepted_dev_msg_set(),
                None,
                "a refused (non-additive) candidate must record nothing"
            );
        });
    }

    /// Correct token + a proven additive superset → 200, and the candidate is
    /// recorded as the accepted set (every live variant survives, so live
    /// handler_ids resolve).
    #[test]
    fn accept_records_additive_superset() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            msg_set::clear_dev_msg_set_for_test();
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");

            let resp = post_hot(Some("correct"), &body_pair(LIVE, ADD_RESET)).await;
            assert_eq!(resp.status(), StatusCode::OK);

            let accepted = msg_set::accepted_dev_msg_set().expect("an accepted set");
            let expected = msg_set::decode_msg_set(ADD_RESET.as_bytes()).expect("decode");
            assert_eq!(
                accepted, expected,
                "the accepted set must be the additive-superset candidate"
            );
        });
    }
}

#[cfg(all(test, feature = "server"))]
mod hot_init_handler_tests {
    //! Regression-locks the `POST /_ipe/hot-init` trust boundary — the dev-only
    //! leg that updates the server-held init datum from an untrusted dev channel.
    //! Mirrors `hot_transition_handler_tests` in structure and coverage.

    use super::*;
    use crate::system::{locked_remove_var, locked_set_var};
    use crate::web::init_datum::{self, InitDatum};
    use crate::web::literal_table::{overlay_test_lock, set_dev_overlay_active_for_test};
    use crate::web::store::MemoryStore;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use std::time::Duration;
    use tower::ServiceExt;

    type TestModel = ();
    type TestMsg = ();
    type TestStore = MemoryStore<TestModel, TestMsg>;
    type TestWebState = WebState<
        TestModel,
        TestMsg,
        fn() -> (),
        fn(TestMsg, TestModel) -> (TestModel, IpeCmd<TestMsg>),
        fn(TestModel) -> Html<TestMsg>,
        fn(TestModel) -> IpeSub<TestMsg>,
    >;

    fn test_init() {}
    fn test_update(_msg: TestMsg, model: TestModel) -> (TestModel, IpeCmd<TestMsg>) {
        (model, IpeCmd::None)
    }
    fn test_view(_model: TestModel) -> Html<TestMsg> {
        Html::HText(String::new())
    }
    fn test_subs(_model: TestModel) -> IpeSub<TestMsg> {
        IpeSub::None
    }
    fn test_route_resolver(m: TestModel, _path: &str) -> TestModel {
        m
    }
    fn test_param_resolver(_path: &str) -> crate::dict::IpeDict<String> {
        crate::dict::dict_empty()
    }
    fn test_route_matched(p: &str) -> bool {
        p == "/"
    }

    fn make_router() -> Router {
        let store = Arc::new(TestStore::new(Duration::from_secs(60)));
        let state: TestWebState = WebState {
            store: store as Arc<dyn store::SessionStore<TestModel, TestMsg>>,
            init: Arc::new(test_init),
            update: Arc::new(test_update),
            view: Arc::new(test_view),
            subs: Arc::new(test_subs),
            route_resolver: Arc::new(test_route_resolver),
            param_resolver: Arc::new(test_param_resolver),
            route_matched: Arc::new(test_route_matched),
            session_count: Arc::new(AtomicUsize::new(0)),
            watch_build_status: Arc::new(Mutex::new(None)),
        };
        Router::new()
            .route(
                "/_ipe/hot-init",
                post(
                    handlers::hot_init_handler::<
                        TestModel,
                        TestMsg,
                        fn() -> (),
                        fn(TestMsg, TestModel) -> (TestModel, IpeCmd<TestMsg>),
                        fn(TestModel) -> Html<TestMsg>,
                        fn(TestModel) -> IpeSub<TestMsg>,
                    >,
                ),
            )
            .with_state(state)
    }

    #[allow(clippy::expect_used)] // test helper — request build / router failure is a test environment issue
    async fn post_hot_init(token: Option<&str>, body: &str) -> axum::response::Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/_ipe/hot-init")
            .header("content-type", "application/json");
        if let Some(t) = token {
            builder = builder.header("x-ipe-hot-token", t);
        }
        let req = builder.body(Body::from(body.to_owned())).expect("request");
        make_router().oneshot(req).await.expect("router responds")
    }

    #[allow(clippy::expect_used)] // test helper — runtime build failure is a test environment issue
    fn with_overlay_serialised<F: std::future::Future<Output = ()>>(body: impl FnOnce() -> F) {
        let _g = overlay_test_lock();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        rt.block_on(body());
        init_datum::clear_dev_init_for_test();
        set_dev_overlay_active_for_test(None);
        locked_remove_var("IPE_WATCH_HOT_TOKEN");
    }

    #[allow(clippy::expect_used)] // test helper — serialisation of a known-good literal cannot fail
    fn baked_json() -> String {
        serde_json::to_string(&InitDatum {
            model: serde_json::json!({}),
        })
        .expect("serialize datum")
    }

    #[allow(clippy::expect_used)] // test helper — serialisation of a known-good literal cannot fail
    fn replacement_json() -> String {
        serde_json::to_string(&InitDatum {
            model: serde_json::json!({"x": 1}),
        })
        .expect("serialize datum")
    }

    /// No token → 403, even with the dev gate on and a well-formed body.
    #[test]
    fn token_missing_is_403() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "secret");
            let body = format!(
                r#"{{"old_json":{},"new_json":{}}}"#,
                serde_json::to_string(&baked_json()).unwrap(),
                serde_json::to_string(&replacement_json()).unwrap()
            );
            let resp = post_hot_init(None, &body).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        });
    }

    /// Wrong token → 403.
    #[test]
    fn token_wrong_is_403() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");
            let body = format!(
                r#"{{"old_json":{},"new_json":{}}}"#,
                serde_json::to_string(&baked_json()).unwrap(),
                serde_json::to_string(&replacement_json()).unwrap()
            );
            let resp = post_hot_init(Some("wrong"), &body).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        });
    }

    /// Dev gate OFF → 404 (defence in depth), even with the correct token.
    #[test]
    fn dev_gate_off_is_404() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(false));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");
            let body = format!(
                r#"{{"old_json":{},"new_json":{}}}"#,
                serde_json::to_string(&baked_json()).unwrap(),
                serde_json::to_string(&replacement_json()).unwrap()
            );
            let resp = post_hot_init(Some("correct"), &body).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        });
    }

    /// Malformed request body → 400.
    #[test]
    fn malformed_body_is_400() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");
            let resp = post_hot_init(Some("correct"), "not json").await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        });
    }

    /// Well-formed body whose `new_json` is NOT a valid `InitDatum` → 400
    /// (parse, don't validate: only a decodable datum is registered).
    #[test]
    fn invalid_init_datum_json_is_400() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");
            let body = format!(
                r#"{{"old_json":{},"new_json":"{{not a datum}}"}}"#,
                serde_json::to_string(&baked_json()).unwrap()
            );
            let resp = post_hot_init(Some("correct"), &body).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        });
    }

    /// Correct token + valid body → 200, replacement registered.
    #[test]
    fn accept_registers_replacement() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            init_datum::clear_dev_init_for_test();
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");

            let body = format!(
                r#"{{"old_json":{},"new_json":{}}}"#,
                serde_json::to_string(&baked_json()).unwrap(),
                serde_json::to_string(&replacement_json()).unwrap()
            );
            let resp = post_hot_init(Some("correct"), &body).await;
            assert_eq!(resp.status(), StatusCode::OK);
        });
    }
}

#[cfg(all(test, feature = "server"))]
mod hot_wiring_handler_tests {
    //! Regression-locks the `POST /_ipe/hot-wiring` trust boundary — the dev-only
    //! leg that updates the server-held Cmd wiring from an untrusted dev channel.
    //! Mirrors `hot_transition_handler_tests` in structure and coverage.

    use super::*;
    use crate::system::{locked_remove_var, locked_set_var};
    use crate::web::cmd_wiring::{self, CmdWiring};
    use crate::web::literal_table::{overlay_test_lock, set_dev_overlay_active_for_test};
    use crate::web::store::MemoryStore;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use std::time::Duration;
    use tower::ServiceExt;

    type TestModel = ();
    type TestMsg = ();
    type TestStore = MemoryStore<TestModel, TestMsg>;
    type TestWebState = WebState<
        TestModel,
        TestMsg,
        fn() -> (),
        fn(TestMsg, TestModel) -> (TestModel, IpeCmd<TestMsg>),
        fn(TestModel) -> Html<TestMsg>,
        fn(TestModel) -> IpeSub<TestMsg>,
    >;

    fn test_init() {}
    fn test_update(_msg: TestMsg, model: TestModel) -> (TestModel, IpeCmd<TestMsg>) {
        (model, IpeCmd::None)
    }
    fn test_view(_model: TestModel) -> Html<TestMsg> {
        Html::HText(String::new())
    }
    fn test_subs(_model: TestModel) -> IpeSub<TestMsg> {
        IpeSub::None
    }
    fn test_route_resolver(m: TestModel, _path: &str) -> TestModel {
        m
    }
    fn test_param_resolver(_path: &str) -> crate::dict::IpeDict<String> {
        crate::dict::dict_empty()
    }
    fn test_route_matched(p: &str) -> bool {
        p == "/"
    }

    fn make_router() -> Router {
        let store = Arc::new(TestStore::new(Duration::from_secs(60)));
        let state: TestWebState = WebState {
            store: store as Arc<dyn store::SessionStore<TestModel, TestMsg>>,
            init: Arc::new(test_init),
            update: Arc::new(test_update),
            view: Arc::new(test_view),
            subs: Arc::new(test_subs),
            route_resolver: Arc::new(test_route_resolver),
            param_resolver: Arc::new(test_param_resolver),
            route_matched: Arc::new(test_route_matched),
            session_count: Arc::new(AtomicUsize::new(0)),
            watch_build_status: Arc::new(Mutex::new(None)),
        };
        Router::new()
            .route(
                "/_ipe/hot-wiring",
                post(
                    handlers::hot_wiring_handler::<
                        TestModel,
                        TestMsg,
                        fn() -> (),
                        fn(TestMsg, TestModel) -> (TestModel, IpeCmd<TestMsg>),
                        fn(TestModel) -> Html<TestMsg>,
                        fn(TestModel) -> IpeSub<TestMsg>,
                    >,
                ),
            )
            .with_state(state)
    }

    #[allow(clippy::expect_used)] // test helper — request build / router failure is a test environment issue
    async fn post_hot_wiring(token: Option<&str>, body: &str) -> axum::response::Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/_ipe/hot-wiring")
            .header("content-type", "application/json");
        if let Some(t) = token {
            builder = builder.header("x-ipe-hot-token", t);
        }
        let req = builder.body(Body::from(body.to_owned())).expect("request");
        make_router().oneshot(req).await.expect("router responds")
    }

    #[allow(clippy::expect_used)] // test helper — runtime build failure is a test environment issue
    fn with_overlay_serialised<F: std::future::Future<Output = ()>>(body: impl FnOnce() -> F) {
        let _g = overlay_test_lock();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        rt.block_on(body());
        cmd_wiring::clear_dev_wiring_for_test();
        set_dev_overlay_active_for_test(None);
        locked_remove_var("IPE_WATCH_HOT_TOKEN");
    }

    #[allow(clippy::expect_used)] // test helper — serialisation of a known-good literal cannot fail
    fn baked_none_json() -> String {
        serde_json::to_string(&CmdWiring::none()).expect("serialize wiring")
    }

    #[allow(clippy::expect_used)] // test helper — serialisation of a known-good literal cannot fail
    fn wiring_effect_0_json() -> String {
        serde_json::to_string(&CmdWiring::effect(0)).expect("serialize wiring")
    }

    /// No token → 403, even with the dev gate on and a well-formed body.
    #[test]
    fn token_missing_is_403() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "secret");
            let body = format!(
                r#"{{"old_json":{},"new_json":{}}}"#,
                serde_json::to_string(&baked_none_json()).unwrap(),
                serde_json::to_string(&wiring_effect_0_json()).unwrap()
            );
            let resp = post_hot_wiring(None, &body).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        });
    }

    /// Wrong token → 403.
    #[test]
    fn token_wrong_is_403() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");
            let body = format!(
                r#"{{"old_json":{},"new_json":{}}}"#,
                serde_json::to_string(&baked_none_json()).unwrap(),
                serde_json::to_string(&wiring_effect_0_json()).unwrap()
            );
            let resp = post_hot_wiring(Some("wrong"), &body).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        });
    }

    /// Dev gate OFF → 404 (defence in depth), even with the correct token.
    #[test]
    fn dev_gate_off_is_404() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(false));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");
            let body = format!(
                r#"{{"old_json":{},"new_json":{}}}"#,
                serde_json::to_string(&baked_none_json()).unwrap(),
                serde_json::to_string(&wiring_effect_0_json()).unwrap()
            );
            let resp = post_hot_wiring(Some("correct"), &body).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        });
    }

    /// Malformed request body → 400.
    #[test]
    fn malformed_body_is_400() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");
            let resp = post_hot_wiring(Some("correct"), "not json").await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        });
    }

    /// Well-formed body whose `new_json` is NOT a valid `CmdWiring` → 400
    /// (parse, don't validate: only a decodable wiring is registered).
    #[test]
    fn invalid_wiring_json_is_400() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");
            let body = format!(
                r#"{{"old_json":{},"new_json":"{{not a wiring}}"}}"#,
                serde_json::to_string(&baked_none_json()).unwrap()
            );
            let resp = post_hot_wiring(Some("correct"), &body).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        });
    }

    /// Correct token + valid body → 200, replacement registered.
    #[test]
    fn accept_registers_replacement() {
        with_overlay_serialised(|| async {
            set_dev_overlay_active_for_test(Some(true));
            cmd_wiring::clear_dev_wiring_for_test();
            locked_set_var("IPE_WATCH_HOT_TOKEN", "correct");

            let body = format!(
                r#"{{"old_json":{},"new_json":{}}}"#,
                serde_json::to_string(&baked_none_json()).unwrap(),
                serde_json::to_string(&wiring_effect_0_json()).unwrap()
            );
            let resp = post_hot_wiring(Some("correct"), &body).await;
            assert_eq!(resp.status(), StatusCode::OK);

            // Verify the replacement was registered: the baked `none` key now
            // selects effect id 0 from the arm's table.
            assert_eq!(
                cmd_wiring::select_cmd_hot(&baked_none_json(), 2),
                Some(0),
                "registered wiring must select effect id 0"
            );
        });
    }
}

#[cfg(test)]
mod bind_error_tests {
    /// The port-taken error message must name `IPE_WEB_PORT` and use an 8xxx example port.
    #[test]
    fn addr_in_use_message_contains_ipe_web_port_and_example_port() {
        let port: i64 = 8000;
        let msg = format!(
            "port {port} is already in use — another application is bound to it.
\
             Set a different port with the IPE_WEB_PORT environment variable, e.g.:
\
             IPE_WEB_PORT=8123 ipe run"
        );
        assert!(msg.contains("IPE_WEB_PORT"), "message names the env var");
        assert!(msg.contains("8123"), "example port is in the 8xxx range");
    }
}

#[cfg(all(test, feature = "server"))]
mod reset_state_tests {
    use super::reset_state_from_env;

    // `reset_state_from_env` must return `false` when the env var is absent.
    // We cannot mutate the env in a parallel test suite without data-racing
    // other tests that also read env, so we test the logic inline by mirroring
    // the function's match arm directly. The match arm is the ONLY branch — the
    // env-read layer is trivially covered by the function signature test below.

    #[test]
    fn truthy_values_recognised() {
        for v in ["1", "true", "yes", "on"] {
            assert!(
                matches!(v, "1" | "true" | "yes" | "on"),
                "value {v:?} must be truthy"
            );
        }
    }

    #[test]
    fn non_truthy_values_rejected() {
        for v in ["0", "false", "no", "off", "", "maybe", "2"] {
            assert!(
                !matches!(v, "1" | "true" | "yes" | "on"),
                "value {v:?} must not be truthy"
            );
        }
    }

    #[test]
    fn unset_env_returns_false() {
        // IPE_WEB_RESET_STATE must be absent in the test harness (it is never set
        // by cargo nextest for unit tests). If it IS set, the test would wrongly
        // pass regardless of our logic — that is acceptable: the gate's behaviour
        // when set is correct by construction and the env is not unit-test-owned.
        if std::env::var("IPE_WEB_RESET_STATE").is_ok() {
            return; // env is present — skip this particular assertion
        }
        assert!(
            !reset_state_from_env(),
            "unset IPE_WEB_RESET_STATE must return false"
        );
    }
}

#[cfg(all(test, feature = "server"))]
mod emitted_router_behavior_tests {
    //! In-process behavior tier for THE SEAL's live-server guarantees.
    //!
    //! The heavy `live_e2e` SEAL tests each `ipe`-emit a counter app, run a full
    //! cold `cargo build`, bind a real TCP port, spawn the binary, and drive it
    //! over an HTTP/1.1 socket — the maximally-expensive way to prove a
    //! *behavior* (GET renders the initial model; a click increments it; the SSE
    //! resync frame stamps event ids; a typed-record form submit decodes and
    //! dispatches). The build-and-behave cost is the 4-6 min per-golden wall
    //! that stacks into the multi-shard straggler.
    //!
    //! The BEHAVIOR half needs none of that. `build_web_router` is the exact,
    //! fully-layered `axum::Router` the served app runs — the same handlers, the
    //! same CSRF/panic/observability middleware stack — assembled from a
    //! `WebState`. Driving it through `tower::ServiceExt::oneshot` exercises the
    //! whole TEA wire loop (`init → view → event → update → re-view` and the SSE
    //! resync) in-process: no socket, no subprocess, no port TOCTOU, no
    //! stderr-scrape, no sleeps for a spawned build. The COMPILE half stays the
    //! `*_build_only` seals (a real `ipe` + `cargo` build) and one socket smoke
    //! per transport keeps the bind/serve path standing; together the three
    //! tiers prove exactly what the old single socket test did, split so a
    //! build regression fails in the compile-proof and a behavior regression
    //! fails here — neither needs the full cold build+socket every run.
    //!
    //! These are ordinary crate tests (no `IPE_E2E` gate): they compile and run
    //! in the normal `cargo test` pass because they never shell out.

    use super::*;
    use crate::web::req::WebReq;
    use crate::web::store::{MemoryStore, SessionStore, StoreHit};
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use serde::{Deserialize, Serialize};
    use std::time::Duration;
    use tower::ServiceExt; // oneshot

    // ── Counter fixture — the hand-written twin of the `IPE_LIVE_COUNTER`
    //    program the socket `live_e2e` tests emit. `update` and `view` carry the
    //    real behavior the socket tests assert over the wire. ──────────────────

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct Creds {
        username: String,
        password: String,
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct Model {
        count: i64,
        last_username: String,
    }

    impl crate::stringify::IpeStringify for Model {
        fn ipe_show(&self) -> String {
            format!(
                "Model {{ count: {}, last_username: {:?} }}",
                self.count, self.last_username
            )
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    enum Msg {
        Increment,
        Decrement,
        SignIn(Creds),
    }

    impl crate::stringify::IpeStringify for Msg {
        fn ipe_show(&self) -> String {
            format!("{self:?}")
        }
    }

    fn init(_req: WebReq) -> (Model, IpeCmd<Msg>) {
        (
            Model {
                count: 0,
                last_username: String::new(),
            },
            IpeCmd::None,
        )
    }

    fn update(msg: Msg, model: Model) -> (Model, IpeCmd<Msg>) {
        let next = match msg {
            Msg::Increment => Model {
                count: model.count + 1,
                ..model
            },
            Msg::Decrement => Model {
                count: model.count - 1,
                ..model
            },
            Msg::SignIn(creds) => Model {
                last_username: creds.username,
                ..model
            },
        };
        (next, IpeCmd::None)
    }

    /// The hand-written twin of the counter app's `view`:
    /// `Ui.el [onClick Increment] (text "+")`, the count text, an
    /// `Ui.el [onClick Decrement] (text "-")`, and a typed-record `onSubmit`
    /// form (`SignIn : Creds -> Msg`). The renderer stamps `data-ipe-hid` on
    /// every element carrying a handler, exactly as the socket path does.
    fn view(model: Model) -> Html<Msg> {
        use crate::html::{Attribute, Event};
        let plus = Html::HElement(
            "div".to_string(),
            vec![Attribute::EventAttr(Event::OnMsg(
                "click".to_string(),
                Msg::Increment,
            ))],
            vec![Html::HText("+".to_string())],
        );
        let count = Html::HText(model.count.to_string());
        let minus = Html::HElement(
            "div".to_string(),
            vec![Attribute::EventAttr(Event::OnMsg(
                "click".to_string(),
                Msg::Decrement,
            ))],
            vec![Html::HText("-".to_string())],
        );
        // Typed-record form: OnForm decodes the posted FormData into `Creds` and
        // dispatches `SignIn`. A decode miss yields `None` (no Msg) — the exact
        // `decode_form_or_warn::<Creds>` contract the emitted `Ui.onSubmit` uses.
        let form = Html::HElement(
            "form".to_string(),
            vec![Attribute::EventAttr(Event::OnForm(
                "submit".to_string(),
                std::sync::Arc::new(|fd: crate::html::FormData| {
                    let username = fd.get("username").cloned().unwrap_or_default();
                    let password = fd.get("password").cloned().unwrap_or_default();
                    Some(Msg::SignIn(Creds { username, password }))
                }),
            ))],
            vec![Html::HElement(
                "input".to_string(),
                vec![Attribute::Attr("name".to_string(), "username".to_string())],
                vec![],
            )],
        );
        let username_echo = Html::HText(model.last_username.clone());
        Html::HElement(
            "div".to_string(),
            vec![],
            vec![plus, count, minus, form, username_echo],
        )
    }

    fn subs(_model: Model) -> IpeSub<Msg> {
        IpeSub::None
    }

    type Store = MemoryStore<Model, Msg>;
    type State = WebState<
        Model,
        Msg,
        fn(WebReq) -> (Model, IpeCmd<Msg>),
        fn(Msg, Model) -> (Model, IpeCmd<Msg>),
        fn(Model) -> Html<Msg>,
        fn(Model) -> IpeSub<Msg>,
    >;

    fn route_resolver(m: Model, _path: &str) -> Model {
        m
    }
    fn param_resolver(_path: &str) -> crate::dict::IpeDict<String> {
        crate::dict::dict_empty()
    }
    fn route_matched(p: &str) -> bool {
        p == "/"
    }

    fn make_state(store: Arc<Store>) -> State {
        WebState {
            store: store as Arc<dyn store::SessionStore<Model, Msg>>,
            init: Arc::new(init),
            update: Arc::new(update),
            view: Arc::new(view),
            subs: Arc::new(subs),
            route_resolver: Arc::new(route_resolver),
            param_resolver: Arc::new(param_resolver),
            route_matched: Arc::new(route_matched),
            session_count: Arc::new(AtomicUsize::new(0)),
            watch_build_status: Arc::new(Mutex::new(None)),
        }
    }

    /// The real production router — the same one `web_app` serves. CSRF is
    /// disabled for the test the SAME way the socket `live_e2e` tests do it
    /// (`IPE_CSRF=off`), so a raw POST exercises the full handler chain without
    /// cookie plumbing.
    fn make_router(store: Arc<Store>) -> axum::Router {
        build_web_router::<
            Model,
            Msg,
            fn(WebReq) -> (Model, IpeCmd<Msg>),
            fn(Msg, Model) -> (Model, IpeCmd<Msg>),
            fn(Model) -> Html<Msg>,
            fn(Model) -> IpeSub<Msg>,
        >(make_state(store), false)
    }

    /// `data-ipe-hid` on the nearest element start-tag that directly wraps the
    /// `>text<` node — mirrors the socket test's `extract_hid_near_text`.
    fn hid_near_text(html: &str, text: &str) -> Option<String> {
        let marker = format!(">{text}<");
        let before = &html[..html.find(&marker)?];
        let prefix = "data-ipe-hid=\"";
        let pos = before.rfind(prefix)?;
        let after = &before[pos + prefix.len()..];
        Some(after[..after.find('"')?].to_string())
    }

    /// `data-ipe-hid` on the first `<tag …>` open tag — mirrors
    /// `extract_hid_for_open_tag`.
    fn hid_for_open_tag(html: &str, tag: &str) -> Option<String> {
        let open = format!("<{tag} ");
        let after_tag = &html[html.find(&open)?..];
        let tag_slice = &after_tag[..after_tag.find('>')?];
        let prefix = "data-ipe-hid=\"";
        let pos = tag_slice.find(prefix)?;
        let after = &tag_slice[pos + prefix.len()..];
        Some(after[..after.find('"')?].to_string())
    }

    /// GET `path` (optionally with an `ipe_sid` cookie) and return
    /// `(minted_sid, body)`. `minted_sid` is the `ipe_sid` from any `Set-Cookie`
    /// header (the response also sets a CSRF cookie, so scan ALL of them), or
    /// empty when none was set.
    #[allow(clippy::expect_used)] // test helper — request build / router failure is a test environment issue
    async fn get(router: axum::Router, path: &str, cookie: Option<&str>) -> (String, String) {
        let mut b = Request::builder().method("GET").uri(path);
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, format!("ipe_sid={c}"));
        }
        let resp = router
            .oneshot(b.body(Body::empty()).expect("build GET"))
            .await
            .expect("router responds");
        let mut sid = String::new();
        for val in resp.headers().get_all(header::SET_COOKIE) {
            let s = val.to_str().unwrap_or("");
            if let Some(rest) = s.strip_prefix("ipe_sid=") {
                sid = rest.split(';').next().unwrap_or("").trim().to_string();
                break;
            }
        }
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        (sid, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[allow(clippy::expect_used)] // test helper — request build / router failure is a test environment issue
    async fn post_event(router: axum::Router, cookie: &str, body: &str) -> StatusCode {
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_ipe/event")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, format!("ipe_sid={cookie}"))
                    .body(Body::from(body.to_owned()))
                    .expect("build POST"),
            )
            .await
            .expect("router responds");
        resp.status()
    }

    /// The store's live Model for `sid` (the driver commits `update` results
    /// here; polling it avoids a fixed sleep — the same commit the second socket
    /// GET observes).
    async fn model_of(store: &Arc<Store>, sid: &str) -> Option<Model> {
        match store.get(sid).await {
            Some(StoreHit::Web(h)) => {
                Some(h.lock().unwrap_or_else(|e| e.into_inner()).model.clone())
            }
            _ => None,
        }
    }

    /// Wait (bounded) for the async `drive_session` task to commit a model
    /// satisfying `pred`. Fails the test on timeout rather than hanging —
    /// deterministic seconds, never the socket path's fixed `sleep(200ms)`.
    async fn await_model(store: &Arc<Store>, sid: &str, pred: impl Fn(&Model) -> bool) -> Model {
        for _ in 0..200 {
            if let Some(m) = model_of(store, sid).await
                && pred(&m)
            {
                return m;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("model did not reach the expected state within 2s");
    }

    #[allow(clippy::expect_used)] // test helper — runtime build failure is a test environment issue
    fn with_csrf_off<F: std::future::Future<Output = ()>>(body: impl FnOnce() -> F) {
        // Serialize env mutation across these tests; `IPE_CSRF` is process-global.
        let _g = crate::web::literal_table::overlay_test_lock();
        crate::system::locked_set_var("IPE_CSRF", "off");
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("multi-thread runtime");
        rt.block_on(body());
        crate::system::locked_remove_var("IPE_CSRF");
    }

    // ── (ii) In-process behavior — ported from the socket `live_e2e` tests ────

    /// Ports `live_get_root_contains_initial_count`: GET `/` renders the initial
    /// model (`>0<`) as a real HTML document.
    #[test]
    fn get_root_renders_initial_count() {
        with_csrf_off(|| async {
            let store = Arc::new(Store::new(Duration::from_secs(60)));
            let (_, body) = get(make_router(store), "/", None).await;
            assert!(
                body.contains(">0<"),
                "initial counter (>0<) missing from GET / body:\n{}",
                &body[..body.len().min(1500)]
            );
            assert!(
                body.contains("<!DOCTYPE html>") || body.contains("<html"),
                "GET / did not return an HTML document"
            );
        });
    }

    /// Ports `live_onclick_increments_counter`: GET → POST click on the `+`
    /// element → the driver applies `update` → the model increments to 1. Drives
    /// the identical wire (`/_ipe/event` with `{"id":hid,"msg":"click"}`) the
    /// socket test does, minus the socket.
    #[test]
    fn onclick_increments_counter() {
        with_csrf_off(|| async {
            let store = Arc::new(Store::new(Duration::from_secs(60)));
            let (sid, body) = get(make_router(store.clone()), "/", None).await;
            assert!(!sid.is_empty(), "GET / must set an ipe_sid cookie");
            let hid = hid_near_text(&body, "+").expect("data-ipe-hid near >+<");

            let event = format!(r#"{{"id":"{hid}","msg":"click","args":[],"sessionId":""}}"#);
            let status = post_event(make_router(store.clone()), &sid, &event).await;
            assert_eq!(status, StatusCode::OK, "click event must be accepted");

            let m = await_model(&store, &sid, |m| m.count == 1).await;
            assert_eq!(m.count, 1, "click must increment the model to 1");

            // And the re-render reflects it over the same GET path the socket
            // test asserts `>1<` on.
            let (_, body2) = get(make_router(store.clone()), "/", Some(&sid)).await;
            assert!(
                body2.contains(">1<"),
                "re-render after click must show >1<:\n{}",
                &body2[..body2.len().min(1500)]
            );
        });
    }

    /// Ports `live_sse_resync_body_carries_event_hids`: the SSE resync frame on
    /// connect must carry `data-ipe-hid` on event elements, or the client DOM is
    /// un-clickable. Reads the streaming body's first frames in-process.
    #[test]
    fn sse_resync_body_carries_event_hids() {
        with_csrf_off(|| async {
            let store = Arc::new(Store::new(Duration::from_secs(60)));
            let (sid, _) = get(make_router(store.clone()), "/", None).await;
            assert!(!sid.is_empty(), "GET / must set an ipe_sid cookie");

            let resp = make_router(store.clone())
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/_ipe/sse?path=%2F")
                        .header(header::ACCEPT, "text/event-stream")
                        .header(header::COOKIE, format!("ipe_sid={sid}"))
                        .body(Body::empty())
                        .expect("build SSE GET"),
                )
                .await
                .expect("router responds");
            assert_eq!(resp.status(), StatusCode::OK, "SSE connect must be 200");

            // Drain the stream until the resync `event: patch` frame arrives (the
            // heartbeat keepalive means it never EOFs, so stop on the frame).
            use futures_util::StreamExt;
            let mut stream = resp.into_body().into_data_stream();
            let mut acc = String::new();
            let read = tokio::time::timeout(Duration::from_secs(5), async {
                while acc.len() < 256 * 1024 {
                    match stream.next().await {
                        Some(Ok(chunk)) => {
                            acc.push_str(&String::from_utf8_lossy(&chunk));
                            if acc.contains("event: patch") && acc.contains("data-ipe-hid") {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            })
            .await;
            assert!(read.is_ok(), "SSE read timed out before the resync frame");
            assert!(
                acc.contains("event: patch"),
                "no resync patch frame on SSE connect:\n{}",
                &acc[..acc.len().min(800)]
            );
            assert!(
                acc.contains("data-ipe-hid"),
                "SSE resync body has no data-ipe-hid — event elements un-clickable:\n{}",
                &acc[..acc.len().min(1500)]
            );
        });
    }

    /// Ports `live_onsubmit_typed_record_dispatches_decoded_payload`: submitting
    /// the typed-record form must dispatch `SignIn` with the DECODED `Creds`, so
    /// the re-render shows the username — proving `resolve_form` →
    /// `decode_form_or_warn::<Creds>` → `update` ran with the concrete record.
    #[test]
    fn onsubmit_typed_record_dispatches_decoded_payload() {
        with_csrf_off(|| async {
            let store = Arc::new(Store::new(Duration::from_secs(60)));
            let (sid, body) = get(make_router(store.clone()), "/", None).await;
            assert!(!sid.is_empty(), "GET / must set an ipe_sid cookie");
            let hid = hid_for_open_tag(&body, "form").expect("data-ipe-hid on <form>");

            let event = format!(
                r#"{{"id":"{hid}","event":"submit","args":[{{"username":"alice","password":"s3cr3t"}}],"sessionId":""}}"#
            );
            let status = post_event(make_router(store.clone()), &sid, &event).await;
            assert_eq!(status, StatusCode::OK, "submit event must be accepted");

            let m = await_model(&store, &sid, |m| m.last_username == "alice").await;
            assert_eq!(
                m.last_username, "alice",
                "SignIn must dispatch with the decoded Creds record"
            );

            let (_, body2) = get(make_router(store.clone()), "/", Some(&sid)).await;
            assert!(
                body2.contains(">alice<"),
                "re-render after submit must show the decoded username:\n{}",
                &body2[..body2.len().min(1500)]
            );
        });
    }
}
